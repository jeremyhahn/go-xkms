# PKCS#11 Backend

## Overview

The PKCS#11 backend (`pkg/backend/pkcs11`) is xkms acting as a **PKCS#11 client**:
it loads somebody else's Cryptoki library (SoftHSM2, YubiKey, Thales nShield,
Utimaco, AWS CloudHSM, ...) and keeps private key material inside that device.
Private keys are generated on the token and never leave it: `Get` returns
`ErrNotSupported`, `ExportKeyMaterial` returns
`ErrAsymmetricKeyExportNotAllowed` for RSA/ECDSA/Ed25519/DSA, and symmetric key
objects report `ErrNotSupported` from `Raw()`.

The implementation binds `github.com/miekg/pkcs11` directly and drives every
operation through a channel-based session pool. The `crypto11` wrapper library
was removed; any document or example still referencing `crypto11.Context`,
`Config.LibraryPath`, `SlotID` or `SharedContext` is describing an API that no
longer exists.

This page is the short overview. The reference documentation lives in
[`../pkcs11/backend/`](../pkcs11/backend/README.md).

## Do not confuse the three PKCS#11 layers

Three separate things in this repository have "pkcs11" in the name. They share a
specification and nothing else. Conflating them has already caused production
damage: two Makefile targets were both named `integration-test-pkcs11`, `make`
took the last definition, and the SoftHSM client suite silently never ran.

| Layer | Code | Direction | Docs | Test entry point |
|---|---|---|---|---|
| **Module** | `pkg/pkcs11/module`, `cmd/pkcs11-module` | xkms **PROVIDES** a `.so` to OpenSSL/OpenSSH/NSS | [`../pkcs11/module/`](../pkcs11/module/README.md) | `make integration-test-pkcs11-module-all` |
| **Client / backend** | `pkg/backend/pkcs11` | xkms **CONSUMES** somebody else's HSM | this page, [`../pkcs11/backend/`](../pkcs11/backend/README.md) | `make integration-test-pkcs11-backend` |
| **Manager** | `pkg/pkcs11/manager` | slot/token lifecycle (init, PIN, probe) | [`../pkcs11/manager.md`](../pkcs11/manager.md) | — |

A green run of one says nothing about the others. `make integration-test-xkey-pkcs11`
is a fourth, unrelated target: it runs xkey's FIDO2/PIV consumer tests.

## Build Tag

Every file in `pkg/backend/pkcs11` is guarded by `//go:build pkcs11`, and cgo is
required. Build and test with the tag:

```bash
go build -tags pkcs11 ./cmd/xkmsd
```

Without the tag, `pkg/server/backend_pkcs11_stub.go` logs
`PKCS#11 backend enabled in config but not compiled in (use -tags pkcs11)` and no
PKCS#11 key provider is registered. Nothing is substituted in its place.

## Service Integration

### Checking Availability

```go
import "github.com/jeremyhahn/go-xkms/pkg/xkms"

if xkms.IsBackendSupported(xkms.BackendPKCS11) {
    fmt.Println("PKCS#11 backend is compiled in")
}
```

`pkg/xkms/register_pkcs11.go` registers `BackendPKCS11` and its factory at init
time, so this predicate is false in a binary built without the tag.

### Using via Service API

```go
key, err := xkms.GenerateKeyWithBackend(ctx, "pkcs11", &types.KeyAttributes{
    CN:           "hsm-signing-key",
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
})

sig, err := xkms.Sign(ctx, "pkcs11:::hsm-signing-key", data, nil)
```

### Auto-Initialize

The factory accepts these keys in `AutoConfig.BackendConfigs` (see
`newPKCS11KeyProvider`): `library`, `config`, `pin`, `so_pin`, `label`, `slot`,
plus `key_dir` / `key_storage` / `cert_storage` for metadata storage.

```go
err := xkms.AutoInitialize(&xkms.AutoConfig{
    DataDir: "/var/lib/xkms",
    BackendConfigs: map[xkms.BackendType]map[string]interface{}{
        xkms.BackendPKCS11: {
            "library": "/usr/lib/softhsm/libsofthsm2.so",
            "label":   "xkms",
            "pin":     "1234",
        },
    },
})
defer xkms.Close()
```

## Configuration

`pkcs11.Config` fields (`pkg/backend/pkcs11/config.go`):

| Field | YAML | Notes |
|---|---|---|
| `CN` | `cn` | Identifier used for logging |
| `Library` | `library` | Path to the Cryptoki `.so`. **Required**; `Validate` returns `ErrLibraryNotFound` if the path does not exist |
| `LibraryConfig` | `config` | Library configuration file (e.g. `softhsm2.conf`) |
| `PIN` | `pin` | User PIN. Minimum 4 characters when set |
| `SOPIN` | `so-pin` | Security Officer PIN, for token initialization only |
| `PlatformPolicy` | `platform-policy` | Apply platform-specific key policies |
| `Slot` | `slot` | `*int`; alternative to `TokenLabel`. For YubiKey PIV this is the PIV slot (`0x9a`, `0x9c`, ...) |
| `TokenLabel` | `label` | **Required**; how the slot is normally resolved |
| `KeyStorage` | — | `storage.Backend` for key **metadata** only; key material stays on the token. Required |
| `CertStorage` | — | `storage.Backend` for certificates. Required |
| `Tracker` | — | `types.AEADSafetyTracker`; defaults to an in-memory tracker. Use a persistent tracker in production |
| `SessionPoolSize` | `session-pool-size` | Pre-opened sessions; defaults to `DefaultSessionPoolSize` |

`Config.String()` masks both PINs. `IsSoftHSM()` and `IsYubiKeyPIV()` classify
the configured library path.

### Daemon configuration

`config.PKCS11Config` (`pkg/config/config.go`) exposes a smaller surface to
`xkmsd`, and `initPKCS11Backend` maps it onto the fields above:

```yaml
backends:
  pkcs11:
    enabled: true
    library: "/usr/lib/softhsm/libsofthsm2.so"
    token: "xkms"
    pin: ""
```

Full field-by-field detail, PIN sourcing and slot resolution:
[configuration.md](../pkcs11/backend/configuration.md).

## Lifecycle

```go
b, err := pkcs11.NewBackend(cfg)   // validates config only
if err != nil {
    return err
}
defer b.Close()                    // idempotent; drains the pool, finalizes the ctx it owns

// Token SO-initialization is an operator action (softhsm2-util / vendor tooling).
// Boot only authenticates:
if err := b.Login(); err != nil {   // loads the library, resolves the slot, builds the pool
    return err
}
```

`Initialize(soPIN, userPIN)` performs SO token initialization and then logs in;
it returns `ErrAlreadyInitialized` when a pool already exists. Every operation
returns `ErrNotInitialized` until the pool is built.

## Supported Algorithms and Operations

- **RSA** — key generation, PKCS#1 v1.5 and PSS signing, OAEP decryption
- **ECDSA** — NIST P-256 / P-384 / P-521 (`SupportedCurves` queries the token)
- **Ed25519** — requires PKCS#11 v3.0+ and token support (SoftHSM v2.6+)
- **ML-DSA / ML-KEM** — PKCS#11 v3.2 post-quantum mechanisms, enabled only when
  `probeQuantumMechanisms` finds them in the token's mechanism list; reported
  through `Capabilities().QuantumSigning` / `.KeyEncapsulation`
- **AES** — on-token symmetric keys (128/192/256-bit) with AES-GCM authenticated
  encryption; non-AEAD modes are rejected and nonce/byte budgets are enforced by
  the `AEADSafetyTracker`
- **ECDH** — `DeriveKeyECDH` with `CKD_NULL` or X9.63 SHA-1/256/384/512 KDFs
- **Seal / Unseal** — `types.Sealer` implemented as envelope encryption under an
  HSM-resident AES-GCM key. This is key-wrapping, not TPM-style binding to
  platform state
- **Import / export** — `ImportKey`, `WrapKey`, `UnwrapKey`, `ExportKey`; export
  only ever succeeds for objects the token marks `CKA_EXTRACTABLE`
- **Attestation** — the backend can produce vendor key-attestation material.
  See [operations.md](../pkcs11/backend/operations.md)
- **Random** — `GenerateRandom` draws from the token's RNG

Details and mechanism tables: [operations.md](../pkcs11/backend/operations.md).

## Security Posture

### No fallback — this backend fails closed

If the library is missing, the slot cannot be resolved, the PIN is wrong, or the
token is absent, the backend returns an error and the operation stops. It does
**not** fall back to SoftHSM, to a software key provider, or to any other
backend, and neither should calling code. A silent downgrade from a certified
HSM to a software token would invalidate every assumption the deployment made
about key custody, and it is forbidden by this project's rules.

Concretely: `Config.Validate` rejects a non-existent library path;
`initPKCS11Backend` propagates a failed `Login` as `ErrBackendCreate`, which
`Server` wraps as `ErrBackendInit` and which aborts startup. A binary built
without `-tags pkcs11` simply has no `pkcs11` provider — requests naming it fail
with a backend-not-found error rather than being served by software keys.

### Other properties

- Private keys are generated with `CKA_SENSITIVE` and cannot be read back
- PINs are never logged; `Config.String()` masks them
- The session pool bounds concurrent token access; all state is mutex-protected
- Slot resolution always honours the configured `TokenLabel`/`Slot` rather than
  taking the first enumerated slot

Threat model, object attributes and what the wrap ceremony exposes:
[security.md](../pkcs11/backend/security.md).

## Testing

```bash
# Client/backend integration suite (SoftHSM2 in Docker) — this backend
make integration-test-pkcs11-backend

# The PKCS#11 module xkms PROVIDES to other applications — a different layer
make integration-test-pkcs11-module-all

# xkey's PKCS#11 consumer tests (FIDO2 adapter + PIV) — a different project
make integration-test-xkey-pkcs11

# Coverage for the client backend (requires SoftHSM)
make coverage-pkcs11
```

Unit tests require the tag: `go test -tags pkcs11 ./pkg/backend/pkcs11/...`.

SoftHSM token setup used by CI:

```bash
softhsm2-util --init-token --slot 0 --label 'test-token' --so-pin 1234 --pin 1234
```

Pointing xkms at a real HSM, verification steps and failure modes:
[runbook.md](../pkcs11/backend/runbook.md).

## References

- [PKCS#11 client backend reference](../pkcs11/backend/README.md)
- [PKCS#11 module (the `.so` xkms provides)](../pkcs11/module/README.md)
- [PKCS#11 slot/token manager](../pkcs11/manager.md)
- [Nitrokey HSM](nitrokey-hsm.md) — a device driven through this backend
- [OASIS PKCS#11 specification](https://docs.oasis-open.org/pkcs11/)
- [miekg/pkcs11](https://github.com/miekg/pkcs11)
- [SoftHSM2](https://github.com/opendnssec/SoftHSMv2)
