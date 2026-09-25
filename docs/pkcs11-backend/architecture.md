# PKCS#11 Backend — Architecture

> **Status: NORMATIVE** · Feature: `pkcs11-backend` · Repo: `go-xkms` · Last verified: 2026-09-24

## Scope: the client backend, not the provider module

This repository has three things named "pkcs11" that share a specification
and nothing else:

| Layer | Code | Direction | Docs |
|---|---|---|---|
| **Module** | `pkg/pkcs11/module`, `cmd/pkcs11-module` | xkms **provides** a `.so` to OpenSSL/OpenSSH/NSS | [`../pkcs11-provider-module/`](../pkcs11-provider-module/) |
| **Client / backend** | `pkg/backend/pkcs11` | xkms **consumes** somebody else's HSM | this folder |
| **Manager** | `pkg/pkcs11/manager` (re-exported as `sdk/go/pkcs11/manager`) | slot/token lifecycle (init, PIN, probe) — driven by `xkmsctl pkcs11 ...`, not `xkmsctl key ...` | [`../pkcs11-provider-module/`](../pkcs11-provider-module/) |

Conflating the module and the backend has caused real production damage in
this repo: two Makefile targets were both once named
`integration-test-pkcs11`, `make` silently took the last definition, and the
SoftHSM client suite never ran — see `Makefile` history and
[`engineering.md`](engineering.md) for the current target names. This folder
is the client/backend only.

## Position in the stack

```
xkms service / transports (rest, grpc, quic, mcp, unix)
        |  keyProviders["pkcs11"]
        v
pkg/backend/pkcs11.Backend          <- this package
        |  SessionPool (channel of CK_SESSION_HANDLE)
        v
github.com/miekg/pkcs11 (cgo)
        v
vendor Cryptoki library (.so)  ->  HSM / token
```

The backend is registered by `pkg/server/backend_pkcs11.go` under the key
`"pkcs11"` — the same pattern as `software`, `tpm2`, `awskms`, `gcpkms`,
`azurekv`, `vault`, `phone`. It satisfies `types.KeyProvider`, so nothing
above it knows it is talking to an HSM.

## Build tag: `pkcs11`, and cgo is required

Every file in `pkg/backend/pkcs11` carries `//go:build pkcs11`
(`Backend` binds `github.com/miekg/pkcs11`, which is cgo). Without the tag,
`pkg/server/backend_pkcs11_stub.go` logs a warning and the backend is absent:

```go
// initPKCS11Backend is a stub when PKCS#11 support is not compiled in
func (s *Server) initPKCS11Backend() error {
	if s.config.Backends.PKCS11 != nil && s.config.Backends.PKCS11.Enabled {
		s.logger.Warn("PKCS#11 backend enabled in config but not compiled in (use -tags pkcs11)")
	}
	return nil
}
```

```bash
go build -tags pkcs11 ./cmd/xkmsd
```

Unlike FROST, this feature *is* fully wired end to end when built with the
tag: `configs/xkmsd.yaml`'s `backends.pkcs11:` section, `pkg/config`'s
`PKCS11Config`, and `pkg/server/backend_pkcs11.go` all exist and connect —
see [`engineering.md`](engineering.md) for the exact fields.

## The `Backend` type

```go
type Backend struct {
	config        *Config
	p11ctx        *pkcs11.Ctx
	pool          *SessionPool
	ownsP11ctx    bool // tracks if this backend owns the PKCS#11 context (should Finalize/Destroy)
	tracker       types.AEADSafetyTracker
	supportsMLDSA bool              // dynamically detected ML-DSA mechanism support
	supportsMLKEM bool              // dynamically detected ML-KEM mechanism support
	slotModel     pivcert.SlotModel // nil for generic (non-PIV) tokens
	mu            sync.RWMutex
	types.KeyProvider
}
```

Interfaces asserted at compile time: `backend.ImportExportBackend`
(`pkcs11_importexport.go:39`), `types.SymmetricKeyProvider` +
`types.SymmetricKeyProviderWithTracking` (`pkcs11_symmetric.go:697`),
`types.SymmetricKey` + `types.SymmetricEncrypter` (`pkcs11_symmetric.go:699`),
`types.KeyAgreementProvider` (`pkcs11_ecdh.go:501`), `types.Sealer`
(`sealer.go:29`).

`Capabilities()` reports `types.NewHardwareCapabilities()`
(`HardwareBacked=true`, `KeyRotation=false`, `SecurityLevel=High`) plus
`SymmetricEncryption`, `Import`, `Export`, and two post-quantum flags
(`QuantumSigning`, `KeyEncapsulation`) set from the token's actual
`C_GetMechanismList` output, not a static claim.

## Lifecycle

1. `NewBackend(config)` — validates config only. No library is loaded, no
   session opened.
2. `Initialize(soPIN, userPIN)` — **operator action**, first-time token
   setup (`C_InitToken` + `C_InitPIN`). `xkmsd` never calls this — token
   provisioning is vendor tooling (`softhsm2-util`, HSM console), not a boot
   action. Returns `ErrAlreadyInitialized` if already initialized.
3. `Login()` — the boot path `xkmsd` actually calls. Loads the library,
   `C_Initialize`s it, resolves the slot, builds the session pool, attaches
   the PIV slot model for `libykcs11`, probes ML-DSA/ML-KEM support.
4. Operations.
5. `Close()` — closes the pool, then `C_Finalize` + `Destroy` only if this
   backend created the context (`ownsP11ctx`). Idempotent.

## Session pool

`SessionPool` (`session_pool.go`) is a buffered channel of pre-opened R/W
sessions — a lock-free semaphore, not a mutex-guarded free list. Default
size `DefaultSessionPoolSize = 8` (`session_pool.go:29`), overridable via
`Config.SessionPoolSize`. Construction opens `size` sessions and logs in
**once** — Cryptoki login state is per token, not per session, so one
`C_Login` covers the whole pool; `CKR_USER_ALREADY_LOGGED_IN` is treated as
success because another pool/manager on the same token may have logged in
first.

`WithSession(fn func(session pkcs11.SessionHandle) error)` rules: the
session handle must not escape `fn` — it returns to the pool the instant
`fn` returns and another goroutine may use it immediately; do not start an
operation in one `WithSession` call and finish it in a later one (Cryptoki
allows at most one active search/crypto operation per session — a leaked
`C_FindObjectsInit` makes every later search fail with
`CKR_OPERATION_ACTIVE`); do not call `Close()` from inside `fn`.

`Close()` sets an atomic `closed` flag, closes a `done` channel, then drains
and closes every pooled session; `WithSession` selects on both `p.pool` and
`p.done` so a caller already blocked when `Close` runs is released rather
than leaking. `Close` is idempotent and tolerates a zero-value pool.

`WithSOSession(soPin, userPin, fn)` logs out, logs in as `CKU_SO`, runs
`fn`, then restores the `CKU_USER` login — required by YubiKey PIV for key
generation and object destruction. The caller must hold the backend write
lock for the whole call, because the intermediate SO state is visible to
every session on the token.

## Key addressing

One identifier serves as both `CKA_LABEL` and `CKA_ID` on every object the
backend creates: `createKeyID(attrs)` is `"<CN>.<algorithm>"`, or `"<CN>."`
when the algorithm is unknown; `keyIDToCN` is its exact inverse.
`resolveKeyID` (`pkcs11.go:1427`) overrides this for PIV, in priority order:
`KeyAttributes.PIVSlot` → single-byte `CKA_ID` via `PIVSlotToCKAID`;
`Config.Slot` when the library is `libykcs11` → `createSlotID(slot)`;
otherwise `createKeyID(attrs)`. Import verifies the identifier afterward
(`verifyImportedKeyIdentity`), repairing `CKA_LABEL`/`CKA_ID` if the token
dropped them from the unwrap template, and destroying the object if it
cannot be addressed — an unaddressable key object is orphaned key material.

## CKA_EC_POINT encodings

PKCS#11 v3.2 §6.3.3 Table 64 defines a short-Weierstrass `CKA_EC_POINT` as a
DER OCTET STRING wrapping the X9.62 uncompressed point, but real tokens
disagree on whether they store the wrapper or the bare point.
`exportECDSAPublicKey` accepts both; `decodeECPoint` discriminates on
**length**, not the leading byte (`0x04` is both the OCTET STRING tag and
the uncompressed-point marker, so it cannot distinguish them). For a curve
with a `byteLen`-byte field the bare point is always `1 + 2*byteLen` bytes
(65/97/133 for P-256/P-384/P-521); any DER wrapper is strictly longer. A
value matching neither form is `ErrInvalidKeyAttributes` rather than
guessed at.

## YubiKey PIV specialization

`Config.IsYubiKeyPIV()` (library path contains `ykcs11`) switches several
paths: minimal key templates (`libykcs11` sets `CKA_TOKEN`/`CKA_SIGN`/
`CKA_VERIFY`/`CKA_PRIVATE`/`CKA_SENSITIVE` itself per slot — supplying them
returns `CKR_ATTRIBUTE_VALUE_INVALID`); key generation runs under
`WithSOSession` with the management key (`ErrSOPINRequired` without a
configured SO PIN); certificate deletion goes through
`hardware.NewPKCS11CertStorageWithSO` (`libykcs11` rejects
`C_DestroyObject` under `CKU_USER`); Ed25519 is rejected outright with a
pointer to ECDSA P-256 or RSA.

## Thread safety

`Backend.mu` is a `sync.RWMutex`; mutating operations (generate, import,
initialize, close) take the write lock, lookups take the read lock. `Seal`/
`Unseal` deliberately do not hold the lock across their call into
`SymmetricEncrypter`, which re-acquires it — `checkInitialized` takes and
releases the read lock itself to avoid the recursive-read-lock deadlock
`sync.RWMutex` documents when a writer arrives between the two acquisitions.

## Attestation: fully implemented, corrects a stale claim

The predecessor documentation for this backend (superseded
`docs/pkcs11/backend/operations.md`) stated that `AttestKey`'s supporting
helpers were placeholders returning "not implemented." **That is no longer
true.** `AttestKey` (`attestation.go:296`) is fully implemented: it checks
token support via `supportsAttestation()`, resolves the token's own device
attestation key (`deviceAttestationKey()`), locates the target key object
(`findKeyObject`, `attestation.go:515`), reads its public half
(`getPublicKeyFromObject`, `attestation.go:585` — from `CKA_MODULUS`/
`CKA_PUBLIC_EXPONENT` for RSA or `CKA_EC_PARAMS`/`CKA_EC_POINT` for EC/
Edwards, or recovered from the certificate under the same `CKA_ID` for
PIV-style tokens), reads properties and token device info, builds the
device identity certificate chain by walking token-resident certificates
and verifying each signature link (`getDeviceIdentityCertificate`,
`attestation.go:651`; `buildDeviceChain`), ASN.1-DER-encodes the attested
facts deterministically (`encodeAttestationData`), and signs them with the
device key (`signAttestationData`, `attestation.go:845`).

What this requires from the token: a certificate published under the fixed
label `DeviceAttestationKeyLabel` (`attestation.go`), paired with a private
key the token uses to sign attestations. **PKCS#11 defines no standard
object for "the key that speaks for this token"** — vendors publish it
under vendor-specific labels or not at all, so a token that has never had
one provisioned (SoftHSM, an unconfigured HSM) returns
`ErrAttestationUnsupported`/`ErrNoDeviceAttestationKey` rather than
succeeding. This is a token-provisioning gap, not an unimplemented code
path.

## Rejected alternative: `crypto11`

The pre-`docs/pkcs11-backend` documentation for this feature described a
`crypto11`-wrapper-based API (`Config.LibraryPath`, `SlotID`,
`SharedContext`, `store.Close(ctx)`, `backend.KeyParams`). That wrapper has
been removed; none of those names exist in the current source. This folder
describes the current, cgo-direct `github.com/miekg/pkcs11` implementation
only.
