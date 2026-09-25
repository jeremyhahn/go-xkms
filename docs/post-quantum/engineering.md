# Post-Quantum Cryptography — Engineering Contract

> **Status: NORMATIVE** · Feature: `post-quantum` · Repo: `go-xkms` · Last verified: 2026-09-24

## Exported surface

### `pkg/keyprovider/quantum` — the key-provider backend

- `New(store storage.Backend) (*QuantumBackend, error)` and
  `NewWithConfig(store storage.Backend, config *Config) (*QuantumBackend,
  error)` (`backend.go:144-167`). `Config.Tracker types.AEADSafetyTracker`
  is optional; nil selects `backend.NewMemoryAEADTracker()`.
- `QuantumBackend` methods: `Type() types.BackendType` (returns
  `types.BackendTypeQuantum`), `Capabilities()`, `GenerateKey`, `GetKey`,
  `DeleteKey`, `ListKeys`, `Signer`, `Decrypter` (always
  `ErrKeyNotDecrypter`), `RotateKey`, `Close` (`backend.go:169-720`).
  `Capabilities()` reports `Keys: true, Signing: true, KeyRotation: true,
  Import: true, Export: true, KeyAgreement: true`, and `Decryption: false,
  SymmetricEncryption: false, ECIES: false, HardwareBacked: false`
  (`backend.go:174-188`).
- `GenerateKey` requires `attrs.QuantumAttributes != nil`
  (`ErrInvalidQuantumAttributes` otherwise) and dispatches on
  `attrs.QuantumAttributes.Algorithm.IsSignature()` /
  `.IsKEM()` (`backend.go:191-259`).
- `MLDSAPrivateKey` (`signer.go:43-123`): implements `crypto.Signer`
  (`Public() crypto.PublicKey`, `Sign(io.Reader, []byte,
  crypto.SignerOpts) ([]byte, error)`), plus `Verify(message, signature
  []byte) (bool, error)`, `Clean()`, `ExportSecretKey() []byte` (the
  32-byte seed).
- `MLKEMPrivateKey` (`signer.go:142-362`): `Public()`,
  `Encapsulate(recipientPublicKey []byte) (ciphertext, sharedSecret
  []byte, error)`, `Decapsulate(ciphertext []byte) (sharedSecret []byte,
  error)`, `Encrypt`/`Decrypt`/`EncryptWithAAD`/`DecryptWithAAD` (ML-KEM
  encapsulation + AES-256-GCM over the shared secret), `Clean()`,
  `ExportSecretKey() []byte` (the 64-byte seed). Does **not** implement
  `crypto.Decrypter`.

### `pkg/quantum/*` — per-algorithm primitives

Six packages, one per (algorithm, parameter set) pair, each exporting `New()
(*T, error)`, `Create(seed []byte) (*T, error)`, `Clean()`,
`ExportSecretKey() []byte`, and the operation methods for its family
(`GenerateKeyPair`/`Encapsulate`/`Decapsulate` for KEM;
`GenerateKeyPair`/`Sign`/`Verify` for signature — see each package's
`*_test.go` for the exact signature methods, which mirror
`crypto.Signer`-shaped calls without importing `crypto`):

| Package | `AlgorithmName` | `SeedSize` | Backing |
|---|---|---|---|
| `pkg/quantum/mlkem512` | `"ML-KEM-512"` | `mlkem512.KeySeedSize` (64) | `cloudflare/circl` |
| `pkg/quantum/kyber768` | `"ML-KEM-768"` | `mlkem.SeedSize` (64) | stdlib `crypto/mlkem` |
| `pkg/quantum/mlkem1024` | `"ML-KEM-1024"` | `mlkem.SeedSize` (64) | stdlib `crypto/mlkem` |
| `pkg/quantum/dilithium2` | `"ML-DSA-44"` | `mldsa.PrivateKeySize` (32) | stdlib `crypto/mldsa` |
| `pkg/quantum/mldsa65` | `"ML-DSA-65"` | `mldsa.PrivateKeySize` (32) | stdlib `crypto/mldsa` |
| `pkg/quantum/mldsa87` | `"ML-DSA-87"` | `mldsa.PrivateKeySize` (32) | stdlib `crypto/mldsa` |

Only `mlkem512.New`/`Create` gate on `crypto/fips140.Enabled()` and return
`ErrFIPSMode`; the other five packages carry no FIPS check of their own
because their stdlib callee refuses unsupported algorithms itself.

Every package's `Clean()` is safe to call more than once, on a zero value,
and on a nil receiver — callers do not need to guard it. Every seed is held
in an `sdk/go/secure.Secret` mlocked enclave, opened only for the instant
`ExportSecretKey` needs it, and wiped by `Clean`.

## Invariants

- **Seed reconstruction is exact.** `GetKey`/`Create` given the same seed
  bytes produce byte-identical key pairs. Nothing in this codebase re-derives
  a quantum key from anything other than its stored seed.
- **A generated key that is never handed to the caller is cleaned.**
  `QuantumBackend.GenerateKey` defers `cleanPrivateKey` and only skips it
  once the key is about to be returned (`backend.go:220-227`, `:257-258`);
  `RotateKey` cleans the intermediate key it generates unconditionally,
  because it is never returned to any caller (`backend.go:668-670`).
- **`Decrypter` never succeeds.** Calling code must not assume every
  `types.KeyProvider` backend answers `Decrypter`; the quantum backend
  documents ML-KEM's KEM/decryption split by refusing outright rather than
  approximating it.
- **AEAD tracking on `MLKEMPrivateKey.Encrypt`/`Decrypt` is best-effort
  in-memory.** See "What is absent" below before relying on it across a
  restart.

## Errors

Both `pkg/quantum/*` (per-package, e.g. `mlkem512.ErrInvalidSeed`) and
`pkg/keyprovider/quantum` (`errors.go`) declare typed sentinel `error`
values, never inline `fmt.Errorf`. The backend-level sentinels:

| Sentinel | Meaning |
|---|---|
| `ErrStorageClosed` | operation attempted after `Close()` |
| `ErrKeyNotSigner` | non-ML-DSA key asked to sign |
| `ErrKeyNotDecrypter` | `Decrypter()` called at all |
| `ErrUnsupportedAlgorithm` | algorithm name not in the six-package table |
| `ErrInvalidQuantumAttributes` | `attrs.QuantumAttributes == nil` |
| `ErrSigningFailed`, `ErrVerificationFailed` | ML-DSA operation failure |
| `ErrEncapsulationFailed`, `ErrDecapsulationFailed` | ML-KEM operation failure |
| `ErrNotInitialized` | operation on a `Clean()`-ed or zero-value key |

`pkg/quantum/mlkem512.ErrFIPSMode` is the one sentinel specific to that
package; the sibling packages have no equivalent because they never refuse
independently of their stdlib callee.

## Configuration

There is no YAML/config-file surface: `Config{Tracker
types.AEADSafetyTracker}` is a Go struct literal passed to
`NewWithConfig`, not a parsed file. The backend registers into the server's
`xkms.BackendType` registry under the constant `xkms.BackendQuantum =
"quantum"` (`pkg/xkms/registry.go:67-69`) via `pkg/xkms/register_quantum.go`,
whose factory `newQuantumKeyProvider` takes a `map[string]interface{}`
config and ignores it — "Configuration keys are reserved for future use"
(`register_quantum.go:33-39`).

**Documentation-vs-code mismatch worth flagging precisely**: both
`register_quantum.go`'s package comment ("This file is only compiled when
the 'quantum' build tag is specified") and `registry.go`'s comment on
`BackendQuantum` ("Requires build tag: quantum") describe a build
constraint that does not exist in this file. `register_quantum.go` carries
no `//go:build` line, and `go list -f '{{.GoFiles}}' ./pkg/xkms/` includes
it unconditionally — the quantum backend is always compiled into `pkg/xkms`
and always registered, contrary to what both comments say. This mirrors the
identical, already-acknowledged situation in
`pkg/pkcs11/module/mechanism_v32.go:39-50` ("No such tag exists — every
`*_quantum.go` file in this package compiles unconditionally").

## What is absent, half-built, or misdescribed

- **SLH-DSA, HSS/LMS, XMSS: mechanism constants only, no implementation,
  anywhere in this repository** — not in `pkg/quantum`, not in
  `pkg/keyprovider/quantum`, not behind the PKCS#11 module's advertised
  mechanisms. See [`architecture.md`](architecture.md) for the exact
  refusal path.
- **AEAD safety tracking has no persistent implementation.**
  `types.AEADSafetyTracker` (`pkg/types/types.go:2751-2779`) is implemented
  exactly once in this repository, by `backend.NewMemoryAEADTracker`
  (`pkg/backend/aead_tracker.go`), which is explicitly documented as
  test/short-lived-process-only. A `QuantumBackend` (or the symmetric
  backend — see [`../symmetric-aead/engineering.md`](../symmetric-aead/engineering.md))
  constructed without an explicit persistent tracker loses all nonce-reuse
  and bytes-encrypted history across a restart; nothing in this codebase
  ships a file- or database-backed tracker to substitute.
- **No REST, gRPC, QUIC, MCP, or `xkmsctl` surface reaches
  `QuantumBackend.GenerateKey`.** `types.QuantumAttributes` is re-exported
  by the SDK type-alias file (`sdk/go/types.go:65-69`) but is never
  constructed by `pkg/api/rest`, `pkg/api/grpc`, or `cmd/xkmsctl`; `grep -rn
  QuantumAttributes` across those trees returns nothing. The generic
  `xkmsctl key generate --key-algorithm` flag's help text lists only `rsa,
  ecdsa, ed25519`, and the REST `GenerateKeyHandler`
  (`pkg/api/rest/handlers.go:241-360`) parses `req.Algorithm` only as an
  `x509.PublicKeyAlgorithm` or a `types.SymmetricAlgorithm` — there is no
  branch that recognizes an ML-KEM/ML-DSA algorithm name. See
  [`api.md`](api.md) and [`cli.md`](cli.md).
- **`xkmsctl algorithms` reports PQC discovery, not generation.** The
  command surfaces a `[post-quantum]` marker per algorithm
  (`cmd/xkmsctl/algorithms.go:88`) sourced from the server's compiled-in
  backend inventory; it answers "can this deployment do X", not "generate me
  an X key". See [`cli.md`](cli.md).
- **The PKCS#11 module is the one production path that both implements a
  full PQC algorithm set (ML-DSA-44/65/87, ML-KEM-512/768/1024) and exposes
  it over a standard wire protocol** (PKCS#11 v3.2), documented in
  [`../pkcs11-provider-module/`](../pkcs11-provider-module/). It is a
  separate consumer of `pkg/quantum/*`, not a caller of
  `pkg/keyprovider/quantum.QuantumBackend`.

## Tests

`make test-quantum` runs `test-quantum-backend` (`pkg/keyprovider/quantum/...`
— ML-DSA keygen/sign, ML-KEM encap/decap, encryption),
`test-quantum-software`, `test-quantum-pkcs11`, `test-quantum-pkcs11-module`,
`test-quantum-ca`, and `test-quantum-primitives` (Makefile:1247-1275). Each
`pkg/quantum/<algo>` package carries its own `*_test.go`, and `mlkem512` and
`mldsa65` additionally carry `fips_test.go` exercising the
`fips140.Enabled()` gate. `pkg/keyprovider/quantum/kat_test.go` runs
known-answer tests; `aead_tracking_test.go` and `encryption_test.go` exercise
the `MLKEMPrivateKey.Encrypt`/`Decrypt` + tracker integration.
