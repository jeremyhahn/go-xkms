# Post-Quantum Cryptography — Architecture

> **Status: NORMATIVE** · Feature: `post-quantum` · Repo: `go-xkms` · Last verified: 2026-09-24

## The problem

NIST standardized three post-quantum families in 2024: ML-KEM (FIPS 203, key
encapsulation), ML-DSA (FIPS 204, signatures), and SLH-DSA (FIPS 205,
hash-based signatures). go-xkms needs these reachable the same way every other
algorithm is — as a `crypto.PrivateKey` a backend generates, stores and
retrieves — without inventing a parallel key model for "quantum" keys.

## Shape chosen: a dedicated key-provider backend over the same seams

`pkg/keyprovider/quantum.QuantumBackend` (`pkg/keyprovider/quantum/backend.go:137`)
implements the same `types.KeyProvider`-shaped surface (`GenerateKey`,
`GetKey`, `DeleteKey`, `ListKeys`, `RotateKey`, `Signer`, `Close`) every other
backend implements, storing a versioned JSON `keyMetadata{Algorithm,
PublicKey, Seed}` record through the generic `storage.Backend` rather than a
quantum-specific store. `Decrypter` always returns `ErrKeyNotDecrypter`
(`pkg/keyprovider/quantum/backend.go:624`) — ML-KEM is a KEM, not RSA-style
decryption, so the `crypto.Decrypter` shape does not fit; callers use the
`MLKEMPrivateKey.Encapsulate`/`Decapsulate`/`Encrypt`/`Decrypt` methods
directly (`pkg/keyprovider/quantum/signer.go`).

Keys are reconstructed from a deterministic seed (32 bytes for ML-DSA, 64
bytes for ML-KEM) rather than a stored expanded private key: `GenerateKey`
draws the seed, derives the key pair from it, seals a copy of the seed in an
mlocked `secure.Secret` enclave for the live key, and persists a second copy
in the metadata record so `GetKey` can rebuild the identical key pair later
(`pkg/keyprovider/quantum/backend.go:292-389`, `:461-531`). Every code path
that touches the plaintext seed — the generator's stack array, the metadata
struct before it is marshaled, the JSON bytes after `GetKey` decodes them —
is wiped with `secure.Wipe` on return, including error paths
(`backend.go:299-343`, `:403-416`, `:444-459`).

## Algorithm sourcing: three different provenances, not one

This is the fact every other document in this folder depends on, so it is
stated once here:

| Family | Parameter sets this repo implements | Source | Package(s) |
|---|---|---|---|
| ML-KEM (FIPS 203) | ML-KEM-768, ML-KEM-1024 | Go stdlib `crypto/mlkem` (Go 1.24+) | `pkg/quantum/mlkem1024`, `pkg/quantum/kyber768` (=ML-KEM-768), `pkg/keyprovider/quantum` |
| ML-KEM (FIPS 203) | ML-KEM-512 | `github.com/cloudflare/circl/kem/mlkem/mlkem512` — **not** in the Go Cryptographic Module | `pkg/quantum/mlkem512` |
| ML-DSA (FIPS 204) | ML-DSA-44, ML-DSA-65, ML-DSA-87 | Go stdlib `crypto/mldsa` (available with Go Cryptographic Module v1.26.0+; **unavailable** under module v1.0.0) | `pkg/quantum/dilithium2` (=ML-DSA-44), `pkg/quantum/mldsa65`, `pkg/quantum/mldsa87`, `pkg/keyprovider/quantum` |
| SLH-DSA (FIPS 205) | none | not implemented anywhere in this repository | — |
| HSS/LMS (RFC 8554), XMSS (RFC 8391) | none | not implemented anywhere in this repository | — |

`crypto/mlkem` implements only the 768 and 1024 parameter sets — there is no
stdlib ML-KEM-512 — so `pkg/quantum/mlkem512` is the one PQC primitive in this
repository that depends on a third-party cryptographic library
(`pkg/quantum/mlkem512/mlkem512.go:14-39`). CIRCL also ships a `kyber512`
package implementing the NIST round-3 Kyber submission; that is a materially
different algorithm from standardized ML-KEM-512 (different key derivation
and encoding, mutually incompatible ciphertexts) and this repository imports
only `kem/mlkem/mlkem512`, never `kem/kyber`.

The naming is legacy-compatible on purpose: `pkg/quantum/kyber768` and
`pkg/quantum/dilithium2` are not the pre-standardization Kyber/Dilithium
algorithms — both wrap the same stdlib ML-KEM-768 / ML-DSA-44 the
correctly-named sibling packages wrap, kept under their pre-FIPS names for
existing callers (`pkg/quantum/kyber768/kyber768.go:14-16`,
`pkg/quantum/dilithium2/dilithium2.go:14-19`).

## Why FIPS mode splits by parameter set, not by algorithm

`crypto/fips140.Enabled()` reports whether the process is running under the
Go Cryptographic Module, but it cannot see CIRCL: CIRCL is an ordinary Go
module, not part of the certified module boundary
(`pkg/quantum/mlkem512/mlkem512.go:33-39`). ML-KEM-512 therefore has no
stdlib implementation to defer its own refusal to, so `mlkem512.New` and
`mlkem512.Create` check `fips140.Enabled()` themselves and return
`ErrFIPSMode` before touching CIRCL
(`pkg/quantum/mlkem512/mlkem512.go:129-153`) — the package's own allowlist
entry, the one place in `pkg/quantum` where this project keeps one at all.
ML-KEM-768/1024 and every ML-DSA level need no such check: they call straight
into `crypto/mlkem` / `crypto/mldsa`, and those stdlib functions refuse on
their own when the linked Go Cryptographic Module version does not yet
certify the algorithm (`pkg/keyprovider/quantum/backend.go:14-20`,
`pkg/quantum/mldsa65/mldsa65.go:17-21`). `go doc crypto/mldsa` states the
module-version boundary explicitly: ML-DSA is unavailable under Go
Cryptographic Module v1.0.0 and available from v1.26.0.

The `MLKEMPrivateKey.Encrypt`/`Decrypt` helpers that wrap ML-KEM's shared
secret in AES-256-GCM use `cipher.NewGCMWithRandomNonce`, not `cipher.NewGCM`
— the module-generated-IV construction SP 800-38D / CMVP IG C.H requires
under `GODEBUG=fips140=only`
(`pkg/keyprovider/quantum/signer.go:385-393`). This is the same construction
and the same reasoning documented in full in
[`../symmetric-aead/architecture.md`](../symmetric-aead/architecture.md)
§"GCM nonce modes and FIPS"; the quantum backend does not re-derive it, it
reuses the stdlib primitive directly rather than importing `pkg/crypto/aead`.

## The PKCS#11 module: three parameter sets implemented, four more advertised and refused

`pkg/pkcs11/module` implements the OASIS PKCS#11 v3.2 CSD01 standard
mechanism range for PQC (`pkg/pkcs11/module/mechanism_v32.go:14-37`), backed
by the same `pkg/quantum/*` primitives: `dilithium2`, `mldsa65`, `mldsa87`,
`mlkem512`, `kyber768`, `mlkem1024`
(`pkg/pkcs11/module/crypto_quantum.go:14-34`). `CKM_SLH_DSA`,
`CKM_HASH_SLH_DSA` (and its eight per-hash variants), `CKM_HSS` and `CKM_XMSS`
/ `CKM_XMSSMT` mechanism type constants and their PKCS#11 v3.2 names are all
declared (`mechanism_v32.go:110-184`), but every one of them carries `Flags:
0` — no `CKF_GENERATE_KEY_PAIR`, `CKF_SIGN` or `CKF_VERIFY` — and every
`*Init` call refuses them with `CKR_MECHANISM_INVALID` at the gate. The
descriptors exist only so the mechanism-type constant resolves and
`C_GetMechanismInfo` can describe it; there is no SLH-DSA, HSS or XMSS
implementation behind any of them
(`pkg/pkcs11/module/mechanism_v32.go:441-467`). This is a deliberate fix, not
an oversight left in place: an earlier version advertised `CKF_SIGN` for
`CKM_SLH_DSA`, which made `C_SignInit` answer `CKR_OK` and the operation then
fail from the backend — the caller learned the token could not do it only
after committing to it.

## Two independent gaps between "implemented" and "reachable"

Both gaps are documented in full, with the exact symptom and the exact fix
needed, in [`engineering.md`](engineering.md) §"What is absent, half-built,
or misdescribed" and in [`api.md`](api.md) / [`cli.md`](cli.md); they are
named here because they shape every other document in this folder:

1. **No AEAD-safety persistence.** `pkg/keyprovider/quantum.QuantumBackend`
   tracks ML-KEM's internal AES-GCM nonce/byte usage through
   `types.AEADSafetyTracker`, but the only implementation in this repository,
   `backend.NewMemoryAEADTracker` (`pkg/backend/aead_tracker.go:29-56`), is
   in-memory and does not survive a process restart. Its own doc comment says
   production systems should use a persistent tracker; none exists.
2. **No network or CLI surface for quantum key generation.** `types.
   QuantumAttributes` is re-exported by the SDK (`sdk/go/types.go:65-69`),
   but nothing in `pkg/api/rest`, `pkg/api/grpc` or `cmd/xkmsctl` constructs
   one. The only way to reach `QuantumBackend.GenerateKey` is to embed
   go-xkms as a library and call it directly, or to go through the PKCS#11
   module.

## Rejected alternatives

- **A single "quantum" algorithm enum spanning KEM and signature.** Rejected:
  `types.QuantumAlgorithm` already splits by `IsSignature()`/`IsKEM()`
  (`pkg/keyprovider/quantum/backend.go:229-239`), and a KEM key and a
  signature key have disjoint operations (`Signer` vs.
  `Encapsulate`/`Decapsulate`) — collapsing them would force one of the two
  to expose methods that panic or error unconditionally.
- **Storing the expanded private key instead of the seed.** Rejected: the
  seed is smaller, is the representation FIPS 203/204 define for key
  transport and storage, and lets `GetKey` re-derive byte-identical key
  material without a second serialization format per algorithm.
- **A shared allowlist of "FIPS-approved" PQC algorithms maintained by this
  project.** Rejected per the project-wide rule
  (`docs/README.md` links this to `fips-stdlib-only`): FIPS enforcement for
  the algorithms the Go Cryptographic Module implements is the stdlib's job.
  The one exception — `pkg/quantum/mlkem512`'s own `fips140.Enabled()` check
  — exists only because CIRCL is invisible to the module boundary, not
  because this project second-guesses the module's own decisions.
