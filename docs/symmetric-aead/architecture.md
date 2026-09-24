# Symmetric Encryption & AEAD — Architecture

> **Status: NORMATIVE** · Feature: `symmetric-aead` · Repo: `go-xkms` · Last verified: 2026-09-24

## The problem

A KMS that only issues asymmetric keys cannot serve envelope encryption,
data-at-rest protection, or any workload where the caller wants a raw secret
key rather than a signer. go-xkms needs symmetric keys to be first-class:
generated, stored, rotated and used for authenticated encryption through the
same backend/service/transport layering as every other key, with cryptographic
nonce-reuse and byte-limit safety built into the encryption path rather than
left to the caller.

## Shape chosen: a software `Backend` implementing `types.SymmetricKeyProvider`

`pkg/keyprovider/symmetric.Backend` (`backend.go:71-79`) generates AES-GCM and
ChaCha20/XChaCha20-Poly1305 keys and stores raw key bytes (not PKCS#8) through
the generic `storage.Backend` seam, so a symmetric key inherits the same
persistence, barrier-encryption-at-rest, and file-naming convention
(`[partition:]sw:secret:cn:algorithm`) as every other backend without a
parallel store. `GenerateSymmetricKey`/`GetSymmetricKey` are the symmetric
counterparts of `GenerateKey`/`GetKey`; calling the asymmetric
`GenerateKey`/`GetKey`/`Signer`/`Decrypter` methods on this backend returns
`backend.ErrOperationNotSupported` (`backend.go:178-188`, `:312-320`) rather
than silently doing something unexpected.

`SymmetricEncrypter` (`types.SymmetricEncrypter`, obtained from
`Backend.SymmetricEncrypter`) is the encryption-side analog of
`crypto.Signer`: an object bound to one already-generated key that performs
`Encrypt`/`Decrypt`, decoupling "here is a key" from "here is an operation on
it" the same way `crypto.Signer` decouples key possession from the act of
signing.

## Four cipher modes behind one `Encrypt`/`Decrypt` pair

`types.EncryptOptions.Mode` / `types.DecryptOptions.Mode` select among:

| Mode | Constant | AEAD? | Key requirement |
|---|---|---|---|
| default (empty string) | — | yes — AES-GCM or ChaCha20/XChaCha20-Poly1305, by key algorithm | any symmetric key |
| unpadded CBC | `types.CipherModeCBC` | no | AES key only |
| PKCS#7-padded CBC | `types.CipherModeCBCPad` | no | AES key only |
| ECB | `types.CipherModeECB` | no | AES key only |

CBC and ECB exist because PKCS#11 v3.2 defines `CKM_AES_CBC`,
`CKM_AES_CBC_PAD` and `CKM_AES_ECB` as mechanisms this module advertises
(`backend.go:921-923`, `:986-996`); the backend implements what it advertises
rather than serving a different mode silently underneath an accepted request.
ECB's own doc comment states the tradeoff without hedging: it is
deterministic and leaks plaintext block structure, and it exists "because
PKCS#11 v3.2 §6.10.4 defines the mechanism and this module advertises it; a
mechanism that is advertised and then quietly served by some other mode is
worse than either offering it or refusing it" (`backend.go:986-996`). CBC
decryption's PKCS#7 unpadding runs its own constant-time check regardless of
*why* padding was invalid, closing the Vaudenay 2002 CBC padding-oracle
class rather than trusting mode-selection alone to prevent it
(`backend.go:1162-1203`).

AES-CBC and AES-ECB take no additional authenticated data, no tag, and (for
ECB) no IV; supplying any of those to the CBC/ECB path is a typed error
(`ErrAdditionalDataNotSupported`, `ErrTagSizeNotSupported`,
`ErrIVNotSupported`) rather than a silently ignored parameter
(`backend.go:929-937`, `:1005-1013`).

## AEAD safety tracking: a seam every AEAD path calls through, one implementation

`types.AEADSafetyTracker` (`pkg/types/types.go:2751-2779`) is a five-method
interface — `CheckNonce`, `RecordNonce`, `IncrementBytes`,
`GetBytesEncrypted`, `GetAEADOptions`/`SetAEADOptions`, `ResetTracking` — that
every AEAD encryption call in this backend goes through in the same order:
check the bytes limit, generate or accept a nonce, check the nonce hasn't
been used, encrypt, record the nonce
(`backend.go:551-737` documents the five steps explicitly in-line). The same
sequence is reused verbatim by
[`../post-quantum/architecture.md`](../post-quantum/architecture.md)'s
`MLKEMPrivateKey.Encrypt` for the AES-256-GCM layer over an ML-KEM shared
secret (`pkg/keyprovider/quantum/signer.go:379-423`) — one tracker interface,
two independent call sites.

There is exactly one implementation of `AEADSafetyTracker` in this
repository: `backend.NewMemoryAEADTracker`
(`pkg/backend/aead_tracker.go:29-56`), in-memory, with its own doc comment
stating "Production systems should use persistent storage (file-based or
database)." None exists. See [`engineering.md`](engineering.md) §"What is
absent" for what this means operationally.

`types.DefaultAEADOptions()` (`pkg/types/types.go:499-506`) is
`NonceTracking: true, BytesTracking: true, BytesTrackingLimit: 350GB,
NonceSize: 12` — the 350GB figure is this project's own choice of headroom
under the NIST SP 800-38D AES-GCM safety bound, not a value SP 800-38D itself
names.

## GCM nonce modes and FIPS

`cipher.NewGCM` (Go's ordinary, caller-supplied-IV AES-GCM constructor) is
refused outright by the Go runtime under `GODEBUG=fips140=only` — FIPS 140-3
(SP 800-38D, CMVP IG C.H) requires the module itself generate the GCM IV, not
accept one from outside the module boundary. `crypto/fips140.Enabled()`
cannot distinguish `fips140=on` (where `NewGCM` still works) from
`fips140=only` (where it panics/errors), so `pkg/crypto/aead.
ArbitraryIVGCMUsable()` probes the actual construction once per process and
caches the answer (`pkg/crypto/aead/gcm_usable.go:22-51`) rather than relying
on a static predicate.

`pkg/crypto/aead.NewGCMForFreshEncrypt` (`random_nonce.go:71-97`) is the
resulting selection function every AES-GCM encryption path in this project
calls through (directly, in `pkg/keyprovider/symmetric`; independently
reimplemented for the same reason in `pkg/keyprovider/quantum` and in
password/key storage — see below):

- If arbitrary-IV GCM is usable (the default; `fips140=on` included): always
  `cipher.NewGCM`, exactly as before FIPS support existed. Nothing changes
  for existing callers or existing ciphertexts.
- If it is not (`fips140=only`) **and** the caller left the nonce to be
  generated **and** requested the full 128-bit tag — the one combination
  `cipher.NewGCMWithRandomNonce` supports — that constructor is substituted.
  Its `NonceSize()` is zero: `Seal` is called with a nil nonce argument and
  generates and prepends its own 96-bit nonce to the output, which must be
  split back out (`aead.SplitGCMWithRandomNonce`) before storage.
- Every other combination under `fips140=only` — a caller-supplied nonce, or
  a truncated tag — fails closed with `ErrArbitraryIVGCMUnavailable`, because
  there is no substitute construction that can honor either request.

`types.GCMNonceMode` (`pkg/types/types.go:1910-1941`) records, per
`EncryptedData`, which construction produced it (`GCMNonceModeExplicit`, the
zero value and every pre-FIPS ciphertext; `GCMNonceModeRandom`), so
`NewGCMForDecrypt` (`random_nonce.go:99-131`) can pick the matching
construction regardless of which FIPS posture the *current* process runs
under — a ciphertext written under `fips140=only` decrypts under
`fips140=on` later, and vice versa where the construction is still available.

The identical `NewGCMWithRandomNonce` substitution appears independently at
three sites in this codebase, all citing the same SP 800-38D / CMVP IG C.H
rationale: symmetric-key AEAD encryption (`backend.go:648-711`), password-based
key-wrapping for stored symmetric keys
(`storeSymmetricKey`/`encryptWithPassword`, `backend.go:1263-1300`), and
ML-KEM's internal AES-256-GCM layer
(`pkg/keyprovider/quantum/signer.go:379-423`). `pkg/crypto/aead` is the one
place that rationale and the fallback logic are written down in full; the
other two call its exported functions (`NewGCMForFreshEncrypt` in
`pkg/keyprovider/symmetric`) or replicate the identical `cipher.
NewGCMWithRandomNonce` call directly (`pkg/keyprovider/quantum`, which does
not import `pkg/crypto/aead`).

## Auto-selected cipher (a separate, narrower mechanism)

`pkg/crypto/aead`'s package-level `SelectOptimal`/`SelectOptimalBackend`
functions (`auto.go`) choose AES-256-GCM vs. ChaCha20-Poly1305 by CPU AES-NI
capability and by whether the key is hardware-backed, always forcing
AES-256-GCM in FIPS mode because ChaCha20-Poly1305 is not FIPS-approved
(`auto.go`'s package doc, "FIPS 140-3" section). This selection logic is
independent of the nonce-mode logic above — it answers "which algorithm,"
not "which GCM IV construction" — and is not wired into
`pkg/keyprovider/symmetric.Backend.GenerateSymmetricKey`, which takes the
algorithm from the caller's `attrs.SymmetricAlgorithm` rather than
auto-selecting one; see [`engineering.md`](engineering.md).

## Rejected alternatives

- **A separate symmetric-key store from `storage.Backend`.** Rejected: every
  other backend already persists through the same seam, and a second store
  would duplicate barrier-encryption-at-rest wiring for no benefit.
- **Silently serving CBC/ECB requests through GCM (or refusing the mechanism
  outright).** Rejected for the reason `encryptECB`'s own doc comment gives:
  advertising a mechanism and serving it with a different, silently-chosen
  mode is worse than either honoring the caller's explicit choice or refusing
  it outright.
- **A package-local AEAD-safety allowlist duplicating `AEADSafetyTracker`.**
  Rejected: the interface already exists in `pkg/types` for the whole
  project; `pkg/keyprovider/symmetric` and `pkg/keyprovider/quantum` share it
  rather than each keeping its own bookkeeping.
