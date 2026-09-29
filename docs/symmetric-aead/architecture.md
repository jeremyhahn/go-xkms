# Symmetric Encryption & AEAD — Architecture

> **Status: NORMATIVE** · Feature: `symmetric-aead` · Repo: `go-xkms` · Last verified: 2026-09-29

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

## AEAD safety tracking: a bytes-budget seam, and a separate nonce guard

`types.AEADSafetyTracker` (`pkg/types/types.go:2802-2822`) is now a
five-method interface covering only the NIST SP 800-38D bytes-encrypted
budget — `IncrementBytes`, `GetBytesEncrypted`, `GetAEADOptions`/
`SetAEADOptions`, `ResetTracking` — that every AEAD encryption call in this
backend still checks first (`backend.go:585-590`). Nonce-reuse used to be
part of this interface too (`CheckNonce`/`RecordNonce`); go-xkms#1201 removed
it, because that design checked and recorded in two separate, non-atomic
steps (a TOCTOU race two concurrent callers could both win), was scoped per
backend *instance*, so a second instance over the same storage — the shape a
restart takes — never saw a key the first instance generated, and covered
only callers reaching a key through `XKMSService`: a caller holding a
`symmetric.Backend`/`quantum.QuantumBackend` directly got no nonce-reuse
protection at all. See "One process-wide claim, made inside `Encrypt`
itself" below for what replaced it. The same bytes-budget sequence is reused
verbatim by [`../post-quantum/architecture.md`](../post-quantum/architecture.md)'s
`MLKEMPrivateKey.Encrypt` for the AES-256-GCM layer over an ML-KEM shared
secret (`pkg/keyprovider/quantum/signer.go`) — one tracker interface, two
independent call sites.

There is exactly one implementation of `AEADSafetyTracker` in this
repository: `backend.NewMemoryAEADTracker`
(`pkg/backend/aead_tracker.go:51`), in-memory, with its own doc comment
stating "Production systems should use persistent storage (file-based or
database)." None exists for the bytes budget; see
[`engineering.md`](engineering.md) §"What is absent" for what this means
operationally. This gap no longer applies to nonce-reuse protection, which
the guard below makes durable and process-independent regardless of this
tracker's state.

`types.DefaultAEADOptions()` (`pkg/types/types.go:499-506`) is
`NonceTracking: true, BytesTracking: true, BytesTrackingLimit: 350GB,
NonceSize: 12` — the 350GB figure is this project's own choice of headroom
under the NIST SP 800-38D AES-GCM safety bound, not a value SP 800-38D itself
names.

## Caller-supplied nonces: one process-wide claim, made inside `Encrypt` itself

go-xkms#1201 was reported and fixed in two halves. The first gave the
service-layer guard a durable, persistent backing (see below). The second
— this section — closed a gap that remained even after that: the claim lived
in `XKMSService.Encrypt`/`wrapAESGCM`, so it protected a caller that reached a
key through `XKMSService`, but a caller holding a
`symmetric.Backend`/`azurekv.Backend`/`pkcs11.Backend`/`tpm2.TPM2`/
`quantum.QuantumBackend` directly (`sdk/go`, `xkey`) bypassed it entirely and
had only the old, non-atomic, per-instance `AEADSafetyTracker` described
above — or, for PKCS#11/TPM2/cloud-KMS backends, no nonce tracking at all.

The claim now lives at the one layer both callers pass through: inside each
backend's own `Encrypt` implementation, immediately before `Seal`.
`pkg/backend`'s `ClaimAEADNonce`/`ClaimGeneratedAEADNonce`
(`aead_nonce.go:75`, `:112`) are the single point every AEAD `Encrypt` path
calls — the software symmetric backend (`pkg/keyprovider/symmetric/
backend.go:561` `claimNonce`), Azure Key Vault
(`pkg/backend/azurekv/azurekv_symmetric.go`), PKCS#11
(`pkg/backend/pkcs11/pkcs11_symmetric.go`), TPM2 (`pkg/tpm2/symmetric.go`),
and the quantum KEM hybrid encrypter (`pkg/keyprovider/quantum/signer.go`,
`encryptWithAESGCM`) alike:

- **Caller-supplied nonce (`opts.Nonce != nil`):** claimed with
  `ClaimAEADNonce`, which refuses outright once the guard's bounded
  in-memory tracker is full (`aead.ErrNonceTrackerFull`) — the guard can no
  longer promise it would notice a repeat, so a caller-chosen nonce is not
  vouched for.
- **Backend-generated nonce (`opts.Nonce == nil`):** claimed with
  `ClaimGeneratedAEADNonce`, which tolerates a full guard: a generated nonce
  is fresh by construction (NIST SP 800-38D §8.2.2), so its own ciphertext is
  safe regardless of whether the guard has room to record it, and once the
  guard is full every caller-supplied nonce is already refused, so an
  unrecorded generated nonce cannot be replayed either. A genuine repeat —
  full guard or not — is still refused (`aead.ErrNonceReuse`).
- **CBC/ECB:** not claimed. They take an IV, not an AEAD nonce.

`XKMSService.Encrypt` and `wrapAESGCM` no longer claim anything themselves
(`pkg/xkms/servicer_crypto.go:653`, `pkg/xkms/servicer_wrapkey.go:532`): they
call `encrypter.Encrypt` exactly as before, and the backend's own claim is
now the only one made for that request. Claiming at both layers, as the
first half of go-xkms#1201 left it, would claim the same pair twice for a
request that arrives through the service — refusing the very first call as a
false reuse — so the old `pkg/xkms/aead_nonce_guard.go` (`claimAEADNonce`,
`claimGeneratedAEADNonce`, `aeadKeyIdentity`) was deleted rather than kept
alongside the new backend-layer claim.

Both claim functions resolve the key identity through `aeadNonceIdentity`
(`aead_nonce.go:133`): the key's own material, passed in by the caller
exactly as the backend already has it in hand for the encryption itself (the
software symmetric backend's `keyBytes`, Azure Key Vault's locally-generated
`keyData`, TPM2's `loadKeyMaterial` result — unsealed into process memory for
this call even though the backend's public `SymmetricKey.Raw` still refuses
to release it), so the same physical key reached under two names or two
backend instances collides on one guard entry; or, when no in-process
material exists at all (PKCS#11, whose key never leaves the token),
`sealedAEADKeyDomain + sealedID`, where `sealedID` is `attrs.ID()` — already
encoding tenant, partition, backend, key type, common name and algorithm.
Neither function takes ownership of or wipes the caller's key material: it
is only read, the same way `KeyNonceGuard`'s own HMAC derivation reads it.

Both resolve to `aead.SharedAEADNonceGuard`
(`pkg/crypto/aead/key_nonce_guard.go`). `KeyNonceGuard.UseContext` checks and
records under one lock, then claims through any attached
`PersistentNonceStore` too (`key_nonce_guard.go:89`,
`nonce_tracker.go:133-156`).

The PKCS#11 module claims a `C_EncryptInit` caller IV in its own process under
`remoteKeyGuardDomain + backend + key id`
(`pkg/pkcs11/module/crypto.go:1948`, `:1987`) before sending the request. That
identity and `aeadNonceIdentity`'s sealed-key identity are domain-separated
and never collide, so a module call succeeds exactly once per IV. The
module's claim stops a repeat in that process, and the PKCS#11 backend's own
claim (reached once the module's request lands, whether directly or through
`XKMSService`) stops a repeat across module processes and every other
caller.

**Persistence: a durable claim, not process memory alone.** The guard's own
tracker is process memory — its salt is drawn at first use and its entries die
with the process — but `pkg/server`'s `initializeAEADNonceStore` attaches a
`pkg/aeadnonce.Store` to `aead.SharedAEADNonceGuard` at startup, built over the
same `createStorage` seam every other durable subsystem in this server uses
(`pkg/pkcs11state`, `pkg/staticpw`). `KeyNonceGuard.UseContext` — what
`ClaimAEADNonceIn`/`ClaimGeneratedAEADNonceIn` call, so every backend's
`Encrypt` uses it, whether reached through `XKMSService` or directly — claims
through that store in addition to the in-memory tracker, via
`storage.Backend.PutIfAbsent`, so the atomic claim-then-seal property holds
whether the check is the first one in the process or the millionth one after a
restart. The store's key is `persistentEntry`, a fixed-domain HMAC over the
key material (deliberately NOT salted with the guard's own per-process random
salt, which would make the same pair derive a different identity after every
restart and defeat the whole point); see `pkg/crypto/aead/key_nonce_guard.go`.
When `Storage.Backend` is `qrdb`, the claim is replicated to every node in the
cluster through the embedded qrdb node, exactly as `pkg/pkcs11state`'s and
`pkg/staticpw`'s records are; with the (also supported) `pebble`/`file`/`memory`
backends the claim is durable per node but not shared across a cluster. See
[go-xkms#1201](https://github.com/jeremyhahn/go-xkms/issues/1201) for the
spec grounding this rests on: PKCS#11 v3.2 §6.13.1–§6.13.2 (`CK_GCM_PARAMS`
always takes a caller-supplied `pIv`; `CK_GCM_MESSAGE_PARAMS`'s `ivGenerator`
makes `CKG_GENERATE` (module-generated) mandatory and `CKG_NO_GENERATE`
(caller-supplied) optional but explicitly supported) and KMIP v1.4 §3.6 /
§4.29 (`Random IV` is an opt-in server-generation request; otherwise "the
IV/Counter/Nonce" travels in the client's request, and "the server does not
store or otherwise manage" it) both permit a caller-supplied nonce as the
default case, so the fix is a durable, atomic guard over that case rather than
removing it.

`pkg/pkcs11/module`'s own in-process claim (`guardGCMNonce`, above) is
unaffected: it calls the plain `Use`, not `UseContext`, because it sits behind
a C ABI with no `context.Context` to thread through and has no reason to carry
a storage dependency into a cgo-loaded client library. Its guarantee is
unchanged — it stops a repeat within its own process — and the service's
persistent claim is what stops one across a restart, across module processes,
and across direct REST/gRPC/MCP callers.

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
- **Keeping the service-layer claim (`pkg/xkms/aead_nonce_guard.go`)
  alongside the new backend-layer claim, so both `XKMSService` and a direct
  `Backend` caller were covered.** Rejected: `XKMSService.Encrypt` and
  `wrapAESGCM` both reach the guarded pair through `encrypter.Encrypt`, so a
  second claim at the service layer would claim the same pair twice for
  every request that arrives through the service, refusing the first,
  legitimate call as a false reuse. Backend `Encrypt` is the lowest layer
  common to both callers, so it is the only place that can claim once for
  both; go-xkms#1201.
- **Identifying every backend's key by `attrs.ID()` alone, including the
  ones that hold material in process (software symmetric, Azure Key Vault,
  TPM2).** Rejected: `KeyNonceGuard`'s whole premise is that the safety
  property belongs to the key's bytes, not to whatever name currently
  addresses them (see `pkg/crypto/aead/key_nonce_guard.go`'s own doc
  comment) — an identifier-keyed guard cannot see one key reachable under
  two names, two backend instances, or a restart, which is exactly the
  aliasing go-xkms#1201 also needed closed. `aeadNonceIdentity` therefore
  prefers material wherever a backend has it in process, and falls back to
  `attrs.ID()` only for PKCS#11, whose key never leaves the token at all.
