# Signing — Architecture

> **Status: NORMATIVE** · Feature: `signing` · Repo: `go-xkms` · Last verified: 2026-09-24

## The problem

A valid signature proves a key produced a signature over *some* digest; it
does not prove that digest is the one a caller believes it signed. A caller
who names a blob by an identifier (a release, a config version, a policy
document) and later re-fetches "the same blob" from storage it does not fully
trust has no way, from the signature alone, to catch a swap: a second blob
validly signed by the same key verifies exactly as well as the first one did.

`pkg/verification` (ported from `go-trusted-platform-original`'s
`keystore/verifier.go`) shipped a `ChecksumProvider` for exactly this, and a
`Verifier` that consulted it — but nothing in go-xkms ever constructed that
`Verifier`. The live verifier was, and is, `types.SimpleVerifier`
(`pkg/xkms/service.go`'s package-level `Verify`), which had no integrity-check
concept at all. Symmetrically, `pkg/tpm2/store.SignerStore.SaveSignature` — the
persistence half — had zero callers. Both halves existed; neither was wired to
the other, and neither was wired to the live path (go-xkms#697, go-xkms#724).

## Shape chosen: merge the checksum check into the live verifier, persist through the same seam every backend already has

`types.VerifyOpts` gained three fields: `BlobCN string`, `IntegrityCheck
bool`, and `ChecksumProvider` (the interface merged in from
`pkg/verification`, unchanged in shape). `SimpleVerifier.Verify` runs its
existing cryptographic check first, unconditionally, and only then — when
`IntegrityCheck` is set — compares the digest just verified against
`ChecksumProvider.Checksum(opts)`. A tampered-but-validly-signed substitute
blob fails at this second step even though the first step passed.

`SignOptions` (`pkg/xkms/service.go`) gained one field, `BlobCN string`,
mirroring `signing.SignerOpts.BlobCN`. When set, `Sign` persists the digest
and signature it produced through `Backend.SignerStore().SaveSignature`,
keyed by the signing key's `KeyAttributes.CN` and `BlobCN`. `Verify` reads it
back the same way: when `VerifyOpts.IntegrityCheck` is set and the caller left
`ChecksumProvider` nil, `Verify` fills it in from `Backend.SignerStore()`.

`Backend.SignerStore() store.SignerStorer` (`pkg/xkms/keystore.go`) is the new
method that makes this "every backend the live signing path supports" rather
than "every backend that happens to be TPM2". `store` here is
`pkg/signing/store`: a package with no TPM dependency at all, not merely an
implementation that happens not to need one (see "Rejected alternatives" for
the one-commit history of that distinction). Since every `xkms.Backend` is a
`compositeBackend` composing *some* `types.KeyProvider` (TPM2, PKCS#11, a
cloud KMS, software, phone) with one `storage.Backend` shared for external
metadata, `New()` builds one `store.SignerStore` from that same
`storage.Backend` — the one already used for `CertStorage()` — for every
backend, unconditionally. A signature record is metadata about a signing
operation the same way a certificate is metadata about a key; it persists the
same way, through the same seam, for the same reason.

`store.SignerStore` gained the read-back half, `GetSignature`, and a
`Checksum(opts *types.VerifyOpts) ([]byte, error)` method that satisfies
`types.ChecksumProvider` directly by structural typing — no adapter type
exists between the two.

`store.SignerStore` keys every record — crypto.Signer material via
`Get`/`Save`/`Delete`, and signature records via
`SaveSignature`/`GetSignature`/`Checksum` — off `KeyAttributes.CN` (and
`BlobCN` for signatures) alone; it has no `KeyAttributes.TenantID` concept, by
design, since it is not itself multi-tenant-aware. `TenantScopedBackend`,
which is, wraps the base store's `SignerStore()` in
`tenantScopedSignerStore`: every method scopes `KeyAttributes.CN` to
`"{tenantID}/{cn}"` before delegating, the same string-prefix mechanism
`scopeCertKeyID` already applies to certificate key IDs. Two tenants signing
under the same CN and the same `BlobCN` against one shared `compositeBackend`
therefore land in different records, not the same one — see
`TestTenantScopedBackend_SignerStore_IsolatesTenantsOnSameBlobCN`
(`pkg/xkms/backend_tenant_test.go`) for the two-tenant round trip this
guarantees.

## Rejected alternatives

- **Wiring persistence inside `pkg/tpm2` only.** `pkg/tpm2.Params` (formerly
  documented here as `pkg/tpm2.Config`) carried a `SignerStore` field
  (`pkg/tpm2/tpm.go`) that nothing read — the most direct place to "finish"
  `SaveSignature` for TPM2 alone. Rejected: the company standard for a new
  behavior on a multi-backend interface is a complete implementation for
  every backend in the same change, and TPM2 is one of eight. The field was
  dead config with the move described below already superseding its would-be
  purpose, so it was deleted rather than left as an unread field for a future
  change to trip over (go-xkms#724 review).
- **Leaving the generic signer/signature store under `pkg/tpm2/store`.** The
  first cut of this feature did exactly that: `SignerStore`'s implementation
  was already backend-agnostic (`storage.Backend` in, `qrdbsdk.GenericDAO`
  out — the same pattern `pkg/acme`, `pkg/staticpw` and `pkg/trust/clusterca`
  use against their own unrelated `storage.Backend` instances), so only its
  package path was wrong, and `pkg/xkms` importing `pkg/tpm2/store` compiled
  and passed every test. Rejected on review anyway: a new
  `pkg/xkms` → `pkg/tpm2/store` dependency for code that is not TPM-specific
  misrepresents ownership regardless of whether it compiles, and the
  `pkg/tpm2/store` package itself mixed genuinely TPM-specific code (blob and
  PCR-policy storage) with this generic part in the same directory. Moved to
  `pkg/signing/store` instead — this package, alongside the pre-existing
  `pkg/signing` (the `crypto.Signer` wrapper with `BlobCN`-aware
  `SignerOpts`) — leaving `pkg/tpm2/store.SignerOpts` (the *different*,
  TPM-specific type with the same name, carrying `Backend`/`PSSOptions` for
  `TPM2.Sign`'s own `crypto.SignerOpts` duty — see `pkg/tpm2/sigscheme.go`
  `isPSSRequest` and `pkg/tpm2/tpm.go`'s `Sign`) and the TPM-specific
  blob/PCR-policy code behind in `pkg/tpm2/store`, genuinely untouched. The
  two `SignerOpts` types were already serving unrelated purposes under one
  name in one package before this feature existed; splitting them apart by
  package is what the move fixed, not a side effect of it.
- **A brand-new adapter type implementing `types.ChecksumProvider` over
  `store.SignerStorer`.** Rejected as an unnecessary abstraction layer:
  `store.SignerStore.Checksum` has the exact signature
  `types.ChecksumProvider` requires and already imports `pkg/types`, so it
  implements the interface directly.
- **Folding tenant scoping into `store.SignerStore` itself (e.g. an optional
  `TenantID` field consulted by `signatureKey`).** Rejected: `pkg/signing/store`
  has no tenant concept anywhere else in its API, and every other
  multi-tenant seam in this codebase (certificates, key generation) scopes at
  the `TenantScopedBackend` decorator layer, never inside the store it wraps.
  Adding a `TenantID`-aware branch to `signatureKey` would give
  `pkg/signing/store` two different identity models depending on whether a
  caller reached it directly or through `TenantScopedBackend`, and would run
  for every caller — including the common single-tenant deployment — instead
  of only where tenancy actually exists.
