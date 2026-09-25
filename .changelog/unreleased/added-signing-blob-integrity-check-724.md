- **Sign and Verify now support a persisted, per-blob integrity check,
  wired for every backend behind the `xkms.Backend` interface (TPM2,
  PKCS#11, AWS/Azure/GCP KMS, Vault, software, phone), tenant-isolated.**
  `SignOptions.BlobCN` persists the produced digest and signature through
  the backend's `SignerStore` when set; a later `Verify` call with matching
  `types.VerifyOpts.BlobCN` and `IntegrityCheck: true` confirms the digest
  being verified against that persisted record, catching a validly signed
  substitute blob that a cryptographic signature check alone would pass.
  `types.ChecksumProvider` (merged in from the former `pkg/verification`
  package) supplies the persisted checksum; the new `pkg/signing/store`
  package's `SignerStore` implements it directly via new `GetSignature`
  read-back, and `xkms.Backend.SignerStore()` exposes one `SignerStorer` per
  backend, shared with certificate storage since a signature record is
  metadata about a signing operation the same way a certificate is metadata
  about a key. `TenantScopedBackend.SignerStore()` wraps it in
  `tenantScopedSignerStore`, prefixing the signing key's CN with the tenant
  ID the same way `scopeCertKeyID` already scopes certificates, so two
  tenants signing under the same key CN and `BlobCN` never collide or read
  each other's record. Leaving `IntegrityCheck` unset keeps the pre-existing
  signature-only behavior unchanged. **BREAKING (internal API only, no
  released consumers):** the generic signer/signature store moved from
  `pkg/tpm2/store` to the new `pkg/signing/store` — it had no TPM dependency,
  and `pkg/xkms` importing `pkg/tpm2/store` for it misrepresented ownership.
  `pkg/tpm2/store.SignerOpts` (the *different*, TPM-specific type used by
  `TPM2.Sign`) is unaffected and stays put; its dead, unread `BlobCN` field is
  removed, as is the unread `pkg/tpm2.Params.SignerStore` field and the
  `sdk/go` `TPMSignerStorer` alias to the interface that moved.
  `pkg/verification`, whose `ChecksumProvider` was never wired to a live
  verifier, is deleted; `types.SimpleVerifier` is the only verifier now.
  Files: `pkg/types/types.go`, `pkg/signing/store/` (new),
  `pkg/tpm2/store/interfaces.go`, `pkg/tpm2/tpm.go`, `sdk/go/tpm.go`,
  `pkg/xkms/{keystore,composite,backend_tenant,service}.go`, plus their
  tests; `pkg/verification/` removed. Fixes go-xkms#724.
