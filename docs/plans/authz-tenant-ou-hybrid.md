# authz-tenant-ou, slice 2: hybrid leaf certificates (lane stenoub)

Row: authz-tenant-ou (docs/SPEC.md:72), epic #2089. Stacked on lane stenoua
(PIV self-signed + xkmsd bootstrap stamped, `StampTenant` in pkg/certsubject).

## Paths

1. `CreateHybridCertificate` (pkg/ca/hybrid.go) signs the caller's template
   subject as is, so a hybrid leaf names a caller-chosen OU.
2. Virtual-authenticator attestation CSR
   (pkg/fido2/authenticator/attestation.go:183-186): Subject-OU fixed by
   WebAuthn Level 2 §8.2.1, so it is exempt, as the FIDO2 profile is.

## Rule

`CreateHybridCertificate` gains a leading `tenantID string`. A leaf template
(`!template.IsCA`) is stamped on the working copy with `StampTenant`, before
the first `issuer.Sign`; an error returns `&HybridCertError{Op: "create"}`
wrapping `ErrTenantRequired`. CA templates keep their subject and may pass an
empty tenant. The caller's template is never modified.

## Steps

1. Test commit: pkg/ca/hybrid_tenant_ou_test.go (leaf OU = tenant, both
   signatures verify; empty tenant on a leaf refused; CA template unchanged;
   caller template unchanged); existing call sites pass `""`.
2. Fix commit: pkg/ca/hybrid.go.
3. Docs commit: engineering.md invariants (hybrid stamped, attestation CSR
   exempt), changelog entry.
4. Checks: go test ./pkg/ca/... ./pkg/certsubject/... and make lint.

## Results

- Hybrid leaves stamped at pkg/ca/hybrid.go:145-152 (test commit before the
  fix commit); engineering.md lists the hybrid path as stamped and the
  attestation CSR (attestation.go:183-186) as exempt.
- `go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/ca/...
  ./pkg/certsubject/...`: pass.
- `make lint` (root, all modules and tag sets): pass, 0 issues.
- Every path in SPEC.md:72's "does not carry it today" list is now stamped
  or exempt with a reason, so the coordinator can set the row (docs/SPEC.md
  not edited by this lane).
