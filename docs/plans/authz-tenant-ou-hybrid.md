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

- Hybrid leaves stamped at pkg/ca/hybrid.go:146-153 (test commit before the
  fix commit); engineering.md lists the hybrid path as stamped and the
  attestation CSR (attestation.go:183-186) as exempt.
- `go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/ca/...
  ./pkg/certsubject/...`: pass.
- `make lint` (root, all modules and tag sets): pass, 0 issues.
- Every path in SPEC.md:72's "does not carry it today" list is now stamped
  or exempt with a reason, so the coordinator can set the row (docs/SPEC.md
  not edited by this lane).
- Ship slice (lane row2089b): docs/SPEC.md row `authz-tenant-ou` set to
  `shipped`; its list now names each path as stamped or exempt with its
  reason, every file:line re-checked against this HEAD, and the proving tests
  (hybrid, PIV, bootstrap) named.

## Codex review (lane-verify, row2089b)

- Finding 1 (security, pkg/ca/hybrid.go): a raw subject with two OUs in one
  RDN SET could let DER SET sorting put another OU ahead of the tenant.
  `StampTenant` (pkg/certsubject) now refuses such a subject with
  `ErrInvalidRawSubject`. Test 97d43d931, fix e21d81961.
- Finding 2 (pkg/ca/hybrid.go): a self-signed hybrid leaf (parent ==
  template) kept the unstamped issuer; the issuer is now a stamped copy of
  the template. Test 97d43d931, fix e21d81961.
- Finding 3 (pkg/factor/piv/factor.go): the PIV factor enrollment
  certificate bypassed `StampTenant`. `Enroll` stamps `params.TenantID` and
  refuses an empty tenant; `DecoyEnrollment` stamps the tenant its record
  names (predominant tenant of the copied enrollments; an explicit tenant
  needs a change to go-qrdb's decoy contract). Test 94c8b80eb, fix 56fd47707.
- Finding 4 (docs/SPEC.md:72 exemptions need owner approval): waits for the
  owner; docs/SPEC.md is not edited in this slice.
- Checks: `go test -count=1 -race -tags "codec_cbor codec_json
  codec_msgpack" ./pkg/ca/... ./pkg/certsubject/... ./pkg/factor/...`,
  `go vet ./...` and `make lint`.

## Codex review, round 2 (autoverify, tip 7f448a53e)

- Finding 1 (security, pkg/factor/piv/decoy.go): go-qrdb's ceremony rebuilds
  quorum roster enrollments without TenantID, so production decoys skipped
  the tenant stamp and an anonymous quorum challenge could tell a stranger
  from a holder by the OU. `DecoyEnrollment` now reads the predominant
  Subject-OU[0] of the roster certificates when no enrollment names a
  tenant; go-qrdb unchanged. Test b476c1f87, fix 3dcf8ad39.
- Finding 2 (pkg/factor/piv/factor.go): `Enroll` replaced the slot key
  before refusing an empty tenant. The tenant is now stamped before
  `GeneratePIVKey`. Test 140ab58e6, fix 75745c420.
- Finding 3 (docs/SPEC.md:72 re-scope): an owner ask; docs/SPEC.md is not
  edited in this slice.
- Checks: `go test -count=1 -race -tags "codec_cbor codec_json
  codec_msgpack" ./pkg/factor/...`, `go vet ./...` and `make lint`.
