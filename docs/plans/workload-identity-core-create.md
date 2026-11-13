# Workload identity: tenant ID checks at core tenant creation (#2094, lane swkidc)

## Gaps

Slice 1 (swkida) refuses a tenant ID that is not a SPIFFE trust-domain name in
the ACME admin path (`TenantAwareAdminService.CreateTenant`,
pkg/acme/admin/tenant_service.go). Two gaps remain in go-xkms:

1. The core tenant lifecycle, which owns /api/v1/tenants on every transport,
   creates through `XKMSService.CreateTenantDetail`
   (pkg/xkms/servicer_tenant.go), which checks only that the ID is non-empty.
2. Neither create path refuses a tenant ID equal to the cluster trust domain;
   `spiffe.BuildURI` refuses it only at signing.

## Checks

- `CreateTenantDetail`: after the empty-ID and empty-name checks (order and
  errors unchanged), call `spiffe.ValidateTrustDomain(tenantID)`; when
  `SPIFFETrustDomain()` is set, refuse `tenantID == SPIFFETrustDomain()` with
  an error that unwraps to `spiffe.ErrTenantIsClusterTrustDomain`. Both run
  before the tenant service (go-qrdb) is called.
- `TenantAwareAdminService.SetClusterTrustDomain` (mirrors `SetTenantService`);
  `CreateTenant` refuses the cluster trust domain once it is set.
  cmd/xkmsd/admin.go wires it with `srv.TrustDomain()`.

## Tests (test commit first, ruling 286)

- CreateTenantDetail refuses `Acme`, `a b`, `a/b`, a 256-byte ID and the
  configured trust domain (`errors.Is` on the spiffe sentinels); accepts
  `acme` and `acme-1.prod_eu`; the fake tenant service is not called on a
  refusal; no trust domain set skips the equality check.
- Admin CreateTenant refuses the cluster trust domain after
  SetClusterTrustDomain.

## Out of scope

go-qrdb's own create path (needs the v0.58.2-alpha bump, frozen); docs/SPEC.md.

## Results

- `go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/xkms/... ./pkg/spiffe/... ./pkg/acme/admin/... ./cmd/xkmsd/...`: pass; no existing test needed a new tenant ID.
- `make lint`: pass (0 issues on every module and tag set).

## What remains of the row (next slice, 2026-11-13)

- docs/SPEC.md row `workload-identity` (line 141): the policy guard refuses this
  lane without LANE_POLICY_ALLOW. Text to apply:
  - after "go-xkms refuses any other tenant before it signs
    (`pkg/spiffe/spiffe.go:97`)" add: ", and both its tenant-create paths, the
    core lifecycle behind /api/v1/tenants (`pkg/xkms/servicer_tenant.go:104`)
    and the ACME admin service (`pkg/acme/admin/tenant_service.go:222`),
    refuse such an ID and the cluster trust domain (`:108`, `:226`) before
    go-qrdb is called".
  - Open note: narrow to "a tenant created directly in go-qrdb, outside
    go-xkms"; go-qrdb v0.58.2-alpha `ValidateTenantIDTrustDomain`
    (`pkg/tenant/reserved.go:146`) closes it with the go-qrdb bump.
- The row stays `in progress` until the go-qrdb v0.58.2-alpha bump, which is
  frozen (DS-7715). pkg/spiffe/spiffe.go and pkg/auth/mtls.go need no change:
  the sign-time refusal (`pkg/spiffe/spiffe.go:97`) is already the cited line.
