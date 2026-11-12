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

Results to follow.
