# Workload identity: refuse a bad tenant ID at the core tenant create path

Epic #2094, row workload-identity (docs/SPEC.md:141). Follows
workload-identity-tenant-create.md (ACME admin path).

## Gaps

1. The core tenant lifecycle, which owns /api/v1/tenants on every transport
   (cmd/xkmsd/admin.go), creates through `XKMSService.CreateTenantDetail`
   (pkg/xkms/servicer_tenant.go), which checks only that the ID is non-empty.
2. Neither create path refuses a tenant ID equal to the cluster trust domain;
   `spiffe.BuildURI` refuses it only at signing.

## Checks

- `CreateTenantDetail`: after the empty-ID and empty-name checks (order and
  errors unchanged), `spiffe.ValidateTrustDomain(tenantID)`, then refuse
  `tenantID == s.SPIFFETrustDomain()` with
  `spiffe.ErrTenantIsClusterTrustDomain` when a trust domain is set.
- `TenantAwareAdminService.SetClusterTrustDomain` (mirrors `SetTenantService`)
  and the same equality refusal in `CreateTenant`; wired in cmd/xkmsd/admin.go
  from `srv.TrustDomain()`.

## Slice

1. Test commit: both refusals, accepted IDs, the tenant service not called on a
   refusal, the equality check skipped with no trust domain.
2. Feat commit: the checks above.
3. Existing tests with now-invalid IDs change the IDs, never the rule.
4. engineering.md open bullet; changelog entry.

## Out of scope

- go-qrdb's own create path (the v0.58.2-alpha bump, under the owner's freeze).

## Results

Results to follow.
