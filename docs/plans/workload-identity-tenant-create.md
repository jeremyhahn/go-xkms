# Workload identity: refuse a non-trust-domain tenant ID at tenant creation

Epic #2094, row workload-identity (docs/SPEC.md:141).

## Objective

go-qrdb v0.51.0-alpha refuses only control bytes, `/` and `\` in a tenant ID,
so a tenant can be created that can never hold an SVID; go-xkms refused such
an ID only later, before signing (`pkg/spiffe/spiffe.go`). This slice makes
go-xkms's own tenant-create path, `TenantAwareAdminService.CreateTenant`
(`pkg/acme/admin/tenant_service.go`), refuse a tenant ID that is not a SPIFFE
trust-domain name, before go-qrdb is called.

## Slice

1. Test commit: `CreateTenant` refuses `"Acme"`, `"a b"`, `"a/b"` and a
   256-byte ID as an input error on field `id` that unwraps to the spiffe
   sentinel; accepts `"acme"` and `"acme-1.prod_eu"`; the go-qrdb tenant
   service is not called on a refusal.
2. Feat commit: export `spiffe.ValidateTrustDomain` (the existing
   `validateTrustDomain`, behaviour unchanged) and call it in `CreateTenant`
   after the empty-ID check, wrapped with `wrapInputError("id", ...)`.
3. Existing tests that create tenants with now-invalid IDs change the IDs,
   never the rule.
4. docs/workload-identity/engineering.md open bullet and a changelog entry.

## Checks

- `go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/spiffe/... ./pkg/acme/admin/... ./pkg/acme/api/...`
- `make lint`

## Out of scope

- Holding go-qrdb's own create path to the grammar: comes with the go-qrdb
  bump to v0.58.2-alpha (`ValidateTenantIDTrustDomain`), a dependency lane
  under the owner's freeze.
- The cluster-trust-domain refusal, if the admin service has no cluster trust
  domain in scope (not plumbed in this slice).

## Results

- `go test -count=1 -tags "codec_cbor codec_json codec_msgpack" ./pkg/spiffe/... ./pkg/acme/admin/... ./pkg/acme/api/...`: pass.
- `make lint`: pass (0 issues on every module and tag set, actionlint clean).
- No existing test used a now-invalid tenant ID; none changed.
- Cluster-trust-domain refusal: not in. `TenantAwareAdminService` holds no
  cluster trust domain, and this slice does not plumb one in; the refusal
  stays at signing (`ErrTenantIsClusterTrustDomain`, pkg/spiffe).
