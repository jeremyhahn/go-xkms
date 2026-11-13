# qrdb-crypto-provider-seam: tenant login CA key provider factory

Row: `qrdb-crypto-provider-seam` (docs/SPEC.md:118), epic #2083.

## Objective

go-qrdb's tenant login CA ("Key B") is still generated in software inside
go-qrdb. The pinned go-qrdb v0.51.0-alpha accepts it from the embedder through
`node.WithCertKeyProviderFactory(cakey.ProviderFactory)`. This slice makes
go-xkms supply that factory over its tenant-scoped backend, so every Key B
signature goes through the tenant's xkms key and no software Key B exists.

## Factory shape

- `tenantCAKeyFactory` (pkg/server/tenant_ca_keyprovider.go) implements
  `qrdbsdk.CAKeyProviderFactory`:
  - `ProviderForTenant(tenantID)` returns a `qrdbsdk.CAKeyAdapter` whose
    `SignerFunc` is `xkms.NewTenantScopedBackend(base, tenantID).Signer` on the
    tenant's login CA key, and whose `CertificateFunc` reads that tenant's CA
    certificate from the same tenant-scoped certificate store. An empty or
    unknown tenant returns an error; a single provider is never shared.
  - `TenantIDs(ctx)` lists the tenants that hold a login CA key in the backend.
- Key ID per tenant: one key per tenant, the fixed common name
  `qrdb-login-ca` under the tenant's scope (`KeyAttributes.TenantID` = tenant),
  so key ID = tenant as go-qrdb's ProviderFactory contract requires.
- The backend is bound after the server's backends exist (the same late-bind
  pattern as `clusterca.KeyProvider.Bind`); an unbound factory returns an error.

## Wiring

`qrdb_node.go` appends `node.WithCertKeyProviderFactory` next to
`clusterCAKeyProviderOptions`, under the same condition
(`trustedCAIsClusterCA`).

## Slices and tests

1. Test commit, pkg/server/tenant_ca_keyprovider_test.go: the provider's signer
   is the tenant-scoped key; two tenants get different keys; an unknown tenant
   errors; TenantIDs lists the backend's tenants; a provider signature verifies
   with the public key xkms reports.
2. Feat commit: the factory and the node option.

## Status

- Done: the factory, `EnsureTenant` (P-256 key plus a self-signed CA
  certificate, OU = tenant, under the tenant scope) and the node option. The
  factory reads the server's default backend at each call, without blocking on
  the server lock, so no `Server` field or later bind is needed.
- Open, next slice: nothing calls `EnsureTenant` in production yet. Once the
  factory is wired, go-qrdb generates no software Key B, so a tenant has a
  login CA only after it is provisioned. The tenant create path (and a boot
  pass over existing tenants) must call `EnsureTenant`.
- The head signer waits for the go-qrdb v0.58.2-alpha pin (frozen).

## Out of scope

- The verifiable-log head signer (`WithHeadSignerProvider`) needs the go-qrdb
  v0.58.2-alpha pin, which is frozen (DS-7684/DS-7715: enclave v0.11.1
  conflicts with the held v0.8 replace). It waits for that pin bump.
- `WithDEKProvider`, `WithKeyDeliveryDecrypter`, `WithVolumeKeyProvider`,
  `WithVolumeProvider`: later slices of the row.
