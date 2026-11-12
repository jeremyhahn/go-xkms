# qrdb-crypto-provider-seam: tenant login CA provisioning (slice 2)

Row: docs/SPEC.md:118 (epic #2083).

## The gap

Slice 1 wired `tenantCAKeyFactory` (pkg/server/tenant_ca_keyprovider.go) into
the embedded node through `qrdbnode.WithCertKeyProviderFactory` when
`trustedCAIsClusterCA()` holds. With the factory wired, go-qrdb no longer mints
its own tenant login CA key (Key B): it asks the factory, and the factory refuses
a tenant that has no key. No production code called `EnsureTenant`, so a
tenant created after slice 1, and every tenant that existed before it, would
fail every login that needs the key. go-qrdb v0.51 resolves the factory lazily
per login, so provisioning at create time plus one pass at boot covers all
tenants.

## The decorator

`provisioningTenantService` (pkg/server/tenant_ca_provisioning.go) embeds
`qrdbsdk.ServiceTenantServicer` and overrides only `CreateTenant`: it calls
the wrapped create, then `EnsureTenant(ctx, info.ID)`. If `EnsureTenant`
fails, it deletes the tenant and returns `*TenantProvisionError{TenantID, Err}`,
where Err is `errors.Join(ensureErr, deleteErr)`. The wrap goes on where
qrdb_node.go adopts `svcNode.Tenant`, and only when the factory is wired. So
both XKMSService (server.go) and the ACME admin service (`TenantService()`)
get the wrapped service.

## The boot pass

`provisionTenantCAKeys(ctx)` runs `ListTenants`, plus the system tenant if the
list leaves it out, and calls `EnsureTenant` for each one. `EnsureTenant` is
already idempotent: an existing key is kept. Any failure comes back as a
`*TenantProvisionError` and stops startup (fail closed); it is not only
logged. No key material goes into any log line or error.

Departure from the brief: the boot pass cannot run in qrdb_node.go right after
the unseal. The node starts in `initializeQRDBStorage` (server.go:701), but the
key backends the factory uses are only ready after `initializeBackends`
(server.go:749). The pass therefore runs in New, right before `runFirstBoot`,
which is also after the node is unsealed. That adds a one-call edit to
server.go.

## Out of scope

The head signer (go-qrdb v0.58.2 pin, frozen); pkg/xkms, pkg/acme/admin,
cmd/xkmsd; go.mod/go.sum.

## Landing order

Slice 1 and this slice must land together: slice 1 alone breaks tenant logins.

## Results

Results to follow.
