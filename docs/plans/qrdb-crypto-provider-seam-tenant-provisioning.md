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
server.go (plus the `tenantCAKeys` field).

Slice 1 bound the factory's backend resolver at node start. The node's
trust-pool refresh goroutine then read `s.backends` while New was still
writing it: a data race under -race in
TestCredentialBarrierStrategy_RoundTripsAcrossRestart. The factory is now
left unbound at node start (logins see the factory's unbound error, as they
did before the backends existed), and the boot pass binds it.

## Out of scope

The head signer (go-qrdb v0.58.2 pin, frozen); pkg/xkms, pkg/acme/admin,
cmd/xkmsd; go.mod/go.sum.

## Landing order

Slice 1 and this slice must land together, in one PR: slice 1 alone breaks
tenant logins and races at startup. The head signer slice comes after
the go-qrdb pin moves past v0.51.

## SPEC row update (pending)

docs/SPEC.md:117 still says go-xkms does not pass `WithCertKeyProviderFactory`.
The lane policy guard refuses docs/SPEC.md without LANE_POLICY_ALLOW, so the
row text was not changed. Replace, in the row's acceptance, the clause from
"`node.WithSealStrategy` (`pkg/embeddednode/embedded_node.go:219`, through
`qrdb_node.go:248`); the pinned ..." through "which go-xkms does not pass." with:

> `node.WithSealStrategy` (`pkg/embeddednode/embedded_node.go:219`, through `qrdb_node.go:248`), and `node.WithCertKeyProviderFactory` (`tenantCAKeyProviderOptions`, `pkg/server/tenant_ca_keyprovider.go:222`, appended at `qrdb_node.go:267` under the same cluster-CA condition). Through it each tenant's login CA key (Key B) is a P-256 key in the tenant-scoped default backend (`tenantCAKeyFactory.ProviderForTenant` `:87`, `EnsureTenant` `:140`), not a key go-qrdb mints in software. Every tenant has that key: the tenant service the node hands out is wrapped at `qrdb_node.go:309` so `CreateTenant` provisions it and deletes the tenant again on failure (`pkg/server/tenant_ca_provisioning.go:49`, `TenantProvisionError`), and a boot pass (`provisionTenantCAKeys` `:77`, run from `New` at `pkg/server/server.go:897`, after the key backends exist) provisions every tenant, the system tenant included, or stops startup. The pinned `sdk/go/node` also offers `WithDEKProvider`, `WithKeyDeliveryDecrypter`, `WithVolumeKeyProvider` and `WithVolumeProvider`, which go-xkms does not pass yet.

The row stays in progress: go-qrdb still owes the head-signer seam (item 144).

## Remaining seams (each needs a design decision)

The pinned go-qrdb v0.51.0-alpha `sdk/go/node` seams that go-xkms does not fill:

- `WithDEKProvider(dek.Provider)` replaces the software tenant DEK keyring.
  On a node that already has software DEKs, the swap needs a migration path,
  or the tenant data keys already there become unreadable. Needs a custody
  and migration ruling first.
- `WithKeyDeliveryDecrypter(keydelivery.Decrypter)`: clustered nodes only;
  dec must be the Raft certificate's key, held on a device through an
  `ecdh.KeyExchanger`. It depends on the Raft mTLS key moving to a backend.
- `WithVolumeKeyProvider(volume.KeyProvider)` replaces the HKDF-from-barrier-root
  derivation of Lockable volume Unlock keys. Swapping it on existing volumes
  makes them unopenable without a re-key.
- `WithVolumeProvider(volume.Provider)` is storage (luks2 pools), not crypto.
  It belongs to the volume row, not this one.

## Results

- `go test -count=1 -race -timeout 75m -tags "codec_cbor codec_json codec_msgpack" ./pkg/server/...`: pass (pkg/server 528 s; credentials, loopback pass). The run hits go test's default 10m bound under -race, so it needs the Makefile's UNIT_TEST_TIMEOUT.
- `make lint`: pass (0 issues, every module and tag set).
