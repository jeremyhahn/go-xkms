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

## SPEC row update (done)

Applied to docs/SPEC.md:117 (lane row2083b, under LANE_POLICY_ALLOW for
docs/SPEC.md); every citation was checked against the branch head, and the
boot pass hop through `provisionTenantCAKeysThenFirstBoot`
(`tenant_ca_provisioning.go:106`) was added. In the row's acceptance, the clause from
"`node.WithSealStrategy` (`pkg/embeddednode/embedded_node.go:219`, through
`qrdb_node.go:248`); the pinned ..." through "which go-xkms does not pass." was replaced with the text below (the
row as committed adds the `provisionTenantCAKeysThenFirstBoot` hop):

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

## Codex P1 findings on 7e753ec9e (lane row2083c)

Each as test commit, then fix commit:

5. Concurrent boot passes: `TestTenantCAKeyFactory_ConcurrentNodesConverge`
   (080332a90); `ErrKeyAlreadyExists` converges on the persisted key and its
   certificate (f97090abc).
3. Key without certificate: `TestTenantCAKeyFactory_RetryAfterSaveCertFailure`
   (cb0aa5a56); an existing key is validated against its saved certificate,
   which is issued if missing (71da131f4).
6. TryRLock contention: `TestServer_TenantCAKeys_ResolveDuringServerLockContention`
   (0eb88f911); the boot pass resolves the default backend once and binds it,
   the read path takes only the factory's lock (d9a48f6c3).
4. TPM system scope: `TestTenantCAKeyFactory_TPM2SystemKeyIsReused`
   (tpm_simulator, 8213e5d92); lookup and `TenantIDs` compare
   `scope.TenantName` (3043fff7c).
2. Native onboarding: `TestServer_TenantCAKeys_NativeOnboardingGetsKey`
   (4ae2a0865); the pinned go-qrdb has no option to wrap the tenant service
   its `TenantOnboardingService` uses, so `ProviderForTenant` provisions a
   tenant the node's tenant service knows (`GetTenant`) on first request and
   refuses an unknown one (3a1b42909). Open: an end-to-end POST /v1/tenants
   CSR test (needs a cluster-CA node harness); the cleaner fix is a go-qrdb
   seam that lets the embedder wrap the onboarding tenant service.
1. PKCS#11: `TestCreateKeyID_TenantScoped` (7c84e77cc); tenant keys use
   `tenant=<tenant>/<CN>.<alg>` as CKA_ID/CKA_LABEL, `ListKeys` reads the
   tenant back, system keys keep the old ID (c8913d06a). Open: a SoftHSM
   two-tenant factory test.

## Codex P1 findings on d94e243c2 (lane-verify, 7 P1)

The two security findings, each as test commit, then fix commit:

1. Login CA key reachable by callers (`tenant_ca_keyprovider.go:183`):
   `TestLoginCAKey_RefusedToUserAddressableOperations` (pkg/xkms, d94bf6c1b):
   User and Operator sign, save a certificate over, rotate, delete or
   pre-create `qrdb-login-ca`. Fix (25e5aa51b): `xkms.LoginCAKeyCN` is
   reserved (`pkg/xkms/reserved_keys.go`, `ErrReservedKey`), refused in
   `resolveKeyOf` (every by-name key operation), in `refuseRotatedKeyID`
   (generate, import, copy) and in the certificate save, chain save and
   delete calls. No permission is added; the node reaches the key on the
   backend directly.
2. Fixed-slot PIV backend (`tenant_ca_keyprovider.go:190`):
   `TestTenantCAKeyFactory_RefusesFixedSlotBackend` and
   `TestBackend_FixedKeySlot` (pkcs11 tag) (51beb0a30). Fix (d3636482a): the
   PKCS#11 backend reports `FixedKeySlot` for a YubiKey PIV token with
   `Config.Slot`; the factory refuses such a backend before any lookup or
   generate. Tenant-to-slot allocation is not implemented.

Open: findings 3-7 of the same review (reliability, correctness, SPEC; see
the lane's verify.codex.json) are later slices of this row and were not
started.

## Results

- `go test -count=1 -race -timeout 75m -tags "codec_cbor codec_json codec_msgpack" ./pkg/server/...`: pass (pkg/server 528 s; credentials, loopback pass). The run hits go test's default 10m bound under -race, so it needs the Makefile's UNIT_TEST_TIMEOUT.
- `make lint`: pass (0 issues, every module and tag set).
