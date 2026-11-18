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

## Codex P1 findings on 58890f3d8 (lane-verify, 9 P1)

The two security findings, each as test commit, then fix commit:

1. A deleted tenant's login CA stayed trusted: it remained in `TenantIDs`,
   `ProviderForTenant` and so in the node's Key B trust pool, and its key and
   certificate stayed on the backend.
   `TestServer_TenantCAKeys_DeletedTenantWithdrawn` (7f54892c1). Fix
   (f7810812c): `ProviderForTenant` and `TenantIDs` check the tenant against
   the node's tenant service and withdraw a deleted one; the provisioning
   tenant service's `DeleteTenant` calls `RemoveTenant`, which deletes the
   login CA key and certificate.
2. `EnsureTenant` adopted any `qrdb-login-ca` key, including one a caller made
   before the name was reserved, and issued a CA certificate over it.
   `TestTenantCAKeyFactory_RefusesKeyWithoutProvisioningProvenance`
   (11c80fd17). Fix (e82662e01): when `EnsureTenant` generates the key it
   records a provenance certificate, signed by that key, under the
   tenant-scoped ID `qrdb-login-ca:provenance` (key-reference validation
   refuses a one-colon ID, so no API caller can write it). `EnsureTenant`,
   `ProviderForTenant` and `TenantIDs` refuse a key without matching
   provenance with `errTenantLoginCAKeyCollision` and issue no certificate.
   A key another node has just generated is waited for (bounded, tied to
   ctx). `RemoveTenant` deletes the provenance record.

Limits and owner asks:

- Existing collisions (a `qrdb-login-ca` key on a deployment from before this
  fix, made by a caller or by an earlier provisioning pass without a
  provenance record) are refused, not adopted. They need an explicit
  migration: owner ask.
- A crash between generating the key and saving its provenance leaves a key
  that reads as a collision; it needs the same migration.
- Trust-pool test gap: the finding 1 test rebuilds go-qrdb's trust from
  `TenantIDs` and `ProviderForTenant`; go-qrdb's own trust pool and
  `IsTenantIssuer` are not reachable from this lane.
- A tenant deleted through go-qrdb's native tenant service leaves trust, but
  its key and certificates stay on the backend (no teardown hook there).

Open: findings 3-9 of the same review (CA migration, cloud KMS, PKCS#11
concurrency, lazy certificate retry, create rollback, the docs/SPEC.md:118
approval and the exported APIs) were not started.

## Results

- `go test -count=1 -race -timeout 75m -tags "codec_cbor codec_json codec_msgpack" ./pkg/server/...`: pass (pkg/server 528 s; credentials, loopback pass). The run hits go test's default 10m bound under -race, so it needs the Makefile's UNIT_TEST_TIMEOUT.
- `make lint`: pass (0 issues, every module and tag set).

## Third Codex review: reliability findings 6 and 7 (lane row2083d)

- Finding 6 (lazy path): `ProviderForTenant` treats a tenant as provisioned
  only when both its login CA key and its certificate exist; otherwise it
  runs `EnsureTenant`, which reuses the key.
- Finding 7 (failed-create rollback): `CreateTenant` undoes an incomplete
  create with `UndoCreateTenant` on a bounded `context.WithoutCancel`
  context, not `DeleteTenant` on the request context.
- Commits: finding 6 test 389e6e9d1, fix ef287990a; finding 7 test
  a4f77128a and 25bcd2d30 (real go-qrdb tenant service with tenant undo
  active), fix 7b017f43a.
- The finding 7 test asserts the retried ID is undone
  (`TenantUndoPendingError`), not retired: the in-memory node has no volume
  pool, so go-qrdb cannot record its cleanup acknowledgement there, and an
  end-to-end reuse check needs a real node.
- Finding 4 (cloud KMS default backends): fixed in lane row2083d, see
  below.
- Still open: finding 3 (owner ask on CA migration when the factory is
  enabled). Finding 5 (cross-node PKCS#11 provisioning claim) is fixed, see
  the Codex round 1 section.

## Finding 4: backends that return no key at generation (lane row2083d)

- The AWS KMS, Azure Key Vault and GCP KMS providers return `(nil, nil)`
  from `GenerateKey`. The composite `GenerateECDSA` now reads the public key
  back through the provider's `Signer` for that key instead of failing with
  `ErrPublicKeyExtraction`.
- Those providers address a key by its CN alone, so the tenant login CA key
  is generated as `qrdb-login-ca-<tenant>` (`tenantLoginCAKeyName`). xkms
  reserves that prefix as well as the bare name. Certificate IDs keep
  `qrdb-login-ca`, which the tenant-scoped certificate store already scopes.
- Commits: test 75a58623e, fix d111a0cb8. The test is a fake provider over
  the software backend that returns no key at generation; the real cloud
  providers were not exercised.
- Still open: findings 3 and 5.

## Codex review round 1 on e23a7115e (lane row2083d)

- Cloud KMS listing (P1, `tenant_ca_keyprovider.go:403`): the AWS KMS,
  Azure Key Vault and GCP KMS providers list keys without TenantID. The
  factory reads the tenant from the key name `qrdb-login-ca-<tenant>` and
  refuses a listed TenantID that disagrees with it. Test 09d31a03a, fix
  07f0e3855.
- Failed provenance save (P1, `tenant_ca_keyprovider.go:270`):
  `EnsureTenant` saves an intent record (`qrdb-login-ca:intent`) before it
  generates the key and drops it once provenance is saved. A key with the
  intent but no provenance is finished over the same key; a key with neither
  is still a collision. The lazy path hands such a key to `EnsureTenant`.
  Test 866a5e170, fix d7e273ef6.
- Exported surface (P1, `reserved_keys.go:15`): the login CA key name moved
  to `internal/loginca` and `ErrReservedKey` is unexported (8aee18946).
  `pkcs11.Backend.FixedKeySlot` is unexported as `fixedKeySlot`: the pkcs11
  package registers a probe with `internal/keyslot` and the factory asks
  `keyslot.Fixed`. Test 856fc0881, fix 29f665943.
- PKCS#11 provisioning claim (P1, `tenant_ca_keyprovider.go:249`):
  `Bind` takes the server's shared storage (`s.sharedStorage()`), and
  `EnsureTenant` claims the tenant with `PutIfAbsent` at
  `tenant-login-ca/claims/<key name>` before it generates. A pass that loses
  the claim waits for the winner's key and adopts it; a claim older than
  30 s with no key behind it is taken over by compare-and-swap; a storage
  error fails closed; `RemoveTenant` releases the claim last. Verified on a
  real PKCS#11 token (SoftHSM2): eight concurrent passes leave one key.
  Test c2102af1f, fix 529431f9e.
- SPEC row expansion (P1, `docs/SPEC.md:118`): reverted to main's text
  (ff6dd1850) until the owner approves a row change.
- Still open, needing the owner: migration of the tenant CAs go-qrdb already
  persisted (P1, `qrdb_node.go:267`). The pinned go-qrdb `sdk/go` gives no
  way to read, import or keep trusting the software Key B it stored, and
  go-xkms may not reach into `go-qrdb/pkg/*`; a credential transition needs
  a go-qrdb seam (item 144) or an owner design.
