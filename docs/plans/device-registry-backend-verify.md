# Device registry: backend-mode verification

Row: device-registry (docs/SPEC.md:87), issue #2093. Lane row2093c, fixing
the Codex P1 on 254d1020279b (lane row2093b, docs/plans/device-registry-ship.md).

## Finding

P1 docs/SPEC.md:87: no production code consulted pkg/devicereg, so pairing or
revoking a record had no effect on backend device acceptance;
`Server.RegisterPhoneBackend` registered any configured phone.

## Objective

In backend mode go-xkms accepts a phone backend only when its registry record
is active and bound to the phone's key:

- `config.PhoneConfig` names the record: `tenant` and `device_id`.
- `Server.RegisterPhoneBackend` (pkg/server/backend_phone.go) opens the
  registry on the server's datastore and refuses, with
  `ErrPhoneDeviceRefused`, a device with no record (unpaired), a revoked
  record, or a record whose `IdentityKey` (SPKI DER, X25519) is not the
  configured `phone_static_key`.

## Slices

1. Test commit: `TestRegisterPhoneBackend_RegistryRefusesDevice`
   (pkg/server/backend_phone_test.go): unpaired, wrong key, other tenant and
   revoked are refused; the paired, active, matching device is accepted;
   the phone test helpers pair the test device. Fails before the fix (all
   four are accepted).
2. Fix commit: the registry check in `RegisterPhoneBackend`.
3. Docs commit: SPEC row 87 cites the backend check and its test.

## Results

- Finding P1: test commit 864aae088 (fails: all four refusal cases
  accepted), fix commit 6a6542796 (passes).

## Codex review of da0470e8707c (lane row2093c, resumed)

1. Security, backend_phone.go: the registry was compared with the
   configuration, not with the connected peer. `RegisterPhoneBackend` now
   takes an `AuthenticatedPhoneSender` and binds the record's identity key
   to the session's `RemoteStaticKey`. Test 44ccfc0b2
   (`TestRegisterPhoneBackend_RefusesOtherPeer`, fails before), fix
   8dbd58fc8.
2. Security, backend_phone.go: verification ran only at registration.
   The backend now sends through `registryGuardedSender`, which re-reads
   the record before every request, so a revocation from any process
   refuses the next operation. Test 317f42580
   (`TestRegisterPhoneBackend_RevokeAfterRegister`, fails before), fix
   d92b14cf6.
3. Tests: the registry-opening path was bypassed. Test-only commit
   6a9297afe (`TestRegisterPhoneBackend_DatastoreRegistry`): registry
   opened through `s.daoFactory` on a shared datastore; matching, revoked
   by another registry after registration, revoked, store failure and no
   datastore.
4. docs/SPEC.md:87 (owner approval of the shipped status): an owner ask;
   this lane does not edit docs/SPEC.md.

Remaining for production use: the phone bridge that calls
`RegisterPhoneBackend` must pass a Sender that reports its Noise
session's remote static key; no such caller exists in this repository yet.

## Codex review of 5ddccd65563c (lane row2093c, resumed)

1. Security, backend_phone.go: the active phone backend was closed before
   the replacement was checked, so a refused peer disabled the accepted
   phone. The existing backend is now closed and swapped only after the
   replacement passes. Test e2fd12724
   (`TestRegisterPhoneBackend_RefusedReplacementKeepsActive`, fails
   before), fix 578db7079.
2. Performance, registry.go: `List` paged the whole `paired_devices`
   collection and filtered by tenant in memory. Records now carry an
   indexed `Tenant` field and `List` queries it. Test 42eca149b
   (`TestListReadsOnlyTheTenant`, fails before: 604 values read for a
   tenant of two), fix da2bb8920.
3. docs/SPEC.md:87 (owner approval of the shipped status): still an owner
   ask; this lane does not edit docs/SPEC.md. The row's citations name
   `verifyPhoneDevice`, which 8dbd58fc8 removed, and stale line numbers;
   they need refreshing with that approval.

## Out of scope

- Permissions, routes and service verbs (row device-share-policy).
- Pairing UX: who writes the record (the authority's `Pair` already exists).
