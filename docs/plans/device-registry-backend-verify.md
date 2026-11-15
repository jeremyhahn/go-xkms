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

## Out of scope

- Permissions, routes and service verbs (row device-share-policy).
- Pairing UX: who writes the record (the authority's `Pair` already exists).
