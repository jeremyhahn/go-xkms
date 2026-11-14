# Device registry: ship the SPEC row

Row: device-registry (docs/SPEC.md:87), issue #2093. Lane row2093b.

Prior lanes: sdevregb (pkg/devicereg), sdevregc (atomic Pair), sdevregd
(atomic Revoke, docs/plans/device-registry-revoke-race.md). The lane before
this one was refused docs/SPEC.md by the policy guard (commit 736705823).

## Objective

Flip the row planned -> shipped, detail none -> [device-registry/](../device-registry/),
citing code and a test for both modes of the acceptance.

## Evidence per mode

- Local mode (xkey verifies only devices paired with it, via its pairing
  record): `PhoneService.Connect` (xkey/pkg/gui/services/phone_service.go:1160)
  refuses a name with no `pairing.PairedDevice` (xkey/pkg/pairing/device.go:39)
  and pins the Noise session to the record's key (:1206, :1242);
  xkey/pkg/phone/phone.go:375 refuses a session with no pinned key.
  Tests: phone_service_test.go:364, tcp_e2e_test.go:256,
  phone_error_paths_test.go:80.
- Backend mode (go-xkms verifier and authority, tenant-scoped):
  `devicereg.Registry` (pkg/devicereg/registry.go:117), tenant key
  `tenantPrefix` (:257), `IsActive` (:236), `Pair` (:139), `Revoke` (:205).
  Tests: pkg/devicereg/registry_test.go:302 (TestTenantIsolation), :323,
  :288, :251.

## Edits

- docs/SPEC.md row device-registry only.
- docs/device-registry/architecture.md: the registry.go line citations had
  drifted (the CompareAndSwap revoke moved them); they now resolve, and the
  local-mode verification path is cited.

## Out of scope

- Permissions, routes and service verbs (row device-share-policy).
- Any code or dependency change.

## Results

- `make test-go UNIT_TEST_SCOPE=./pkg/devicereg/...` (-race): pass.
