# ota-image-keys: pin the go-qrdb OTA grants (row #1606)

## Claim

docs/SPEC.md row `ota-image-keys` lists one blocker: the OTA activate and
confirm permissions are not yet registered in go-qrdb (#737). The pinned
`github.com/jeremyhahn/go-qrdb/sdk/go v0.51.0-alpha` registers
`ota:activate` and `ota:confirm` and grants both to the built-in Admin role
(`builtin_role_grants.go`, `registerAdminGrants`). The blocker is stale.

## Slice (this lane)

1. Test `pkg/xkms/ota_image_keys_qrdb_grant_test.go`:
   - both strings parse through `qrdbsdk.ParsePermission`;
   - `HasPermissionRoleGrant(PermissionRoleAdmin, p)` is true for each;
   - a non-admin built-in role does not hold them (if the sdk exposes one);
   - `pkg/auth` defines no OTA permission or role of its own.
2. A fix commit only if go-xkms checks an OTA string that differs from qrdb's.
3. Docs: key-management/engineering.md section `per-board-ota-image-keys`
   names the go-qrdb source; the SPEC row names the test instead of the
   registration blocker.
   - Departure: the lane's policy guard refuses docs/SPEC.md without
     LANE_POLICY_ALLOW, so the SPEC row edit is left for a lane launched
     with it. Status stays `in progress` (the row text does not say the
     blocker was its only gap).

## Out of scope

- go.mod / go.sum changes (no pin bump).
- pkg/auth/permissions.go, CI files, ROADMAP.md.
