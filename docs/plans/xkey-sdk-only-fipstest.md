# xkey-sdk-only: pkg/testing/fipstest through sdk/go/xkmstest

Row: xkey-sdk-only (docs/SPEC.md:180), epic #2084, PR #2107.

## Objective

xkey reaches go-xkms only through sdk/go. The xkey tests that import
`pkg/testing/fipstest` switch to `sdk/go/xkmstest`, which re-exports the
two helpers they use.

## Re-exports (sdk/go/xkmstest/xkmstest.go)

- `var OutsideFIPS = fipstest.OutsideFIPS`
- `var OutsideFIPSAfterRefusal = fipstest.OutsideFIPSAfterRefusal`

## Files switched (import line and `fipstest.` qualifier only)

- xkey/cmd/e2eprobe: enrollment_support_test.go, main_test.go, probe_test.go
- xkey/cmd/xkey/cmd/device_relay_test.go
- xkey/pkg/gui/services: fips_test.go, oath_service_test.go,
  pkcs11_ipc_roundtrip_test.go
- xkey/pkg: oath/fips_gate_test.go, oath/generator_test.go,
  phone/fips_test.go, nativemsg/fips_test.go, pairing/fips_test.go,
  attestation/device_session_test.go, attestation/attesttest/fips_test.go
- xkey/test/e2esupport/sshechod/main_test.go

## Commit slices

1. docs(plans): this plan.
2. test(sdk/go/xkmstest): xkmstest_test.go asserts each re-export points at
   the fipstest function (reflect pointer compare); red until 3.
3. feat(sdk/go/xkmstest): the two re-exports.
4. refactor commits, one per group: xkey/cmd, xkey/pkg/gui/services,
   xkey/pkg (other), xkey/test.

## Out of scope

- pkg/testing/fipstest itself; sdk/go tests that import it directly.
- pkg/trust/bootstrap, pkg/pairingproto, pkg/fido2/authenticator (moved on
  row/2084-xkey-sdk-only).
- Other go-xkms/pkg imports in xkey (pkg/storage, pkg/types, keybackend):
  later slices.
