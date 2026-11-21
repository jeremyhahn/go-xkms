# xkey-sdk-only: pkg/types through the sdk/go root package

Row: xkey-sdk-only (docs/SPEC.md:180), epic #2084. Lane sxsdkg, stacked on
row/2084-xkey-sdk-only after sxsdka, sxsdkb and sxsdke.

## Objective

No xkey file imports `github.com/jeremyhahn/go-xkms/pkg/types`. The 7 test
files and 3 usage docs that do switch to the sdk/go root package
`xkms "github.com/jeremyhahn/go-xkms/sdk/go"`, which re-exports the names in
sdk/go/types.go.

## Files

- xkey/pkg/gui/services/pkcs11_slotmodel_test.go (already imports sdk/go as `xkms`)
- xkey/pkg/gui/services/ssh_service_test.go
- xkey/pkg/gui/services/staticpw_vault_keyfactor_test.go
- xkey/cmd/xkey/cmd/password_vault_keyfactor_test.go
- xkey/cmd/xkey/cmd/xkmsd_harness_test.go
- xkey/pkg/pairing/bridge_enrollment_test.go
- xkey/test/integration/password/vault_tpm_test.go
- xkey/docs/usage/certificate-management.md, getting-started.md, key-import-export.md
  (code samples)

## sdk/go names used

KeyAttributes, StoreType, BackendType, ECCAttributes, TPMAttributes,
Capabilities, KeyProvider, FSExtension, KeyTypeEncryption, TPMPolicyPlatform.

## TPMPolicyPlatform

pkg/types.TPMPolicyPlatform is the untyped string const "platform".
sdk/go `TPMPolicyPlatform` aliases pkg/tpm2/policy.PlatformPolicy, which is
declared as `const PlatformPolicy = types.TPMPolicyPlatform`, so it is the
same untyped "platform" constant and vault_tpm_test.go uses it unchanged.

## Slices

1. This plan (docs(plans)).
2. refactor(xkey): import line and qualifier changes in the 10 files; the
   existing tests of cmd/xkey/cmd, pkg/gui/services, pkg/pairing and
   test/integration/password cover them (no new tests: no behaviour change).

## Out of scope

Every other pkg/ import group in xkey tests: pkg/storage, pkg/oidc,
pkg/testing/fipstest, pkg/truststore, pkg/fido2/*, pkg/xkms, pkg/tpm2,
pkg/ca, pkg/auth and the rest.
