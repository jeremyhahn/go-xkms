# xkey-sdk-only: pkg/fido2/authenticator through sdk/go/fido2/authenticator

Row: xkey-sdk-only (docs/SPEC.md:180), epic #2084. Lane sxsdke.

## Objective

No xkey file imports `github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator`;
all go through `github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator`
(same package name, so only the import path changes). The non-test xkey
files already import the SDK path; the 24 test files below still import pkg.

## Files (import path only)

- cmd/xkey/cmd (10): extension_serve_audit_test.go, extension_serve_test.go,
  fido2_audit_test.go, fido2_cdp_test.go, fido2_init_token_test.go,
  fido2_policy_test.go, fido2_provision_attestation_test.go,
  fido2_set_pin_test.go, fido2_storage_test.go, fido2_test.go
- pkg/gui/services (9): autofill_service_test.go,
  coverage_boost_phase2_test.go, fido2_device_service_presence_test.go,
  fido2_device_service_test.go, fido2_service_test.go,
  final_coverage_push7_test.go, misc_services_coverage_test.go,
  surgical_coverage_c_test.go, surgical_final_test.go
- pkg/presence (2): socket_audit_test.go, socket_test.go
- pkg/audit (1): fido2_test.go
- pkg/gui (1): enterprise_policy_test.go
- test/integration/fido2 (1): backend_test.go

## Symbols the SDK lacks (re-exported in this slice)

- Constants: ClientDataHashSize, CmdGetAssertion, CmdMakeCredential,
  COSEAlgES384, VendorCmdSetSOPIN
- Types: AuditLogger, AuthenticatorState, AutoGrantHandler,
  InteractiveHandler, MemoryStorage
- Functions: DefaultConfig, NewAuthenticatorState
- Errors: ErrAttestationCertNotIssuedForKey, ErrConfigInvalidVendorCmd,
  ErrInvalidParameter, ErrKeyManagerLocked, ErrKeyManagerNoAttestKey,
  ErrNilStorage, ErrPINPolicyViolation, ErrRPPolicyInvalidRPID,
  ErrRPPolicyNotFound, ErrSOPINInvalid, ErrSOPINPolicyViolation,
  ErrUserVerificationDenied

## Commits

1. test: sdk/go/fido2/authenticator/reexport_test.go asserts each new alias
   is identical to the pkg symbol.
2. feat: the re-exports in authenticator.go.
3. refactor: import switch per directory group (cmd/xkey/cmd,
   pkg/gui/services, pkg/presence+pkg/audit+pkg/gui, test/integration).

## Out of scope

pkg/fido2/authenticator/keybackend imports (later slice), any other
go-xkms/pkg import in xkey, go.mod/go.sum.
