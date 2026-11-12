# xkey-sdk-only: pkg/pairingproto through sdk/go/pairingproto

Row: xkey-sdk-only (docs/SPEC.md:180), epic #2084.

## Objective

xkey reaches go-xkms only through sdk/go. This slice removes every
direct `go-xkms/pkg/pairingproto` import from xkey.

## Files

The non-test xkey files already import sdk/go/pairingproto. These 71
test files still import pkg/pairingproto:

- xkey/cmd/e2eprobe: enrollment_test.go, main_test.go, probe_test.go
- xkey/cmd/xkey/cmd: backup_device_test.go, device_attest_run_test.go,
  device_enroll_phone_test.go, device_listen_bridge_test.go,
  device_listen_collaborators_test.go, device_listen_enrollment_test.go,
  device_listen_handler_test.go, device_listen_handler_wipe_test.go,
  device_oath_sync_run_test.go, device_oath_sync_test.go,
  device_pair_flow_test.go, device_pair_reconnect_interop_test.go,
  device_piv_sync_run_test.go, device_share_run_test.go,
  device_sync_run_test.go, fido2_phone_bridge_collaborators_test.go,
  fido2_phone_bridge_test.go, sdk_client_fake_test.go
- xkey/pkg/attestation: device_pure_test.go, device_realchain_test.go,
  device_session_test.go, device_test.go, attesttest/fixtures_test.go,
  attesttest/phone_test.go
- xkey/pkg/gui/services: phone_liveness_test.go,
  phone_pair_attestation_test.go
- xkey/pkg/pairing: 19 test files (biometric_handler, bridge_*,
  device_enrollment_policy*, exchange, message_loop*, sharing_policy,
  tcp_transport, tpm_enroller)
- xkey/pkg/phone: 21 test files (ble_*, errors, fido2,
  live_attestation, phone_*, tcp_*, test_helpers)
- xkey/test/integration: ble/ble_integration_test.go,
  phone/tcp_e2e_test.go

## Symbols sdk/go/pairingproto lacks

- Constants: AttestChannelBindingSize, AttestProtocolV1,
  AttestStaticKeySize, FragmentHeaderSize, FlagLastFragment,
  ErrorCodeUserCancelled, PIVSlotAuthentication
- Type: RemoteListBackupsParams
- Functions: ComputeAttestChannelBinding, IsLocalMethod
- Errors: ErrAttestGenesisChallenge, ErrAttestSignatureInvalid,
  ErrAttestSignatureMissing

## Slices

1. test: sdk/go/pairingproto/reexport_test.go asserts each new
   re-export equals the pkg symbol.
2. feat: add the re-exports to sdk/go/pairingproto/pairingproto.go.
3. refactor: switch the imports, one commit per directory group
   (cmd, pkg/attestation + pkg/gui, pkg/pairing + pkg/phone,
   test/integration).

## Out of scope

Other go-xkms/pkg imports in xkey; pkg/pairingproto itself; go.mod.
