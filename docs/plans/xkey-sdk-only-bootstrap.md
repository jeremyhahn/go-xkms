# xkey-sdk-only: pkg/trust/bootstrap through sdk/go/bootstrap

Row: xkey-sdk-only (docs/SPEC.md:180), epic #2084. xkey must reach go-xkms
only through the sdk/go module.

## Objective

Move every xkey import of `github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap`
to `github.com/jeremyhahn/go-xkms/sdk/go/bootstrap`. The package qualifier
stays `bootstrap`, so only the import line changes.

## Files (36, all `_test.go`)

- pkg/phone (20): tcp_server_test, ble_peripheral_shutdown_test,
  tcp_server_pin_test, live_attestation_test, ble_peripheral_live_attest_test,
  test_helpers_test, phone_connect_ble_test, phone_keyownership_test,
  phone_happy_path_test, ble_peripheral_advertising_test,
  phone_proveliveness_test, retention_test, errors_test,
  ble_peripheral_test, phone_test, fips_test, phone_error_paths_test,
  ble_peripheral_acceptconnection_test, tcp_e2e_test,
  phone_boundeddrain_test.
- cmd/xkey/cmd (3): device_relay_test, device_pair_reconnect_interop_test,
  device_listen_handler_test.
- pkg/gui/services (4): phone_service_drain_test,
  phone_service_teardown_test, phone_pair_attestation_test, fips_test.
- pkg/pairing (4): message_loop_test, sas_test, exchange_test, fips_test.
- pkg/attestation (3): device_session_test, attesttest/phone_test,
  attesttest/fips_test.
- test/integration (2): ble/ble_integration_test, phone/tcp_e2e_test.

## Symbols used

NoiseSession, NoiseSessionConfig, NewNoiseSession, NoiseStaticKey,
GenerateNoiseStaticKey, LoadNoiseStaticKey, LoadNoiseStaticKeyFromBuffer,
EncodeNoiseStaticKey, WithNoisePrivateKey, WipeNoiseBytes, NoiseKeySize,
NoiseHexKeySize, ErrNoiseFIPSUnsupported, ErrNoiseHandshakeFailed,
ErrNoiseEncryptionFailed, ErrNoiseDecryptionFailed.

sdk/go/bootstrap already re-exports all of them (aliases and constants), so
this slice adds no re-export and no reexport_test.go.

## Slices

1. This plan.
2. Refactor commits, one per group: pkg/phone; cmd and gui; pairing and
   attestation; test/integration. Import line only.
3. Gates: sdk/go build + bootstrap tests; xkey build, vet, unit tests with
   the codec tags; make lint.

## Out of scope

- pkg/pairingproto (71 files): a later slice.
- truststore: lane strota (trust-roots).
- pkg/trust/bootstrap itself, go.mod/go.sum.
