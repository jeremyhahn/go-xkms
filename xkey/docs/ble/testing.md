# BLE Phone Backend Testing

> **Status: REFERENCE** · Last verified: 2026-10-13
> How the phone/BLE code is tested in this repository; the [ble](engineering.md) feature folder's test section is normative.

## Unit Tests

The phone backend is `xkey/pkg/phone`; the wire protocol, fragmentation and
Noise session it uses are `xkey/pkg/pairing`.

```bash
cd xkey
make test-phone                      # go test ./pkg/phone/... (Makefile:449)
go test ./pkg/pairing/
cd ..
go test ./pkg/pairingproto/ ./pkg/trust/bootstrap/
go test ./pkg/trust/bootstrap/ -run TestNoiseSession_FullHandshake
```

| Area | Test files |
|------|-----------|
| Noise handshake and transport | `pkg/trust/bootstrap/noise_session_test.go`, `pkg/pairingproto/handshake_test.go` |
| JSON-RPC encoding | `pkg/pairingproto/protocol_test.go` and `protocol_*_test.go` |
| Fragment / reassemble | `pkg/pairingproto/fragmentation_test.go` |
| Backend, config, error paths | `pkg/phone/phone_test.go`, `phone_*_test.go`, `errors_test.go` |
| BLE central and peripheral (via seams and fakes, no hardware) | `pkg/phone/ble_transport_*_test.go`, `ble_peripheral_*_test.go` |
| Builds without the `ble` tag | `pkg/phone/ble_stub_test.go` |

### Benchmarks

```bash
go test -bench=. ./pkg/phone/                                # in xkey/
go test -bench=. ./pkg/pairingproto/ ./pkg/trust/bootstrap/  # in the repo root
```

- `BenchmarkNoiseHandshake`, `BenchmarkNoiseEncrypt` (`pkg/trust/bootstrap/noise_session_test.go:483`, `:894`)
- `BenchmarkFragment`, `BenchmarkReassemble` (`pkg/pairingproto/fragmentation_test.go:311`, `:322`)
- `BenchmarkHexEncodeCredentialID` (`pkg/phone/phone_test.go:325`)

## Phone Integration Tests

`make integration-test-phone` (`Makefile:544`) runs
`./test/integration/phone/...` under the `integration` tag. No BLE hardware
is involved:

| File | What it covers |
|------|----------------|
| `phone_integration_test.go` | `xkey device` CLI surface: help, list, status, unpair, relay, the `phone` alias |
| `tcp_e2e_test.go` | Full protocol over TCP against an in-process phone server (`tcp_phone_server.go`): handshake, ping, getInfo, generateKey, sign, deleteKey, loadKey, errors, concurrency, reconnect, all algorithms |
| `android_e2e_test.go` | Emulator boot and TCP pairing; needs the additional `androidemu` tag |

`mock_phone.go` and `mock_transport.go` simulate the phone and the transport
in-process.

## BLE Integration Tests

`make integration-test-ble` (`Makefile:664`) runs
`test/integration/ble/ble_integration_test.go` in a privileged container
against virtual HCI controllers — a real BlueZ stack, no physical hardware:

- `TestVirtualHCIHarness`
- `TestBLEPeripheral_VirtualHCIRoundTrip`
- `TestBLEPeripheral_VirtualHCIRepeatedRequests`

## Manual Testing with a Phone

Needs the xkey-android app and a desktop built with the `ble` tag.

```bash
xkey device pair                 # pair (prints the verification code)
xkey device status               # show paired devices
xkey fido2 --backend phone       # then register/authenticate on a WebAuthn test site
```

## Debugging (Linux)

```bash
sudo btmon                       # monitor BLE traffic
bluetoothctl show                # adapter status
bluetoothctl devices             # known devices
```
