# Phone Backend — Engineering Contract

> **Status: NORMATIVE** · Feature: `phone` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

For the Noise session, JSON-RPC protocol, and `device` CLI verbs, see
[phone-hsm/engineering.md](../phone-hsm/engineering.md). This document covers
only `xkey/pkg/phone` and the GUI's `PhoneService`.

## Exported surface — `xkey/pkg/phone`

### The FIDO2 key backend

```go
// xkey/pkg/phone/phone.go
const BackendTypePhone xkms.BackendType = xkms.BackendTypePhone

type PhoneKeyBackendConfig struct {
	DeviceAddress             string
	LocalStaticKey            *pairing.StaticKey
	OwnsStaticKey              bool
	ExpectedRemoteStatic       []byte
	TrustNewDevices            bool
	ExpectedDeviceFingerprint  []byte
	ScanTimeout, ConnectTimeout, OperationTimeout time.Duration
	MTU                        int
	Logger                     *slog.Logger
	Notifier                   notify.Notifier
	AuditLogger                audit.Logger
	DeviceName                 string
	RequireLiveAttestation     bool
	LiveAttest                 pairing.LiveAttestFunc
}

func DefaultPhoneKeyBackendConfig() *PhoneKeyBackendConfig
func NewPhoneKeyBackend(cfg *PhoneKeyBackendConfig) (*PhoneKeyBackend, error)
func NewPhoneKeyBackendWithTransport(cfg *PhoneKeyBackendConfig, transport pairing.Transport) (*PhoneKeyBackend, error)

type PhoneKeyBackend struct{ … } // implements keybackend.FIDO2KeyBackend
```

`PhoneKeyBackend` methods: `Type`, `Capabilities`, `Connect`,
`EnableBidirectional`, `SendRequest`, `GenerateCredentialKey`, `Sign`,
`LoadKey`, `DeleteKey`, `ExportPrivateKey`/`ImportPrivateKey` (both return
`ErrExportNotSupported`/`ErrImportNotSupported` — private keys never leave
the phone), `Close`, `IsConnected`, `ConnectedAddress`,
`LocalStaticPublicKey`, `RemoteStaticPublicKey`, `GetDeviceInfo`, `Ping`,
`SendPairingConfirm`, `ListFido2Credentials`, `SignFido2Assertion`,
`Notifier` (`xkey/pkg/phone/phone.go:436-1584`).

### Transports

```go
// xkey/pkg/phone/transport.go
type BLECapableTransport interface {
	pairing.Transport
	Scan(ctx context.Context) ([]ScanResult, error)
	ConnectWithBondedAddress(ctx context.Context, address, bondedAddress string) error
	Disconnect() error
	ConnectedAddress() string
	CleanStaleBlueZEntry(address string)
	DisconnectAndRemove() error
}
```

| Type | File | Build tag | Role |
|---|---|---|---|
| `BLETransport` | `ble_transport.go` | `ble` | BLE central (this host initiates) |
| `BLEPeripheral` | `ble_peripheral.go` | `ble` | BLE peripheral/GATT server (this host accepts) |
| `USBTransport` | `usb_transport.go` | `usb` | USB Accessory Mode client |
| `TCPPairingServer` | `tcp_server.go` | (none) | TCP relay responder, default `:8444` |

Without the `ble`/`usb` tag, `BLETransport`/`BLEPeripheral`/`USBTransport`
still exist with the identical exported surface (constructors, config
structs, methods) but every method returns `ErrBLEUnavailable` /
`ErrUSBUnavailable` — callers compile against one surface regardless of build
(`ble_transport_stub.go`, `ble_peripheral_stub.go`, `usb_transport_stub.go`).

### Attestation continuity

```go
// xkey/pkg/phone/fingerprint.go
const DeviceFingerprintSize = pairing.IdentityAckKnownSize - 1 // 32

func DecodeDeviceFingerprint(encoded string) ([]byte, error)

var ErrInvalidDeviceFingerprint = errors.New(...)
type InvalidDeviceFingerprintError struct {
	Value    string // bounded to 32 chars
	ValueLen int
	Err      error
}
```

`""` decodes to `(nil, nil)` — "no fingerprint policy configured" — and is
the only input that does. Every other invalid input returns
`*InvalidDeviceFingerprintError`, never `(nil, nil)`
(`fingerprint.go:168-196`).

### Errors — `xkey/pkg/phone/errors.go`

Most sentinels are re-exported from `xkey/pkg/pairing` so `errors.Is`
matches across both packages (`ErrNotConnected`, `ErrConnectionFailed`,
`ErrDeviceNotFound`, `ErrPairingFailed`, `ErrNoiseHandshakeFailed`,
`ErrBackendClosed`, `ErrUnsupportedAlgorithm`, `ErrExportNotSupported`,
`ErrImportNotSupported`, and ~50 more — see `errors.go:37-105` for the full
list). Phone-only sentinels:

| Error | Meaning |
|---|---|
| `ErrBLEUnavailable` | Bluetooth unavailable, or built without `-tags ble` |
| `ErrUSBUnavailable` | Built without `-tags usb` |
| `ErrBLEPeripheralStopped` | Peripheral stopped; no further connections accepted |
| `ErrAdapterDisabled` | Bluetooth adapter disabled |
| `ErrServiceNotFound` / `ErrCharacteristicNotFound` | The xKey BLE GATT service/characteristic was not found — see [../ble/](../ble/architecture.md) |
| `ErrDBusStaleObject` | BlueZ D-Bus stale object; caller should re-scan |
| `ErrShutdownIncomplete` | `Close`/`Stop` could not confirm every reader finished; the component IS shut down, but a caller that supplied a *borrowed* static key must not destroy it on this error — see the doc comment at `errors.go:136-154` |
| `ErrLiveAttestationUnavailable` | `RequireLiveAttestation` set with no `LiveAttest` verifier configured — a refusal, not a skip (`errors.go:24-33`) |

Typed wrappers `MessageError`, `SentinelCauseError`, `WrappedError`
(`errors.go:157-202`) replace inline `fmt.Errorf` construction throughout
the package.

## Invariants

- **Static-key custody is explicit, never implicit.** `OwnsStaticKey`
  decides who destroys `LocalStaticKey`. A caller that transfers ownership
  must not keep using the pointer afterward — `newPhoneKeyBackend` and
  `NewTCPPairingServer` both consume it out of the config on success rather
  than leaving a second owner for the same protected pages
  (`phone.go:343-361`, `tcp_server.go:194-201`).
- **`Close`/`Stop` is idempotent and latched**, not "first caller wins."
  `sync.Once` ensures every caller — concurrent or repeated — observes the
  same outcome, including `ErrShutdownIncomplete`
  (`phone.go:1130-1147`, `tcp_server.go:262-272`).
- **A borrowed key is retained, never destroyed, on `ErrShutdownIncomplete`.**
  The error means "a reader might still be using those pages," and it is
  reported precisely so the key's actual owner — not this package — decides
  whether to free them (`phone.go:1117-1147`, `errors.go:136-154`).
- **`directMu` serializes the whole encrypt→send→receive→decrypt sequence**
  on the direct (non-router) send path, because a Noise `CipherState`
  advances a monotonic nonce per message and is not concurrency-safe
  (`phone.go:196-209`).
- **`RequireLiveAttestation` fails closed on a missing verifier.** Treating
  a nil `LiveAttest` as "no policy configured" would make the control
  vanish on exactly the caller mistake it exists to catch
  (`phone.go:136-147`).

## Configuration

### `xkey fido2 --backend phone`

| Source | Key | Meaning |
|---|---|---|
| flag | `--phone-device` | Device name or address; falls back to the config's default device, then the first paired device (`fido2_device.go:38-71`) |
| `devices.yaml` | shared with the CLI's `device` group | Paired-device records: name, address, static keys, stored fingerprint, attestation policy |

### Bidirectional xkmsd bridge (`xkey fido2 --backend phone` only)

No CLI flags — config file / environment only, read via viper
(`xkey/cmd/xkey/cmd/fido2_phone_bridge.go:91-104`):

| Key | Default | Meaning |
|---|---|---|
| `xkmsd.enabled` | `false` | Bridge is a no-op unless set |
| `xkmsd.protocol` | `unix` | `unix` only |
| `xkmsd.address` | `xkms-data/xkms.sock` | Socket path or `host:port` |
| `xkmsd.connect_timeout` | `10s` | |
| `xkmsd.request_timeout` | `30s` | |
| `xkmsd.tls_ca_file` | system trust store | CA that verifies xkmsd's socket certificate |
| `xkmsd.tls_cert_file` / `xkmsd.tls_key_file` | — | Client certificate and key that admit xkey on xkmsd's TLS socket |
| `xkmsd.sharing.allowed_backends` / `xkmsd.sharing.denied_backends` | — | Restricts which xkmsd backends the phone's `remote.*` requests can reach |
| `xkmsd.tpm.enrollment` | `false` | Offer this host's TPM to the phone acting as enterprise CA |
| `xkmsd.tpm.device` / `xkmsd.tpm.pcr_bank` | `/dev/tpmrm0` / stack default | |

## Exported surface — GUI `PhoneService`

`xkey/pkg/gui/services/phone_service.go`. Grouped by concern (all are
Wails-bound; see [api.md](api.md)):

| Group | Methods |
|---|---|
| Setup | `SetContext`, `SetEventEmitter`, `SetStatusChangeFunc`, `SetTrustStore`, `SetBarrierService` |
| Discovery / inventory | `ListDevices`, `GetDeviceStatus`, `Scan` |
| Pairing | `Pair`, `Unpair`, `SetDeviceAsBackend`, `GetBackendDevices` |
| Connection | `Connect`, `Disconnect`, `IsConnected`, `ConnectedDeviceName`, `RetainedKeyCount` |
| Attestation | `AttestDevice`, `SetAttestationPolicy`, `ClearAttestationPolicy`, `GetAttestationPolicy` |

(line numbers: `phone_service.go:334-2153`, exact per-method lines listed in
[api.md](api.md)).

### The local Noise private key is barrier-sealed, not written in plaintext by default policy

`resolveNoiseKeyBarrier`/`sealOrWarnLocalNoiseKey`
(`phone_service.go:387-461`) mirror the CLI's `device_barrier_shared.go`
behavior documented in phone-hsm's engineering.md (#42 owner ruling): if a barrier is
initialized on this host but not currently open, `Pair`/`Connect` refuse
with `ErrPhoneBarrierRequired` rather than falling back to plaintext. A host
with **no barrier at all** is not refused — the key is written unsealed with
a logged warning, the same legacy-compat behavior the CLI path uses.

### `GetDeviceStatus` — current behavior, verified in code

`GetDeviceStatus(name)` returns `ErrPhoneDeviceNotFound` for an empty name
and `ErrPhoneNotConnected` for every non-empty name today — it does not
look up per-device live status yet (`phone_service.go:494-499`). Documented
here rather than assumed, per this folder's citation requirement.

## Tests

Representative files (not exhaustive): `phone_happy_path_test.go`,
`phone_error_paths_test.go`, `phone_directpath_test.go`,
`phone_boundeddrain_test.go`/`phone_boundeddrain_noble_test.go`,
`phone_connect_ble_test.go`, `phone_proveliveness_test.go`,
`phone_keyownership_test.go`, `retention_test.go`, `fingerprint_test.go`,
`ble_transport_seams_test.go`, `ble_peripheral_shutdown_test.go`,
`ble_peripheral_acceptconnection_test.go`,
`ble_peripheral_advertising_test.go`, `ble_peripheral_handlewrite_test.go`,
`usb_transport_test.go`, `usb_framing_test.go`, `usb_transport_stub_test.go`,
`tcp_server_test.go`, `tcp_e2e_test.go`, `errors_test.go` (all under
`xkey/pkg/phone/`), plus `phone_service_test.go`,
`phone_service_coverage_test.go`, `phone_service_drain_test.go`,
`phone_service_teardown_test.go`, `phone_pair_attestation_test.go`,
`phone_liveness_test.go`, `phone_record_roundtrip_test.go`,
`phone_barrier_test_helper_test.go`,
`phone_storage_trust_coverage_test.go` (under `xkey/pkg/gui/services/`).
