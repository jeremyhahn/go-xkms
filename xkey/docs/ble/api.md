# BLE Transport — API

> **Status: NORMATIVE** · Feature: `ble` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

No REST or gRPC surface: BLE is a local radio link between this host and a
paired phone, reachable through the CLI (`cli.md`) and the desktop GUI's
Wails IPC bridge. There is no remote **xkmsd** capability for it, and the
go-xkms SDK's transport contract in `xkey/docs/phone-hsm/api.md` covers the
USB AOA transport specifically — the BLE-specific pieces of the GUI's
`services.PhoneService` are documented here instead, since no existing
feature folder covers them.

## GUI IPC — `services.PhoneService` (BLE-specific methods)

Bound to the Wails runtime the same way `xkey/docs/luks/api.md` describes
for `StorageService`: every method below is callable from the frontend as
`window.go.services.PhoneService.<Method>(...)`.

| Method | Signature | Notes |
|---|---|---|
| `Scan` | `(timeoutSeconds int) ([]DiscoveredDevice, error)` | `timeoutSeconds` must be `1..120` or `ErrPhoneInvalidTimeout`; opens a fresh `phone.BLETransport`, calls `ScanAll`, closes it (`phone_service.go:504-560`) |
| `Pair` | `(address string) (*PairedDevice, error)` | connects the BLE transport to `address`, then hands off to `pairOverTransport` for the handshake/attestation/persist steps shared with every transport (`phone_service.go:571-644`) |

`Scan` also emits an `events.EventPhoneScanResult` event
(`payload: {Devices: []DiscoveredDevicePayload}`) with the same results, so
the frontend can render progressively rather than only on the call's
return.

### `DiscoveredDevice`

```go
type DiscoveredDevice struct {
    Name    string `json:"name"`
    Address string `json:"address"`
    RSSI    int    `json:"rssi"`
}
```

`Name` is `phone.ScanResult.DisplayName()` — the advertised local name, or
`"xKey (<last 5 chars of address>)"` when the phone advertises none.

### Errors

| Condition | Error |
|---|---|
| `timeoutSeconds` outside `1..120` | `ErrPhoneInvalidTimeout` |
| adapter unavailable / not built with `-tags ble` | `ErrPhoneBLEUnavailable` |
| scan started but failed | `ErrPhoneScanFailed` |
| pairing failed | `ErrPhonePairFailed` |
| device already paired | `ErrPhoneAlreadyPaired` |
| pairing-time attestation could not be verified | `ErrPhonePairAttestationRefused` |

Every other `PhoneService` method (`Connect`, `Attest`, `Sync*`, `Share*`,
`Unpair`, ...) operates once a session exists and is not BLE-specific; it
belongs to `xkey/docs/phone-hsm/`, which does not yet document the GUI IPC
layer — only the go-xkms SDK transport contract. That gap is out of this
folder's scope.

## Frontend

`frontend/src/lib/components/PairBLEDialog.svelte` drives `Scan` on open
and `Pair` when the user selects a discovered device
(`selectAndPair`/`startScan` in that file) — it is the only frontend
component that calls these two BLE-specific methods directly.
