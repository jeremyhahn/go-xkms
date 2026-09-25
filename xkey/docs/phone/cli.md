# Phone Backend — CLI

> **Status: NORMATIVE** · Feature: `phone` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

There is no `xkey phone` command group. Pairing, scanning, listening, the TCP
relay, and attestation-by-hand are all under `xkey device *`, documented in
phone-hsm's [cli.md](../phone-hsm/cli.md). This page documents the one verb
this package (`xkey/pkg/phone`) actually adds: selecting the phone as the
FIDO2 daemon's key backend.

## `xkey fido2 --backend phone`

Binary: `xkey`, command `fido2` (`xkey/cmd/xkey/cmd/fido2.go`).

| Flag | Default | Meaning |
|---|---|---|
| `--backend` | `software` | Set to `phone` to use a paired phone's TEE/StrongBox for FIDO2 credential keys |
| `--phone-device` | `""` (default paired device) | Device name or address from `devices.yaml`; falls back to the config's default device, then the first paired device |

```
# Requires a device already paired via `xkey device pair` (phone-hsm)
sudo xkey fido2 --backend phone

# Target a specific paired device
sudo xkey fido2 --backend phone --phone-device "Pixel-8"
```

Requirements, verified in code:

- Built with `-tags ble` — without it, selecting `--backend phone` fails
  immediately with `ErrFIDO2BLENotAvailable`
  (`xkey/cmd/xkey/cmd/fido2_phone_stub.go`).
- A device already present in `devices.yaml` (paired via `xkey device pair`)
  — otherwise `ErrFIDO2DeviceConfigRequired`
  (`xkey/cmd/xkey/cmd/fido2_device.go:36-38, 66-72`).
- If `--phone-device` is given and matches no paired device's name or
  address, `xkey fido2` fails to start with a detailed
  "device '<name>' not found in paired devices" error
  (`fido2_device.go:52-53`).

`xkey fido2 --backend phone` pre-connects to the phone before serving any
FIDO2 request, so a failure is visible at startup rather than on the first
authentication attempt (`fido2_device.go:103-110`). If Android has rotated
its BLE Resolvable Private Address since pairing, the connected address is
written back into `devices.yaml` automatically (`fido2_device.go:112-131`).

### Bidirectional xkmsd bridge

When `xkmsd.enabled: true` is set in the xkey config (there is no flag for
this — see [engineering.md](engineering.md)'s configuration table),
`xkey fido2 --backend phone` also connects to this host's own xkmsd and
enables bidirectional routing, so the phone can call back into this host's
key backends over `remote.*` requests while the phone continues answering
this host's `local.*` FIDO2 requests
(`xkey/cmd/xkey/cmd/fido2_phone_bridge.go:177-224`).

## Related verbs (documented in phone-hsm)

| Verb | Purpose |
|---|---|
| `xkey device pair` | Pair a phone before `--backend phone` can use it |
| `xkey device scan` / `list` / `status` / `unpair` | Inventory management |
| `xkey device listen` | Desktop as BLE peripheral (phone connects to it) — uses `phone.BLEPeripheral` from this package |
| `xkey device relay` | TCP relay path — uses `phone.TCPPairingServer` from this package |
| `xkey device attest-device` | Manual attestation check |

See [../phone-hsm/cli.md](../phone-hsm/cli.md) for flags and examples.
