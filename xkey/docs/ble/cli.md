# BLE Transport — CLI

> **Status: NORMATIVE** · Feature: `ble` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

BLE is reached through `xkey device` (aliased `xkey phone`), the same
command group `xkey/docs/phone-hsm/` documents for every transport. This
page covers only the three verbs whose implementation is BLE-specific —
`pair`, `scan`, and `listen` — and the build-tag gate that applies to
(almost) the entire `device` group. Every other `device` verb (`attest`,
`sync`, `share`, `enroll-phone`, ...) operates on an already-connected
session and is documented in `xkey/docs/phone-hsm/cli.md`.

## The `ble` build-tag gate

Every file under `cmd/xkey/cmd/device_*.go` except `device.go`,
`device_enroll.go`, `device_relay.go` (TCP relay — no BLE needed), and
`device_share_policy.go` carries `//go:build ble`, with a matching
`//go:build !ble` stub registering the same `Use`, flags, and help text but
returning `ErrDeviceBLEUnavailable` from `RunE`
(`cmd/xkey/cmd/device_pair_stub.go` and siblings). A binary built without
`-tags ble` (the default `go build ./cmd/xkey` with no tags) still shows
these commands in `--help`; running one fails with that sentinel and a
"rebuild with `-tags ble`" hint in `--help`'s long description. The
Makefile's `make build` target **does** include `ble` (architecture.md),
so the combined GUI+CLI binary it produces has it; a bare `go build
./cmd/xkey` does not.

## `xkey device pair` — central: scan and connect

```bash
xkey device pair [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--device` | string | | Specific device name or address to pair |
| `--timeout` | duration | `30s` | Scan timeout duration |
| `--force` | bool | `false` | Force re-pairing even if already paired |
| `--so-pin-stdin` | bool | `false` | Read the SO PIN from standard input (enterprise policy verification) |
| `--barrier-password`, `--barrier-password-file` | string | | Barrier password, for sealing the new Noise static key (#42) |

```bash
xkey device pair                                 # scan and interactively select
xkey device pair --device "John's Pixel"
xkey device pair --timeout 60s
xkey device pair --device "John's Pixel" --force
echo -n "$SO_PIN" | xkey device pair --so-pin-stdin
```

Steps (`cmd/xkey/cmd/device_pair.go`, `runDevicePair`): enable the adapter →
scan for the xKey GATT service → let the user pick a result → BLE-connect
→ Noise XX handshake → verify hardware attestation → save the pairing
record. `pairingTransport` is an injection seam
(`newBLEPairingTransport` wires the real `phone.NewBLETransport` in
production) so the command can be driven in tests without a radio.

## `xkey device scan` — central: discovery only

```bash
xkey device scan [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--timeout` | duration | `30s` | Scan timeout duration |

Lists nearby devices advertising the xKey GATT service without connecting
or pairing.

## `xkey device listen` — peripheral: accept phone-initiated connections

```bash
xkey device listen [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--device` | string | | Specific paired device to accept connections from |
| `--name` | string | (hostname) | Advertised device name |
| `--timeout` | duration | `0s` (indefinite) | Listen timeout |
| `--attestation-mode` | string | `auto` | `auto` \| `tpm2` \| `software` |
| `--tpm-enrollment` | bool | `false` | Also serve TCG-CSR-IDEVID device enrollment from this host's TPM |
| `--tpm-device` | string | `/dev/tpmrm0` | TPM2 device path |
| `--tpm-pcr-bank` | string | | PCR bank for the platform policy digest (default SHA-256) |
| `--barrier-password`, `--barrier-password-file` | string | | Barrier password |

```bash
xkey device listen                          # default paired device, indefinite
xkey device listen --device "John's Pixel"
xkey device listen --name "My Laptop"
xkey device listen --timeout 5m
xkey device listen --attestation-mode tpm2
xkey device listen --tpm-enrollment
```

Starts the desktop as a `BLEPeripheral`, advertising the xKey service.
Once the paired phone connects and completes the Noise handshake, this
laptop serves requests from it — the documented use case is the phone
asking for re-attestation, but any method the pairing protocol defines can
arrive this direction. With `--tpm-enrollment`, a `remote.attestDevice`
request can additionally drive TCG-CSR-IDEVID enrollment of this host's
TPM against the phone acting as CA; a host with no TPM still listens and
serves everything else, reporting enrollment as unavailable.

## Troubleshooting

- **"BLE unavailable"** / `ErrBLEUnavailable` — Bluetooth adapter could not
  be enabled, or the binary was built without `-tags ble`. `--help` on any
  gated verb states which case applies.
- **Repeated scan failures against a previously-paired phone** — often BLE
  RPA rotation or a stale BlueZ D-Bus object; `device pair`/`connect`
  retries through this automatically (architecture.md "BlueZ integration
  quirks"). `bluetoothctl remove <address>` clears a stuck cache entry
  manually.
- **`xkey device listen` never sees the phone connect** — confirm the phone
  app is actively trying to reach this laptop (it is the one initiating);
  `listen` only advertises and waits, it does not scan.
