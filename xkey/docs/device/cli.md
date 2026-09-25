# Device Pairing and Enrollment — CLI

> **Status: NORMATIVE** · Feature: `device` · Module: `go-xkms/xkey` · Last verified: 2026-09-25

Binary: `xkey`. Parent command: `xkey device` (also reachable as `xkey
phone`, its cobra alias — `cmd/xkey/cmd/device.go:Aliases`).

This page documents the verbs this feature owns: the base management verbs,
agent enrollment, and QR-assisted relay pairing. The full phone-pairing
verb catalog (`pair`, `scan`, `listen`, `attest`, `attest-device`,
`device-info`, `oath-sync`, `piv-sync`, `share*`, `sync*`, and the
`ble`-tagged barrier/SO-PIN flags shared across them) is documented once, in
[phone-hsm/cli.md](../phone-hsm/cli.md) — it is not repeated here.

## Always compiled (no `ble` tag required)

| Verb | Flags |
|---|---|
| `device list` | — |
| `device unpair <device-name>` | `--force` (skip confirmation) |
| `device status` | `--device` (name filter) |
| `device relay` | `--listen` (host:port; default `phone.relay_listen_address`, `:8444`), `--qr` (show QR code + URI) |
| `device enroll` | `--server` (required, `host:port`), `--code` (rejected — see below), `--name` (default: hostname), `--cert-profile`, `--validity-days` |
| `device connect <address>` | `--tls-cert`, `--tls-key`, `--tls-ca` |

Persistent flag on the whole group: `--trust-new-devices` (allow connecting
to a device with an empty Noise prologue).

```
xkey device list
xkey device list -o json
xkey device status --device "Pixel-8"
xkey device unpair "Pixel-8"
xkey device unpair "Pixel-8" --force
```

## `device relay` and QR pairing

```
xkey device relay                        # listen on phone.relay_listen_address (:8444)
xkey device relay --listen :9443         # override the listen address
xkey device relay --qr                   # also render a terminal QR code + xkey-pair:// URI
```

`--qr` prints a `qrgen.PairingPayload` (protocol version, Noise public key,
listen address, transport `"tcp"`, this host's name) as both an ASCII
terminal QR code and its `xkey-pair://<base64url-json>` URI form. A phone
scans either to obtain the same material `xkey device pair` would have
exchanged over BLE — the Noise XX handshake it then performs is documented
in [phone-hsm/architecture.md](../phone-hsm/architecture.md); this command
has no `--scan` counterpart of its own on the desktop side.

## `device enroll` / `device connect` — agent enrollment

```
xkey device enroll --server master.example.com:9443 --xkmsd-url grpcs://xkms.example.com:8443
xkey device enroll --server master.example.com:9443 --cert-profile client --validity-days 365
xkey device connect master.example.com:9443
```

`enroll` generates an ECDSA P-256 agent key pair, has the xkmsd certificate
authority named by `--xkmsd-url`/`XKMSD_URL` sign the resulting CSR, writes
the key, CSR, certificate and CA trust anchor under the agent certificate
directory (`agent-key.pem` 0600, `agent-csr.pem`, `agent-cert.pem`,
`ca-cert.pem`), and then opens a mutually authenticated TLS connection to
`--server` to confirm the master accepts the new certificate. A successful
run always leaves the device able to run `device connect` immediately after.

`--code` exists as a flag but always fails with
`ErrDeviceEnrollCodeUnsupported`: a one-time enrollment code is redeemed by
the master's own enrollment service (`xkey agent` — see
[agent/cli.md](../agent/cli.md)), which has no remote RPC for a device to
call it against. Drop `--code` and point `--xkmsd-url`/`XKMSD_URL` at the
certificate authority instead.

`connect` opens a connection to a previously enrolled master using the
certificate `enroll` wrote; `--tls-cert`/`--tls-key`/`--tls-ca` override the
default file locations when needed.

No CLI verb corresponds to the master's side of this exchange — that is
`xkey agent start`/`status`/`code`/`pending`/`approve`/`reject`/`remove`,
documented in [agent/cli.md](../agent/cli.md).

## Exit codes

`0` on success. Non-zero for: no device found, a scan timeout, a Noise
handshake or attestation mismatch (phone path — see phone-hsm), an invalid
`--server` address, an xkmsd certificate authority error, or the master
refusing the newly issued agent certificate
(`ErrDeviceEnrollMasterUnreachable`).

## Build-tag note

`--help` output for `pair`, `scan`, `listen`, `attest`, `attest-device`,
`device-info`, `share*`, `sync*`, `xkey oath sync`/`push`/`pull`, and `xkey
piv phone-list`/`phone-push-cert`/`phone-pull-cert`/`phone-generate` looks
the same whether or not the binary was built with `-tags ble` — the flags
are registered either way (the latter two groups live under `oath`/`piv`,
not `device`, but share this same build-tag gate). Running one of them
without the tag returns `ErrDeviceBLEUnavailable` ("device: bluetooth
unavailable"); the `--help` text itself says so. See
[architecture.md](architecture.md#build-tag-boundary).
