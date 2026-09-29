# Device Pairing and Enrollment — Architecture

> **Status: NORMATIVE** · Feature: `device` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

## The problem

`xkey device` is the single CLI namespace under which xkey brings a second
machine into its trust boundary. Two, quite different, second machines land
here:

- a **phone**, whose TEE/StrongBox becomes a hardware key backend reachable
  over BLE, USB or TCP; and
- a **remote agent**, another host that wants to reuse this host's xkmsd
  backends over the network.

Both need a bootstrap step before any operation can be trusted, and both
happen to be invoked as `xkey device <verb>`. That shared front door is the
entire scope of this feature; the two bootstraps behind it are architecturally
unrelated and are owned by different documents.

## Shape chosen: one CLI namespace, two independent trust mechanisms

| | Phone pairing | Agent enrollment |
|---|---|---|
| Verbs | `pair`, `scan`, `list`, `unpair`, `status`, `listen`, `relay`, `attest`, `attest-device`, `device-info`, `oath-sync`, `piv-sync`, `share*`, `sync*` | `enroll`, `connect` |
| Trust primitive | Noise XX mutual handshake (`xkey/pkg/pairing`) | X.509 client certificate signed by the xkmsd CA |
| Where the record lives | `devices.yaml` (`pairing.PairedDevice`) | PEM files under the agent certificate directory (`agent-key.pem`, `agent-cert.pem`, `ca-cert.pem`) |
| Build gate | `ble` build tag (`cmd/xkey/cmd/device_pair.go:14` `//go:build ble`) | none — always compiled |
| Owning feature folder | [phone-hsm](../phone-hsm/) | [agent](../agent/) (server side); this folder (client side) |

They share a command tree for discoverability — a user reaching for "how do I
connect another machine to xkey" should find every answer under `xkey
device` — but they share no code path below the CLI layer. `pairing.PairedDevice`
(`xkey/pkg/pairing/device.go`) is phone-only; the agent flow never
constructs one, and `cmd/xkey/cmd/device_enroll.go`'s `deviceEnrollCA`
interface never touches `xkey/pkg/pairing` at all.

## What this folder owns vs. what it links to

**This folder owns**: the `device enroll` / `device connect` client-side
agent-enrollment flow (the counterpart to [agent](../agent/)'s server side)
and the devices.yaml multi-record config format as a CLI artifact.
`xkey/pkg/qrgen`/`xkey/pkg/qrscan` are covered under "QR pairing was removed
from `device relay`" below — no CLI verb constructs a `qrgen.PairingPayload`
any more.

**[phone-hsm](../phone-hsm/) owns**: everything about *why* phone pairing is
shaped the way it is — the Noise XX protocol choice, the attestation model,
the barrier custody of the local Noise private key (#42), the SO-PIN-gated
enterprise pairing policy (#118), and the full verb-by-verb operational
reference for `pair`, `scan`, `listen`, `attest*`, `*-sync`, `share*`. Those
verbs are documented once, in [phone-hsm/cli.md](../phone-hsm/cli.md) and
[phone-hsm/architecture.md](../phone-hsm/architecture.md); this folder does
not repeat them, only locates them.

**[agent](../agent/) owns**: the master/server side of enrollment — the
enrollment store, one-time codes, admin approval, and the connection-time
revocation check. This folder owns the other end of that same protocol: the
device that runs `enroll` to obtain a certificate and `connect` to use it.

## Rejected: a unified device-type record

An earlier design sketch, visible only as unused exports until #130 deleted
them, tried to unify all of this under one model: `pairing.DeviceType`
(phone / agent / desktop / usb), a `pairing.EnrollmentMethod`, and a separate
`pairing.AttestationPolicy` (`RequireTPM`, `RequireSecureBoot`, …) sitting
beside `pairing.PairedDevice`. None of the four were ever constructed or
enforced by any command. They were removed as dead exports rather than kept
as an aspirational API. The legacy `device/README.md` this folder supersedes
still carried a "Supported Device Types" table listing `desktop` and `usb` as
pairable types with their own transports — that table described the deleted
sketch, not the code; there is no desktop or USB device type today, and the
correct read of `usb` in this feature is a *transport* for phone pairing
(USB AOA), not a device kind. See [engineering.md](engineering.md) for the
real `PairedDevice` shape.

## QR pairing was removed from `device relay` (go-xkms#1306)

`xkey device relay` used to accept a `--qr` flag that rendered a
`pairing.PairingPayload` (`xkey/pkg/qrgen/payload.go`) — protocol version, a
freshly generated Noise public key, TCP address, transport tag, host name
— as a terminal QR code and an `xkey-pair://` URI, framed as an alternative
way to carry the Noise XX bootstrap material to a phone when BLE was not
available. An audit found it did not work as an alternative pairing path at
all: the relay never read the payload's `Code` field, wired no `pairing
confirm` handler and no `RequestHandler` at all (`ErrTCPServerNotRunning`
aside, every request got "method not found"), and generated a throwaway key
every invocation that nothing could ever be pinned to. There was never a
working QR-based pairing flow to carry forward, and `xkey device pair`
(BLE) has no TCP counterpart today.

`device relay` was redesigned around what it can actually be: the TCP
counterpart to `device listen`'s BLE peripheral, serving an **already
paired** device's session (pinned to that device's stored Noise static key,
gated on live attestation), never a first-pairing mechanism. `--qr` is gone.
See [phone-hsm/cli.md](../phone-hsm/cli.md#connectivity) and
[phone-hsm/user.md](../phone-hsm/user.md#when-the-phone-is-not-on-the-same-bus)
for the current command.

`xkey/pkg/qrgen` and `xkey/pkg/qrscan` are unchanged and still exist, but as
of this change no `xkey device` (or any other) CLI verb constructs a
`qrgen.PairingPayload` or drives `qrscan.ScanModePairing` — both packages
are reachable only as libraries, with no current caller. Reviving a
QR-based pairing flow would need a real protocol addition (a one-time code
verified by both sides, at minimum) coordinated with xkey-android, not a
restoration of the flag removed here.

## Build-tag boundary

A binary built without `-tags ble` still has a full `xkey device` command:
`list`, `unpair`, `status`, `relay`, `enroll`, `connect` all work, because
none of those six files carry a `ble` build constraint. Every phone-pairing
verb compiles instead from a `//go:build !ble` stub
(`cmd/xkey/cmd/device_pair_stub.go` and its siblings) that registers the same
flags — so `--help` looks identical either way — and returns
`ErrDeviceBLEUnavailable` when run. This is a compile-time capability split,
not a runtime feature flag: there is no way to detect at runtime which set a
given `xkey` binary was built with other than trying the command.

## Trust boundaries

- **Agent enrollment never signs anything locally.** `device enroll` submits
  a CSR to the xkmsd certificate authority named by `--xkmsd-url`/`XKMSD_URL`
  and fails closed with no CA configured
  (`cmd/xkey/cmd/device_enroll.go:ErrDeviceEnrollServerRequired` and
  friends). The issued certificate is only trusted once this same command has
  confirmed the master named by `--server` accepts it in a real mTLS
  handshake (`deviceEnrollMasterProbe`).
- **One-time enrollment codes cannot be redeemed remotely.** `--code` on
  `device enroll` returns `ErrDeviceEnrollCodeUnsupported`: codes are
  consumed by the master's own enrollment service (see
  [agent/cli.md](../agent/cli.md#xkey-agent-code)), which exposes no RPC for
  a remote device to call.
- **Phone pairing's trust model — Noise XX, attestation binding, barrier
  custody of the local static key — is documented once, in
  [phone-hsm/architecture.md](../phone-hsm/architecture.md).**

## What this feature deliberately does not do

- **It has no GUI binding.** `pkg/gui/services/pairing_service.go`'s
  `PairingService` is the browser-extension native-messaging pairing service
  (see the AutoFill/headless-WebAuthn surface) — an unrelated feature that
  happens to share the word "pairing". `xkey device` (phone and agent) is
  CLI-only; there is no Wails-bound equivalent of `device pair` or `device
  enroll` today.
- **It does not implement the phone side.** That is xkey-android, per
  [phone-hsm/architecture.md](../phone-hsm/architecture.md#component-boundaries).
- **It does not persist agent enrollment records.** Those live in
  [agent](../agent/)'s `FileStore`, on the master; this folder's `enroll`
  only writes this device's own key, CSR, certificate and CA trust anchor.
