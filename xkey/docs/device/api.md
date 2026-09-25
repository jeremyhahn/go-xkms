# Device Pairing and Enrollment — API

> **Status: NORMATIVE** · Feature: `device` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

No REST, gRPC or MCP transport surface of its own, and — unlike most
CLI-fronted xkey features — **no GUI (Wails) binding either.**

## Reachable only through the CLI

Every verb under `xkey device` is exercised the same way: as a cobra command
in `cmd/xkey/cmd/device*.go`. There is no `pkg/gui/services` type that wraps
`xkey/pkg/pairing` or the agent-enrollment CSR flow. This is a real gap
relative to most other xkey features, not an omission from this page:

- `pkg/gui/services/pairing_service.go`'s `PairingService` is a **different
  feature** that happens to share the word "pairing" — it is the browser
  extension's native-messaging pairing verifier (`RequestPairing`,
  `VerifyPairingCode`, `InstallManifest`), documented under the AutoFill /
  headless-WebAuthn surface, and has no relationship to `xkey device`.
- `pkg/gui/services/fido2_device_service.go`'s `FIDO2DeviceService` manages
  the virtual FIDO2 UHID device, not a paired phone or agent.

An operator who wants to pair a phone or enroll an agent from the desktop
GUI today has no path other than a terminal running `xkey device ...`
alongside it.

## SDK

`xkey/pkg/qrgen` and `xkey/pkg/qrscan` are ordinary Go packages any Go
program in this module can import directly (payload encode/decode, terminal
QR rendering, screen scanning) — there is no separate SDK facade for them,
and none is needed since they have no network or IPC surface of their own.

`device enroll`'s only outbound call is to the xkmsd certificate authority,
through the same `agent.CAService` / `*xkmsdCA` client
[agent/api.md](../agent/api.md) documents for the master side
(`cmd/xkey/cmd/agent_ca.go`). It reuses that client rather than defining a
second one.

## Capabilities exercised by other surfaces

Nothing outside `cmd/xkey/cmd` currently constructs a `pairing.PairedDevice`
or drives the agent-enrollment CA client on this device's behalf. The
[phone-hsm](../phone-hsm/) capability list documents the phone-operation
surface (`local.*`/`remote.*` JSON-RPC over the paired Noise session) that
*is* reachable once pairing has completed; this feature is only the
bootstrap that gets a device into that state.
