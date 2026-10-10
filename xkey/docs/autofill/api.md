# Browser Extension AutoFill — API

> **Status: NORMATIVE** · Feature: `autofill` · Module: `go-xkms/xkey` · Last verified: 2026-10-09

Three transports carry this feature's traffic, all local to the machine
running xKey — none of it crosses the network.

## Native messaging (browser ↔ host)

stdin/stdout, length-prefixed JSON (`pkg/nativemsg.ReadMessage`/
`WriteMessage`: 4-byte little-endian length + JSON payload, 1 MB max per
Chrome's limit). Message types (`pkg/nativemsg/host.go`):
`handshake`/`handshake_ok` (X25519 key exchange), `handshake_pair` (host
requires pairing), `handshake_rejected` (identity check failed),
`pairing_confirm`/`pairing_ok`/`pairing_failed` (pairing-code ceremony),
`encrypted` (every payload after handshake, AES-256-GCM with a monotonic
nonce), `error`. See [architecture.md](architecture.md) for the full
handshake/pairing sequence.

The browser launches the host process via the installed native messaging
manifest (`xkey extension host`, or the equivalent embedded in `xkey
extension serve`'s process for the headless case) — see [cli.md](cli.md).

## IPC (host ↔ GUI or headless server)

Unix domain socket (mode `0600`, directory mode `0700`), JSON message
framing, map-based O(1) dispatch (`pkg/ipc`). It exists only while local
app access is on: in the GUI, only while xKey is also unlocked. With the
setting off, the native host finds no socket. Two message types this
feature owns:

- `autofill` — `AutofillPayload{Action, Domain, ID, Challenge, Username,
  Password, Title}`, actions `search`, `get`, `totp`, `totp_by_id`,
  `status`, `policy`, `save`, `ignore_domain`, `focus`. Dispatched to
  whichever process implements `ipc.AutofillHandler` — `AutoFillService`
  in both the GUI and `xkey extension serve`.
- `pairing` — `PairingPayload{Action, Code, IdentityKey, Origin}`, actions
  `notify_code` (host → server: display this code) and `completed` (host →
  server: pairing finished for this origin). Dispatched to
  `ipc.PairingHandler`.

See [engineering.md](engineering.md) for the full payload/result type
definitions and the handler interfaces.

## GUI bindings (Wails)

`pkg/gui/services.AutoFillService` and `pkg/gui/services.PairingService`
are registered as Wails bindings, callable directly from the Svelte
frontend as Go methods (no serialization boundary beyond Wails' own
JSON marshaling of the same request/result types the IPC transport uses).
`PairingService` additionally emits Wails events
(`extension:pairing_request`, `extension:paired`, `extension:unpaired`) so
the frontend can react to a pairing ceremony started by an external native
host process (e.g. Firefox), not just one it initiated itself.

## Not present

No REST or gRPC surface, and no dependency on a remote `xkmsd` server: every
transport above terminates on the same machine as the browser.
