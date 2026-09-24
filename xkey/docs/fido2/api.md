# FIDO2 Daemon and GUI Device Host — API

> **Status: NORMATIVE** · Feature: `fido2` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

No REST/gRPC/QUIC/MCP/embedded surface. `xkey` is a local agent, not a
server; the six-transport rule governs go-xkms's own control surfaces, and
this feature exposes none of them. The CTAP2-over-USB-HID surface the
authenticator itself presents is
[`virtual-authenticator/api.md`](../virtual-authenticator/api.md).

## Local IPC

The daemon's Unix socket (`--socket`, default
`$XDG_RUNTIME_DIR/xkey/xkey.sock`) is the local API this folder owns a slice
of. Filesystem permissions are its access control — there is no
authentication on top. Message types relevant here (`xkey/pkg/ipc/protocol.go`):

| Message | Client method | Used by |
|---|---|---|
| `touch` | `Client.Touch()` | `xkey touch` |
| `type_password` | `Client.TypePassword(name)` | `xkey touch --password` |
| `status` | `Client.Status()` | `xkey fido2 status`, `xkey unlock`'s post-unlock confirmation |
| `unlock` | `Client.Unlock(pin)` | `xkey unlock` |

`autofill`, `pkcs11`, `pairing` and `state` share the same socket and server
but belong to other features: autofill to the password vault, `pkcs11` to
[`pkcs11/ipc.md`](../pkcs11/ipc.md), `pairing` to device pairing, `state` to
whichever subsystem a query names.

## Outbound: the attestation CA

`xkey fido2 provision-attestation` is a client of an existing go-xkms
capability, not a new one: it calls `SignCSR` on the xkms enterprise CA
through `sdk/go/transport` (the same transport the rest of `xkey`'s
`--xkmsd-url`-driven commands use). The CA's own transport surface is
documented under the CA and trust-bootstrap feature docs in the root
`docs/` tree, not here.

## Error mapping

There is no HTTP status mapping because there is no HTTP. IPC responses
carry a status of `ok` or `error` and, on error, a message the CLI wraps in
one of the typed errors listed in
[`engineering.md`](engineering.md#error-semantics).
