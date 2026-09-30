# Static Passwords — API

> **Status: NORMATIVE** · Feature: `password` · Module: `go-xkms/xkey` · Last verified: 2026-09-30

Two separate transports, matching the "store location vs. session state"
split in [architecture.md](architecture.md):

## Local: CLI, GUI bindings, and the daemon IPC socket

Store CRUD (`add`/`get`/`list`/`remove`) and the GUI's
`pkg/gui/services.StaticPasswordService` (Wails bindings, see
[engineering.md](engineering.md)) reach the store directly — no network
transport, no `xkmsd` server required.

`xkey touch` and `xkey password type` talk to the running `xkey fido2`
daemon over a local Unix domain socket (mode `0600`), the same IPC server
documented in [autofill/api.md](../autofill/api.md) (`touch`,
`type_password` message types). `xkey password list --source
daemon|auto` and `xkey password status --source daemon|auto` use the same
socket to ask the daemon for its live view of the barrier-backed store
(`ipc.Client.StatePasswordList`/`StatePasswordStore`) — read-only, no
values.

## Remote: `xkmsd` session server

`xkey password unlock`/`lock`/`access-mode`, and `xkey password status
--source xkmsd`, are the one part of this feature that crosses the network:
they use `sdk/go/transport.PasswordService` (`Connect`, `Close`,
`PasswordStoreUnlock`, `PasswordStoreLock`, `PasswordStoreStatus`,
`PasswordStoreSetAccessMode`) against an `xkmsd` server selected by
`--xkmsd-url`/`XKMSD_URL`/config, through the shared `newXKMSdClient`
helper every xkey command group uses for xkmsd connectivity. The GUI's
`StaticPasswordService` reaches the identical session verbs through
`SetClient(transport.Client)`.

No REST or gRPC surface is defined by this feature folder itself; `xkmsd`'s
own transport implementation (TLS, auth, wire framing) is documented where
`xkmsd` is documented, not here.
