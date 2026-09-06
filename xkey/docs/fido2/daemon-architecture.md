# FIDO2 Daemon Architecture

The daemon is one process, `fido2Device` in
`xkey/cmd/xkey/cmd/fido2.go`, holding every component below. This document
covers how those pieces fit together; for the CTAP2 authenticator library
itself see [authenticator-architecture.md](authenticator-architecture.md).

## Components

| Field | Type | Responsibility |
|-------|------|----------------|
| `uhidDevice` | `uhid.Device` | The virtual USB HID device — what makes the OS see a security key |
| `hidHandler` | `authenticator.CTAPHIDHandler` | Frames CTAPHID traffic on and off the HID device |
| `auth` | `authenticator.Authenticator` | The CTAP2 authenticator: credential creation, assertion, PIN |
| `storage` | `authenticator.StatefulCredentialStorage` | Credential persistence (memory or file) |
| `keyBackend` | `keybackend.FIDO2KeyBackend` | Where private keys live: software, TPM 2.0, or phone |
| `keyboard` | `keyboard.Keyboard` | Virtual keyboard used to type stored passwords |
| `pwStore` | `xkms.StaticPasswordBackendStore` | The static password store behind autofill and `xkey touch --password` |
| `ipcServer` | `ipc.Server` | Unix socket serving unlock, touch, status and autofill |
| `socketHandler` | `authenticator.SocketHandler` | Turns socket approvals into user-presence answers |
| `notifier` | `notify.Notifier` | Tells the user a touch is pending |
| `cdpBridge` | `cdp.Bridge` | Alternative to UHID: drives Chrome's virtual authenticator |

## Two ways in

The authenticator is reachable over either transport, and they are mutually
exclusive in practice:

```
Browser --USB HID--> /dev/uhid --> CTAPHIDHandler --> Authenticator --> KeyBackend
Chrome  --CDP------> cdp.Bridge -------------------> Authenticator --> KeyBackend
```

UHID is the realistic path — the OS genuinely sees a security key, and any
browser can use it — but it needs `/dev/uhid`, which normally means root. The
CDP bridge needs no device node and no privileges, but only works against a
Chrome started with remote debugging, and only for that Chrome.

## User presence

A CTAP2 ceremony that requires user presence has to get an answer from
somewhere. The daemon has three ways to produce one:

1. **PIN in place of touch** — `--require-touch=false` skips the presence
   request after a verified PIN, because the PIN was the deliberate act. A
   ceremony that carried no PIN still asks. The daemon never reports user
   verification it did not perform: `getInfo` says `uv=false` where a PIN is
   the verification method, so a browser collects the PIN in its own dialog.
2. **Interactive** — `--interactive` prompts on the terminal.
3. **Socket** — the default for service deployments. The notifier tells the
   user, and the request blocks on `SocketHandler` until something calls the
   IPC socket. That something is normally `xkey touch`.

The request fails when nothing answers within `--timeout` (30s by default).

## The IPC socket

The socket lives at `$XDG_RUNTIME_DIR/xkey/xkey.sock`, falling back to
`/tmp/xkey-$UID/xkey.sock` when `XDG_RUNTIME_DIR` is unset (`pkg/ipc/socket.go`).
`--socket` overrides it. Three kinds of client use it:

- **`xkey touch`** approves a pending presence request, or types a stored
  password through the virtual keyboard.
- **`xkey unlock`** unlocks the running instance with a PIN.
- **The browser extension** searches the password store by domain, fetches a
  credential, requests a TOTP code, and queries status and policy.

The client methods are `Touch`, `TypePassword`, `Status`, `Unlock`,
`AutofillSearch`, `AutofillGet`, `AutofillTOTP`, `AutofillTOTPByID`,
`AutofillStatus` and `AutofillPolicy` (`pkg/ipc/client.go`). A response carries
a status of `ok` or `error` and an action such as `approved_up`,
`typed_password`, `no_pending` or `daemon_ready`.

## Notifiers

`notify.Notifier` has several implementations, selected by `--notify` and
`--notify-command`:

| Implementation | Used for |
|----------------|----------|
| `DBusNotifier` | Desktop notifications over D-Bus |
| `CommandNotifier` | A custom command, from `--notify-command` |
| `LogNotifier` | Log-only, for headless deployments |
| `WailsNotifier` | Notifications inside the GUI |
| `MultiNotifier` | Fan-out to several of the above |

## See Also

- [Daemon Overview](overview.md)
- [Daemon Configuration](daemon-configuration.md)
- [Authenticator Architecture](authenticator-architecture.md) -- the CTAP2 library internals
- [Authenticator Security](authenticator-security.md) -- key hierarchy and threat model
