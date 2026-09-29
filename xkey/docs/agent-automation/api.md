# Agent Automation — API

> **Status: NORMATIVE** · Feature: `agent-automation` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

Transport shapes:
[`../../../docs/key-management/api.md`](../../../docs/key-management/api.md).

## There is no network API, and that is the design

Automation is entirely local: flags on a daemon, a Unix domain socket, and the
PIN sent with each ceremony. **No server-side endpoint participates**, and no
server flag enables it. An agent authenticating through an unattended daemon
produces exactly the ceremony a human produces, and the relying party cannot
tell — deliberately, because a second trust path would be a second thing to
get wrong. What the ceremony reports is also what happened: UV is set because
the PIN was verified, and a ceremony with no PIN carries no UV.

## The local IPC socket

| Property | Value |
|---|---|
| Path | `--socket` / `XKEY_IPC_SOCKET` if set; else `<XKEY_HOME>/run/xkey.sock` when `XKEY_HOME` is set (a hashed runtime-dir path if that would exceed the `sun_path` limit); else `<runtime dir>/xkey/xkey.sock`, where the runtime dir is `$XDG_RUNTIME_DIR`, or on macOS `$TMPDIR` then `~/Library/Caches`, or elsewhere `~/.xkey/run` (`xkey/pkg/ipc/socket.go:72` `DefaultSocketPath`, `:136` `runtimeDirFor`). Never a shared directory such as `/tmp` |
| Transport | Unix domain socket |
| Access control | filesystem permissions, enforced on both ends: the socket directory must be yours, not a symlink, mode exactly `0700` (`xkey/pkg/ipc/socketdir.go:51`); the client also checks the listener's kernel-reported uid (`xkey/pkg/ipc/peercred.go:26`) |
| Clients | `xkey unlock`, `xkey touch`, `xkey fido2 status`, `xkey auth`, the browser extension's native-messaging host, `go-xkms/sdk/go` |
| Implementation | `xkey/pkg/ipc` |

There is no authentication on the socket itself. Anything that can open it while
the authenticator is unlocked can use the credential. That is the security model,
and it is why the socket lives in a per-user runtime directory.

Because `xkey unlock` sends the user PIN over this socket, a client must never
talk to a listener another user planted. Every xkey IPC client — `ipc.Client`,
the PKCS#11 module transport, the native-messaging host — connects through
`ipc.Dial` (`xkey/pkg/ipc/client.go:273`), which refuses:

| Refusal | Error | When |
|---|---|---|
| Insecure directory | `ipc.ErrSocketDirInsecure` | the socket's directory is a symlink, not a directory, owned by anyone but you / root / the `sudo` user, or has any group or other bit |
| Untrusted listener | `ipc.ErrPeerUntrusted` | the listening process's uid (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS and FreeBSD) is not you, root, or the `sudo` user |
| No peer-credential API | `ipc.ErrPeerCredentialsUnsupported` | any other platform (OpenBSD, NetBSD, illumos, Windows): the client fails closed |
| No per-user location | `ipc.ErrSocketPathUnresolved` | no `XKEY_IPC_SOCKET`, `XKEY_HOME`, `XDG_RUNTIME_DIR` and no resolvable home directory |

Root is trusted because it can already read anything the socket protects; the
`sudo` user is trusted because `sudo xkey fido2` serves the invoking user, whose
clients then see a listener running as uid 0 (`xkey/pkg/ipc/socketdir.go:36`
`trustedUIDs`).

Handler failures reach the client as fixed text: `ipc: handler returned error`,
or the bare sentinel for the few user-actionable classes (invalid message,
barrier sealed, browser extension disabled). The detail is logged by the
server, never echoed (`xkey/pkg/ipc/server.go:710-728` `clientErrorMessage`).

Several instances can run side by side under one UID, one per `XKEY_HOME`. Each
derives its own socket, and every command resolves the socket the same way, so
an agent whose environment names instance A never reaches instance B.

## The presence handler seam

The one Go API this feature owns is the handler an authenticator is built with:

```go
// xkey/pkg/authenticator
type Config struct {
    // ...
    UserPresenceHandler UserPresenceHandler // required; nil is ErrUserPresenceHandlerRequired
}

func NewSocketHandler(notifier notify.Notifier, logger *slog.Logger) *SocketHandler
func NewInteractiveHandler() (*InteractiveHandler, error)
func NewAutoGrantHandler() *AutoGrantHandler
```

A programmatic device names `NewAutoGrantHandler()` at its own construction
site (`xkey/pkg/virtualdevice` does, with the reason beside it). Auto-grant
answers the presence test; it never sets the UV flag, which comes only from a
verified PIN or a key backend that verifies a human itself.

## SDK integration

```go
// go-xkms/sdk/go/options.go
const defaultXKeySocketEnvVar = "XKEY_IPC_SOCKET"

var ErrXKeyAuthFailed = errors.New("xkey IPC authentication failed")
```

Set `XKEY_IPC_SOCKET` and an SDK consumer authenticates through the running xkey
rather than through a key file — which is the dogfooding path for agent
credentials.

## The Chrome DevTools bridge

| Property | Value |
|---|---|
| Enabled by | `--cdp` (default `false`) |
| Host / port | `--cdp-host localhost`, `--cdp-port 9222` |
| Protocol | Chrome DevTools Protocol, virtual-authenticator domain |
| Purpose | browser automation without a device on the USB bus |

The bridge registers a Chrome virtual authenticator with automatic presence
simulation and user verification simulated by Chrome: a test device, by
Chrome's definition. Anything that can reach that port can drive it. Bind it
to loopback and leave it off outside test runs.

## What the relying party sees

The ordinary WebAuthn ceremonies —
[`../headless-webauthn/api.md`](../headless-webauthn/api.md) and
[`../../../docs/webauthn/api.md`](../../../docs/webauthn/api.md). No additional
field, header or claim marks a login as automated. The UP and UV flags are the
ordinary ones, and true.

If a deployment needs to distinguish agent logins, the way to do it is **by
account** — a dedicated `agent-*` identity — not by expecting the ceremony to
look different. It will not.

## Error mapping

Local, so these are process errors rather than status codes:

| Condition | Result |
|---|---|
| socket missing | the daemon is not running, or paths disagree |
| SDK cannot reach the socket | `ErrXKeyAuthFailed` |
| wrong PIN on a ceremony or on unlock | refused; retries counted |
| presence timeout | a touch was required (no PIN on the ceremony, or `--require-touch` on) and nobody supplied it |
| authenticator built without a handler | `ErrUserPresenceHandlerRequired` |
| CDP port unreachable | the bridge is off or bound elsewhere |

## Versioning

Nothing here is versioned by go-xkms: the ceremonies are W3C WebAuthn, the
bridge is Chrome's protocol, and the socket is a local implementation detail
whose only stable contract is its path and the `XKEY_IPC_SOCKET` variable.
