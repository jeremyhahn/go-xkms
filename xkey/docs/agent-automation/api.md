# Agent Automation — API

> **Status: NORMATIVE** · Feature: `agent-automation` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

Transport shapes:
[`../../../docs/key-management/api.md`](../../../docs/key-management/api.md).

## There is no network API, and that is the design

Automation is entirely local: flags on a daemon and a Unix domain socket. **No
server-side endpoint participates**, and no server flag enables it. An agent
authenticating with `--auto-uv` produces exactly the ceremony a human produces,
and the relying party cannot tell — deliberately, because a second trust path
would be a second thing to get wrong.

## The local IPC socket

| Property | Value |
|---|---|
| Path | `$XDG_RUNTIME_DIR/xkey/xkey.sock` (override with `--socket`) |
| Transport | Unix domain socket |
| Access control | **filesystem permissions only** |
| Clients | `xkey unlock`, `xkey touch`, `xkey auth`, the browser extension's native-messaging host, `go-xkms/sdk/go` |
| Implementation | `xkey/pkg/ipc` |

There is no authentication on the socket itself. Anything that can open it while
the authenticator is unlocked can use the credential. That is the security model,
and it is why the socket lives in a per-user runtime directory.

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

Anything that can reach that port can drive the authenticator. Bind it to
loopback and leave it off outside test runs.

## What the relying party sees

The ordinary WebAuthn ceremonies —
[`../headless-webauthn/api.md`](../headless-webauthn/api.md) and
[`../../../docs/webauthn/api.md`](../../../docs/webauthn/api.md). No additional
field, header or claim marks a login as automated.

If a deployment needs to distinguish agent logins, the way to do it is **by
account** — a dedicated `agent-*` identity — not by expecting the ceremony to
look different. It will not.

## Error mapping

Local, so these are process errors rather than status codes:

| Condition | Result |
|---|---|
| socket missing | the daemon is not running, or paths disagree |
| SDK cannot reach the socket | `ErrXKeyAuthFailed` |
| wrong PIN on unlock | refused; retries counted |
| presence timeout without `--auto-uv` | the ceremony expires |
| CDP port unreachable | the bridge is off or bound elsewhere |

## Versioning

Nothing here is versioned by go-xkms: the ceremonies are W3C WebAuthn, the
bridge is Chrome's protocol, and the socket is a local implementation detail
whose only stable contract is its path and the `XKEY_IPC_SOCKET` variable.
