# Virtual FIDO2 Authenticator — API

> **Status: NORMATIVE** · Feature: `virtual-authenticator` · Module: `go-xkms/xkey` · Last verified: 2026-09-06

## The API is CTAP2 over USB HID

This feature's public interface is the **FIDO CTAP2 protocol**, spoken over a
Linux UHID device. It is a standards-defined wire format, not one of the six
portfolio transports, and that is the entire point: the consumer is an
unmodified browser or WebAuthn client that already knows how to talk to a
security key.

The six-transport rule applies to go-xkms's control surfaces. An authenticator
does not have one — a remote "make a credential" RPC would be a request to use
someone else's security key.

## Commands implemented

| CTAP2 command | Implementation |
|---|---|
| `authenticatorMakeCredential` | `xkey/pkg/authenticator/cmd_makecredential.go` |
| `authenticatorGetAssertion` | `cmd_getassertion.go` |
| `authenticatorGetInfo` | `cmd_getinfo.go` |
| `authenticatorClientPIN` | `cmd_clientpin.go`, `pin_protocol.go`, `pin_protocol_v1.go` |
| `authenticatorCredentialManagement` | `cmd_credmgmt.go` |
| `authenticatorConfig` | `cmd_config.go` |
| `authenticatorReset` | `cmd_reset.go` |

Extensions: **`hmac-secret`** (`ext_hmac_secret.go`) — the derived-key extension
that lets a credential produce a stable secret from a salt — and a device-config
extension (`ext_deviceconfig.go`).

`authenticatorGetInfo` is what a client uses to discover all of the above;
capabilities are not assumed.

### Vendor subcommands of `authenticatorConfig`

`authenticatorConfig` (`0x0D`) carries a vendor-prototype range above `0x80`
that administers the token's Security Officer role (`cmd_config.go`). The
lifecycle ones:

| Subcommand | Method it dispatches to | Requires |
|---|---|---|
| `setSOPIN` | `Authenticator.InitializeToken` | nothing — the token has no SO yet |
| `changeSOPIN` | `Authenticator.ChangeSOPIN` | the current SO PIN |
| `unlockWithSOPIN` | `Authenticator.UnlockSO` | the SO PIN |
| `getTokenInfo` | `Authenticator.TokenFlags` | nothing — read-only, returns no secret |

Every mutating vendor handler — `resetUserPIN`, `replaceAttestKey`,
`setAttestCert`, `setRPPolicy`, `deleteRPPolicy`, `setProfile` — begins at
`requireSOUnlocked`, which distinguishes the two refusals that would otherwise
look identical: a token with no Security Officer at all
(`ErrTokenUninitialized`) and a Security Officer who has not authenticated
(`ErrKeyManagerLocked`). It never permits. The read-only policy queries
(`getRPPolicy`, `listRPPolicies`) return no secret and are not SO-gated.

`setSOPIN` carries no `pinUvAuthParam` because there is nothing yet to
authenticate against. `InitializeToken` bounds that trust-on-first-use window
with CTAP 2.1 §6.9's own two conditions — accepted only within
`Config.TokenInitWindow` (10 s) of power-up, and requiring user presence. The
offline CLI path (`xkey fido2 init-token`) constructs the authenticator itself,
so neither bound constrains it; `cli.md` records what does.

## Two front ends

| Front end | Transport | Use |
|---|---|---|
| **UHID** | Linux kernel HID → USB HID to userspace | the real path; every WebAuthn consumer |
| **CDP bridge** | Chrome DevTools Protocol on `--cdp-port` (default `9222`) | browser tests without a device on the bus |

The CDP bridge is a debugging surface. Anything that can reach that port can
drive the authenticator, so it is off by default and belongs on a loopback
interface.

## Local IPC

`xkey` exposes an IPC socket (`--socket`, default
`$XDG_RUNTIME_DIR/xkey/xkey.sock`) used by other `xkey` verbs —
`xkey unlock`, `xkey touch` — and by the browser extension's native-messaging
host. It is a local Unix socket, not a network API, and its access control is
filesystem permissions.

`go-xkms/sdk/go` reaches this socket through `XKEY_IPC_SOCKET`
(`sdk/go/options.go`) for its xkey-auth option, which is how an SDK consumer can
authenticate using a running xkey.

## The relying-party side

Everything this authenticator produces is verified by a relying party, which is
documented in go-xkms:

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Registration ceremony | `POST /api/v1/webauthn/registration/begin` · `/finish` | `BeginRegistration` · `FinishRegistration` | same as REST | **MISSING — docs/13** | `FIDO2Service.*` |
| Authentication ceremony | `POST /api/v1/webauthn/login/begin` · `/finish` | `BeginAuthentication` · `FinishAuthentication` | same as REST | **MISSING — docs/13** | `FIDO2Service.*` |

Detail: [`../../../docs/webauthn/api.md`](../../../docs/webauthn/api.md).

## Error mapping

CTAP2 status codes (`CTAP2_ERR_*`) go back to the consumer; there is no HTTP
mapping because there is no HTTP. In a browser these surface in the console
rather than as an application error, which is worth knowing when a login "just
does nothing".

| Situation | Result |
|---|---|
| no user presence within `--timeout` | CTAP2 timeout |
| wrong PIN | CTAP2 PIN-invalid, with retries remaining |
| PIN retries exhausted | CTAP2 PIN-blocked |
| credential not found for the RP | CTAP2 no-credentials |
| backend unavailable (TPM absent, phone unpaired) | operation error — **never a silent downgrade to software** |

## Versioning

CTAP2 is a FIDO Alliance specification; version and capability negotiation is
`authenticatorGetInfo`. The PIN protocol has versioned implementations
(`pin_protocol_v1.go`) because clients differ in which they use.

`migration.go` handles xkey's own stored-state layout changes — see
[`engineering.md`](engineering.md) §Persistence.
