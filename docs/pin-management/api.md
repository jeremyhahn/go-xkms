# PIN Management — API

> **Status: NORMATIVE** · Feature: `pin-management` · Repo: `go-xkms` · Last verified: 2026-09-23

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

PIN routes are registered under `/api/v1/pin` with `RouteAuthPermission`: an
authenticated identity that also holds the route's `pin:*` permission when RBAC
is enabled. Setting, changing, or resetting the lockout of a PIN needs
`pin:write`; verifying a PIN or reading the lockout counters needs `pin:read`.
These are the pairs gRPC enforces for the same RPCs, so REST, QUIC (which
serves the REST router), and gRPC/Unix demand the same grant. A caller without
the grant receives `403` before the PIN is ever compared, so an authenticated
session alone can no longer drive the token's retry counter. Admin and Owner
hold both permissions by default. MCP gates the same eight methods (`xkms.setSOPIN` and
siblings) with the same `pin:read` / `pin:write` pairs when RBAC is enabled.

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC (HTTP/3) | MCP | Embedded (`PINService.`) | Permission |
|---|---|---|---|---|---|---|
| Set SO PIN | `POST /api/v1/pin/so/set` | `SetSOPIN` | same as REST | `xkms.setSOPIN` | `SetSOPIN` | `pin:write` |
| Change SO PIN | `POST /api/v1/pin/so/change` | `ChangeSOPIN` | same as REST | `xkms.changeSOPIN` | `ChangeSOPIN` | `pin:write` |
| Verify SO PIN | `POST /api/v1/pin/so/verify` | `VerifySOPIN` | same as REST | `xkms.verifySOPIN` | `VerifySOPIN` | `pin:read` |
| Set user PIN | `POST /api/v1/pin/user/set` | `SetUserPIN` | same as REST | `xkms.setUserPIN` | `SetUserPIN` | `pin:write` |
| Change user PIN | `POST /api/v1/pin/user/change` | `ChangeUserPIN` | same as REST | `xkms.changeUserPIN` | `ChangeUserPIN` | `pin:write` |
| Verify user PIN | `POST /api/v1/pin/user/verify` | `VerifyUserPIN` | same as REST | `xkms.verifyUserPIN` | `VerifyUserPIN` | `pin:read` |
| Lockout status | `GET /api/v1/pin/lockout` | `GetLockoutStatus` | same as REST | `xkms.getLockoutStatus` | `GetLockoutStatus` | `pin:read` |
| Reset lockout | `POST /api/v1/pin/lockout/reset` | `ResetLockout` | same as REST | `xkms.resetLockout` | `ResetLockout` | `pin:write` |

**MCP now carries the full PIN surface** (go-xkms#773). Every method
delegates to `XKMSService`'s own `SetSOPIN` / `SetUserPIN` / `ChangeSOPIN` /
`ChangeUserPIN` / `VerifySOPIN` / `VerifyUserPIN` / `GetLockoutStatus` /
`ResetLockout` — the same servicer methods REST calls through `PINManager`
and gRPC calls through its composed `qrdbsdk.PINBackend` — so behaviour,
including the backend-dependent table below, is identical across all four
transports.

Handlers: `pkg/api/rest/handlers_barrier_pin.go`,
`pkg/api/grpc/service_barrier_pin.go`, `pkg/api/mcp/handlers_pin.go`.

## Backend-dependent behaviour

The same route does different things depending on which backend `pinselect`
chose at startup. This is the most important thing on this page for a client
author:

| Route | software | pkcs11 | **tpm2** |
|---|---|---|---|
| `pin/so/set` | sets | sets on the token | **`ErrPINNotSet`** |
| `pin/so/change` | changes | changes on the token | **`ErrPINNotSet`** |
| `pin/so/verify` | verifies | verifies against the token | **`ErrPINNotSet`** |
| `pin/user/*` | works | works | works |
| `pin/lockout` | reports | token retry counter | TPM dictionary-attack state |
| `pin/lockout/reset` | resets | SO-authorized reset | **lockout authorization**, not the user PIN |

A client cannot assume the SO routes work. The correct handling of
`ErrPINNotSet` on `/pin/so/*` is "this backend has no SO PIN", not "the PIN has
not been configured yet" — the name is qrdb's and reads ambiguously here.

## Request and response schemas

Go types in `pkg/api/transport/types.go`: `SetSOPINRequest`,
`SetUserPINRequest`, `ChangeSOPINRequest`, `ChangeUserPINRequest`,
`VerifySOPINRequest`, `VerifyUserPINRequest`, `ResetLockoutRequest`, and
`LockoutStatusResponse`. Protobuf counterparts in `xkms.proto`.

`LockoutStatusResponse` wraps `qrdbsdk.PINLockoutStatus` — whether the device is
locked out, and where its retry counter stands. On a PKCS#11 token that counter
is the thing standing between the deployment and a dead token.

**PIN values are request fields and never appear in a URL, a query string, or a
response.** Nothing in this feature echoes a PIN back.

## Status and error mapping

| Condition | REST | gRPC / Unix |
|---|---|---|
| success | 200 | `OK` |
| caller lacks the route's `pin:*` permission | 403 | `PermissionDenied` |
| wrong PIN | 401 | `Unauthenticated` |
| `qrdbsdk.ErrPINNotSet` (no such PIN on this backend) | 501 | `Unimplemented` |
| device locked out | 423 | `FailedPrecondition` |
| platform not provisioned (`IsInitialized()` false) | 409 | `FailedPrecondition` |
| device absent or unreadable | 503 | `Unavailable` |

Locked-out and wrong-PIN are deliberately distinct: retrying a wrong PIN is
reasonable, retrying against a locked-out device is how a token gets bricked.

## Pagination

Not applicable.

## Versioning and deprecation

`/api/v1/pin/*`, gRPC package `xkmsv1`. Nothing deprecated.

Note for future work: the SO routes' behaviour is backend-dependent rather than
versioned. If a future backend gains an SO PIN, no wire change is needed — but
existing clients that special-cased `ErrPINNotSet` for TPM2 will need to stop.
