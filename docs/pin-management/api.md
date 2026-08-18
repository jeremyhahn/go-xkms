# PIN Management — API

> **Status: NORMATIVE** · Feature: `pin-management` · Repo: `go-xkms` · Last verified: 2026-08-19

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

PIN routes are registered under `/api/v1/pin` with `RouteAuthSession` — an
authenticated identity, no specific RBAC permission. They are **not**
permission-gated, because holding the PIN is the authorization: a caller who
can present the current PIN is who the device says they are.

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC (HTTP/3) | MCP | Embedded (`PINService.`) | Auth |
|---|---|---|---|---|---|---|
| Set SO PIN | `POST /api/v1/pin/so/set` | `SetSOPIN` | same as REST | **MISSING — docs/13** | `SetSOPIN` | session |
| Change SO PIN | `POST /api/v1/pin/so/change` | `ChangeSOPIN` | same as REST | **MISSING — docs/13** | `ChangeSOPIN` | session |
| Verify SO PIN | `POST /api/v1/pin/so/verify` | `VerifySOPIN` | same as REST | **MISSING — docs/13** | `VerifySOPIN` | session |
| Set user PIN | `POST /api/v1/pin/user/set` | `SetUserPIN` | same as REST | **MISSING — docs/13** | `SetUserPIN` | session |
| Change user PIN | `POST /api/v1/pin/user/change` | `ChangeUserPIN` | same as REST | **MISSING — docs/13** | `ChangeUserPIN` | session |
| Verify user PIN | `POST /api/v1/pin/user/verify` | `VerifyUserPIN` | same as REST | **MISSING — docs/13** | `VerifyUserPIN` | session |
| Lockout status | `GET /api/v1/pin/lockout` | `GetLockoutStatus` | same as REST | **MISSING — docs/13** | `GetLockoutStatus` | session |
| Reset lockout | `POST /api/v1/pin/lockout/reset` | `ResetLockout` | same as REST | **MISSING — docs/13** | `ResetLockout` | session |

**MCP carries none of the PIN surface.** Recorded as eight gaps rather than
omitted. Unlike the WebAuthn case, this one is easy to argue for: an MCP tool
server driven by a model is not somewhere PIN material should flow. But it is a
capability with a wire surface on four transports and none on the fifth, so it
is tracked debt with an owner rather than an unstated decision.

Handlers: `pkg/api/rest/handlers_barrier_pin.go`,
`pkg/api/grpc/service_barrier_pin.go`.

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
