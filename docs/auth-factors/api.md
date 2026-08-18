# Auth Factors — API

> **Status: NORMATIVE** · Feature: `auth-factors` · Repo: `go-xkms` · Last verified: 2026-08-19

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

## This is a tier-2 capability

The six-transport completeness rule applies to **tier 1** — data and control
plane capabilities. Auth factors are **tier 2: composition plane, in-process**.
They are registered into go-qrdb's `AuthFactorRegistry` at composition time and
have no transport surface of their own, by design rather than by omission.

What *is* on the wire is (a) the hardware operations each factor wraps, and
(b) the authentication surface go-qrdb exposes and go-xkms serves.

## In-process surface

| Capability | Embedded call | Notes |
|---|---|---|
| Build the canonical factor slice | `factor.DefaultFactors(cfg)` | the authoritative list: `piv`, `pkcs11`, `fido2`, `mtls` |
| Build a registry with them | `factor.NewDefaultRegistry(cfg)` | returns `*qrdbsdk.AuthFactorRegistry` |
| Register into an existing registry | `registry.Register(f)` for each of `DefaultFactors(cfg)` | the registry type is **go-qrdb's** |

SDK access is `Security().Auth().FIDO2()` and `Security().Auth().PIV()`.

## The authentication surface that consumes them

These routes belong to the identity plane; they are listed here so the reader
can see where a factor is actually exercised.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Register (WebAuthn) | `POST /api/v1/webauthn/registration/begin` · `/finish` | `BeginRegistration` · `FinishRegistration` | same as REST | **MISSING — docs/13** | `FIDO2Service.BeginRegistration` · `FinishRegistration` |
| Authenticate (WebAuthn) | `POST /api/v1/webauthn/login/begin` · `/finish` | `BeginAuthentication` · `FinishAuthentication` | same as REST | **MISSING — docs/13** | `FIDO2Service.BeginAuthentication` · `FinishAuthentication` |
| SDK ceremony variants | `POST /api/v1/webauthn/sdk/registration/begin` · `/finish` · `/sdk/authentication/begin` · `/finish` | — | same as REST | — | — |
| PIV login | `POST /api/v1/auth/login/piv` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | — |
| List a user's credentials | `GET /api/v1/users/{username}/credentials` | `ListUserCredentials` | same as REST | **MISSING — docs/13** | `UserService.ListUserCredentials` |
| Bind a certificate to a user (mTLS factor) | `POST /api/v1/users/{username}/cert-bindings` | `BindUserCert` | same as REST | **MISSING — docs/13** | `UserService.BindUserCert` |

The WebAuthn routes sit in `GroupWebAuthn` and are `RouteAuthPublic` — they are
**unauthenticated because they are the authentication**. `POST
/api/v1/auth/login/piv` is likewise `RouteAuthPublic` in `GroupAuthSession`.
Both groups sit behind the login rate limiter.

`GET /api/v1/users/{username}/credentials` and the cert-binding route are in
`GroupUsers`: authenticated, permission-gated (`users:read`, `users:update`),
and **not** tenant-scoped — the user plane is identity-scoped, not
tenant-scoped.

## Status and error mapping

| Condition | REST | gRPC / Unix |
|---|---|---|
| challenge expired | 401 | `Unauthenticated` |
| assertion or signature invalid | 401 | `Unauthenticated` |
| enrollment not found | 404 | `NotFound` |
| RP id mismatch | 400 | `InvalidArgument` |
| rate limited (login groups) | 429 | `ResourceExhausted` |

Every one of these is a failure, not a downgrade. There is no response shape
that means "partially verified".

## Versioning and deprecation

Adding a factor to `DefaultFactors` is additive on the wire — a client that does
not know it simply never selects it. Removing one invalidates every enrollment
that used it, which is breaking for users, not just for code.
