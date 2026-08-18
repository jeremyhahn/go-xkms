# Headless WebAuthn — API

> **Status: NORMATIVE** · Feature: `headless-webauthn` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

Transport shapes:
[`../../../docs/key-management/api.md`](../../../docs/key-management/api.md).

## There is no separate API

This feature calls the **ordinary** WebAuthn ceremonies. There is no
headless-specific endpoint, no server flag, and no relaxed policy — which is the
security property worth stating plainly: an agent authenticates through exactly
the surface a human does.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Begin / finish registration | `POST /api/v1/webauthn/registration/begin` · `/finish` | `BeginRegistration` · `FinishRegistration` | same as REST | **MISSING — docs/13** | `FIDO2Service.*` |
| Begin / finish login | `POST /api/v1/webauthn/login/begin` · `/finish` | `BeginAuthentication` · `FinishAuthentication` | same as REST | **MISSING — docs/13** | `FIDO2Service.*` |
| SDK ceremony variants | `POST /api/v1/webauthn/sdk/registration/begin` · `/finish` · `/sdk/authentication/begin` · `/finish` | — | same as REST | — | — |
| PIV login (`--piv`) | `POST /api/v1/auth/login/piv` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | — |
| Refresh | `POST /api/v1/auth/refresh` | — | same as REST | — | — |
| Who am I | `GET /api/v1/auth/me` | — | same as REST | — | — |
| Validate | `GET /api/v1/auth/validate` | — | same as REST | — | — |
| Logout | `POST /api/v1/auth/logout` | — | same as REST | — | — |

The `/sdk/...` variants are the ones a non-browser client uses, and are what the
headless client drives.

All of these are `RouteAuthPublic` in their groups — **they are the
authentication** — and sit behind the login rate limiter. The `auth/*` routes are
gated on `hasIssuer`: without a token issuer configured they are not registered
at all, which is why `xkey auth login` against such a server fails with a 404
rather than an authentication error.

Full detail: [`../../../docs/webauthn/api.md`](../../../docs/webauthn/api.md).

## Local IPC

`xkey auth` reaches the running authenticator over xkey's Unix IPC socket
(`$XDG_RUNTIME_DIR/xkey/xkey.sock`), not over the network. `go-xkms/sdk/go`
reads the same path from `XKEY_IPC_SOCKET` (`sdk/go/options.go`) for its
xkey-auth option — that is how an SDK consumer authenticates through a running
xkey rather than through a key file.

## Token shape

A finish response carries either a single token or an access/refresh pair,
depending on whether the server has a `TokenPairGenerator` injected. The
handlers select by type assertion, so **the same route returns different shapes
on different deployments** — a client must handle what its server produces.

## Status mapping

| Condition | REST |
|---|---|
| ceremony succeeded | 200 with token(s) |
| any ceremony failure | **401, uniformly** |
| public registration disabled | 403 |
| rate limited | 429 |
| no token issuer configured | route absent (404) |

The uniform 401 is deliberate — the server does not tell a client which part
failed. When debugging a headless enrolment, the client's own typed error and
the server's log are where the reason is.

## Versioning

W3C WebAuthn on the wire; nothing here is versioned by go-xkms. The `/sdk/...`
routes are an addition, not a replacement.
