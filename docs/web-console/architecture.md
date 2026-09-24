# Web Console — Architecture

> **Status: NORMATIVE** · Feature: `web-console` · Repo: `go-xkms` · Last verified: 2026-09-24

## The problem

An operator needs to see and drive a running `xkmsd` without writing
`xkmsctl` scripts for every task, and a desktop user with no server at all
still wants a local KMS with the same screens. Both need the same feature
set, the same RBAC model, and the same passwordless login — built and
shipped once.

## Shape chosen: one SPA, three hosts

`web/app/` is a single Svelte 5 SPA. It is served three ways from the same
build:

1. **Server-hosted** — embedded in `xkmsd` and mounted at `/ui/` when the
   binary is built with the `ui` build tag (`web/embed.go`,
   `pkg/webui.MountChi`).
2. **Desktop, remote** — the Wails v2 shell in `web/desktop/` (its own Go
   module, command `xkms-console`) points the same SPA at a remote `xkmsd`
   over `XKMS_SERVER_URL` or a saved bookmark.
3. **Desktop, standalone** — the Wails shell boots the real
   `pkg/server.Server` engine in-process on a loopback-only listener with a
   per-launch bearer token (`pkg/server/loopback.Launch`) — the "MS Access"
   model: one desktop binary is a complete local KMS with no separate
   daemon process.

Every mode talks REST to an engine; there is no console-specific protocol.
Authentication is passwordless everywhere: WebAuthn passkeys
(`pkg/webauthn/`) and PIV/mTLS client certificates
(`POST /api/v1/auth/login/piv`) only — there is no password grant on this
surface.

Rejected alternative: a separate SPA per host mode. Rejected because the
three modes differ only in how the SPA reaches an engine — same origin,
an injected remote URL, or an injected loopback URL plus a static bearer —
which `web/app/src/lib/desktop.ts` and `stores/sdkClient.ts` resolve at
boot. Maintaining three frontends for one feature set was never considered
once that seam existed.

## Distinct from xkey

The web console is **not** the xkey GUI, despite sharing the Wails+Svelte
toolchain. xkey (`xkey/`) is a personal security-key application — FIDO2/
WebAuthn, OATH TOTP/HOTP, PIV, an SSH agent, OIDC login, and the password
vault, all driven from hardware the operator's own machine can reach (USB
CTAP2, local PKCS#11 modules, PIV smart cards) — consuming any go-xkms
backend through `sdk/go`. The web console is a management surface for a
running `xkmsd` **server**: key lifecycle, CA, barrier, users, audit — all
over that server's REST API. They are two Go modules, two frontends, two
products, built by two different teams' concerns even though `web/desktop/`
and xkey's Wails shell look similar from the outside.

## Component boundaries

| Piece | Package |
|---|---|
| The SPA | `web/app/` (Svelte 5 + Vite 6 + Tailwind 4 + daisyUI) |
| Server-hosted embed | `web/embed.go` (`//go:build ui`), `web/embed_stub.go` (`//go:build !ui`) |
| SPA file server | `pkg/webui` (`NewHandler`, `MountChi`, `NormalizePrefix`) — the same package a chi router in `pkg/acme/gui/webui` wraps for the ACME client's own SPA |
| Desktop shell | `web/desktop/` (own `go.mod`, command `xkms-console`) |
| Loopback engine launcher | `pkg/server/loopback` |
| REST/SDK client | `sdk/ts` (`@go-xkms/sdk`) |
| Shared passwordless login components | `sdk/ts/svelte-auth` (`@go-xkms/svelte-auth`) |
| Capability + auth-session endpoints | `pkg/api/rest` (`handlers_capabilities.go`, `handlers_auth.go`) |
| UI mount configuration | `pkg/config.UIConfig`, wired in `pkg/server/server.go` |

## Data flow

Server-hosted boot:

```
browser  → GET /ui/                       (pkg/webui serves index.html, SPA loads)
         → GET /api/v1/capabilities        (unauthenticated: webauthn/piv_login/ui flags)
         → WebAuthn or PIV login ceremony  → POST /api/v1/auth/login/piv
                                              or /api/v1/webauthn/login/{begin,finish}
         → GET /api/v1/auth/me             (identity, per-pair RBAC permissions, capability flags)
         → every subsequent call carries Authorization: Bearer <access token>
```

Desktop standalone boot:

```
xkms-console (no XKMS_SERVER_URL) → pkg/server/loopback.Launch(cfg)
    → binds 127.0.0.1:0, generates a 32-byte hex per-launch token
    → server.New(cfg, WithAuthenticatorDecorator(...))  composite auth: static token + configured authenticator
    → Wails webview loads web/desktop/frontend's embedded SPA
    → the bound `bridge.GetConnection()` JS call returns {mode, base_url, token}
    → the SPA sets window.__XKMS_API_BASE_URL__ and a static loopback bearer, then boots normally
```

Desktop remote boot is the same SPA boot as server-hosted, except the
`bridge` supplies `base_url` from `XKMS_SERVER_URL` or a saved bookmark
instead of `window.location.origin`.

## Trust boundaries

- **Passwordless only.** No password grant exists on this transport; the
  capability document (`GET /api/v1/capabilities`) tells the login screen
  which of WebAuthn or PIV login is available before any credential is
  asked for.
- **The server is the enforcement authority, the SPA is a convenience
  gate.** `GET /api/v1/auth/me` returns a `permissions` map the sidebar
  (`web/app/src/stores/session.svelte.ts`'s `can()`) and per-tab controls
  hide on, and a `capabilities` map (`hasCapability()`) that hides an entry
  for a subsystem this deployment never wired. Both are read-only signals
  for the UI; every REST handler still enforces its own RBAC decorator
  independently, and a view that is reached anyway (a stale link, a typed
  URL) renders the 403 it gets back rather than assuming access.
- **The loopback bearer is loopback-only by construction**, not by policy:
  `pkg/server/loopback.Launch` binds `127.0.0.1:0`, so the standalone
  engine is off-box unreachable regardless of the token's secrecy.
- **`cmd/xkmsd` never injects a remote API base URL into the server-hosted
  SPA.** `pkg/webui.WithAPIBaseURL` exists (and is used by the unrelated
  ACME client SPA, `cmd/acme-client/serve.go`), but `cmd/xkmsd/main.go`
  calls `SetUIAssets` without it, so the served `index.html` carries no
  injected base URL and the SPA falls back to `window.location.origin` —
  correct, since the server-hosted UI is always same-origin with the API
  it drives.

## What this feature deliberately does not do

- **It never terminates an SSH session, on any transport.** The SSH screen
  manages stored keys (list/generate/delete) only; `pkg/ssh` signs
  authentication challenges but never proxies a shell. A console-hosted
  terminal would let any authenticated caller make the appliance dial an
  arbitrary host. The one place an interactive terminal exists in this
  stack is xkey's `SSHConsoleService`, wrapping `sdk/ts`'s
  `ssh-console.ts` WebSocket client — `web/app` does not import it (see
  `docs/web-console/api.md`).
- **It does not run FROST signing rounds.** The FROST screen manages
  threshold keys and verifies finished signatures; the three-round dealer/
  participant protocol coordinates across separate share-holders and runs
  through `xkmsctl frost`.
- **It does not perform Shamir initialization or rekey.** `barrier init`
  with a Shamir strategy and `barrier rekey` are CLI ceremonies; the
  console's Barrier & Seal screen covers status/unseal/seal.
- **It is not a second cluster-admin plane, and today it is not a working
  one either.** See `docs/web-console/engineering.md` §"Known gaps" — the
  Cluster screen's own REST calls have no server-side route.
