# Web Console — Engineering Contract

> **Status: NORMATIVE** · Feature: `web-console` · Repo: `go-xkms` · Last verified: 2026-09-24

## Exported surface

### `pkg/webui` — the SPA file server

- `DefaultPathPrefix = "/ui/"`.
- `NewHandler(assets fs.FS, logger *slog.Logger, opts ...Option) (http.Handler, error)`
  — static files with content-type detection, no directory listings, and an
  `index.html` fallback for client-side routes.
- `MountChi(r chi.Router, assets fs.FS, prefix string, logger *slog.Logger, opts ...Option) error`
  — mounts on a chi router; a request for the bare prefix without its
  trailing slash 302s to the canonical prefix.
- `NormalizePrefix(prefix string) (string, error)` — empty selects
  `DefaultPathPrefix`; a prefix without a leading `/` is `*ErrInvalidPrefix`.
- `WithAPIBaseURL(baseURL string) Option` — injects
  `<script>window.__API_BASE_URL__=...</script>` into `index.html`, JSON-
  encoded so it cannot break out of the tag. **Not used by `cmd/xkmsd`** for
  this console (the mount is same-origin); it is used by the unrelated ACME
  client SPA (`cmd/acme-client/serve.go`).
- Typed errors: `ErrNilAssets`, `ErrNilRouter`, `ErrInvalidPrefix{Prefix}`.

### `web` package — the embed switch

- `Assets() (fs.FS, bool)` — two build-tag-selected implementations.
  `web/embed.go` (`//go:build ui`) embeds `web/dist` (`//go:embed all:dist`)
  and returns `(sub, true)`. `web/embed_stub.go` (`//go:build !ui`) returns
  `(nil, false)` so a plain build stays green with no `web/dist` present.
  `cmd/xkmsd/main.go` calls `web.Assets()` and, when `ok`, calls
  `srv.SetUIAssets(assets)`.

### `pkg/server` — mount wiring

- `(*Server) SetUIAssets(assets fs.FS)` — installs the compiled filesystem;
  call before `Start`. A nil value (or `!s.config.UIEnabled()`) leaves the
  UI unmounted.
- `(*Server) SetRESTListener(net.Listener)` — hands the REST transport a
  pre-bound listener instead of binding the configured port; the loopback
  launcher uses this with a `127.0.0.1:0` listener.
- Composition (`pkg/server/server.go`, building `rest.UIOptions`): the UI
  mounts only when `s.uiAssets != nil && s.config.UIEnabled()`; CORS headers
  are emitted only when `s.config.CORS.Enabled` (same-origin needs none).

### `pkg/server/loopback` — the standalone engine launcher

```go
type Options struct {
    Config *config.Config   // copied and forced into a loopback, REST-only posture
    Logger *slog.Logger
}
type Instance struct {
    BaseURL string   // "https://127.0.0.1:<port>" (or http:// when TLS is off)
    Token   string    // 32 bytes, hex-encoded, per launch
    Port    int
}
func Launch(ctx context.Context, o Options) (*Instance, error)
func (i *Instance) Close(ctx context.Context) error
```

`Launch` pre-binds `127.0.0.1:0`, forces `cfg.Protocols = ProtocolsConfig{REST: true}`
and `cfg.Server.Host = "127.0.0.1"`, composes a `auth.NewStaticTokenAuthenticator`
(identity `desktop-owner`, tenant `system`, role `admin`) ahead of the
configured authenticator via `auth.NewCompositeAuthenticator`, constructs
`server.New(cfg, server.WithAuthenticatorDecorator(decorator))`, and starts
it in a goroutine. Typed error: `LaunchError{Reason, Err}`.

### `web/desktop` — the Wails shell (separate Go module, command `xkms-console`)

- `Connection{Mode, BaseURL, Token}`, `Mode` = `"remote"` or `"standalone"`.
- `resolveConnection(ctx, logger) (Connection, func(), error)` — reads
  `XKMS_DESKTOP_MODE`; empty defaults to `remote` when `XKMS_SERVER_URL` is
  set, else `standalone`. Remote mode falls back to the first saved
  bookmark (`$XDG_CONFIG_HOME/xkms-desktop/bookmarks.json`, via
  `os.UserConfigDir()`, mode 0600).
- `runGUI(conn, logger) error` — build-tag split: `gui_enabled.go`
  (`//go:build desktop`) opens the real Wails window with a bound `bridge`
  exposing `GetConnection() string` (JSON), `ListBookmarks() []Bookmark`,
  `SaveBookmark(name, baseURL string) error`. `gui_disabled.go`
  (`//go:build !desktop`) returns `*GUIUnavailableError` so a binary built
  without cgo/WebKit still compiles and the connection logic is still
  testable headlessly.
- Typed errors: `ConfigError{Reason, Err}`, `GUIUnavailableError{}`.
- `web/desktop/frontend` (`//go:embed all:dist`) embeds the same `dist/`
  `make build-web` stages into `web/dist` for the daemon.

### `pkg/api/rest` — capability and session endpoints the console depends on

- `GET /api/v1/capabilities` (unauthenticated, `GroupRoot`) —
  `{version, webauthn_enabled, piv_login_enabled, ui_enabled}` only; deliberately
  coarse so an anonymous scanner cannot fingerprint the deployment further.
- `GET /api/v1/auth/me` (authenticated) — identity, `roles`, a `permissions`
  map built from `uiPermissionMatrix` (resource:action pairs the console
  gates on — RBAC-disabled deployments return all of them `true`), and a
  `capabilities` map from `capabilityFlags()` (`webauthn`, `piv_login`,
  `rbac`, `ca`, `custodians`, `shares`, `tenants`, `passwords`, `platform`,
  `policies`, `ceremony`, `ssh`, `frost`, `factors`, `audit`).
- `POST /api/v1/auth/login/piv`, `POST /api/v1/auth/refresh`,
  `GET /api/v1/auth/validate`, `POST /api/v1/auth/logout`.

## Invariants

- **The nav sidebar (`web/app/src/lib/nav.ts`) never hides more than the
  server would refuse.** A `requires` gate checks `permissions[resource:action]`;
  a `capability` gate checks `capabilities[name]`. Both read from the same
  `GET /api/v1/auth/me` response, cached in `session.svelte.ts`.
- **`pkg/webui.MountChi` falls back to `index.html` for every unresolved
  path**, so client-side routes (`#/keys`, `#/audit`, ...) work on a
  hard refresh without a server-side route per screen.
- **The desktop bridge is the only source of `window.__XKMS_API_BASE_URL__`.**
  `web/app/src/stores/sdkClient.ts`'s `resolveBaseURL()` reads it if present,
  else falls back to `window.location.origin`; there is no other injection
  path into the server-hosted build.
- **A loopback bearer token is issued once per launch and never persisted.**
  `pkg/server/loopback.Launch` generates it in memory; closing the instance
  invalidates it (the static authenticator goes away with the process).

## Known gaps

Accuracy over completeness: these are real, currently-broken or
unreachable corners of the console, verified against the route table and
the frontend gating code — not roadmap items copied from elsewhere.

### The Cluster screen's REST calls have no server-side route

`web/app/src/views/ClusterView.svelte` calls `sdk/ts`'s `cluster` client
(`sdk/ts/src/clients/cluster.ts`, `BASE = '/api/v1/cluster'`) for
`GET /api/v1/cluster/status` and `GET /api/v1/cluster/members`. **Neither
route is registered anywhere in the production REST surface.**
`pkg/api/rest/routes.go` — the file whose own header comment calls it "the
single source of truth for the xkms REST surface" — has no `cluster` route
at all; the only existing `/api/v1/cluster/*` path in the tree is
`clustercapkg.SecretDeliveryPath = "/api/v1/cluster/secret"`
(`pkg/trust/clusterca/secret_delivery.go`), an unrelated CA-secret-delivery
endpoint. The cluster control plane (status, peers, membership add/remove)
is real, but it is served over gRPC on the Unix socket only
(`pkg/server/qrdb_control_plane.go`, wired via `registerQRDBControlPlane` in
`pkg/server/server.go`) — the transport `xkmsctl cluster` uses, not REST.

A second, independent symptom of the same gap: the Cluster nav entry's
capability gate (`nav.ts`: `capability: "cluster"`) can never resolve
`true`. `capabilityFlags()` in `pkg/api/rest/handlers_auth.go` does not set
a `"cluster"` key at all, so `hasCapability("cluster")` in
`session.svelte.ts` is always `false` — the Cluster sidebar entry is
permanently hidden regardless of deployment, independently of the missing
routes underneath it. Reaching `#/cluster` directly (typed URL) would still
load the view, which would then fail every request it makes.

### The Audit and Auth Factors nav entries never become visible

`uiPermissionMatrix` (`pkg/api/rest/handlers_auth.go`) — the fixed list of
resource:action pairs `GET /api/v1/auth/me` evaluates into the
`permissions` map — does **not** include `{auth.ResourceAudit, auth.ActionRead}`
("audit:read") or `{auth.ResourceUsers, auth.ActionRead}` ("users:read"),
even though both are real, enforced RBAC pairs (`auth.ResourceAudit =
"audit"`, `auth.ResourceUsers = "users"`, `auth.ActionRead = "read"`,
`pkg/auth/permissions.go`) and both are exactly what `nav.ts` gates the
Audit and Auth Factors entries on (`requires: {resource: "audit", action:
"read"}`, `requires: {resource: "users", action: "read"}`). Because the key
is absent from the map rather than `false`, `session.svelte.ts`'s `can()`
(`_me.permissions[key] === true`) returns `false` unconditionally — for
every identity, including one that genuinely holds `audit:read` or
`users:read`, and even when RBAC is disabled (RBAC-disabled mode only
back-fills pairs that ARE in `uiPermissionMatrix`). The two sidebar entries
are therefore never reachable by navigation for anyone. There is no
client-side route guard beyond the sidebar (`router.svelte.ts` has none), so
a direct hash-route visit (`#/audit`, `#/factors`) still loads the view and
still calls the real, correctly-RBAC-enforced API underneath — only the
sidebar's discoverability is affected, but it is affected for every
deployment, not as an edge case.

## Test strategy

Four layers, fastest first; the first three run in `make test`, the fourth
in `make integration-test`:

| Layer | Command | What it proves |
|---|---|---|
| Go unit | `make test-go` | Handlers, RBAC gates, `pkg/webui`, `pkg/server/loopback` |
| TS unit + component | `make test-web` | `sdk/ts` wire contracts, the auth store, every Svelte view |
| Playwright, mock tier | `make test-web-e2e` (`web/app/e2e/`) | The real SPA in a real browser against `page.route()` interception — no server |
| Playwright, live tier | `make integration-test-web` (`test/integration/web/`) | The real SPA against a real `xkmsd`, including a real WebAuthn ceremony over Chrome's CDP virtual authenticator |

`make test-web` runs under coverage (`vitest run --coverage`, not a plain
`vitest run`), so the thresholds in each package's `vitest.config.ts` /
`vite.config.ts` gate the build: statements/lines/functions 90% in all
three packages (`sdk/ts`, `svelte-auth`, `web/app`); branches 90% in
`sdk/ts` and `svelte-auth`, 80% in `web/app` (the Svelte compiler emits
implicit branches for every `{#if}`/keyed `{#each}`/optional prop, so a 90%
floor there would chase generated-code coverage rather than behavior).

`make integration-test-web` is deliberately **not** part of the
`integration-test` aggregate (`Makefile`'s `integration-test` target lists
it out): `test/integration/web/tests/auth.spec.ts` passes against a real
server, but `key-lifecycle.spec.ts` and `barrier-audit.spec.ts` are
documented red for a server-side tenant-scoping reason unrelated to the
console itself (every tenant-scoped call 403s for the first registered
user because tenant `system` has no barrier-registry entry).

## Configuration

See `docs/web-console/user.md` and `docs/web-console/api.md` for the
`ui:`/`cors:`/`auth.piv_login:`/`auth.session:` keys the console depends
on; `pkg/config.UIConfig`, `pkg/config.CORSConfig`, `pkg/config.PIVLoginConfig`,
`pkg/config.SessionConfig` are the source of truth, all in `pkg/config/config.go`.
