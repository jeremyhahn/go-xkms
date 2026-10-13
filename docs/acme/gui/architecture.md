# GUI Architecture

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on how the ACME SPAs are hosted. The code lives in `pkg/acme/gui` and `pkg/acme/web`.

## Hosts

One Svelte bundle per app runs unchanged in every host:

| Host | Code | Serves | Wired into a binary |
|------|------|--------|---------------------|
| Client desktop (Wails) | `pkg/acme/gui/client/app.go` | client SPA + `/api/v1` client router | yes: `trusted-acme-client`, `-tags gui` (`cmd/acme-client/gui.go:44`) |
| Admin desktop (Wails) | `pkg/acme/gui/admin/app.go` | admin SPA + `/api/v1` admin router | no (go-xkms#743, go-xkms#746) |
| xkmsd admin module | `cmd/xkmsd/admin.go:91` | admin SPA at `/admin-ui` | yes: `xkmsd` |
| ACME API server | `pkg/acme/gui/webui/handler.go` via `pkg/acme/api/server/server.go:670` | admin SPA at `/ui/admin/` | no; only tests call `server.NewMultiProtocolServer` |

### Desktop mode (Wails)

1. Wails opens a native webview and serves the embedded `dist/`.
2. The `/api/v1` router is the asset server's `Handler`
   (`assetserver.Options.Handler`), so the API shares the frontend's origin.
3. `initTransport()` calls the `GetApiBaseUrl()` binding, which returns `""`.
   That empty string is a same-origin base (`pkg/acme/gui/admin/app.go:111`).
4. All API calls are `fetch('/api/v1/...')` against the window's own origin.

The desktop apps open **no network listener**. Nothing outside the process can
reach a route. The admin router is built with `adminapi.WithInProcessTransport()`
(`pkg/acme/gui/admin/app.go:103`).

### Web mode

`webui.RegisterSPA` (`pkg/acme/gui/webui/handler.go:41`) mounts an SPA under a
prefix. It uses `http.StripPrefix` and the shared `corewebui.NewHandler`, which
serves files from the embedded `dist/` and falls back to `index.html`.
`xkmsd` mounts the admin SPA through `WithAdminWebUI` instead
(`cmd/xkmsd/admin.go:104`). In both cases there is no Wails runtime, so the SPA
uses a relative API base.

## Transport detection

`pkg/acme/web/packages/shared/src/api/transport.ts`:

- `isWailsAvailable()` (`:18`) is true when `window.runtime` or `window.go` exists.
- `getApiBaseUrl()` (`:26`) returns `window.__API_BASE_URL__` if set, else `''`.
- `initTransport()` (`:45`) calls `runtime.Call('main.App', 'GetApiBaseUrl')`
  in desktop mode and stores the result on `window.__API_BASE_URL__`.

Each app calls `initTransport()` once, in its root `onMount`.

## Why REST over Wails bindings

The frontend talks to Go only through `fetch()`, not through generated Wails
bindings:

- the same calls work in the desktop and web hosts
- the API is testable with plain HTTP (`httptest`)
- the frontend has no compile-time dependency on Go types

## In-process API pattern

Both desktop apps follow the same pattern:

1. Build a `gorilla/mux` router with the `/api/v1` routes, wrapped in the
   `pkg/acme/gui/guard` middleware.
2. Start Wails with an `AssetServer` whose `Assets` is the embedded `dist/`
   and whose `Handler` is that router.
3. Wails serves a GET from `Assets` first and falls back to `Handler` when the
   file does not exist. Every non-GET goes straight to `Handler`.

Closing the window ends the process. There is no server to shut down.

The admin app takes a `trustedca.Client` (`pkg/acme/gui/admin/app.go:55`). The
client app takes the ACME client `*service.Service` plus a `trustedca.Client`
(`pkg/acme/gui/client/app.go:59`).

## Build tags

`pkg/acme/gui/admin/app.go`, `pkg/acme/gui/client/app.go` and
`cmd/acme-client/gui.go` carry `//go:build gui`. Without the tag,
`cmd/acme-client/gui_nogui.go` returns `ErrGUINotAvailable`, and the binary
needs neither cgo nor WebKit2GTK.

| Tag | Effect |
|-----|--------|
| `gui` | Links Wails and the desktop apps |
| (none) | CLI only, no native window |

No Makefile target passes `-tags gui`. Build it directly:
`go build -tags gui ./cmd/acme-client`.

## Package layout

```
pkg/acme/gui/
  admin/            app.go (gui tag), config.go, errors.go
    api/            router.go, handlers.go, *_handlers.go, tenant_ca.go, orders.go
  client/           app.go (gui tag), config.go, errors.go
    api/            router.go, handlers.go, acme_handlers.go, device_handlers.go
  guard/            guard.go: origin check + CORS for the routers
  webui/            embed.go (AdminAssets, ClientAssets), handler.go (RegisterSPA, RegisterRoutes)
pkg/acme/web/       npm workspace: packages/{shared,admin,client}
```
