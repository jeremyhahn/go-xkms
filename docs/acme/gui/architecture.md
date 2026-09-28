# GUI Architecture

> This page describes `pkg/acme/gui/admin`, the **desktop host** (Wails) for
> the admin SPA. It has no current `cmd/` entry point; which binary hosts it
> is tracked in go-xkms#743 / go-xkms#746 — see [README.md](README.md). The
> admin UI xkmsd actually serves today is a separate implementation at
> `/admin-ui` (`pkg/acme/web/packages/admin`,
> `cmd/xkmsd/admin.go:73`/`:130`); its web-mode routing below (`/ui/admin/`
> via `webui.RegisterRoutes()`) does not describe that surface.

## Dual-Mode Design

The same Svelte bundle works in two environments without code changes. The transport layer auto-detects the runtime and resolves the correct API base URL.

### Desktop Mode (Wails)

1. Wails opens a native webview and serves the pre-built Svelte assets
2. The REST API router is mounted in that same asset server as `assetserver.Options.Handler`, so it shares the frontend's origin
3. On startup, the frontend calls the `GetApiBaseUrl()` Wails binding, which returns an empty, same-origin base
4. All subsequent API calls use `fetch('/api/v1/...')` against the window's own origin

The desktop apps open **no network listener**. There is no port to discover, no
token to carry and no cross-origin negotiation, because nothing outside the
process can reach a route.

### Web Mode (Server-hosted)

1. The ACME server registers the admin SPA under `/ui/admin/` via `webui.RegisterRoutes()`
2. A `spaFileServer` serves static files from the embedded `dist/` directory, falling back to `index.html` for client-side routing
3. The frontend detects no Wails runtime and defaults to relative URL `/api/v1`
4. The browser's same-origin policy routes requests to the server's REST API

## Transport Detection

`web/packages/shared/src/api/transport.ts` implements runtime detection:

```typescript
// Wails injects window.runtime or window.go
export function isWailsAvailable(): boolean {
  return typeof window !== 'undefined' &&
    (!!(window as any).runtime || !!(window as any).go);
}

// Same-origin in both modes: the base is a prefix, empty unless configured
export function getApiBaseUrl(): string {
  if (typeof window !== 'undefined' && (window as any).__API_BASE_URL__) {
    return (window as any).__API_BASE_URL__;
  }
  return '';
}
```

`initTransport()` is called once in each app's root `onMount`. In desktop mode it calls `runtime.Call('main.App', 'GetApiBaseUrl')` and stores the result on `window.__API_BASE_URL__`.

## Why REST Over Wails RPC

The frontend communicates exclusively through REST API calls rather than Wails Go bindings because:

- **Same code path** -- identical `fetch()` calls work in both desktop and web mode
- **Protocol flexibility** -- the admin desktop app can connect to the CA server over any supported protocol (Unix socket, gRPC, QUIC, REST, MCP) via the `AdapterFactory` pattern
- **Testability** -- API endpoints are testable with standard HTTP tools
- **Decoupling** -- frontend has zero compile-time dependency on Go types

## In-Process API Pattern

Both desktop apps (`pkg/acme/gui/admin/app.go` and `pkg/acme/gui/client/app.go`) follow the same pattern:

1. Create a `gorilla/mux` router with the `/api/v1` routes
2. Launch Wails with an `AssetServer` carrying both the embedded `dist/` filesystem as `Assets` and that router as `Handler`
3. Wails serves a GET from `Assets` first and falls back to `Handler` when the file does not exist; every non-GET goes straight to `Handler`

So the SPA keeps loading from `Assets`, `/api/v1` lands on the router, and no
socket is bound under either. Nothing needs shutting down because nothing was
started: closing the window ends the process.

The admin app uses an `AdapterFactory` to create protocol adapters per request. The client app injects the ACME client `Service` directly.

## Build Tag System

GUI code is gated behind the `gui` build tag to keep CLI-only builds free of CGO and WebKit dependencies.

| Tag | Effect |
|-----|--------|
| `gui` | Includes Wails desktop app packages (`pkg/gui/admin`, `pkg/gui/client`) |
| (no `gui`) | CLI-only binary, no native window support |

Build commands:
- `make build` -- CLI binaries, no `gui` tag
- `make build-gui` -- GUI binaries, includes `-tags=gui`

## Package Layout

```
pkg/gui/
  admin/
    app.go          # Wails app, API mounted in the asset server
    config.go       # GUIConfig struct with defaults
    errors.go       # Typed errors
    api/
      router.go     # gorilla/mux routes for admin API
      handlers.go   # HTTP handler implementations
  client/
    app.go          # Wails app, API mounted in the asset server
    config.go       # GUIConfig struct with defaults
    errors.go       # Typed errors
    api/
      router.go     # gorilla/mux routes for client API
      handlers.go   # HTTP handler implementations
  webui/
    handler.go      # SPA file server for /ui/admin/ on the ACME server
```
