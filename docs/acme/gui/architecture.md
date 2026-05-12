# GUI Architecture

## Dual-Mode Design

The same Svelte bundle works in two environments without code changes. The transport layer auto-detects the runtime and resolves the correct API base URL.

### Desktop Mode (Wails)

1. Go binary starts an embedded HTTP server on `127.0.0.1:0` (random port)
2. Wails opens a native webview and serves the pre-built Svelte assets
3. On startup, the frontend calls the `GetApiBaseUrl()` Wails binding to discover `http://localhost:{port}/api/v1`
4. All subsequent API calls use `fetch()` against that URL

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

// Returns absolute URL in desktop mode, relative /api/v1 in web mode
export function getApiBaseUrl(): string {
  if (typeof window !== 'undefined' && (window as any).__API_BASE_URL__) {
    return (window as any).__API_BASE_URL__;
  }
  return '/api/v1';
}
```

`initTransport()` is called once in each app's root `onMount`. In desktop mode it calls `runtime.Call('main.App', 'GetApiBaseUrl')` and stores the result on `window.__API_BASE_URL__`.

## Why REST Over Wails RPC

The frontend communicates exclusively through REST API calls rather than Wails Go bindings because:

- **Same code path** -- identical `fetch()` calls work in both desktop and web mode
- **Protocol flexibility** -- the admin desktop app can connect to the CA server over any supported protocol (Unix socket, gRPC, QUIC, REST, MCP) via the `AdapterFactory` pattern
- **Testability** -- API endpoints are testable with standard HTTP tools
- **Decoupling** -- frontend has zero compile-time dependency on Go types

## Embedded HTTP Server Pattern

Both desktop apps (`pkg/gui/admin/app.go` and `pkg/gui/client/app.go`) follow the same pattern:

1. Bind a TCP listener on `127.0.0.1:0` (OS-assigned port)
2. Create a `gorilla/mux` router with `/api/v1` routes and CORS middleware
3. Start `http.Server.Serve()` in a goroutine
4. Launch Wails with `AssetServer` pointing to the embedded `dist/` filesystem
5. On shutdown, gracefully stop the HTTP server with a 5-second timeout

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
    app.go          # Wails app, embedded HTTP server
    config.go       # GUIConfig struct with defaults
    errors.go       # Typed errors
    api/
      router.go     # gorilla/mux routes for admin API
      handlers.go   # HTTP handler implementations
  client/
    app.go          # Wails app, embedded HTTP server
    config.go       # GUIConfig struct with defaults
    errors.go       # Typed errors
    api/
      router.go     # gorilla/mux routes for client API
      handlers.go   # HTTP handler implementations
  webui/
    handler.go      # SPA file server for /ui/admin/ on the ACME server
```
