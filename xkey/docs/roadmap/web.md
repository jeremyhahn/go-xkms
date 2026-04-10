# Roadmap: Dual-Mode xkey GUI (Wails Desktop + Browser Web App)

## Context

The xkey GUI is built with **Wails v2 + Svelte + TypeScript + Tailwind CSS**. The frontend is pure web technology, but it communicates with the Go backend exclusively through Wails-specific RPC (`window.go.services`) and events (`EventsOn`). This roadmap describes how to add a browser mode so the same Svelte frontend can run as a standalone web app served by a Go HTTP server, while preserving the existing Wails desktop mode unchanged.

The architecture is well-suited for this: ~88% of the 26 Go services are pure business logic with zero Wails coupling, and all services use callback injection for events (they don't import Wails directly). Only `tpm_service.go` and `trust_service.go` have 3 direct Wails file dialog calls.

Browser authentication uses **WebAuthn** — the app's own FIDO2 authenticator authenticates the user into the web UI. The complete WebAuthn relying party server already exists in `pkg/webauthn/` (service, HTTP handlers, stores, JWT generation), requiring zero new ceremony code.

---

## Phase 1: Frontend Transport Abstraction

**Goal**: Replace direct `window.go.services` and `EventsOn` calls with a pluggable transport layer. Desktop mode continues working identically.

### New Files

1. **`xkey/frontend/src/lib/api/transport.ts`** — Transport interface
   ```typescript
   export interface ITransport {
     invoke<T>(service: string, method: string, ...args: unknown[]): Promise<T>;
     on(event: string, callback: (...data: unknown[]) => void): () => void;
     off(event: string): void;
     isAvailable(): boolean;
     connect(): Promise<void>;
     disconnect(): void;
   }
   ```

2. **`xkey/frontend/src/lib/api/wails-transport.ts`** — Wraps existing `window.go.services` and `window.runtime.EventsOn` calls behind `ITransport`

3. **`xkey/frontend/src/lib/api/runtime.ts`** — Singleton detection: if `window.go` exists, use `WailsTransport`; otherwise `HTTPTransport`

### Modified Files

4. **`xkey/frontend/src/lib/api/backend.ts`** — Replace `window.go.services[svc][method]()` with `getTransport().invoke()` inside `callBackend`, `callBackendWithError`, `callBackendVoid`, `callBackendVoidWithError`. Replace `isWailsAvailable()` with `getTransport().isAvailable()`. No changes to the function signatures — all 29 views and 13 stores continue calling the same helpers.

5. **`xkey/frontend/src/lib/stores/events.ts`** — Replace the dynamic `import('../../wailsjs/runtime/runtime')` + `wailsRuntime.EventsOn()` pattern with `getTransport().on()`. The `setupEventListeners()` function calls `transport.connect()` first (no-op for Wails, WebSocket connect for HTTP).

---

## Phase 2: Go HTTP Server + JSON-RPC Dispatch

**Goal**: Expose all 26 services via a single `/api/rpc` endpoint using JSON-RPC style dispatch with reflection-based method invocation.

### New Package: `xkey/pkg/gui/webserver/`

1. **`server.go`** — HTTP server lifecycle
   - Serves Svelte `dist/` assets via `embed.FS` with SPA fallback (unmatched routes serve `index.html`)
   - Mounts `/api/rpc` (JSON-RPC handler), `/api/events` (WebSocket), `/api/webauthn/*` (auth)
   - `ServerConfig` struct with addr, assets FS, registry, hub, auth secret

2. **`rpc.go`** — ServiceRegistry + reflection-based dispatch
   - `ServiceRegistry` with `map[string]interface{}` for O(1) service lookup
   - `Register(svc interface{})` derives name from type (e.g., `*services.KeyService` -> `"KeyService"`)
   - Reflection-based method invocation with JSON param coercion (marshal params to JSON, unmarshal into method's Go parameter types — same coercion Wails does)
   - Request: `{"service": "KeyService", "method": "ListKeys", "params": [...]}`
   - Response: `{"result": ..., "error": "..."}`

3. **`events.go`** — WebSocket event hub
   - `EventHub` manages connected WebSocket clients
   - `Broadcast(eventType string, data interface{})` sends to all clients
   - `EmitFunc()` returns a `func(string, any)` callback compatible with `SetEmitFunc()` and `EmitEvent()`
   - Clients reconnect automatically (handled by frontend `HTTPTransport`)

4. **`auth.go`** — Authentication middleware
   - `AuthMiddleware(jwtSecret, next)` validates Bearer JWT on `/api/rpc` and `/api/events`
   - JWT is issued by the existing `pkg/webauthn/jwt_generator.go` on successful WebAuthn login
   - JWT secret: random 128-bit key generated on first web-mode launch, stored in `~/.config/xkey/web-session.key` (0600)
   - WebSocket auth via subprotocol `bearer.<token>` (browser WebSocket API doesn't support custom headers)
   - `/api/webauthn/*` routes are exempt from auth (they ARE the auth flow)
   - Configurable TTL (default 30 min)

5. **`errors.go`** — Typed errors

6. **Tests**: `server_test.go`, `rpc_test.go`, `events_test.go`, `auth_test.go`

---

## Phase 3: Emit Function Abstraction in app.go

**Goal**: Make event emission injectable so WebApp can swap Wails emit for WebSocket broadcast.

### Modified File: `xkey/pkg/gui/app.go`

- Add `emitFunc func(eventType string, data interface{})` field to `App` struct
- Add `SetEmitFunc(fn)` method
- Refactor `EmitEvent()` to call `a.emitFunc` if set, otherwise fall back to `wailsruntime.EventsEmit`
- Refactor the 4 inline `wailsruntime.EventsEmit()` calls to use `a.emitFunc` when set
- Add `StartServices(ctx context.Context)` that contains the service initialization logic from `startup()` (context propagation, emitter wiring, policy init, barrier setup, etc.) — callable from both Wails `OnStartup` and `WebApp.Run()`
- Add `StopServices()` wrapping `shutdown()` logic

The existing `startup()` method calls `StartServices(ctx)` so desktop mode is unchanged.

---

## Phase 4: WebApp Wrapper + Entry Point

**Goal**: A `WebApp` struct that boots the same services but uses the HTTP server instead of Wails.

### New Files

1. **`xkey/pkg/gui/webapp.go`** — WebApp struct
   - `NewWebApp(cfg *GUIConfig) *WebApp`
   - `Run(addr string, assets fs.FS) error`:
     - Creates `App` with standard config
     - Registers all 26 services in `ServiceRegistry`
     - Sets `App.emitFunc` to `EventHub.Broadcast`
     - Wires notifier, phone emitter, FIDO2 emitter through the hub
     - Calls `App.StartServices(ctx)` with `context.Background()`
     - Starts HTTP server (blocking)
     - On shutdown: `App.StopServices()`

2. **`xkey/cmd/xkey-web/main.go`** — CLI entry point
   - Flags: `--addr :8443`, `--dev` (skip embedded assets, proxy to Vite), `--tls-cert`, `--tls-key`
   - Loads `GUIConfig`, creates `WebApp`, calls `Run()`
   - In dev mode: serves API only (frontend from Vite HMR on :5173)

3. **`xkey/frontend/embed.go`** — Already exists; reused for web mode asset embedding

---

## Phase 5: HTTP Transport (Frontend)

**Goal**: Browser can communicate with the Go HTTP server.

### New File

1. **`xkey/frontend/src/lib/api/http-transport.ts`** — HTTPTransport implementing ITransport
   - `invoke()`: `POST /api/rpc` with JSON body, Bearer token header
   - `on()`: Registers callback in local listeners map, dispatched from WebSocket
   - `connect()`: Opens WebSocket to `/api/events` with auth subprotocol
   - Auto-reconnect with exponential backoff on disconnect
   - `setToken(token)` for auth integration

### Modified File

2. **`xkey/frontend/vite.config.ts`** — Add dev server proxy:
   ```typescript
   server: {
     proxy: {
       '/api': { target: 'http://localhost:8080', ws: true }
     }
   }
   ```

---

## Phase 6: WebAuthn Browser Authentication

**Goal**: Use the app's own FIDO2 authenticator to log into the browser UI via WebAuthn. The xkey app *is* a FIDO2 authenticator — using it to authenticate into its own web interface is a natural fit and dogfoods the core product.

### Existing Infrastructure to Reuse (zero new Go ceremony code needed)

- **`pkg/webauthn/service.go`** — Complete WebAuthn service with `BeginRegistration`, `FinishRegistration`, `BeginLogin`, `FinishLogin`
- **`pkg/webauthn/http/handler.go`** — 5 HTTP handlers ready to mount (begin/finish registration, begin/finish login, status)
- **`pkg/webauthn/http/routes.go`** — `MountStdlib(mux, prefix, handler)` for stdlib `http.ServeMux`
- **`pkg/webauthn/memory_stores.go`** — In-memory `UserStore`, `SessionStore`, `CredentialStore` (thread-safe, with TTL)
- **`pkg/api/rest/webauthn_stores.go`** — `NewWebAuthnStores()` convenience wrapper with cleanup routines
- **`pkg/webauthn/config.go`** — Config with RPID, origins, timeouts, user verification preference
- **`pkg/webauthn/jwt_generator.go`** — JWT token generation on successful login

### Backend Integration (in `xkey/pkg/gui/webserver/`)

Add to **`server.go`**:
- Create `webauthn.Service` with config: `RPID = "localhost"` (or hostname), `RPOrigins = ["https://localhost:8443"]`
- Create `webauthn/http.Handler` with the service
- Mount via `webauthnhttp.MountStdlib(mux, "/api/webauthn", handler)`
- Start store cleanup routine via `stores.StartCleanupRoutine(ctx, time.Minute)`

Add to **`auth.go`**:
- `AuthMiddleware` validates JWT returned by WebAuthn `FinishLogin` (same JWT the existing `JWTGenerator` produces)
- Bearer token required on `/api/rpc` and `/api/events`
- WebSocket auth via subprotocol `bearer.<token>`
- Unauthenticated requests to `/api/webauthn/*` are allowed (registration/login endpoints)

### Frontend

1. **`xkey/frontend/src/lib/api/auth.ts`** — WebAuthn ceremony client
   - `register(email, displayName)` — Calls `/api/webauthn/register/begin`, runs `navigator.credentials.create()`, calls `/api/webauthn/register/finish`, stores JWT
   - `login(email?)` — Calls `/api/webauthn/login/begin`, runs `navigator.credentials.get()`, calls `/api/webauthn/login/finish`, stores JWT
   - `getToken(): string | null` — from `sessionStorage`
   - `isAuthenticated(): boolean`
   - `logout()` — clear token, disconnect transport

### Modified Files

2. **`xkey/frontend/src/App.svelte`** — In browser mode (`!isDesktopMode()`), show login gate before main app. Reuse existing auth gating pattern.

3. **`xkey/frontend/src/lib/api/http-transport.ts`** — Wire token from `auth.ts` into request headers

---

## Phase 7: File Dialog Abstraction

**Goal**: TPM policy export/import and cert import work in browser mode.

### New File

1. **`xkey/pkg/gui/services/file_dialog.go`** — `FileDialogProvider` interface
   ```go
   type FileDialogProvider interface {
     SaveFileDialog(title, defaultFilename string, filters []FileFilter) (string, error)
     OpenFileDialog(title string, filters []FileFilter) (string, error)
   }
   ```

2. **`xkey/pkg/gui/services/file_dialog_wails.go`** — Implementation wrapping `wailsruntime.SaveFileDialog` / `OpenFileDialog`

### Modified Files

3. **`xkey/pkg/gui/services/tpm_service.go`** (lines 3446, 3524) — Use `FileDialogProvider` instead of direct `wailsruntime` calls

4. **`xkey/pkg/gui/services/trust_service.go`** (line 218) — Same

5. Add data-based alternatives for browser mode:
   - `ExportPolicyData(name string) ([]byte, error)` — returns policy bytes (frontend triggers download via Blob)
   - `ImportPolicyData(name string, data []byte) error` — accepts policy bytes (frontend uses `<input type="file">`)
   - `ImportCertificateData(data []byte) error` — accepts cert PEM bytes

---

## Phase 8: Build System + Documentation

### Modified Files

1. **`xkey/Makefile`** — Add targets:
   - `build-web`: Build `xkey-web` binary (Go HTTP server + embedded frontend)
   - `dev-web`: Development mode (Go server on :8080, API only)
   - `run-web`: Build and run web server

2. **`xkey/docs/gui/web-mode.md`** — Usage documentation for browser mode

---

## Wails API Surface to Abstract (Complete Inventory)

| Location | Wails Call | Abstraction |
|----------|-----------|-------------|
| `app.go:1704` | `EventsEmit` in `EmitEvent()` | `emitFunc` callback |
| `app.go:1159` | `EventsEmit` in FIDO2 emitter setup | Already callback-injected |
| `app.go:1165` | `EventsEmit` in WailsNotifier setup | Already callback-injected |
| `app.go:1226,1229` | `EventsEmit` for auto-unseal events | Route through `emitFunc` |
| `app.go:1320` | `EventsEmit` for password expiry | Route through `emitFunc` |
| `app.go:1754` | `EventsEmit` for `app:shutting_down` | Route through `emitFunc` |
| `app.go:1110` | `WindowHide` in `beforeClose` | Skip in web mode |
| `app.go:1792-1795` | `WindowShow/Unminimise/AlwaysOnTop` | Skip in web mode |
| `app.go:1803` | `WindowHide` | Skip in web mode |
| `tpm_service.go:3446` | `SaveFileDialog` | `FileDialogProvider` |
| `tpm_service.go:3524` | `OpenFileDialog` | `FileDialogProvider` |
| `trust_service.go:218` | `OpenFileDialog` | `FileDialogProvider` |

---

## Implementation Order & Dependencies

```
Phase 1 (Frontend transport) ──────────────────────┐
                                                    │
Phase 2 (Go HTTP server) ──── independent ──────────┤
                                                    │
Phase 3 (Emit abstraction in app.go) ──────────────┤
                                                    │
Phase 7 (File dialog abstraction) ── independent ───┤
                                                    │
Phase 4 (WebApp wrapper) ── depends on 2, 3 ────────┤
                                                    │
Phase 5 (HTTP transport) ── depends on 2, 4 ────────┤
                                                    │
Phase 6 (WebAuthn auth) ── depends on 5 ────────────┤
                                                    │
Phase 8 (Build + docs) ── depends on all ───────────┘
```

Phases 1, 2, 3, and 7 can be developed in parallel.

---

## Verification

1. **Desktop mode regression**: After Phase 1, run existing Wails dev mode — all views load, events fire, services respond identically
2. **HTTP server unit tests**: Phase 2 tests verify JSON-RPC dispatch with mock services, correct error handling, param coercion
3. **WebSocket event tests**: Phase 3 tests verify event broadcast to connected clients
4. **End-to-end browser test**: After Phase 5, run `make dev-web` + `cd frontend && npm run dev`, open `http://localhost:5173` — Dashboard loads with real data
5. **WebAuthn auth test**: Phase 6 — unauthenticated requests return 401, register xkey FIDO2 authenticator via WebAuthn, login returns JWT, subsequent API requests succeed with Bearer token
6. **File operations**: Phase 7 — TPM policy export downloads in browser, cert import via file picker works
7. **Production build**: `make build-web` produces a single binary that serves the full app on `https://localhost:8443`

---

## Critical Files

- `xkey/frontend/src/lib/api/backend.ts` — RPC wrapper (4 functions to refactor)
- `xkey/frontend/src/lib/stores/events.ts` — Event subscription (1 function to refactor)
- `xkey/frontend/vite.config.ts` — Add proxy for dev mode
- `xkey/pkg/gui/app.go` — Add `emitFunc`, `StartServices()`, `StopServices()`
- `xkey/pkg/gui/services/tpm_service.go` — 2 file dialog calls to abstract
- `xkey/pkg/gui/services/trust_service.go` — 1 file dialog call to abstract
- `xkey/pkg/gui/events/events.go` — Event type definitions (reused by WebSocket hub)
- `pkg/webauthn/service.go` — WebAuthn ceremony service (reuse as-is for browser auth)
- `pkg/webauthn/http/handler.go` — WebAuthn HTTP handlers (mount via `MountStdlib`)
- `pkg/webauthn/http/routes.go` — `MountStdlib()` for stdlib mux integration
- `pkg/api/rest/webauthn_stores.go` — `NewWebAuthnStores()` convenience wrapper (reuse as-is)
