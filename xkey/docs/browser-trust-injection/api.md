# Browser Trust Injection — API

> **Status: NORMATIVE** · Feature: `browser-trust-injection` · Repo: `go-xkms` (`xkey/`) · Last verified: 2026-09-24

**No REST, gRPC, QUIC, or MCP surface.** This feature is reachable only
through the `xkey` CLI (see [`cli.md`](cli.md)) and the Wails IPC bindings
the desktop GUI's frontend calls. It has no network transport because it has
no remote caller: the browser it launches and the trust store it reads both
live on the same machine as the GUI/CLI process.

## Wails-bound service methods

Two Go services are bound to the frontend via Wails and exposed as generated
TypeScript bindings under `xkey/frontend/wailsjs/go/services/`:

### `BrowserService` (`xkey/frontend/wailsjs/go/services/BrowserService.d.ts`)

| Method | Go signature |
|---|---|
| `DetectBrowsers` | `() Promise<BrowserInfo[]>` |
| `GetConfig` | `() Promise<BrowserConfig>` |
| `SetConfig` | `(BrowserConfig) Promise<void>` |
| `GetTrustBundlePath` | `() Promise<string>` |
| `SetTrustBundlePath` | `(string) Promise<void>` |
| `OpenURL` | `(string) Promise<void>` |
| `SetContext` | `(context.Context) Promise<void>` — Wails startup lifecycle hook, not caller-invoked |

### `SecureBrowserService` (`xkey/frontend/wailsjs/go/services/SecureBrowserService.d.ts`)

| Method | Go signature |
|---|---|
| `DetectBrowsers` | `() Promise<BrowserInfo[]>` — filtered to Chrome/Firefox-family only |
| `LaunchBrowser` | `(browserPath: string, url: string) Promise<LaunchResult>` |
| `LaunchBrowserWithOptions` | `(browserPath: string, url: string, opts: LaunchOptions) Promise<LaunchResult>` |
| `Rebuild` | `() Promise<void>` |
| `SetContext` | `(context.Context) Promise<void>` |

`LaunchResult` carries explicit `json` tags — `browser`, `family`, `mode`,
`cert_count`, `pid`, `extensions_imported`
(`secure_browser_service.go:59-70`) — so the frontend sees exactly those
snake_case keys. `LaunchOptions` (`secure_browser_service.go:75-93`) has no
`json` tags of its own, so Wails marshals its fields under their Go names
(`IncludeExtensions`, `ExtensionIDs`, `SourceProfile`); confirm the generated
`xkey/frontend/wailsjs/go/models.ts` for the exact casing before consuming it
from new frontend code.

The frontend calls these through a `callBackend<T>(service, method, ...args)`
helper (`xkey/frontend/src/views/Browser.svelte:101-162`), not by importing
the generated bindings directly in every call site — that indirection is a
frontend implementation detail, not part of this feature's contract.

## GUI wiring

`xkey/pkg/gui/app.go:1814-1835` constructs `BrowserService`, then
`SecureBrowserService`, wires `browserSvc.SetTrustSyncer(secureBrowserSvc)`
so `BrowserService.OpenURL`'s optional trust-bundle sync
(`IncludeTrustBundle`) reaches the browser certificate stores rather than
only `SSL_CERT_FILE`, and registers `trustSvc.SetOnMutate(func() {
secureBrowserSvc.Rebuild() })` so every trust-store mutation the GUI
performs (add/remove/update a CA certificate) resyncs both browser families
immediately.

## Embedded Go usage

Both services are ordinary exported Go types; embedding go-xkms's xkey
package does not require Wails:

```go
browserSvc, _ := services.NewBrowserService("", logger)
trustSvc := services.NewTrustService(store)
secureSvc := services.NewSecureBrowserService(baseDir, browserSvc, trustSvc, logger)

result, err := secureSvc.LaunchBrowserWithOptions("/usr/bin/google-chrome", "https://example.com",
    services.LaunchOptions{})
```

See [`engineering.md`](engineering.md) for the full method and error
surface.
