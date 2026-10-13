# Admin Web Mode

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on serving the admin SPA over HTTP.

## xkmsd (`/admin-ui`)

`xkmsd` is the binary that serves the admin SPA:

1. `newAdminModule` (`cmd/xkmsd/admin.go:91`) takes
   `fs.Sub(adminweb.Assets, "dist")` (`:92`), where `adminweb` is
   `pkg/acme/web/packages/admin`.
2. It mounts that filesystem at `/admin-ui` with
   `WithAdminWebUI(adminUIPrefix, uiFS, false)` (`:104`).

```
https://kms.example.com:<port>/admin-ui/
```

The SPA has no Wails runtime, so it uses a same-origin API base. Its calls go
to xkmsd's `/admin/*` and `/api/v1/tenants/...` endpoints. See
[acme-issuance/user.md](../../../acme-issuance/user.md#browsing-the-api-interactively).

## `webui.RegisterRoutes` (`/ui/admin/`)

`pkg/acme/gui/webui` can also mount the SPA:

1. `webui.AdminAssets` (`pkg/acme/gui/webui/embed.go:22`) is the same
   embedded admin bundle.
2. `RegisterSPA` (`handler.go:41`) strips the prefix and serves the bundle
   through the shared `corewebui.NewHandler`. Known files are served directly;
   unknown paths fall back to `index.html`. Its `WithAPIBaseURL` option
   (`handler.go:32`) injects an API base for the SPA.
3. `RegisterRoutes` (`handler.go:61`) calls `RegisterSPA` for `/ui/admin/`
   with no options.

Only `pkg/acme/api/server` calls `RegisterRoutes`
(`pkg/acme/api/server/server.go:670`), and only tests construct that server.
`test/integration/acmeserver/acmeserver_gui_test.go` covers it.

## Differences from desktop mode

| Aspect | Desktop (Wails) | Web |
|--------|-----------------|-----|
| API base URL | `''` from the `GetApiBaseUrl` binding | `''`, or the `WithAPIBaseURL` value |
| Transport detection | Wails runtime present | no Wails runtime |
| Socket | none: the API is the asset server's handler | the hosting server's listener and TLS |
| Origin check | `guard` with the in-process transport | `guard` same-host check (webui), or xkmsd's own middleware |
