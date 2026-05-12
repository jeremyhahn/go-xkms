# Admin Web Mode

When the ACME server starts, it registers the admin SPA at `/ui/admin/` via `webui.RegisterRoutes()`.

## How It Works

1. The admin frontend is compiled into the server binary as an embedded `fs.FS`
2. `RegisterRoutes()` creates a sub-filesystem from `dist/` and mounts it on the server's `gorilla/mux` router
3. A custom `spaFileServer` handles static file serving with SPA fallback:
   - Known files (JS, CSS, images) are served directly with proper content types
   - Unknown paths return `index.html` so Svelte handles client-side routing

## Access

```
https://your-ca-server:8443/ui/admin/
```

The SPA uses relative URLs (`/api/v1`) for API calls, which resolve against the server's origin.

## Differences from Desktop Mode

| Aspect | Desktop | Web |
|--------|---------|-----|
| API base URL | `http://localhost:{random}/api/v1` | `/api/v1` (same origin) |
| Transport detection | Wails runtime detected | No Wails, uses defaults |
| Connection Settings view | Available | Not shown (server is the CA) |
| Authentication | Token from config | Browser session/token via server auth |
| TLS | Embedded server is plain HTTP on loopback | Server's TLS configuration |

## Authentication

In web mode, the admin SPA sends a Bearer token via the `Authorization` header and a tenant identifier via `X-Tenant-ID`. Configure authentication through the server's auth middleware.
