# Testing

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on how the ACME GUI code is tested.

## Frontend

The `pkg/acme/web` workspace has no unit-test runner and no `test` script.
The only automated frontend check is type checking:

```bash
cd pkg/acme/web && npm run check     # svelte-check, admin and client
```

## Go API routers

The `/api/v1` routers are plain `http.Handler`s, tested with `httptest` in
`pkg/acme/gui/admin/api/admin_api_test.go` and
`pkg/acme/gui/client/api/{client_api_test,security_test}.go`:

```go
router := adminapi.NewRouter(client, logger, adminapi.WithInProcessTransport())
req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
w := httptest.NewRecorder()
router.ServeHTTP(w, req)
```

`NewRouter` takes a `trustedca.Client` for admin
(`pkg/acme/gui/admin/api/router.go:32`). For the client router it takes a
`workflow.Workflow` and the client `*service.Service`
(`pkg/acme/gui/client/api/router.go:42`).

```bash
make test-acme                                  # pkg/acme/..., includes the router tests
go test -tags gui ./pkg/acme/gui/...            # adds app_security_test.go (gui tag)
go test ./pkg/acme/gui/guard/ ./pkg/acme/gui/webui/
```

The desktop apps bind no port, so you cannot `curl` a running window.

## Integration

`test/integration/acmeserver/acmeserver_gui_test.go` (`integration` tag)
checks that the admin SPA is served at `/ui/admin/`, falls back to
`index.html`, serves static assets, and 404s for missing assets:

```bash
make integration-test-acmeserver
```

Run it in the devcontainer, as with every integration suite.

## Build verification

```bash
cd pkg/acme/web && npm run build && npm run check
go build -tags gui ./cmd/acme-client
```
