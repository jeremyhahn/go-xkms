# CA Admin GUI

> **Status: REFERENCE** · Last verified: 2026-10-21
> Legacy, unabsorbed notes on the admin SPA (`pkg/acme/web/packages/admin`) and its hosts.

The admin SPA is a single Svelte bundle. Three hosts can serve it:

| Host | Where | In a binary |
|------|-------|-------------|
| xkmsd admin module | `/admin-ui` (`cmd/xkmsd/admin.go:55`, `:92`, `:104`) | yes |
| Wails desktop (`pkg/acme/gui/admin`) | native window | `xkmsctl acme gui`, `gui` tag only (`cmd/xkmsctl/acme_gui.go:99`; [cli.md](../../../acme-issuance/cli.md#xkmsctl-acme-gui)) |
| ACME API server (`pkg/acme/gui/webui`) | `/ui/admin/` | no: only tests build that server |

The SPA's API calls (`src/lib/api/admin-api.ts`) target `/admin/*` and
`/api/v1/tenants/...`: the ACME admin API's routes (`pkg/acme/admin/routes.go`).
xkmsd mounts that API itself. The desktop host's router serves the same paths
through the SDK (see [api.md](api.md)), and
`pkg/acme/gui/admin/spa_routes_test.go` checks the SPA client against it. On
the desktop, `GET /admin/audit` and
`PUT /api/v1/tenants/{id}/default-intermediate-ca` answer 404 until the SDK
has operations for them.

## Desktop defaults (`pkg/acme/gui/admin/config.go:17-24`)

| Property | Value |
|----------|-------|
| Title | Trusted CA Admin |
| Size | 1280 x 800 |
| Min size | 1024 x 700 |
| Transport | `unix` |
| Address | `/run/trusted-ca-grpc.sock` |
| Timeout | 30 s |

The Linux `ProgramName` is `xkmsctl` (`pkg/acme/gui/admin/app.go:87`). The
transport, address and TLS defaults above are overwritten by `xkmsctl acme gui`
from `--acme-server`, `--acme-transport` and `--tls-*`
(`cmd/xkmsctl/acme_gui.go:122`).

## Navigation

`App.svelte` gates the UI on setup and seal state (loading, setup wizard,
sealed, app). The sidebar then shows these entries, in this order:

| View | Purpose |
|------|---------|
| Dashboard | CA status, statistics, certificates expiring in 30 days |
| Seal Manager | Barrier seal/unseal status |
| Certificates | Certificate list |
| Accounts | ACME account list |
| CA Manager | Root and per-tenant intermediate CAs |
| Orders | Order list and order detail |
| Tenants | Tenant list, create, tenant detail |
| Audit Log | Audit entries |
| Connection | Shows the API base URL and connection status |
| Settings | Light / Dark / System theme |

## Related documentation

- [Views reference](views.md)
- [Web mode](web-mode.md)
- [Desktop admin API](api.md)
