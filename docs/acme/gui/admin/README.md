# CA Admin GUI

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on the admin SPA (`pkg/acme/web/packages/admin`) and its hosts.

The admin SPA is a single Svelte bundle. Three hosts can serve it:

| Host | Where | In a binary |
|------|-------|-------------|
| xkmsd admin module | `/admin-ui` (`cmd/xkmsd/admin.go:55`, `:92`, `:104`) | yes |
| Wails desktop (`pkg/acme/gui/admin`) | native window | no: there is no `cactl` binary (go-xkms#743, go-xkms#746) |
| ACME API server (`pkg/acme/gui/webui`) | `/ui/admin/` | no: only tests build that server |

The SPA's API calls (`src/lib/api/admin-api.ts`) target `/admin/*` and
`/api/v1/tenants/...`. That is the xkmsd admin surface. The desktop host's
router serves `/api/v1/status`, `/api/v1/certificates` and so on (see
[api.md](api.md)), so most SPA calls would not match it.

## Desktop defaults (`pkg/acme/gui/admin/config.go:17-24`)

| Property | Value |
|----------|-------|
| Title | Trusted CA Admin |
| Size | 1280 x 800 |
| Min size | 1024 x 700 |
| Transport | `unix` |
| Address | `/run/trusted-ca-grpc.sock` |
| Timeout | 30 s |

The Linux `ProgramName` is still `cactl` (`pkg/acme/gui/admin/app.go:87`).

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
