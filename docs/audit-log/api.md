# Audit Log — API

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-10-12

No API surface for the product audit log (`pkg/audit`): its query routes, RPCs
and MCP method were removed; the read side is go-qrdb's `AuditService`.
Writers use `pkg/audit` in-process.

## ACME audit trail

The ACME server keeps its own trail (`pkg/acme/audit`, configured under
`acme.audit`; see [engineering.md](engineering.md#acme-audit-trail)). It has
one read route on the ACME admin plane:

`GET /admin/audit`, permission `audit:read`
(`pkg/acme/admin/handlers.go:132`), handled by `ListAuditLogs`
(`handlers.go:446-488`). The caller must be a platform (system-tenant)
principal; a tenant-scoped caller gets `403` (`requirePlatformScope`,
`pkg/acme/admin/tenant_binding.go:113`).

| Parameter | Meaning |
|---|---|
| `page` | page number, default 1 |
| `per_page` | page size, default 25, capped at 100 (`pkg/acme/audit/query.go:51`, `:54`) |
| `event_type`, `actor`, `action`, `resource`, `result`, `request_id` | filters |
| `start_time`, `end_time` | RFC 3339 timestamps (`handlers.go:526-537`) |

Parameters are parsed at `handlers.go:491-523`. The success body is
`{items, total, page, per_page}`.

| Status | When |
|---|---|
| `200` | the page of events |
| `400` | a timestamp that is not RFC 3339; `end_time` before `start_time` (`ErrInvalidTimeRange`, `query.go:42`); or a page beyond the 10 000-event query window (`ErrQueryWindowExceeded`, `query.go:39`, `:58`) |
| `403` | the caller is not a platform principal, or lacks `audit:read` |
| `501` | the server has no audit querier configured |
| `500` | the query failed |

Records that cannot be decoded are not returned; their count is logged as a
warning (`handlers.go:476-479`).

**xkmsd answers `501`.** It builds its admin handlers without an audit querier
(`cmd/xkmsd/admin.go:143`), so the trail is written but cannot be queried
through xkmsd. The library `MultiProtocolServer` serves the route when its
`ServerConfig.AuditQuerier` is set (`pkg/acme/api/server/server.go:108-113`,
`:627-631`).
