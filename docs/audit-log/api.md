# Audit Log — API

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-08-19

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC | MCP | Embedded (`AuditService.`) | Permission |
|---|---|---|---|---|---|---|
| Query audit | `GET /api/v1/audit/` | `QueryAudit` | same as REST | `xkms.queryAudit` | `QueryAudit` | `audit:read` |

One capability, on all five wire transports plus embedded. Registered
conditionally on `hasAudit` — where auditing is disabled the route does not
exist, which is itself informative.

**There is no write endpoint, deliberately.** Audit records are produced by the
operations being audited, in-process. A remote "append an audit record" API
would let a caller write history, which defeats the point of having one.

## The write side is in-process only

```go
audit.Logger.Log(ctx, &audit.Event{
	Timestamp:  time.Now(),
	Subject:    "alice",
	Action:     "sign",
	Resource:   "keys",
	ResourceID: "web-tls",
	Outcome:    audit.OutcomeAllow,   // or OutcomeDeny
	Details:    map[string]string{"backend": "tpm2"},
})
```

`Details` values reach durable, queryable, exportable storage. Nothing secret
goes in them.

## Query schema

`AuditFilter` (`pkg/api/transport/types.go`) mirrors the CLI flags: actor,
resource, action, outcome, tenant, from, to, limit, cursor.

`AuditPage` carries the matching `Event` values plus a next cursor. Every field
of `Event` is on the wire: `timestamp`, `subject`, `action`, `resource`,
`resource_id`, `outcome`, `details`.

`outcome` is exactly `"allow"` or `"deny"`. A client can rely on that being a
closed set.

## Status and error mapping

| Condition | REST | gRPC / Unix | MCP |
|---|---|---|---|
| results (including none) | 200 | `OK` | `result` |
| malformed timestamp or filter | 400 | `InvalidArgument` | JSON-RPC `-32602` |
| invalid or expired cursor | 400 | `InvalidArgument` | error object |
| not permitted (`audit:read`) | 403 | `PermissionDenied` | error object |
| audit not configured | route absent (404) | `Unimplemented` | error object |

An empty result set is **200 with no events**, not 404. "Nothing happened" is a
legitimate and often important answer.

A denied audit query is itself an audit event — an attempt to read the log is
worth recording.

## Pagination

Cursor-based, and mandatory in effect: an audit log is unbounded by
construction, so `QueryAudit` never returns everything. `limit` of `0` means the
server's default page size; the response carries the next cursor.

Callers walking a large range should bound it with `from`/`to` rather than
paging from the beginning of time.

Handlers: `pkg/api/rest/handlers_audit.go`, `pkg/api/grpc/service_audit.go`,
`pkg/api/mcp/handlers_audit.go`.

## Tenant scoping

`AuditFilter.Tenant` filters by tenant. The `/api/v1` routes run behind tenant
middleware, so a tenant-scoped caller sees their own events; a filter is a
narrowing tool, not an escape from that scoping.

## Versioning and deprecation

`GET /api/v1/audit/`, gRPC package `xkmsv1`. Nothing deprecated.

The compatibility rule with teeth here is `Outcome`: it is a two-value set, and
adding a third value would silently change the meaning of every stored query and
alert that assumed otherwise.
