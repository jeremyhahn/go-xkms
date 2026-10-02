# Audit Log — API

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-09-28 (#1115)

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC | MCP | Embedded (`AuditService.`) | Permission |
|---|---|---|---|---|---|---|
| Query audit | `GET /api/v1/audit/` | `QueryAudit` | same as REST | `xkms.queryAudit` | `QueryAudit` | `audit:read`; the caller's own tenant only |

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

The tenant a query reads is decided by the service, not by the request
(`XKMSService.auditTenantFilter`, `pkg/xkms/servicer_audit.go`). All the
handlers forward the filter unchanged, and none of them decides tenancy. The
route permission, `audit:read`, is self-scope, so it cannot bound the tenant on
its own.

| Caller | `tenant_id` sent | Tenant the chain is queried for |
|---|---|---|
| tenant identity | anything, including empty or another tenant's | the caller's own tenant |
| system-tenant identity | anything, including empty or another tenant's | `system`, plus the untenanted platform events |
| no identity, or an identity with no tenant | anything | `system` |

This is go-qrdb's audit contract: every caller, the system tenant included,
reads only its own tenant's events, and go-qrdb has no cross-tenant audit
permission (`audit:read:cross` was removed). No authorizer decision is
consulted, with RBAC on or off. A narrowed query succeeds and returns the
narrower result; it does not return an error. The clamp is never `""`,
because `""` is the chain's match-everything filter.

## Versioning and deprecation

`GET /api/v1/audit/`, gRPC package `xkmsv1`. Nothing deprecated.

The compatibility rule with teeth here is `Outcome`: it is a two-value set, and
adding a third value would silently change the meaning of every stored query and
alert that assumed otherwise.
