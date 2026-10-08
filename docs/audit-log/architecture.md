# Audit Log — Architecture

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-10-07 (S2c)

## The problem

A KMS that cannot say who used which key, when, and whether it was allowed is
not deployable in a regulated environment. The audit log is what makes the
system answerable — and it has to survive the thing it is auditing, including an
operator who would rather it did not.

## Shape chosen: one product event, go-qrdb's logger

go-xkms owns the product event vocabulary and nothing else. The sink, its
chaining, persistence and query are go-qrdb's `NodeAuditLogger`.

```go
func Emit(ctx context.Context, sink qrdbsdk.NodeAuditLogger, event *Event) error
```

```go
type Event struct {
	Timestamp  time.Time         // when
	Subject    string            // who
	Action     string            // what
	Resource   string            // keys, certs, users, …
	ResourceID string            // which one
	Outcome    string            // "allow" or "deny"
	Details    map[string]string
}
```

`Outcome` is a closed two-value set. **Denials are audited as first-class
events**, not as errors that happen to get logged somewhere. An audit log
containing only successes cannot answer the question anyone actually asks after
an incident.

A nil sink means auditing is off; `Emit` then returns nil. There is no no-op
logger type.

Rejected alternatives:

- **Logging audit events through the ordinary logger.** Rejected: application
  logs rotate, get filtered, and are written by anything; an audit record needs
  its own path and its own retention.
- **A rich event type per subsystem.** Rejected — one shape means one query
  surface. Subsystem specifics go in `Details`.
- **A go-xkms sink alongside go-qrdb's.** Rejected: two trails, two severity
  vocabularies and two chains answer the same question twice. The sink is
  go-qrdb's; go-xkms contributes events.

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| `Event`, `Emit` | `pkg/audit` | go-xkms |
| Sink: file, ring buffer, node | `go-qrdb/sdk/go` (`NodeAuditLogger`) | **go-qrdb** |
| ACME-specific audit | `pkg/acme/audit`, `pkg/acme/server/handlers/audit.go` | go-xkms |
| Seal audit | `pkg/seal/audit.go` (adapts the barrier's audit interface onto `Emit`) | go-xkms |
| Identity and RBAC decisions | go-qrdb — audited on its side | **go-qrdb** |

## Data flow

```
operation → authorization decision (allow | deny)
   → audit.Emit(ctx, sink, &Event{Subject, Action, Resource, ResourceID, Outcome, Details})
     → NodeAuditEvent{Actor, TenantID, Role, ClientIP, Attributes, …}
     → go-qrdb logger: chained, persisted, indexed
   → operation proceeds, or is refused when Emit returns *AuditGateError
```

Reading the log back is go-qrdb's `AuditService.QueryAudit`, cursor-paginated
and tenant-confined; xkms does not re-expose it.

## Trust boundaries

- **The audit log is evidence.** Its integrity matters more than its
  availability: an audit write that fails should be visible, and the
  go-qrdb's chained logger makes tampering after the fact detectable rather
  than merely discouraged.
- **Denials are the valuable records.** A log of successes tells you what
  worked; a log of denials tells you what was attempted.
- **`Details` is free-form and therefore dangerous.** It is a
  `map[string]string` that ends up in durable, queryable, exportable storage.
  Never put key material, PINs, passphrases, share bytes or tokens in it.

- **A nil sink is a deliberate, visible choice.** A deployment running with
  audit disabled should know it.

## Write-failure policy

An audit write that fails must not look like a healthy one. `Emit` wraps every
sink error in go-qrdb's typed `*AuditGateError`, and the call site propagates
it so the request fails closed. The old per-event severity split
(security vs. informational) is gone from `pkg/audit`: it duplicated go-qrdb's
levels. It remains only in `xkey/pkg/audit` and `pkg/acme/audit`, which still
own separate sinks.

Rejected alternatives:

- **Tolerate failures for low-risk events inside `pkg/audit`.** Rejected: that
  is go-qrdb's severity decision, and re-deciding it here is the duplication
  this feature removed.

## What this feature deliberately does not do

- **It does not decide anything.** Authorization is go-qrdb's RBAC; audit
  records the outcome.
- **It does not define the permission vocabulary** — that is `pkg/auth`,
  mirroring go-qrdb's model.
- **It does not ship a retention or archival policy.** Retention is a
  deployment decision.
- **It does not replace go-qrdb's own audit** of identity and RBAC operations.
