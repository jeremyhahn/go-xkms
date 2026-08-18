# Audit Log — Architecture

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-08-19

## The problem

A KMS that cannot say who used which key, when, and whether it was allowed is
not deployable in a regulated environment. The audit log is what makes the
system answerable — and it has to survive the thing it is auditing, including an
operator who would rather it did not.

## Shape chosen: one tiny interface, two real implementations

```go
type Logger interface {
	Log(ctx context.Context, event *Event) error
	Close() error
}
```

Two methods. Everything interesting is in the record and in the backends.

```go
type Event struct {
	Timestamp  time.Time         `json:"timestamp"`
	Subject    string            `json:"subject"`     // who
	Action     string            `json:"action"`      // what
	Resource   string            `json:"resource"`    // keys, certs, users, …
	ResourceID string            `json:"resource_id"` // which one
	Outcome    string            `json:"outcome"`     // "allow" or "deny"
	Details    map[string]string `json:"details,omitempty"`
}

const (
	OutcomeAllow = "allow"
	OutcomeDeny  = "deny"
)
```

`Outcome` is a closed two-value set. **Denials are audited as first-class
events**, not as errors that happen to get logged somewhere. An audit log
containing only successes cannot answer the question anyone actually asks after
an incident.

Implementations:

| Implementation | File | Use |
|---|---|---|
| chained file | `chained_file.go` | tamper-evident local log — each record chained to its predecessor |
| qrdb-backed | `qrdb.go` | durable, queryable, replicated with the database |
| no-op | `logger.go` (`NoOpLogger`) | audit disabled |

`NoOpLogger` is explicit and discards everything. That is better than a nil
logger — the call sites stay uniform and "audit is off" is a visible
configuration choice rather than an accident.

Rejected alternatives:

- **Logging audit events through the ordinary logger.** Rejected: application
  logs rotate, get filtered, and are written by anything; an audit record needs
  its own path and its own retention.
- **A rich event type per subsystem.** Rejected — one shape means one query
  surface. Subsystem specifics go in `Details`.
- **File only, or database only.** Rejected: the chained file is tamper-evident
  on one host; the qrdb log is queryable across a cluster. Different questions.

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| `Logger`, `Event`, `NoOpLogger` | `pkg/audit` | go-xkms |
| Chained-file backend | `pkg/audit/chained_file.go` | go-xkms |
| qrdb backend | `pkg/audit/qrdb.go` — through `go-qrdb/sdk/go` | store is **go-qrdb's** |
| Query surface | `pkg/api/rest/handlers_audit.go`, `pkg/api/mcp/handlers_audit.go`, `pkg/api/grpc/service_audit.go` | go-xkms |
| ACME-specific audit | `pkg/acme/audit`, `pkg/acme/server/handlers/audit.go` | go-xkms |
| Seal audit | `pkg/seal/audit.go` | go-xkms |
| Identity and RBAC decisions | go-qrdb — audited on its side | **go-qrdb** |

## Data flow

```
operation → authorization decision (allow | deny)
   → audit.Logger.Log(ctx, &Event{Subject, Action, Resource, ResourceID, Outcome, Details})
     → chained file:  append, chained to the previous record's hash
     → qrdb:          durable, indexed, queryable
   → operation proceeds or is refused
```

Query goes the other way, through `QueryAudit` with an `AuditFilter`, returning
an `AuditPage` — cursor-paginated, because an audit log is by construction
unbounded.

## Trust boundaries

- **The audit log is evidence.** Its integrity matters more than its
  availability: an audit write that fails should be visible, and the
  chained-file backend exists so tampering after the fact is detectable rather
  than merely discouraged.
- **Denials are the valuable records.** A log of successes tells you what
  worked; a log of denials tells you what was attempted.
- **`Details` is free-form and therefore dangerous.** It is a
  `map[string]string` that ends up in durable, queryable, exportable storage.
  Never put key material, PINs, passphrases, share bytes or tokens in it.
- **Query is permission-gated** (`audit:read`) and tenant-filterable. An
  audit log readable by everyone is an information-disclosure surface.
- **`NoOpLogger` is a deliberate, visible choice.** A deployment running with
  audit disabled should know it.

## What this feature deliberately does not do

- **It does not decide anything.** Authorization is go-qrdb's RBAC; audit
  records the outcome.
- **It does not define the permission vocabulary** — that is `pkg/auth`,
  mirroring go-qrdb's model.
- **It does not ship a retention or archival policy.** Retention is a
  deployment decision.
- **It does not replace go-qrdb's own audit** of identity and RBAC operations.
