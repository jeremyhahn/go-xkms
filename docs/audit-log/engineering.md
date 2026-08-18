# Audit Log — Engineering Contract

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-08-19

## Exported surface — `pkg/audit`

```go
type Logger interface {
	Log(ctx context.Context, event *Event) error
	Close() error
}

type Event struct {
	Timestamp  time.Time         `json:"timestamp"`
	Subject    string            `json:"subject"`
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	ResourceID string            `json:"resource_id"`
	Outcome    string            `json:"outcome"`
	Details    map[string]string `json:"details,omitempty"`
}

const (
	OutcomeAllow = "allow"
	OutcomeDeny  = "deny"
)

type NoOpLogger struct{}
func (n *NoOpLogger) Log(ctx context.Context, event *Event) error { return nil }
func (n *NoOpLogger) Close() error                                { return nil }
```

Backends: `chained_file.go` (tamper-evident local), `qrdb.go` (durable,
queryable). Errors: `errors.go`.

Query contract — `sdk/go/transport`:

```go
type AuditService interface {
	QueryAudit(ctx context.Context, filter *AuditFilter) (*AuditPage, error)
}
```

## Invariants

- **`Outcome` is `OutcomeAllow` or `OutcomeDeny`.** Nothing else. A third value
  makes every existing query wrong.
- **Denials are logged, always.** A refused operation produces an audit record;
  it does not fail silently into an error return.
- **`Details` never carries secrets.** Key material, PINs, passphrases, share
  bytes, tokens, and certificate private keys are excluded. Details land in
  durable, queryable, exportable storage — treat every value as published.
- **`Close()` flushes.** A process that exits without closing the logger can
  lose its last records, which are usually the interesting ones.
- **The chained file is append-only and chained.** Each record links to its
  predecessor; rewriting history breaks the chain and is detectable. Do not add
  an update or delete path.
- **`Timestamp` is the event time**, set at the operation, not at write time.
- **Concurrency.** Loggers are safe for concurrent use; both backends serialise
  their writes internally.

## Error semantics

`pkg/audit/errors.go`. A `Log` error means the record was **not** durably
written. The calling site decides what that implies for the operation, and that
decision is a security policy, not a coding detail: in a regulated deployment,
an operation that cannot be audited generally should not proceed.

`NoOpLogger` always returns nil — by construction it cannot fail, and the
deployment has opted out.

## Configuration

Choosing a backend is composition, in-process:

- **`NoOpLogger`** — audit disabled. Visible, deliberate.
- **chained file** — a path on local disk; tamper-evident, single host.
- **qrdb** — through `go-qrdb/sdk/go`; durable, queryable, cluster-wide.

The CLI query filters (`cmd/xkmsctl/audit.go`) mirror `AuditFilter`: `--actor`,
`--resource`, `--action`, `--outcome`, `--tenant`, `--from`, `--to` (RFC 3339),
`--limit` (0 = server default), `--cursor`, `--all`.

## Persistence

- **Chained file** — append-only, each record chained to the previous record's
  hash.
- **qrdb** — durable and indexed for the filter dimensions above.

Retention and archival are deployment decisions; this package ships neither a
policy nor a pruner. That is intentional — a KMS that silently discarded audit
records after N days would be worse than one that grows.

## Test strategy

- **Unit** — `pkg/audit/logger_test.go`, `chained_file_test.go` (including
  chain integrity), `qrdb_test.go`.
- **Transport** — `pkg/api/rest/handlers_audit_test.go`,
  `handlers_transport_audit_test.go`; `pkg/api/grpc/service_transport_audit_test.go`.
- **Subsystem audit** — `pkg/seal/audit_test.go`;
  `pkg/acme/server/handlers/audit_e2e_test.go`, `audit_tcg_test.go`.

`handlers_transport_audit_test.go` and its gRPC counterpart are the ones that
matter most: they assert that operations reaching the service through a
transport are audited, which is what catches a new route added without an audit
call.

## Observability

The audit log **is** the observability surface for this feature; it does not get
its own. The thing worth monitoring is audit-write failures — a logger that
starts erroring is losing evidence, and that is an incident whether or not the
operations themselves still work.
