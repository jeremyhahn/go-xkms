# Audit Log — Engineering Contract

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-09-23

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
queryable). Errors: `errors.go`. Write-failure policy: `severity.go`.

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

## Write-failure policy (issue #688)

`Log`'s returned error is never discarded. Every call site runs it through the
package's `HandleWriteFailure(slogger, classifier, writeErr)` (three
independent, structurally identical implementations — `pkg/audit/severity.go`,
`xkey/pkg/audit/severity.go`, `pkg/acme/audit/severity.go` — one per module
that owns its own event/operation vocabulary):

- **`SeveritySecurity`** — PIN, seal/unseal, key create/delete/use, CA issuance
  and revocation, authentication and authorization, and (see below) TPM,
  FIDO2/OATH credential, and password-store operations. A failed write returns
  a typed `*ErrAuditWriteFailed` (`Unwrap()`s to the underlying cause); the
  caller **must** propagate it and fail the request rather than complete a
  security-relevant action that could not be audited. The action that
  triggered the event may already be committed (e.g. a key already created,
  a certificate already revoked with the CA) — write-failure policy governs
  whether the caller reports success, not whether the side effect is undone;
  there is no rollback path.
- **`SeverityInformational`** — protocol/lifecycle progress that is not
  itself a security decision (e.g. ACME order/challenge progress, connection
  established/closed, service start/stop). A failed write is logged via the
  caller's `*slog.Logger` and counted in `metrics.AuditWriteFailuresTotal`
  (`pkg/metrics`, label `operation`; xkey and ACME servers share this same
  Prometheus counter rather than each registering their own, since they run
  as separate processes and never link both registrations into one binary),
  and `HandleWriteFailure` returns `nil` so the caller proceeds.

Classification is a fixed set per package (`informationalActions` /
`informationalOps` / `informationalEvents`); **an operation not in the set
defaults to `SeveritySecurity`** — fail-closed for anything nobody has
explicitly reviewed. Extending the vocabulary means adding to the
informational set explicitly, not the reverse.

`NoOpLogger` always returns nil — by construction it cannot fail, and the
deployment has opted out; the policy above never triggers for it.

### Declared-event coverage

Every event/operation constant a package declares is emitted from at least
one real call site, or is removed with a comment explaining why the
operation does not exist in this codebase (e.g. `xkey`'s
`OpOATHCredentialUpdated`/`OpOATHCredentialAccessed`/`OpOATHCodeValidated`/
`OpOATHCodeInvalid`/`OpTouchEventReceived`, `pkg/acme/audit`'s
`EventCAKeyRotated`). A small number of declared, still-unemitted events
remain because wiring them touches an area with no audit hook today and an
architecture decision the owner has not made yet — `pkg/ca` (CA
initialization, CRL generation, cross-signing: `EventCAInitialized`,
`EventCACRLGenerated`, `EventCACrossSign`), the shared ACME challenge
verifier signature (`EventTPMAttestation`, `EventDeviceAttestation`,
`EventEndorsementVerified`), and `pkg/authenticator`'s core CTAP2 path
(`OpFIDO2CredentialCreated`, `OpPINSeeded`). These are tracked, not silently
dropped — see the issue #688 delivery report for the specific reasoning per
event.

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
  chain integrity), `qrdb_test.go`, `severity_test.go` (write-failure policy:
  a failing sink fails a `SeveritySecurity` write and does not fail a
  `SeverityInformational` one, which instead increments the metric).
- **Transport** — `pkg/api/rest/handlers_audit_test.go`,
  `handlers_transport_audit_test.go`; `pkg/api/grpc/service_transport_audit_test.go`,
  `service_authz_test.go` (`TestAuthz_AuthorizeAuditWriteFailureFailsRequest`).
- **Subsystem audit** — `pkg/seal/audit_test.go`, `platform_sealer_test.go`
  (`TestPlatformSealer_{Seal,Unseal}_AuditWriteFailureFailsOperation`);
  `pkg/acme/server/handlers/audit_e2e_test.go` (one test per newly emitted
  ACME event: invalid nonce, invalid signature, challenge failure, account
  deactivation, plus the updated
  `TestAuditTrail_WriteFailureFailsSecurityOperation`), `audit_tcg_test.go`;
  `pkg/acme/server/rate_limiter_audit_test.go`
  (`TestRateLimiter_RecordsEventRateLimitExceeded`).
- **xkey** — `xkey/pkg/audit/severity_test.go` (same write-failure policy
  shape as the server); per-service tests alongside each emitter, e.g.
  `xkey/pkg/gui/services/staticpw_service_audit_test.go`,
  `autofill_service_test.go`, `tpm_service_reset_audit_test.go`.

`handlers_transport_audit_test.go` and its gRPC counterpart are the ones that
matter most: they assert that operations reaching the service through a
transport are audited, which is what catches a new route added without an audit
call.

## Observability

The audit log **is** the observability surface for this feature; it does not get
its own. The thing worth monitoring is audit-write failures — a logger that
starts erroring is losing evidence, and that is an incident whether or not the
operations themselves still work.
