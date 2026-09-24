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
`EventCAKeyRotated`).

Issue #766 wired the remaining `SeveritySecurity` events #688 deferred, each
gating the state change it describes — the audit record is written before
the CA persists a certificate/CRL, before the ACME challenge is allowed to
transition to valid, or before the FIDO2/PIN state reaches storage, so a
write failure refuses the operation rather than let a completed action go
unaudited (`pkg/ca/audit.go`'s `CA.emitAudit`; the attestation gate in
`pkg/acme/server/handlers/challenge.go`'s `ChallengeHandler`;
`establishPINLocked` and `storeCredentialWithPolicy` in
`xkey/pkg/authenticator`):

- `pkg/ca` — `CA_INITIALIZED` (`CA.createRootCertificate`,
  `createIntermediateCertificates`, and `initializeAsIntermediate` for
  `NewIntermediateCA`), `CA_CRL_GENERATED` (`generateAndPersistCRL`),
  `CA_CROSS_SIGN` (`ImportXSignedCertificate`). `pkg/ca` cannot import
  `pkg/acme/audit` (ACME depends on `pkg/ca`, not the reverse — `pkg/ca` is
  also embedded by non-ACME callers such as the `xkmsd init` ceremony), so
  these emit through the generic `pkg/audit.Logger`/`Event` (the same
  contract `pkg/seal` and `pkg/api/grpc` already use) with action strings
  `ca_init`/`ca_crl_generate`/`ca_cross_sign`, not through
  `pkg/acme/audit`'s `EventType` enum. A `*ca.Params`/`*ca.MultiIdentityParams`
  caller that wants CA lifecycle events sets `AuditLogger`; `pkg/server`
  wires the server's own audit logger in, and the `xkmsd init` ceremony's
  one-shot, fully in-memory bootstrap CA (`cmd/xkmsd/init_ceremony.go`
  `newCeremonyCA`) deliberately leaves it nil — the ceremony runs before the
  server's audit pipeline exists and nothing that CA does survives the
  process.
- ACME challenge verification — `TPM_ATTESTATION` (a successful `enroll-01`
  challenge) and `ENDORSEMENT_VERIFIED` (a successful `endorse-01`
  challenge), gated in `ChallengeHandler` itself rather than in the
  `sdk/go/acme.ACMEAttestationVerifiers` challenge-verifier closures: the
  closures have no request-scoped identity/correlation context, and
  `ChallengeHandler` already holds the account, challenge and `s.auditLog`
  the sibling `CHALLENGE_FAILED` gate uses. `EventDeviceAttestation` stays
  unemitted: the `device-attest-01` ACME challenge type it would describe
  (distinct from the TCG `enroll-01`/`endorse-01` pair) has no verifier
  registered in any `ChallengeMap` built anywhere in this codebase
  (`cmd/xkmsd/acme.go`'s `buildChallengeMap`, the only production builder,
  wires `http-01`, `dns-01`, and `sdk/go/acme.ACMEAttestationVerifiers`'s
  `enroll-01`/`endorse-01` — nothing registers `device-attest-01`) — there is
  no operation to audit yet.
- `xkey/pkg/authenticator` — `OpFIDO2CredentialCreated`
  (`storeCredentialWithPolicy`, the single persist path both `MakeCredential`
  call sites share) and `OpPINSeeded` (`establishPINLocked`, the single path
  both the CTAP `setPIN` wire ceremony and the in-process `SetInitialPIN`
  share). The `Authenticator` takes its audit logger via `SetAuditLogger`
  (nil disables it, like `SetPINVerifier`); `xkey/pkg/gui/app.go`'s
  `PostBarrierUnseal` wires it alongside every other service's
  `SetAuditLogger(auditStore)` call. Other, narrower production callers that
  construct their own `*Authenticator` directly (`cmd/xkey/cmd/fido2.go` and
  siblings, `pkg/virtualdevice`) do not wire an audit logger and so audit
  nothing for those processes' credentials — filed as a gap, not fixed here.

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
- **#766's newly wired events**, each with a success test (fields), an
  audit-write-failure test (the operation fails and its state is asserted
  absent from the store), and an operation-failure test (the audit gate is
  never reached when the operation is refused before it):
  `pkg/ca/audit_test.go` (`CA_INITIALIZED`/`CA_CRL_GENERATED`/`CA_CROSS_SIGN`,
  asserting on `certStore`/`revocationStore`/`objectStore` directly);
  `pkg/acme/server/handlers/challenge_attestation_audit_test.go`
  (`TPM_ATTESTATION`/`ENDORSEMENT_VERIFIED`, through the real
  `ChallengeHandler`, plus `TestChallengeHandler_HTTP01_NoAttestationEvent`
  pinning the gate's scope to the two TCG challenge types);
  `pkg/api/rest/handlers_auth_audit_test.go` (`auth.login.piv` allow and deny
  outcomes, `auth.logout`); `xkey/pkg/authenticator/cmd_clientpin_audit_test.go`
  (`OpPINSeeded`) and `cmd_makecredential_audit_test.go`
  (`OpFIDO2CredentialCreated`).

`handlers_transport_audit_test.go` and its gRPC counterpart are the ones that
matter most: they assert that operations reaching the service through a
transport are audited, which is what catches a new route added without an audit
call.

## Observability

The audit log **is** the observability surface for this feature; it does not get
its own. The thing worth monitoring is audit-write failures — a logger that
starts erroring is losing evidence, and that is an incident whether or not the
operations themselves still work.
