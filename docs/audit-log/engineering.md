# Audit Log — Engineering Contract

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-10-07 (S2c)

## Exported surface — `pkg/audit`

```go
type Event struct {
	Timestamp  time.Time
	Subject    string
	Action     string
	Resource   string
	ResourceID string
	Outcome    string
	Details    map[string]string
}

const (
	OutcomeAllow = "allow"
	OutcomeDeny  = "deny"
)

// Emit writes event to sink. A nil sink is "auditing off" and returns nil.
func Emit(ctx context.Context, sink qrdbsdk.NodeAuditLogger, event *Event) error

var ErrNilEvent = errors.New("nil audit event")
```

`pkg/audit` has no sink of its own. The sink is go-qrdb's
`qrdbsdk.NodeAuditLogger` (`Emit`/`Query`/`Close`), and `Emit` maps the product
`Event` onto go-qrdb's `NodeAuditEvent`: `Subject` becomes `Actor`;
`Details["remote_addr"]` becomes `ClientIP`; `Details["role"]` becomes `Role`;
`ResourceID` and the remaining `Details` become `Attributes`
(`resource_id` and the detail keys). Severity is go-qrdb's; go-xkms keeps no
severity levels of its own in this package. `pkg/audit/audittest` provides the
in-memory `Recorder` and `Failing` sinks for tests.

The audit read side is go-qrdb's (`AuditService.QueryAudit`, `audit:read`,
tenant-confined). xkms exposes no query verb on any transport.

## Invariants

- **`Outcome` is `OutcomeAllow` or `OutcomeDeny`.** Nothing else. A third value
  makes every existing query wrong.
- **Denials are logged, always.** A refused operation produces an audit record;
  it does not fail silently into an error return.
- **`Details` never carries secrets.** Key material, PINs, passphrases, share
  bytes, tokens, and certificate private keys are excluded. Details land in
  durable, queryable, exportable storage — treat every value as published.
- **The node closes its sink.** Components receiving a sink never close it;
  `pkg/server` closes only a fallback file logger it created itself.
- **The sink is append-only.** go-qrdb's logger owns chaining and retention;
  go-xkms adds no update or delete path.
- **`Timestamp` is the event time**, set at the operation, not at write time.

- **An emitted event's tenant is normalized, never left empty.**
  `audit.Emit` (`pkg/audit/emit.go`) resolves the tenant from the
  identity on the context, same as the query side, and folds it through
  `qrdbsdk.NormalizeTenantID` before it is stored: no identity, or an identity
  with an empty `TenantID`, becomes `system`. Every sink goes through `Emit`, so there is a single place the
  fold has to hold. Without it, an event emitted off a background job or any
  other identity-less path stored `""` — the query side's
  match-everything filter — and no confined query, a system-tenant auditor's
  included, ever saw it (#1134). Events stored before the fix keep their
  stored tenant; there is no rewrite of the existing chain.
- **Concurrency.** go-qrdb's loggers are safe for concurrent use.

## Write-failure policy (issues #688, S2c)

`Emit`'s returned error is never discarded, and every `pkg/audit` write is
fail-closed: a sink error comes back as `*qrdbsdk.AuditGateError`
(`Component` is the event action; `Unwrap()` reaches the cause). The caller
must propagate it and fail the request rather than complete a
security-relevant action that could not be audited. The action may already be
committed (a key created, a certificate revoked) — the policy governs whether
the caller reports success, not whether the side effect is undone.

The one deliberate exception is best-effort emission in `pkg/oidc/credential`,
which logs a warning and proceeds. There is no `NoOpLogger`: a nil sink means
auditing is off and `Emit` returns nil.

The informational/security severity split (`HandleWriteFailure`,
`ClassifyAction`, `metrics.AuditWriteFailuresTotal`) survives only in the two
modules that own a separate vocabulary and sink: `xkey/pkg/audit` and
`pkg/acme/audit`. Classification there is a fixed set; **an operation not in
the set defaults to security** — fail-closed for anything nobody reviewed.

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
  these emit through the generic `pkg/audit.Emit`/`Event` (the same
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
  attesting-verifier closures (`sdk/go/acme.ACMEAttestingVerifiers`): the
  closures have no request-scoped identity/correlation context, and
  `ChallengeHandler` already holds the account, challenge and `s.auditLog`
  the sibling `CHALLENGE_FAILED` gate uses. A successful `device-attest-01`
  challenge emits `DEVICE_ATTESTATION` the same way.
- `xkey/pkg/authenticator` — `OpFIDO2CredentialCreated`
  (`storeCredentialWithPolicy`, the single persist path both `MakeCredential`
  call sites share) and `OpPINSeeded` (`establishPINLocked`, the single path
  both the CTAP `setPIN` wire ceremony and the in-process `SetInitialPIN`
  share). The `Authenticator` takes its audit logger via `SetAuditLogger`
  (nil disables it, like `SetPINVerifier`); `xkey/pkg/gui/app.go`'s
  `PostBarrierUnseal` wires it alongside every other service's
  `SetAuditLogger(auditStore)` call.

The authenticator itself never constructs a logger; every production
entry point that can create a FIDO2 credential or seed a PIN wires one in
explicitly after constructing the `Authenticator` (#804):

- the xKey GUI (`xkey/pkg/gui/app.go`, `PostBarrierUnseal` →
  `initializeAuthenticator`) — the shared `audit.BackendStore`, barrier
  encrypted and used by every other GUI service (#803);
- the `xkey fido2` virtual USB device daemon
  (`xkey/cmd/xkey/cmd/fido2.go`, `newFIDO2Device`) — `audit.NewSlogLogger`,
  the same slog-backed logger the headless extension-serve daemon already
  used for `AutoFillService`; this daemon has no durable, queryable audit
  store of its own, so its security events land in the structured log stream
  it already writes;
- the headless browser-extension daemon
  (`xkey/cmd/xkey/cmd/extension_serve.go`, `initHeadlessAuthenticator` →
  `runExtensionServe`) — the same `audit.NewSlogLogger` instance already
  wired to `AutoFillService`, so both share one audit trail.

The offline token/attestation operator verbs
(`xkey/cmd/xkey/cmd/fido2_offline_device.go`'s `newOfflineAuthenticator`,
used by `fido2 init-token`, `fido2 change-so-pin`, and
`fido2 provision-attestation`) construct an authenticator only to drive
`InitializeToken`/`ChangeSOPIN`/attestation provisioning — none of which
reach `establishPINLocked` or `storeCredentialWithPolicy` — so they carry no
audit wiring for these two events; the Security Officer PIN lifecycle they
drive is a separate, already-covered surface (`OpSOPINChanged` etc. in
`pkg/gui/services/pin_service.go`).

## Configuration

The sink is go-qrdb's, chosen by composition:

- **Node sink** — when an embedded qrdb node exists, `pkg/server` uses the
  node's audit logger (`embeddednode.NewEmbeddedAuditSink`), so product events
  and go-qrdb's own events share one trail.
- **File fallback** — with no node, `pkg/server` opens
  `qrdbsdk.NewAuditFileLogger` at `<datastore.path>/audit-events.ndjson`
  (`audit-events.ndjson` in the working directory when no datastore path is
  set), and closes it at shutdown.
- **Off** — a nil sink; `Emit` returns nil.

## Persistence

Owned by go-qrdb: its logger persists, chains and indexes the records.

Retention and archival are deployment decisions; this package ships neither a
policy nor a pruner. That is intentional — a KMS that silently discarded audit
records after N days would be worse than one that grows.

## Test strategy

- **Unit** — `pkg/audit/emit_test.go`: a product event reaches go-qrdb's
  logger with its fields and actor, no identity folds onto the system tenant,
  and a sink failure surfaces as `*qrdbsdk.AuditGateError`.

- **Transport** — `pkg/api/rest/handlers_transport_audit_test.go`; `pkg/api/grpc/service_transport_audit_test.go`,
  `service_authz_test.go` (`TestAuthz_AuthorizeAuditWriteFailureFailsRequest`).
- **Subsystem audit** — `pkg/seal/audit_test.go`, `platform_sealer_test.go`
  (`TestPlatformSealer_{Seal,Unseal}_AuditWriteFailureFailsOperation`);
  `pkg/acme/server/handlers/audit_e2e_test.go` (one test per newly emitted
  ACME event: invalid nonce, invalid signature, challenge failure, account
  deactivation, plus the updated
  `TestAuditTrail_WriteFailureFailsSecurityOperation`), `audit_tcg_test.go`;
  `pkg/acme/server/rate_limiter_audit_test.go`
  (`TestRateLimiter_RecordsEventRateLimitExceeded`).
- **xkey** — `xkey/pkg/audit/severity_test.go` (its own severity policy); per-service tests alongside each emitter, e.g.
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
- **#804's non-GUI entry points** — one `*_audit_test.go` per production
  entry point that wires `SetAuditLogger`:
  `xkey/cmd/xkey/cmd/fido2_audit_test.go` (the `xkey fido2` daemon) and
  `extension_serve_audit_test.go` (the headless extension-serve daemon),
  proving both that the wired logger receives the record and that a failing
  logger refuses the operation, end to end from that entry point.

`handlers_transport_audit_test.go` and its gRPC counterpart are the ones that
matter most: they assert that operations reaching the service through a
transport are audited, which is what catches a new route added without an audit
call.

## Observability

The audit log **is** the observability surface for this feature; it does not get
its own. The thing worth monitoring is audit-write failures — a logger that
starts erroring is losing evidence, and that is an incident whether or not the
operations themselves still work.
