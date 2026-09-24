- **Audit sink write failures now fail security operations instead of being
  silently swallowed.** Four confirmed sinks discarded the write error from
  the audit backend (`xkey/pkg/audit/store.go`'s and `dao_store.go`'s
  `Log`, `pkg/api/grpc/service.go`'s `authorize`, `pkg/seal/audit.go`'s
  `emitAudit`), and the ACME server's `recordAudit` helper logged a write
  failure without ever failing the request. Every audit event/operation
  constant is now classified `SeveritySecurity` or `SeverityInformational`
  (`pkg/audit`, `xkey/pkg/audit`, `pkg/acme/audit`, each in a
  `severity.go`): a failed write for a security event — PIN, seal/unseal,
  key create/delete/use, CA issuance and revocation, authentication and
  authorization, and their desktop-app equivalents (TPM seal/unseal/reset,
  password store, FIDO2/OATH credentials) — now returns a typed
  `*ErrAuditWriteFailed` that the caller propagates, failing the request
  rather than reporting success for an action that could not be proven
  audited; a failed write for an informational event (ACME protocol
  progress, connection/service lifecycle) is logged and counted in the new
  `xkms_audit_write_failures_total` Prometheus metric (`pkg/metrics`) and
  does not fail the request. Every previously-declared-but-unemitted audit
  event this policy applies to is now emitted at its real call site —
  including new ACME server emissions for invalid JWS signatures, invalid
  or replayed nonces, rate-limit exceeded, challenge validation failure,
  and account deactivation, and new xkey emissions for the password store
  (create/read/update/delete/unlock/lock), autofill request/denial, and TPM
  seal-failure/unseal-failure/reset — or removed with an explanation when no
  corresponding operation exists anywhere in the codebase
  (`EventCAKeyRotated`; xkey's `OpOATHCredentialAccessed`,
  `OpOATHCredentialUpdated`, `OpOATHCodeValidated`, `OpOATHCodeInvalid`,
  `OpTouchEventReceived`). See `docs/audit-log/engineering.md` for the full
  policy and the small number of declared events still pending an
  architecture decision before they can be wired (CA lifecycle audit hooks,
  the shared ACME challenge-verifier signature, and `pkg/authenticator`'s
  core CTAP2 path). Fixes go-xkms#688.
