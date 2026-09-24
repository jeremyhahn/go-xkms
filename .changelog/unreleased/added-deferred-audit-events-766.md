- **The six audit events #688/#765 deferred are now emitted, gating the
  operation they describe rather than following it.** `pkg/ca` gains an
  optional `AuditLogger` (`Params.AuditLogger` / `MultiIdentityParams.AuditLogger`,
  forwarded through `New`, `NewParentCA`, `NewIntermediateCA`,
  `NewFromMultiIdentityConfig`, `NewHierarchicalCA`) and emits `ca_init`
  before `CA.createRootCertificate`/`createIntermediateCertificates`/
  `initializeAsIntermediate` store a certificate, `ca_crl_generate` before
  `generateAndPersistCRL` persists a CRL artifact, and `ca_cross_sign` before
  `ImportXSignedCertificate` persists a cross-signed certificate — all three
  through the generic `pkg/audit.Logger`/`Event` contract (`pkg/ca` cannot
  depend on `pkg/acme/audit`'s ACME-specific vocabulary without inverting the
  package layering), wired in from `pkg/server`'s server-wide audit logger.
  `pkg/acme/server/handlers.ChallengeHandler` now records `TPM_ATTESTATION`
  on a successful `enroll-01` challenge and `ENDORSEMENT_VERIFIED` on a
  successful `endorse-01` challenge before allowing the challenge to
  transition to valid. `xkey/pkg/authenticator.Authenticator` gains
  `SetAuditLogger` and records `OpPINSeeded` before `establishPINLocked`
  persists new PIN state and `OpFIDO2CredentialCreated` before
  `storeCredentialWithPolicy` persists a new credential, wired in from
  `xkey/pkg/gui/app.go`'s `PostBarrierUnseal` alongside every other service's
  audit logger. `pkg/api/rest/handlers_auth.go`'s `auditAuthEvent` (PIV
  login allow/deny and logout) now applies the same write-failure policy
  instead of logging a failed write and continuing: a failed write returns
  `*audit.ErrAuditWriteFailed` and the caller refuses the request (a login
  whose grant could not be audited returns no token; a logout whose event
  could not be audited returns 500 even though the token was already
  revoked). `EventDeviceAttestation` stays unemitted: no `ChallengeMap`
  built anywhere in this codebase registers a verifier for the
  `device-attest-01` challenge type it would describe, so there is no
  operation to audit yet. Files: `pkg/ca/{ca,constructors,crl_persistence,
  cross_signing,audit}.go`, `pkg/server/server.go`,
  `pkg/acme/server/handlers/challenge.go`, `pkg/api/rest/handlers_auth.go`,
  `xkey/pkg/authenticator/{authenticator,cmd_clientpin,cmd_makecredential}.go`,
  `xkey/pkg/gui/app.go`. Docs: `docs/audit-log/engineering.md`. Verified by
  `pkg/ca/audit_test.go`, `pkg/acme/server/handlers/
  challenge_attestation_audit_test.go`, `pkg/api/rest/handlers_auth_audit_test.go`,
  `xkey/pkg/authenticator/{cmd_clientpin_audit_test.go,
  cmd_makecredential_audit_test.go}` — a success test (event fields), an
  audit-write-failure test (the operation fails and its state is asserted
  absent from the store), and an operation-failure test (the audit gate is
  never reached when the operation is refused before it) per event.
  go-xkms#766, stacked on go-xkms#765/go-xkms#688.
