- **xkey's agent server rejects revoked and removed agents at connect time,
  and removing an agent now revokes its certificate.** An audit found the
  master-side agent server (`xkey/pkg/agent/server.go`) accepted any client
  certificate that chained to the configured CA, with no check against the
  enrollment store or the CA's revocation state — a removed agent's
  certificate kept working indefinitely, because `RemoveAgent`
  (`xkey/pkg/gui/services/agent_service.go`) only deleted the store record and
  never called `CAService.RevokeCertificate`. Both are fixed. `Server`'s mTLS
  `tls.Config.VerifyPeerCertificate` now runs
  `EnrollmentService.VerifyAgentCertificate` on every connection: the leaf's
  public-key fingerprint must match an enrolled, still-present agent in the
  store, and its serial number must not be revoked (checked directly through
  the CA's existing `IsRevoked` RPC — no new CRL parser). Either check failing,
  or the revocation check itself failing, rejects the connection; enrollment
  now records each issued certificate's serial number
  (`AgentInfo.CertificateSerial`) so it can be revoked later.
  `EnrollmentService.RemoveAgent` revokes the certificate through the CA
  first and only then deletes the record; a revocation failure returns the
  error and leaves the record in place. The GUI's `AgentService.RemoveAgent`
  now calls it instead of deleting directly, and the CLI gained `xkey agent
  code`, `xkey agent pending`, `xkey agent approve <id>`, `xkey agent reject
  <id>`, and `xkey agent remove <id>` over the same shared service layer,
  closing a GUI/CLI parity gap. One-time codes and pending enrollment
  requests, previously held only in the enrollment service's memory, are now
  persisted through `EnrollmentStore` (`FileStore`'s `agents/`, `codes/`,
  `pending/` subdirectories; `DAOStore`'s matching DAO namespaces), so a code
  or request from one process is honored by another sharing the same store
  - the CLI and a running `agent start` daemon in particular. Codes are
  stored by their SHA-256 hash, never in plaintext; `EnrollmentStore.ConsumeCode`
  is single-use and atomic even across processes (`FileStore` relies on
  `os.Remove`'s atomicity; `DAOStore`'s is Get-then-Delete, a documented gap
  since go-qrdb's `GenericDAO` has no compare-and-delete primitive yet).
  Pending requests are deleted on approval or rejection, so `ErrEnrollmentRejected`
  - unreachable once rejection deletes the record - is removed. Files:
  `xkey/pkg/agent/{enrollment,entity,errors,server,store,dao_store}.go`,
  `xkey/cmd/xkey/cmd/{agent_ca,agent_verbs}.go`,
  `xkey/pkg/gui/services/agent_service.go`.
