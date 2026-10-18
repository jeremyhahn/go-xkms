# Network Agent — Engineering Contract

> **Status: NORMATIVE** · Feature: `agent` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

## Exported surface

Package `xkey/pkg/agent`:

- `Server` — the master-side mTLS/gRPC listener. `NewServer(cfg, enrollment, logger)`,
  `Start()`, `Stop()`, `ConnectedAgents()`, `IsRunning()`, `Addr()`.
- `Client` / `SSHProxy` — agent-side connection and the local SSH agent
  socket it backs. Unchanged by this feature.
- `EnrollmentService` — the business-logic layer for enrollment,
  revocation-gated connection verification, and removal.
  `NewEnrollmentService(cfg, ca, store, logger)`.
- `CAService` — the certificate authority contract `EnrollmentService`
  drives. Implemented in this codebase by `XKMSdCA` (`xkmsd_ca.go`), which
  reaches the real xkmsd CA over the SDK transport; `xkey` holds no CA key
  of its own. The CLI connects a client for it per command; the GUI's
  `AgentService` binds one to the connected server client on
  `EventServerConnected` and drops it on disconnect.
- `EnrollmentStore` — persistence for enrolled agent records, one-time
  enrollment codes, and pending admin-approval requests.
  `FileStore` (JSON files under `agents/`, `codes/`, `pending/`
  subdirectories, `0600`), `MemoryStore` (tests), `DAOStore`
  (go-qrdb-backed, matching DAO namespaces).
- `AgentInfo` — the enrolled-agent domain type.
- `Config` / `ClientConfig` — server- and client-side configuration.

## `CAService` (added: `IsRevoked`)

```go
type CAService interface {
    SignCSR(csrPEM []byte) (certPEM []byte, err error)
    GetCACertificate() ([]byte, error)
    RevokeCertificate(serialNumber string) error

    // IsRevoked reports whether the certificate identified by its serial
    // number has been revoked. Callers must fail closed on error: an
    // indeterminate revocation status is never treated as "not revoked".
    IsRevoked(serialNumber string) (bool, error)
}
```

`serialNumber` is `big.Int.Text(16)` — hex, no leading zero padding, no
`0x` prefix — matching what xkmsd's CA API returns from `SignCSR` and
accepts on `RevokeCertificate` / `IsRevoked`. Every implementation of
`CAService` in this codebase or its tests must implement `IsRevoked`; there
is no default or degraded mode.

## `AgentInfo` (added: `CertificateSerial`)

```go
type AgentInfo struct {
    ID                     string    // SHA-256 fingerprint of the public key
    Name                   string
    Address                string
    CertificateFingerprint string    // same value as ID, kept for the JSON shape
    CertificateSerial      string    // NEW: serial of the issued certificate
    EnrolledAt             time.Time
    LastSeen               time.Time
    Status                 string
}
```

`CertificateSerial` is populated by `EnrollWithCode` and `ApproveEnrollment`
immediately after `CAService.SignCSR` returns, by parsing the leading
PEM-encoded certificate in the response (`certificateSerialHex`). A record
with an empty `CertificateSerial` cannot be revoked and `RemoveAgent`
refuses to delete it (see Errors below) rather than leaving an
un-revocable certificate unaccounted for.

## `EnrollmentStore` (added: code and pending-request persistence)

```go
type EnrollmentStore interface {
    SaveAgent(agent *AgentInfo) error
    GetAgent(id string) (*AgentInfo, error)
    ListAgents() ([]*AgentInfo, error)
    DeleteAgent(id string) error

    // SaveCode persists a one-time code by the hex-encoded SHA-256 hash
    // of the code value. The plaintext code is never passed to the store.
    SaveCode(hash string, expiresAt time.Time) error

    // ConsumeCode atomically validates and single-use-consumes the code
    // identified by hash. At most one caller - including a caller in a
    // separate process sharing the same backing storage - observes
    // success for a given hash.
    ConsumeCode(hash string) error

    // CleanExpiredCodes removes every expired, unconsumed code and
    // reports how many were removed.
    CleanExpiredCodes() (int, error)

    SavePending(p *PendingEnrollment) error
    GetPending(id string) (*PendingEnrollment, error)
    ListPending() ([]*PendingEnrollment, error)
    DeletePending(id string) error
}
```

Every existing and new `EnrollmentStore` implementation (`FileStore`,
`MemoryStore`, `DAOStore`, and any test double) must implement all eleven
methods; there is no default or embeddable base. `EnrollmentService` itself
now holds no mutex and no in-memory state - `codes`, `pending`, and its
`sync.RWMutex` fields are gone - since every mutable fact it needs lives in
the store. Any number of `EnrollmentService` instances, in any number of
processes, backed by the same store observe and mutate the same state.

`FileStore.ConsumeCode`'s cross-process guarantee rests on `os.Remove`'s
atomicity, not on its own mutex (which only serializes calls within one
`FileStore` Go value): it reads the code file, then removes it; exactly one
caller's `os.Remove` for a given path succeeds, and every other caller -
racing at the same instant or arriving later - observes the file already
gone and reports `ErrEnrollmentCodeInvalid`. `MemoryStore.ConsumeCode` gets
the same guarantee from its mutex, sufficient since a `MemoryStore` is
never process-shared. `DAOStore.ConsumeCode` is Get-then-Delete, not a true
compare-and-delete - go-qrdb's `GenericDAO` has no atomic primitive for it
yet - documented as a gap in `DAOStore`'s doc comment, since it is the
clustered/embedded backend, not the default CLI/GUI path (`FileStore`).

`PendingEnrollment.Reason` is gone: `RejectEnrollment` deletes the pending
record instead of marking it `"rejected"`, so there is no resting record
left to carry a reason. The reason parameter is logged and emitted as an
event at rejection time only.

## `EnrollmentService` (added/changed methods)

```go
// VerifyAgentCertificate is the connection-time gate. Two independent
// checks both have to pass: the certificate's public key fingerprint
// matches an enrolled, still-present agent, and the certificate's serial
// number is not on the CA's revocation list. Fails closed on any error,
// including a revocation-check failure.
func (s *EnrollmentService) VerifyAgentCertificate(cert *x509.Certificate) error

// RemoveAgent revokes the agent's certificate through the CA and only
// then deletes its enrollment record. If revocation fails, the record is
// left in place and the error is returned.
func (s *EnrollmentService) RemoveAgent(id string) error

// CleanExpiredCodes now delegates to the store and can fail.
func (s *EnrollmentService) CleanExpiredCodes() (int, error)
```

`Server.buildTLSConfig` wires `VerifyAgentCertificate` into
`tls.Config.VerifyPeerCertificate` whenever `tls_ca_file` is configured
(mTLS mode). Plaintext/no-mTLS mode — development only — has no client
certificate to verify and does not install the hook.

`RejectEnrollment(requestID, reason)` now deletes the pending record
(previously it only mutated `Status` in an in-memory map that nothing ever
purged). Approving or rejecting a request that was already rejected
returns `ErrRequestNotFound`, not a distinct "already rejected" sentinel:
once deleted, the two cases are indistinguishable, which is why
`ErrEnrollmentRejected` is removed rather than kept unreachable.

## Errors

New sentinels in `xkey/pkg/agent/errors.go`, all wrapped in `*AgentError`
(`Operation`, `Err`, optional `Cause`) per this package's existing
convention:

| Sentinel | Meaning |
|---|---|
| `ErrCertificateSerialMissing` | `RemoveAgent` refuses to proceed: the record has no serial to revoke. |
| `ErrRevocationCheckFailed` | `VerifyAgentCertificate` could not determine revocation status (CA unreachable, etc.) — treated as a rejection. |
| `ErrAgentRevocationFailed` | The CA refused or failed to revoke a certificate during `RemoveAgent`. |
| `ErrAgentNotFound` | (pre-existing) also returned by `VerifyAgentCertificate` and `RemoveAgent` when the store has no matching record. |
| `ErrCertificateRevoked` | (pre-existing, now actually reachable) `VerifyAgentCertificate` when the CA reports the certificate revoked. |
| `ErrCertificateInvalid` | (pre-existing) malformed certificate, or an empty verified chain reaching `Server.verifyPeerCertificate`. |

`xkey/pkg/agent/xkmsd_ca.go` adds `ErrCARevocationCheckFailed` for the
`XKMSdCA.IsRevoked` transport call, wrapped in an `AgentError` like
`ErrCARevokeFailed`.

`xkey/pkg/gui/services/agent_service.go` adds no new sentinels:
`RemoveAgent` maps `agent.ErrAgentNotFound` to the existing
`ErrAgentNotFound` and any other failure (including a revocation failure)
to the existing `ErrAgentEnrollmentFailed`.

`ErrEnrollmentRejected` is removed: `RejectEnrollment` now deletes the
pending record instead of marking it `"rejected"`, so a subsequent
`ApproveEnrollment` call on the same request ID finds no record at all and
returns `ErrRequestNotFound` - the sentinel that used to distinguish
"rejected" from "never existed" no longer has a state to describe.

## Service layer: `services.AgentService`

`RemoveAgent(agentID string) error` now calls
`EnrollmentService.RemoveAgent` instead of deleting the store record
directly. It still requires both `SetEnrollmentService` and
`SetEnrollmentStore` to have been called (`ErrAgentServiceNotReady` /
`ErrAgentNilStore` otherwise), matching every other method on this type.

Two additions support certificate delivery and configurable code validity,
both used by the new CLI verbs and available to the GUI:

```go
// GenerateEnrollmentCodeWithValidity generates a one-time code valid for
// the given duration; GenerateEnrollmentCode delegates to it with 0
// (the enrollment service's configured default).
func (s *AgentService) GenerateEnrollmentCodeWithValidity(validity time.Duration) (*EnrollmentCodeInfo, error)

// EnrollmentApprovalResult carries the certificate material an approval
// issued, for a caller (the CLI) that needs to deliver it to the
// enrolling agent out of band.
type EnrollmentApprovalResult struct {
    RequestID        string
    CertificatePEM   []byte
    CACertificatePEM []byte
}

// ApproveEnrollmentWithCertificate approves and returns the result;
// ApproveEnrollment delegates to it and discards the certificate material,
// preserving its existing signature for the GUI binding.
func (s *AgentService) ApproveEnrollmentWithCertificate(requestID string) (*EnrollmentApprovalResult, error)
```

## Configuration

`Config` and `ClientConfig` are unchanged by this feature. Their field
tables live in [user.md](user.md#server-configuration).

## Connection tracking

`Server.ConnectedAgents()` (`xkey/pkg/agent/server.go:200`) returns copies
of the tracked entries, so later activity never changes a returned value.

Invariants:

- An mTLS peer with a verified certificate is tracked under its agent ID
  (`peerAgentID`, `server.go:248`), the public-key fingerprint that also
  keys the enrollment store. Any other peer is tracked under its `ip:port`.
- Each gRPC connection holds its entry through a `connTag` that the
  `connTracker` stats handler (`server.go:343`) attaches in `TagConn` and
  releases on `stats.ConnEnd`. The entry is deleted when its last
  connection closes (`connectionClosed`, `server.go:322`). A connection
  whose entry was evicted or replaced never deletes the newer entry.
- The table holds at most `maxConnectedAgents` (1024) entries. When full,
  entries idle for more than `agentIdleTimeout` (10 minutes) are evicted
  (`evictIdleLocked`, `server.go:311`); if the table is still full the
  activity goes untracked.

Neither limit is configurable.

## Tests

- `xkey/pkg/agent/enrollment_test.go` — `VerifyAgentCertificate` (enrolled
  accepted, revoked rejected, revocation-check-failure rejected, removed
  rejected), `RemoveAgent` (not found, revokes-then-deletes, revocation
  failure keeps the record, missing-serial refusal), and
  `CertificateSerial` capture on enroll.
- `xkey/pkg/agent/server_test.go` — `buildTLSConfig` installs
  `VerifyPeerCertificate` in mTLS mode; `Server.verifyPeerCertificate`
  against enrolled/revoked/unenrolled certificates and an empty chain.
- `xkey/pkg/agent/server_tracking_test.go` — entries removed on
  disconnect; 100 reconnects leave nothing behind; two connections from one
  mTLS agent share one ID-keyed entry that survives until the last closes;
  an unverified certificate is not used as an identity; the 1024-entry cap;
  idle eviction when full; a stale connection end never removes a newer
  entry.
- `xkey/pkg/agent/xkmsd_ca_test.go` — `XKMSdCA` sign, CA certificate,
  revoke and `IsRevoked` (not revoked, revoked, fails closed) against a fake
  transport client.
- `xkey/cmd/xkey/cmd/agent_ca_test.go` — the CLI's `newAgentCA` against a
  fake xkmsd endpoint.
- `xkey/pkg/gui/services/agent_service_test.go` — `RemoveAgent` revokes the
  certificate before deleting, and a revocation failure keeps the record.
- `xkey/cmd/xkey/cmd/agent_verbs_test.go` — one success and one error case
  per CLI verb (`code`, `pending`, `approve`, `reject`, `remove`), `--json`
  output shape, and cross-process persistence: a code generated (or a
  request submitted) through one `EnrollmentService`/`FileStore` instance
  is honored by the command under test's own, separately-constructed
  instance sharing the same on-disk store.
- `xkey/pkg/agent/store_test.go`, `dao_store_test.go` — `SaveCode` /
  `ConsumeCode` (valid, invalid, expired, single-use) / `CleanExpiredCodes`
  and `SavePending` / `GetPending` / `ListPending` / `DeletePending` for
  `FileStore`, `MemoryStore`, and `DAOStore`.
- `xkey/pkg/agent/enrollment_test.go` — cross-instance tests built on two
  independent `EnrollmentService` values sharing one `FileStore` directory:
  a code generated by one is honored, and single-use, and expiry-checked,
  by the other; a concurrency test proves exactly one winner among many
  goroutines racing to consume the same code; admin-approval submit,
  approve, and reject each work across instances.

Every test that exercises `EnrollWithCode` or `ApproveEnrollment` now needs
a `CAService.SignCSR` stub that returns a real, parseable certificate
embedding the CSR's own public key (`certificateSerialHex` parses it); a
placeholder string like `"fake-cert"` no longer round-trips.

## See also

- [Architecture](architecture.md) — design and the connection-time model
- [CLI](cli.md) — `xkey agent` verbs
- [API](api.md) — service-layer surface reused by GUI and CLI
