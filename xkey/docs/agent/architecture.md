# Network Agent — Architecture

> **Status: NORMATIVE** · Feature: `agent` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

## The problem

The xKey network agent lets a remote machine use the xKey services running on
a master machine — PKCS#11, FIDO2, PIV, CCID, crypto, SSH — without ever
holding key material itself. That guarantee only holds if the master's agent
server can tell, on every connection, exactly which remote machines it has
agreed to trust, and can stop trusting one the moment an administrator says
so. Two properties have to hold together for that to be true:

- a certificate that chains to the trusted CA is **necessary** to connect,
  but is not **sufficient** — it must also belong to an agent this master
  still has an active enrollment record for, and must not have been revoked;
- removing an agent has to mean the certificate stops working, not just that
  a row disappears from a list.

An audit of the server (`xkey/pkg/agent/server.go`) and the GUI's removal
path (`xkey/pkg/gui/services/agent_service.go`) found both properties
violated: the server accepted any certificate that chained to the configured
CA, with no check against the enrollment store or the CA's revocation state,
and removing an agent deleted its store record without ever calling
`CAService.RevokeCertificate`. A removed agent's certificate stayed valid
indefinitely.

## Shape chosen: two independent, fail-closed checks at connect time

`Server.buildTLSConfig` already configures `tls.RequireAndVerifyClientCert`
when `tls_ca_file` is set, so Go's TLS stack verifies the certificate chains
to a trusted CA before anything else runs. On top of that, `tls.Config`'s
`VerifyPeerCertificate` hook now runs `EnrollmentService.VerifyAgentCertificate`
against the verified leaf, which enforces two checks that chain validity
alone cannot:

1. **Enrollment lookup.** The leaf's public key is fingerprinted the same way
   enrollment computed `AgentInfo.ID` (SHA-256 of the SubjectPublicKeyInfo),
   and the store is queried for that ID. A removed agent has no record, so
   this check alone rejects it — independent of what the CA's revocation
   list says, which matters if revocation itself was never confirmed.
2. **Revocation check.** The leaf's serial number (`big.Int.Text(16)`, the
   same encoding xkmsd's CA API uses) is checked against the CA through
   `CAService.IsRevoked`, a direct RPC rather than a fetched-and-parsed CRL —
   this feature has no CRL parser of its own and does not add one.

Both checks have to pass. Either one failing rejects the connection. If the
revocation check itself cannot be completed (the CA is unreachable, for
example), the connection is rejected — a rejection is never downgraded to
"assume not revoked."

**Why not just check the CRL locally?** xkms's CA already exposes
`IsRevoked(serialNumber)` as a direct call (`GET /api/v1/ca/revoked/{serial}`
over the REST transport, mirrored on every other transport). Fetching and
parsing a CRL to answer the same question would be new parsing logic for
no operational benefit — the RPC is already synchronous and the CA is
already a required dependency for enrollment.

## Shape chosen: revoke, then delete

`EnrollmentService.RemoveAgent(id)` is the single place removal happens:

1. look up the agent's record, which now carries `CertificateSerial` — the
   serial number of the certificate the CA issued during enrollment;
2. call `CAService.RevokeCertificate(serial)` with a cessation-of-operation
   reason;
3. only on success, delete the store record.

If revocation fails, the function returns the error and the record is left
in place. An agent is never "removed" while its certificate is still valid:
that combination is exactly what would let a removed agent keep connecting.
Retrying `RemoveAgent` is safe and is the documented recovery path when the
CA was briefly unreachable.

`AgentInfo.CertificateSerial` is new. `EnrollWithCode` and `ApproveEnrollment`
now parse the certificate the CA just issued (`certificateSerialHex`) and
persist its serial number alongside the fingerprint that was already stored.
A record enrolled before this change has no serial and cannot be revoked;
`RemoveAgent` refuses to delete such a record (`ErrCertificateSerialMissing`)
rather than silently leaving an unrevocable certificate unaccounted for. Per
this project's pre-release policy there is no migration path for that case —
re-enroll the agent.

## Shape chosen: one service layer, two callers

`RemoveAgent`, `GenerateOneTimeCode`, `ListPending`, `ApproveEnrollment`, and
`RejectEnrollment` all live on `agent.EnrollmentService` — the
business-logic layer this feature has always had.
`xkey/pkg/gui/services.AgentService` is a thin Wails-facing wrapper around
it; the CLI (`xkey agent code|pending|approve|reject|remove`) builds the
identical `*services.AgentService`, wired to the same on-disk `FileStore`
and the same `CAService` client `xkey agent start` uses, and calls the same
methods. Neither the GUI nor the CLI re-implements revocation, persistence,
or store-lookup logic; both call through the one shared layer, satisfying
this repository's rule that a public interface (GUI binding or CLI command)
never reaches past a service layer into business logic directly.

## Shape chosen: codes and pending requests are persisted, not held in memory

Before this change, `EnrollmentService` kept one-time codes and pending
admin-approval requests in memory only. That was invisible from the GUI,
which has always hosted its own agent server in the same process, but it
meant the CLI's `agent start` — a separate, long-running process — could
never see a code or pending request created by a later `xkey agent code` /
`xkey agent pending` / `xkey agent approve` invocation. `xkey agent remove`
never had this problem, because `AgentInfo` records were already persisted
to the `FileStore`.

`EnrollmentStore` now persists all three record types, each under its own
namespace so they can never be confused for one another (`FileStore`'s
`agents/`, `codes/`, `pending/` subdirectories; `DAOStore`'s `agents`,
`codes`, `pending` DAO namespaces):

- **One-time codes** are stored by the hex-encoded SHA-256 hash of the code
  value (`hashCode`), never the plaintext code — the same property the
  in-memory map had by construction (nothing to leak by definition), now
  preserved against a compromised store. `GenerateOneTimeCode` writes the
  hash and expiry; the plaintext code is returned to the caller and
  discarded.
- **Pending requests**, including their CSR, are stored by request ID and
  deleted on approval or rejection — there is no lingering "rejected"
  state to query later; `RejectEnrollment`'s reason is logged and emitted
  as an event at rejection time, not persisted.

**Single-use consumption is atomic across processes, not just within one.**
`EnrollmentStore.ConsumeCode` is the one place a code's validity is
checked and it is single-use is enforced, and the contract is that at most
one caller — in this process or a separate one sharing the same store —
observes success for a given code. `FileStore.ConsumeCode` gets this for
free from the filesystem: it reads the code file, then removes it: exactly
one caller's `os.Remove` for a given path succeeds; every other caller,
whether racing at the same instant or arriving after the winner, sees the
file already gone and reports the code invalid, identical to a code that
never existed. No lock file, `flock`, or additional coordination primitive
is needed — the guarantee comes from POSIX unlink semantics, which already
hold across every process on the same filesystem. `MemoryStore.ConsumeCode`
gets the same guarantee from its own mutex, sufficient since a `MemoryStore`
is never shared across processes by construction. `DAOStore.ConsumeCode` is
Get-then-Delete rather than a true compare-and-delete, since the underlying
go-qrdb `GenericDAO` exposes no atomic primitive for it yet — `DAOStore` is
the clustered/embedded backend, not the default CLI/GUI path, so this is a
documented gap rather than a blocking one.

Why hash the code rather than store it as `EnrollWithCode` compared it
before (plain equality against the map key)? A one-time code already
carries enough entropy (`generateSecureCode`) that hashing needs no salt to
resist guessing, and a single hash-equality check is exactly as strong a
gate as the plaintext comparison it replaces — the only thing that changes
is that the store's on-disk (or DAO-backed) representation never contains
a value an attacker with read access to the store could redeem directly.

## Shape chosen: the connected-agent table is keyed on identity and bounded

`Server.ConnectedAgents` reports the agents currently talking to the master.
The table behind it used to be keyed on the peer's `ip:port` and cleared only
by `Stop`, so without mTLS any network peer could grow it without limit by
reconnecting from fresh source ports. The table is now bounded three ways
(`xkey/pkg/agent/server.go`):

1. **Keyed on the authenticated agent ID.** `peerAgentID` (`server.go:248`)
   derives the ID from the verified client certificate the same way
   enrollment does, so every connection from one agent shares one entry.
   A peer without a verified certificate (plaintext development mode) is
   tracked per connection under its address.
2. **Released on disconnect.** A gRPC stats handler, `connTracker`
   (`server.go:343`), tags each connection; `recordActivity`
   (`server.go:267`) binds the tag to the entry on the first RPC, and
   `connectionClosed` (`server.go:322`) drops the entry when the last
   connection holding it ends.
3. **Capped.** At `maxConnectedAgents` (1024, `server.go:38`) entries,
   `recordActivity` evicts entries idle for longer than `agentIdleTimeout`
   (10 minutes, `server.go:42`); if none are idle the new activity is not
   tracked and a warning is logged. Tracking is observational only, so an
   untracked peer is not refused.

## Rejected alternative: check revocation only, skip the store lookup

Checking only `IsRevoked` and trusting chain validity plus revocation status
would still leave one gap: a removed agent whose revocation call happened to
fail (or was skipped by an operational error) would keep connecting forever,
because nothing else in that model ever re-checks enrollment. Requiring the
independent store lookup means a removed record — the state that unarguably
should have been revoked — is rejected even if the revocation side of the
bookkeeping is somehow wrong. Defense in depth here costs one map lookup per
connection.

## See also

- [Engineering Contract](engineering.md) — exported surface, invariants, errors
- [CLI](cli.md) — `xkey agent` verbs
- [API](api.md) — service-layer surface reused by GUI and CLI
- [User Guide](user.md) — task-oriented usage
