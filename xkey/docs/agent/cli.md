# Network Agent — CLI

> **Status: NORMATIVE** · Feature: `agent` · Module: `go-xkms/xkey` · Last verified: 2026-09-23

Binary: `xkey`. Parent command: `xkey agent` (server-side, master-only —
enrolling and connecting from the agent side is `xkey device enroll` /
`xkey device connect`, documented separately).

## `xkey agent start`

Starts the agent server. Requires a reachable xkmsd certificate authority
(`--xkmsd-url` or `XKMSD_URL`); fails closed without one. Records its PID
and bound address under the xKey data directory so `status` and `stop` can
find it.

```
xkey agent start --xkmsd-url unix:///var/run/xkmsd.sock
xkey agent start --xkmsd-url grpcs://xkms.example.com:8443 --listen :9443
xkey agent start --tls-cert server.pem --tls-key server-key.pem --tls-ca ca.pem
```

Flags: `--listen`, `--tls-cert`, `--tls-key`, `--tls-ca`, `--cert-profile`
(default `client`), `--cert-validity-days` (`0` uses the CA default).

When `--tls-ca` is set (mTLS), every connection is checked against the
enrollment store and the CA's revocation state before it is accepted — see
[architecture.md](architecture.md). Without `--tls-ca` the server runs in
plaintext, development-only mode with no client certificate to check.

## `xkey agent stop`

```
xkey agent stop
```

Sends `SIGTERM` to the recorded PID, escalating to `SIGKILL` after 10
seconds. Exits non-zero if no server is running; it never claims to have
stopped a server it did not stop.

## `xkey agent status`

```
xkey agent status
```

Reports whether the server process is running (PID, listen address, TLS
mode, start time) followed by every enrolled agent from the on-disk store —
regardless of whether the server is currently running, since the store is
read directly from disk.

## `xkey agent code`

Generates a one-time enrollment code.

```
xkey agent code
xkey agent code --validity 30m
xkey agent code --json
```

Flags: `--validity` (duration; `0` uses the configured default, 15
minutes), `--cert-profile`, `--cert-validity-days`, `--json`.

Only the code's hash is persisted through the enrollment store — the same
on-disk store `agent status` and `agent remove` already share with a
running `agent start` process — so a code generated here is honored
whether the enrolling agent presents it to this same invocation, a
separately running `agent start` daemon, or the GUI. The code is single-use
and expires after its validity period; either consumes it. See
[architecture.md](architecture.md) for how single-use consumption stays
atomic across processes.

Human output:

```
Enrollment code generated
  Code:       a1b2c3d4
  Expires at: 2026-09-23T15:30:00Z
```

`--json` output is `services.EnrollmentCodeInfo`:

```json
{ "code": "a1b2c3d4", "expires_at": "2026-09-23T15:30:00Z" }
```

## `xkey agent pending`

Lists enrollment requests submitted for admin approval that have not yet
been approved or rejected. Requests, including their CSR, are persisted
through the enrollment store, so a request submitted to a running `agent
start` process is visible here regardless of which process lists it.

```
xkey agent pending
xkey agent pending --json
```

Human output when empty:

```
No pending enrollment requests
```

Human output with entries:

```
Pending Enrollment Requests (1):

  ID:           06adeb21d10812d7
  Fingerprint:  63a76e219a9420d3...
  Requested at: 2026-09-23T15:00:00Z
  Status:       pending
```

`--json` output is a `[]services.PendingEnrollmentInfo` array.

## `xkey agent approve <request-id>`

Approves a pending enrollment request: signs its CSR with the xkmsd
certificate authority, records the new agent (with its certificate
serial number, so it can be revoked later), and prints the issued
certificate.

```
xkey agent approve 3f9c2a1b8e7d4f60
xkey agent approve 3f9c2a1b8e7d4f60 --json
```

Flags: `--cert-profile`, `--cert-validity-days`, `--json`.

The certificate and CA certificate are printed for the administrator to
deliver to the enrolling agent out of band; xkey never transmits them
anywhere on the approver's behalf. `--json` output is
`services.EnrollmentApprovalResult` (`request_id`, `certificate_pem`,
`ca_certificate_pem`).

## `xkey agent reject <request-id>`

Rejects a pending enrollment request: deletes it from the enrollment store
without signing its CSR. This is the same operation the GUI's "Reject"
action performs, over the same shared service.

```
xkey agent reject 3f9c2a1b8e7d4f60
xkey agent reject 3f9c2a1b8e7d4f60 --reason "not authorized"
xkey agent reject 3f9c2a1b8e7d4f60 --json
```

Flags: `--reason` (recorded in the log and event for this rejection; not
persisted, since the request it would describe no longer exists once
rejection completes), `--cert-profile`, `--cert-validity-days`, `--json`.

Human output:

```
Enrollment rejected: 3f9c2a1b8e7d4f60
```

`--json` output: `{"request_id": "...", "status": "rejected"}`.

## `xkey agent remove <agent-id>`

Revokes the agent's certificate through the xkmsd certificate authority,
then deletes its enrollment record. If revocation fails, the command fails
and the record is left in place — retry once the CA is reachable again.

```
xkey agent remove 3f9c2a1b8e7d4f60
xkey agent remove 3f9c2a1b8e7d4f60 --json
```

Flags: `--cert-profile`, `--cert-validity-days`, `--json`.

`AgentInfo` records are persisted to the on-disk `FileStore`, so removal
(and the revocation it performs) sees the same enrollment the running
`agent start` daemon does, exactly like every other verb on this page.

Human output:

```
Agent removed: 3f9c2a1b8e7d4f60
```

## See also

- [Architecture](architecture.md) — the connection-time model and how
  codes, pending requests, and agent records are persisted
- [User Guide](user.md) — end-to-end enrollment and removal walkthroughs
