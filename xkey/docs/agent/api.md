# Network Agent — API

> **Status: NORMATIVE** · Feature: `agent` · Module: `go-xkms/xkey` · Last verified: 2026-09-23

No REST/gRPC/MCP transport surface of its own. This feature is reachable
through two façades that both call the same service layer
(`xkey/pkg/agent.EnrollmentService`, `xkey/pkg/agent.Server`), so there is
one capability list, not two:

| Capability | GUI (`services.AgentService`, Wails binding) | CLI (`xkey agent ...`) |
|---|---|---|
| Start / stop the agent server | `StartServer(address)` / `StopServer()` | `agent start` / `agent stop` |
| Server status | `GetServerStatus()` | `agent status` |
| Generate a one-time enrollment code | `GenerateEnrollmentCode()` / `GenerateEnrollmentCodeWithValidity(d)` | `agent code` |
| List pending enrollment requests | `ListPendingEnrollments()` | `agent pending` |
| Approve a pending request | `ApproveEnrollment(id)` / `ApproveEnrollmentWithCertificate(id)` | `agent approve <id>` |
| Reject a pending request | `RejectEnrollment(id, reason)` | `agent reject <id>` |
| List enrolled agents | `ListAgents()` | `agent status` |
| Remove an agent (revokes, then deletes) | `RemoveAgent(id)` | `agent remove <id>` |

The GUI calls these methods in the same process that hosts the agent
server it is managing. The CLI's `agent start` runs as its own long-lived
process; every other verb (`code`, `pending`, `approve`, `reject`,
`remove`) builds a separate, short-lived instance of the same service
layer, backed by the same on-disk `EnrollmentStore` `agent start` uses.
Agent records, one-time codes (by hash), and pending requests (with their
CSR) are all persisted through that store, so every verb sees the same
state regardless of which process — the running daemon, the GUI, or a
separate CLI invocation — produced it. See
[architecture.md](architecture.md) for how single-use code consumption
stays atomic across processes sharing the store.

## Certificate authority transport calls

`EnrollmentService` and the connection-time verifier reach the certificate
authority through `agent.CAService`, implemented by
`pkg/agent.XKMSdCA` over the go-xkms SDK transport
(`sdk/go/transport.Client`). The two calls this feature added or now
exercises for the first time:

- `RevokeCertificate(serialNumber)` — now actually called, by
  `EnrollmentService.RemoveAgent`. Previously implemented but unreferenced.
- `IsRevoked(serialNumber)` — new. Wraps the transport's existing
  `CAService.IsRevoked`, which reaches xkmsd's `GET /api/v1/ca/revoked/{serial}`
  (or the equivalent verb on gRPC/QUIC/Unix/embedded transports). See the
  xkms CA feature docs for the wire contract; this feature adds no new
  wire format.

## Agent-side connection protocol

Out of scope for this document: the mTLS handshake a remote agent performs
to connect (`xkey/pkg/agent.Client`) is unchanged by this feature except
that the master now enforces the two checks in
[architecture.md](architecture.md) during that handshake's certificate
verification. There is no new request/response shape on the wire; a
rejected agent sees a standard TLS handshake failure.
