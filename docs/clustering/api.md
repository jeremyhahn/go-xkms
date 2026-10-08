# Clustering — API

> **Status: NORMATIVE** · Feature: `clustering` · Repo: `go-xkms` · Last verified: 2026-10-07

Clustering shows up on xkms's own API surface (REST, gRPC, QUIC, MCP — the
transports documented in
[`../key-management/api.md`](../key-management/api.md)) in one way only: a
not-leader redirect that applies to every write endpoint on every transport.

xkms carries no cluster status, membership or membership-mutation endpoint of
its own on any transport. Those belong to go-qrdb's control plane: its
`AdminService` (registered on xkmsd's Unix gRPC socket by
`pkg/server/qrdb_control_plane.go:registerQRDBControlPlane`) and the embedded
node's admin-plane `GET /peers`. `xkmsctl cluster` and `rebalance` (cli.md)
speak that control plane directly. The former `GET /api/v1/cluster/status` and
`GET /api/v1/cluster/members` REST routes re-hosted it and were removed.

## `/auth/me` capability flag

`GET /api/v1/auth/me` (`pkg/api/rest/handlers_auth.go:capabilityFlags`)
reports `"cluster": true` only when `XKMSService.Clustered()` is true — i.e.
only on an actually-clustered node. The web console's dashboard renders this
flag as its "clustered" / "standalone" card; it makes no cluster API call.

## Not-leader redirect, per transport

Applies to every clustered *write* endpoint (`POST /api/v1/keys`, `POST
/api/v1/ca/sign-csr`, …).

| Transport | Mechanism |
|---|---|
| REST | HTTP `421 Misdirected Request`. Headers `X-XKMS-Shard-ID`, `X-XKMS-Leader-ID`, `X-XKMS-Leader-Address`, `X-XKMS-Leader-API-Address` (each omitted, never emitted empty, when unresolved). JSON body: `{"error": "...", "shard_id": N, "leader_id": N, "leader_address": "...", "leader_api_address": "..."}` (`NotLeaderResponse`, `pkg/api/rest/errors.go`). |
| gRPC | `codes.FailedPrecondition` status, with an `ErrorInfo` detail: `Reason: "NOT_LEADER"`, `Domain: "xkms.cluster"`, `Metadata: {shard_id, leader_id, leader_address, leader_api_address?}` (`pkg/api/grpc/errors.go:notLeaderStatus`). |
| QUIC | Same `421` mapping as REST — QUIC is HTTP/3 served on the unified REST listener, not a separate server package. |
| MCP | No dedicated translation — verified absent: `pkg/api/mcp` calls neither `AsNotLeader` nor constructs an `ErrNotLeader`-aware response. A write against a follower reaches the same servicer-level `xkms.ErrNotLeader`, but MCP surfaces it through its generic error path (the error's plain text), without the structured shard/leader metadata REST and gRPC attach. |

`leader_address` is the leader's **Raft peer** address — not dialable as an
API endpoint. `leader_api_address` is the address to dial to reach the
leader over the **same** API protocol the failed request used, resolved via
`XKMSService.ClusterLeaderEndpoint(ctx, protocol)`
(`pkg/xkms/servicer_cluster.go`); it is empty (and omitted) when the leader
has advertised nothing for that protocol.

## Redirect behavior

- The SDK client follows a not-leader response **once**; a second one is
  returned to the caller unchanged rather than chased, so a leadership flap
  cannot cause a redirect loop.
- The retry reuses the caller's own TLS configuration and credentials — only
  the scheme and host change. Path, query, headers, and body are preserved.
  This is why the redirect is safe: the caller re-presents its **own**
  identity to the leader, which runs the identical authenticate-then-authorize
  path it runs for a directly-dialed request.
- The client's configured target address is never permanently repointed; a
  transient leadership change does not stick.
- The **Unix socket** transport does not follow redirects — a local socket
  client has no network credentials to re-present to a remote leader, so it
  surfaces the typed not-leader error instead of hanging.

## Advertised endpoints

Each node publishes its own client-facing API endpoints (keyed by protocol:
`rest`, `grpc`, `quic`, `mcp` — a protocol absent from the map means that
node does not serve it) into the cluster registry, derived from
`cluster.advertise_host` plus each enabled protocol's configured port —
never derived from the Raft address by port arithmetic. The Unix socket is
never advertised (a socket path is only meaningful on the node that owns
it). `xkmsctl cluster members` shows these endpoints per replica.

## Reads vs. writes

Read operations succeed on any member (served with follower-read
consistency — see
[`../datastore/engineering.md`](../datastore/engineering.md)).
Only writes require the leader and trigger the redirect above.
