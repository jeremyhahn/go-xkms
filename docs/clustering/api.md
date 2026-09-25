# Clustering — API

> **Status: NORMATIVE** · Feature: `clustering` · Repo: `go-xkms` · Last verified: 2026-09-24

Clustering shows up on xkms's own API surface (REST, gRPC, QUIC, MCP — the
transports documented in
[`../key-management/api.md`](../key-management/api.md)) in two ways: a
read-only REST cluster status/membership surface for the web console, and a
not-leader redirect that applies to every write endpoint on every transport.
Neither gRPC nor MCP carries a cluster status/membership RPC or tool of its
own — verified absent from `pkg/api/grpc` and `pkg/api/mcp`. Cluster
membership *mutation* (`add`/`remove`) is reachable only through `xkmsctl
cluster`/`rebalance`, which speak a **different**, xkms-REST-independent
service — see cli.md and architecture.md's "Two distinct surfaces over the
same Raft shard" for why that surface's authorization posture differs from
the REST routes below.

## REST: `/api/v1/cluster/*` (go-xkms#847)

Served by `pkg/api/rest/handlers_cluster.go:ClusterHandlers`, backed by the
`XKMSService` servicer (`pkg/xkms/servicer_cluster.go`). This is the
browser-facing surface the embedded web console's Cluster page and the
TypeScript SDK's `ClusterClient` (`sdk/ts/src/clients/cluster.ts`) use — see
architecture.md for how it differs from `xkmsctl cluster`, which talks to
go-qrdb's own control plane directly and never goes through this REST
surface.

Both routes are read-only and require an RBAC permission when RBAC is
enabled (never a free pass for an authenticated caller); see
engineering.md's "RBAC vocabulary" for the resource:action pairs. There is
no membership-mutation route: Raft membership changes go through go-qrdb's
own control plane exclusively, via `xkmsctl cluster add`/`remove` (cli.md)
— see "Two distinct surfaces over the same Raft shard" in architecture.md and
`docs/web/parity.md`'s "Cluster mutations" section. A route that could only
ever answer "not supported" would be a stub, so none is registered.

### `GET /api/v1/cluster/status`

Permission: `admin:status`.

```json
{
  "status": {
    "shard_id": 1,
    "leader_id": 1,
    "has_leader": true,
    "node_id": 1,
    "clustered": true
  }
}
```

On a standalone node this returns `200` with `"clustered": false`,
`"has_leader": false`, `"leader_id": 0` — never an error. The `node_id` field
is this responding node's own Raft replica ID (`config.Cluster.NodeID`),
distinct from any member's `replica_id` below.

### `GET /api/v1/cluster/members`

Permission: `admin:peers`.

```json
{
  "members": [
    {
      "replica_id": 1,
      "address": "10.0.0.1:63001",
      "api_endpoints": { "rest": "10.0.0.1:8443" },
      "is_leader": true
    }
  ]
}
```

`api_endpoints` is omitted (not an empty object) when a replica advertises
nothing. On a standalone node this returns `200` with `"members": []`.

### No membership-mutation route

There is no `POST`/`DELETE /api/v1/cluster/members` — REST never mutates
Raft membership, on any node, clustered or standalone. Registering a route
that could only ever answer "not implemented" would be a stub, and this
codebase does not register stubs. Raft membership changes go through
go-qrdb's own control plane exclusively: `xkmsctl cluster add`/`remove`
(cli.md). The TypeScript SDK's `ClusterClient`
(`sdk/ts/src/clients/cluster.ts`) exposes only `status()`/`members()` for the
same reason; there is no `addMember`/`removeMember` to call.

### Why reads never fail on a standalone node

Status and membership are meaningful even absent a Raft group — "not
clustered" is itself a valid, well-defined answer the web console renders as
a badge, so the read routes degrade gracefully instead of erroring. See
architecture.md's "Standalone degradation, not capability gating, for
reads".

### `/auth/me` capability flag

`GET /api/v1/auth/me` (`pkg/api/rest/handlers_auth.go:capabilityFlags`)
reports `"cluster": true` only when `XKMSService.Clustered()` is true — i.e.
only on an actually-clustered node, never merely because the REST cluster
routes exist (they always exist, on every node). The web console's nav
(`src/lib/nav.ts`, `capability: "cluster"`) uses this to hide the Cluster
page by default on a standalone deployment; the read routes themselves
remain reachable (per above) if navigated to directly.

## Not-leader redirect, per transport

Applies to every clustered *write* endpoint (`POST /api/v1/keys`, `POST
/api/v1/ca/sign-csr`, …), never to the cluster status/membership routes
above — those answer from local Raft state on any member.

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
it). `xkmsctl cluster members` and `GET /api/v1/cluster/members` both show
these endpoints per replica.

## Reads vs. writes

Read operations succeed on any member (served with follower-read
consistency — see
[`../storage-engines/engineering.md`](../storage-engines/engineering.md)).
Only writes require the leader and trigger the redirect above. The cluster
status/membership routes are reads in this sense too, but are documented
separately above because they are cluster-introspection endpoints rather
than xkms's general key/CA/RBAC data plane.
