---
status: current
last_verified: 2026-09-24
---

# Clustering — API

## REST: `/api/v1/cluster/*` (go-xkms#847)

Served by `pkg/api/rest/handlers_cluster.go`, backed by the `XKMSService`
servicer (`pkg/xkms/servicer_cluster.go`). This is the browser-facing
surface the embedded web console's Cluster page and the TypeScript SDK's
`ClusterClient` (`sdk/ts/src/clients/cluster.ts`) use — see
`docs/cluster/architecture.md` for how it differs from `xkmsctl cluster`,
which talks to go-qrdb's own control plane directly and never goes through
this REST surface.

Both routes are read-only and require RBAC permission when RBAC is enabled
(never a free pass for an authenticated caller); see
`docs/cluster/engineering.md#rbac-vocabulary` for the resource:action pairs.
There is no membership-mutation route: Raft membership changes go through
go-qrdb's own control plane exclusively, via `xkmsctl cluster add`/`remove`
(`docs/cluster/cli.md`) — see "REST never mutates Raft membership" in
`docs/cluster/architecture.md` and `docs/web/parity.md`'s "Cluster
mutations" section. A route that could only ever answer "not supported"
would be a stub, so none is registered.

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
(`docs/cluster/cli.md`). The TypeScript SDK's `ClusterClient`
(`sdk/ts/src/clients/cluster.ts`) exposes only `status()`/`members()` for the
same reason; there is no `addMember`/`removeMember` to call.

### Why reads never fail on a standalone node

Status and membership are meaningful even absent a Raft group — "not
clustered" is itself a valid, well-defined answer the web console renders as
a badge, so the read routes degrade gracefully instead of erroring. See
`docs/cluster/architecture.md`.

### `/auth/me` capability flag

`GET /api/v1/auth/me` (`pkg/api/rest/handlers_auth.go:capabilityFlags`)
reports `"cluster": true` only when `XKMSService.Clustered()` is true — i.e.
only on an actually-clustered node, never merely because the REST cluster
routes exist (they always exist, on every node). The web console's nav
(`src/lib/nav.ts`, `capability: "cluster"`) uses this to hide the Cluster
page by default on a standalone deployment; the read routes themselves
remain reachable (per above) if navigated to directly.

## Not-leader redirect (unrelated write endpoints)

The cluster status/membership routes above are never subject to Raft
leader redirection — they answer from local Raft state on any member. Every
*other* clustered write endpoint (`POST /api/v1/keys`, `POST
/api/v1/ca/sign-csr`, …) is: a write reaching a follower is rejected with
HTTP `421 Misdirected Request`, the leader echoed in
`X-XKMS-Leader-ID`/`X-XKMS-Leader-Address`/`X-XKMS-Leader-API-Address`
response headers and the JSON body. gRPC/Unix surface the same condition as
`FailedPrecondition` with an `ErrorInfo` detail (`Domain: xkms.cluster`,
`Reason: NOT_LEADER`); QUIC uses the same `421` mapping as REST. See
`docs/cluster/architecture.md#leader-redirect-client-request-routing`.
