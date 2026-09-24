---
status: current
last_verified: 2026-09-24
---

# Clustering — Architecture

Clustering gives xkms high availability by replicating all datastore state
(keys, users, RBAC, custodian records, shares, CA serials/revocations, audit
events) across multiple xkmsd nodes via Raft. An enabled node hosts an
in-process go-qrdb clustered engine (`qrdbnode.NewClusteredNode`); a disabled
one hosts the standalone engine (`qrdbnode.NewStandaloneNode`) — see
`pkg/daemon/node_cluster.go`. Clustering is opt-in and requires the `raft`
build tag; a default build is standalone-only.

## Two distinct surfaces over the same Raft shard

xkms exposes cluster status and membership through **two independent
surfaces**, each built for a different caller, and neither is a thin wrapper
around the other:

1. **go-qrdb's own control plane**, registered directly onto xkmsd's gRPC
   server and Unix socket
   (`pkg/server/qrdb_control_plane.go:registerQRDBControlPlane`) with zero
   xkms-authored handlers. `xkmsctl cluster status|members|add|remove`
   (`cmd/xkmsctl/cluster.go`) drives this surface as a qrdb SDK client over
   gRPC or the Unix socket — never through xkms's REST API. This is the
   operator/automation path, and it is the one qrdb's own AdminService RPCs
   answer.

2. **The xkms REST cluster surface** (`/api/v1/cluster/*`, go-xkms#847),
   served by `pkg/api/rest/handlers_cluster.go` and backed by the
   `XKMSService` servicer (`pkg/xkms/servicer_cluster.go`). This exists
   because a browser cannot speak gRPC or reach a Unix socket: the embedded
   web console's read-only Cluster page (`web/app/src/views/ClusterView.svelte`)
   and the TypeScript SDK's `ClusterClient`
   (`sdk/ts/src/clients/cluster.ts`) need an HTTP surface, authenticated and
   authorized exactly like every other xkms API route.

Both surfaces read the *same* Raft shard through the *same* underlying
go-qrdb `ClusterClient` (`Members`, `Leader`) — there is no second membership
model. The REST layer never calls qrdb directly for reads; it goes through
the `XKMSService` servicer, following the same service-layer discipline as
every other xkms subsystem (custodian groups, shares, tenants, …).

**Membership is mutated through surface #1 only — REST exposes no mutation
route at all.** There is no `POST`/`DELETE /api/v1/cluster/members`: a route
that could only ever answer "not implemented" would be a stub, and this
codebase does not register stubs. This is not a gap to be filled in later:
an earlier xkms-authored cluster/auth-factor proxy plane was already deleted
once (see the "replaces the deleted xkms-authored cluster/auth-factor proxy
planes" comment in `qrdb_control_plane.go`), and adding a REST mutation
path — working or not — would recreate exactly that proxy.
`docs/web/parity.md`'s "Cluster mutations" section and the web console's
Cluster page banner ("Cluster membership changes are performed over the Raft
admin plane … and are intentionally not exposed here") both document the
same decision independently. The `XKMSService` servicer therefore exposes
only the read half (`ClusterStatus`, `ClusterMembers`); it has no
`ClusterAddReplica`/`ClusterRemoveReplica` method for REST (or any other
transport) to call, and the TypeScript SDK's `ClusterClient` has no
`addMember`/`removeMember` method either. The lower-level `ClusterClient`/
`ClusterMutator` Go contract the qrdb SDK adapter satisfies still carries
`AddReplica`/`RemoveReplica` — that plumbing exists only to satisfy the qrdb
SDK's shape, and nothing calls it.

## Standalone degradation, not capability gating, for reads

`XKMSService.Clustered()` reports whether this node's cluster client is wired
(`SetClusterClient` with a non-nil `ClusterClient`, set only when
`config.Cluster.Enabled`). Read operations do **not** gate on it:

- `ClusterStatus` returns `{clustered: false, has_leader: false, leader_id:
  0}` on a standalone node instead of failing — there is a well-defined
  "no cluster" status, not an absent one.
- `ClusterMembers` returns an empty list on a standalone node.

This lets the web console's Cluster page render a "standalone" badge
correctly whether or not the deployment ever intends to cluster, and lets
`xkmsctl cluster status`/`members` work identically on every node (see
`docs/cluster/cli.md`). The REST `/auth/me` `capabilities.cluster` flag still
reports `false` on a standalone node — it exists only to hide the nav entry
by default, not to gate the read routes.

**Membership mutation is different and does not degrade — it is simply not
offered.** See the "REST never mutates Raft membership" note above and
`docs/cluster/api.md`.

## Leader redirect (client request routing)

xkms client APIs (REST, gRPC, QUIC, Unix socket) route around Raft
leadership independently of the cluster status/membership surface above:

- Read operations succeed on any member.
- Write operations (`CreateKey`, `SignCSR`, `SetPin`, …) require the leader.
  A write sent to a follower is rejected with a typed not-leader error
  naming the current leader, surfaced per protocol (REST: HTTP `421
  Misdirected Request` with `X-XKMS-Leader-*` headers; gRPC/Unix:
  `FailedPrecondition` with an `ErrorInfo` detail; QUIC: the same `421`
  mapping as REST) — see `pkg/xkms/errors.go:ErrNotLeader`,
  `pkg/api/rest/errors.go:writeNotLeader`.

xkms **redirects the client** to the leader rather than forwarding
server-side. This is a security decision: xkms identities are bound to the
caller's own credentials (mTLS client certificate or session token). A
follower does not hold the caller's private key, so it cannot re-present the
caller's identity to the leader; forwarding server-side would require either
an impersonation channel or a full delegation protocol. With a redirect the
caller re-presents its own credentials to the leader, so the leader enforces
authentication and authorization exactly as it would for a directly-dialed
request.

Redirect behavior: exactly one hop (a second not-leader response is returned
to the caller rather than chased, so a leadership flap cannot loop); the
retry reuses the same TLS configuration and credentials; the client's
configured address is never permanently repointed; a not-leader response
carrying no API address is returned unchanged; the Unix socket transport
never follows redirects (a local socket client has no network credentials).

### Advertised API endpoints

For a redirect to be actionable, a client must be able to turn "the leader is
replica N" into a dialable address. Each node publishes its own
client-facing API endpoints into the cluster registry, keyed by protocol
(`rest`, `grpc`, `quic`, `mcp` — never the Unix socket, which is meaningful
only on the node that owns it). Values come from the node's own
configuration (`cluster.advertise_host` plus each enabled protocol's
configured port), never derived from the Raft address by port arithmetic.
When no concrete host is available the node advertises nothing rather than
an address no client can dial, and membership listing never fails because
endpoint discovery did (`pkg/server/cluster_adapter.go:apiEndpointsToStrings`).

## Cluster CA key custody

Provisioning inter-node Raft mTLS and deciding which nodes may issue node
certificates is a separate design surface from Raft membership itself. See
[Cluster CA Key Custody Architecture](ca-key-custody.md) for the
`ClusterCAKeyStrategy` seam, the three custody models (`barrier`, `hsm`,
`tpm-kek`), and TPM-sealed seed delivery.
