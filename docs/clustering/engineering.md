# Clustering — Engineering Contract

> **Status: NORMATIVE** · Feature: `clustering` · Repo: `go-xkms` · Last verified: 2026-09-24

## Exported surface

### Config — `pkg/config/config.go:ClusterConfig`

```go
type ClusterConfig struct {
	Enabled       bool                 `yaml:"enabled"`
	NodeID        uint64               `yaml:"node_id"`
	ShardID       uint64               `yaml:"shard_id"`
	DeploymentID  uint64               `yaml:"deployment_id"`
	RaftAddress   string               `yaml:"raft_address"`
	ListenAddress string               `yaml:"listen_address"`
	AdvertiseHost string               `yaml:"advertise_host"`
	Peers         string               `yaml:"peers"`
	Join          bool                 `yaml:"join"`
	RaftTLS       RaftTLSConfig        `yaml:"raft_tls"`
	RaftEnrollment RaftEnrollmentConfig `yaml:"raft_enrollment"`
}

func (c ClusterConfig) Members() (map[uint64]string, error)
```

```go
type RaftTLSConfig struct {
	CACertFile string `yaml:"ca_cert_file"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
}
func (r RaftTLSConfig) Enabled() bool
func (r RaftTLSConfig) IsComplete() bool
```

```go
type RaftEnrollmentConfig struct {
	TrustDomain        string                   `yaml:"trust_domain"`         // default "xkms.cluster"
	KeyBackend         string                   `yaml:"key_backend"`          // "" | "tpm2" | "pkcs11"
	AdvertiseNoisePort int                      `yaml:"advertise_noise_port"` // default 63006
	AdvertiseNoiseHost string                   `yaml:"advertise_noise_host"` // defaults to server.host
	Bootstrap          RaftBootstrapConfig      `yaml:"bootstrap"`
	ACME               RaftACMEEnrollmentConfig `yaml:"acme"`
	ClusterCACN        string                   `yaml:"cluster_ca_cn"`
	CAKeyProtection    string                   `yaml:"ca_key_protection"` // "" | "tpm2" | "pkcs11" | "passphrase" | "none"
	CAKeyPassphrase    *types.SecretValue        `yaml:"ca_key_passphrase"`
	CAKeyStrategy      string                   `yaml:"ca_key_strategy"`   // "" | "barrier" | "hsm" | "tpm-kek"
}

type RaftBootstrapConfig struct {
	NoiseKey, NoiseAddr, SPKIPin, ServerAddr, DANEDNS string
	DANEDoT    bool
	DirectURL  string
}
func (b RaftBootstrapConfig) Configured() bool

type RaftACMEEnrollmentConfig struct {
	Enabled       bool   `yaml:"enabled"`
	DirectoryURL  string `yaml:"directory_url"`
	ChallengePort string `yaml:"challenge_port"` // default "8080"
}
```

### `pkg/daemon` — the shared, build-tag-dispatched node builder

```go
// !raft build (pkg/daemon/node_standalone.go)
func NewNode(ctx context.Context, opts *Options) (*Result, error) // always standalone; ErrClusterRequiresRaftBuild if opts.Cluster.Enabled

// raft build (pkg/daemon/node_cluster.go)
func NewNode(ctx context.Context, opts *Options) (*Result, error) // standalone if !opts.Cluster.Enabled, else qrdbnode.NewClusteredNode
```

### `pkg/server` — the xkmsd-specific composition

```go
func (s *Server) buildXKMSQRDBConfig() *qrdbsdk.DaemonConfig       // qrdb_node.go
func (s *Server) initEmbeddedQRDBNode() error                      // qrdb_node.go
func (s *Server) newQRDBNode(qcfg, serverOpts, nodeOpts) (*qrdbnode.Node, error) // build-tag specific: qrdb_node_standalone.go / qrdb_node_cluster.go
func (s *Server) waitForClusterLeader() error                      // qrdb_node.go
func (s *Server) resolveRaftMTLS(ctx, members) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error) // raft build only, qrdb_node_cluster.go
func (s *Server) registerQRDBControlPlane(gs *grpc.Server)         // qrdb_control_plane.go
```

### `pkg/xkms` — the servicer surface backing the REST cluster routes (`pkg/xkms/servicer_cluster.go`)

`XKMSService` wires an optional `cluster ClusterClient` (nil on a standalone
node) plus `clusterShardID`/`clusterNodeID`, set once at composition time by
`SetClusterClient(c ClusterClient, shardID, nodeID uint64)`
(`pkg/xkms/service.go`). `pkg/server/server.go` calls it with a live
`*clusterClientAdapter` (`pkg/server/cluster_adapter.go`, bridging the
embedded go-qrdb node's `*qrdbsdk.ClusterClient`) only when
`s.qrdbClient != nil && s.config.Cluster.Enabled`; otherwise it passes `nil`.

```go
type ClusterClient interface {
    ClusterReader          // Members, Leader
    ClusterEndpointResolver // LeaderEndpoint
    ClusterMutator          // AddReplica, RemoveReplica
}
```

Exported methods, all on `*XKMSService` — read-only by design; see
architecture.md's "Two distinct surfaces over the same Raft shard" for why there is
deliberately no `ClusterAddReplica`/`ClusterRemoveReplica`:

| Method | Standalone behavior | Clustered behavior |
|---|---|---|
| `Clustered() bool` | `false` | `true` |
| `ClusterStatus(ctx) (*ClusterStatus, error)` | returns `{ShardID, NodeID}` with `Clustered: false`, `HasLeader: false`, no error | queries `Leader`; returns `*ClusterStatusError` on failure |
| `ClusterMembers(ctx) ([]ClusterMember, error)` | returns `nil, nil` (empty) | queries `Members`; returns `*ClusterMembersError` on failure |
| `ClusterLeaderEndpoint(ctx, protocol) (string, error)` | returns `"", nil` | resolves the leader's advertised address for `protocol`; returns `*ClusterLeaderEndpointError` on failure |

`ClusterStatus` and `ClusterMembers` are the only two servicer methods in the
codebase that intentionally *degrade* rather than fail closed on a missing
optional subsystem — every other subsystem servicer method (custodian,
shares, tenants, …) returns `xkms.ErrNotConfigured` when its backing client
is nil. This asymmetry is deliberate (see architecture.md's "Standalone
degradation, not capability gating, for reads") and is exercised directly by
`pkg/xkms/servicer_cluster_test.go` (`TestClusterStatus_Standalone`,
`TestClusterMembers_Standalone`).

The `ClusterMutator` half of the `ClusterClient` interface (`AddReplica`,
`RemoveReplica`) still exists and `pkg/server/cluster_adapter.go` still
implements it — that plumbing is what lets `clusterClientAdapter` satisfy the
qrdb SDK's `*qrdbsdk.ClusterClient` shape — but no `XKMSService` method ever
calls it. Nothing in the REST, gRPC, or QUIC transports reaches it either.

#### Types (`pkg/xkms/servicer_cluster.go`)

```go
type ClusterMember struct {
    ReplicaID    uint64
    Address      string
    APIEndpoints map[string]string // nil when the replica advertises nothing
    IsLeader     bool
}

type ClusterStatus struct {
    ShardID   uint64
    NodeID    uint64
    LeaderID  uint64
    HasLeader bool
    Clustered bool
}
```

### `pkg/api/rest` — the REST handler surface (`pkg/api/rest/handlers_cluster.go`)

```go
type ClusterHandlers struct{ /* unexported */ }
func NewClusterHandlers(svc *xkms.XKMSService) *ClusterHandlers
func (h *ClusterHandlers) StatusHandler(w http.ResponseWriter, r *http.Request)
func (h *ClusterHandlers) MembersHandler(w http.ResponseWriter, r *http.Request)
```

`ClusterHandlers` is constructed unconditionally in `NewServer`
(`pkg/api/rest/server.go`), unlike the other optional handler groups
(`custodianHandlers`, `tenantHandlers`, …), because `StatusHandler` and
`MembersHandler` must work on a standalone node. There is no
`AddMemberHandler`/`RemoveMemberHandler` and no `POST`/`DELETE` route
registered in `pkg/api/rest/routes.go` — a handler that could only ever
answer "not implemented" would be a stub, so none is registered; see api.md
for the wire contract.

`handleClusterError` (`pkg/api/rest/handlers_cluster.go`) maps
`errors.Is(err, xkms.ErrNotConfigured)` to a typed `rest.ErrClusterNotConfigured`
(503 — the construction-order case where no `XKMSService` was wired at all,
not the standalone-node case, which never errors) and logs anything else
before returning a generic 500 (`slog.Default().Error`) — the same pattern
`handleCustodianError` uses.

### Not-leader translation — `pkg/xkms/errors.go`

```go
type ErrNotLeader struct {
	ShardID, LeaderID uint64
	LeaderAddress     string // Raft peer address — NOT dialable as an API endpoint
	LeaderAPIAddress  string // dialable address for the SAME protocol the failed request used
}
func AsNotLeader(err error) (*ErrNotLeader, bool)
```

## RBAC vocabulary (`pkg/auth/permissions.go`)

The two REST cluster routes mirror go-qrdb's own `AdminService` vocabulary
exactly (`pkg/permission/constants.go` in go-qrdb: `AdminStatus`,
`AdminPeers`), declared as `auth.ResourceAdmin` ("admin") combined with
`auth.ActionStatus` ("status") and `auth.ActionPeers` ("peers"):

| Route | Method | Permission |
|---|---|---|
| `/api/v1/cluster/status` | GET | `admin:status` |
| `/api/v1/cluster/members` | GET | `admin:peers` |

This is the same grant qrdb's own control-plane gRPC surface enforces
internally (`pkg/server/qrdb_control_plane.go`), so a caller's RBAC role
never has to diverge between the two surfaces — see architecture.md's Trust
boundaries for why only the REST surface currently *enforces* it as xkms
RBAC. `pkg/auth/permissions.go` deliberately carries no
`ActionAddMember`/`ActionRemoveMember`: go-qrdb's
`AdminAddMember`/`AdminRemoveMember` permissions are enforced only by the
qrdb control plane itself (`xkmsctl cluster add`/`remove`), never by xkms's
REST layer, so xkms defines no xkms-side vocabulary for a route that does
not exist.

## Invariants

- **Clustering requires the `raft` build tag at compile time**, and
  `storage.backend: "qrdb"` at config time. Neither is optional; the
  non-raft build refuses `cluster.enabled=true` outright
  (`ErrClusterRequiresRaftBuild`), and `Config.Validate` refuses
  `cluster.enabled=true` with any backend other than `"qrdb"`.
- **A raft-tagged binary without `cluster.enabled` still runs standalone.**
  The tag adds capability; it does not change default behavior.
- **Multi-node Raft always requires mTLS.** `resolveRaftMTLS` is consulted
  only when `len(members) > 1`; a single-node "cluster" uses an in-process
  transport.
- **The runtime xkms CA is never the Raft mTLS root.** It is hosted by the
  node the Raft transport replicates — using it would be circular
  (`ClusterConfig.RaftTLS` doc comment).
- **Exactly one redirect hop.** The SDK client follows a not-leader response
  once; a second one is returned to the caller rather than chased, so a
  leadership flap cannot loop.
- **The Unix socket transport never follows redirects** — a local socket
  client has no network credentials to re-present to a remote leader, so it
  surfaces the typed not-leader error instead.
- **`waitForClusterLeader` gates readiness only when `Cluster.Enabled`.**
  Standalone nodes never wait on a leader election.
- **Cluster status/membership reads never gate on `Clustered()`.** They are
  the sole servicer methods that degrade to a defined empty/standalone
  result instead of `xkms.ErrNotConfigured` — see "Exported surface" above.

## Error semantics

| Condition | Type / mechanism | Notes |
|---|---|---|
| `cluster.enabled` on a non-`raft` build | `ErrClusterRequiresRaftBuild` (`pkg/daemon/errors.go`) | "daemon: clustering requires building with -tags raft" |
| `cluster.enabled` with a non-`qrdb` storage backend | `Config.Validate` error | "cluster.enabled requires storage.backend \"qrdb\"" |
| `node_id` unset / `raft_address` unset / `peers` empty or malformed | `Config.Validate` error, or `*errs.Message` from `ClusterConfig.Members()` | e.g. `"cluster: peer %q is not in nodeID=address form"` |
| bootstrapping node's own `node_id` missing from `peers` (when `join=false`) | `Config.Validate` error | must list itself when bootstrapping |
| partial `raft_tls` (one or two of the three PEM paths set) | `ErrClusterRaftTLSIncomplete` (`pkg/config/config.go`) | all three or none |
| operator Raft TLS PEM file unreadable at boot | `*ErrRaftTLSRead{Field, Path, Err}` (`pkg/server/qrdb_node_cluster.go`) | files are read at boot, not at `Validate` time |
| no leader elected within 30s of boot | `*QRDBNodeError{Stage: "await cluster leader", ...}` (`pkg/server/qrdb_node.go`) | 250ms poll interval |
| write reaches a follower | `xkms.ErrNotLeader` / `AsNotLeader` (`pkg/xkms/errors.go`) | translated per transport, see api.md |
| membership mutation on a standalone node | HTTP 409 Conflict / gRPC `FailedPrecondition` (per the control-plane RPC, transport-native — not an xkms typed error) | no Raft group to reconfigure |
| REST cluster route with no `XKMSService` wired | `rest.ErrClusterNotConfigured` (503) (`pkg/api/rest/handlers_cluster.go`) | construction-order bug, not the standalone-node case (which never errors) |
| `ClusterStatus`/`ClusterMembers` underlying query fails on a clustered node | `*xkms.ClusterStatusError` / `*xkms.ClusterMembersError` (`pkg/xkms/errors.go`), each carrying `ShardID` and implementing `Unwrap() error` | mapped to HTTP 500 by `handleClusterError`, logged server-side |

## Configuration (`pkg/config/config.go:ClusterConfig`)

| Field | YAML Key | Env Var | Type | Description |
|-------|----------|---------|------|-------------|
| Enabled | `enabled` | `XKMS_CLUSTER_ENABLED` | bool | Turns on Raft clustering. Requires `Storage.Backend == "qrdb"`. |
| NodeID | `node_id` | `XKMS_CLUSTER_NODE_ID` | uint64 | This node's unique Raft replica ID within the shard. Must be non-zero and unique across the cluster. |
| ShardID | `shard_id` | `XKMS_CLUSTER_SHARD_ID` | uint64 | The Raft shard (group) identifier. Defaults to 1. |
| DeploymentID | `deployment_id` | (config only) | uint64 | Isolates clusters that share a network. Optional; defaults to 0. |
| RaftAddress | `raft_address` | `XKMS_CLUSTER_RAFT_ADDRESS` | string | This node's advertised address for Raft peer communication. |
| ListenAddress | `listen_address` | `XKMS_CLUSTER_LISTEN_ADDRESS` | string | The address to bind for Raft communication. Defaults to `RaftAddress`. |
| AdvertiseHost | `advertise_host` | (config only) | string | Host/IP clients use to reach this node's xkms APIs. Defaults to the host portion of `raft_address`. |
| Peers | `peers` | `XKMS_CLUSTER_PEERS` | string | Comma-separated `nodeID=address` list of initial members. |
| Join | `join` | `XKMS_CLUSTER_JOIN` | bool | `false` bootstraps a new cluster; `true` joins an existing one. |
| RaftTLS.{CACertFile,CertFile,KeyFile} | `raft_tls.*` | `XKMS_CLUSTER_RAFT_TLS_*` | string | Raft peer mTLS material; all three or none (`ErrClusterRaftTLSIncomplete` on a partial set). |
| RaftEnrollment.* | `raft_enrollment.*` | (config only, mostly) | — | Auto-provisioned Raft mTLS — see user.md. |

Environment variables follow the `XKMS_<PATH>` rule (nesting joined by
underscores). Confirmed in real deployment fixtures
(`test/integration/cluster/docker-compose.yml`):
`XKMS_CLUSTER_ENABLED`, `XKMS_CLUSTER_NODE_ID`, `XKMS_CLUSTER_SHARD_ID`,
`XKMS_CLUSTER_RAFT_ADDRESS`, `XKMS_CLUSTER_LISTEN_ADDRESS`,
`XKMS_CLUSTER_PEERS`, `XKMS_CLUSTER_JOIN`,
`XKMS_CLUSTER_RAFT_TLS_CA_CERT_FILE`, `_CERT_FILE`, `_KEY_FILE`.
`deployment_id`, `advertise_host`, and every `raft_enrollment.*` field are
config-file-only in the fixtures examined (no environment variable observed
in use), though the general `XKMS_<PATH>` rule would still resolve them if
set.

### Validation (`pkg/config`, `Config.Validate`, ~line 1579)

```go
if c.Cluster.Enabled {
	// ShardID defaults to 1 if zero.
	// storage.backend must equal "qrdb" (case-insensitive).
	// NodeID must be non-zero.
	// RaftAddress must be non-empty.
	// Peers must parse and be non-empty.
	// If !Join, Peers must include this node's own NodeID.
	// RaftTLS must be all-or-nothing (IsComplete()).
}
```

Raft mTLS provisioning precedence, highest first (`Server.resolveRaftMTLS`,
`pkg/server/qrdb_node_cluster.go`):

1. **Operator files** — `cluster.raft_tls.*` (all three set).
2. **TPM-attested ACME enroll-01** — `cluster.raft_enrollment.acme.enabled: true`,
   requires `raft_enrollment.key_backend: tpm2`. The runtime `TrustedCA` is
   the single cluster trust anchor; joining nodes prove identity via TPM
   attestation instead of receiving a shared CA key.
3. **Hardware node key** — `cluster.raft_enrollment.key_backend: tpm2` or
   `pkcs11` without ACME; the node key never leaves the device.
4. **Software auto-provisioned** (default) — the first node generates a
   dedicated self-signed cluster CA and serves a Noise NK bootstrap endpoint;
   joining nodes fetch it via `raft_enrollment.bootstrap` (Noise / SPKI /
   DANE / Direct — the same dispatch as
   [`../trust-bootstrap/`](../trust-bootstrap/architecture.md)).

Cluster CA key custody, at steady state (`raft_enrollment.ca_key_strategy`,
doc comment on `RaftEnrollmentConfig.CAKeyStrategy`, `pkg/config/config.go`;
full detail in [`ca-key-custody.md`](ca-key-custody.md)):

| Value | Custody model |
|---|---|
| `""` / `"barrier"` (default) | Software HA: the key is promoted into the replicated, **barrier-encrypted** datastore; every node loads and decrypts it with its own barrier, so any node can issue |
| `"hsm"` | Shared PKCS#11 HSM; key material never leaves it; every node signs through the same HSM by reference |
| `"tpm-kek"` | The replicated key is wrapped under a KEK derived from a cluster seed sealed to each node's own TPM, delivered via TPM credential activation during enrollment |

Cluster CA key protection at rest, before the datastore exists
(`raft_enrollment.ca_key_protection`, doc comment on
`RaftEnrollmentConfig.CAKeyProtection`):

| Value | Protection |
|---|---|
| `""` (auto) | TPM/HSM-sealed when available, else operator passphrase, else refused |
| `"tpm2"` / `"pkcs11"` | random keystore key sealed to the device, unattended |
| `"passphrase"` | PBES2 with `ca_key_passphrase` (supports `credential://`) |
| `"none"` | plaintext PKCS#8 — reported by `Config.ComplianceGaps`, so `cmd/xkmsd` refuses to start with it; reachable only by a program embedding `pkg/server` directly |

## Persistence

Every node's data is the same replicated `qrdb` datastore described in
[`../storage-engines/architecture.md`](../storage-engines/architecture.md);
clustering does not add a second store. The cluster CA's own bootstrap
keystore is the one exception — it must exist **before** the replicated
datastore does, so it lives node-local under
`<Storage.Path>/raft-tls` (software auto-provisioning) or
`<Storage.Path>/<clusterCACacheSubdir>` (ACME-attested mode), protected by
the seal strategies above rather than the barrier.

## Test strategy

- **Unit** — `pkg/config/cluster_test.go`; `pkg/server/cluster_advertise_test.go`,
  `cluster_ca_strategy_test.go`, `qrdb_node_cluster_test.go`,
  `qrdb_node_cluster_hw_test.go`, `qrdb_node_cluster_acme_test.go`,
  `node_seal_test.go`, `node_seal_simulator_test.go`,
  `tenant_node_barrier_test.go`; `pkg/daemon/node_standalone_test.go`,
  `node_cluster_test.go`; `pkg/xkms/servicer_cluster_test.go`
  (`ClusterStatus`/`ClusterMembers`, both the standalone-degradation and
  clustered paths, plus underlying-error mapping to the typed errors above);
  `pkg/api/rest/handlers_cluster_test.go` (handler success/error per route,
  standalone vs. clustered; RBAC denial (`TestClusterRoutes_RBACDenied`) and
  the positive RBAC control (`TestClusterRoutes_RBACRequiredPermission`)
  over the two GET routes only; and the `/auth/me` `capabilities.cluster`
  flag (`TestCapabilityFlags_Cluster`)); `cmd/xkmsctl/cluster_test.go`,
  `rebalance_test.go` (the qrdb-control-plane CLI path — see cli.md).
- **CI build-tag matrix** — the `build-raft` job (`.github/workflows/ci.yml`)
  builds and tests the `raft`-tagged binary across the codec tag matrix, so
  the clustered path is exercised on every change even though it is not the
  default build.
- **Integration** (`test/integration/cluster/`) — `cluster_test.go`,
  `cluster_cas_test.go`, `cluster_crypto_test.go`, `cluster_crypto_ops_test.go`,
  `cluster_resilience_test.go` (leader failover, node restart/rejoin),
  `standalone_test.go`, `cluster_rest_api_test.go` (the 3-node cluster and
  standalone harnesses, proving the REST surface's status/members agree
  with go-qrdb's own `/peers` admin-plane view); driven by
  `docker-compose.yml` (3 nodes) and `Dockerfile.xkmsd` (builds with
  `-tags "raft pkcs8 codec_cbor codec_json codec_msgpack"`).
- **Makefile target** — `integration-test-cluster`: "Run 3-node Raft cluster +
  standalone-server integration tests (crypto gen/sign/verify replication,
  public-key consistency, delete replication, leader failover, node
  restart/rejoin catch-up, standalone lifecycle)".

## Observability

Cluster startup and membership are logged
(`s.logger.Info("qrdb engine started in-process", "clustered", ...)`,
`pkg/server/qrdb_node.go`); a failed advertisement only warns, it does not
fail startup. There is no cluster-specific metrics surface beyond what
go-qrdb's own node exposes; xkms adds no additional instrumentation.
