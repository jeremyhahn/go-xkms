# Clustering — Engineering Contract

> **Status: NORMATIVE** · Feature: `clustering` · Repo: `go-xkms` · Last verified: 2026-09-24

## Exported surface

### Config — `pkg/config/config.go`

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
// !raft build (node_standalone.go)
func NewNode(ctx context.Context, opts *Options) (*Result, error) // always standalone; ErrClusterRequiresRaftBuild if opts.Cluster.Enabled

// raft build (node_cluster.go)
func NewNode(ctx context.Context, opts *Options) (*Result, error) // standalone if !opts.Cluster.Enabled, else qrdbnode.NewClusteredNode
```

### `pkg/server` — the xkmsd-specific composition

```go
func (s *Server) buildXKMSQRDBConfig() *qrdbsdk.DaemonConfig       // qrdb_node.go
func (s *Server) initEmbeddedQRDBNode() error                      // qrdb_node.go
func (s *Server) newQRDBNode(qcfg, serverOpts, nodeOpts) (*qrdbnode.Node, error) // build-tag specific
func (s *Server) waitForClusterLeader() error                      // qrdb_node.go
func (s *Server) resolveRaftMTLS(ctx, members) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error) // raft build only, qrdb_node_cluster.go
func (s *Server) registerQRDBControlPlane(gs *grpc.Server)         // qrdb_control_plane.go
```

### Not-leader translation — `pkg/xkms/errors.go`

```go
type ErrNotLeader struct {
	ShardID, LeaderID uint64
	LeaderAddress     string // Raft peer address — NOT dialable as an API endpoint
	LeaderAPIAddress  string // dialable address for the SAME protocol the failed request used
}
func AsNotLeader(err error) (*ErrNotLeader, bool)
```

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

## Configuration

See architecture.md for the config struct and engineering.md's Exported
surface above for every field and its yaml tag. `Config.Validate` additions
specific to clustering (`pkg/config/config.go`, ~line 1579):

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
doc comment on `RaftEnrollmentConfig.CAKeyStrategy`, `pkg/config/config.go`):

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
  `tenant_node_barrier_test.go`; `pkg/daemon/node_standalone_test.go`.
- **CI build-tag matrix** — the `build-raft` job (`.github/workflows/ci.yml`)
  builds and tests the `raft`-tagged binary across the codec tag matrix, so
  the clustered path is exercised on every change even though it is not the
  default build.
- **Integration** (`test/integration/cluster/`) — `cluster_test.go`,
  `cluster_cas_test.go`, `cluster_crypto_test.go`, `cluster_crypto_ops_test.go`,
  `cluster_resilience_test.go` (leader failover, node restart/rejoin),
  `standalone_test.go`; driven by `docker-compose.yml` (3 nodes) and
  `Dockerfile.xkmsd` (builds with `-tags "raft pkcs8 codec_cbor codec_json codec_msgpack"`).
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
