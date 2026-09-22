# Clustering

Clustering enables high availability by replicating all datastore state across multiple xkms nodes via Raft. When enabled, xkms hosts an in-process go-qrdb clustered node so that keys, users, RBAC, custodian, shares, CA serials, revocations, audit events, and all other persistent state are replicated and available if any single node fails.

## What Clustering Does

A clustered xkms deployment runs a Raft consensus group where:

- All datastore mutations are replicated to every member.
- Reads can be served from any member.
- Write operations (key creation, CA signing, RBAC changes, etc.) must be sent to the Raft leader; followers will refuse writes with a "not leader" error.
- The cluster automatically elects a new leader if the current leader becomes unavailable.

Clustering is **not** required to use xkms; a single-node deployment works identically but has no redundancy.

## Build Requirement

Clustering is compiled in only with the `-tags raft` build tag:

```bash
go build -tags raft -o xkmsd ./cmd/xkmsd
```

A default build (without `-tags raft`) is **standalone-only**. If you attempt to start a standalone-built binary with `cluster.enabled: true`, it will immediately fail with:

```
error: clustering requires building xkms with -tags raft
```

Both builds run identically in single-node mode (the default). The raft tag adds clustering support but does not require it.

## Configuration

Cluster settings are configured via the `cluster:` block in `xkmsd.yaml` and overridden by `XKMS_CLUSTER_*` environment variables. Each setting maps to a go-qrdb Raft configuration parameter.

### Config Fields

| Field | YAML Key | Env Var | Type | Description |
|-------|----------|---------|------|-------------|
| Enabled | `enabled` | `XKMS_CLUSTER_ENABLED` | bool | Turns on Raft clustering. Requires Storage.Backend == "qrdb". |
| NodeID | `node_id` | `XKMS_CLUSTER_NODE_ID` | uint64 | This node's unique Raft replica ID within the shard. Must be non-zero and unique across the cluster. |
| ShardID | `shard_id` | `XKMS_CLUSTER_SHARD_ID` | uint64 | The Raft shard (group) identifier. Defaults to 1. All members of the same cluster must have the same ShardID. |
| DeploymentID | `deployment_id` | (config only) | uint64 | Isolates clusters that share a network. Optional; omit or set to 0 if not needed. Two clusters with different DeploymentIDs will not interfere. |
| RaftAddress | `raft_address` | `XKMS_CLUSTER_RAFT_ADDRESS` | string | This node's advertised address for Raft peer communication (e.g., "10.0.0.1:63001"). Must be reachable by all other cluster members. |
| ListenAddress | `listen_address` | `XKMS_CLUSTER_LISTEN_ADDRESS` | string | The address to bind for Raft communication. Defaults to RaftAddress. Use when the advertised address differs from the bind address (e.g., behind a load balancer). |
| AdvertiseHost | `advertise_host` | (config only) | string | Host or IP that clients use to reach **this node's xkms APIs**. Published into the cluster registry with the ports of the enabled protocols so a client can be redirected to the leader. Distinct from `server.host`, which is a bind address and is often a wildcard no client can dial. Defaults to the host portion of `raft_address`; set explicitly when the API and Raft planes are reached over different addresses (NAT, split networking). If no concrete host is available the node advertises nothing and clients fall back to the leader hint alone. |
| Peers | `peers` | `XKMS_CLUSTER_PEERS` | string | Comma-separated list of initial cluster members in `nodeID=address` format (e.g., `1=10.0.0.1:63001,2=10.0.0.2:63001,3=10.0.0.3:63001`). Must include this node's own NodeID and address when bootstrapping. |
| Join | `join` | `XKMS_CLUSTER_JOIN` | bool | If `true`, the node joins an existing cluster; if `false`, it bootstraps a new cluster. The first node to boot should have `join: false` and a complete Peers list; subsequent nodes should have `join: true`. |
| RaftTLS.CACertFile | `raft_tls.ca_cert_file` | `XKMS_CLUSTER_RAFT_CA_CERT` | string | Path to the PEM CA certificate used to verify Raft peer certificates. Enables mutual TLS on the inter-node Raft transport when all three `raft_tls.*` paths are set. |
| RaftTLS.CertFile | `raft_tls.cert_file` | `XKMS_CLUSTER_RAFT_CERT` | string | Path to this node's PEM Raft certificate. |
| RaftTLS.KeyFile | `raft_tls.key_file` | `XKMS_CLUSTER_RAFT_KEY` | string | Path to this node's PEM Raft private key. |
| RaftEnrollment.TrustDomain | `raft_enrollment.trust_domain` | (config only) | string | SPIFFE trust domain stamped into auto-provisioned node certificates. Defaults to `xkms.cluster`. |
| RaftEnrollment.KeyBackend | `raft_enrollment.key_backend` | (config only) | string | Crypto backend holding the node's Raft signing key: `tpm2`/`pkcs11` (hardware-resident) or empty (software, default). |
| RaftEnrollment.ACME.Enabled | `raft_enrollment.acme.enabled` | (config only) | bool | Switches node-certificate issuance to TPM-attested ACME enroll-01 with the runtime TrustedCA as the single cluster trust anchor. |
| RaftEnrollment.ACME.DirectoryURL | `raft_enrollment.acme.directory_url` | (config only) | string | ACME directory of an existing node. Required on joining nodes; ignored on the first node (issues in-process). |
| RaftEnrollment.ClusterCACN | `raft_enrollment.cluster_ca_cn` | (config only) | string | CN of the dedicated cluster intermediate that issues node transport certificates. Empty uses the CA's default issuing identity. |
| RaftEnrollment.CAKeyProtection | `raft_enrollment.ca_key_protection` | (config only) | string | Protection at rest for the node-local cluster CA keystore: `""` (auto), `tpm2`/`pkcs11`, `passphrase`, or `none` (insecure). |
| RaftEnrollment.CAKeyPassphrase | `raft_enrollment.ca_key_passphrase` | (config only) | `types.SecretValue` | Operator passphrase for `passphrase` protection (and auto fallback). A plain string or a `credential://` reference in YAML either way; the resolved plaintext is held in protected memory, never a plain Go string — see [xkmsd-configuration](../xkmsd-configuration/engineering.md#decoding-notes). |
| RaftEnrollment.CAKeyStrategy | `raft_enrollment.ca_key_strategy` | (config only) | string | Cluster CA key custody so any node can issue: `""`/`barrier` (replicated barrier-encrypted, default), `hsm` (shared PKCS#11), `tpm-kek` (planned). |

### Example: 3-Node Cluster via YAML

```yaml
cluster:
  enabled: true
  node_id: 1
  shard_id: 1
  raft_address: "10.0.0.1:63001"
  listen_address: "10.0.0.1:63001"
  # Optional: host clients use to reach THIS node's xkms APIs. Defaults to the
  # host portion of raft_address; set it when the API and Raft planes are
  # reached over different addresses.
  advertise_host: "10.0.0.1"
  peers: "1=10.0.0.1:63001,2=10.0.0.2:63001,3=10.0.0.3:63001"
  join: false  # First node bootstraps
```

The second and third nodes would use identical YAML except:

```yaml
cluster:
  node_id: 2  # or 3 for node3
  advertise_host: "10.0.0.2"  # or 10.0.0.3
  join: true
```

### Example: 3-Node Cluster via Environment Variables

Node 1 (bootstrapper):

```bash
export XKMS_CLUSTER_ENABLED=true
export XKMS_CLUSTER_NODE_ID=1
export XKMS_CLUSTER_SHARD_ID=1
export XKMS_CLUSTER_RAFT_ADDRESS=node1:63001
export XKMS_CLUSTER_LISTEN_ADDRESS=node1:63001
export XKMS_CLUSTER_PEERS=1=node1:63001,2=node2:63001,3=node3:63001
export XKMS_CLUSTER_JOIN=false
xkmsd
```

Node 2 (joiner):

```bash
export XKMS_CLUSTER_ENABLED=true
export XKMS_CLUSTER_NODE_ID=2
export XKMS_CLUSTER_SHARD_ID=1
export XKMS_CLUSTER_RAFT_ADDRESS=node2:63001
export XKMS_CLUSTER_LISTEN_ADDRESS=node2:63001
export XKMS_CLUSTER_PEERS=1=node1:63001,2=node2:63001,3=node3:63001
export XKMS_CLUSTER_JOIN=true
xkmsd
```

Node 3 (joiner):

```bash
export XKMS_CLUSTER_ENABLED=true
export XKMS_CLUSTER_NODE_ID=3
export XKMS_CLUSTER_SHARD_ID=1
export XKMS_CLUSTER_RAFT_ADDRESS=node3:63001
export XKMS_CLUSTER_LISTEN_ADDRESS=node3:63001
export XKMS_CLUSTER_PEERS=1=node1:63001,2=node2:63001,3=node3:63001
export XKMS_CLUSTER_JOIN=true
xkmsd
```

## Bootstrap vs. Join

When forming a cluster, exactly one node must bootstrap the shard:

- **Bootstrapper** (join=false): Boot first with a complete Peers list. It forms the initial Raft group.
- **Joiners** (join=true): Boot after the bootstrapper is healthy. They discover the shard and replicate state from the leader.

If multiple nodes try to bootstrap simultaneously (join=false), the cluster may not form correctly. If all nodes set join=true, they will block waiting for a leader that never appears.

For most deployments, start node1 with join=false, then bring up node2 and node3 with join=true.

## Raft Peer Communication

Raft uses a separate network channel for consensus messages, distinct from xkms's client APIs. The `raft_address` and `listen_address` settings control this channel:

- **raft_address**: The address advertised to other Raft members. It must be reachable from all cluster members.
- **listen_address**: The address the node binds to for Raft. Usually the same as raft_address, but may differ if behind a load balancer or running in a containerized environment.

### Raft mTLS

The inter-node Raft transport supports mutual TLS. Set all three `raft_tls.*`
paths (or the `XKMS_CLUSTER_RAFT_CA_CERT` / `_CERT` / `_KEY` environment
variables) to encrypt and mutually authenticate Raft peer traffic:

```yaml
cluster:
  enabled: true
  # ... node_id, peers, etc ...
  raft_tls:
    ca_cert_file: /etc/xkms/raft-ca.pem
    cert_file: /etc/xkms/raft-cert.pem
    key_file: /etc/xkms/raft-key.pem
```

mTLS is enabled only when all three paths are present; a partially configured
`raft_tls` block (one or two of the three paths) is a startup error
(`ErrClusterRaftTLSIncomplete`). The PEM material must be operator-supplied and
**must not** be the runtime xkms CA: that CA is hosted by the very node the Raft
transport replicates, so binding Raft mTLS to it would be circular.

When `raft_tls` is unset, Raft peers communicate without TLS. That is suitable
only for a trusted private network; for untrusted networks configure `raft_tls`
or restrict Raft traffic with firewall rules to authorized members.

### Auto-provisioned Raft mTLS (`raft_enrollment`)

Supplying `raft_tls.*` files by hand does not scale past a few nodes. The
`raft_enrollment` block instead provisions inter-node mTLS **touch-free**: the
first node stands up a cluster CA and every node obtains its own transport
certificate automatically. Provisioning follows a fixed precedence, highest
first:

1. **Operator files** — `raft_tls.*` set (above). Always wins when present.
2. **ACME-attested** — `raft_enrollment.acme.enabled: true`. TPM-attested
   enroll-01 with the runtime TrustedCA as the single cluster trust anchor
   (below).
3. **Hardware node key** — `raft_enrollment.key_backend: tpm2|pkcs11`. The node
   key is generated inside the device and never leaves it; the transport uses a
   signer-backed certificate.
4. **Software node key** — the default. The first node generates the cluster CA
   and serves a Noise NK bootstrap endpoint; joining nodes fetch the CA bundle
   over the configured `raft_enrollment.bootstrap` method (Noise NK / SPKI /
   DANE / Direct) and enroll.

This is the same `pkg/trust/clusterca` provisioning toolkit every product in the
stack consumes through the go-xkms SDK (`sdk/go/clusterca`), so xkmsd,
quicbaasd, and downstream nodes provision cluster mTLS identically.

### ACME-attested cluster enrollment

With `raft_enrollment.acme.enabled: true`, node certificates are issued through
**TPM-attested ACME enroll-01** rather than a shared CA key:

- The **first node** pre-stages the CA hierarchy from the `ca` configuration
  (the datastore does not exist yet), issues its own transport leaf, and caches
  the full CA certificate set so a later boot adopts it without forking a second
  root.
- **Joining nodes** fetch the trust anchor via `raft_enrollment.bootstrap`, then
  prove their identity with TPM attestation to the existing node's ACME
  directory (`raft_enrollment.acme.directory_url`). No shared CA private key is
  ever distributed.
- Each node certificate carries its **SPIFFE identity**
  (`spiffe://<trust-domain>/node/<raft-address>`) as a URI SAN, stamped by the
  server-side pre-sign hook from the TCG permanent identifier the joiner
  presents.
- Transport issuance is routed through a **dedicated cluster intermediate**
  (`raft_enrollment.cluster_ca_cn`) — root signs intermediates only — the
  recommended FedRAMP/PCI posture. When unset, the CA's default issuing identity
  is used.

```yaml
cluster:
  enabled: true
  node_id: 1
  raft_address: 10.0.0.1:63001
  peers: "1=10.0.0.1:63001,2=10.0.0.2:63001,3=10.0.0.3:63001"
  raft_enrollment:
    trust_domain: prod.cluster
    acme:
      enabled: true
      # directory_url is required on JOINING nodes only; the first node issues
      # in-process from its local TrustedCA.
      directory_url: https://10.0.0.1:8443/acme/directory
    cluster_ca_cn: "Cluster Intermediate CA"   # dedicated transport intermediate
    ca_key_protection: ""                        # auto: TPM/HSM → passphrase → refuse
    advertise_noise_host: 10.0.0.1               # bind host for the enrollment listener
    advertise_noise_port: 63006                  # its TCP port (default)
    bootstrap:
      # how a joiner fetches the trust anchor from an existing node
      spki_pin: <base64 SPKI pin>
      server_addr: 10.0.0.1:8443
```

#### The enrollment listener's bind host

The first node of a multi-node cluster serves the Noise NK bootstrap endpoint
that joiners fetch the trust anchor from. That endpoint is the ONE socket a
joining node reaches before it holds any credential, so `clusterenroll` refuses
to pick a bind host for it: a node contained to a single interface must not have
its enrollment listener quietly opened on every interface, and only the
configuration layer knows which containment the operator asked for.

`raft_enrollment.advertise_noise_host` is that bind host, in the same sense as
`server.host`, and it **defaults to `server.host`**. It is not
`cluster.advertise_host`, which is the address clients dial and is deliberately
not a bind address. A first node whose `server.host` is empty and that sets no
`advertise_noise_host` refuses to start the advertiser rather than binding a
wildcard.

#### Cluster CA key protection

The node-local cluster CA signing keystore must exist **before** the replicated
datastore, so it lives outside the storage barrier and is protected instead by
the stack's standard seal strategies via `raft_enrollment.ca_key_protection`:

| Value | Protection at rest |
| --- | --- |
| `""` (auto) | TPM/HSM-sealed when available, else operator passphrase, else **refused** |
| `tpm2` / `pkcs11` | random keystore key sealed to the TPM/HSM (unattended) |
| `passphrase` | PBES2 with `raft_enrollment.ca_key_passphrase` (supports `credential://`) |
| `none` | plaintext PKCS#8 — reported by `config.ComplianceGaps`, so `xkmsd` refuses to start with it; reachable only by a program embedding `pkg/server` directly |

Auto mode never silently falls back to plaintext: with no hardware and no
passphrase it refuses to start (surfaced by `config.ComplianceGaps`). This
mirrors the barrier's secure-by-default posture — `xkmsd` never writes the
cluster CA private key to disk in the clear, and there is no override.

#### Cluster CA key custody — which nodes can issue (`ca_key_strategy`)

`ca_key_protection` above protects the *bootstrap* keystore. Which nodes can
issue node certificates at steady state — and where the signing key lives — is
governed by `raft_enrollment.ca_key_strategy`, a pluggable custody strategy so
every product (xkmsd, quicbaasd) behaves identically:

| Value | Custody model |
| --- | --- |
| `""` / `barrier` | **Default, software HA.** The first node bootstraps the CA key node-local (so it can issue before the datastore exists), then *promotes* it into the qrdb-routed **replicated, barrier-encrypted** datastore. Every node loads it — each decrypting with its own barrier (sealed to its own TPM/passphrase) — so **any node can issue**. The CA key exists barrier-encrypted on every node. Set a cluster `ca_key_passphrase` so the promoted key blob is decryptable cluster-wide. |
| `hsm` | **Shared PKCS#11 HSM.** The CA key is generated inside a shared HSM under a fixed label; every node signs through the same HSM by reference. **Key material never leaves the HSM** and there is no promotion. FIPS-grade. Requires all nodes to reach the same HSM (network HSM / shared partition) and the CA keystore type to be `pkcs11`. |
| `tpm-kek` | **TPM-sealed cluster seed, hardware-rooted without a shared HSM.** The replicated CA key is wrapped under a KEK derived from a cluster seed. The bootstrap node generates the seed and seals it to its local TPM; each joining node receives it via **TPM credential activation** during attested enrollment (so it never transits any channel in the clear — only the genuine target TPM can recover it) and seals it to its own TPM. Delivery is a **post-enrollment authenticated fetch**: after enrolling, a node presents its cluster-CA-signed cert over mTLS to an existing node's secret-delivery endpoint and receives the credential-wrapped seed. Requires every node to have a TPM. |

The `tpm-kek` seed delivery is intentionally **decoupled** from enroll-01: the enrollment protocol stays generic (it knows only the pre-sign hook seam), and a strategy that needs to deliver material implements the optional `EnrollmentSecretStrategy` interface, discovered by type assertion. A neutral `NodeSecretProvider` produces the wrapped material and a reusable `SecretDeliveryService` serves the fetch — so quicbaas and trusted-platform reuse the identical mechanism.

The strategy is the single seam every composition root consumes via
`sdk/go/clusterca` (`NewClusterCAKeyStrategy`, `ClusterCAKeyStrategy`), so the
custody model is a one-line config choice rather than product-specific code. For
the internal design — the strategy seam, the three custody models, and the
decoupled TPM seed delivery — see [Cluster CA Key Custody
Architecture](ca-key-custody.md).

### enroll-01 vs. endorse-01 node admission

Two distinct admission models are available; enable whichever the deployment
needs via the ACME challenge configuration:

- **enroll-01** — TPM-attested **self-enrollment**. The node proves TPM
  residency of its key; the attestation itself is the gate. Suitable for
  touch-free scale-out on a trusted bootstrap network.
- **endorse-01** — **EAB-admin-gated** admission. An operator holding an
  external-account-binding credential explicitly authorizes a specific node
  (matched by device identifier) before it can enroll. Enable with
  `endorse_eab_required` on the ACME server.

Both issue through the same cluster intermediate when `cluster_ca_cn` is set. A
deployment that requires every node to be admin-approved enables endorse-01 only.

## Client Request Routing

xkms client APIs (REST, gRPC, QUIC, Unix socket) operate independently of Raft:

- **Read operations** (Get, List, etc.) succeed on any member.
- **Write operations** (CreateKey, SignCSR, SetPin, etc.) require the leader. A
  write sent to a follower is rejected with a typed not-leader error that names
  the current leader so the client can retry against it.

The not-leader rejection is surfaced per protocol:

- **REST**: HTTP `421 Misdirected Request`. The leader is echoed in the
  `X-XKMS-Leader-ID`, `X-XKMS-Leader-Address` and `X-XKMS-Leader-API-Address`
  response headers and in the JSON body (`{"error": ..., "shard_id": ...,
  "leader_id": ..., "leader_address": ..., "leader_api_address": ...}`).
- **gRPC / Unix**: `FailedPrecondition` with an `ErrorInfo` detail whose
  `Reason` is `NOT_LEADER`, `Domain` is `xkms.cluster`, and `Metadata` carries
  `shard_id`, `leader_id`, `leader_address` and `leader_api_address`.
- **QUIC**: same `421 Misdirected Request` mapping as REST (HTTP/3).

`leader_address` is the leader's **Raft peer** address, which is not dialable as
an API endpoint. `leader_api_address` is the address to dial to reach the leader
over the **same API protocol the failed request used** — see
[Leader redirect](#leader-redirect).

### Leader redirect

xkms **redirects the client** to the leader rather than forwarding the request
server-side. The SDK follows that redirect automatically, so a write sent to a
follower still succeeds from the caller's point of view.

This is a security decision, not just a simplicity one. xkms identities are
bound to the caller's credentials — an mTLS client certificate (matched by its
SPKI thumbprint) or a session token. A follower does not hold the caller's
private key, so it cannot re-present the caller's identity to the leader.
Forwarding server-side would therefore require either dialing the leader with
the *node's* own identity while asserting "I am acting for user X" — an
impersonation channel, where compromising one node forges any identity
cluster-wide — or a full delegation/token-exchange protocol.

With a redirect the caller re-presents its **own** credentials to the leader.
The leader runs exactly the same authenticate-then-authorize path it runs for a
directly-dialed request, so the caller's identity and permissions are enforced
at the leader by construction and are never delegated in transit.

Redirect behaviour:

- exactly **one** hop — a second not-leader response is returned to the caller
  rather than chased, so a leadership flap cannot cause a redirect loop;
- the retry reuses the same TLS configuration and credentials, and only the
  scheme and host change; path, query, headers and body are preserved;
- the client's configured address is never permanently repointed, so a
  transient leadership change does not stick;
- a not-leader response carrying **no** API address is returned to the caller
  unchanged — the pre-advertisement behaviour;
- the **Unix socket** transport does not follow redirects. A local socket client
  has no network credentials and the leader is remote, so it surfaces the typed
  not-leader error instead of hanging.

### Advertised API endpoints

For a redirect to be actionable, a client must be able to turn "the leader is
replica N" into an address. Each node publishes its own client-facing API
endpoints into the cluster registry, keyed by protocol:

```yaml
cluster:
  advertise_host: "10.0.0.1"   # host clients use to reach THIS node's APIs
```

- Endpoints are a **protocol-keyed set** (`rest`, `grpc`, `quic`, `mcp`), not a
  single address, because a redirected client must reach the leader over the
  same protocol it is already speaking: codec, streaming semantics, TLS
  configuration and credential presentation all differ per protocol. Omitting a
  protocol is how a node states that it does not serve it.
- Values come from the node's **own configuration** — `advertise_host` plus the
  configured port of each enabled protocol. They are never derived from the Raft
  address by port arithmetic, which would break under NAT, split networking and
  non-default ports.
- When `advertise_host` is unset, the host portion of `raft_address` is used,
  since that is by definition an address peers already reach this node on. If
  neither yields a concrete host (for example a wildcard bind address), the node
  advertises **nothing** rather than an address no client can dial.
- The Unix socket is never advertised: a socket path is meaningful only on the
  node that owns it.
- Advertisement is **backward compatible**. A replica that advertises nothing —
  because it predates this feature, has no advertise host, or serves no remote
  protocol — is listed normally with no endpoints, and clients fall back to
  today's behaviour. Membership listing never fails because endpoint discovery
  did.

`xkmsctl cluster members` shows the advertised endpoints under each replica.

## Cluster Inspection (CLI)

The read-only cluster surface is exposed over REST, gRPC and the Unix socket,
and through `xkmsctl`:

```bash
# Raft leadership status for the server's configured shard
xkmsctl cluster status

# Raft replicas for the configured shard, with each replica's advertised
# API endpoints
xkmsctl cluster members

# JSON output and an explicit shard
xkmsctl cluster status --shard 1 --output json
xkmsctl cluster members --shard 1 --output json
```

These map to `GET /api/v1/cluster/status` and `GET /api/v1/cluster/members`.
When RBAC is enabled, both require the `backends:read` permission. A standalone
(non-clustered) server answers both uniformly: `status` reports a single-node,
non-clustered result (the node is its own leader) and `members` returns an empty
set, so the commands work whether or not clustering is enabled.

## Membership Management (CLI)

Replicas can be added to and removed from the shard's Raft group at runtime:

```bash
# Add a replica: <replica-id> <raft-address>
xkmsctl cluster add 2 10.0.0.2:63001

# Remove a replica
xkmsctl cluster remove 2

xkmsctl cluster add 3 node3.example.com:63001 --output json
```

These map to `POST /api/v1/cluster/members` and
`DELETE /api/v1/cluster/members/{replicaID}`, and to the `AddClusterReplica` /
`RemoveClusterReplica` gRPC RPCs.

Notes:

- **Privileged and fail-closed.** Membership mutation is authorized against the
  canonical go-qrdb membership permissions — `admin:add_member` and
  `admin:remove_member` — the same permissions qrdb enforces on its own control
  plane. If no authorizer is configured on a network listener, the request is
  **denied**; a mutation endpoint is never silently open. The Unix socket is the
  one deliberate exception and declares its local-IPC trust explicitly, since
  its trust boundary is the filesystem socket mode.
- **Idempotent.** Adding a replica that is already a member, or removing one
  that is already absent, succeeds without changing the configuration, so both
  commands are safe to retry.
- **Rejected on a standalone node.** There is no Raft group to reconfigure, so
  the request fails explicitly (HTTP `409 Conflict` / gRPC `FailedPrecondition`)
  rather than silently succeeding.
- The Raft address is the new replica's **peer** address (`host:port`) on the
  consensus plane, not an API address. A replica ID of `0` is rejected: Raft
  reserves it to mean "no replica".
- Removing a replica does not stop the process running it; shut that node down
  separately.

## Storage Backend

Clustering requires the embedded "qrdb" storage backend. The configuration must include:

```yaml
storage:
  backend: qrdb
  path: /var/lib/xkms/data
```

The `path` field specifies the directory where the PebbleDB Raft log and data are stored. Each node must have its own isolated data directory.

## Validation

xkms validates the cluster configuration at startup:

- Enabled=true requires NodeID > 0, RaftAddress is not empty, Peers is not empty, and Storage.Backend=="qrdb".
- Peers must be parseable as `nodeID=address` entries. Malformed entries cause a startup failure.
- DeploymentID is optional and defaults to 0.
- ShardID defaults to 1 if omitted.

## Monitoring and Debugging

When clustering is enabled, xkms logs cluster startup and election events:

```
time=2026-06-08T10:15:30Z level=info msg="Hosting clustered qrdb engine via NewClusteredNode" node_id=1 shard_id=1 raft_address=node1:63001 members=3 join=false
```

Look for "raft" in logs to see leader elections, membership changes, and replication status.

The CLI and SDKs can be used to verify cluster health: a healthy cluster responds to read operations on all members and write operations on the leader.
