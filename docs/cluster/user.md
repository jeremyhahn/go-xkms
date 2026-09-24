---
status: current
last_verified: 2026-09-24
---

# Clustering — User Guide

Clustering enables high availability by replicating all datastore state
across multiple xkms nodes via Raft. When enabled, xkms hosts an in-process
go-qrdb clustered node so that keys, users, RBAC, custodian, shares, CA
serials, revocations, audit events, and all other persistent state are
replicated and available if any single node fails.

A clustered xkms deployment runs a Raft consensus group where:

- All datastore mutations are replicated to every member.
- Reads can be served from any member.
- Write operations (key creation, CA signing, RBAC changes, etc.) must be
  sent to the Raft leader; followers refuse writes with a "not leader" error
  and the client is redirected automatically (see `docs/cluster/architecture.md`).
- The cluster automatically elects a new leader if the current leader
  becomes unavailable.

Clustering is **not** required to use xkms; a single-node deployment works
identically but has no redundancy. You can check either way — via the web
console's Cluster page or `xkmsctl cluster status`, see
`docs/cluster/cli.md` — which reports a "standalone" result on a
non-clustered node rather than an error.

## Build requirement

Clustering is compiled in only with the `-tags raft` build tag:

```bash
go build -tags raft -o xkmsd ./cmd/xkmsd
```

A default build (without `-tags raft`) is **standalone-only**. Starting a
standalone-built binary with `cluster.enabled: true` fails immediately with:

```
error: clustering requires building xkms with -tags raft
```

Both builds run identically in single-node mode (the default).

## Configuration

Cluster settings are configured via the `cluster:` block in `xkmsd.yaml` and
overridden by `XKMS_CLUSTER_*` environment variables. See
`docs/cluster/engineering.md` for the complete field reference.

### Example: 3-node cluster via YAML

```yaml
cluster:
  enabled: true
  node_id: 1
  shard_id: 1
  raft_address: "10.0.0.1:63001"
  listen_address: "10.0.0.1:63001"
  # Optional: host clients use to reach THIS node's xkms APIs. Defaults to
  # the host portion of raft_address; set it when the API and Raft planes
  # are reached over different addresses.
  advertise_host: "10.0.0.1"
  peers: "1=10.0.0.1:63001,2=10.0.0.2:63001,3=10.0.0.3:63001"
  join: false  # First node bootstraps
```

The second and third nodes use identical YAML except:

```yaml
cluster:
  node_id: 2  # or 3 for node3
  advertise_host: "10.0.0.2"  # or 10.0.0.3
  join: true
```

### Example: 3-node cluster via environment variables

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

Node 2 and node 3 (joiners) use the same variables with their own `NODE_ID`,
`RAFT_ADDRESS`/`LISTEN_ADDRESS`, and `JOIN=true`.

## Bootstrap vs. join

When forming a cluster, exactly one node must bootstrap the shard:

- **Bootstrapper** (`join=false`): boots first with a complete `peers` list.
  It forms the initial Raft group.
- **Joiners** (`join=true`): boot after the bootstrapper is healthy. They
  discover the shard and replicate state from the leader.

If multiple nodes try to bootstrap simultaneously (`join=false`), the
cluster may not form correctly. If all nodes set `join=true`, they block
waiting for a leader that never appears. For most deployments, start node 1
with `join=false`, then bring up node 2 and node 3 with `join=true`.

## Raft peer communication

Raft uses a separate network channel for consensus messages, distinct from
xkms's client APIs. `raft_address` is the address advertised to other Raft
members; `listen_address` is the address the node binds to (usually the
same, but may differ behind a load balancer or in a container).

### Raft mTLS

Set all three `raft_tls.*` paths (or the corresponding `XKMS_CLUSTER_RAFT_TLS_*`
environment variables) to encrypt and mutually authenticate Raft peer
traffic:

```yaml
cluster:
  enabled: true
  # ... node_id, peers, etc ...
  raft_tls:
    ca_cert_file: /etc/xkms/raft-ca.pem
    cert_file: /etc/xkms/raft-cert.pem
    key_file: /etc/xkms/raft-key.pem
```

mTLS is enabled only when all three paths are present; a partially
configured `raft_tls` block is a startup error. The PEM material must be
operator-supplied and **must not** be the runtime xkms CA: that CA is hosted
by the very node the Raft transport replicates, so binding Raft mTLS to it
would be circular. When `raft_tls` is unset, Raft peers communicate without
TLS — suitable only for a trusted private network.

### Auto-provisioned Raft mTLS (`raft_enrollment`)

Supplying `raft_tls.*` files by hand does not scale past a few nodes. The
`raft_enrollment` block instead provisions inter-node mTLS touch-free: the
first node stands up a cluster CA and every node obtains its own transport
certificate automatically, in precedence order: operator files
(`raft_tls.*`, above) → ACME-attested → hardware node key
(`raft_enrollment.key_backend: tpm2|pkcs11`) → software node key (default,
Noise NK / SPKI / DANE / Direct bootstrap). This is the same
`pkg/trust/clusterca` toolkit every product in the stack consumes through
`sdk/go/clusterca`.

#### ACME-attested cluster enrollment

With `raft_enrollment.acme.enabled: true`, node certificates are issued
through TPM-attested ACME enroll-01 rather than a shared CA key: the first
node pre-stages the CA hierarchy and issues its own transport leaf; joining
nodes fetch the trust anchor via `raft_enrollment.bootstrap`, then prove
their identity with TPM attestation to the existing node's ACME directory.
No shared CA private key is ever distributed.

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
      directory_url: https://10.0.0.1:8443/acme/directory  # joining nodes only
    cluster_ca_cn: "Cluster Intermediate CA"
    ca_key_protection: ""   # auto: TPM/HSM -> passphrase -> refuse
    advertise_noise_host: 10.0.0.1
    advertise_noise_port: 63006
    bootstrap:
      spki_pin: <base64 SPKI pin>
      server_addr: 10.0.0.1:8443
```

Two admission models are available via the ACME challenge configuration:
**enroll-01** (TPM-attested self-enrollment, touch-free) and **endorse-01**
(EAB-admin-gated: an operator explicitly authorizes each node). See
`docs/cluster/ca-key-custody.md` for the cluster CA key protection and
custody-strategy options (`ca_key_protection`, `ca_key_strategy`).

## Storage backend

Clustering requires the embedded "qrdb" storage backend:

```yaml
storage:
  backend: qrdb
  path: /var/lib/xkms/data
```

`path` is the directory where the PebbleDB Raft log and data are stored.
Each node must have its own isolated data directory.

## Checking cluster status

```bash
# CLI (drives qrdb's control plane directly over gRPC/Unix socket)
xkmsctl cluster status
xkmsctl cluster members
```

The embedded web console's **Cluster** page shows the same read-only status
and membership (over the REST API — see `docs/cluster/api.md`) once signed
in, when the node is clustered; a standalone deployment hides the nav entry
by default but the page still renders a "standalone" result if visited
directly.

Membership changes (`xkmsctl cluster add`/`remove`) are performed over the
Raft admin plane only — see `docs/cluster/cli.md` — and are intentionally
not exposed as a button in the web console.

## Monitoring and debugging

When clustering is enabled, xkms logs cluster startup and election events:

```
time=2026-06-08T10:15:30Z level=info msg="Hosting clustered qrdb engine via NewClusteredNode" node_id=1 shard_id=1 raft_address=node1:63001 members=3 join=false
```

Look for "raft" in logs to see leader elections, membership changes, and
replication status. A healthy cluster responds to read operations on all
members and write operations on the leader.
