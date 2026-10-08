# Clustering — User Guide

> **Status: NORMATIVE** · Feature: `clustering` · Repo: `go-xkms` · Last verified: 2026-10-07

## What clustering gets you

Multiple `xkmsd` nodes sharing one replicated datastore: keys, users, CA
serials, and everything else survive the loss of any single node, and reads
succeed against any member. It is entirely optional — a single node works
identically, just without redundancy.

## Before you start: you need a different binary

Clustering is **not** in the default build. If you `make build` (or run a
pre-built `xkmsd`), setting `cluster.enabled: true` fails immediately:

```
error: clustering requires building xkms with -tags raft
```

Build it yourself:

```bash
go build -tags raft -o xkmsd ./cmd/xkmsd
```

A `raft`-tagged binary still runs single-node by default — the tag only adds
the capability, it does not turn clustering on.

## Bootstrapping a 3-node cluster

Exactly one node bootstraps (`join: false`, with the complete peer list);
the rest join (`join: true`) after it is healthy.

### Via YAML

Node 1 (bootstrapper):

```yaml
storage:
  backend: qrdb
  path: /var/lib/xkms/data

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
  # Required on every multi-node replica: go-quicraft admits a Raft member by
  # its identity and nothing else. "spki:" + hex SHA-256 of each OTHER
  # member's Raft certificate SubjectPublicKeyInfo (this node's own entry is
  # derived from its certificate). A bootstrapping node names every initial
  # member; a joining node at least one existing member.
  member_identities: "2=spki:936038a9…,3=spki:c01d77e2…"
  join: false  # First node bootstraps
```

Compute an identity from a member's Raft certificate with
`qrdbd node-identity` (given the certificate file), or with OpenSSL:

```bash
openssl x509 -in node2.crt -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
```

Nodes 2 and 3 use identical YAML except:

```yaml
cluster:
  node_id: 2  # or 3 for node3
  advertise_host: "10.0.0.2"  # or 10.0.0.3
  join: true
```

`storage.path` must be a separate, node-local directory on every node —
never shared or NFS-mounted.

### Via environment variables

Each `XKMS_CLUSTER_*` variable below is an instance of the generic
`XKMS_<SECTION>_<KEY>` environment binding (`pkg/config/load.go:175-182`,
`SetEnvPrefix("XKMS")` + `AutomaticEnv`) applied to `ClusterConfig`'s
`cluster.*` keys (`pkg/config/config.go:680-726`) — `XKMS_CLUSTER_ENABLED`
reads `cluster.enabled`, `XKMS_CLUSTER_NODE_ID` reads `cluster.node_id`, and
so on. Environment variables take precedence over the config file; see
[`../xkmsd-configuration/architecture.md`](../xkmsd-configuration/architecture.md)
for the full precedence order.

Node 1 (bootstrapper):

```bash
export XKMS_CLUSTER_ENABLED=true
export XKMS_CLUSTER_NODE_ID=1
export XKMS_CLUSTER_SHARD_ID=1
export XKMS_CLUSTER_RAFT_ADDRESS=node1:63001
export XKMS_CLUSTER_LISTEN_ADDRESS=node1:63001
export XKMS_CLUSTER_PEERS=1=node1:63001,2=node2:63001,3=node3:63001
export XKMS_CLUSTER_MEMBER_IDENTITIES=2=spki:936038a9…,3=spki:c01d77e2…
export XKMS_CLUSTER_JOIN=false
xkmsd
```

Nodes 2 and 3: identical, with their own `NODE_ID`, `RAFT_ADDRESS`,
`LISTEN_ADDRESS`, and `XKMS_CLUSTER_JOIN=true`. The config file itself
(`storage.backend: qrdb` is required) can be shared across all three nodes
unchanged, with only the per-node identity supplied through environment
variables — see `test/integration/cluster/config.node.yaml` and
`docker-compose.yml` in this repository for a complete, working example
(`gen-certs.sh` there derives `XKMS_CLUSTER_MEMBER_IDENTITIES` from the
per-node Raft certificates).

A node with a `passphrase` or `shamir` barrier boots sealed and serves only
its sealed-window listener until an operator initializes (first boot) or
unseals it through `POST /v1/barrier/initialize` / `POST /v1/barrier/unseal`
— every node, after every restart. The window binds loopback unless
`barrier.sealed_window_allow_remote: true`; the cluster harness sets that
only because its nodes are reachable solely on a private compose network.

If every node sets `join: true`, they block waiting for a leader that never
appears. If more than one sets `join: false`, the cluster may not form
correctly. Bring the bootstrapper up first, confirm it is healthy, then
bring up the joiners.

## Securing the Raft channel

Raft peer traffic is a separate network channel from the client APIs. By
default it auto-provisions its own mTLS (a dedicated cluster CA, distinct
from your runtime xkms CA) with no operator action needed. If you would
rather supply certificates yourself:

```yaml
cluster:
  raft_tls:
    ca_cert_file: /etc/xkms/raft-ca.pem
    cert_file: /etc/xkms/raft-cert.pem
    key_file: /etc/xkms/raft-key.pem
```

All three paths must be set together, or none — a partial set is a startup
error. Without either operator files or a network you trust, do not run
multi-node Raft unencrypted.

### Auto-provisioned Raft mTLS (`raft_enrollment`)

Supplying `raft_tls.*` files by hand does not scale past a few nodes. The
`raft_enrollment` block instead provisions inter-node mTLS touch-free: the
first node stands up a cluster CA and every node obtains its own transport
certificate automatically, in the precedence order above (operator files →
ACME-attested → hardware node key → software node key, Noise NK / SPKI /
DANE / Direct bootstrap). This is the same `pkg/trust/clusterca` toolkit
every product in the stack consumes through `sdk/go/clusterca`.

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
    key_backend: tpm2
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
[Cluster CA key custody](ca-key-custody.md) for the cluster CA key
protection and custody-strategy options (`ca_key_protection`,
`ca_key_strategy`).

## Checking on the cluster

```bash
xkmsctl cluster status
xkmsctl cluster members
```

`status` shows the shard's current leader; `members` lists every replica
with its advertised API endpoints. Run these against any node — they answer
the same regardless of which node you ask.

The embedded web console's dashboard shows only whether the node is
clustered. Status, membership and membership changes are go-qrdb's control
plane and are reached through `xkmsctl cluster` alone.

## Monitoring and debugging

When clustering is enabled, xkms logs cluster startup and election events:

```
time=2026-06-08T10:15:30Z level=info msg="Hosting clustered qrdb engine via NewClusteredNode" node_id=1 shard_id=1 raft_address=node1:63001 members=3 join=false
```

Look for "raft" in logs to see leader elections, membership changes, and
replication status. A healthy cluster responds to read operations on all
members and write operations on the leader.

## Adding and removing nodes

```bash
xkmsctl cluster add --replica-id 4 --raft-address node4:63001
xkmsctl cluster remove --replica-id 4
```

`remove` does not stop the process on that node — shut it down yourself
afterward, or it will keep trying to participate in a group it is no longer
a member of.

## Rebalancing

If shard load becomes uneven across nodes:

```bash
xkmsctl rebalance report                     # see the imbalance
xkmsctl rebalance plan --dry-run             # preview a move plan
xkmsctl rebalance plan --out plan.json       # save one
xkmsctl rebalance execute --plan plan.json   # run it later, verbatim
```

## What happens if you write to the wrong node

Nothing you need to handle yourself. If your write lands on a follower, the
`xkmsctl`/SDK client is redirected to the current leader automatically and
retries once with your own credentials — you see the write succeed, not the
redirect. This is different from a load balancer forwarding your request
server-side: your identity is what reaches the leader, not the follower's.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| "clustering requires building xkms with -tags raft" | you're running a non-`raft` binary | rebuild with `-tags raft` |
| joining nodes hang at startup | the bootstrapper isn't healthy yet, or everyone set `join: true` | confirm the bootstrapper (`join: false`) is up first |
| "cluster.peers must include this node's own node_id" | the bootstrapper's own `node_id=address` is missing from `peers` | add it |
| a not-leader error you see directly (not auto-retried) | you're on the Unix socket transport, which never follows redirects | retry against the leader yourself, or use a network transport |
| `cluster add`/`remove` fails with a conflict | you ran it against a standalone (non-clustered) node | there's no Raft group to modify on a standalone node |
| raft_tls partially set, server won't start | all three of `ca_cert_file`/`cert_file`/`key_file` must be set together | set all three, or remove all three and let auto-provisioning run |

## Where to go next

- [Datastore](../datastore/user.md) — the `qrdb` backend
  clustering requires
- [RBAC](../rbac/user.md) — also requires `storage.backend: qrdb`
- [Certificate authority](../certificate-authority/user.md) — the runtime
  CA that ACME-attested cluster enrollment builds on
