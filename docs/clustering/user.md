# Clustering — User Guide

> **Status: NORMATIVE** · Feature: `clustering` · Repo: `go-xkms` · Last verified: 2026-09-24

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

Nodes 2 and 3: identical, with their own `NODE_ID`, `RAFT_ADDRESS`,
`LISTEN_ADDRESS`, and `XKMS_CLUSTER_JOIN=true`. The config file itself
(`storage.backend: qrdb` is required) can be shared across all three nodes
unchanged, with only the per-node identity supplied through environment
variables — see `test/integration/cluster/config.node.yaml` and
`docker-compose.yml` in this repository for a complete, working example.

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

## Checking on the cluster

```bash
xkmsctl cluster status
xkmsctl cluster members
```

`status` shows the shard's current leader; `members` lists every replica
with its advertised API endpoints. Run these against any node — they answer
the same regardless of which node you ask.

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

- [Storage engines](../storage-engines/user.md) — the `qrdb` backend
  clustering requires
- [RBAC](../rbac/user.md) — also requires `storage.backend: qrdb`
- [Certificate authority](../certificate-authority/user.md) — the runtime
  CA that ACME-attested cluster enrollment builds on
