# trust-domain-grammar: one cluster trust domain for xkms and qrdb (#1602)

## Objective

One trust domain names a cluster (docs/SPEC.md trust-domain-grammar row).
go-xkms and its embedded go-qrdb node must use the same value from one source.

## Today

- `embeddednode.DefaultTrustDomain = "xkms.cluster"`
  (`pkg/embeddednode/node_options.go`) and `embeddednode.TrustDomain(cfg)`
  (the configured `cluster.raft_enrollment.trust_domain`, else the default).
- `cmd/xkmsd/acme.go` keeps its own `const defaultClusterTrustDomain =
  "xkms.cluster"` for the ACME node URI-SAN hook.
- `pkg/server/qrdb_node_cluster.go` keeps `defaultRaftTrustDomain`, an alias of
  the embeddednode default, and `buildClusterCAOptions` repeats the
  configured-or-default fallback by hand.
- `EmbeddedNodeStorageConfig` sets only `Auth.SPIFFETrustDomain`; it never sets
  `Auth.ClusterTrustDomain`, so go-qrdb falls back to its own default
  `"qrdb.cluster"` (`config.DefaultClusterTrustDomain`).

## What ClusterTrustDomain drives in go-qrdb v0.51.0-alpha

`config.AuthConfig.ClusterTrustDomain` (doc comment, `pkg/config`) is the trust
domain of cluster-peer node identities: it is written into each auto-generated
node certificate as `spiffe://<trust-domain>/node/<raftAddress>` and pinned by
`clusterkeys.Receiver` and `clusterkeys.Sender`. It is also the tenant
principals' trust domain when `SPIFFETrustDomain` is empty.
`EffectiveClusterTrustDomain()` returns it, or `"qrdb.cluster"` when empty.
So xkms node SANs (`spiffe://xkms.cluster/node/...`) and qrdb's peer pin
(`qrdb.cluster`) disagree today.

## Slice (this lane)

1. Test commit: `pkg/embeddednode/trust_domain_test.go` — for a default and a
   configured domain, the built qrdb config has
   `Auth.EffectiveClusterTrustDomain() == TrustDomain(cfg)` and
   `Auth.SPIFFETrustDomain == TrustDomain(cfg)`; cmd/xkmsd's ACME domain and
   the pkg/server raft domain both equal `embeddednode.TrustDomain(cfg)`.
2. Fix commit: set `qcfg.Auth.ClusterTrustDomain = TrustDomain(cfg)`; the ACME
   hook and `buildClusterCAOptions` call `embeddednode.TrustDomain(cfg)`; the
   duplicate constants go.
3. Doc commit: `docs/workload-identity/engineering.md` Seams names the one
   source and the qrdb field.

## Out of scope

- `ValidateTenantIDTrustDomain` (go-qrdb v0.58.2-alpha, frozen bump).
- `pkg/api/grpc/errors.go` `Domain: "xkms.cluster"`: the google.rpc
  ErrorInfo domain, not a trust domain.
