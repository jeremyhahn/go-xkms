- **Two ACME packages that were pure duplicates of live code are deleted —
  BREAKING for anyone importing them directly.** `pkg/acme` (the root
  `acme.go`/`acme_test.go`) held nothing but type and `var` aliases over
  `pkg/acme/{client,common,entities,storage}`; `sdk/go/acme` is, and remains,
  the canonical public surface, and `grep`/`go list` across the go-xkms
  module tree (root, `sdk/go`, `xkey`) and the read-only `go-quicbaas` and
  `go-trusted-platform` checkouts found zero importers of
  `github.com/jeremyhahn/go-xkms/pkg/acme`. `pkg/acme/qrdb/dao` (`Factory`
  and its tests) duplicated the live `pkg/acme/storage/objstore` `Factory` /
  `TenantAwareFactory` — both build on `qrdbsdk.NewDAO` over the same entity
  set — and had zero importers by the same search. `objstore`'s tenant
  isolation is the more complete implementation (a real prefixed-key
  `KVStore` decorator with atomic-operation passthrough, `pkg/acme/storage/
  objstore/prefixed_kvstore.go`, versus the dead package's bare string
  prefix), so nothing regresses. The dead `dao.Factory`'s one feature the
  live factory lacked verbatim — a `daoOpts ...qrdbsdk.DAOOption` pass-through
  for `DAOWithShard`/`DAOWithCodec`/`DAOWithTimeout`/`DAOWithPartition` — was
  never exercised: no call site anywhere in the tree (including the dead
  package's own tests) passes any of those options, so there was no
  capability to fold into `objstore` before deleting. `docs/acme/README.md`'s
  stale DAO-layer example, which named the now-deleted `pkg/qrdb/dao`
  package and a `NewFactoryFromService` constructor that never existed on
  it, is corrected to point at `objstore.NewTenantAwareFactoryFromKVStore`.
  go-xkms#740, go-xkms#696.
