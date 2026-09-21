- **`storage.CompareAndSwapper.CompareAndSwap` no longer treats a `nil`
  `expected` as "require the key to be absent" — BREAKING.** The contract used
  to give `CompareAndSwap` a second job: `expected == nil` meant "create only
  if the key is absent," the same precondition `PutIfAbsent` uses. That
  diverged from go-qrdb's own `GuardedKVClient.CompareAndSwap`, whose
  `KVEngine.handleCompareAndSwap` refuses unconditionally on an absent key
  ("an absent key is NOT created — a swap moves a record between two states,
  and a record that does not exist has no first state") and from this
  package's own `CompareAndDeleter.CompareAndDelete`, which already reads
  `nil` as "equivalent to an empty slice," never as a wildcard for absence. A
  swap now edits and never creates: `expected` — nil included — is compared
  as raw bytes against the current value, so `nil` matches only a stored
  empty value, and an absent key refuses regardless of what `expected` was. A
  caller that wants a guarded create uses `PutIfAbsent`, which already exists
  for exactly that precondition. One caller needed the old "absent-or-equals"
  combination — `pkg/pkcs11/module`'s remote lockout-counter increment,
  detailed below — and moved to `PutIfAbsent` plus a `CompareAndSwap` retry
  loop that never passes a nil `expected`; every other caller in this
  repository was already a plain value-compare or a pass-through and needed
  no change. Implementations updated to match: `pkg/storage/engine.go` (`engineBackend`,
  backing `NewMemory`/`NewFile`/`NewPebble`) now checks existence
  unconditionally before the byte comparison, instead of branching on
  `expected == nil`; `pkg/storage/qrdb/backend_compareandswap.go`'s
  transaction fallback now sends the same two ANDed preconditions
  `CompareAndDelete` already sends (`version > 0` **and** `value == expected`)
  instead of substituting a `version == 0` "absent" precondition when
  `expected` was nil — go-qrdb evaluates a value compare against `nil` for an
  absent key as a match (`bytes.Compare(nil, nil) == 0`), so a value-only
  compare would otherwise let a nil-expected swap create the key: exactly the
  wildcard this change removes. `pkg/storage/kvadapter/atomic.go`'s
  `atomicKVStoreAdapter.CompareAndSwap` — which used to refuse a nil
  `expected` outright specifically because the two contracts disagreed — is
  now a straight delegation, the same shape `CompareAndDelete` already had,
  because the contracts agree. `pkg/storage/prefix_compareandswap.go` and
  `pkg/storage/file/storage_compareandswap.go` needed no logic change; they
  already delegate to the engine. The shared conformance suite
  (`pkg/storage/storagetest/absentkey.go`, run by every fixture in
  `pkg/storage`, `pkg/storage/file`, `pkg/storage/luks`,
  `pkg/storage/sealed` and `pkg/storage/mocks`) now asserts that
  `CompareAndSwap` refuses on an absent key for a nil, empty, and non-empty
  `expected` alike, skipping backends that do not claim the optional
  `storage.CompareAndSwapper` capability.

  **The PKCS#11 remote multi-client lockout-counter caller moved to the
  explicit verb, in the same change.** `ModuleStorage.incrementViaCAS`
  (`pkg/pkcs11/module/storage.go`) used the old wildcard to create a token's
  failed-attempt counter on its first increment (`expected = nil //
  require-absent`); it now calls `PutIfAbsent` to create the counter at `1`
  when `Get` reports it absent, and only enters the `CompareAndSwap` retry
  loop once it holds real bytes — losing the create race just means a
  concurrent writer won, so it re-reads and falls through to the loop instead.
  The loop itself now treats a refusal's `current == nil` (a concurrent
  reset/delete) the same way, recreating rather than ever looping back into
  `CompareAndSwap` with a nil `expected`.

  The `PKCS11StateCAS` RPC's `ExpectAbsent` field
  (`pkg/api/transport/types_pkcs11state.go` and every transport that carries
  it: grpc, unix, quic, rest, plus the REST handler and grpc service) is kept
  on the wire for compatibility — no proto regeneration — but is REDEFINED:
  it no longer selects "require absent" on a compare-and-swap (there is no
  such precondition to select, post-#186); it now tells
  `pkg/xkms/servicer_pkcs11state.go`'s `PKCS11StateCAS` handler to perform
  `PutIfAbsent` using the request's `New` field as the value instead of a
  compare-and-swap. `pkg/pkcs11/module`'s `remoteBackend.CompareAndSwap`
  (`storage_remote.go`) no longer sets `ExpectAbsent` — it forwards `expected`
  as an ordinary value compare, nil included — because the module reaches
  `PutIfAbsent` directly through the RPC that already existed for it
  (`PKCS11StatePutIfAbsent`) rather than asking the CAS RPC to do double duty.
  `test/integration/cluster/cluster_cas_test.go`'s real 3-node Raft E2E test
  follows the identical split (`putIfAbsentCounter` then `swapCounter`, never
  setting `ExpectAbsent`) so it keeps proving the multi-client property against
  the real cluster.

  Verified: `pkg/pkcs11/module` passes in full under `-race`, including
  `TestModuleStorage_FailedAttemptCounter_CAS`,
  `TestModuleStorage_FailedAttemptCounter_ConcurrentAccumulates`, and the
  rewritten `TestRemoteBackend_CompareAndSwap` (plus the new
  `TestRemoteBackend_CompareAndSwap_NeverSendsExpectAbsent`, which pins that
  the client-side change actually took). `go vet -tags integration
  ./test/integration/cluster/...` is clean (the suite needs the real cluster
  to run). (#186, follows #125)
