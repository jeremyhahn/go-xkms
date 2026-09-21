- **`pkg/storage/qrdb`'s embedded constructors (`NewMemory`, `NewFile`,
  `NewPebble`) now serve `PutIfAbsent` and `CompareAndSwap`** (#125). Both
  methods dispatched exclusively to `transport.TransactionClient`, and
  `newEmbedded`'s `embedded.New(kvSvc, adminSvc)` wires no transaction
  service, so every embedded constructor failed both verbs identically with
  `embedded: TransactionServicer must not be nil` — even though the same
  client already implements `transport.GuardedKVClient`, which delegates
  straight to the KV service and needs no transaction service at all.
  `CompareAndDelete` already preferred that capability (go-xkms#406, once
  go-qrdb's `FastStateMachine` gained the guarded-delete opcode in
  v0.16.3-alpha); `PutIfAbsent` and `CompareAndSwap` simply never asked for
  it. Fixed by giving both the same GuardedKVClient-first, TransactionClient-fallback
  dispatch order, so a capability refusal (not any other failure) is the only
  thing that falls through to the transaction. `Backend.GuardedWritesAvailable`
  and `NewBackend`'s capability detection are updated to match: a client
  offering either capability now reports guarded writes available, not only
  one carrying a transaction.

  No on-disk layout changed and no data migration is needed: `newEmbedded`
  still builds the same `Storage -> FastStateMachine -> LocalBackend ->
  KVService/AdminService -> embedded.Transport` stack over the same
  `qrdbsdk.NewFileStorage` / `NewPebbleStorage` / `NewMemoryStorage` engines
  it always did, so every directory an existing `NewFile`/`NewPebble` backend
  wrote is read back unchanged (`TestClose_FlushesPendingWrites` reopens a
  file/pebble directory across `Close` and still finds every key). Routing
  these constructors onto `storage.OpenEngine` instead — the option the
  issue's discussion raised — was not taken: `pkg/storage` already imports
  `pkg/storage/qrdb` (`constructors.go` delegates `NewFile`/`NewPebble` here),
  so the reverse import would be a compile-time cycle, and `OpenEngine`'s
  `engineBackend` reaches guarded writes by a different mechanism entirely (a
  process-local mutex over the raw storage engine, never a transaction
  service or the embedded transport). Reaching the same outcome by correcting
  the dispatch order is smaller and avoids both the cycle and a data move.

  Files: `pkg/storage/qrdb/backend_putifabsent.go`,
  `pkg/storage/qrdb/backend_compareandswap.go`, `pkg/storage/qrdb/backend.go`,
  `pkg/storage/qrdb/factory.go`. Verified by tests pinning the dispatch order
  (GuardedKVClient preferred, capability refusals — and only those — fall
  through to the transaction, in `backend_gaps_test.go` and
  `backend_compareandswap_test.go`) and by conformance tests against the real
  constructors (`factory_cas_characterization_test.go`,
  `pkg/storage/constructors_test.go`,
  `pkg/storage/absentkey_contract_test.go`,
  `pkg/storage/kvadapter/atomic_test.go`) confirming `PutIfAbsent`,
  `CompareAndSwap` and `CompareAndDelete` all execute, a stale
  `CompareAndSwap` guard leaves the stored value untouched, and
  `kvadapter.New` now hands the DAO layer an `AtomicKVStore` for these
  backends. This closes #125; the OpGet-in-a-transaction-branch fix on this
  same branch has its own entry above.
