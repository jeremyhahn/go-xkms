- **`pkg/storage/qrdb`'s `Backend.CompareAndSwap` no longer builds an illegal
  transaction** (#125). It put an `OpGet` in the transaction's `FailureOps` so
  a failed swap could report the current value, and go-qrdb's transaction
  service rejects any op other than Put/Delete in a success or failure branch
  — a branch executes atomically as a single Raft write with no per-op
  read-result channel, so `service: unsupported transaction operation type 1
  (transaction branches support only Put and Delete)` refused every
  `CompareAndSwap` a caller with a transaction-capable client issued, on every
  engine. The transaction now carries no failure branch — the same shape
  `PutIfAbsent` and `CompareAndDelete` already use in this package — and on a
  refused swap `current` is fetched with a follow-up `Get` instead: the
  contract already documents `current` as advisory for a retry, so nothing is
  lost by reading it a moment later. Files: `pkg/storage/qrdb/backend_compareandswap.go`,
  `pkg/storage/qrdb/backend_compareandswap_test.go`. Verified by tests pinning
  the transaction's shape (`FailureOps` carries no read op, on both the
  success and refusal paths) and the behavioural contract (a stale expected
  value refuses the swap, `current` reports the value actually present via the
  follow-up `Get`, and the stored value is left unchanged).

  This was independent of the rest of #125 at the time it was written: the
  embedded constructors in `pkg/storage/qrdb/factory.go` (`NewMemory`,
  `NewFile`, `NewPebble`) still wired no transaction service at all, so this
  fix alone did not make `CompareAndSwap` or `PutIfAbsent` reachable through
  them. The remainder — preferring `transport.GuardedKVClient` over the
  transaction, which needs no transaction service — is the companion
  "guarded-writes-125" entry in this same unreleased set; together the two
  entries close #125.
