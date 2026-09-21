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

  This is independent of the rest of #125: the embedded constructors in
  `pkg/storage/qrdb/factory.go` (`NewMemory`, `NewFile`, `NewPebble`) still
  wire no transaction service at all, so `CompareAndSwap` and `PutIfAbsent`
  remain unavailable through them regardless of this fix —
  `factory_cas_characterization_test.go` continues to pin that. Routing those
  constructors onto a working transaction path (`storage.OpenEngine`, per the
  option the issue recommends) is a separate, owner-decided change and is not
  part of this entry.
