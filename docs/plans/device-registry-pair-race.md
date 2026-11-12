# Device registry: atomic pair across processes (#2093, slice sdevregc)

## The race

`Registry.Pair` (pkg/devicereg/registry.go:142-153) is check-then-insert:
it loads the natural key and, on a miss, saves the record. Only the
Registry's in-process `sync.Mutex` guards it, so two xkmsd processes (or two
Registry values) on one store both see the key absent and both save; the
second pair silently overwrites the first device's identity key.

## The fix

Pair creates the record with `GenericDAO.SaveIfAbsent` (go-qrdb v0.51.0-alpha
pkg/dao/dao.go:105), which delegates the condition to the KV store's atomic
`PutIfAbsent`. `stored == false` maps to `ErrDeviceExists`; any error is a
`StoreError{Op: "pair"}`. A store without atomic writes returns
`DAOAtomicWriteUnsupportedError` (matches `ErrKVAtomicWriteUnsupported`) and
Pair fails closed on it; there is no Get-then-Save fallback. Pair no longer
takes the mutex.

## Tests

1. `TestPairConcurrentAcrossRegistries`: two Registry values on one shared KV
   whose writes wait on a barrier until both goroutines reach their write;
   exactly one pair succeeds, the other gets `ErrDeviceExists`, and the stored
   record is the winner's.
2. `TestPairRefusesNonAtomicStore`: a KV that hides `PutIfAbsent`; Pair
   returns a `*StoreError` matching `ErrKVAtomicWriteUnsupported` and nothing
   is stored.
3. `TestStoreFailures`: Pair no longer reads, so the failing-read case expects
   success; the failing-write case stays.

## Out of scope

Revoke's load-then-Save: it is idempotent and keeps the first revocation
time; it could later use `CompareAndSwap`.

## Results
- `go test -count=3 -race -tags "codec_cbor codec_json codec_msgpack" ./pkg/devicereg/...`: ok (TestPairConcurrentAcrossRegistries failed before the fix: both pairs nil).
- `make lint`: Linting complete, 0 issues in every module and tag set (the first two runs hit the 10-minute shell cap before finishing; the third, on a warm cache, completed).
