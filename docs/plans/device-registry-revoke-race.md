# Device registry: atomic revoke across processes

Row: device-registry (docs/SPEC.md:87), issue #2093. Lane sdevregd.

Prior lanes: sdevregb (pkg/devicereg on the qrdb DAO) and sdevregc
(atomic Pair on `SaveIfAbsent`, docs/plans/device-registry-pair-race.md).
This slice closes the open item sdevregc left out of scope.

## The race

`Registry.Revoke` (pkg/devicereg/registry.go:206-216) loads the record,
checks `Active()`, sets `RevokedAt` and calls `Save`, an unconditional
`Put`. Only the in-process `sync.Mutex` guards it. Two registries on one
store (two xkmsd processes) both see the device active and both write, so
the stored revocation time is the last writer's, not the first, and the
doc's promise to keep the first revocation time is broken.

## The fix

- Revoke uses `GenericDAO.CompareAndSwap` (go-qrdb v0.51.0-alpha
  pkg/dao/dao.go:212), the store's guarded compare-and-write, in a
  bounded loop (`maxRevokeAttempts = 8`). A lost swap re-reads; the
  re-read sees the winner's revoke and returns nil (idempotent).
- After the bound: a revoke `StoreError` wrapping the new sentinel
  `ErrRevokeConflict`.
- A store without atomic writes is refused (fail closed): a revoke
  `StoreError` matching `qrdbsdk.ErrKVAtomicWriteUnsupported`; never a
  Get-then-Save fallback.
- The `mu` field and the `sync` import go.

## Tests (pkg/devicereg/registry_test.go)

- `TestRevokeConcurrentAcrossRegistries`: two registries on one barrier
  store revoke d1 at once; both nil, exactly one write, stored RevokedAt
  is one of the two times.
- `TestRevokeRefusesNonAtomicStore`: revoke on `nonAtomicKV` is a revoke
  StoreError matching ErrKVAtomicWriteUnsupported; the device stays
  active.
- `TestRevokeGivesUpOnConflict`: a store whose CompareAndSwap always
  misses ends in a revoke StoreError matching ErrRevokeConflict.

## Out of scope

- Routes, service verbs and permissions (row device-share-policy).
- Any dependency change.

## Results
