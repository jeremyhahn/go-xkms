# 2540: authenticator.test memory under -race (CA m2540)

## Objective

`make coverage` was OOM-killed on main (job 130424434369): `authenticator.test`
(pkg/fido2/authenticator) reached 6.6 GB anon RSS under -race in an 8 GiB
cgroup. Bring the race binary's peak RSS under 3 GiB (at most half of before)
without weakening any test and without changing production Argon2 parameters.

## Measurement (before, this node, -race, tags of TEST_TAGS, GOMEMLIMIT=10GiB)

- Full binary, `-test.count=1`: peak RSS **7369 MB**, 104 s, PASS.
- Heap profile, alloc_space: 40.71 GB total, of which 40.63 GB (99.8 %) is
  `golang.org/x/crypto/argon2.initBlocks`: every Argon2id derivation at the
  shipped parameters (64 MiB, t=3, p=4) allocates 64 MiB.
  - `SOPINManager.DeriveKey` 33.1 GB (Initialize 18.0, BeginVerify 10.1,
    Rekey 2.4); `KeyManager.deriveUMK` 7.5 GB.
  - Top tests by allocation: TestWrapFromProtected_NoNestedBorrowDeadlock
    7.8 GB, TestUnwrapIntoProtected_NoNestedBorrowDeadlock 3.3 GB,
    TestKeyManager_ConcurrentAccess 1.25 GB (concurrent).
- Per-test peak RSS (`-test.run '^X$'`):
  - TestKeyManager_ConcurrentAccess **4166 MB** (concurrent derivations, each
    64 MiB, multiplied by the race detector's shadow memory) -> the peak.
  - TestWrapFromProtected_NoNestedBorrowDeadlock 823 MB.
  - TestUnwrapIntoProtected_NoNestedBorrowDeadlock 692 MB.
  - TestSOPINManager_EdgeCases 692 MB.
- No grower fixture and no leaked manager: the memory is the KDF's scratch.

## Slices

1. Test commit: `TestArgon2idTestCost` asserts that one SO PIN
   initialisation in the test binary allocates far less than the 64 MiB
   production cost. Fails today.
2. Fix commit: a package-level seam `argon2IDKey` (defaults to
   `argon2.IDKey`) used by `SOPINManager.DeriveKey` and
   `KeyManager.deriveUMK`; the test binary's `TestMain` replaces it with the
   same KDF at a reduced memory cost. Stored parameters (SOPINDefault*,
   umk*) and production behaviour are unchanged; derivations stay
   deterministic, so every PIN test keeps its meaning.

## Out of scope

Production Argon2 parameters, the Makefile's GOMEMLIMIT/-p, other packages.
