- **`types.QuantumAlgorithm` now classifies itself; the stale `pkg/quantum`
  duplicate enum is gone.** `IsSignature()` and `IsKEM()` replace the eight
  `strings.HasPrefix(..., "ML-DSA"/"ML-KEM")` call sites in
  `pkg/keyprovider/quantum/backend.go` (key generation, load, list, rotate,
  and AEAD-tracking dispatch), `pkg/keyprovider/pkcs8/pkcs8.go` (quantum-key
  listing filter), and `pkg/backend/pkcs11/pkcs11_objects_test.go` with an
  O(1) map-keyed lookup instead of string matching. The root `pkg/quantum`
  package's `types.go` — a duplicate `Algorithm` enum with 0% test coverage
  that lacked ML-KEM-512 and had zero importers — is deleted; the live
  `pkg/quantum/<alg>` implementation subpackages (dilithium2, kyber768,
  mldsa65, mldsa87, mlkem1024, mlkem512) are unaffected (#726).
