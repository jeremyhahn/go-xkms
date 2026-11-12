# optee-sealed-blob (#1760): every format rule pinned by a test

Row: docs/SPEC.md `optee-sealed-blob`. Format: docs/optee-sealed-blob/README.md.
Codec: pkg/enclaveprovider/opteeblob. Tests: opteeblob_test.go (refusals.test
cases live in TestUnsealErrors unless named otherwise).

## Rules and the tests that pin them

| # | Rule (README section) | Test that pins it | Gap |
|---|---|---|---|
| 1 | §1 key is HKDF-SHA-256, zero salt, L=32, of the TA unique key | TestVectors (DeriveKey == vector key == independent RFC 5869 HMAC) | none |
| 2 | §1 info = label ‖ 0x00 ‖ TA UUID, 45 bytes | TestVectors (kdf_info bytes) | wrong label not shown to fail Unseal |
| 3 | §1 context makes each TA's key its own | TestDeriveKeyBindsTheTA | none |
| 4 | §2 blob bytes: tag 16, array of 3, fixed protected header, IV, ciphertext ‖ tag | TestVectors, TestFixedEncodings, TestSealRoundTrip (length) | none |
| 5 | §3 AAD = Enc_structure("Encrypt0", protected, TA UUID) | TestVectors, TestFixedEncodings, "flipped external AAD byte" | none |
| 6 | §4 fresh random nonce per Seal | TestSealRoundTrip (two seals differ) | none |
| 7 | §5 key is 32 bytes: ErrKeyLength, checked first | TestKeyLengthErrors (Unseal of a nil blob gives ErrKeyLength, not ErrTruncated) | none |
| 8 | §5 TA unique key exactly 32 bytes: ErrTAUniqueKeyLength | TestKeyLengthErrors | none |
| 9 | §5 incomplete CBOR item: ErrTruncated | "empty", "cut in the ciphertext", "cut in the header" | none |
| 10 | §5 ciphertext shorter than the tag: ErrTruncated, before the header rules | "ciphertext shorter than the tag" | order against version/algorithm/header not pinned |
| 11 | §5 tag 16 around [bstr, map, bstr], no trailing bytes: ErrMalformed | "another CBOR tag", "untagged", "four elements", "trailing byte" | none |
| 12 | §5 version 1: ErrVersion, before the algorithm | "version 2" | order against the algorithm not pinned |
| 13 | §5 algorithm 3: ErrAlgorithm, before the header bytes | "A128GCM" | order against an extra parameter not pinned |
| 14 | §5 protected header exactly the bytes of §2: ErrHeader | "no version", "text version", "no algorithm", "extra protected parameter", "empty protected header", "protected header not a map" | same parameters in other bytes (key order, non-minimal int) |
| 15 | §5 unprotected header only a 12-byte bstr IV: ErrHeader | "no IV", "extra unprotected parameter", "11-byte IV", "text IV", "unprotected header not a map" | none |
| 16 | §5 core deterministic encoding: ErrMalformed | "not deterministic" (nonce head) | ciphertext head and tag head not pinned |
| 17 | §5 tag verifies under key, nonce, AAD: ErrAuthentication | "flipped tag/ciphertext/nonce/external AAD byte", "wrong key" | key derived from another TA unique key or label |
| 18 | §5 no plaintext returned on refusal | TestUnsealErrors (plaintext nil) | none |
| 19 | §6 vectors recompute, vector 1 from the all-zero TA unique key | TestVectors | none |

## Slices

1. This table (docs).
2. Test commit: TestUnsealErrorOrder, TestUnsealErrors cases for rows 14 and 16,
   TestUnsealDerivedKeyMismatch for rows 2 and 17.
3. Fix commit only if a new test exposes the codec accepting bad input or
   refusing in the wrong order.

Out of scope: the TA (trusted-firmware #253, #288), go-enclave's consumer,
docs/SPEC.md and the README text.
