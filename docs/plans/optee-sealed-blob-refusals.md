# optee-sealed-blob (#1760): every format rule pinned by a test

Row: docs/SPEC.md `optee-sealed-blob`. Format: docs/optee-sealed-blob/README.md.
Codec: pkg/enclaveprovider/opteeblob. Tests: opteeblob_test.go (quoted
names are cases of TestUnsealErrors unless a test is named).

## Rules and the tests that pin them

| # | Rule (README section) | Test that pins it | Gap |
|---|---|---|---|
| 1 | §1 key is HKDF-SHA-256, zero salt, L=32, of the TA unique key | TestVectors (DeriveKey == vector key == independent RFC 5869 HMAC) | none |
| 2 | §1 info = label ‖ 0x00 ‖ TA UUID, 45 bytes | TestVectors (kdf_info bytes), TestUnsealDerivedKeyMismatch (45 bytes, label ‖ 00 ‖ UUID; another label fails) | closed |
| 3 | §1 context makes each TA's key its own | TestDeriveKeyBindsTheTA | none |
| 4 | §2 blob bytes: tag 16, array of 3, fixed protected header, IV, ciphertext ‖ tag | TestVectors, TestFixedEncodings, TestSealRoundTrip (length) | none |
| 5 | §3 AAD = Enc_structure("Encrypt0", protected, TA UUID) | TestVectors, TestFixedEncodings, "flipped external AAD byte" | none |
| 6 | §4 fresh random nonce per Seal | TestSealRoundTrip (two seals differ) | none |
| 7 | §5 key is 32 bytes: ErrKeyLength, checked first | TestKeyLengthErrors, TestUnsealErrorOrder "short key before truncation" | none |
| 8 | §5 TA unique key exactly 32 bytes: ErrTAUniqueKeyLength | TestKeyLengthErrors | none |
| 9 | §5 incomplete CBOR item: ErrTruncated | "empty", "cut in the ciphertext", "cut in the header" | none |
| 10 | §5 ciphertext shorter than the tag: ErrTruncated, before the header rules | "ciphertext shorter than the tag", TestUnsealErrorOrder "short ciphertext before version/algorithm/IV" | closed (fix: checked before the headers) |
| 11 | §5 tag 16 around [bstr, map, bstr], no trailing bytes: ErrMalformed | "another CBOR tag", "untagged", "four elements", "trailing byte" | none |
| 12 | §5 version 1: ErrVersion, before the algorithm | "version 2", TestUnsealErrorOrder "version before algorithm/extra parameter/IV" | closed |
| 13 | §5 algorithm 3: ErrAlgorithm, before the header bytes | "A128GCM", TestUnsealErrorOrder "algorithm before extra parameter" | closed |
| 14 | §5 protected header exactly the bytes of §2: ErrHeader | "no version", "text version", "no algorithm", "extra protected parameter", "empty protected header", "protected header not a map", TestUnsealEncodingErrors "protected keys out of order", "non-minimal version/algorithm" | closed |
| 15 | §5 unprotected header only a 12-byte bstr IV: ErrHeader | "no IV", "extra unprotected parameter", "11-byte IV", "text IV", "unprotected header not a map" | none |
| 16 | §5 core deterministic encoding: ErrMalformed | "not deterministic" (nonce head), TestUnsealEncodingErrors (ciphertext head, tag head, indefinite array), TestUnsealErrorOrder "encoding before authentication" | closed |
| 17 | §5 tag verifies under key, nonce, AAD: ErrAuthentication | "flipped tag/ciphertext/nonce/external AAD byte", "wrong key", TestUnsealDerivedKeyMismatch (another TA unique key, TA, label) | closed |
| 18 | §5 no plaintext on refusal; typed error | assertRefused (errors.Is the sentinel, plaintext nil, message formats and leads with the sentinel) | closed (fix: errs.Joined with a nil Cause panicked in Error) |
| 19 | §6 vectors recompute, vector 1 from the all-zero TA unique key | TestVectors | none |

## Slices

1. This table (docs).
2. Test commit: TestUnsealErrorOrder, TestUnsealEncodingErrors,
   TestUnsealDerivedKeyMismatch, assertRefused on every refusal table.
3. Fix commit: the two defects the tests exposed (rows 10 and 18).

Out of scope: the TA (trusted-firmware #253, #288), go-enclave's consumer,
docs/SPEC.md and the README text.

## Closure

Row can close: every rule pinned. Every README rule above names a test, and
the package tests pass with the codec tags.

One reading to record, not a gap: README §5 lists ErrTruncated before
ErrMalformed, but a ciphertext can only be measured once the item has the
[bstr, map, bstr] shape, so a blob that is both misshapen and short is
refused ErrMalformed. A truncated CBOR item is still ErrTruncated first.
If the owner wants that stated, the README's row 3 wording is the place
(outside this lane's file map).

What the codec cannot prove alone: that trusted-firmware's TA produces and
accepts these bytes (the seam with #253 slice 5 and #288).
