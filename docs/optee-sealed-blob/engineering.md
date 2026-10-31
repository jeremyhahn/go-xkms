# OP-TEE TA sealed blob — engineering contract

> **Status: NORMATIVE** · Feature: `optee-sealed-blob` · Repo: `go-xkms` · Last verified: 2026-10-30

The format is [README.md](README.md). This is the contract of its codec, `pkg/enclaveprovider/opteeblob`.

## Exported surface

| Name | File | What it does |
|---|---|---|
| `DeriveKey(huk []byte, ta TAUUID) ([]byte, error)` | `opteeblob.go` | README §1: HKDF-SHA-256 of the HUK, 32 bytes out |
| `Seal(key []byte, ta TAUUID, plaintext []byte) ([]byte, error)` | `opteeblob.go` | README §2–§4, with a fresh random nonce |
| `Unseal(key []byte, ta TAUUID, blob []byte) ([]byte, error)` | `opteeblob.go` | README §5's checks, then AES-GCM open |
| `TAUUID` | `opteeblob.go` | `[16]byte`, the TA UUID in RFC 9562 octet order |
| `Version`, `KeySize`, `NonceSize`, `TagSize`, `MinHUKSize`, `UUIDSize` | `opteeblob.go` | the format's constants |

The codec is its own package because the blob is a wire format shared with the TA, not part of the `KeyProtector` envelope beside it in `pkg/enclaveprovider`: it has its own error set and no go-enclave dependency, and its names read without a prefix (`opteeblob.Seal`).

## Invariants

- `Seal` never takes a nonce. It uses `cipher.NewGCMWithRandomNonce`, the FIPS 140-3 approved GCM construction, which draws each 96-bit nonce from the DRBG. Only `export_test.go` seals under a fixed nonce, to recompute the vectors.
- `Unseal` accepts exactly the bytes `Seal` writes for some nonce and ciphertext: it re-encodes what it parsed and refuses any difference (`ErrMalformed`).
- Every function is safe for concurrent use: none holds state.
- Only the Go standard library does cryptography (`crypto/aes`, `crypto/cipher`, `crypto/hkdf`, `crypto/sha256`); `github.com/fxamacker/cbor/v2` does the CBOR.

## Errors

All are sentinels in `errors.go`, matched with `errors.Is`; a wrapped cause stays reachable through `errs.Joined`. README §5 gives the order `Unseal` checks in. `ErrSealFailed` and `ErrDeriveFailed` report a CBOR or HKDF failure that the format's inputs cannot cause.

## Tests

`opteeblob_test.go`:

- `TestVectors` recomputes every field of `testdata/vectors.json` (info, key, AAD, blob) and unseals each blob, and checks the key against an HMAC-only RFC 5869 §2.2–§2.3 implementation independent of `crypto/hkdf`.
- `TestFixedEncodings` checks the hand-written protected header and `Enc_structure` bytes against the CBOR library's deterministic encoding.
- `TestUnsealErrors` has a case for every error of README §5, including a single flipped byte in the tag, the ciphertext, the nonce and the external AAD.
- `TestSealRoundTrip`, `TestKeyLengthErrors` and `TestDeriveKeyBindsTheTA` cover the random nonce, the key and HUK lengths, and per-TA keys.

Run: `GOWORK=off go test -race -tags 'codec_cbor codec_json codec_msgpack' ./pkg/enclaveprovider/...`.
