# OP-TEE TA sealed blob — format specification

> **Status: NORMATIVE** · Feature: `optee-sealed-blob` · Repo: `go-xkms` · Last verified: 2026-10-31

trusted-firmware's OP-TEE trusted application (TA) seals data under a key rooted in the device's hardware unique key (HUK): OP-TEE derives the TA's unique key from the HUK, and the TA derives the sealing key from that (§1). Its `SEAL` command (`0x00000003`) returns the blob defined here and its `UNSEAL` command (`0x00000004`) accepts it. go-xkms owns the format, the key derivation and the reference codec (owner ruling 251, item 177 (a)); the TA, trusted-firmware #253 slice 5 and #288, is the producer, and go-enclave's arm-trustzone backend is the consumer.

Every rule below is one of three standards, adopted as written:

| Piece | Standard | Copy |
|---|---|---|
| Blob | COSE_Encrypt0, RFC 9052 §5.2, tagged (CBOR tag 16), §5.3 for the AEAD inputs | [rfc-9052.txt](../references/rfc-9052.txt) |
| Algorithm | A256GCM (COSE alg 3), RFC 9053 §4.1 | [rfc-9053.txt](../references/rfc-9053.txt) |
| Key derivation | HKDF-SHA-256, RFC 5869 §2.2 (extract) and §2.3 (expand) | [rfc-5869.txt](../references/rfc-5869.txt) |
| Encoding | CBOR core deterministic encoding, RFC 8949 §4.2.1 | — |

The codec is `pkg/enclaveprovider/opteeblob`; its contract is [engineering.md](engineering.md).

## 1. Key derivation

The TA derives one 32-byte AES-256 key from its TA unique key with HKDF-SHA-256 (RFC 5869):

| Input | Value |
|---|---|
| Hash | SHA-256 |
| IKM | the TA unique key: the 32-byte output of OP-TEE 4.11.0's system PTA command `PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY`, called by the TA with extra_data = the 28 ASCII bytes `go-xkms optee-sealed-blob v1` (the label below, fixed for every TA and device) and a requested key size of 32 bytes |
| salt | absent: §2.2's string of 32 zero bytes |
| info | label ‖ `0x00` ‖ context |
| label | the 28 ASCII bytes `go-xkms optee-sealed-blob v1` |
| context | the TA's UUID, 16 bytes in RFC 9562 §4 octet order (`tee_uuid_to_octets`) |
| L | 32 bytes |

The info is 45 bytes. The context makes each TA's key its own: two TAs on one device never share a key.

The IKM is never the raw HUK (owner ruling 7dbbb72, item 183 (a); #1783). On OP-TEE 4.11.0 the HUK is read only by OP-TEE's core (`tee_otp_get_hw_unique_key`); no syscall or PTA gives it to a user TA. The system PTA's `PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY` is the only HUK-backed interface a user TA has: OP-TEE derives a subkey from the HUK, the calling TA's UUID and the extra_data (`huk_subkey_derive(HUK_SUBKEY_UNIQUE_TA, uuid ‖ extra_data, …)`) and returns only that subkey, so the HUK never leaves OP-TEE's core (#1783's reading of OP-TEE 4.11.0). go-xkms's derivation starts at the PTA output: OP-TEE's step is OP-TEE's, and neither go-xkms nor its vectors reproduce it.

## 2. The blob

The blob is `COSE_Encrypt0_Tagged` (RFC 9052 §5.2), in core deterministic encoding, and nothing else: no wrapper, no trailing bytes.

```
#6.16([                          ; d0, then 83: an array of three
  protected:   bstr .cbor {      ; 49 a2 01 03 3a 00 01 00 00 01
                 1: 3,           ;   alg: A256GCM (RFC 9053 §4.1)
                 -65537: 1       ;   the blob version
               },
  unprotected: { 5: bstr(12) },  ; a1 05 4c <nonce>: IV (RFC 9052 §3.1)
  ciphertext:  bstr              ; AES-GCM ciphertext ‖ 16-byte tag
])
```

| Offset | Bytes | Field |
|---|---|---|
| 0 | `d0` | CBOR tag 16, COSE_Encrypt0 |
| 1 | `83` | array of 3 |
| 2 | `49` + 9 bytes | protected header, exactly `a2 01 03 3a 00 01 00 00 01` |
| 12 | `a1 05 4c` + 12 bytes | unprotected header: the IV and nothing else |
| 27 | bstr head + n + 16 bytes | ciphertext of an n-byte plaintext, the 16-byte tag last |

The bstr head of the ciphertext is one byte (`0x40`+len) up to 23 bytes, `58 xx` up to 255 and `59 xx xx` up to 65535 (RFC 8949 §3.1). A blob is 27 + head + n + 16 bytes; 84 for vector 1.

**Version.** The version is the protected header parameter `-65537`, the first private-use label: the IANA COSE Header Parameters registry reserves integers below -65536 for private use, and RFC 9052 §11.6 keeps private-use ranges for "testing purposes and closed environments", which a TA and its own codec are. Version 1 is the only version. Being in the protected header, it is authenticated with the ciphertext.

**Algorithm.** A256GCM: AES-GCM with a 256-bit key, a 96-bit nonce and a 128-bit tag (RFC 9053 §4.1). It is FIPS 140-3 approved (NIST SP 800-38D).

## 3. The AEAD inputs

| Input | Value |
|---|---|
| key | §1's derived key |
| nonce | the 12 bytes of the IV |
| plaintext | the data the TA seals |
| AAD | the CBOR encoding of `Enc_structure` (RFC 9052 §5.3) |

```
Enc_structure = [
  "Encrypt0",                    ; 83 68 45 6e 63 72 79 70 74 30
  protected,                     ; 49 a2 01 03 3a 00 01 00 00 01
  external_aad: bstr(16)         ; 50 <TA UUID>
]
```

The AAD is 37 bytes: a fixed 21-byte prefix, then the TA UUID. It binds the algorithm and the version (the protected header) and the TA identity (external_aad, RFC 9052 §4.3): a blob unsealed by another TA, or with its header changed, fails authentication.

## 4. The nonce

Every `SEAL` draws a fresh 96-bit nonce from the TA's random generator (`TEE_GenerateRandom`); go-xkms's `Seal` draws it from the FIPS DRBG. A nonce is never chosen, counted or reused under one key: a repeat under AES-GCM loses confidentiality and authenticity of both blobs (NIST SP 800-38D §8). With random nonces one key seals at most 2^32 blobs (SP 800-38D §8.3). The fixed nonces in §6 exist only to make the vectors reproducible.

## 5. What is refused

The codec and the TA refuse every blob that breaks a rule, checking in this order and returning no plaintext:

| Rule | Codec error |
|---|---|
| The key is 32 bytes | `ErrKeyLength` |
| The TA unique key is exactly 32 bytes | `ErrTAUniqueKeyLength` (derivation only) |
| The blob is a complete CBOR item, and the ciphertext holds at least the 16-byte tag | `ErrTruncated` |
| The item is CBOR tag 16 around an array of three: bstr, map, bstr; no trailing bytes | `ErrMalformed` |
| The protected header's version is 1 | `ErrVersion` |
| The protected header's algorithm is 3 (A256GCM) | `ErrAlgorithm` |
| The protected header is a map holding exactly the version and the algorithm, in the bytes of §2; the unprotected header holds only a 12-byte bstr IV | `ErrHeader` |
| The blob is in core deterministic encoding (no non-minimal heads) | `ErrMalformed` |
| The tag verifies under the key, the nonce and the AAD | `ErrAuthentication` |

A TA maps these to its GlobalPlatform results; `TEE_ERROR_MAC_INVALID` for an authentication failure and `TEE_ERROR_BAD_FORMAT` for the rest is the natural mapping, and the choice is trusted-firmware's.

## 6. Test vectors

[`pkg/enclaveprovider/opteeblob/testdata/vectors.json`](../../pkg/enclaveprovider/opteeblob/testdata/vectors.json) holds them, every field hex. The vectors are inputs to go-xkms's HKDF (§1): **the `ta_unique_key` values are test values, never a real device's, and are not derived from any HUK**. Vector 1 uses 32 zero bytes. Both use the test TA UUID `00112233-4455-6677-8899-aabbccddeeff`.

Vector 1, `zero-ta-key`:

```
ta_unique_key  0000000000000000000000000000000000000000000000000000000000000000
ta_uuid   00112233445566778899aabbccddeeff
kdf_info  676f2d786b6d73206f707465652d7365616c65642d626c6f622076310000112233445566778899aabbccddeeff
key       a5a767396c6bd0694dae3164b1cef7d8b6351469960cb5f7ef1f61373d16ae3c
nonce     000102030405060708090a0b
plaintext "go-xkms optee sealed-blob test vector 1"
          676f2d786b6d73206f70746565207365616c65642d626c6f62207465737420766563746f722031
aad       8368456e63727970743049a201033a00010000015000112233445566778899aabbccddeeff
blob      d08349a201033a0001000001a1054c000102030405060708090a0b5837
          476b78d4c745b24a8bddf2b27ae637845031a784dda0ac4160e56eb8a4caeb233ca96cf75d1a3f1587
          641249cab4ce59f553cb3a9aa1ab
```

Vector 2, `empty-plaintext`, uses the 32-byte test TA unique key `000102…1f`, the nonce `f0f1…fb` and an empty plaintext: its blob is the 16-byte tag alone, `d08349a201033a0001000001a1054cf0f1f2f3f4f5f6f7f8f9fafb50377865c654d1597722811f0fc1e446f8`.

## 7. Alternatives rejected

- **The COSE HKDF of RFC 9053 §5.1 with the COSE_KDF_Context of §5.2.** Those derive a content key for a recipient of COSE_Encrypt or COSE_Mac0 from a shared secret and the recipient's parameters. COSE_Encrypt0 has no recipient: the key is already known to whoever decrypts (RFC 9052 §5.2). The derivation here is the TA's own, from its TA unique key, outside any COSE message, so plain RFC 5869 HKDF with a fixed label and the TA UUID is the standard that fits.
- **COSE_Encrypt with a `direct+HKDF` recipient.** It would carry a recipient structure and an empty encrypted key on every blob to say what both sides already know.
- **A version outside the COSE structure** (a prefix byte, or an outer array). The blob would no longer be a COSE object, and the version would not be authenticated unless it were repeated in the AAD. A protected header parameter is both.
- **A deterministic or counter nonce.** The TA keeps no state across `SEAL` calls that survives a reset, so a counter could repeat; random 96-bit nonces from the TA's generator are the SP 800-38D §8.2.2 construction.
- **The raw HUK as IKM.** It was §1's IKM as first merged (#1771). OP-TEE 4.11.0 has no syscall or PTA that gives the HUK to a user TA: only its core reads it (#1783), so a user TA cannot meet that rule. `PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY` is the HUK-backed interface the TA has, and its output keeps the key rooted in the HUK.
- **A producer inside OP-TEE's core** (a pseudo-TA or core patch that reads the HUK). It would need a modified OP-TEE; owner ruling 7dbbb72 item 183 (a) keeps the producer a user TA on stock OP-TEE 4.11.0.
