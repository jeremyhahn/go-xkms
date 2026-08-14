# Supported Mechanisms

This document describes the cryptographic mechanisms supported by the PKCS#11 module.

## RSA Mechanisms

### CKM_RSA_PKCS_KEY_PAIR_GEN

RSA key pair generation.

| Property | Value |
|----------|-------|
| Key sizes | 2048, 3072, 4096 bits |
| Flags | CKF_GENERATE_KEY_PAIR |

```bash
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type rsa:2048 \
  --label "my-rsa-key"
```

### CKM_RSA_PKCS

RSA PKCS#1 v1.5 encryption and signing.

| Property | Value |
|----------|-------|
| Key sizes | 2048-4096 bits |
| Flags | CKF_ENCRYPT, CKF_DECRYPT, CKF_SIGN, CKF_VERIFY, CKF_WRAP, CKF_UNWRAP |
| pkcs11-tool | RSA-PKCS |

Operations:
- Encrypt/Decrypt data
- Sign/Verify messages
- Wrap/Unwrap keys

```bash
# Sign
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism RSA-PKCS \
  --label "my-rsa-key" \
  --input-file data.bin \
  --output-file signature.bin
```

### CKM_RSA_PKCS_OAEP

RSA OAEP encryption (RFC 8017).

| Property | Value |
|----------|-------|
| Key sizes | 2048-4096 bits |
| Flags | CKF_ENCRYPT, CKF_DECRYPT, CKF_WRAP, CKF_UNWRAP |
| Hash | SHA-256 (default) |
| MGF | MGF1-SHA-256 |
| pkcs11-tool | RSA-PKCS-OAEP |

Parameters:

```c
typedef struct CK_RSA_PKCS_OAEP_PARAMS {
    CK_MECHANISM_TYPE hashAlg;      // CKM_SHA256
    CK_RSA_PKCS_MGF_TYPE mgf;       // CKG_MGF1_SHA256
    CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
    CK_VOID_PTR pSourceData;
    CK_ULONG ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;
```

### CKM_RSA_PKCS_PSS

RSA PSS signing (RFC 8017).

| Property | Value |
|----------|-------|
| Key sizes | 2048-4096 bits |
| Flags | CKF_SIGN, CKF_VERIFY |
| pkcs11-tool | RSA-PKCS-PSS |

Parameters:

```c
typedef struct CK_RSA_PKCS_PSS_PARAMS {
    CK_MECHANISM_TYPE hashAlg;      // CKM_SHA256
    CK_RSA_PKCS_MGF_TYPE mgf;       // CKG_MGF1_SHA256
    CK_ULONG sLen;                  // Salt length
} CK_RSA_PKCS_PSS_PARAMS;
```

`CK_RSA_PKCS_PSS_PARAMS` is validated against the mechanism actually requested. For a hash-specific PSS mechanism
(`CKM_SHA256_RSA_PKCS_PSS`, etc.), `hashAlg` must match the hash the mechanism name implies -- a mismatch is
rejected with `CKR_MECHANISM_PARAM_INVALID` rather than silently honored. The generic `CKM_RSA_PKCS_PSS`
mechanism carries no hash of its own, so `hashAlg` is authoritative and must name one of the supported digests.

**The input to `C_Sign`/`C_Verify` under `CKM_RSA_PKCS_PSS` is already a hash.** Per PKCS#11 v3.2 section 6.1.10
the mechanism "corresponds only to the part of PKCS #1 that involves block formatting and RSA, given a hash value;
it does not compute a hash value on the message to be signed". `hashAlg` therefore identifies the digest the
application computed -- PSS needs it for MGF1 and the salt length -- without being an instruction to apply it.
The module carries both facts to the backend separately: `SignRequest.Hash` names the digest and
`SignRequest.DataIsDigest` says the data is already that digest. The hash-prefixed variants
(`CKM_SHA256_RSA_PKCS_PSS` and friends) do compute the digest, so for those the module sends the message with
`DataIsDigest` clear.

Signatures produced under `CKM_RSA_PKCS_PSS` interoperate with SoftHSM2 and verify with `crypto/rsa.VerifyPSS`
over the digest the caller supplied.

```bash
# Sign with PSS
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism RSA-PKCS-PSS \
  --hash-algorithm SHA256 \
  --label "my-rsa-key" \
  --input-file data.bin \
  --output-file signature.bin
```

### CKM_SHA256_RSA_PKCS

RSA PKCS#1 v1.5 with SHA-256 hashing.

| Property | Value |
|----------|-------|
| Key sizes | 2048-4096 bits |
| Flags | CKF_SIGN, CKF_VERIFY |
| Hash | SHA-256 |

### CKM_SHA384_RSA_PKCS

RSA PKCS#1 v1.5 with SHA-384 hashing.

| Property | Value |
|----------|-------|
| Key sizes | 2048-4096 bits |
| Flags | CKF_SIGN, CKF_VERIFY |
| Hash | SHA-384 |

### CKM_SHA512_RSA_PKCS

RSA PKCS#1 v1.5 with SHA-512 hashing.

| Property | Value |
|----------|-------|
| Key sizes | 2048-4096 bits |
| Flags | CKF_SIGN, CKF_VERIFY |
| Hash | SHA-512 |

### CKM_SHA256_RSA_PKCS_PSS

RSA PSS with SHA-256 hashing.

| Property | Value |
|----------|-------|
| Key sizes | 2048-4096 bits |
| Flags | CKF_SIGN, CKF_VERIFY |
| Hash | SHA-256 |
| MGF | MGF1-SHA-256 |

### CKM_SHA384_RSA_PKCS_PSS

RSA PSS with SHA-384 hashing.

| Property | Value |
|----------|-------|
| Key sizes | 2048-4096 bits |
| Flags | CKF_SIGN, CKF_VERIFY |
| Hash | SHA-384 |
| MGF | MGF1-SHA-384 |

### CKM_SHA512_RSA_PKCS_PSS

RSA PSS with SHA-512 hashing.

| Property | Value |
|----------|-------|
| Key sizes | 2048-4096 bits |
| Flags | CKF_SIGN, CKF_VERIFY |
| Hash | SHA-512 |
| MGF | MGF1-SHA-512 |

## ECDSA Mechanisms

### CKM_EC_KEY_PAIR_GEN

Elliptic curve key pair generation.

| Property | Value |
|----------|-------|
| Curves | P-256, P-384, P-521 |
| Key sizes | 256, 384, 521 bits |
| Flags | CKF_GENERATE_KEY_PAIR, CKF_EC_F_P |

```bash
# P-256
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type EC:secp256r1 \
  --label "my-ec-key"

# P-384
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type EC:secp384r1 \
  --label "my-ec-384"
```

### CKM_ECDSA

Raw ECDSA signing (requires pre-hashed data).

| Property | Value |
|----------|-------|
| Key sizes | 256-521 bits |
| Flags | CKF_SIGN, CKF_VERIFY, CKF_EC_F_P |
| Input | Pre-computed hash |
| pkcs11-tool | ECDSA |

The signature at the PKCS#11 boundary is the raw concatenation `r || s`, each component padded to the curve's
field-element width -- never ASN.1 DER (PKCS#11 v3.2 section 6.3.1). Because the underlying crypto backends verify
via `crypto/ecdsa`, which expects DER, the module normalizes in both directions: a DER signature coming back from
a backend is converted to raw `r || s` before it reaches the caller, and a raw signature going into verification
is converted to DER before the round trip. A signature that already arrives as raw bytes is passed through
unchanged.

```bash
# Hash data first
sha256sum data.bin | xxd -r -p > hash.bin

# Sign hash
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism ECDSA \
  --label "my-ec-key" \
  --input-file hash.bin \
  --output-file signature.bin
```

### CKM_ECDSA_SHA256

ECDSA with integrated SHA-256 hashing.

| Property | Value |
|----------|-------|
| Key sizes | 256-521 bits |
| Flags | CKF_SIGN, CKF_VERIFY, CKF_EC_F_P |
| Hash | SHA-256 |
| pkcs11-tool | ECDSA-SHA256 |

### CKM_ECDSA_SHA384

ECDSA with integrated SHA-384 hashing.

| Property | Value |
|----------|-------|
| Key sizes | 256-521 bits |
| Flags | CKF_SIGN, CKF_VERIFY, CKF_EC_F_P |
| Hash | SHA-384 |
| pkcs11-tool | ECDSA-SHA384 |

### CKM_ECDSA_SHA512

ECDSA with integrated SHA-512 hashing.

| Property | Value |
|----------|-------|
| Key sizes | 256-521 bits |
| Flags | CKF_SIGN, CKF_VERIFY, CKF_EC_F_P |
| Hash | SHA-512 |
| pkcs11-tool | ECDSA-SHA512 |

### CKM_ECDH1_DERIVE

Elliptic curve Diffie-Hellman key derivation.

| Property | Value |
|----------|-------|
| Key sizes | 256-521 bits |
| Flags | CKF_DERIVE, CKF_EC_F_P |

#### Supported CK_EC_KDF_TYPE values

`CK_ECDH1_DERIVE_PARAMS.kdf` selects the key derivation function. Every value
below is implemented end to end and derives; `module.SupportedECDHKDFs()`
enumerates the same set programmatically.

| `CK_EC_KDF_TYPE` | Derivation |
|---|---|
| `CKD_SHA1_KDF`, `CKD_SHA1_KDF_ASN1`, `CKD_SHA1_KDF_CONCATENATE` | ANSI X9.63 / SHA-1 |
| `CKD_SHA224_KDF` | ANSI X9.63 / SHA-224 |
| `CKD_SHA256_KDF` | ANSI X9.63 / SHA-256 |
| `CKD_SHA384_KDF` | ANSI X9.63 / SHA-384 |
| `CKD_SHA512_KDF` | ANSI X9.63 / SHA-512 |
| `CKD_SHA3_224_KDF` … `CKD_SHA3_512_KDF` | ANSI X9.63 / SHA3-224 … SHA3-512 |
| `CKD_SHA1_KDF_SP800` … `CKD_SHA512_KDF_SP800` | NIST SP 800-56A / SHA-1 … SHA-512 |

The `_ASN1` and `_CONCATENATE` variants differ only in how the caller encodes
`pSharedData` before it is used as SharedInfo; the derivation is the same X9.63
construction, so all three SHA-1 types derive identical bytes for identical
inputs.

SHA-1 and the 224-bit digests are approved for this construction — see
[docs/crypto/kdf.md](../../crypto/kdf.md) — and are not affected by the
signature-side weak-hash policy.

Any other value, including `CKD_NULL`, `CKD_CPDIVERSIFY_KDF` and the
`CKD_BLAKE2B_*` types, returns **`CKR_MECHANISM_PARAM_INVALID`**. The KDF is a
mechanism *parameter*, not a mechanism, so `CKR_MECHANISM_PARAM_INVALID` is the
conformant code. `C_DeriveKey` never substitutes a different KDF for an
unsupported one: returning key material derived by a function the caller did
not name, under `CKR_OK`, is undetectable by the caller.

`CKD_NULL` (return the raw shared secret) is not offered because the transport
layer has no "no KDF" representation; it is refused rather than silently
answered with HKDF.

## EdDSA Mechanisms (Edwards Curves)

### CKM_EC_EDWARDS_KEY_PAIR_GEN

Edwards curve key pair generation for Ed25519 and Ed448.

| Property | Value |
|----------|-------|
| Curves | Ed25519, Ed448 |
| Key sizes | 255 (Ed25519), 448 (Ed448) bits |
| Flags | CKF_GENERATE_KEY_PAIR |
| Key type | CKK_EC_EDWARDS |

```bash
# Generate Ed25519 key pair
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --keypairgen --key-type EC:edwards25519 \
  --label "my-ed25519-key"
```

The Ed25519 curve OID (1.3.101.112) is passed via CKA_EC_PARAMS attribute.

### CKM_EDDSA

EdDSA signing and verification (RFC 8032).

| Property | Value |
|----------|-------|
| Key sizes | 255 (Ed25519), 448 (Ed448) bits |
| Flags | CKF_SIGN, CKF_VERIFY |
| Signature size | 64 bytes (Ed25519), 114 bytes (Ed448) |
| Input | Raw data (EdDSA handles hashing internally) |
| pkcs11-tool | EDDSA |

Key characteristics:
- **Deterministic signatures**: Same message always produces same signature
- **No pre-hashing required**: EdDSA handles internal hashing (SHA-512 for Ed25519)
- **Fast**: Edwards curves provide fast signature generation and verification
- **Small keys**: Ed25519 public keys are 32 bytes

```bash
# Sign with EdDSA
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --sign --mechanism EDDSA \
  --label "my-ed25519-key" \
  --input-file data.bin \
  --output-file signature.bin

# Verify EdDSA signature
pkcs11-tool --module $P11_MODULE \
  --login --pin 123456 \
  --verify --mechanism EDDSA \
  --label "my-ed25519-key" \
  --input-file data.bin \
  --signature-file signature.bin
```

### Ed25519 vs ECDSA

| Feature | Ed25519 | ECDSA (P-256) |
|---------|---------|---------------|
| Curve | Edwards25519 | secp256r1 |
| Signature size | 64 bytes | ~70 bytes (DER) |
| Public key size | 32 bytes | 64 bytes (uncompressed) |
| Deterministic | Yes | No (requires secure random) |
| Pre-hashing | No | Yes (or use SHA256_ECDSA) |
| Performance | Faster | Slower |

## AES Mechanisms

### CKM_AES_KEY_GEN

AES key generation.

| Property | Value |
|----------|-------|
| Key sizes | 128, 192, 256 bits |
| Flags | CKF_GENERATE |

### CKM_AES_ECB

AES ECB mode encryption.

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_ENCRYPT, CKF_DECRYPT |

ECB takes no mechanism parameter and no IV. The plaintext (encrypt) or
ciphertext (decrypt) must already be a whole number of 16-byte AES blocks;
a length that is not is refused rather than padded.

Note: ECB mode is not recommended for most use cases due to lack of semantic
security. Each block is enciphered independently, so identical plaintext
blocks produce identical ciphertext blocks and the block-level structure of
the plaintext is visible in the ciphertext. It also provides no integrity
protection. Prefer CKM_AES_GCM unless a specific key-transport construction
requires the raw block cipher.

### CKM_AES_CBC

AES CBC mode encryption.

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_ENCRYPT, CKF_DECRYPT, CKF_WRAP, CKF_UNWRAP |
| IV size | 16 bytes (required) |

Parameters:

```c
typedef struct CK_AES_CBC_PARAMS {
    CK_BYTE iv[16];
} CK_AES_CBC_PARAMS;
```

The 16-byte IV is a required mechanism parameter, not optional (PKCS#11 v3.2 sections 6.10.5/6.10.6):
`CK_MECHANISM.pParameter` points directly at the raw IV bytes for this mechanism -- there is no wrapping struct.
`EncryptInit`/`DecryptInit` reject a mechanism parameter that is not exactly 16 bytes with
`CKR_MECHANISM_PARAM_INVALID`; the module never generates or defaults the CBC IV on the caller's behalf.

### CKM_AES_CBC_PAD

AES CBC mode with PKCS#7 padding.

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_ENCRYPT, CKF_DECRYPT, CKF_WRAP, CKF_UNWRAP |
| IV size | 16 bytes |
| Padding | PKCS#7 |

### CKM_AES_GCM

AES GCM authenticated encryption.

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_ENCRYPT, CKF_DECRYPT, CKF_WRAP, CKF_UNWRAP |
| IV/Nonce | 12 bytes (recommended) |
| Tag size | 12-16 bytes (96, 104, 112, 120 or 128 bits); default 16 |

Parameters:

```c
typedef struct CK_GCM_PARAMS {
    CK_BYTE_PTR pIv;
    CK_ULONG ulIvLen;
    CK_BYTE_PTR pAAD;
    CK_ULONG ulAADLen;
    CK_ULONG ulTagBits;
} CK_GCM_PARAMS;
```

Per PKCS#11 v3.2 section 6.13.7, the ciphertext this module produces and expects on the wire is
`ciphertext || tag` -- the authentication tag is appended to the ciphertext, not returned or supplied separately.
The IV/nonce is never embedded in that byte string; it always travels in `CK_GCM_PARAMS.pIv`. Decryption requires
the caller to supply the exact IV used at encryption time (`CK_GCM_PARAMS.pIv`) -- unlike encryption, the module
never invents or recovers a decryption IV on its own.

The tag length is taken from `CK_GCM_PARAMS.ulTagBits` when set, defaulting to the full 128-bit (16-byte) tag
recommended by NIST SP 800-38D appendix C. A truncated tag is honored end to end: NIST SP 800-38D section 5.2.1.2
defines a t-bit tag as the leading t bits of the full 128-bit tag, and the module carries the requested length to
the backend on both `C_Encrypt` and `C_Decrypt` so the ciphertext framing and the tag verification agree.

PKCS#11 v3.2 section 6.13.7 permits any `ulTagBits` from 0 to 128, but SP 800-38D section 5.2.1.2 approves only
t of 96, 104, 112, 120 and 128. **The module enforces the intersection**: those five values plus 0 (meaning "use
the backend default"). Anything else is rejected with `CKR_MECHANISM_PARAM_INVALID` rather than rounded to a
permitted length, because a substituted tag length produces output no conforming peer can authenticate.

`ulTagBits` is resolved identically on all four AEAD initialization paths -- `C_EncryptInit`, `C_DecryptInit`,
`C_MessageEncryptInit` (which delegates to `C_EncryptInit`) and `C_MessageDecryptInit` -- as is
`CK_GCM_PARAMS.pAAD`. A parameter honored on one path and dropped on another makes every round trip fail as
`CKR_ENCRYPTED_DATA_INVALID`, which reads like corrupt ciphertext rather than a missing parameter.

Not every backend can truncate. The software and PKCS#11/HSM backends implement all five lengths (the HSM by
setting `CK_GCM_PARAMS.ulTagBits` on the token itself); AWS KMS, GCP KMS, Vault Transit and the phone backend
return an opaque ciphertext and refuse a non-default length rather than silently returning a 128-bit tag;
ChaCha20-Poly1305 refuses any length other than its full 16-byte tag, since Poly1305 has no truncation
construction (RFC 8439 section 2.5).

### CKM_AES_KEY_WRAP

AES key wrap (RFC 3394).

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_WRAP, CKF_UNWRAP |

### CKM_AES_KEY_WRAP_KWP

AES key wrap with padding (RFC 5649). This is the current identifier for the
construction; `CKM_AES_KEY_WRAP_PAD` is the deprecated alias PKCS#11 v3.2 §6.10
retains for existing applications. Both are advertised and both wrap
identically, so either spelling works.

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_WRAP, CKF_UNWRAP |

### CKM_AES_KEY_WRAP_PAD

AES key wrap with padding (RFC 5649). Deprecated alias of
`CKM_AES_KEY_WRAP_KWP`; prefer the latter in new applications.

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_WRAP, CKF_UNWRAP |

This is a different construction from CKM_AES_KEY_WRAP (RFC 3394), not a
variant of it: RFC 5649 prefixes an Alternative Initial Value carrying the
true plaintext length and pads the input to an 8-byte boundary. Key material
of any length can therefore be wrapped, including lengths RFC 3394 cannot
express at all, and the two mechanisms produce different blobs for the same
input.

## Digest Mechanisms

### CKM_SHA_1

SHA-1 message digest.

| Property | Value |
|----------|-------|
| Digest size | 20 bytes (160 bits) |
| Flags | CKF_DIGEST |

Note: SHA-1 is deprecated for security-sensitive applications.

### CKM_SHA224

SHA-224 message digest (FIPS 180-4 §6.3).

| Property | Value |
|----------|-------|
| Digest size | 28 bytes (224 bits) |
| Flags | CKF_DIGEST |

### CKM_SHA256

SHA-256 message digest.

| Property | Value |
|----------|-------|
| Digest size | 32 bytes (256 bits) |
| Flags | CKF_DIGEST |

### CKM_SHA384

SHA-384 message digest.

| Property | Value |
|----------|-------|
| Digest size | 48 bytes (384 bits) |
| Flags | CKF_DIGEST |

### CKM_SHA512

SHA-512 message digest.

| Property | Value |
|----------|-------|
| Digest size | 64 bytes (512 bits) |
| Flags | CKF_DIGEST |

### CKM_SHA512_224

Truncated SHA-512 message digest (FIPS 180-4 §6.6). A distinct function from
SHA-224, not a re-labelling of it.

| Property | Value |
|----------|-------|
| Digest size | 28 bytes (224 bits) |
| Flags | CKF_DIGEST |

### CKM_SHA512_256

Truncated SHA-512 message digest (FIPS 180-4 §6.7). A distinct function from
SHA-256 despite the matching digest length.

| Property | Value |
|----------|-------|
| Digest size | 32 bytes (256 bits) |
| Flags | CKF_DIGEST |

## Mechanism Flags

| Flag | Value | Description |
|------|-------|-------------|
| CKF_ENCRYPT | 0x00000100 | Supports encryption |
| CKF_DECRYPT | 0x00000200 | Supports decryption |
| CKF_DIGEST | 0x00000400 | Supports hashing |
| CKF_SIGN | 0x00000800 | Supports signing |
| CKF_SIGN_RECOVER | 0x00001000 | Supports signing with message recovery |
| CKF_VERIFY | 0x00002000 | Supports verification |
| CKF_VERIFY_RECOVER | 0x00004000 | Supports verification with message recovery |
| CKF_GENERATE | 0x00008000 | Supports key generation |
| CKF_GENERATE_KEY_PAIR | 0x00010000 | Supports key pair generation |
| CKF_WRAP | 0x00020000 | Supports key wrapping |
| CKF_UNWRAP | 0x00040000 | Supports key unwrapping |
| CKF_DERIVE | 0x00080000 | Supports key derivation |
| CKF_EC_F_P | 0x00100000 | EC: prime field |
| CKF_EC_OID | 0x00800000 | EC: parameters may be a named-curve OID |
| CKF_ENCAPSULATE | 0x10000000 | Supports `C_EncapsulateKey` |
| CKF_DECAPSULATE | 0x20000000 | Supports `C_DecapsulateKey` |
| CKF_EXTENSION | 0x80000000 | Vendor extension |

## Mechanism Summary Table

The complete table — every advertised mechanism with its operations, key-size
range, unit and FIPS status, plus everything registered but withheld — is in the
[support matrix](support-matrix.md). An abridged view:

| Mechanism | Sign | Verify | Encrypt | Decrypt | Wrap/Unwrap | Key Gen |
|-----------|------|--------|---------|---------|-------------|---------|
| CKM_RSA_PKCS | Y | Y | Y | Y | Y | - |
| CKM_RSA_PKCS_OAEP | - | - | Y | Y | Y | - |
| CKM_RSA_PKCS_PSS | Y | Y | - | - | - | - |
| CKM_RSA_PKCS_KEY_PAIR_GEN | - | - | - | - | - | Y |
| CKM_ECDSA | Y | Y | - | - | - | - |
| CKM_ECDSA_SHA256 | Y | Y | - | - | - | - |
| CKM_EC_KEY_PAIR_GEN | - | - | - | - | - | Y |
| CKM_EDDSA | Y | Y | - | - | - | - |
| CKM_EC_EDWARDS_KEY_PAIR_GEN | - | - | - | - | - | Y |
| CKM_AES_GCM | - | - | Y | Y | Y | - |
| CKM_AES_CBC | - | - | Y | Y | Y | - |
| CKM_AES_KEY_WRAP | - | - | - | - | Y | - |
| CKM_AES_KEY_GEN | - | - | - | - | - | Y |
| CKM_ML_DSA | Y | Y | - | - | - | - |
| CKM_SHA256 | - | - | - | - | - | - |

`CKM_RSA_PKCS` additionally carries sign-recover and verify-recover.
`CKM_ML_KEM` carries encapsulate and decapsulate, which are neither
encrypt/decrypt nor derive.

## Quantum-Safe Mechanisms (Vendor-Defined)

Quantum-safe cryptography predates the v3.2 standard identifiers in this module, so a set of vendor-defined mechanisms exists alongside them. No build tag is required, but **none of the vendor mechanisms is advertised**: they are registered so the implementation survives and withheld from `C_GetMechanismList` so nothing is promised. New callers should use the advertised `CKM_ML_KEM` / `CKM_ML_DSA` described in [Standard Dispatch](#ml-kem-fips-203-and-ml-dsa-fips-204-standard-dispatch) below.

### ML-DSA (Module-Lattice Digital Signature Algorithm) - NIST FIPS 204

ML-DSA (FIPS 204) provides quantum-resistant digital signatures via Cloudflare's `circl` library.

#### CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN (0x80001001)

ML-DSA-44 key pair generation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 2 (~128-bit classical) |
| Public key size | 1312 bytes |
| Secret key size | 2560 bytes |
| Flags | CKF_GENERATE_KEY_PAIR, CKF_EXTENSION |

#### CKM_VENDOR_ML_DSA_44 (0x80001002)

ML-DSA-44 signing and verification.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 2 |
| Signature size | 2420 bytes |
| Flags | CKF_SIGN, CKF_VERIFY, CKF_EXTENSION |

#### CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN (0x80001003)

ML-DSA-65 key pair generation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 3 (~192-bit classical) |
| Public key size | 1952 bytes |
| Secret key size | 4032 bytes |
| Flags | CKF_GENERATE_KEY_PAIR, CKF_EXTENSION |

#### CKM_VENDOR_ML_DSA_65 (0x80001004)

ML-DSA-65 signing and verification.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 3 |
| Signature size | 3309 bytes |
| Flags | CKF_SIGN, CKF_VERIFY, CKF_EXTENSION |

#### CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN (0x80001005)

ML-DSA-87 key pair generation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 5 (~256-bit classical) |
| Public key size | 2592 bytes |
| Secret key size | 4896 bytes |
| Flags | CKF_GENERATE_KEY_PAIR, CKF_EXTENSION |

#### CKM_VENDOR_ML_DSA_87 (0x80001006)

ML-DSA-87 signing and verification.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 5 |
| Signature size | 4627 bytes |
| Flags | CKF_SIGN, CKF_VERIFY, CKF_EXTENSION |

### ML-KEM (Module-Lattice Key Encapsulation Mechanism) - NIST FIPS 203

ML-KEM (FIPS 203) provides quantum-resistant key encapsulation. The 768 and 1024
parameter sets come from Go's standard library `crypto/mlkem`; ML-KEM-512 comes
from `pkg/quantum/mlkem512`, which wraps CIRCL's FIPS 203 implementation because
`crypto/mlkem` implements only the other two. Note that CIRCL also ships
`kem/kyber/kyber512`, the NIST round-3 submission — a different algorithm, and
not what is used.

#### ML-KEM-512 (0x80002001-0x80002003)

`CKM_VENDOR_ML_KEM_512_KEY_GEN`, `_ENCAPSULATE` and `_DECAPSULATE` generate,
encapsulate and decapsulate at security level 512. The standard `CKM_ML_KEM`
mechanisms reach the same code through a `CKA_PARAMETER_SET` of
`CKP_ML_KEM_512`.

#### CKM_VENDOR_ML_KEM_768_KEY_GEN (0x80002004)

ML-KEM-768 key pair generation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 3 (~192-bit classical) |
| Public key size | 1184 bytes |
| Secret key size | 2400 bytes |
| Flags | CKF_GENERATE_KEY_PAIR, CKF_EXTENSION |

#### CKM_VENDOR_ML_KEM_768_ENCAPSULATE (0x80002005)

ML-KEM-768 key encapsulation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 3 |
| Ciphertext size | 1088 bytes |
| Shared secret | 32 bytes |
| Flags | CKF_ENCAPSULATE, CKF_EXTENSION |

#### CKM_VENDOR_ML_KEM_768_DECAPSULATE (0x80002006)

ML-KEM-768 key decapsulation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 3 |
| Shared secret | 32 bytes |
| Flags | CKF_DECAPSULATE, CKF_EXTENSION |

#### CKM_VENDOR_ML_KEM_1024_KEY_GEN (0x80002007)

ML-KEM-1024 key pair generation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 5 (~256-bit classical) |
| Public key size | 1568 bytes |
| Secret key size | 3168 bytes |
| Flags | CKF_GENERATE_KEY_PAIR, CKF_EXTENSION |

#### CKM_VENDOR_ML_KEM_1024_ENCAPSULATE (0x80002008)

ML-KEM-1024 key encapsulation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 5 |
| Ciphertext size | 1568 bytes |
| Shared secret | 32 bytes |
| Flags | CKF_ENCAPSULATE, CKF_EXTENSION |

#### CKM_VENDOR_ML_KEM_1024_DECAPSULATE (0x80002009)

ML-KEM-1024 key decapsulation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 5 |
| Shared secret | 32 bytes |
| Flags | CKF_DECAPSULATE, CKF_EXTENSION |

### Vendor-Defined Key Types

| Key Type | Value | Description |
|----------|-------|-------------|
| CKK_VENDOR_ML_DSA | 0x80000001 | ML-DSA (FIPS 204) key |
| CKK_VENDOR_ML_KEM | 0x80000002 | ML-KEM (FIPS 203) key |

### ML-KEM (FIPS 203) and ML-DSA (FIPS 204): Standard Dispatch

Alongside the vendor-defined mechanisms above, the module also accepts the OASIS-standard `CKM_ML_KEM` and
`CKM_ML_DSA` mechanisms (see [v3.2 Compliance](v32-compliance.md) for their full constant list). Unlike the
vendor mechanisms, which encode the security level in the mechanism itself (e.g., `CKM_VENDOR_ML_DSA_65` is
always ML-DSA-65), the standard mechanisms are algorithm-level: the security level comes from the key object's
`CKA_PARAMETER_SET` attribute. The module resolves the concrete ML-KEM/ML-DSA level by reading that attribute
from the key, falling back to the raw key material's length when the attribute is absent -- the ML-KEM and ML-DSA
public key sizes for each level never collide, so the length alone is unambiguous.

For these two mechanisms, `ulMinKeySize`/`ulMaxKeySize` in `CK_MECHANISM_INFO` are the supported *public key* size
range in bytes (per PKCS#11 v3.2 sections 6.67.4/6.67.5 for ML-DSA and 6.68.4/6.68.5 for ML-KEM), not a bit count:
ML-DSA spans 1312-2592 bytes across its three levels, and ML-KEM spans 800-1568 bytes.

### Quantum Mechanism Summary Table

| Mechanism | Key Gen | Sign | Verify | Encapsulate | Decapsulate | Registered |
|-----------|---------|------|--------|-------------|-------------|------------|
| CKM_VENDOR_ML_DSA_44 | Y | Y | Y | - | - | yes, unadvertised |
| CKM_VENDOR_ML_DSA_65 | Y | Y | Y | - | - | yes, unadvertised |
| CKM_VENDOR_ML_DSA_87 | Y | Y | Y | - | - | yes, unadvertised |
| CKM_VENDOR_ML_KEM_512 | - | - | - | - | - | **no** |
| CKM_VENDOR_ML_KEM_768 | Y | - | - | Y | Y | yes, unadvertised |
| CKM_VENDOR_ML_KEM_1024 | Y | - | - | Y | Y | yes, unadvertised |

None of the vendor mechanisms appears in `C_GetMechanismList`. Reach ML-KEM and
ML-DSA through the advertised algorithm-level `CKM_ML_KEM` / `CKM_ML_DSA`
instead, selecting the parameter set with `CKA_PARAMETER_SET`.

### Parameter set support

| Parameter set | Status |
|---------------|--------|
| ML-DSA-44 | Supported |
| ML-DSA-65 | Supported |
| ML-DSA-87 | Supported |
| ML-KEM-512 | Supported via `pkg/quantum/mlkem512` (CIRCL FIPS 203); absent from Go's `crypto/mlkem` |
| ML-KEM-768 | Supported |
| ML-KEM-1024 | Supported |

### References

- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
- OASIS PKCS#11 v3.0: Vendor-defined mechanisms (Section 6.1)

## Key Derivation Mechanisms

### Where the derivation happens

`C_DeriveKey` runs the KDF over the base key's material and nothing else. How
that material is reached depends on how the base key came to exist, and the
module sends exactly one of the two forms to the server:

| Base key | What the module sends | Where the KDF runs |
|----------|-----------------------|--------------------|
| Created by `C_CreateObject` with `CKA_VALUE` | the key material | server side, over the supplied bytes |
| Created by `C_GenerateKey` (or otherwise held by the backend) | the base key's **identity** — backend name and key identifier | inside the backend, over the key it holds |

The second form exists because the module runs inside the calling
application's address space and knows a backend-held key only by its object
handle, label and key identifier. None of those is secret. Running the KDF
there would either derive from a non-secret — a key anyone holding the same
label could reproduce — or require exporting a key whose `CKA_SENSITIVE` and
`CKA_EXTRACTABLE` settings forbid export. Sending the identity instead keeps
the base key where it already is.

A base key that resolves to neither `CKA_VALUE` nor a backend key identifier
is refused with `CKR_KEY_HANDLE_INVALID`. There is no fallback: deriving from
a key's name is not a derivation.

Backends that can run the KDF over their own symmetric key material implement
`types.SymmetricKeyDeriver`: **software**, the **symmetric** key provider,
**TPM 2.0** (which unseals inside the daemon and zeroizes afterwards) and
**PKCS#11** (for a token key whose `CKA_EXTRACTABLE` permits the token to
release it). AWS KMS, GCP KMS, Azure Key Vault, Vault Transit and the phone
backend expose neither the key material nor a KDF over it, so they do not
implement the capability and a derivation naming one of them is refused
rather than answered.

`CKA_EXTRACTABLE` is **not** required on the base key. PKCS#11 v3.2 §5.18.5
constrains the derived key's sensitivity and extractability from the base
key's and places no extractability requirement on the base key itself.

### CKM_HKDF_DERIVE

HKDF key derivation (RFC 5869).

| Property | Value |
|----------|-------|
| Key sizes | Variable |
| Flags | CKF_DERIVE |
| Hash | SHA-256, SHA-384, SHA-512 |

Parameters:

```c
typedef struct CK_HKDF_PARAMS {
    CK_BBOOL bExtract;            // TRUE to perform extract step
    CK_BBOOL bExpand;             // TRUE to perform expand step
    CK_MECHANISM_TYPE prfHashMechanism; // Hash algorithm (CKM_SHA256, etc.)
    CK_ULONG ulSaltType;          // CKF_HKDF_SALT_NULL, CKF_HKDF_SALT_DATA, CKF_HKDF_SALT_KEY
    CK_BYTE_PTR pSalt;            // Salt data
    CK_ULONG ulSaltLen;           // Salt length
    CK_OBJECT_HANDLE hSaltKey;    // Salt key handle (if ulSaltType is CKF_HKDF_SALT_KEY)
    CK_BYTE_PTR pInfo;            // Application-specific info
    CK_ULONG ulInfoLen;           // Info length
} CK_HKDF_PARAMS;
```

### CKM_SP800_108_COUNTER_KDF

NIST SP 800-108 Counter Mode KDF.

| Property | Value |
|----------|-------|
| Key sizes | Variable |
| Flags | CKF_DERIVE |
| PRF | HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512 |

The Counter Mode KDF uses a counter value that is incremented for each iteration of the PRF.

### CKM_SP800_108_FEEDBACK_KDF

NIST SP 800-108 Feedback Mode KDF.

| Property | Value |
|----------|-------|
| Key sizes | Variable |
| Flags | CKF_DERIVE |
| PRF | HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512 |

The Feedback Mode KDF chains the output of each PRF iteration as input to the next.

### CKM_SP800_108_DOUBLE_PIPELINE_KDF

NIST SP 800-108 Double Pipeline Iteration Mode KDF.

| Property | Value |
|----------|-------|
| Key sizes | Variable |
| Flags | CKF_DERIVE |
| PRF | HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512 |

The Double Pipeline Mode uses two separate pipelines for key derivation.

## Excluded Mechanisms

The following mechanisms are intentionally **not supported** due to deprecation or security concerns:

| Mechanism Category | Status | Recommendation |
|-------------------|--------|----------------|
| DSA (CKM_DSA_*) | Excluded | Use ECDSA or EdDSA |
| DH (CKM_DH_PKCS_*, CKM_X9_42_DH_*) | Excluded | Use ECDH or X25519 |
| DES (CKM_DES_*) | Excluded | Use AES |
| RC2 (CKM_RC2_*) | Excluded | Use AES |
| RC4 (CKM_RC4_*) | Excluded | Use AES-GCM |
| IDEA (CKM_IDEA_*) | Excluded | Use AES |

Modern alternatives are strongly recommended for all new applications.

### Removed because the module cannot perform them

A mechanism descriptor is a promise: `C_GetMechanismInfo` is how an application
decides what to ask for, so a mechanism the module cannot perform must not have
one. The following were registered with capability flags the implementation did
not back, which made `C_*Init` accept the mechanism and the operation then fail.
They now return `CKR_MECHANISM_INVALID` immediately, and each returns as soon as
its operation works end to end.

| Mechanism | Why |
|-----------|-----|
| CKM_SHA3_256, CKM_SHA3_384, CKM_SHA3_512 | Carried CKF_DIGEST; the digest layer has no SHA-3 case |
| CKM_AES_CTR | Ignores `CK_AES_CTR_PARAMS.cb`; the same plaintext, key and counter block produce different ciphertexts |
| CKM_AES_CCM | Returns a ciphertext the length of the plaintext, so it carries no authentication tag |
| CKM_AES_CMAC, CKM_XEDDSA | `C_Sign` fails with `CKR_FUNCTION_FAILED`; no signing path exists |
| CKM_ECMQV_DERIVE, CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE, CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH, CKM_PUB_KEY_FROM_PRIV_KEY | Not among the mechanisms `C_DeriveKey` dispatches on |
| CKM_ECDH_AES_KEY_WRAP, CKM_ECDH_X_AES_KEY_WRAP, CKM_ECDH_COF_AES_KEY_WRAP | Carried CKF_WRAP/CKF_UNWRAP; nothing routes them to a wrapping algorithm |
| CKM_HKDF_KEY_GEN | No mechanism-to-key-type mapping, so `C_GenerateKey` cannot build a request |

### Implemented but not advertised

These have a working implementation in the module and are withheld from
`C_GetMechanismList` because no configured backend can complete the operation,
or because `CK_MECHANISM_INFO` cannot describe them truthfully. They are
registered so the implementation survives, and unadvertised so nothing is
promised.

| Mechanism | Why |
|-----------|-----|
| CKM_RSA_X_509 | Only verify-recover is performed. Sign, verify, encrypt and decrypt are refused with `CKR_MECHANISM_INVALID` by withholding their flags — see [deviations.md](deviations.md#no-raw-rsa-signing-or-decryption) |
| CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC | No backend performs a symmetric MAC. The constants remain valid as KDF PRF selectors |
| CKM_EC_MONTGOMERY_KEY_PAIR_GEN | No backend generates a Montgomery (X25519/X448) key pair |
| CKM_GENERIC_SECRET_KEY_GEN | Generates only at AES key sizes, while §6.9 requires arbitrary lengths, so no contiguous key-size range is truthful |
| HashML-DSA, SLH-DSA, HashSLH-DSA, HSS/LMS, XMSS, XMSS^MT, and the vendor ML-DSA / ML-KEM mechanisms | Registered constants and descriptors with no end-to-end operation. The algorithm-level `CKM_ML_KEM` and `CKM_ML_DSA` **are** advertised |

The full list, with counts, is in the [support matrix](support-matrix.md#not-advertised-and-why).

## List Mechanisms

Query supported mechanisms:

```bash
pkcs11-tool --module $P11_MODULE --list-mechanisms
```

Output example:

```
Supported mechanisms:
  RSA-PKCS-KEY-PAIR-GEN, keySize={2048,4096}, generate_key_pair
  RSA-PKCS, keySize={2048,4096}, encrypt, decrypt, sign, verify, wrap, unwrap
  RSA-PKCS-OAEP, keySize={2048,4096}, encrypt, decrypt, wrap, unwrap
  RSA-PKCS-PSS, keySize={2048,4096}, sign, verify
  SHA256-RSA-PKCS, keySize={2048,4096}, sign, verify
  EC-KEY-PAIR-GEN, keySize={256,521}, generate_key_pair
  ECDSA, keySize={256,521}, sign, verify
  ECDSA-SHA256, keySize={256,521}, sign, verify
  EC-EDWARDS-KEY-PAIR-GEN, keySize={255,448}, generate_key_pair
  EDDSA, keySize={255,448}, sign, verify
  AES-KEY-GEN, keySize={16,32}, generate
  AES-CBC, keySize={16,32}, encrypt, decrypt, wrap, unwrap
  AES-GCM, keySize={16,32}, encrypt, decrypt, wrap, unwrap
  SHA256, digest
  SHA384, digest
  SHA512, digest
```

## FIPS Mode

The module implements the full OASIS PKCS#11 v3.2 mechanism set by default. FIPS
140-3 restricts a validated module to approved algorithms, so those are two
different claims: the specification defines what a Cryptoki module must
implement, and FIPS narrows which of it a validated deployment may use.

FIPS mode is enabled through the same process-wide signal the rest of the stack
uses:

```bash
GOFIPS140=on xkmsd --config /etc/xkms/xkmsd.yaml
```

When it is enabled, a non-approved mechanism is withheld from
`C_GetMechanismList`, `C_GetMechanismInfo` reports it as unknown, and any
operation naming it fails with `CKR_MECHANISM_INVALID`. Advertising and
enforcement are driven from the same flag on one mechanism table, so a mechanism
the module offers always works and one it withholds is always refused — there is
no state in which an application can use something the module does not admit to
supporting.

### Mechanisms withheld in FIPS mode

| Mechanism | Reason |
|-----------|--------|
| `CKM_SHA1_RSA_PKCS` | SHA-1 signature generation is disallowed by NIST SP 800-131A Rev. 2 |
| `CKM_ECDSA_SHA1` | same |
| `CKM_HKDF_DERIVE` | SP 800-56C Rev. 2 approves extract-then-expand for a shared secret from an approved key-establishment scheme; `C_DeriveKey` applies it to an arbitrary base key |
| `CKM_HKDF_DATA` | same |

RSA additionally narrows from a 4096-bit ceiling to 3072 bits (v3.2 §6.1.21).

`CKM_SHA_1` itself remains available: SHA-1 is still an approved hash function
(FIPS 180-4), and it is only *signature generation* over it that is disallowed.

Everything else the module advertises is FIPS-approved, including EdDSA (FIPS
186-5), ML-KEM (FIPS 203), ML-DSA (FIPS 204) and the SP 800-108 KDFs.

### Interaction with the daemon's weak-hash policy

The module governs which mechanisms exist; the daemon separately governs which
digests may be used for signing. `crypto.allow_weak_hashes` is `false` by
default, so a SHA-1 signature is refused by the service layer even outside FIPS
mode, while `CKM_SHA1_RSA_PKCS` stays in `C_GetMechanismList`: advertising and
performing are separate. A deployment that needs SHA-1 for legacy interop —
including the conformance suite, whose test daemon sets it — must enable it
explicitly.

### Interaction with the daemon's key-wrap policy

The same split applies to `C_WrapKey` / `C_UnwrapKey`. The module advertises the
mechanisms; the daemon decides which of them it will perform. Three of them
authenticate nothing, so `crypto.allow_legacy_key_wrap` is `false` by default
and each is refused by the service layer:

| Mechanism | Service algorithm | Why it is gated |
|-----------|-------------------|-----------------|
| `CKM_RSA_PKCS` | `RSA_PKCS1_V1_5` | PKCS#1 v1.5 has no integrity check; its conformance check is the Bleichenbacher / Marvin decryption oracle (RFC 8017 §7.2.2) |
| `CKM_AES_CBC_PAD` | `AES_CBC_PAD` | PKCS#7 unpadding has no integrity check; its accept/reject answer is the Vaudenay padding oracle. Measured here: 215 random blobs before one was accepted |
| `CKM_AES_CBC` | `AES_CBC` | Unpadded CBC checks nothing at all. A random 48-byte blob unwraps into 32 bytes of key material on the first try, and `UnwrapKeyByID` imports it as a usable key |

`C_UnwrapKey` takes a caller-designated key and a caller-supplied blob over
every transport (gRPC, QUIC, MCP, the unix socket, REST), which is what turns
each of these into a remotely reachable oracle. **An unwrap success under any of
them is not authentication**: it means the ciphertext decrypted, and the caller
chose the ciphertext.

PKCS#11 v3.2 §6.10 (the AES-CBC pair) and §6.1 (`CKM_RSA_PKCS`) do sanction all
three, so this is deployment policy rather than a conformance deviation. A
deployment that must interoperate with an application requiring one sets:

```yaml
crypto:
  allow_legacy_key_wrap: true
```

`Config.ComplianceGaps` reports that as a gap, so the daemon then refuses to
start without `--insecure` (`XKMS_INSECURE=true`). While it is off, a request
naming one of the three is refused with a typed policy error that names the
mechanism and the setting — not with "unsupported algorithm", which would send
an operator looking for a missing feature.

`RSAES_OAEP_SHA_1` is *not* covered by this setting. It is refused
unconditionally in both states: OAEP has no legacy blobs to read in this
codebase, so no interop argument reaches the weakest OAEP digest.
