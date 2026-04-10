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

Note: ECB mode is not recommended for most use cases due to lack of semantic security.

### CKM_AES_CBC

AES CBC mode encryption.

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_ENCRYPT, CKF_DECRYPT |
| IV size | 16 bytes |

Parameters:

```c
typedef struct CK_AES_CBC_PARAMS {
    CK_BYTE iv[16];
} CK_AES_CBC_PARAMS;
```

### CKM_AES_CBC_PAD

AES CBC mode with PKCS#7 padding.

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_ENCRYPT, CKF_DECRYPT |
| IV size | 16 bytes |
| Padding | PKCS#7 |

### CKM_AES_GCM

AES GCM authenticated encryption.

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_ENCRYPT, CKF_DECRYPT |
| IV/Nonce | 12 bytes (recommended) |
| Tag size | 16 bytes |

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

### CKM_AES_KEY_WRAP

AES key wrap (RFC 3394).

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_WRAP, CKF_UNWRAP |

### CKM_AES_KEY_WRAP_PAD

AES key wrap with padding (RFC 5649).

| Property | Value |
|----------|-------|
| Key sizes | 128-256 bits |
| Flags | CKF_WRAP, CKF_UNWRAP |

## Digest Mechanisms

### CKM_SHA_1

SHA-1 message digest.

| Property | Value |
|----------|-------|
| Digest size | 20 bytes (160 bits) |
| Flags | CKF_DIGEST |

Note: SHA-1 is deprecated for security-sensitive applications.

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

## Mechanism Flags

| Flag | Value | Description |
|------|-------|-------------|
| CKF_ENCRYPT | 0x00000100 | Supports encryption |
| CKF_DECRYPT | 0x00000200 | Supports decryption |
| CKF_DIGEST | 0x00000400 | Supports hashing |
| CKF_SIGN | 0x00000800 | Supports signing |
| CKF_VERIFY | 0x00002000 | Supports verification |
| CKF_GENERATE | 0x00008000 | Supports key generation |
| CKF_GENERATE_KEY_PAIR | 0x00010000 | Supports key pair generation |
| CKF_WRAP | 0x00020000 | Supports key wrapping |
| CKF_UNWRAP | 0x00040000 | Supports key unwrapping |
| CKF_DERIVE | 0x00080000 | Supports key derivation |
| CKF_EC_F_P | 0x00100000 | EC: prime field |

## Mechanism Summary Table

| Mechanism | Sign | Verify | Encrypt | Decrypt | Key Gen |
|-----------|------|--------|---------|---------|---------|
| CKM_RSA_PKCS | Y | Y | Y | Y | - |
| CKM_RSA_PKCS_OAEP | - | - | Y | Y | - |
| CKM_RSA_PKCS_PSS | Y | Y | - | - | - |
| CKM_RSA_PKCS_KEY_PAIR_GEN | - | - | - | - | Y |
| CKM_ECDSA | Y | Y | - | - | - |
| CKM_ECDSA_SHA256 | Y | Y | - | - | - |
| CKM_EC_KEY_PAIR_GEN | - | - | - | - | Y |
| CKM_EDDSA | Y | Y | - | - | - |
| CKM_EC_EDWARDS_KEY_PAIR_GEN | - | - | - | - | Y |
| CKM_AES_GCM | - | - | Y | Y | - |
| CKM_AES_CBC | - | - | Y | Y | - |
| CKM_AES_KEY_GEN | - | - | - | - | Y |
| CKM_SHA256 | - | - | - | - | - |

## Quantum-Safe Mechanisms (Vendor-Defined)

Quantum-safe cryptography support is provided through vendor-defined mechanisms using NIST post-quantum algorithms. These mechanisms are always available -- no special build tags are required.

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

ML-KEM (FIPS 203) provides quantum-resistant key encapsulation via Go's standard library `crypto/mlkem` package.

#### CKM_VENDOR_ML_KEM_512_KEY_GEN (0x80002001)

ML-KEM-512 key pair generation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 1 (~128-bit classical) |
| Public key size | 800 bytes |
| Secret key size | 1632 bytes |
| Flags | CKF_GENERATE_KEY_PAIR, CKF_EXTENSION |

#### CKM_VENDOR_ML_KEM_512_ENCAPSULATE (0x80002002)

ML-KEM-512 key encapsulation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 1 |
| Ciphertext size | 768 bytes |
| Shared secret | 32 bytes |
| Flags | CKF_DERIVE, CKF_EXTENSION |

#### CKM_VENDOR_ML_KEM_512_DECAPSULATE (0x80002003)

ML-KEM-512 key decapsulation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 1 |
| Shared secret | 32 bytes |
| Flags | CKF_DERIVE, CKF_EXTENSION |

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
| Flags | CKF_DERIVE, CKF_EXTENSION |

#### CKM_VENDOR_ML_KEM_768_DECAPSULATE (0x80002006)

ML-KEM-768 key decapsulation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 3 |
| Shared secret | 32 bytes |
| Flags | CKF_DERIVE, CKF_EXTENSION |

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
| Flags | CKF_DERIVE, CKF_EXTENSION |

#### CKM_VENDOR_ML_KEM_1024_DECAPSULATE (0x80002009)

ML-KEM-1024 key decapsulation.

| Property | Value |
|----------|-------|
| Security Level | NIST Category 5 |
| Shared secret | 32 bytes |
| Flags | CKF_DERIVE, CKF_EXTENSION |

### Vendor-Defined Key Types

| Key Type | Value | Description |
|----------|-------|-------------|
| CKK_VENDOR_ML_DSA | 0x80000001 | ML-DSA (FIPS 204) key |
| CKK_VENDOR_ML_KEM | 0x80000002 | ML-KEM (FIPS 203) key |

### Quantum Mechanism Summary Table

| Mechanism | Key Gen | Sign | Verify | Encapsulate | Decapsulate |
|-----------|---------|------|--------|-------------|-------------|
| CKM_VENDOR_ML_DSA_44 | Y | Y | Y | - | - |
| CKM_VENDOR_ML_DSA_65 | Y | Y | Y | - | - |
| CKM_VENDOR_ML_DSA_87 | Y | Y | Y | - | - |
| CKM_VENDOR_ML_KEM_512 | Y | - | - | Y | Y |
| CKM_VENDOR_ML_KEM_768 | Y | - | - | Y | Y |
| CKM_VENDOR_ML_KEM_1024 | Y | - | - | Y | Y |

### Implementation Status

| Algorithm | Key Gen | Sign/Verify | Encap/Decap | Notes |
|-----------|---------|-------------|-------------|-------|
| ML-DSA-44 | Yes | Yes | N/A | Full support via circl |
| ML-DSA-65 | Yes | Yes | N/A | Full support via circl |
| ML-DSA-87 | Yes | Yes | N/A | Full support via circl |
| ML-KEM-512 | No | N/A | No | Not supported (not in Go stdlib) |
| ML-KEM-768 | Yes | N/A | Yes | Full support via crypto/mlkem |
| ML-KEM-1024 | Yes | N/A | Yes | Full support via crypto/mlkem |

### References

- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
- OASIS PKCS#11 v3.0: Vendor-defined mechanisms (Section 6.1)

## Key Derivation Mechanisms

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
  AES-KEY-GEN, keySize={128,256}, generate
  AES-CBC, keySize={128,256}, encrypt, decrypt
  AES-GCM, keySize={128,256}, encrypt, decrypt
  SHA256, digest
  SHA384, digest
  SHA512, digest
```
