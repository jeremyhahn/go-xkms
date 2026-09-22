# Mechanism Support Matrix

The authoritative, one-page answer to "what will this token do?".

Every row below is transcribed from the module's mechanism registry, which is the
single source of truth: `C_GetMechanismList`, `C_GetMechanismInfo` and every
`C_*Init` gate resolve through it, so what is advertised and what is performed
cannot disagree.

| Source | File |
|--------|------|
| Classical mechanisms (48 entries) | `pkg/pkcs11/module/mechanism.go`, `mechanismRegistry` |
| PKCS#11 v3.2 PQC mechanisms (34 entries) | `pkg/pkcs11/module/mechanism_v32.go`, `v32MechanismRegistry` |
| Vendor PQC mechanisms (12 entries) | `pkg/pkcs11/module/mechanism_quantum.go`, `quantumMechanismRegistry` |
| Projection into `C_GetMechanismList` | `pkg/pkcs11/module/token.go`, `defaultMechanismInfo` |
| Reasons an entry is withheld | `pkg/pkcs11/module/mechanism_conformance_test.go`, `mechanismsAwaitingAnImplementation` |

**94 mechanisms are registered. 46 are advertised** (42 under FIPS mode). A
registered-but-unadvertised mechanism is absent from `C_GetMechanismList`; see
[Not advertised, and why](#not-advertised-and-why).

## Reading the key-size columns

`ulMinKeySize`/`ulMaxKeySize` do not carry a unit in `CK_MECHANISM_INFO` — the
unit is fixed per mechanism family by the specification, and the families here do
not agree. The **Unit** column states which one applies.

| Family | Unit | Spec |
|--------|------|------|
| RSA | bits (modulus) | v3.2 §6.1.4 |
| EC / EdDSA | bits (field size) | v3.2 §6.3.1, §6.3.9-6.3.10 |
| AES | **bytes** | v3.2 §6.10.3 |
| ML-KEM / ML-DSA | **bytes** (public key) | v3.2 §6.67.4-6.67.5, §6.68.4-6.68.5 |
| Digests, KDFs | none | v3.2 §6.1 Table 10 |

`0` in the maximum column is the registry's "no maximum I enforce" sentinel. No
advertised mechanism carries it alongside a non-zero minimum, because an
application reading `ulMinKeySize=1, ulMaxKeySize=0` would see an empty range.

## Advertised mechanisms

FIPS column: **yes** = `FIPSApproved`, offered in FIPS mode; **no** = withheld
entirely when `crypto/fips140.Enabled()` selects FIPS mode (go-xkms #21:
`GODEBUG=fips140=on|only` at runtime, or a `GOFIPS140` build) —
`C_GetMechanismInfo` answers `CKR_MECHANISM_INVALID`, not merely "unlisted".

### RSA

RSA sizes are clamped to **2048-3072 bits in FIPS mode** (v3.2 §6.1.21). Outside
FIPS the ceiling is 4096: that is the largest modulus the stack's backends
enumerate and the integration suite generates. It is deliberately not 8192 or
16384 — advertising 16384 once let an authenticated caller exhaust the daemon's
memory at a size the module itself had said was valid.

| Mechanism | Operations | Min | Max | Unit | FIPS | Params |
|-----------|-----------|-----|-----|------|------|--------|
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | generate key pair | 2048 | 4096 | bits | yes | - |
| `CKM_RSA_PKCS` | sign, verify, sign-recover, verify-recover, encrypt, decrypt, wrap, unwrap | 2048 | 4096 | bits | yes | - |
| `CKM_RSA_PKCS_OAEP` | encrypt, decrypt, wrap, unwrap | 2048 | 4096 | bits | yes | required |
| `CKM_RSA_PKCS_PSS` | sign, verify | 2048 | 4096 | bits | yes | required |
| `CKM_SHA1_RSA_PKCS` | sign, verify | 2048 | 4096 | bits | **no** | - |
| `CKM_SHA256_RSA_PKCS` | sign, verify | 2048 | 4096 | bits | yes | - |
| `CKM_SHA384_RSA_PKCS` | sign, verify | 2048 | 4096 | bits | yes | - |
| `CKM_SHA512_RSA_PKCS` | sign, verify | 2048 | 4096 | bits | yes | - |
| `CKM_SHA256_RSA_PKCS_PSS` | sign, verify | 2048 | 4096 | bits | yes | required |
| `CKM_SHA384_RSA_PKCS_PSS` | sign, verify | 2048 | 4096 | bits | yes | required |
| `CKM_SHA512_RSA_PKCS_PSS` | sign, verify | 2048 | 4096 | bits | yes | required |

`CKM_RSA_PKCS` carries `CKF_SIGN_RECOVER`/`CKF_VERIFY_RECOVER` because v3.2
§6.1.6 defines the mechanism as supporting signature "with and without message
recovery", and the module implements the recover direction by stripping the v1.5
block. The flags were previously absent while the operation worked, so
`C_GetMechanismInfo` told a conformant application the token could not recover
and the token recovered anyway.

### Elliptic curve

| Mechanism | Operations | Min | Max | Unit | FIPS | Params |
|-----------|-----------|-----|-----|------|------|--------|
| `CKM_EC_KEY_PAIR_GEN` | generate key pair | 256 | 521 | bits | yes | - |
| `CKM_ECDSA` | sign, verify | 256 | 521 | bits | yes | - |
| `CKM_ECDSA_SHA1` | sign, verify | 256 | 521 | bits | **no** | - |
| `CKM_ECDSA_SHA224` | sign, verify | 256 | 521 | bits | yes | - |
| `CKM_ECDSA_SHA256` | sign, verify | 256 | 521 | bits | yes | - |
| `CKM_ECDSA_SHA384` | sign, verify | 256 | 521 | bits | yes | - |
| `CKM_ECDSA_SHA512` | sign, verify | 256 | 521 | bits | yes | - |
| `CKM_ECDH1_DERIVE` | derive | 256 | 521 | bits | yes | required |
| `CKM_ECDH1_COFACTOR_DERIVE` | derive | 256 | 521 | bits | yes | required |
| `CKM_EC_EDWARDS_KEY_PAIR_GEN` | generate key pair | 255 | 448 | bits | yes | - |
| `CKM_EDDSA` | sign, verify | 255 | 448 | bits | yes | - |

`CKM_ECDSA_SHA1` is withheld in FIPS mode for the same reason as
`CKM_SHA1_RSA_PKCS`: SP 800-131A Rev. 2 disallows SHA-1 for signature
*generation*. `CKM_SHA_1` as a bare digest stays available.

`CKM_ECDH1_COFACTOR_DERIVE` produces the same shared secret as
`CKM_ECDH1_DERIVE` here, because every curve this module supports is a
prime-order NIST curve with cofactor 1, so §6.3.18's cofactor multiplication is
the identity. Both take `CK_ECDH1_DERIVE_PARAMS`.

EdDSA is FIPS-approved (FIPS 186-5).

### AES

Key sizes are **bytes** — 16/24/32 for AES-128/192/256.

| Mechanism | Operations | Min | Max | Unit | FIPS | Params |
|-----------|-----------|-----|-----|------|------|--------|
| `CKM_AES_KEY_GEN` | generate | 16 | 32 | bytes | yes | - |
| `CKM_AES_ECB` | encrypt, decrypt | 16 | 32 | bytes | yes | - |
| `CKM_AES_CBC` | encrypt, decrypt, wrap, unwrap | 16 | 32 | bytes | yes | required |
| `CKM_AES_CBC_PAD` | encrypt, decrypt, wrap, unwrap | 16 | 32 | bytes | yes | required |
| `CKM_AES_GCM` | encrypt, decrypt, wrap, unwrap | 16 | 32 | bytes | yes | required |
| `CKM_AES_KEY_WRAP` | wrap, unwrap | 16 | 32 | bytes | yes | - |
| `CKM_AES_KEY_WRAP_KWP` | wrap, unwrap | 16 | 32 | bytes | yes | - |
| `CKM_AES_KEY_WRAP_PAD` | wrap, unwrap | 16 | 32 | bytes | yes | - |

`CKM_AES_KEY_WRAP_KWP` and `CKM_AES_KEY_WRAP_PAD` are deliberately identical
descriptors: both name the RFC 5649 AES-Key-Wrap-with-Padding construction, KWP
being the current v3.2 identifier and PAD the deprecated alias the spec retains.

Wrapping with `CKM_AES_CBC`, `CKM_AES_CBC_PAD` or `CKM_RSA_PKCS` is separately
gated by the *daemon's* `crypto.allow_legacy_key_wrap` policy (off by default).
The module advertises them; the service layer refuses them. See
[mechanisms.md](mechanisms.md#interaction-with-the-daemons-key-wrap-policy).

### Digests

Pure digests take no key, so no key-size range applies (§6.1 Table 10). All are
computed locally — `C_Digest` never leaves the process.

| Mechanism | Operations | FIPS |
|-----------|-----------|------|
| `CKM_SHA_1` | digest | yes |
| `CKM_SHA224` | digest | yes |
| `CKM_SHA256` | digest | yes |
| `CKM_SHA384` | digest | yes |
| `CKM_SHA512` | digest | yes |
| `CKM_SHA512_224` | digest | yes |
| `CKM_SHA512_256` | digest | yes |

There is no SHA-3 digest mechanism. See [Not advertised, and
why](#removed-outright).

### Key derivation

Min/max are 0/0: neither RFC 5869 nor SP 800-108r1 bounds the length of the input
keying material, so no range is stated.

| Mechanism | Operations | FIPS | Params |
|-----------|-----------|------|--------|
| `CKM_HKDF_DERIVE` | derive | **no** | required |
| `CKM_HKDF_DATA` | derive | **no** | required |
| `CKM_SP800_108_COUNTER_KDF` | derive | yes | required |
| `CKM_SP800_108_FEEDBACK_KDF` | derive | yes | required |
| `CKM_SP800_108_DOUBLE_PIPELINE_KDF` | derive | yes | required |

The HKDF pair is not marked FIPS-approved and is therefore **withheld in FIPS
mode**: SP 800-56C Rev. 2 approves extract-then-expand for a shared secret
produced by an approved key-establishment scheme, and `C_DeriveKey` here applies
it to an arbitrary base key, which is outside that scope. The SP 800-108 KDFs are
approved because `mechanismToHashFromPRF` admits only the HMAC-SHA2/SHA3 PRFs.

### Post-quantum

Only the four algorithm-level v3.2 mechanisms are advertised. Key sizes are the
**public key size in bytes**; the concrete parameter set comes from the key
object's `CKA_PARAMETER_SET`.

| Mechanism | Operations | Min | Max | Unit | FIPS |
|-----------|-----------|-----|-----|------|------|
| `CKM_ML_KEM_KEY_PAIR_GEN` | generate key pair | 800 | 1568 | bytes | yes |
| `CKM_ML_KEM` | encapsulate, decapsulate | 800 | 1568 | bytes | yes |
| `CKM_ML_DSA_KEY_PAIR_GEN` | generate key pair | 1312 | 2592 | bytes | yes |
| `CKM_ML_DSA` | sign, verify | 1312 | 2592 | bytes | yes |

`CKM_ML_KEM` carries `CKF_ENCAPSULATE`/`CKF_DECAPSULATE`, not `CKF_DERIVE`: v3.2
§5.20 gates `C_EncapsulateKey`/`C_DecapsulateKey` on those flags and gates
`C_DeriveKey` on `CKF_DERIVE`, and no KEM mechanism appears in `C_DeriveKey`'s
dispatch. `CKF_DERIVE` therefore made `CanDerive` answer true for an operation
that always returns `CKR_MECHANISM_INVALID`, while the flag that should have
gated the operation the mechanism *does* perform went unset.

The advertised ML-KEM minimum is 800 bytes, the ML-KEM-512 public key size. All
three FIPS 203 parameter sets are supported.

## Not advertised, and why

### Registered, unadvertised

Reachable only by naming the raw constant. Registered so the implementation is
not deleted; unadvertised so no application is told to rely on it. The list is
closed and machine-checked: `TestNoMechanismIsUndiscoverableButUsable` fails if a
registry entry is neither advertised nor recorded here with a reason.

| Mechanism | Reason |
|-----------|--------|
| `CKM_RSA_X_509` | Only verify-recover is performed; sign, verify, encrypt and decrypt are refused. See [deviations.md](deviations.md#no-raw-rsa-signing-or-decryption) |
| `CKM_SHA256_HMAC`, `CKM_SHA384_HMAC`, `CKM_SHA512_HMAC` | No backend performs a symmetric MAC; `C_Sign` fails with `CKR_FUNCTION_FAILED`. The constants stay valid as KDF PRF selectors in `CK_HKDF_PARAMS.prfHashMechanism` |
| `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` | No backend generates an X25519/X448 key pair; `C_GenerateKeyPair` returns `CKR_GENERAL_ERROR` |
| `CKM_GENERIC_SECRET_KEY_GEN` | Generates only at AES key sizes (16 and 32 bytes) while §6.9 requires arbitrary caller-chosen lengths, so no contiguous `ulMinKeySize`/`ulMaxKeySize` pair is truthful |

### Registered, unadvertised: post-quantum

42 further entries, all sharing one cause — the module has descriptors and
constants for them but no end-to-end operation.

| Family | Mechanisms | Where |
|--------|-----------|-------|
| HashML-DSA | `CKM_HASH_ML_DSA` + 10 SHA/SHA3/SHAKE variants | `mechanism_v32.go` |
| SLH-DSA (FIPS 205) | `CKM_SLH_DSA_KEY_PAIR_GEN`, `CKM_SLH_DSA`, `CKM_HASH_SLH_DSA` + 10 variants | `mechanism_v32.go` |
| HSS/LMS (RFC 8554) | `CKM_HSS_KEY_PAIR_GEN`, `CKM_HSS` | `mechanism_v32.go` |
| XMSS / XMSS^MT (RFC 8391) | `CKM_XMSS_KEY_PAIR_GEN`, `CKM_XMSSMT_KEY_PAIR_GEN`, `CKM_XMSS`, `CKM_XMSSMT` | `mechanism_v32.go` |
| Vendor ML-DSA | `CKM_VENDOR_ML_DSA_{44,65,87}` and their `_KEY_PAIR_GEN` | `mechanism_quantum.go` |
| Vendor ML-KEM | `CKM_VENDOR_ML_KEM_{768,1024}_{KEY_GEN,ENCAPSULATE,DECAPSULATE}` | `mechanism_quantum.go` |

The vendor mechanisms predate the v3.2 standard identifiers and are retained for
backward compatibility; new callers should use `CKM_ML_KEM` / `CKM_ML_DSA` with
`CKA_PARAMETER_SET`. `GetStandardMechanism()` and `GetStandardKeyType()` map the
old identifiers to the new.

### Removed outright

These have no registry entry at all, so `C_*Init` refuses them with
`CKR_MECHANISM_INVALID` immediately rather than accepting the mechanism and
failing deep inside the operation. Each returns the moment its operation works
end to end.

| Mechanism | Why |
|-----------|-----|
| `CKM_SHA3_224`, `CKM_SHA3_256`, `CKM_SHA3_384`, `CKM_SHA3_512` | Carried `CKF_DIGEST`; the digest layer has no SHA-3 case |
| `CKM_AES_CTR` | Ignored `CK_AES_CTR_PARAMS.cb`, so the same plaintext, key and counter block produced different ciphertexts |
| `CKM_AES_CCM` | Returned a ciphertext the length of the plaintext, so it carried no authentication tag — output without a MAC is not CCM |
| `CKM_AES_CMAC`, `CKM_XEDDSA` | `C_Sign` fails with `CKR_FUNCTION_FAILED`; no signing path exists |
| `CKM_ECMQV_DERIVE`, `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE`, `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH`, `CKM_PUB_KEY_FROM_PRIV_KEY` | Not among the mechanisms `C_DeriveKey` dispatches on |
| `CKM_ECDH_AES_KEY_WRAP`, `CKM_ECDH_X_AES_KEY_WRAP`, `CKM_ECDH_COF_AES_KEY_WRAP` | Carried `CKF_WRAP`/`CKF_UNWRAP`; nothing routes them to a wrapping algorithm |
| `CKM_HKDF_KEY_GEN` | No mechanism-to-key-type mapping, so `C_GenerateKey` cannot build a request |
| `CKM_ML_KEM_512` vendor mechanisms | Go's `crypto/mlkem` implements only the 768 and 1024 parameter sets |
| DSA, Diffie-Hellman, DES/3DES, RC2, RC4, IDEA families | Deprecated; use ECDSA/EdDSA, ECDH, and AES |

Their `mechanismNames` entries are kept deliberately: a name is a diagnostic, not
a capability. `CKM_ECDH_X_AES_KEY_WRAP: CKR_MECHANISM_INVALID` is a better
refusal than `CKM_UNKNOWN(0x00004038): CKR_MECHANISM_INVALID`.

## FIPS mode

FIPS mode is selected process-wide by `crypto/fips140.Enabled()`, the same
signal the rest of the stack uses (go-xkms #21), so the module and its
backends cannot end up in different modes. `GOFIPS140` set as a plain runtime
environment variable has no effect — it is a `go build` selector only.

```bash
GODEBUG=fips140=on xkmsd --config /etc/xkms/xkmsd.yaml
```

A non-approved mechanism is then hidden entirely: absent from
`C_GetMechanismList`, reported unknown by `C_GetMechanismInfo`, and refused with
`CKR_MECHANISM_INVALID` by any operation naming it. Four advertised mechanisms
are affected:

| Mechanism | Reason |
|-----------|--------|
| `CKM_SHA1_RSA_PKCS` | SHA-1 signature generation, disallowed by SP 800-131A Rev. 2 |
| `CKM_ECDSA_SHA1` | same |
| `CKM_HKDF_DERIVE` | derivation from an arbitrary base key is outside SP 800-56C Rev. 2 |
| `CKM_HKDF_DATA` | same |

RSA additionally narrows from 4096 to 3072 bits. The narrowing is applied in
`effectiveKeySizeRange`, which feeds `C_GetMechanismList`, `C_GetMechanismInfo`
and the module's own request validation from one place, so all three report the
same ceiling.

## See also

- [Deliberate deviations and limits](deviations.md)
- [Mechanism reference](mechanisms.md) — per-mechanism detail, parameters, examples
- [v3.2 compliance](v32-compliance.md) — function-by-function status
