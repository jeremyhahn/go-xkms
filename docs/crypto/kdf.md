# Key Derivation Functions

`pkg/crypto/kdf` is the only KDF implementation in go-xkms. The backends, the
service layer, and the PKCS#11 module all reach it — nothing derives keys on
its own.

## Layering

```
pkg/backend/{tpm2,software,pkcs11,phone}.applyKDF
        |
        v
types.KDFParams.Derive          <- one bridge, enforces parameter applicability
        |
        v
pkg/crypto/kdf adapters         <- the algorithms
```

`applyKDF` in every backend is a two-line delegation. A backend cannot derive
a key any other way, which is what makes the four backends produce identical
bytes for identical inputs.

## Algorithms

| `types.KDFAlgorithm` | Standard | Inputs consumed |
| --- | --- | --- |
| `HKDF` | RFC 5869 | `Salt`, `Info` |
| `X963` | ANSI X9.63 | `Info` (SharedInfo) |
| `SP800-56A` | NIST SP 800-56A one-step concat | `Info` (OtherInfo) |
| `SP800-108-COUNTER` | NIST SP 800-108r1 §4.1 | `Label`, `Context`, `CounterLength`, `CounterLocation` |
| `SP800-108-FEEDBACK` | NIST SP 800-108r1 §4.2 | `Label`, `Context`, `CounterLength`, `CounterLocation`, `IV` |

`pkg/crypto/kdf` additionally implements SP 800-108r1 §4.3 Double-Pipeline
Iteration Mode, PBKDF2, and Argon2. Those are reachable through the `DeriveKey`
service verb and the password hasher; they are not offered on the ECDH path.

## Approved hashes

The approved hash set is **per algorithm**, because it is a property of the
construction and of the interoperability contract it carries — not of the
package.

| Construction | Approved hashes |
| --- | --- |
| `HKDF`, `SP800-108-COUNTER`, `SP800-108-FEEDBACK` | SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512 |
| `X963`, `SP800-56A` | the above **plus** SHA-1, SHA-224, SHA3-224 |

Anything outside the set for the selected algorithm returns
`types.ErrUnsupportedKDFHash`, from `Validate` as well as from `Derive`. MD4,
MD5, RIPEMD-160, MD5+SHA1 and the truncated SHA-512 digests are not reachable
by name from any construction.

### Why the concatenation KDFs accept SHA-1 and the 224-bit digests

The two single-step concatenation KDFs are the ones PKCS#11 exposes, one
`CK_EC_KDF_TYPE` per hash, and the xkms PKCS#11 module advertises the whole
range. Advertising `CKD_SHA1_KDF`, `CKD_SHA224_KDF` or `CKD_SHA3_224_KDF` and
then failing at derivation time is not an option, and refusing them is not
required:

* ANSI X9.63 defines its concatenation KDF over SHA-1.
* NIST SP 800-56A Rev. 3 §5.1 approves SHA-1, SHA-224 and the SHA-3 family as
  hash functions for its key-derivation functions.
* NIST SP 800-131A Rev. 2 disallows SHA-1 for **digital signature generation**
  and keeps it acceptable for non-signature applications, which is exactly this
  use.

A concatenation KDF depends on the preimage resistance and pseudorandomness of
the digest, not on its collision resistance, so the SHA-1 collision attacks
that bar it from signing do not apply here.

This is not the weak-hash policy in disguise: it is fixed, and it does not move
with `crypto.allow_weak_hashes`. SHA-1 derives under X9.63 in a fully compliant
deployment, and SHA-1 remains refused for signing in that same deployment. See
`docs/crypto/weak-hashes.md`.

HKDF and the SP 800-108 modes carry no equivalent external contract in this
codebase, so they hold a 256-bit digest floor.

## SP 800-108 construction

The PRF is HMAC keyed with the key derivation key. The fixed input data is the
encoding SP 800-108r1 recommends:

```
Label || 0x00 || Context || [L]_2
```

`[L]_2` is the requested output length in bits, encoded big-endian in 32 bits.
The iteration counter `[i]_r` is placed by `CounterLocation`:

```
before   [i]_r || Label || 0x00 || Context || [L]_2
middle   Label || 0x00 || [i]_r || Context || [L]_2
after    Label || 0x00 || Context || [L]_2 || [i]_r
```

Counter mode:

```
K(i) = PRF(KDK, fixedInput(i))
```

Feedback mode chains the previous block, with `K(0) = IV`:

```
K(i) = PRF(KDK, K(i-1) || fixedInput(i))
```

`CounterLength` must be 8, 16, 24, or 32 bits; zero selects 32. The number of
iterations may not exceed `2^r - 1`, so a request that would wrap the counter
returns `kdf.ErrOutputTooLong` rather than silently repeating a PRF input.

`kdf.KDFParams.FixedInput` accepts an already-assembled fixed input blob for
protocols that specify their own encoding. It is mutually exclusive with
`Label` and `Context`, and requires a counter location of `before` or `after`.

## Parameter applicability is enforced

Each algorithm consumes a specific subset of `types.KDFParams`. Supplying a
field outside that subset returns `types.ErrKDFParamNotApplicable` instead of
being ignored:

```go
// Rejected: SP 800-108 has no salt and no HKDF info.
params := &types.KDFParams{
    Algorithm: types.KDFAlgorithmSP800108Counter,
    Hash:      "SHA-256",
    KeyLength: 32,
    Salt:      []byte("salt"),
}
_, err := params.Derive(sharedSecret) // types.ErrKDFParamNotApplicable
```

A derivation that quietly drops a caller-supplied input produces a key the
caller did not ask for, which is indistinguishable from a wrong key.

## Wire parameter mapping

`DeriveKeyECDHRequest` carries `KDFSalt` and `KDFInfo`, which are HKDF's
vocabulary. `pkg/xkms.buildECDHKDFParams` maps them explicitly:

| Algorithm | `KDFSalt` | `KDFInfo` |
| --- | --- | --- |
| HKDF, X9.63, SP 800-56A | `Salt` | `Info` |
| SP 800-108 counter | rejected | `Context` |
| SP 800-108 feedback | `IV` (K(0)) | `Context` |

The wire has no field for the SP 800-108 `Label`, so ECDH derivations over the
API use an empty label. An empty label is valid SP 800-108; a dedicated wire
field is a follow-up.

## Test vectors

`pkg/crypto/kdf/sp800108_cavp_vectors_test.go` carries 144 official NIST CAVP
KDF108 vectors, covering HMAC-SHA256/384/512, counter widths of 8/16/24/32
bits, and both supported counter placements, for all three SP 800-108 modes:

- `KBKDF800-108/CounterMode.zip` → `KDFCTR_gen.rsp`
- `KBKDF800-108/FeedbackModeNOzeroiv.zip` → `KDFFeedback_gen.rsp`
- `KBKDF800-108/PipelineModewithCounter.zip` → `KDFDblPipeline_gen.rsp`

`pkg/crypto/kdf/concat_test.go` carries the official CAVP ANS X9.63 vectors
(`components/800-135testvectors/ansx963_2001.zip`). The SP 800-56A one-step
KDF has no standalone CAVP response file; it is validated against the
construction in SP 800-56A Rev. 3 §5.8.2.1, computed independently in the
test.

## Breaking change: SP 800-108 no longer derives with HKDF

Affected labels: `SP800-108-COUNTER` and `SP800-108-FEEDBACK`, on the ECDH key
agreement path only.

Before this change the backends accepted both labels and derived the key with
HKDF-Expand, dropping the caller's Label and Context. Keys derived under those
labels were not SP 800-108 keys, and any FIPS claim resting on the label was
false. They now run the real construction.

What changes:

- Keys previously derived under these two labels do not reproduce.
- `Salt` and `Info` are no longer accepted for these labels; supply `Label`
  and `Context`.
- HKDF, X9.63, and SP 800-56A derivations are bit-for-bit unchanged.
- SP 800-108 derivations through the `DeriveKey` service verb (and its gRPC
  equivalent) are unchanged; that path always used the correct implementation.

There is no compatibility shim and no legacy-mode flag. A caller that needs
the old bytes was never getting SP 800-108 and should request HKDF explicitly.

Operator action: re-derive any symmetric key obtained from `DeriveKeyECDH`
with `KDFAlgorithm` `SP800-108-COUNTER` or `SP800-108-FEEDBACK`, and re-wrap
anything encrypted under such a key, before upgrading. xkms never persists
these derived keys — `DeriveKeyECDH` returns the key to the caller and keeps
no copy — so there is no xkms-side data migration. Material an application
stored itself is outside xkms and must be handled there.

## References

- [NIST SP 800-108 Rev. 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf)
- [NIST SP 800-56A Rev. 3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf)
- [RFC 5869 — HKDF](https://tools.ietf.org/html/rfc5869)
- [CAVP KBKDF test vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/key-derivation)
