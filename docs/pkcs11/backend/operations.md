# Operations

All operations require a live session pool. Without `Login()` (or
`Initialize()`) they return `ErrNotInitialized`.

## Mechanism map

| Operation | Mechanism | Source |
|---|---|---|
| RSA key pair generation | `CKM_RSA_PKCS_KEY_PAIR_GEN` | `signer_rsa.go:357` |
| RSA PKCS#1 v1.5 sign | `CKM_RSA_PKCS` (DigestInfo prefix built in software) | `signer_rsa.go:112` |
| RSA-PSS sign | `CKM_RSA_PKCS_PSS` | `signer_rsa.go:158` |
| RSA PKCS#1 v1.5 decrypt | `CKM_RSA_PKCS` | `signer_rsa.go:193` |
| RSA-OAEP decrypt | `CKM_RSA_PKCS_OAEP` | `signer_rsa.go:243` |
| EC key pair generation | `CKM_EC_KEY_PAIR_GEN` | `signer_ecdsa.go:247` |
| ECDSA sign | `CKM_ECDSA` (raw R‖S, re-encoded to ASN.1 DER) | `signer_ecdsa.go:91` |
| Ed25519 key pair generation | `CKM_EC_EDWARDS_KEY_PAIR_GEN` (0x1055), `CKA_EC_PARAMS` = OID 1.3.101.112 | `pkcs11.go:1027` |
| Ed25519 sign | `CKM_EDDSA` (0x1057) over the full message | `pkcs11.go:1547` |
| ML-DSA / ML-KEM generation | `CKM_ML_DSA_KEY_PAIR_GEN` / `CKM_ML_KEM_KEY_PAIR_GEN` | `pkcs11.go:805` |
| AES key generation | `CKM_AES_KEY_GEN` | `pkcs11.go:1091` |
| AES-GCM encrypt/decrypt | `CKM_AES_GCM` | `pkcs11_symmetric.go:291,425` |
| ECDH key agreement | `CKM_ECDH1_DERIVE` with `CKD_NULL` | `pkcs11_ecdh.go:362` |
| Key unwrap (hybrid stage 2) | `CKM_AES_KEY_WRAP_PAD` | `pkcs11_importexport.go:483` |
| Random | `C_GenerateRandom` | `pkcs11.go:500` |

Hash mechanisms used for PSS/OAEP parameters: SHA-1, SHA-224, SHA-256, SHA-384,
SHA-512 with the matching `CKG_MGF1_*` (`signer_rsa.go:40`).

## Key generation

`GenerateKey(ctx, attrs)` dispatches on `attrs.QuantumAttributes` first, then on
`attrs.KeyAlgorithm`.

- **RSA** — `GenerateRSA` reads `attrs.RSAAttributes.KeySize`, defaulting to
  2048; `GenerateRSAWithSize` also coerces anything `< 512` to 2048.
- **ECDSA** — `GenerateECDSA` reads `attrs.ECCAttributes.Curve`, defaulting to
  P-256. The curve OID must be in `curveToOID` or generation fails with
  `ErrUnsupportedKeyAlgorithm`.
- **Ed25519** — requires PKCS#11 v3.0 Edwards support (SoftHSM ≥ 2.6). Rejected
  on YubiKey PIV.
- **Post-quantum** — ML-DSA and ML-KEM are refused unless
  `probeQuantumMechanisms` saw the key-pair-gen mechanism in the token's
  `C_GetMechanismList`. `Capabilities().QuantumSigning` /
  `.KeyEncapsulation` reflect the same probe.
- **AES** — `GenerateSecretKey(attrs, keySize)` accepts 128, 192 and 256 bits
  only.

Generated key pairs are `CKA_TOKEN=true`, `CKA_PRIVATE=true`,
`CKA_SENSITIVE=true`. See [security.md](security.md) for what is *not* set.

## Signing and decryption

`Signer(ctx, attrs)` returns a `crypto.Signer` bound to the token; the RSA
signer additionally implements `crypto.Decrypter`, which is what
`Decrypter(ctx, attrs)` type-asserts for. `Sign(attrs, digest, opts)` is a
convenience wrapper over `Signer`. `GetSignerByID`/`GetDecrypterByID` build
attributes from a bare CN with `KEY_TYPE_SIGNING` / `KEY_TYPE_ENCRYPTION`.

`opts` selects the RSA scheme: `*rsa.PSSOptions` → PSS, anything else → PKCS#1
v1.5. The v1.5 path builds the DigestInfo DER prefix in software and submits the
result under `CKM_RSA_PKCS`.

`Verify(attrs, digest, signature)` verifies **in software** using the public key
read back from the token. Only ECDSA is implemented; RSA returns
`backend.ErrInvalidAlgorithm` with "RSA verification requires hash algorithm
specification".

## Symmetric (AES-GCM)

`GenerateSymmetricKey` / `GetSymmetricKey` / `SymmetricEncrypter` accept only
`SymmetricAES128GCM`, `SymmetricAES192GCM`, `SymmetricAES256GCM`
(`requireAESGCMAlgorithm`). Any other `types.CipherMode` — CBC included — is
rejected by `requireAEADMode` rather than silently downgraded.

The nonce is fixed at 12 bytes (`gcmNonceSize`). The authentication tag length
comes from `types.EncryptOptions.TagSize` / `types.DecryptOptions.TagSize`,
defaults to 16 bytes when unset, and is passed to `CK_GCM_PARAMS.ulTagBits` in
**bits** — the token itself performs the truncation NIST SP 800-38D section
5.2.1.2 defines. `resolveGCMTagSize` accepts only the lengths that standard
approves (12, 13, 14, 15 and 16 bytes) and rejects everything else:

```go
	ErrInvalidNonceLength = errors.New("pkcs11: invalid AEAD nonce length")
	ErrInvalidTagSize     = errors.New("pkcs11: unsupported AEAD authentication tag size")
	ErrInvalidTagLength   = errors.New("pkcs11: invalid AEAD authentication tag length")
```

A caller-supplied nonce of the wrong length would panic `crypto/cipher`'s GCM,
so it is rejected before it can reach the token or consume the key's byte
budget.

On decrypt the tag length comes from `DecryptOptions.TagSize`, never from
`EncryptedData.Tag` — SP 800-38D section 5.2.2 verifies a t-bit tag by
recomputing the tag at t bits, so inferring t from the bundle would let a
caller choose how many bits get checked. A tag whose length does not match the
requested one is rejected with `ErrInvalidTagLength`, and an unapproved
requested length with `ErrInvalidTagSize`; neither is rounded to a nearby
value, because a substituted length produces output no conforming peer can
authenticate.

Each encryption consults `types.AEADSafetyTracker`: byte budget first
(`IncrementBytes`), then nonce uniqueness (`CheckNonce`) before the operation
runs. `GetTracker()` exposes it.

`pkcs11.NewGCMParams` allocates the IV and AAD in C memory that is not freed
automatically; every call site owns the `defer gcmParams.Free()`.

Encrypt/decrypt open their own session and log in, and deliberately never log
out — `C_Logout` affects every session on the token, not just the caller's.

## Sealing

`Seal` / `Unseal` (`sealer.go`) are a thin, HSM-resident wrapper over the
symmetric path: `opts.KeyAttributes` must name an existing symmetric key, the
payload is encrypted with AES-GCM on the token, and the result is a
`types.SealedData` carrying ciphertext, nonce, tag, `KeyID`, and
`Metadata["pkcs11:algorithm"]`. `Unseal` refuses sealed data whose `Backend` is
not `types.BackendTypePKCS11` and whose `KeyID` does not match the supplied
attributes. `CanSeal()` reports whether both the pool and the context are live.
`MarshalSealedData`/`UnmarshalSealedData` are JSON helpers.

## ECDH key agreement

`DeriveKeyECDH(ctx, privateKeyAttrs, peerPublicKey, kdfParams)`:

1. Locate the private key handle on the token.
2. Parse the peer key from DER SubjectPublicKeyInfo **or** a raw uncompressed
   point (`0x04 ‖ X ‖ Y`; 65/97/133 bytes identify P-256/P-384/P-521).
3. Reject a cross-curve peer with `ErrCurveMismatch` — PKCS#11 leaves
   cross-curve `C_DeriveKey` to the token.
4. `C_DeriveKey` with `CKM_ECDH1_DERIVE` and `CKD_NULL` produces the raw shared
   secret as a session object.
5. The KDF from `kdfParams` is applied **in software**; the derived session
   object is destroyed.

`SupportedCurves()` returns `P-256`, `P-384`, `P-521` when the token advertises
both an ECDH derive mechanism and `CKM_EC_KEY_PAIR_GEN`, an empty slice when it
does not, and the same three as a static answer when no context is open yet.

> Caveat: the key templates in `generateECDSAKeyPair` do not set `CKA_DERIVE`,
> whose §4.9 default is `CK_FALSE`. A conforming token will refuse
> `C_DeriveKey` on a key created by `GenerateECDSA` with
> `CKR_KEY_FUNCTION_NOT_PERMITTED`. The ECDH tests provision their own keys with
> `CKA_DERIVE=true` for this reason (`ecdh_test.go:671`).

## Import and export

The ceremony matches the other import/export backends
(`backend.ImportExportBackend`):

```
GetImportParameters -> WrapKey (software, on the host) -> ImportKey (C_UnwrapKey, in the HSM)
ExportKey (C_WrapKey, in the HSM)
```

- `GetImportParameters` finds or creates a **persistent** RSA-4096 wrapping key
  pair labelled `go-xkms-wrapping-key` and returns its public half. There is no
  expiry: `ExpiresAt` is nil because the key lives in the token. `ImportToken`
  is the wrapping key label.
- Accepted algorithms: `RSAES_OAEP_SHA_1`, `RSAES_OAEP_SHA_256`,
  `RSA_AES_KEY_WRAP_SHA_1`, `RSA_AES_KEY_WRAP_SHA_256`.
- `WrapKey` runs on the host via `pkg/crypto/wrapping` — direct OAEP for small
  keys, hybrid RSA+AES for large ones.
- `ImportKey` unwraps inside the token. Direct OAEP uses `C_UnwrapKey` with
  `CKM_RSA_PKCS_OAEP`. The hybrid path (`importKeyHybrid`) works around
  SoftHSM2's refusal of OAEP-unwrap for secret keys: it `C_Decrypt`s the
  ephemeral AES KEK, re-imports it as a session object, unwraps the target with
  `CKM_AES_KEY_WRAP_PAD`, and destroys the KEK. The 4-byte length prefix is
  parsed in `uint64` so an attacker-controlled length cannot wrap around and
  defeat the bounds check.
- `UnwrapKey` deliberately returns `backend.ErrNotSupported`: unwrapping happens
  in the HSM during `ImportKey`, and exposing a host-side unwrap would defeat
  the point.
- `ExportKey` requires `attrs.Exportable` (policy) **and** `CKA_EXTRACTABLE`
  read back off the object (device truth), then wraps with `C_WrapKey` under
  OAEP SHA-1 or SHA-256.
- `ExportKeyMaterial` returns raw plaintext bytes and is restricted to
  `CKO_SECRET_KEY`; RSA/ECDSA/Ed25519/DSA return
  `backend.ErrAsymmetricKeyExportNotAllowed`. Because `GenerateSecretKey`
  hard-codes `CKA_EXTRACTABLE=false`, keys this backend generated can never be
  exported this way.

## Enumeration and deletion

`ListKeys(ctx)` enumerates `CKO_PRIVATE_KEY` objects with `CKA_TOKEN=true`,
reads `CKA_ID`/`CKA_LABEL`/`CKA_KEY_TYPE`, maps a single-byte `CKA_ID` to a PIV
slot, maps `CKK_RSA`/`CKK_EC`/`CKK_EC_EDWARDS` to the x509 algorithm, and
recovers the CN with `keyIDToCN`. It retrieves at most 256 handles in one
`C_FindObjects` call, so a token with more private keys is truncated. Secret
keys are not listed.

`DeleteKey(ctx, attrs)` destroys every object class sharing the `CKA_ID` and
then verifies removal. `Delete(attrs)` is the context-free alias.

## Random

`GenerateRandom(length)` calls `C_GenerateRandom` on a pooled session — hardware
entropy from the device. Length must be positive; some devices cap the bytes
per call (~1024), so large requests should be chunked by the caller.

## Not supported (by design)

| Call | Result |
|---|---|
| `Get(attrs, ext)` | `backend.ErrNotSupported` — "PKCS#11 private keys cannot be exported" |
| `Save(attrs, data, ext, overwrite)` | `backend.ErrNotSupported` — use the `Generate*` methods |
| `RotateKey(ctx, attrs)` | `backend.ErrOperationNotSupported`; `Capabilities().KeyRotation` is false |
| `UnwrapKey(...)` | `backend.ErrNotSupported` — the HSM unwraps during `ImportKey` |

## Attestation

`AttestKey(ctx, attrs, nonce)` (`attestation.go`) is the intended entry point
for device-backed key attestation: check that the device supports it, find the
key, read its public half, fetch the device identity certificate and chain, sign
an `attestationData` record binding key, HSM model, timestamp and caller nonce,
and return an `attestation.AttestationStatement` with `Format: "pkcs11"` and
`PCRValues` empty (HSMs have no PCRs). Vendor mechanisms differ — certificate
based (Thales, Gemalto), challenge-response (YubiKey), device identity
(SmartCard-HSM); SoftHSM has none.

**Status:** the supporting helpers in `attestation.go` are placeholders that
return "not implemented" (`findKeyObject`, `getPublicKeyFromObject`,
`getDeviceIdentityCertificate`) or fabricated constants (`signAttestationData`,
`encodeAttestationData`), so `AttestKey` cannot currently succeed. This file was
being rewritten while these docs were produced — check the current source before
relying on any of it.
