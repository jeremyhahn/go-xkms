# Deliberate Deviations and Limits

Things a conformant PKCS#11 application might reasonably expect from this token
and will not get, each with the reason. Nothing here is a "we'll wire it up
later" stub: where an operation cannot be completed the mechanism is either
absent from the registry or absent from `C_GetMechanismList`, so the refusal
arrives at `C_*Init` rather than deep inside the operation.

For what *is* offered, see the [support matrix](support-matrix.md).

## Algorithms

### No raw RSA signing or decryption

`CKM_RSA_X_509` carries `CKF_VERIFY_RECOVER` and nothing else. `C_SignInit`,
`C_VerifyInit`, `C_EncryptInit` and `C_DecryptInit` naming it are refused with
`CKR_MECHANISM_INVALID`.

PKCS#11 v3.2 §6.1.7 requires the input be interpreted as an integer and raised to
the private exponent with **no padding of any kind**. This token reaches its keys
through `crypto.Signer` and `crypto.Decrypter`, interfaces with no raw-primitive
form; a key held in a TPM, an HSM or a cloud KMS could not expose one even in
principle.

Verify-recover is genuinely performed and is not a stub: it is `s^e mod n`
computed locally from a public key, returned unprocessed, which is exactly what
§6.1.7 defines.

What the module did before was leave the padding field empty, which the wire
defines as PKCS#1 v1.5, so `C_Sign` returned a v1.5 signature under `CKR_OK`.
Recovering `s^e mod n` from it yields `00 01 FF..FF 00 || M` rather than `M`, and
no conformant verifier accepts it. A caller that asked for raw RSA and received
v1.5 has no way to detect the substitution.

The mechanism is also unadvertised, so `C_GetMechanismList` does not offer it.

### No SHA-3 digests

`CKM_SHA3_224`, `CKM_SHA3_256`, `CKM_SHA3_384` and `CKM_SHA3_512` have no
registry entry; `C_DigestInit` refuses them with `CKR_MECHANISM_INVALID`. Three
of them used to be registered with `CKF_DIGEST`, which made `C_DigestInit` accept
the mechanism and then fail, because the digest layer has no SHA-3 case.

Restoring them is a two-part change that must land together: the SHA-3 cases in
`newDigestOperation`, and the registry entries.
`TestEveryDigestMechanismIsBothRegisteredAndImplemented` fails if either half
lands alone.

### No symmetric MAC

`CKM_SHA256_HMAC`, `CKM_SHA384_HMAC` and `CKM_SHA512_HMAC` are registered but not
advertised: the module builds a correct HMAC signing request, but no backend in
this deployment performs a symmetric MAC, so `C_Sign` fails with
`CKR_FUNCTION_FAILED`. `CKM_AES_CMAC` has no entry at all.

The three HMAC constants remain valid as PRF selectors in
`CK_HKDF_PARAMS.prfHashMechanism` and the SP 800-108 parameters, which is a
different lookup that never consults the mechanism registry.

### RSA below 2048 bits, and above 4096

The floor is 2048 bits. NIST SP 800-131A has disallowed RSA below 2048 since
2014, and this module targets FedRAMP, PCI and HIPAA deployments, so it is
stricter than v3.2 §6.1.21, which still lists 1024 as permissible in FIPS mode.
Being stricter is allowed; being laxer is not.

The ceiling is 4096, narrowing to 3072 in FIPS mode. 4096 is the largest modulus
the stack's backends enumerate and the integration suite generates — a size
proven to work end to end. The mechanism previously advertised 16384, and
generating a key at that advertised maximum exhausted memory and killed the
daemon serving the token: an authenticated caller could take the service down
using a size the module itself had said was valid.

## Mechanism parameters

### OAEP: `mgf` must be MGF1 over `hashAlg`

`CK_RSA_PKCS_OAEP_PARAMS.mgf` is accepted only when it is unset (`0`) or the MGF1
variant matching `hashAlg`. Any independent pairing — `hashAlg = CKM_SHA256`
with `mgf = CKG_MGF1_SHA1`, for instance — is refused with
`CKR_MECHANISM_PARAM_INVALID`.

The specification permits the two to differ. Go's `rsa.EncryptOAEP` derives the
mask from the digest alone and takes no separate MGF argument, so honouring a
mismatched `mgf` would silently produce ciphertext under a different MGF than the
one requested. Refusing is the only honest answer available.

`pSourceData` (the OAEP label) round-trips: it is parsed at the cgo boundary,
carried through to the crypto layer and applied to both encrypt and decrypt.
`ulSourceDataLen > 0` requires `source = CKZ_DATA_SPECIFIED`; a mismatched pair is
refused with `CKR_MECHANISM_PARAM_INVALID`.

### PSS: `sLen = 0` is not honoured, and `mgf` is not validated

Two known gaps in `CK_RSA_PKCS_PSS_PARAMS` handling:

- **`sLen = 0`** is intended to mean a literal zero-byte salt (RFC 8017 §9.1
  permits it and several profiles require it). The module carries that intent
  correctly across the wire as the `PSSSaltLengthZero` sentinel, but the service
  layer maps the sentinel back to a literal `0` in `rsa.PSSOptions.SaltLength` —
  and in Go `0` *is* `rsa.PSSSaltLengthAuto`. The effect is the behaviour the
  sentinel exists to prevent: the largest salt the modulus allows when signing,
  and "accept any salt length" when verifying. **Do not rely on `sLen = 0` to
  constrain a verification.**
- **`mgf`** is decoded at the cgo boundary and then dropped. There is no check
  that it agrees with `hashAlg`, unlike OAEP above, and `rsa.PSSOptions` has no
  field to carry it. A mismatched `mgf` is neither honoured nor refused.

There is also no bound check on `sLen`; an oversized salt fails inside
`rsa.SignPSS`/`rsa.VerifyPSS` rather than at `C_SignInit`.

`hashAlg` *is* validated: for a hash-specific mechanism such as
`CKM_SHA256_RSA_PKCS_PSS` it must match the hash the mechanism name implies, and
it must name a digest the module recognises. Either failure is
`CKR_MECHANISM_PARAM_INVALID`, and the parameters are mandatory.

## C interface

### Not fork-safe

`C_GetInterface` refuses **any** non-zero `flags`, including
`CKF_INTERFACE_FORK_SAFE`, with `CKR_ARGUMENTS_BAD`. Neither the Go runtime nor
the daemon connection behind these functions survives `fork(2)`, so no interface
this module publishes can claim fork safety.

An application that forks must call `C_Initialize` again in the child. There is
no `CKF_OS_LOCKING_OK`-style accommodation that makes a forked child usable.

### `C_WaitForSlotEvent` cannot block

Called without `CKF_DONT_BLOCK`, it returns `CKR_FUNCTION_NOT_SUPPORTED`. Called
with it, it returns `CKR_NO_EVENT`.

The token is virtual and generates no insertion or removal events, so a blocking
wait could never be satisfied. Returning `CKR_NO_EVENT` to a blocking call was
worse than refusing: it turned a monitoring thread's blocking wait into a spin at
full CPU.

`CKF_DONT_BLOCK` was missing from `cmd/pkcs11-module/include/pkcs11t.h` and has
been added, so a caller can now name it.

### No async operations

`C_AsyncComplete`, `C_AsyncGetID` and `C_AsyncJoin` validate their arguments and
return `CKR_FUNCTION_NOT_SUPPORTED`. Async operation requires backend support
that does not exist yet.

### No message-based signature-first verification

`C_MessageVerifySignatureInit`, `C_VerifyMessageSignature`,
`C_VerifyMessageSignatureBegin`, `C_VerifyMessageSignatureNext` and
`C_MessageVerifySignatureFinal` are not implemented. The single-part and
multi-part signature-first functions (`C_VerifySignatureInit`,
`C_VerifySignature`, `C_VerifySignatureUpdate`, `C_VerifySignatureFinal`) are.

### `C_EncapsulateKey` / `C_DecapsulateKey` are v3.2-only

They appear in `CK_FUNCTION_LIST_3_2` and not in `CK_FUNCTION_LIST_3_0` or the
v2.x list. An application reaching the module through `C_GetFunctionList` (which
yields the v2.40 table) or through the v3.0 interface cannot call them; use
`C_GetInterface` with version 3.2, or no version at all, which yields the latest.

### Length queries on `*Update`

`C_EncryptUpdate` and `C_DecryptUpdate` called with a NULL output pointer answer
the output length **without consuming the input**. Passing the real input on a
length-query call would append it a second time when the caller retried with a
real buffer, encrypting or digesting it twice.

`C_DigestUpdate`, `C_SignUpdate` and `C_VerifyUpdate` have no output parameter at
all, so the two-call convention does not apply to them; it applies to their
`*Final` counterparts.

## Stricter than the specification requires

Not deviations — these are rules v3.2 states and many tokens do not enforce.
Applications that worked against a laxer token will see refusals here. None of
them has a configuration flag to relax it.

### `CKA_TRUSTED` is Security-Officer-only

Setting `CKA_TRUSTED` to `CK_TRUE` requires an SO session (v3.2 Table 13 footnote
10: "Can only be set to CK_TRUE by the SO user"). Any other attempt, and any
attempt to retract an already-true value, is `CKR_ATTRIBUTE_READ_ONLY`.

Enforced on every creation path — `C_CreateObject`, `C_GenerateKey`,
`C_GenerateKeyPair`, `C_DeriveKey`, `C_UnwrapKey` and the KEM operations — and on
`C_CopyObject` and `C_SetAttributeValue`.

A trusted object defaults to `CKA_PRIVATE = CK_FALSE`, a token-specific default
Table 17 explicitly permits. Without it the two rules deadlock: the SO cannot
reach private objects (§4.2), so the only role permitted to create a trusted key
would be the one role forbidden to create it. An explicit `CKA_PRIVATE` in the
caller's template always wins.

### One-way boolean attributes

| Attribute | Permitted transition |
|-----------|---------------------|
| `CKA_SENSITIVE` | false → true only |
| `CKA_EXTRACTABLE` | true → false only |
| `CKA_COPYABLE` | true → false only |
| `CKA_WRAP_WITH_TRUSTED` | false → true only |

The reverse is `CKR_ATTRIBUTE_READ_ONLY`, on both `C_CopyObject` and
`C_SetAttributeValue` (v3.2 Table 13 footnote 11 and Table 17).

### ECDH peer public keys are validated on-curve

`CKM_ECDH1_DERIVE` and `CKM_ECDH1_COFACTOR_DERIVE` validate the peer point before
any backend sees it: it must be the uncompressed SEC1 form (`0x04` prefix) at the
length the named curve requires, and it must lie on the curve. Failure is
`CKR_MECHANISM_PARAM_INVALID`.

This is the invalid-curve attack countermeasure of NIST SP 800-56A Rev. 3
§5.6.2.3.2. The check runs in the module, so it holds for every backend —
software, TPM, PKCS#11 and cloud KMS alike.

### Authenticated wrap refuses a weaker wrapping key

`C_WrapKeyAuthenticated` (and its size-query form) refuses a wrapping key shorter
than the key it would carry, with `CKR_WRAPPING_KEY_SIZE_RANGE` — NIST SP 800-57
Part 1 §5.6.2.

The check is deliberately asymmetric: it is **not** applied to
`C_UnwrapKeyAuthenticated`, nor to the plain `C_WrapKey`/`C_UnwrapKey` path.

### PIN lockout survives `C_Finalize`

Failed-attempt counters for both the SO and the user PIN are persisted, so
`CKR_PIN_LOCKED` is not cleared by `C_Finalize` followed by `C_Initialize`.
`MaxPINAttempts` is 3 and is not configurable.

Surviving a **process restart** additionally requires the file storage backend
(`XKMS_PKCS11_STORAGE_TYPE=file`). With the in-memory default the counters are
lost with the process. Only the counts are stored; lock state is recomputed from
them.

### Session objects are destroyed and zeroized

`C_CloseAllSessions` destroys every session object. `C_Finalize` does the same and
then zeroizes every remaining in-memory object, overwriting each attribute's
bytes rather than merely dropping the reference. Persisted ciphertext in the
storage backend is untouched.

## Other known limitations

- **Objects are not slot-scoped.** See
  [security.md](security.md#known-limitation-objects-are-not-slot-scoped).
- **SLH-DSA, HSS/LMS, XMSS, XMSS^MT and the HashML-DSA / HashSLH-DSA variants
  are registered without an implementation.** They are unadvertised, so an
  application that enumerates mechanisms will not find them. But because
  `validateInitMechanism` gates on registration rather than on advertisement,
  a caller naming one of the raw constants gets `CKR_OK` from `C_SignInit` and a
  failure later, from the backend, rather than an immediate
  `CKR_MECHANISM_INVALID`.
- **`CKM_GENERIC_SECRET_KEY_GEN` generates only at 16 and 32 bytes**, while §6.9
  defines the mechanism as producing a secret of arbitrary caller-chosen length.
  No contiguous `ulMinKeySize`/`ulMaxKeySize` pair describes that, which is why
  it is unadvertised.
- **`CKM_EC_MONTGOMERY_KEY_PAIR_GEN`** (X25519/X448) is mapped and requested but
  no backend generates the key pair; `C_GenerateKeyPair` returns
  `CKR_GENERAL_ERROR`.
- **Legacy key wrap is refused by the daemon, not the module.** `CKM_RSA_PKCS`,
  `CKM_AES_CBC` and `CKM_AES_CBC_PAD` are advertised for wrapping and gated by
  `crypto.allow_legacy_key_wrap`, off by default. See
  [mechanisms.md](mechanisms.md#interaction-with-the-daemons-key-wrap-policy).
