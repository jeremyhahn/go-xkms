# Image Signing — Architecture

> **Status: NORMATIVE** · Feature: `image-signing` · Repo: `go-xkms` · Last verified: 2026-10-15

## The problem

A platform that runs container images must know who built each image and
that the bytes it pulls are the bytes that were signed. The signing key must
never exist as a file: a key file can be copied, and a copied key signs
anything. The signature also has to be readable by the tool operators already
use, cosign, without a go-xkms-specific format.

## Shape chosen

`pkg/image` signs with a KMS `crypto.Signer`: a TPM, PKCS#11 or cloud key
whose private half never leaves the device. `TrustedCA` certifies the key
under its code-signing profile (`pkg/image/signer.go:221`). The signer:

1. Resolves the reference to its manifest digest (`pkg/image/registry.go:215`).
2. Writes an in-toto statement with that digest as its subject
   (`pkg/image/dsse.go:79`).
3. Wraps the statement in a DSSE envelope signed over the PAE
   (`pkg/image/dsse.go:111`, `:139`). RSA and ECDSA keys sign SHA-256(PAE);
   Ed25519 signs the PAE itself (`pkg/image/dsse.go:128`).
4. Optionally gets an RFC 3161 timestamp over the envelope bytes
   (`pkg/image/timestamp.go:247`).
5. Pushes the attestation twice (`pkg/image/registry.go:271`):
   - as an OCI 1.1 referrer whose subject is the image, with the DSSE media
     type as its artifact type (`pkg/image/oci.go:199`);
   - into cosign's `sha256-<hex>.att` tag, appended to any attestations
     already stored there (`pkg/image/oci.go:213`).

`Verifier.VerifyImage` (`pkg/image/verifier.go:127`) resolves the image and
reads its attestations. It reads the OCI 1.1 referrers first and falls back
to the `.att` tag (`pkg/image/registry.go:329`). The first attestation that
passes every check wins; when none passes, the error joins every failure.

## Rejected alternatives

| Alternative | Why rejected |
|---|---|
| Sign with a key file (PEM on disk, as cosign's default does) | A file can be copied. Only a KMS `crypto.Signer` is accepted (`pkg/image/signer.go:34`). |
| Push only the `.att` tag | Registries that support OCI 1.1 index referrers; tags are the fallback for those that do not. Writing both serves both kinds of registry. |
| Push only the OCI 1.1 referrer | cosign and registries without the referrers API read the tag. |
| Trust the certificate chain stored in the attestation | Anyone who can push can write the annotation. The chain is used only as intermediates; trust comes from the root store alone (`pkg/image/verifier.go:224`, `:164`). |
| Verify the certificate at the current time when a timestamp is present | A signing certificate expires long before the image stops running. A verified timestamp's `genTime` is used instead (`pkg/image/verifier.go:164`). |
| A new RSA verify in `pkg/signing` | `types.SimpleVerifier` is the one RSA verify. Both `pkg/signing.Verify` (`pkg/signing/verify.go:37`) and the DSSE check (`pkg/image/dsse.go:157`) call it. |

## Component boundaries

| Piece | Where | Notes |
|---|---|---|
| Reference parsing, registry referrer push, RFC 3161 client | `pkg/image` | Came from go-trusted-platform's `pkg/image`, rewritten onto go-xkms packages |
| DSSE, in-toto, OCI manifests, signer, verifier | `pkg/image` | Standard library and go-xkms packages only; no build tag |
| Code-signing certificate | `pkg/ca` `TrustedCA.SignCSR` (`pkg/ca/ca.go:1660`) | Reached through `pkg/image.CertificateIssuer` (`pkg/image/signer.go:96`) |
| Trusted image-signer roots | The caller's root store | `pkg/image.RootStore[P]` (`pkg/image/verifier.go:29`) asks for certificates by purpose; any store with `CertificatesByPurpose` fits |
| RSA PKCS#1 v1.5 verify | `pkg/signing.Verify` (`pkg/signing/verify.go:37`) | SHA-256, SHA-384 or SHA-512 over RSA keys only |
| SDK edge | `sdk/go/image.go`, `sdk/go/crypto.go:60` | go-quicbaas consumes `VerifyImage` and `VerifySignature` here |

go-quicbaas replaces its Tier 0 `ImageSignature` with `ImageVerifier.VerifyImage`
through the SDK. go-trusted-platform keeps its manifest format and its AK-key
extraction, and calls the `pkg/signing` verify through go-quicbaas.

## Data flow

```
sign:   ref ─▶ Resolve ─▶ digest ─▶ in-toto statement ─▶ DSSE (KMS signer)
             ─▶ [RFC 3161 TSA] ─▶ push envelope + empty config blobs
             ─▶ referrer manifest (subject = image) ─▶ .att tag manifest

verify: ref ─▶ Resolve ─▶ digest ─▶ referrers ─▶ (none) ─▶ .att tag
             ─▶ each attestation: certificate ─▶ envelope signature
                ─▶ statement subject = digest ─▶ predicate type
                ─▶ [timestamp] ─▶ chain to root at genTime or now
```

The registry and the TSA are the only network peers. Both are reached over
HTTP(S) by `pkg/image`; nothing is persisted locally.

## Trust boundaries

- **The private key** stays in the KMS. Only the CSR leaves it
  (`pkg/image/signer.go:221`). `NewSigner` refuses a certificate that does
  not match the signer's public key, lacks the codeSigning EKU or
  digitalSignature usage, or is outside its validity period
  (`pkg/image/signer.go:252`).
- **The registry is untrusted.** Every attestation read from it is checked
  in full: the envelope signature, the statement subject against the digest
  the registry resolved, and the certificate chain against the root store
  with the codeSigning EKU and digitalSignature usage
  (`pkg/image/verifier.go:164`). Every page of the referrers index is read;
  a `Link` to a next page off the registry's host is refused.
- **The TSA** is trusted only through `TimestampRoots`. The token must cover
  the envelope bytes and chain to a root, and the TSA certificate must carry
  id-kp-timeStamping as its only extended key usage, marked critical
  (RFC 3161 section 2.3; `pkg/image/timestamp.go:312`). Without `TimestampRoots`, a timestamp is
  ignored rather than trusted (`pkg/image/verifier.go:209`).

## What this feature does not do

- **No transparency-log append.** Appending each signature to the
  transparency log ships separately; nothing here stubs it.
- **No transport route.** Image signing is an embedded Go and SDK call; it
  has no REST, gRPC, QUIC, MCP or Unix-socket route.
- **No non-SHA-256 digests.** A `sha512-<hex>.att` tag would exceed the
  128-character OCI tag limit, so `AttestationTag` refuses any other
  algorithm (`pkg/image/reference.go:185`), and signing or verifying an image
  pinned by such a digest fails with `ErrInvalidDigest`. A tag reference
  always resolves to a SHA-256 digest (`pkg/image/registry.go:215`).
- **No manifest-format or AK-key logic** from go-trusted-platform; that
  stays there.
