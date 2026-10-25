# Image Signing — Architecture

> **Status: NORMATIVE** · Feature: `image-signing` · Repo: `go-xkms` · Last verified: 2026-10-25

## The problem

A platform that runs container images must know who built each image and
that the bytes it pulls are the bytes that were signed. The signing key must
never exist as a file: a key file can be copied, and a copied key signs
anything. The signature also has to be readable by the tool operators already
use, cosign, without a go-xkms-specific format.

## Shape chosen

`pkg/image` signs with a KMS `crypto.Signer`: a TPM, PKCS#11 or cloud key
whose private half never leaves the device. `TrustedCA` certifies the key
under its code-signing profile, in the caller's tenant, which it stamps as
the certificate's first OU (`RequestCodeSigningCertificate`,
`pkg/image/signer.go`). The signer:

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
| Sign with a key file (PEM on disk, as cosign's default does) | A file can be copied. Only a KMS `crypto.Signer` is accepted (`pkg/image/signer.go:33`). |
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
| Code-signing certificate | `pkg/ca` `TrustedCA.SignCSR` (`pkg/ca/ca.go:1660`) | Reached through `pkg/image.CertificateIssuer` (`pkg/image/signer.go:103`) |
| Trusted image-signer roots | The caller's root store | `pkg/image.RootStore[P]` (`pkg/image/verifier.go:29`) asks for certificates by purpose; any store with `CertificatesByPurpose` fits |
| RSA PKCS#1 v1.5 verify | `pkg/signing.Verify` (`pkg/signing/verify.go:37`) | SHA-256, SHA-384 or SHA-512 over RSA keys only |
| SDK edge | `sdk/go/image.go`, `sdk/go/crypto.go:60` | go-quicbaas consumes `VerifyImage` and `VerifySignature` here |
| Signing service | `XKMSService.SignImage` (`pkg/xkms/servicer_signing_keys.go:302`) | Signs with the repository's resolved key (owner ruling 134), on every transport through `transport.SigningKeyService.SignImage` (`pkg/api/transport/types_signing_key.go:56`) |

## The signing service

`XKMSService.SignImage` signs an image with the key the repository resolves
to in the caller's tenant: the key bound to the repository, or else the
tenant's release key, `release-signing` (see the `release-signing-key` row of
[SPEC.md](../SPEC.md)). Per call it:

1. checks the `attestation_signing_keys` `sign` permission and refuses the
   system tenant (`:317`);
2. parses the reference and validates its repository, then seals the
   registry credentials (`registryAuth`, `:420`) before anything is issued;
3. resolves the key (`Appraiser.ResolveSigningKey`) and opens it through the
   tenant-scoped backend (`repositorySigner`, `:204`), so it never leaves
   the backend;
4. has the service CA issue that key a code-signing certificate in the
   tenant (`image.RequestCodeSigningCertificate`);
5. drives `pkg/image`'s `Signer`, which pushes the attestation to the
   image's registry with the caller's credentials.

It returns the resolved key, the digest, the envelope, the PEM certificate
and the push result (`SignedImage`, `pkg/api/transport/types_signing_key.go:86`).

### Registry credentials on each transport

The request carries the registry username and password
(`ImageRegistryCredentials`, `pkg/api/transport/types_signing_key.go:80`).
The service uses them for that call only, wipes the password on every path
(`pkg/xkms/servicer_signing_keys.go:306`) and names neither in an error. In
transit they are as safe as the transport:

| Transport | Carries the credentials over |
|---|---|
| Embedded | No wire: an in-process call (`pkg/api/transport/embedded/transport_signing_key.go:75`) |
| MCP | mTLS only; the client has no plaintext mode (`pkg/api/transport/mcp/transport.go:17`) |
| QUIC | TLS 1.3 always (`pkg/api/transport/quic/transport.go:193`) |
| Unix socket | A local socket (`pkg/api/unix/grpc_server.go:261`), TLS 1.3 on top when `TLSEnabled` (`pkg/api/transport/unix/transport.go:101`) |
| gRPC | TLS 1.3 (`pkg/api/transport/grpc/transport.go:115`, `:122`); a TLS-disabled TCP endpoint is refused (`:95`) |
| REST | TLS 1.3 over `https://` (`pkg/api/transport/rest/transport.go:129`, `:135`); any other base URL is refused (`:121`) |
| USB | Refused: `SignImage` returns `ErrNotSupported` (`pkg/api/transport/usb/transport_signing_key.go:57`) |

No client sends the password in clear (ruling 152). The gRPC and REST
constructors refuse a TLS-disabled TCP endpoint with
`transport.ErrInsecureTransport`. `SignImage` checks again before it sends
`Registry` credentials, because the caller can change the `transport.Config`
after construction (`pkg/api/transport/grpc/transport_signing_key.go:96`,
`pkg/api/transport/rest/transport_signing_key.go:92`). The one opt-out,
`AllowInsecureTransport` or `XKMS_TRANSPORT_ALLOW_INSECURE_TRANSPORT`, is for
loopback tests and dev only; see
[Client Transport Security](../configuration/README.md#client-transport-security).
`types.SecretBytes` prints as `[REDACTED]` for every `fmt` verb
(`Format`, `pkg/types/types_secretbytes.go:250`), so a logged request never shows the
password.

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
  (`pkg/image/signer.go:229`). `NewSigner` refuses a certificate that does
  not match the signer's public key, lacks the codeSigning EKU or
  digitalSignature usage, or is outside its validity period
  (`pkg/image/signer.go:263`).
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
  transparency log waits on the transparency-log rows (#1549); nothing here
  stubs it.
- **No signing for the system tenant.** It has no release signing key, so
  `SignImage` refuses it with `ErrSystemTenantImageSigning`
  (`pkg/xkms/servicer_signing_keys.go:98`, `:317`) until the owner decides
  otherwise (owner-queue item 153).
- **No automatic release key.** Nothing creates a tenant's `release-signing`
  key; the tenant provisions it, or binds the repository to another key.
- **No non-SHA-256 digests.** A `sha512-<hex>.att` tag would exceed the
  128-character OCI tag limit, so `AttestationTag` refuses any other
  algorithm (`pkg/image/reference.go:185`), and signing or verifying an image
  pinned by such a digest fails with `ErrInvalidDigest`. A tag reference
  always resolves to a SHA-256 digest (`pkg/image/registry.go:215`).
- **No manifest-format or AK-key logic** from go-trusted-platform; that
  stays there.
