# Image Signing — Engineering Contract

> **Status: NORMATIVE** · Feature: `image-signing` · Repo: `go-xkms` · Last verified: 2026-10-25

## Exported surface

Every `pkg/image` name is re-exported from `sdk/go/image.go` under an
`Image` prefix: `image.Signer` is `xkms.ImageSigner`, `image.NewVerifier` is
`xkms.NewImageVerifier`, and `image.ErrNoValidAttestation` is
`xkms.ErrImageNoValidAttestation`. The exceptions are `RFC3161Client`,
`PredicateTypeCosign`, `NewRFC3161Client` and `RequestCodeSigningCertificate`,
which keep their names, and `VerifyTimestamp`, which becomes
`VerifyRFC3161Timestamp`. Type aliases and `var` assignments keep the SDK
values identical to the package values, so `errors.Is` matches across the
boundary.

### Signing — `pkg/image/signer.go`

```go
type SignerConfig struct {
	Signer      crypto.Signer       // a TPM, PKCS#11 or cloud KMS key
	Certificate *x509.Certificate   // Signer's code-signing certificate
	Chain       []*x509.Certificate // issuer chain up to and including the root
	Registry    RegistryClient
	Timestamper Timestamper         // optional
}

func NewSigner(cfg *SignerConfig) (*Signer, error)
func (s *Signer) SignImage(ctx context.Context, ref string, opts *SignOptions) (*SignResult, error)

type SignOptions struct {
	PredicateType string          // PredicateTypeCosign when empty
	Predicate     json.RawMessage // may be empty only for PredicateTypeCosign
}

type CertificateIssuer interface {
	SignCSR(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error)
}

func RequestCodeSigningCertificate(ctx context.Context, issuer CertificateIssuer,
	signer crypto.Signer, tenantID, commonName string) (*x509.Certificate, error)
```

`SignerConfig` is at `:33`, `NewSigner` at `:109`, `SignImage` at `:148`,
`CertificateIssuer` at `:103` and `RequestCodeSigningCertificate` at `:229`.
`*ca.CA` (`TrustedCA`) satisfies `CertificateIssuer`; `sdk/go/image_test.go`
proves it at compile time. `SignResult` (`:78`) carries the image digest, the
envelope, the timestamp and the `PushResult`.

### Signing service — `pkg/xkms/servicer_signing_keys.go`

```go
func (s *XKMSService) SignImage(ctx context.Context, req *transport.SignImageRequest) (*transport.SignedImage, error)

type SignImageRequest struct {
	Reference     string                    // registry/repository[:tag][@digest]
	PredicateType string                    // PredicateTypeCosign when empty
	Predicate     json.RawMessage           // may be empty only for PredicateTypeCosign
	Registry      *ImageRegistryCredentials // nil sends no credentials
}

type ImageRegistryCredentials struct {
	Username string
	Password types.SecretBytes
}
```

`XKMSService.SignImage` is at `:302`. It signs with the key the reference's
repository resolves to in the caller's tenant (owner ruling 134), opened
through the tenant-scoped backend, and certified per call by the service CA
in that tenant. The request, `ImageRegistryCredentials` and `SignedImage` are
at `pkg/api/transport/types_signing_key.go:61`, `:81` and `:87`;
`SignedImage` carries the resolved key, the digest, the envelope, the PEM
certificate, the referrer digest, `ReferrerIndexed` and the `.att` tag.

| Surface | Where |
|---|---|
| Transport interface | `transport.SigningKeyService.SignImage` (`pkg/api/transport/types_signing_key.go:56`) |
| gRPC | `KeystoreService.SignImage` (`pkg/api/grpc/proto/xkmsv1/xkms.proto:1036`), served at `pkg/api/grpc/service_signing_key.go:147` |
| REST | `POST /api/v1/attestation/signing-keys/sign-image` (`pkg/api/rest/routes.go:482`, `pkg/api/rest/handlers_signing_key.go:107`) |
| MCP | `attestation.signing_key.sign_image` (`pkg/api/mcp/server.go:542`, `pkg/api/mcp/handlers_signing_key.go:87`) |
| Client transports | embedded `:75`, gRPC `:92`, MCP `:95`, QUIC `:88`, REST `:88` and unix `:92`, each in its `pkg/api/transport/<name>/transport_signing_key.go`; USB refuses (`pkg/api/transport/usb/transport_signing_key.go:57`) |
| `sdk/go` | `transport.SigningKeyService` (`sdk/go/transport/client.go:39`), `SignImageRequest` and `SignedImage` (`sdk/go/transport/types.go:372`, `:374`), `SignAttestationImageRequest` and `SignedAttestationImage` (`sdk/go/attestation_appraisal.go:129`, `:135`) |
| `sdk/ts` | `signingKeys.signImage` (`sdk/ts/src/clients/signingKey.ts:74`), `SignImageRequest` (`sdk/ts/src/types/signingKey.ts:81`) |

Every transport needs the `attestation_signing_keys` resource's `sign`
action. How each one protects the registry credentials in transit is in
[architecture.md](architecture.md#registry-credentials-on-each-transport).

### Verification — `pkg/image/verifier.go`

```go
type RootStore[P ~string] interface {
	CertificatesByPurpose(purpose P) ([]*x509.Certificate, error)
}

type VerifierConfig[P ~string] struct {
	Registry         RegistryClient
	Roots            RootStore[P]
	Purpose          P              // selects the image-signer roots
	PredicateType    string         // any type when empty
	TimestampRoots   *x509.CertPool // verifies timestamps when set
	RequireTimestamp bool           // needs TimestampRoots
}

func NewVerifier[P ~string](cfg *VerifierConfig[P]) (*Verifier, error)
func (v *Verifier) VerifyImage(ctx context.Context, ref string) (*VerificationResult, error)
```

`RootStore` is at `:29`, `VerifierConfig` at `:34`, `NewVerifier` at `:83` and
`VerifyImage` at `:127`. `RootStore` is generic over the purpose type, so a
trust-roots store whose purpose is a named string type fits without an
adapter. In the SDK, `NewImageVerifier` is a generic function
(`sdk/go/image.go:130`) because a generic function cannot be assigned to a
`var`. `VerificationResult` (`:68`) carries the digest, the statement, the
signing certificate and the verified timestamp, if any.

### Registry — `pkg/image/registry.go`

```go
type RegistryClient interface {
	Resolve(ctx context.Context, ref *Reference) (*Descriptor, error)
	PushAttestation(ctx context.Context, ref *Reference, subject *Descriptor, att *Attestation) (*PushResult, error)
	Attestations(ctx context.Context, ref *Reference) ([]*Attestation, error)
	Close() error
}

func NewRegistryClient(opts *RegistryOptions) (RegistryClient, error)
```

`RegistryClient` is at `:73` and `NewRegistryClient` at `:167`. `PushResult`
(`:124`) reports the referrer descriptor and `ReferrerIndexed`, which is true
when the registry answered with an `OCI-Subject` header. It also reports the
`.att` tag written.

### Timestamps — `pkg/image/timestamp.go`

```go
type Timestamper interface {
	Timestamp(ctx context.Context, data []byte) ([]byte, error)
}

func NewRFC3161Client(tsaURL string, httpClient *http.Client) (*RFC3161Client, error)
func VerifyTimestamp(response, data []byte, roots *x509.CertPool) (*TimestampInfo, error)
```

`Timestamper` is at `:108`, `NewRFC3161Client` at `:230` and `VerifyTimestamp`
at `:312`. The request imprint is SHA-256 with a 64-bit nonce. The response
must cover the data and echo the nonce (`:247`).

### References and attestations

- `ParseReference` (`pkg/image/reference.go:76`) parses a reference into a
  `Reference` (`:58`) holding the registry, repository, tag and digest. The
  registry defaults to `docker.io`. `AttestationTag` (`:185`) derives
  `sha256-<hex>.att`.
- `Attestation` (`pkg/image/oci.go:130`) holds the envelope, the predicate
  type, the PEM certificate and chain, and the DER `TimeStampResp`. Each is
  stored as a layer and its cosign annotations (`pkg/image/oci.go:151`).

### Signature verify — `pkg/signing/verify.go:37`

```go
func Verify(publicKey crypto.PublicKey, hash crypto.Hash, digest, signature []byte) error
```

This is RSA PKCS#1 v1.5 over a SHA-256, SHA-384 or SHA-512 digest, run
through `types.SimpleVerifier`. The SDK name is `xkms.VerifySignature`
(`sdk/go/crypto.go:60`).

## Invariants

- **The key never leaves the KMS.** `SignerConfig.Signer` is a
  `crypto.Signer`; `pkg/image` takes no key material.
  `RequestCodeSigningCertificate` sends only a CSR, under
  `ca.ProfileNameCodeSigning` and the caller's tenant, which `TrustedCA`
  stamps as the certificate's first OU and refuses when empty
  (`ca.ErrTenantRequired`, also returned before any CSR when `tenantID` is
  blank).
- **The certificate is checked before every use.** `NewSigner` refuses a
  certificate that does not match the signer's key, lacks the codeSigning EKU
  or digitalSignature usage, or is outside its validity period
  (`pkg/image/signer.go:252`). `RequestCodeSigningCertificate` checks the
  issued certificate the same way, and `SignImage` re-checks validity on
  every call.
- **The signed digest is the resolved digest.** `SignImage` signs the digest
  the registry resolved and pushes to the reference pinned by that digest. A
  reference that carries a digest must match the manifest bytes
  (`pkg/image/registry.go:215`).
- **Every push writes both forms.** The referrer is written first, then the
  `.att` tag. The tag manifest is read, appended to and rewritten, so
  earlier attestations survive (`pkg/image/oci.go:213`). The read-modify-write
  is not atomic: two signers pushing the same image at once can lose one
  tag entry, though both referrers remain.
- **Verification fails closed.** Every attestation is checked in full; the
  first that passes is returned. When none passes, `ErrNoValidAttestation`
  joins every failure (`pkg/image/verifier.go:127`). A layer whose timestamp
  annotation does not decode fails alone: `Attestations` returns it with
  `Attestation.Invalid` naming the layer, and the verifier refuses it and
  goes on to the next (`attestationFromLayer`, `pkg/image/oci.go`). The check order is the
  certificate, the envelope signature, the statement subject, the predicate
  type, the timestamp, and then the chain at `genTime`, or at the current
  time when no timestamp verifies (`pkg/image/verifier.go:164`).
- **The chain annotation grants no trust.** It only supplies intermediates.
  Roots come from `RootStore` alone, fetched on each `VerifyImage`
  (`pkg/image/verifier.go:107`).
- **Credentials stay with the registry host.** A blob upload redirected to
  another host is sent without credentials, and a non-HTTPS upload location
  is refused (`pkg/image/registry.go:480`, `:526`). Every registry and
  token-realm request follows redirects only to HTTPS, at most 10 of them,
  and drops its `Authorization` header on a redirect to another host; any
  other redirect fails with `ErrRedirectRefused`, unretried, before it is
  followed (`checkRedirect`, `pkg/image/registry.go`).
- **Bearer challenges are followed once.** Without `Auth.Token`, a 401 that
  carries `WWW-Authenticate: Bearer` makes the client fetch a token from the
  challenge's realm with its `service` and `scope`, sending the basic
  credentials if any, and repeat the request once with it. The realm must be
  HTTPS. The token is kept per registry host and sent first afterwards
  (`pkg/image/registry.go`, `pkg/image/registry_token.go`).
- **The password stays sealed.** `Auth.Password` is a caller-owned
  `*secure.Secret`. Each request that carries basic credentials opens it,
  builds the header from a `username:password` copy that is wiped at once,
  and destroys the opened buffer; the client never destroys the Secret
  itself (`pkg/image/registry.go:783`).
- **Concurrency.** `Signer` and `Verifier` hold no mutable state after
  construction; the registry client's only state is its token cache, a
  `sync.Map`. All three are safe for concurrent use.
- **Every referrers page is read.** The referrers index follows each
  `Link: <...>; rel="next"` header until none remains, up to 64 pages. A
  next page must be HTTPS on the registry's host; anything else, or a
  malformed `Link`, fails with `ErrInvalidManifest` (`pkg/image/registry.go`).

## Error semantics

All errors are sentinels in `pkg/image/errors.go` and `pkg/signing/errors.go`,
wrapped in `errs.Detail` or `errs.Joined` so that `errors.Is` matches the
sentinel. The SDK re-exports each one under the `ErrImage` or `ErrSigning`
prefix.

| Error | Returned when |
|---|---|
| `ErrInvalidReference` (`:21`), `ErrInvalidDigest` (`:25`) | The reference does not parse, or the digest is malformed or not SHA-256 where a tag is derived |
| `ErrKeyMismatch` (`:51`), `ErrNotCodeSigning` (`:55`), `ErrCertificateNotValid` (`:59`) | The signing certificate fails the code-signing check: `NewSigner` and the verifier both require the codeSigning EKU and digitalSignature usage |
| `ca.ErrTenantRequired` | `RequestCodeSigningCertificate` is given a blank tenant |
| `ErrUnsupportedKey` (`:62`) | The key is not RSA, ECDSA or Ed25519 |
| `ErrRegistryUnavailable` (`:86`) | Retries ran out on 5xx or transport errors |
| `ErrRedirectRefused` | A registry or realm redirect leads to a destination other than HTTPS, or past 10 redirects |
| `ErrRegistryAuth` | A Bearer challenge is malformed or has no HTTPS realm, or the realm issues no token |
| `ErrRegistryCredentials` (`:93`) | `Auth.Password` cannot be opened, for example after it was destroyed |
| `ErrNoTrustedRoots` (`:130`) | The root store fails or holds nothing for the purpose |
| `ErrNoAttestation` (`:134`) | Neither the referrers nor the `.att` tag hold an attestation |
| `ErrNoValidAttestation` (`:137`) | Attestations exist but none verified; the cause joins each failure |
| `ErrInvalidAttestation` (`:141`) | The attestation has no certificate or more than one, an undecodable chain, or an undecodable timestamp annotation |
| `ErrSignatureInvalid` (`:161`) | No envelope signature verifies under the certificate key |
| `ErrSubjectMismatch` (`:153`), `ErrPredicateTypeMismatch` (`:157`) | The statement names another digest, or has the wrong predicate type |
| `ErrUntrustedSigner` (`:165`) | The certificate does not chain to a trusted root for codeSigning at the verification time |
| `ErrTimestampRequired` (`:205`) | `RequireTimestamp` is set and the attestation has no timestamp |
| `ErrTimestampMismatch` (`:189`), `ErrTimestampUntrusted` (`:197`) | The token does not cover the envelope or echo the nonce, or does not chain to `TimestampRoots` |
| `ErrTimestampExtKeyUsage` | The TSA certificate's extended key usage is not exactly id-kp-timeStamping, marked critical (RFC 3161 section 2.3) |
| `ErrTimestampRootsRequired` (`:201`) | `RequireTimestamp` is set without `TimestampRoots`, or `VerifyTimestamp` gets no roots |
| `signing.ErrPublicKeyRequired` (`pkg/signing/errors.go:35`) | The public key is nil |
| `signing.ErrUnsupportedKeyType` (`:41`) | The key is not RSA |
| `signing.ErrInvalidHashFunction` (`:29`) | The hash is not SHA-256, SHA-384 or SHA-512 |
| `signing.ErrSignatureRequired` (`:38`) | The signature is empty |
| `signing.ErrVerificationFailed` (`:44`) | The signature does not verify; the cause is the `SimpleVerifier` error |

`XKMSService.SignImage` returns the image errors above wrapped in
`ImageSignError` (`pkg/xkms/servicer_signing_keys.go:103`), which names the
reference and the key and unwraps to the cause. The gRPC, REST and MCP
servers map its errors through `SigningKeySentinelClasses` (`pkg/api/apierrors/tables.go:334`):

| Error | Class |
|---|---|
| `ErrSystemTenantImageSigning` (`pkg/xkms/servicer_signing_keys.go:98`): the caller is the system tenant, which has no release key (owner-queue item 153) | FailedPrecondition |
| `ErrSigningKeyForbidden` | PermissionDenied |
| `ErrNotConfigured`: the service has no CA | Unavailable |
| `ErrInvalidReference`, `ErrInvalidDigest`, `ErrInvalidStatement`, `ErrRegistryCredentials` (also a password without a username) | InvalidArgument |
| `ErrManifestNotFound` | NotFound |
| `ErrRegistryUnavailable` | Unavailable |
| `ErrRegistryRequest`, `ErrRegistryAuth`, `ErrUnsupportedKey`, `ErrKeyNotFound` (the resolved key is absent) | FailedPrecondition |

## Configuration

`RegistryOptions` (`pkg/image/registry.go:100`) uses its default for any zero
field (`pkg/image/registry.go:38`):

| Field | Default |
|---|---|
| `Timeout` | 30 s per request |
| `MaxRetries` | 3 retries |
| `RetryDelay` | 1 s |
| `UserAgent` | `go-xkms-image` |
| `RootCAs` | The system pool |
| `Auth` | No credentials; a Bearer challenge is still followed anonymously |

`NewRFC3161Client` uses a 30 s HTTP timeout when it is given no client
(`pkg/image/timestamp.go:39`). Manifests are capped at 4 MiB and blobs at
32 MiB.

## Persistence

None. Attestations live in the registry.

## Test strategy

Unit tests run with `make test-image`, against `httptest` servers only:

- **Registry fake.** `newTestRegistry` (`pkg/image/helpers_test.go:285`)
  serves manifests, blob uploads and, when enabled, the referrers API. Tests
  turn referrers off to exercise the `.att` fallback, page the referrers
  index or set its `Link` header, make the registry
  unavailable for a number of requests to exercise retries, require a bearer
  token (optionally issued by its own `/token` realm behind a Bearer
  challenge), redirect uploads, and tamper with stored blobs.
- **TSA fake.** `newTestTSA` (`pkg/image/helpers_test.go:567`) answers with
  CMS-signed tokens. A tamper hook edits each `TSTInfo` (imprint, nonce,
  time), and the status can refuse. `timestampResponse` builds tokens with
  the wrong algorithms, attributes, signer count or certificates.
- **PKI.** `newTestPKI` (`pkg/image/helpers_test.go:115`) builds a root that
  issues code-signing and timestamping leaves. Signers cover RSA, ECDSA and
  Ed25519.
- **End to end.** `verifier_test.go` signs and verifies through both stores.
  It covers the timestamped expired-certificate case, an untrusted TSA, and a
  valid attestation found among invalid ones.
- **SDK.** `sdk/go/image_test.go` proves the aliases are the package types,
  pins every sentinel by identity, and runs `VerifySignature` both ways.
- **Signing service.** `pkg/xkms/servicer_signing_keys_image_test.go` signs
  against the registry fake with the release key by default and with a bound
  key, checks the credentials reach the registry and are wiped, and covers
  another tenant's key, the system tenant, a missing `sign` permission and an
  unconfigured CA. `pkg/api/{grpc,rest,mcp}/*signing_key_image_test.go` pin
  each server's error classes, and `sdk/ts/src/signingKey.test.ts` the
  TypeScript client.

There is no integration suite against a real registry or TSA; the fakes
above speak the OCI distribution and RFC 3161 wire protocols.

## Observability

`pkg/image` neither logs nor emits metrics. Callers log the returned errors.
