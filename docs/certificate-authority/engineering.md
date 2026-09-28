# Certificate Authority — Engineering Contract

> **Status: NORMATIVE** · Feature: `certificate-authority` · Repo: `go-xkms` · Last verified: 2026-09-28

## Exported surface — `pkg/ca`

`TrustedCA` (`interface.go:107`) embeds `crypto.Signer` plus fifteen
sub-interfaces. Method sets, verbatim from `interface.go`:

**`CALifecycle`** — `Init(ctx) error`, `Load(ctx) error`, `IsInitialized() bool`.
`Init` self-signs for a root CA, or produces a CSR then the intermediate
certificate for an intermediate. Returns `ErrAlreadyInitialized` if already
initialized, `ErrInvalidConfig` on bad config. Thread-safe, but call once at
startup.

**`CAIssuer`** — `SignCSR(ctx, csrPEM []byte, opts *SignOptions) (*x509.Certificate, error)`,
`CreateCSR(ctx, request *CertificateRequest) ([]byte, error)`,
`IssueCertificate(ctx, request *CertificateRequest) (*IssuedCertificate, error)`.

**`CATrustChain`** — `CACertificate()`, `CABundle()`,
`CABundleFiltered(storeType types.StoreType, keyAlgorithm x509.PublicKeyAlgorithm)`,
`Verify(cert, xsigner ...crypto.Signer) ([][]*x509.Certificate, error)`,
`TrustedRoot()`, `TrustedIntermediate()`, `RootCertificate(childCert)`,
`ParseBundle(bundle)`.

**`CARevoker`** — `Revoke(ctx, serial *big.Int, reason int) error`,
`RevokeCert(ctx, cert, opts RevokeOptions) error`, `GenerateCRL(ctx) ([]byte, error)`,
`CRL(ctx) ([]byte, error)`, `IsRevoked(serial *big.Int) (bool, error)`.
`RevokeCert`'s `RevokeOptions.DeleteKeys` deletes exactly the key the CA
generated or resolved at issuance, resolved from the `issued-keys/` record
(see "Issued-key persistence" under Persistence) rather than reconstructed
from the certificate; a CSR-signed certificate — one whose key the CA never
held — is a no-op, not a failure (go-xkms#751).
`GenerateCRL` always signs a new CRL (the explicit force-refresh verb,
`POST /ca/crl`); `CRL` returns the persisted DER, regenerating first only
when none exists or the published `NextUpdate` has passed (`GET /ca/crl`).
See "CRL persistence" under Persistence.

**`CATLSConfig`** — `TLSCertificate(ctx, attrs)`, `TLSConfig(ctx, attrs)`,
`ServerTLSConfig(ctx, attrs, requireClientCert bool)`,
`ClientTLSConfig(ctx, attrs, serverName string)`.

**`CATrustPools`** — `TrustedRootCertPool(cert)`,
`TrustedIntermediateCertPool(cert)`, `CABundleCertPool()`, `OSTrustStore()`,
and the `…WithXSigner` variants.

**`CAStores`** — `KeyStore() xkms.Backend`, `CertStore() certstore.CertStore`.

**`CAIdentityInfo`** — `Config() *Identity`, `Identity() string`,
`IssuingIdentity() Identity`, `CAKeyAttributes(storeType)`,
`DefaultKeyAlgorithm()`, `DefaultSignatureAlgorithm()`, `DefaultValidityPeriod()`,
`Hash() crypto.Hash`, `IsAutoImportingIssuerCAs() bool`.

**`CASigningIdentity`** — `Signer(ctx)`, `PrivateKey(ctx, attrs)`,
`PubKey(ctx, attrs)`, `SignedBlob(ctx, data)`,
`CASigner(ctx, storeType, algo)`.

**`CACertificateAccessor`** — `Exists(ctx, cn, algo)`, `Certificate(ctx, attrs)`,
`CertificatePEM(ctx, cn)`, `ImportCertificate(ctx, cert)`,
`ImportCertificatePEM(ctx, cn, pemBytes)`, `PEM(ctx, attrs)`.

**`CAObjectStore`** — `Blob(key)`, `ImportBlob(key, data)`.

**`CAChainImporter`** — `ImportDistributionCRLs(cert)`,
`ImportIssuingCAs(ctx, cert)`. This is the AIA walk.

**`CACrossSigner`** — `ImportXSignedCertificate(issuerCN, cert)`,
`XSignedCertificate(issuerCN, attrs)`, `XSignedRootCertificate(issuerCN, cert)`,
`XSignedIntermediateCertificates(issuerCN, cert)`,
`CrossSignedPEM(attrs)`.

**`CAAttestation`** — `ImportAttestation(ctx, akAttrs, blobType, data)`,
`ImportAttestationKeyCertificate(ctx, attrs, akDER)`,
`ImportAttestationEventLog(ctx, akAttrs, eventLog)`,
`ImportAttestationPCRs(ctx, akAttrs, pcrs)`,
`ImportAttestationQuote(ctx, akAttrs, quote)`,
`ImportLocalAttestation(ctx, akAttrs, quote *tpm2.Quote)`,
`VerifyAttestationQuote(akAttrs, quote)`.

**`CATCGEnrollment`** —
`VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg x509.SignatureAlgorithm) (blob, secret, plain []byte, err error)`.
The `TPM2_MakeCredential` challenge is built in software
(`tpm2.NewCredentialChallenge`, `tpm2.ActivationKeyName`); this method no
longer calls `ca.getTPM()` and no longer requires `SetTPM` to have been
called (go-xkms#798) -- `EnrollDevice` (the full IAK/IDevID issuance path)
still does, for `SignTCGCSRIDevID`.

**TCG DevID certificate conformance** (`tcg.go`, `tcg_oids.go`,
`tcg_devid_name.go`, `san.go`) — the IDevID and IAK certificates
`SignTCGCSRIDevID` issues conform to TCG *TPM 2.0 Keys for Device Identity and
Attestation* v1.00 r12 §8.1 and §8.2:

- `TCGDeviceIdentityFromEKCertificate(ekCert, manufacturerOverride)` and
  `TCGDeviceIdentityFromEKPublicKey(ekPubDER)` derive the §8.1 pair. The
  hwSerialNum is `<TCG TPM manufacturer code>:<EK AKI>:<EK cert serial>`, the
  two binary components rendered as lowercase hexadecimal; the
  identifierValue is `hex(SHA-256(EK certificate DER))`. Without an EK
  certificate both are SHA-256 digests of the DER SubjectPublicKeyInfo, the
  identifier over `"EkPubkey" || key`.
- `TCGTPMManufacturer(ekCert)` reads tcg-at-tpmManufacturer (2.23.133.2.1)
  from the subject, the subjectDirectoryAttributes extension, or a
  directoryName inside subjectAltName, in that order.
  `TCGTPMManufacturerFromCSR(csr)` searches a certificate request the same way.
- `ValidateTCGTPMManufacturer(code)` accepts only the form the attribute
  carries and the tpm2 package reports in `PropertiesFixed.ManufacturerCode`:
  `id:` and eight uppercase hexadecimal digits (`id:49465800` is Infineon).
  Anything else is `ErrTCGInvalidManufacturerCode`.
- `IssueEKCertificate` records `CertificateRequest.TPMManufacturer` as
  tcg-at-tpmManufacturer inside a subjectAltName directoryName, the placement
  the TCG EK Credential Profile uses and `TCGTPMManufacturer` reads, so a
  TPM endorsed here can later enroll an IDevID with no manufacturer override.
  `TCGTPMManufacturerSubjectAltName(subject, code)` builds the same extension
  for a certificate request.
- `BuildSubjectAltName(subject, dns, email, ip, uri, others, directoryNames)`
  is the only GeneralNames encoder in go-xkms. `CertificateSpec.OtherNames`
  and `CertificateSpec.DirectoryNames` route through it; crypto/x509 has
  neither and skips its own subjectAltName once one is supplied, so the
  standard names are encoded here too.
- `OtherName`, `MarshalHardwareModuleName`, `MarshalPermanentIdentifier`,
  `ParseHardwareModuleNameExtension`, `ParsePermanentIdentifierExtension`,
  and the OIDs `OIDTCGHwTypeTPM2` (2.23.133.1.2) and
  `OIDTCGOnEKPermIdSha256` (2.23.133.12.1).

Constructors are `pkg/ca/constructors.go`; configuration types are
`pkg/ca/config.go` (`Identity`, and the CA config it hangs off).

## Invariants

- **`Init` is once.** A second `Init` returns `ErrAlreadyInitialized` rather
  than replacing the root. `Load` is the idempotent startup path.
- **`Load` resolves every identity's key attributes through the same
  `getCAKeyAttributes` default-filling `Init` uses**, never the bare
  `Identity.ToKeyAttributes`. An identity's `KeyConfig` that leaves key-type
  unset still stores and loads under the same `KeyTypeCA`-defaulted
  attributes on every call; the two paths must never diverge (go-xkms#793).
  See "CA reload / restart persistence" under Persistence.
- **Only a genuine `storage.ErrNotFound` behind a certificate lookup becomes
  `ErrCertificateNotFound`.** A `certStore.GetCertificate` failure for any
  other reason (a corrupt or unparseable persisted certificate, a backend
  I/O failure) is returned as a distinct error that does not satisfy
  `errors.Is(_, ErrCertificateNotFound)`, so a caller — in particular
  `pkg/server`'s `initializeCA` — can never mistake damaged existing state
  for an empty store (`wrapCertLookupError`, go-xkms#793).
- **Every operation requires `IsInitialized()`.** Issuance against an
  uninitialized CA fails closed.
- **`getOrGenerateCAKey` (`pkg/ca/ca.go`) generates a key only when the
  backend's `GetKey` reports it does not exist yet** —
  `errors.Is(err, backend.ErrKeyNotFound)`, per the contract in
  [`../crypto-backends/engineering.md`](../crypto-backends/engineering.md#error-semantics).
  Any other `GetKey` failure (a TPM transient fault, a PKCS#11 login
  failure, cloud KMS throttling, an I/O error against the metadata store)
  returns `ErrKeyRetrievalFailed` and generates nothing (#801). Treating
  "the backend could not answer" the same as "no key yet" would silently
  replace a hardware-backed CA signing key the first time its backend had a
  bad moment.
- **Serial numbers are unique and never reused**, including across revocation.
- **`Verify` returns chains, not a boolean**, so callers can inspect which path
  validated. An empty result with a nil error is not success.
- **`ImportAttestation*` stores; `VerifyAttestationQuote` decides.** Never treat
  a successful import as a successful verification.
- **`CABundleFiltered` is not cosmetic.** A relying party that cannot handle the
  CA's other algorithm must be given the filtered bundle, or chain building
  fails at the far end.
- **Concurrency.** Issuance is safe for concurrent use; `Init` is not, and is
  documented as a startup-only call.
- **The persisted CRL artifact is the source of truth; `certStore`'s
  `StoreCRL`/`GetCRL` is a cache, never authoritative.** `CA.CRL` checks the
  cache first, but a miss or a stale cached entry always falls through to
  `ca.revocationStore` — never to signing without first
  checking there.
- **CRL `Number` is monotonic per issuer, derived from the previously
  persisted artifact, not from wall-clock time.** Two regenerations inside
  the same clock tick — refresh-on-revoke firing twice in quick succession,
  or a test with a fixed injected clock — still produce strictly increasing
  numbers. Only `ErrCRLNotFound` starts the sequence at 1; a store fault or
  an unparseable persisted number fails generation with `ErrStorageError`
  (`nextCRLNumber`, `pkg/ca/crl_persistence.go:134`).
- **Revocation reads fail closed (#1116).** `IsRevoked`, `Verify`,
  `VerifyPeerCertificate`, OCSP, CRL generation and `Load` report "not
  revoked" only for a definite `storage.ErrNotFound`. A store fault is
  `ErrStorageError` with the storage cause kept in the chain
  (`pkg/ca/ca_extensions.go:776`, `pkg/ca/crl_persistence.go:106`); a record
  that does not decode, or names a serial other than the one its key is
  for, is `ErrRevocationRecordCorrupt` naming the key
  (`pkg/ca/ca_extensions.go:805`, `pkg/ca/errors.go:97`). `Load` refuses to
  bring up a CA over a corrupt record rather than skip it.
  `VerifyPeerCertificate` returns `ErrPeerVerificationFailed` joined with
  the `IsRevoked` error (`pkg/ca/tls.go:508`, `:544`); OCSP answers
  `ocsp.Unknown` with `ErrOCSPStorageError` joined with the cause
  (`pkg/ca/ocsp.go:231`); CRL generation returns `ErrCRLGenerationFailed`
  joined with the cause and publishes nothing.
- **Cluster visibility.** A serial missing from the in-memory map is read
  through to `revocationStore` (`lookupRevocation`,
  `pkg/ca/ca_extensions.go:856`), and a CRL is built from the store's full
  record set (`pkg/ca/crl_persistence.go:179`), so a revocation recorded on
  any node is enforced and published by every node. Store hits are cached
  (`cacheRevocation`, `pkg/ca/ca_extensions.go:831`); misses never are.
- **Staleness is a read-time decision, not a write-time one.** There is no
  leader election and no background CRL scheduler; any instance may sign a
  refresh. A read past the persisted `NextUpdate` regenerates before
  answering; a read before it never signs.
- **A TCG DevID certificate carries its §8.1 subjectAltName or it is not
  issued.** The hardwareModuleName and permanentIdentifier are a SHALL and are
  derived from the endorsement key certificate the CSR carries, so a request
  without one, or whose TPM manufacturer code cannot be determined, is refused
  (`ErrTCGInvalidEKCert`, `ErrTCGEKManufacturerUnknown`). Extension
  construction never swallows an error: `ErrTCGMandatoryExtension` refuses
  issuance instead.
- **The §8.2 assertions are certificate policies, not extensions, and the
  fixed and restricted assertions are mutually exclusive.** An IAK carries
  verifiedTPMResidency and verifiedTPMRestricted; an IDevID carries
  verifiedTPMResidency and verifiedTPMFixed. §8.2 makes each pairing with the
  other a MUST NOT.
- **TCG TPM attributes are subjectAltName directoryName entries, never
  standalone extensions.** tcg-at-tpmManufacturer, tpmModel and tpmVersion
  are attribute types, not extension identifiers; an extension under one of
  those OIDs is read by nothing. An EK certificate once recorded its
  manufacturer that way, and every IDevID enrollment of a TPM endorsed here was
  refused with `ErrTCGEKManufacturerUnknown`. The standalone encoders
  (`CreateTPMManufacturerExtension`, `CreateTPMModelExtension`,
  `CreateTPMVersionExtension`) were removed with it.
- **The device serial number lives in the subject, the device model under
  tcg-at-platformModel.** Neither belongs under tcg-at-tpmModel or
  tcg-at-tpmVersion, which name the TPM's own model and firmware version.
- **A CSR whose keys are not Template H-0 with the §7.3.6.6 key policy is
  refused.** `tpm2.AssertDevIDKeyConformant` applies to a received public area
  the attribute and policy half of the rule provisioning applies before
  `TPM2_CreatePrimary`: Restricted per key kind, Signing, decrypt CLEAR,
  fixedTPM, fixedParent, userWithAuth, adminWithPolicy, and `authPolicy ==
  DevIDKeyPolicyDigest(kind, nameAlg)`. The creation-only rules — the §7.3.1
  unique string and the H-1..H-4 parameters — are not applied to a received
  public area: `TPM2_CreatePrimary` consumes the unique string as derivation
  input and returns a public area holding the generated key instead, so
  demanding it server-side would refuse every genuine device.
- **The EK certificate chain IS verified against a configured
  TPM-manufacturer truststore**, per §6.1.2 step 5b and §6.2.2 step 4b
  (`verifyEKCertificateChain`, `pkg/ca/tcg_ek_trust.go`), before
  `SignTCGCSRIDevID`, `EnrollDevice` or `VerifyTCG_CSR_IDevIDBytes` do
  anything else with the EK certificate -- including generating the
  `TPM2_MakeCredential` challenge, which only proves possession of the EK
  private key, not that the EK belongs to a genuine TPM. The trust anchors
  are `MultiIdentityCAConfig.TCGConfig.TrustAnchors`
  (`pkg/attestation/truststore.Config` -- the same shape
  `pkg/config.AttestationConfig` uses for the "tpm2" attestation format,
  reused rather than duplicated). **A CA with no anchors configured refuses
  every EK certificate with `ErrTCGEKCertUntrusted`; there is no fallback to
  residency-only proof.** This is a breaking behavior change for any
  deployment enrolling TCG-CSR-IDEVID devices: `ca.tcg-config.trust-anchors`
  (or the equivalent `CAConfig.TCGConfig`) must name at least one
  TPM-manufacturer root before enrollment will succeed.
  `requireTCGEKCertificateEKU` additionally requires the tcg-kp-EKCertificate
  extended key usage (2.23.133.8.1) or anyExtendedKeyUsage on the leaf.
  `parseEKCertificateChain` accepts intermediates the device concatenated
  after the leaf in a PEM-encoded EkCert field; `stripTCGEKQuirks` accepts
  the TCG EK Credential Profile's critical-subjectAltName-with-only-a-
  directoryName encoding without weakening any other check
  `x509.Certificate.Verify` performs.

## Error semantics

`pkg/ca/errors.go` holds the vocabulary — typed errors, never `fmt.Errorf`.
The lifecycle and validation errors named in the interface contract are
`ErrAlreadyInitialized` and `ErrInvalidConfig`; key-layer failures surface as
the keystore errors from `pkg/xkms/errors.go`
(see [`../key-management/engineering.md`](../key-management/engineering.md)).
`ErrRevocationRecordCorrupt` is the revocation readers' fail-closed error for
a persisted record that cannot be decoded (#1116, see the invariant above).
`ErrKeyRetrievalFailed` is `getOrGenerateCAKey`'s fail-closed error for a
backend `GetKey` failure that is not a genuine not-found result (#801, see
the invariant above).

Transport mapping is in `pkg/api/rest/handlers_ca.go` /
`handlers_ca_bundle.go` / `handlers_ca_tcg.go`, `pkg/api/grpc/service_ca_bundle.go`,
and `pkg/api/mcp/handlers_ca.go` / `handlers_ca_tcg.go`. `ErrCRLNotFound` maps
to `404`; `ErrNotInitialized` maps to `503`; both are declared in
`pkg/ca/errors.go` and joined into REST's `caErrorStatusMap` by
`errors.Is`, so they map correctly even wrapped in `xkms.ErrCAOperation`.

### gRPC/Unix CA wiring is per-`Service`, not a package global (go-xkms#951)

`pkg/api/grpc.Service` carries its own `ca any` and `caBundler CABundler`
fields (`service.go`), set via the instance methods `(*Service).SetCA` and
`(*Service).SetCABundler` (`service_ca.go`, `service_ca_bundle.go`) — the
same auxiliary-wiring pattern `SetSSHClient` already used. Before this fix,
`SetCA`/`SetCABundler` were package-level functions writing a single
process-wide global that no production composition root ever called, so
every CA RPC (`GetCACertificate`, `SignCSR`, `IssueCertificate`,
`RevokeCertificate`, `GenerateCRL`, `IsRevoked`, and the TCG EK/AK/enroll
variants) answered `codes.Unavailable` over `unix://`, `grpc://` and
`grpcs://` regardless of whether a CA was configured. REST was unaffected —
`pkg/api/rest`'s `Config.CA` was always per-`Server`.

Composition roots wire `SetCA`/`SetCABundler` right after `NewService`,
under the same condition `pkg/server`'s `buildRESTConfig` uses for
`restConfig.CA` (a configured CA **and** a composed `XKMSService`):

- `pkg/server`'s `startUnix` (`server.go`) forwards `s.xkmsService` as the
  CA servicer through `unix.GRPCConfig.CA`/`CABundler`, which
  `unix.NewGRPCServer.Start` passes to `(*Service).SetCA`/`SetCABundler`
  (`pkg/api/unix/grpc_server.go`).
- `pkg/apimodule.Module.keystore` (`module.go`) — the unified qrdb server's
  gRPC surface — wires the resolved `XKMSService` itself whenever
  `XKMSService.CA() != nil`, since the same object exposes both the
  transport-shaped CA methods and the `provider.CA` accessor.

A CA servicer (`x any`) is duck-typed against the transport-shaped method
sets in `service_ca.go`/`service_ca_tcg.go` (`grpcCAMethodCert`,
`grpcCAMethodSignCSR`, ...) exactly as before; only the storage location of
the configured value changed, from a package variable to a `Service` field.

Any other binary embedding `pkg/api/grpc.Service` directly (rather than
through `pkg/api/unix` or `pkg/apimodule`) must call the instance methods
`(*Service).SetCA` / `(*Service).SetCABundler` on the constructed `*Service`
before serving CA RPCs; the removed package-level `SetCA`/`GetCA`/
`SetCABundler`/`GetCABundler` have no replacement free functions.

**Fail-closed paths:** uninitialized CA; a CSR that fails policy; a revoked or
expired issuer; an attestation quote that does not verify; a TCG CSR whose
IDevID signature does not check; a TCG CSR with no EK certificate, with no
determinable TPM manufacturer code, or whose IDevID/IAK public area departs
from TCG Template H-0 or carries a foreign `authPolicy`; an EK certificate
that does not chain to a configured TPM-manufacturer trust anchor, lacks the
tcg-kp-EKCertificate extended key usage, or is presented with no trust
anchors configured at all (`ErrTCGEKCertUntrusted`). None of these fall back
to issuing.

## Configuration

CA configuration lives under the server config's CA section (`pkg/config`),
resolved into `ca.Identity` (`pkg/ca/config.go`). The settings that change
behaviour rather than naming:

- `DefaultKeyAlgorithm` / `DefaultSignatureAlgorithm` — what a request gets when
  it does not ask.
- `DefaultValidityPeriod` — days, applied when the request omits validity.
- `TCGConfig.TrustAnchors` (`MultiIdentityCAConfig.TCGConfig`, or the flat
  `CAConfig.TCGConfig`) — CA-wide, not per-identity: the
  `pkg/attestation/truststore.Config` naming the TPM-manufacturer root (and,
  concatenated into the same file, any issuing intermediate) certificates an
  endorsement key certificate must chain to before `IssueEKCertificate`'s
  sibling issuance paths (`SignTCGCSRIDevID`, `EnrollDevice`,
  `VerifyTCG_CSR_IDevIDBytes`) trust it. `NewFromMultiIdentityConfig`,
  `NewHierarchicalCA`, `NewParentCA` and `NewIntermediateCA` all carry it
  through from `Params.Config` / `MultiIdentityParams.Config` into the
  constructed `CA`; there is no separate wiring step.
- `IsAutoImportingIssuerCAs()` — whether the AIA walk runs automatically on
  import. Off means chains must be supplied.
- Multi-keystore identities — one CA name, several `{storeType, keyAlgorithm}`
  signing keys.

REST routes for the CA group are gated by the `hasCA` predicate in
`pkg/api/rest/routes.go`; when no CA is configured, only the fallback
`GET /api/v1/ca/bundle` (the `noCA` variant) is registered.

## Persistence

- Certificates and chains: `pkg/certstore` over go-objstore.
- Serial and revocation records: through `go-qrdb/sdk/go`.
- CA signing keys: the keystore backend, never a file this package writes.
- Cross-signed material is keyed by issuer CN.
- Attestation blobs are keyed by AK key attributes and blob type.

Compatibility: certificate encodings are standards-defined and stable. The
store layout is internal, and a change to it needs a data migration.

### CRL persistence (#275)

`pkg/ca/crl_persistence.go`. `ca.revocationStore` — the sole persistence
medium, the same `storage.Backend` revocation records use, so a CRL artifact replicates under Raft exactly the way the
revocation state that produced it does. No separate storage wiring or server
config exists for it.

| key | value | written by |
|---|---|---|
| `revocations/<serial-decimal>.json` | `persistedRevocation{Serial, Reason, RevokedAt, DeletedKeys}` | `recordRevocation` (`Revoke`, `RevokeCert`) |
| `crl/<issuer-ski-hex>` | `persistedCRL{DER, Number, ThisUpdate, NextUpdate}` | `generateAndPersistCRL` (`GenerateCRL`, `CRL`, and the refresh-on-revoke hook in `recordRevocation`) |

The CRL key is the issuing certificate's Subject Key Identifier, hex-encoded
— not its CN — because `crypto/x509.CreateRevocationList` requires the
issuer to have one, `x509.CreateCertificate` always populates it for a CA
template, and keying by SKI survives a CA renaming its subject and
disambiguates a root's CRL from an intermediate's when a `CA` instance holds
both.

Read path (`CA.CRL`): `certstore.compositeCertStore`'s `GetCRL` in-memory
cache first (a per-process hot path, keyed by issuer CN, warmed by
`StoreCRL` after every regeneration on that instance) → the persisted `crl/`
row → regenerate via `generateAndPersistCRL` when neither has a
not-yet-stale entry. `GenerateCRL` always calls `generateAndPersistCRL`
directly, skipping both freshness checks.

### CA reload / restart persistence (go-xkms#793)

`pkg/server`'s `initializeCA` calls `trustedCA.Load` on every start and falls
through to `trustedCA.Init` only when `errors.Is(loadErr, ca.ErrCertificateNotFound)`
— the one condition that legitimately means "this data directory has never
held a CA": the root (or the selected intermediate's) certificate record is
genuinely absent from `certStore`. Any other `Load` failure — a corrupt or
unreadable persisted certificate (`wrapCertLookupError` classifies this),
an unavailable keystore backend, a `KeyAttributes` validation defect — is
returned to the caller as `*server.ErrCAInit{Operation: "load existing CA"}`
and fails server startup closed. `Init` is never called over existing,
merely-damaged state.

Before this fix, `initializeCA` treated *any* `Load` error identically to
"never initialized", and `Load` itself resolved a root or intermediate
identity's key attributes via the bare `Identity.ToKeyAttributes` — which,
unlike `Init`'s `getCAKeyAttributes`, never defaults `KeyType` to
`KeyTypeCA`. An identity whose `KeyConfig` left `key-type` unset (or set it
under the YAML field `key_type`, which the struct tag does not bind) failed
`Load` with a `KeyAttributes.Validate` error — never a not-found — on every
restart, and `initializeCA` silently re-ran `Init`, minting a new
self-signed root certificate (new serial, new validity window; the key
itself was often reused because `getOrGenerateCAKey` is get-or-generate) on
every `xkmsd run` over the same data directory. This invalidated every
certificate issued from the previous root and every client's pin to it.

**The contract going forward:** an identity's key attributes must resolve
identically across `Init` and `Load` (`getCAKeyAttributes`, not
`ToKeyAttributes`, in both), and only `ErrCertificateNotFound` -- itself
gated on the underlying cause being `storage.ErrNotFound`, not any
`certStore.GetCertificate` failure -- authorizes `initializeCA` to
(re-)initialize.

### Issued-key persistence (#751)

`pkg/ca/ca_extensions.go`. A third sibling of `revocations/` and `crl/` in
the same `ca.revocationStore`, written once per certificate whose key the CA
itself generated or resolved:

| key | value | written by |
|---|---|---|
| `issued-keys/<serial-decimal>.json` | `persistedIssuedKey{Serial, CN, TenantID, Partition, Backend, StoreType, KeyType, KeyAlgorithm, ECCCurve, RSAKeySize}` | `recordIssuedKey` (`IssueCertificateWithProfile`, after `signCSR` succeeds) |

Why this exists: a certificate's `Subject.CommonName` and
`PublicKeyAlgorithm` are not enough to reconstruct a `types.KeyAttributes`
that `types.KeyAttributes.Validate` accepts (`StoreType` and `KeyType` are
also required) or that names the same key ID generation stored it under
(`KeyAttributes.ID`, which also folds in `Partition` and `TenantID` when
set). `RevokeCert`'s `DeleteKeys` option reads this record back
(`resolveIssuedKeyAttributes`) instead of guessing, and deletes the record
itself (`deleteIssuedKeyRecord`) once the key is gone.

`recordIssuedKey` is called only when `CertificateRequest.Signer == nil` —
i.e. `CreateCSR` generated or fetched the key through `ca.keyStore` for this
request. `SignCSR` (the caller-supplied-CSR path) never calls it, because
the CA never holds that key. `resolveIssuedKeyAttributes` returns `(nil,
nil)` — not an error — when no record exists, which is both the CSR-signed
case and a certificate issued before this recording existed;
`RevokeCert(DeleteKeys: true)` treats that as a no-op key deletion, logs it,
and still deletes the certificate from `certStore`.

A real failure at any cleanup step (`keyStore.DeleteKey`,
`deleteIssuedKeyRecord`, `certStore.DeleteCertificate`) is wrapped in a
typed error and joined with `errors.Join` into `RevokeCert`'s return rather
than discarded; the revocation record itself is already durable by the time
cleanup runs, so a cleanup failure never leaves a certificate un-revoked
(go-xkms#687, go-xkms#751). `RevokeCert` no longer calls
`keyStore.DeleteCert`: the keystore's own certificate side is never
populated for issued certificates — only `ImportCertificate` /
`ImportCertificatePEM` call `keyStore.SaveCert`, and only best-effort — so
`certStore` is the sole authoritative certificate store this method cleans
up.

## Test strategy

- **Unit** — `pkg/ca` carries the repo's densest suite: `ca_core_test.go`,
  `issuance_test.go`, `csr_test.go`, `cross_signing_test.go`, `hybrid_test.go`,
  `certpolicy_test.go`, `bundle_test.go`, `attestation_test.go`,
  `interface_contract_test.go` (the conformance test for `TrustedCA`), plus
  `multi_keystore_test.go`, `multi_keystore_pkcs11_test.go`,
  `multi_keystore_tpm2_sim_test.go`. CRL persistence:
  `crl_persistence_test.go` (round trip across independent `*CA` instances
  sharing a backend, refresh-on-revoke, regenerate-on-read past/before
  `NextUpdate` via an injected `Clock`, force-regenerate),
  `ocsp_revocationstore_test.go` (the OCSP cold-path fix),
  `revocation_cluster_test.go` (#1116: two `*CA` instances over one shared
  in-memory revocation store — a revocation on A enforced by B's
  `IsRevoked`, `Verify`, `VerifyPeerCertificate` and CRL — plus store-fault
  and corrupt-record injection proving `IsRevoked`, OCSP, CRL listing, CRL
  numbering, `Load` and `VerifyPeerCertificate` each fail closed), and
  `revoke_delete_keys_test.go` (`RevokeCert(DeleteKeys)`: server-generated
  key + certificate deleted and subsequently not found, CSR-signed no-op,
  injected keystore/revocation-store failure propagation, and the
  `recordIssuedKey`/`resolveIssuedKeyAttributes`/`deleteIssuedKeyRecord`
  helpers directly). EK chain trust:
  `tcg_ek_trust_test.go` — real generated root/intermediate/leaf chains
  covering a trusted root, a trusted configured intermediate, a
  request-supplied intermediate, an unknown root, a missing
  tcg-kp-EKCertificate EKU, an expired leaf, no anchors configured, and the
  critical-directory-name-only-SAN quirk; `tcg_iak_certstore_test.go`'s
  `enrollSoftwareDevice` fixture configures a trust anchor per test so the
  full `SignTCGCSRIDevID` path exercises the real check rather than a mock.
  CA reload persistence (go-xkms#793): `ca_reload_793_test.go` — `Load`
  succeeds over the same durable state `Init` wrote when the identity's
  `KeyConfig` never set `key-type`, an uninitialized store fails `Load` with
  `ErrCertificateNotFound`, and a corrupt persisted root certificate fails
  `Load` with a distinct error that does not satisfy
  `errors.Is(_, ErrCertificateNotFound)`.
- **End to end** — `pkg/ca/issuance_e2e_test.go`,
  `pkg/api/rest/init_ceremony_e2e_test.go`.
- **Integration** — `test/integration/certstore`, `test/integration/acme-tpm`,
  `test/integration/cluster` (CA key custody across nodes). `pkg/server`
  carries the `initializeCA` end of the go-xkms#793 contract over the
  embedded qrdb storage backend: `server_ca_reload_793_test.go` —
  `TestInitializeCA_QRDB_ReloadsPersistedCAAcrossRestarts` (a second `New()`
  over the same data directory loads the persisted CA -- same serial, same
  SPKI -- instead of re-initializing) and
  `TestInitializeCA_QRDB_CorruptPersistedCertificateFailsClosed` (a damaged
  persisted certificate fails startup with `*server.ErrCAInit` instead of
  being silently replaced).
- **Parity** — `CommandDefinition` entries exist for `ca-bundle`,
  `ca-certificate`, `ca-crl`, `ca-issue`, `ca-revoke`, `ca-sign-csr`,
  `ca-status`, `cert-info`, `cert-list`, `tls-cert`.

## Observability

Issuance and revocation emit audit records through `pkg/audit`
(see [`../audit-log/`](../audit-log/engineering.md)); every request carries a
correlation ID. Certificate lifetimes and CRL generation are exposed through
`pkg/metrics`.
