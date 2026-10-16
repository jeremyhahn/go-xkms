# Certificate Authority — Engineering Contract

> **Status: NORMATIVE** · Feature: `certificate-authority` · Repo: `go-xkms` · Last verified: 2026-10-12

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
The RFC 5280 reason codes for `reason` and `RevokeOptions` are exported from
`sdk/go` as `CARevocationReasonUnspecified`, `…KeyCompromise`, `…CACompromise`,
`…AffiliationChanged`, `…Superseded` (4), `…CessationOfOperation`,
`…CertificateHold`, `…RemoveFromCRL`, `…PrivilegeWithdrawn`, `…AACompromise`.
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
Both methods fetch through `fetchPKIObject` (`pkg/ca/pki_fetch.go:112`)
under fixed limits: http and https only, destinations `pkg/netguard.ReservedAddr`
does not refuse only (checked at dial time, after DNS resolution, by the
`pkg/netguard.GuardedTransport` dialer both this client and the ACME
challenge-validation client build on — see
[`../acme-issuance/engineering.md`](../acme-issuance/engineering.md)), at
most 3 redirects, a 30-second timeout, and a body cap of 64 KiB for a
certificate or 32 MiB for a CRL (`pki_fetch.go:31-49`). `ImportIssuingCAs`
also requires each fetched issuer to verify the child's signature and stops
a walk that repeats a certificate or climbs more than 5 issuers
(`trust_chain_extensions.go:278-328`). None of the limits is configurable.

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

**Local Attestation Key (LAK) certificates** (`tcg_lak.go`) — go-xkms#715.
TCG DevID v1 r12/v1.10 r9 §8 requires the IAK certificate's Subject to be a
unique X.500 DN; WebAuthn Level 2 §8.3.1 requires the "tpm" attestation
statement's AIK certificate Subject to be empty, and go-webauthn enforces
this literally (`aikCert.Subject.String() != ""`). Rather than compromise
either spec, `IssueLAKCertificate(ctx, request, evidence)` issues a *second*
attestation key certificate, over a Local Attestation Key the device creates
separately (`pkg/tpm2.(*TPM2).CreateLAK`) and the IAK certifies via
`TPM2_Certify`, per TCG "TPM 2.0 Keys for Device Identity and Attestation"
v1.10 r9 §5.3/§6.3 ("Owner Creation of a LAK Certificate based on an IAK
Certificate"). The IAK's own certificate is unchanged.

- `LAKCertificationEvidence` carries the TPM2_Certify evidence: `CertifyInfo`,
  `Signature` (the ordinary X.509-form signature, not a marshalled
  `TPMT_SIGNATURE`), `SignatureAlgorithm`, the device's `IAKCertificate`,
  `LAKPublicArea` and the `Nonce` the evidence must echo.
- Before issuing, `IssueLAKCertificate` verifies (a) `evidence.IAKCertificate`
  chains to the certificate about to sign the LAK — `resolveTCGSigner`'s
  `signingCert`, this CA's own issuing certificate or the tenant's issuer
  certificate in multi-tenant mode — and is within its validity period
  (`verifyIAKTrustedForLAK`; revocation is deliberately not checked here, the
  same as every other TCG issuance path in this file), and (b) the
  TPM2_Certify evidence itself via `tpm2.VerifyCertifyByCertificate`, which
  requires the IAK certificate to carry `tcg-kp-AIKCertificate`
  (2.23.133.8.3), the signature over `CertifyInfo` to verify under the IAK's
  certified public key, `TPM_GENERATED_VALUE`, a Certify (not Quote)
  attestation, and a certified Name matching `LAKPublicArea`.
- The issued certificate follows `ca.NewTCGLocalAttestationKeyProfile`
  (`profiles.go`): an empty Subject; `CertificateSpec.DirectoryNames` carries
  a critical subjectAltName directoryName with `request.TPMManufacturer`,
  `TPMModel` and `TPMFirmwareVersion` under tcg-at-tpmManufacturer/tpmModel/
  tpmVersion (criticality follows automatically from the empty Subject —
  `BuildSubjectAltName`); Extended Key Usage is `tcg-kp-AIKCertificate` alone,
  deliberately without the TLS ClientAuth/ServerAuth purposes or the
  tcg-cap-verifiedTPM\* certificate policies the IAK/AK profiles carry — this
  is not a TCG DevID credential and asserts no purpose it does not have; Basic
  Constraints CA:false.
- A certificate with no Subject has no Common Name, so it cannot be stored the
  way every other certificate in this package is. `certstore.CertificateKey`
  keys it by its SPKI SHA-256 thumbprint instead (`qrdbsdk.ComputeSPKIThumbprint`
  — qrdb's own canonical mTLS binding identifier, applied here rather than
  reimplemented); `compositeCertStore.StoreCertificate`/`StoreCertificateChain`
  apply this uniformly, not only to the LAK.
- `pkg/tpm2` supplies the device-side half: `CreateLAK` builds the LAK as a
  Restricted, Sign-only child of the Platform SRK (not an Endorsement-hierarchy
  primary like the IAK/IDevID); `CertifyLAK` produces the IAK-over-LAK
  TPM2_Certify evidence this method verifies; `CertifyKeyWithLAK` is what
  xkey's TPM-backed WebAuthn/FIDO2 authenticator then uses to certify each
  credential key under the LAK, never the IAK. See
  [`../tpm2/engineering.md`](../tpm2/engineering.md) for the TPM-side
  invariants.

Constructors are `pkg/ca/constructors.go`; configuration types are
`pkg/ca/config.go` (`Identity`, and the CA config it hangs off).

### Canonical issuance — the `Issuer` seam (`pkg/ca/issuance.go`)

Every X.509 certificate go-xkms signs goes through one seam.
`Issuer.Sign` (`issuance.go:331`) holds the only `x509.CreateCertificate`
call in `pkg/ca` (`issuance.go:348`); `Issue` (`issuance.go:297`) is
`Template` + `Sign` + parse.

- `Issuer` (`issuance.go:47`) is who signs: `Signer`, `Certificate` (nil means
  self-signed — a root, including a per-tenant root) and `Identity` (the
  CRL/OCSP/AIA endpoints; nil means none).
- `CertificateSpec` (`issuance.go:77`) is what the caller owns: serial,
  subject (`Subject` or `RawSubject`), validity, `PublicKey` (nil certifies the
  issuer's own key), `SignatureAlgorithm`, the names (`DNSNames`,
  `EmailAddresses`, `IPAddresses`, `URIs`, `SANS`, `OtherNames`,
  `DirectoryNames`), `ExtraExtensions`, `NameConstraints`, the originating
  `Request`, and the required `Profile`. It has no key-usage, EKU or
  basic-constraints fields on purpose (`issuance.go:71-76`): those belong to
  the profile, applied by `profile.Apply` inside `Template`
  (`issuance.go:377`). A spec with no profile is refused
  (`issuance.go:178`).
- Callers that must sign the same template twice use `Template` once and
  `Sign` twice. ACME issuance lint-signs and signs the precertificate, then
  the final certificate (`pkg/acme/issuance/issuance.go:205`, `:220`,
  `:275`, `:282`). Hybrid issuance builds an `Issuer` over the classical key
  (`pkg/ca/hybrid.go:146`) and signs twice (`hybrid.go:150`, `:177`).
- Regression guard: `testutil.PolicyFingerprint`
  (`pkg/testutil/certpolicy.go:148`) reduces a certificate to its policy
  fields, and the `TestCertificatePolicy_*` suites
  (`pkg/ca/certpolicy_test.go`, `pkg/acme/issuance/certpolicy_test.go`,
  `pkg/acme/admin/certpolicy_test.go`) assert every issuance path and
  endpoint lands on the seam, that a profile change reaches each path, that
  a spec without a profile is refused, and that an incomplete `Issuer` is
  refused.

### Built-in profiles

`NewDefaultProfileRegistry` (`profiles.go:55`, filled by
`registerBuiltinProfiles` at `profiles.go:67`) registers, keyed by lowercase
name: `server`, `client`, `code-signing`, `email`, `ocsp-responder`,
`timestamping`, `ca` (`ProfileNameCA`, `profiles.go:398`), `acme-leaf`
(`ProfileNameACMELeaf`, `profiles.go:453`), the TCG set `tcg-ek`, `tcg-ak`,
`tcg-iak`, `tcg-idevid`, `tcg-lak` (`profiles.go:506-510`),
`fido2-attestation` (`profile_fido2.go:42`), `dice-idevid`
(`profile_dice.go:38`), `ipsec-vtep` and `x509-svid`
(`profile_ipsec_svid.go:35`, `:38`).

A CA's registry is `(*CA).Profiles()` (`ca_extensions.go:340`).
`ProfileRegistry.Register(name, profile)` (`interface.go:820`, implemented at
`profiles.go:101`) adds or replaces a profile; `NewProfileBuilder`
(`profiles.go:743`) with `WithKeyUsage`, `AsCA` and `Build` composes one.

**FIDO2 attestation profile.** `NewFIDO2AttestationProfile(permitted ...[16]byte)`
(`profile_fido2.go:136`) issues WebAuthn §8.2.1 packed-attestation
certificates: digitalSignature, no EKU, basic constraints present with cA
false; subject C and O from the CA, OU `Authenticator Attestation`, CN from
the request; the AAGUID extension non-critical. The AAGUID must be on the
allowlist, which with no arguments is `XKeyAAGUID` alone
(`profile_fido2.go:71`); anything else is
`ErrFIDO2AttestationAAGUIDNotPermitted` (`errors.go:455`).

**Code-signing profile.** `code-signing` (`ProfileNameCodeSigning`,
`NewCodeSigningProfile` at `profile_codesigning.go:79`) validates the CSR
rather than reshaping it: a request that breaks a rule is refused with that
rule's error, and no field is ever dropped silently. It issues cA false
(basic constraints asserted), digitalSignature, EKU codeSigning, a subject of
exactly one RDN holding one non-empty CN, and no SANs; 365 days by default and
460 days at most (CA/B Forum CS BR §6.3.2).

| The CSR (or the issuing call) | Is refused with |
|---|---|
| has a subject other than a single CN, or an empty CN | `ErrSubjectNotCommonNameOnly` |
| requests subjectAltName, or `SignOptions.SANS` adds names | `ErrSubjectAltNameNotPermitted` |
| requests BasicConstraints with cA true | `ErrCARequestNotPermitted` |
| requests a KeyUsage other than digitalSignature alone | `ErrKeyUsageNotPermitted` |
| requests an ExtKeyUsage other than codeSigning alone | `ErrExtKeyUsageNotPermitted` |
| asks for a lifetime above 460 days | `ErrValidityExceedsProfile` (refused, never clamped) |

The checks run through the optional `CSRValidator` contract
(`ValidateCSR(csr *x509.CertificateRequest) error`,
`profile_contracts.go:68`), which `CA.SignCSR` calls before it resolves the
lifetime or builds the template (`ca.go:1786`).

**Key binding.** `SignOptions.BoundKey *types.KeyAttributes` (`types.go:507`)
names a key in the CA's keystore, under any profile. The CSR is refused unless
its public key is that key's public key, compared as marshalled SPKI
(`ca.go:1904`): a key the keystore does not hold is `ErrBoundKeyNotFound`, a
different key `ErrBoundKeyMismatch`, and a CA built without a keystore
`ErrKeyStoreRequired`. The SDK re-exports these as
`xkms.ProfileNameCodeSigning`, `xkms.CSRValidator`,
`xkms.TrustedCASignOptions` and `xkms.ErrCA*`:

```go
cert, err := trustedCA.SignCSR(ctx, csrPEM, &xkms.TrustedCASignOptions{
    Profile:  xkms.ProfileNameCodeSigning,
    BoundKey: attrs, // *xkms.KeyAttributes of the signing key
})
if errors.Is(err, xkms.ErrCABoundKeyMismatch) {
    // the CSR was not made over the named key
}
```

### TCG naming and defaults

- An IAK certificate's CN is `IAKCommonName(model, serial)` →
  `iak-<model>-<serial>` (`tcg.go:297`); `IAKCertificateReader`
  (`interface.go:848`) reads one back. The SDK re-exports both
  (`sdk/go/acme/ca.go:44`, `:126`).
- TCG device certificates carry NotAfter `99991231235959Z`, the RFC 5280
  "no well-defined expiration" value (`tcg.go:47`), and NotBefore one minute
  in the past to absorb clock skew (`tcg.go:187`, `tcg_lak.go:175`).
- Private extensions under the arc 1.3.6.1.4.1.29377.101
  (`tcg_oids.go:120-136`): `tp-issuerKeyStore` (.1), `tp-keyStore` (.2),
  `tp-fips140` (.3), `tp-tenantID` (.20), `tp-networkZone` (.21); built by
  `CreateTPIssuerKeyStoreExtension`, `CreateTPKeyStoreExtension` and
  `CreateTPFIPS140Extension` (`tcg_oids.go:314`, `:300`, `:327`).
  `CreateTPMSpecificationExtension` (`tcg_oids.go:200`) encodes the TCG TPM
  specification attribute.
- Hybrid (classical + post-quantum) certificates carry
  `OIDQuantumAlgorithm` (…29377.101.10) and `OIDQuantumSignature`
  (…29377.101.11) (`tcg_oids.go:125-126`).

### Revocation, OCSP and TLS helpers

- `VerifyAgainstCRL(cert, crlDER) (bool, error)` (`revocation.go:412`,
  SDK alias `sdk/go/ca.go:554`) checks one certificate against a DER CRL the
  caller already holds.
- `OCSPResponderConfig` (`ocsp.go:71`): `CacheTTL`, `NextUpdate` (default 7
  days) and `MaxCacheEntries`, which bounds the response cache because a
  request may name any serial (go-xkms#1263). Zero fields take
  `DefaultOCSPResponderConfig()`.
- `TLSBundle`, `TLSBundleWithCrossSigner` and `TLSConfigWithXSigner`
  (`tls_extensions.go:44`, `:99`, `:140`) build TLS material from the CA,
  with or without a cross-signer.

### Overlay identity surface (`pkg/ca`)

| Symbol | Purpose |
|---|---|
| `ProfileNameIPsecVTEP`, `NewIPsecVTEPProfile` | IKEv2 endpoint profile: `id-kp-ipsecIKE` (`OIDIPsecIKE`, 1.3.6.1.5.5.7.3.17) as the only EKU, digitalSignature, cA false; ECDSA P-256/P-384 or RSA ≥ 3072 |
| `ProfileNameX509SVID`, `NewX509SVIDProfile` | SPIFFE X.509-SVID leaf: serverAuth + clientAuth, digitalSignature (+ keyEncipherment for RSA), cA false; ECDSA P-256/P-384/P-521, RSA ≥ 2048, Ed25519 |
| `NameConstraints` | RFC 5280 name constraints; `Validate` refuses nil or host-bit ranges and malformed domains |
| `SubordinateCARequest`, `SubordinateIssuer`, `(*CA).IssueSubordinateCA` | certify a caller-held key as a name-constrained CA (pathLen 0 unless `AllowSubordinates`; default lifetime `DefaultSubordinateLifetime`, never past the issuer) |
| `CertificateSpec.NameConstraints` | constraints for `Issuer.Issue`; refused on a non-CA template |
| `SignOptions.Validity` | lifetime as a duration; overrides `ValidityDays` |
| `CallerSANProfile`, `LifetimeBoundedProfile`, `TemplateValidator` | optional profile contracts |
| `AttestationEvidence`, `OIDAttestationEvidence`, `CreateAttestationEvidenceExtension`, `ParseAttestationEvidenceExtension` | the `tp-attestationEvidence` extension |

`TrustedCA` is unchanged: `IssueSubordinateCA` lives on `*CA` behind the separate
`SubordinateIssuer` interface, so existing `TrustedCA` implementations keep
compiling. Assert `trustedCA.(ca.SubordinateIssuer)`.

The extension, OID 1.3.6.1.4.1.29377.101.23 (non-critical):

```asn1
AttestationEvidence ::= SEQUENCE {
    verdictID           UTF8String,
    pcrDigestAlgorithm  OBJECT IDENTIFIER,  -- id-sha256 | id-sha384 | id-sha512
    pcrDigest           OCTET STRING,       -- length matches the algorithm
    attestedAt          GeneralizedTime     -- UTC, one-second precision
}
```

Overlay-profile invariants:

- Under a `CallerSANProfile`, the CSR's subject and names never reach the
  certificate. Every caller-supplied name must parse (`ErrInvalidSAN`); none
  at all is `ErrCallerSANsRequired`.
- `SPIFFETrustDomain`, `SPIFFEKind` or `SPIFFEName` with a caller-named profile
  is `ErrTenantSPIFFEWithCallerSANs`. `TenantID` alone is accepted: it only
  records which tenant may revoke the certificate.
- A caller-named certificate with an empty CommonName (an SVID may have no
  subject) is not written to the CN-keyed certificate store. It stays
  revocable, because `RevokeCert` takes the certificate and its tenant is
  recorded by serial.
- A lifetime above a `LifetimeBoundedProfile`'s maximum is
  `ErrValidityExceedsProfile`. It is never clamped.
- `Issuer.Template` refuses any leaf whose names violate the issuer's name
  constraints (`ErrNameConstraintViolation`), and runs the profile's
  `ValidateTemplate` last, after extra extensions are attached.
- `ipsec-vtep` refuses a duplicate or undecodable evidence extension
  (`ErrInvalidAttestationEvidence`).
- A relying party verifying an `ipsec-vtep` certificate with `crypto/x509` must
  pass `ExtKeyUsageAny`; Go's default EKU check requires serverAuth.

## Exported surface — `pkg/spiffe` (re-exported by `sdk/go/spiffe`)

| Name | Contract |
|---|---|
| `ParseTrustDomain(name) (TrustDomain, error)` | bare name only; `[a-z0-9._-]`, at most 255 bytes |
| `TrustDomain.ID(segments...)`, `TrustDomain.IDFromPath(path)` | build `spiffe://<td>/<path>`; each segment non-empty, not `.`/`..`, `[A-Za-z0-9._-]`; a segment carrying `/` is refused, never split |
| `ParseWorkloadID(s)`, `WorkloadIDFromURL(u)` | validate a SPIFFE ID; no user info, port, query, fragment, trailing `/`; at most 2048 bytes |
| `WorkloadID.TrustDomain`, `.Path`, `.String`, `.URL`, `.IsZero` | accessors; `URL()` is ready for a template's `URIs` |
| `WorkloadID.MemberOf(td)` | trust-domain membership |
| `WorkloadID.HasPathPrefix(prefix)` | whole-segment prefix match; `"/"` admits everything; an invalid prefix admits nothing |
| `ValidatePath`, `ValidatePathPrefix` | the path and prefix rules above |
| `InvalidIDError{Input, Err}` | wraps one sentinel: `ErrTrustDomainEmpty`, `ErrTrustDomainCharacters`, `ErrTrustDomainTooLong`, `ErrSchemeInvalid`, `ErrSegmentEmpty`, `ErrSegmentDotted`, `ErrSegmentCharacters`, `ErrIDTooLong`, `ErrIDComponents`, `ErrPathPrefixInvalid` |
| `ID`, `BuildURI`, `ParseID`, `TenantFromURIs`, `KindUser`, `KindService` | the tenant-scoped shape, unchanged |

The tenant-scoped shape keeps its own, looser name rules: usernames such as
e-mail addresses are valid tenant names and are not SPIFFE path segments.

## Invariants

- **Certificate storage is confined to the caller's tenant** (go-xkms#1228).
  The `XKMSService` certificate methods resolve the backend with
  `resolveTenantBackend` (`pkg/xkms/servicer_cert.go:29-284`), so a tenant's
  certificates live under `{tenant}/{keyID}` (`pkg/xkms/backend_tenant.go:58`)
  and its listing is filtered to that prefix
  (`pkg/xkms/backend_tenant.go:162`). REST, gRPC and MCP call these methods and
  nothing else; none may reach the certificate store through an unscoped
  backend. A key ID is validated before use and `/` is refused, so no ID
  crosses a namespace. Another owner's certificate must answer exactly as a
  missing one; the cross-tenant tests compare the two responses byte for byte
  (`pkg/api/rest/handlers_certseal_crosstenant_test.go`,
  `pkg/api/grpc/service_certseal_crosstenant_test.go`,
  `pkg/api/mcp/handlers_certseal_crosstenant_test.go`).
- **A CA-issued certificate's revoke is confined to its issuing tenant**
  (go-xkms#1229). `signCSR` (`pkg/ca/ca.go`) — the single issuance site
  shared by `SignCSR`/`SignCSRWithSPIFFE` and
  `IssueCertificate`/`IssueCertificateWithProfile` — records the tenant the
  certificate was issued for (`""` for the system/platform scope) against
  its serial via `recordCertTenant`, in the same `revocationStore` as
  `recordIssuedKey` (`pkg/ca/ca_extensions.go`, `cert-tenant/<serial-decimal
  >.json`). `XKMSService.RevokeCertificate` (`pkg/xkms/servicer_ca.go`)
  reads it back with `CertificateTenant` and runs it through the same
  `bindTenantTarget` (`pkg/xkms/tenant_binding.go:88`) every other
  tenant-scoped operation uses: every caller may revoke only its own
  tenant's certificates — a system-tenant caller only the system/platform
  scope's own (`""`), never a tenant's (go-xkms#1406). `IssueCertificate` binds `req.TenantID`
  the same way before forwarding it, so a tenant-scoped caller cannot mint
  a certificate attributed to a different tenant either. A certificate
  issued through a path that never calls `signCSR` — the TCG device-identity
  family (EK/AK/IDevID) and the CA's own root/intermediate certificates —
  carries no record and so resolves to the system/platform scope, reachable
  only by a system-tenant caller. `certs:revoke` (and `certs:generate`) is
  the same permission on every transport (REST, gRPC, MCP); go-qrdb's
  built-in Admin role grants it by default in every tenant it is seeded
  into, including the system tenant, so both a system admin and a tenant
  admin hold it without any xkms-side default-grant registration.
- **A malformed certificate is a request fault.** `certFromPEM`
  (`pkg/xkms/servicer_cert.go:340`) returns `ErrInvalidEncodingPEM` (via
  `ErrPEMBlock` for a wrong block type) or `ErrCertificateParse`, which matches
  `ErrInvalidCertificate` (`pkg/xkms/errors.go:169`, `:775`); every transport
  maps both to its invalid-argument code.
- **`Init` is once.** A second `Init` returns `ErrAlreadyInitialized` rather
  than replacing the root. `Load` is the idempotent startup path.
- **`Load` resolves every identity's key attributes through the same
  `getCAKeyAttributes` default-filling `Init` uses**, never the bare
  `Identity.ToKeyAttributes`. An identity's `KeyConfig` that leaves key-type
  unset still stores and loads under the same `KeyTypeCA`-defaulted
  attributes on every call; the two paths must never diverge (go-xkms#793).
  See "CA reload / restart persistence" under Persistence.
- **Only the certificate store's DAO reporting the entity not found
  (`qrdbsdk.IsDAONotFound`) becomes `ErrCertificateNotFound`.** A
  `certStore.GetCertificate` failure for any other reason (a corrupt or
  undecodable persisted record, a datastore failure) is returned as a distinct error that does not satisfy
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
The chain importer's refusals are `ErrPKIFetchRefused` (scheme, destination
address or redirect count), `ErrPKIFetchTooLarge` (body over the cap),
`ErrAIAIssuerSignatureInvalid`, `ErrAIALoop` and `ErrAIADepthExceeded`
(`pkg/ca/errors.go:183-205`). A download that fails for any other reason,
including a non-200 status, stays `ErrStorageError`.

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
  signing keys. See "Multi-keystore routing" below.

### Multi-keystore routing

Each key in an identity's `Keys` names its own store type, so one CA can sign
with a software key, a TPM key and an HSM key at once.

- The constructor takes a `BackendForStore`
  (`BackendForStoreFunc func(cn string, storeType types.StoreType) (xkms.Backend, error)`,
  `constructors.go:74`). It is required: without it construction fails with
  `ErrBackendForStoreRequired` (`errors.go:173`; checked at `ca.go:223` and
  `ca.go:676`).
- `buildKeystoreMap` (`ca.go:1272`) calls the factory once per distinct store
  type across the identity's keys and keeps the result in `keystoreMap`
  (`ca.go:267`). An empty store type means `types.StoreSoftware`
  (`ca.go:1290-1291`); a factory that returns a nil backend is
  `ErrKeyStoreRequired` (`ca.go:1301-1302`); a factory error is wrapped and
  fails construction.
- `resolveKeyBackend` (`ca.go:1260`) picks a key's backend by store type and
  answers `ErrKeyStoreRequired` for a store type with no backend.
- Only `Keys[0]` is bound to the CA certificate. The other keys are generated
  ahead of use by `initSecondaryKeys` (`ca.go:1312-1318`). A secondary-key
  failure does not fail `Init`; it is kept (`ca.go:782`) and readable from
  `(*CA).SecondaryKeyInitError()` (`ca.go:738`).
- Per-store settings sit under the identity's `keystores` block
  (`Identity.Keystores`, `config.go:109`; `CAKeystoresConfig`,
  `config.go:165`):

  | Key | Type | Source |
  |---|---|---|
  | `keystores.software.password` | secret reference | `config.go:136` |
  | `keystores.tpm2.srk-handle` | uint32, e.g. `0x81000001` | `config.go:145` |
  | `keystores.tpm2.srk-auth` | KMS URI resolving to the SRK auth | `config.go:148` |
  | `keystores.pkcs11.pin` | secret reference | `config.go:157` |
  | `keystores.pkcs11.slot` | int | `config.go:158` |
  | `keystores.pkcs11.module` | module path | `config.go:159` |

  `password` and `pin` are `*types.SecretValue`: a reference string in YAML,
  sealed in memory once resolved. A key's own `KeyConfig.Password` wins; the
  software keystore password is the fallback for keys that set none
  (`config.go:587`, applied at `config.go:605-606`).
- The SDK re-exports the config and factory types as
  `TrustedCAKeystoresConfig` and `TrustedCABackendForStoreFunc`
  (`sdk/go/ca.go:300`, `:319`).

### CA-backed server TLS

With `tls.enabled` and `tls.server_cn` set (`pkg/config/config.go:391`),
xkmsd issues its own TLS server certificate from its CA at boot
(`ensureTLSServerCert`, `pkg/server/server.go:2154`), adding
`tls.extra_sans` (`config.go:396`). Without `tls.ca_file`
(`config.go:386`) the bootstrap bundle is served from the CA itself
(`server.go:2396-2397`); with it, from that file (`tlsCABundler`,
`pkg/server/ca_bundler.go:26`). The key list is in
[`../xkmsd-configuration/engineering.md`](../xkmsd-configuration/engineering.md).

### SignCSR attestation gate

A `SignCSR` request that names an `attestation_format`
(`pkg/api/transport/types.go:1472`; `tpm2` or `yubikey-piv`) is checked
before signing (`pkg/xkms/servicer_ca.go:161`). With no attestation trust
anchors configured at all it fails with `ErrAttestationNotConfigured`, and
with none for the named format with `ErrAttestationFormatNotConfigured`
(`servicer_ca.go:50`, `:55`; returned at `:319`, `:323`). Neither falls back
to unattested issuance. See
[`../attestation-verifier/engineering.md`](../attestation-verifier/engineering.md).

REST routes for the CA group are gated by the `hasCA` predicate in
`pkg/api/rest/routes.go`; when no CA is configured, only the fallback
`GET /api/v1/ca/bundle` (the `noCA` variant) is registered.

## Persistence

- Certificates and chains: `pkg/certstore`, as go-qrdb DAO entities in the
  CA's own database, `certstore.DatabaseName` (`ca`). `certificates` holds
  one certificate's DER per `certstore.CertificateKey` (the Common Name, or
  the SPKI SHA-256 thumbprint of a subject-less certificate);
  `certificate_chains` holds a chain's DER, leaf first, under its leaf's
  key. Both are looked up by that natural key. `certstore.New` takes the DAO
  factory in `certstore.Config.DAOs` and refuses a factory that does not
  serve the database (`*dao.DatabaseUnavailableError`). A miss is a
  `*certstore.NotFoundError` that matches `ErrCertNotFound` /
  `ErrChainNotFound` and wraps the DAO's typed not-found error; any other
  failure is a `*certstore.StoreError` naming the operation.
- Serial and revocation records: through `go-qrdb/sdk/go`.
- CA signing keys: the keystore backend, never a file this package writes.
- Blobs — cross-signed certificates (`cross-signed/<issuer CN>/<subject CN>.pem`),
  distribution-point CRLs (`crls/distribution/<sha256(url)>.crl`) and
  attestation evidence (`attestation/...`, keyed by AK key attributes and
  blob type): the go-qrdb storage engine in `Params.ObjectStore`
  (`qrdbsdk.Storage`, `pkg/ca/ca.go:144`), whose backend is chosen by
  configuration. go-xkms never imports go-objstore. Layout and errors:
  `docs/datastore/engineering.md`, "CA blob storage".

The composition root opens the `ca` database and hands its factory to
`compose.BuildCA` (`CAParams.DAOs`): `xkmsd` through the shared datastore
(`pkg/server` `initializeCA`), a module host through `compose.Databases`,
and the `xkmsd init` ceremony's bootstrap CA through an in-memory factory.

Compatibility: certificate encodings are standards-defined and stable. The
store layout is internal. The move from the file/KV certificate adapter to
DAO entities carried no migration: certificates stored the old way are not
read.

### CRL persistence (#275)

`pkg/ca/crl_persistence.go`. `ca.revocationStore` — the sole persistence
medium, the same `storage.Backend` revocation records use, so a CRL artifact replicates under Raft exactly the way the
revocation state that produced it does. No separate storage wiring or server
config exists for it.

| key | value | written by |
|---|---|---|
| `revocations/<serial-decimal>.json` | `persistedRevocation{Serial, Reason, RevokedAt, DeletedKeys}` | `recordRevocation` (`Revoke`, `RevokeCert`) |
| `crl/<issuer-ski-hex>` | `persistedCRL{DER, Number, ThisUpdate, NextUpdate}` | `generateAndPersistCRL` (`GenerateCRL`, `CRL`, and the refresh-on-revoke hook in `recordRevocation`) |
| `cert-tenant/<serial-decimal>.json` | `persistedCertTenant{Serial, TenantID}` | `recordCertTenant`, called from `signCSR` after `certStore.StoreCertificate` succeeds (go-xkms#1229) |

`recordRevocation` (`pkg/ca/ca_extensions.go:745`) persists before it
caches (go-xkms#1131): it checks for a duplicate via `lookupRevocation` --
the map, then the store, failing closed on a store read fault -- then
writes the record with `putRevocationBlobIfAbsent`
(`pkg/ca/ca_extensions.go:830`), and only caches the in-memory entry
(`cacheRevocation`) once that write actually lands. A store write failure
returns a typed `*errs.Joined` wrapping `ErrStorageError` and the
underlying cause, and leaves the map untouched, so a caller can retry
once the store recovers rather than have the retry rejected as a
duplicate of a write that never persisted. The write uses `PutIfAbsent`,
`storage.Backend`'s unconditional create-if-absent primitive (not the
optional `CompareAndSwapper`/`CompareAndDeleter` capabilities) --
replicated backends (every `go-qrdb`-backed `Backend` this package runs
against) make it a linearizable cross-node compare-and-swap keyed on "no
record exists yet" (`pkg/storage/qrdb/backend_putifabsent.go:53`), so two
nodes racing to revoke the same serial can both attempt the write but
only one succeeds; the loser observes `stored=false` and returns
`ErrAlreadyRevoked` wrapped in `*errs.Detail` naming the winner's
original reason and time (`alreadyRevokedError`,
`pkg/ca/ca_extensions.go:814`), read back through the same
`lookupRevocation` path, instead of silently overwriting it.

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
gated on the underlying cause being the DAO's typed not-found, not any
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

### Hardware certificate storage — `pkg/storage/hardware`

A PKCS#11 token or a TPM can hold certificates as well as keys.
`HardwareCertStorage` (`pkg/storage/hardware/interface.go:26`) is the
contract for that: the certificate and chain record methods, plus
`GetCapacity`, `SupportsChains`, `IsHardwareBacked` and `Compact`.

**Modes.** `CertStorageMode` is `external` (the default), `hardware` or
`hybrid` (`interface.go:92`). The PKCS#11 backend applies a mode through
`CreateCertificateStorage` (`pkg/backend/pkcs11/cert_config.go:78`, build tag
`pkcs11`):

- `external` returns the caller's `storage.Backend` unchanged.
- `hardware` wraps the token store in a `HardwareBackendAdapter`.
- `hybrid` wraps a `HybridCertStorage` of the token and the external backend.

`Validate` requires an external backend for `external` and `hybrid`, and
`EnableHardwareStorage` for `hardware` and `hybrid` (`cert_config.go:45`).
On a YubiKey PIV token the store elevates to the SO session, authenticated
with the management key, for deletes (`cert_config.go:130`). The errors are
`ErrSOSessionRequired` when no SO PIN is set and
`ErrDeleteNotSupportedOnToken` when the token ignores `C_DestroyObject`
(`errors.go:94`, `:86`). No TPM2 backend constructor applies a mode. The TPM
store is built directly with `NewTPM2CertStorage`, and `pkg/pivcert/tpm2`
wraps any `HardwareCertStorage` (`pkg/pivcert/tpm2/tpm2.go:157`).

**Hybrid behavior** (`hybrid_cert_storage.go`):

- `SaveCert` writes to hardware first (`:369`). It falls back to external
  storage only on a capacity or hardware error (`IsCapacityError`,
  `IsHardwareError`, `errors.go:99`, `:107`); any other hardware error is
  returned as is.
- `GetCert` falls back to external storage on not-found or a hardware error
  (`:418`).
- `ListCerts` merges and deduplicates the IDs from both sides, and fails only
  when both sides fail (`:618`).
- Deletes go to both sides. A delete reports `storage.ErrNotFound` only when
  neither side held the record, and reports a failure from either side
  (`combineDeleteResults`, `:482`).

**Records per ID.** A certificate and its chain share an ID but are separate
records, each with its own delete. `HardwareBackendAdapter` routes
`certs/{id}-chain.pem` to `DeleteCertChain` and `certs/{id}.pem` to
`DeleteCert`, and refuses any other key shape (`backend_adapter.go:159`). On
PKCS#11, chain members are objects with `CKA_ID = <id>-chain-<n>`
(`chain_member.go:18`). An ID shaped `<id>-chain` or `<id>-chain-<n>` is
refused as a certificate ID on every store with `ErrIDReservedForChain`
(`errors.go:49`; `chain_member.go:60`). The adapter implements `PutIfAbsent`
(`backend_adapter_putifabsent.go:32`) but not `storage.CompareAndDeleter`. A
token or NV index has other writers, so a guard checked in this process would
not be checked where the hardware's writes serialize. A test pins this
(`backend_adapter_record_scope_test.go:36`).

**TPM2 NV layout** (`tpm2_cert_storage.go`):

- Each ID has its own NV index: the base (default `0x01800000`) plus an
  xxhash64 of the ID modulo `0x00400000` (`:565`, `:46`).
- A base outside `0x01000000`–`0x01BFFFFF` is refused (`:145`).
- Each record is `"XKC1"`, a big-endian 16-bit ID length, the ID, then the
  PEM payload (`:74`). Storing the ID is what lets `ListCerts` return IDs
  that `GetCert` accepts.
- The index holds whichever of `SaveCert` and `SaveCertChain` wrote last.
  Chain blocks carry the PEM header `Record: chain` (`:614`), and each method
  treats a record of the other kind as absent (`interface.go:35`).
- `Compact` returns `ErrNotSupported` (`:559`).
- Every operation holds one mutex, reads included, because the TPM transport
  carries one command at a time (`:56`).

## Test strategy

- **Unit** — `pkg/ca` carries the repo's densest suite: `ca_core_test.go`,
  `issuance_test.go`, `csr_test.go`, `cross_signing_test.go`, `hybrid_test.go`,
  `certpolicy_test.go`, `bundle_test.go`, `attestation_test.go`,
  `interface_contract_test.go` (the conformance test for `TrustedCA`), plus
  `multi_keystore_test.go`, `multi_keystore_pkcs11_test.go` (build tag
  `pkcs11`: a secondary key lands in SoftHSM) and
  `multi_keystore_tpm2_sim_test.go` (build tag `tpm_simulator`: a TPM key as
  secondary and as the primary that self-signs the CA certificate).
  CRL persistence:
  `crl_persistence_test.go` (round trip across independent `*CA` instances
  sharing a backend, refresh-on-revoke, regenerate-on-read past/before
  `NextUpdate` via an injected `Clock`, force-regenerate),
  `ocsp_revocationstore_test.go` (the OCSP cold-path fix),
  `revocation_cluster_test.go` (#1116: two `*CA` instances over one shared
  in-memory revocation store — a revocation on A enforced by B's
  `IsRevoked`, `Verify`, `VerifyPeerCertificate` and CRL — plus store-fault
  and corrupt-record injection proving `IsRevoked`, OCSP, CRL listing, CRL
  numbering, `Load` and `VerifyPeerCertificate` each fail closed),
  `revocation_race_1131_test.go` (#1131, reusing that harness: a failed
  `PutIfAbsent` leaves the in-memory map untouched and a retry after the
  store recovers persists; two `*CA` instances racing to revoke the same
  serial leave the loser with `ErrAlreadyRevoked` and the winner's reason
  and time still on record; a store read fault during the duplicate check
  fails closed before any write is attempted), and
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
  Chain import: `aia_import_test.go` serves real generated chains from an
  httptest repository — a full walk at the depth limit imports every issuer;
  one issuer deeper is refused after exactly five fetches; a
  self-referencing AIA URL is refused as a loop; a certificate that did not
  sign the child is refused and not stored; a loopback repository is
  refused by the production client without receiving a request; an
  oversized or unparseable response is refused. `pki_fetch_test.go` covers
  the scheme filter, the body cap at and over the limit, a hostname
  resolving to loopback, the metadata address, redirect loops and redirects
  to a non-http scheme, and the CRL importer's private-address, oversized
  and `ldap://` refusals; the reserved-address classification itself is
  `pkg/netguard`'s (`reserved_test.go`, `dial_test.go`, `transport_test.go`).
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

### Overlay profile tests

`pkg/ca/profile_ipsec_svid_test.go`, `name_constraints_test.go` and
`attestation_evidence_test.go` cover the following, and
`sdk/go/ca_overlay_profiles_test.go` repeats the end-to-end flow through the
SDK names only:

- issuance under subordinates constrained to an IPv4 /24, an IPv6 /64 and a
  trust domain, with full `x509.Verify` of each leaf;
- that a CSR's own names, subject and evidence extension are ignored;
- every refusal: missing names, foreign names, tenant SPIFFE options,
  lifetime, key type and evidence encoding;
- agreement between the pre-sign constraint check and `crypto/x509` path
  validation.

## Observability

Issuance and revocation emit audit records through `pkg/audit`
(see [`../audit-log/`](../audit-log/engineering.md)); every request carries a
correlation ID. Certificate lifetimes and CRL generation are exposed through
`pkg/metrics`.
