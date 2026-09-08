# Certificate Authority — Engineering Contract

> **Status: NORMATIVE** · Feature: `certificate-authority` · Repo: `go-xkms` · Last verified: 2026-09-08

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
`IsRevoked(serial *big.Int) (bool, error)`.

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
- `BuildSubjectAltName(subject, dns, email, ip, uri, others)` is the only
  GeneralNames encoder in go-xkms. `CertificateSpec.OtherNames` routes
  otherNames through it; crypto/x509 has none and skips its own
  subjectAltName once one is supplied, so the standard names are encoded here
  too.
- `OtherName`, `MarshalHardwareModuleName`, `MarshalPermanentIdentifier`,
  `ParseHardwareModuleNameExtension`, `ParsePermanentIdentifierExtension`,
  and the OIDs `OIDTCGHwTypeTPM2` (2.23.133.1.2) and
  `OIDTCGOnEKPermIdSha256` (2.23.133.12.1).

Constructors are `pkg/ca/constructors.go`; configuration types are
`pkg/ca/config.go` (`Identity`, and the CA config it hangs off).

## Invariants

- **`Init` is once.** A second `Init` returns `ErrAlreadyInitialized` rather
  than replacing the root. `Load` is the idempotent startup path.
- **Every operation requires `IsInitialized()`.** Issuance against an
  uninitialized CA fails closed.
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
- **The device serial number lives in the subject, the device model under
  tcg-at-platformModel.** Neither belongs under tcg-at-tpmModel or
  tcg-at-tpmVersion, which name the TPM's own model and firmware version.
- **The EK certificate chain is NOT verified against a manufacturer
  truststore.** §6.2.2 step 7b calls for it and no code path in this
  repository does it; what enrollment proves today is residency in *a* TPM,
  not in one a manufacturer vouched for. Tracked as an open gap, not a
  property to rely on.

## Error semantics

`pkg/ca/errors.go` holds the vocabulary — typed errors, never `fmt.Errorf`.
The lifecycle and validation errors named in the interface contract are
`ErrAlreadyInitialized` and `ErrInvalidConfig`; key-layer failures surface as
the keystore errors from `pkg/xkms/errors.go`
(see [`../key-management/engineering.md`](../key-management/engineering.md)).

Transport mapping is in `pkg/api/rest/handlers_ca.go` /
`handlers_ca_bundle.go` / `handlers_ca_tcg.go`, `pkg/api/grpc/service_ca_bundle.go`,
and `pkg/api/mcp/handlers_ca.go` / `handlers_ca_tcg.go`.

**Fail-closed paths:** uninitialized CA; a CSR that fails policy; a revoked or
expired issuer; an attestation quote that does not verify; a TCG CSR whose
IDevID signature does not check; a TCG CSR with no EK certificate or with no
determinable TPM manufacturer code. None of these fall back to issuing.

## Configuration

CA configuration lives under the server config's CA section (`pkg/config`),
resolved into `ca.Identity` (`pkg/ca/config.go`). The settings that change
behaviour rather than naming:

- `DefaultKeyAlgorithm` / `DefaultSignatureAlgorithm` — what a request gets when
  it does not ask.
- `DefaultValidityPeriod` — days, applied when the request omits validity.
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
store layout is internal, and a change to it needs a migration
(`pkg/migration`).

## Test strategy

- **Unit** — `pkg/ca` carries the repo's densest suite: `ca_core_test.go`,
  `issuance_test.go`, `csr_test.go`, `cross_signing_test.go`, `hybrid_test.go`,
  `certpolicy_test.go`, `bundle_test.go`, `attestation_test.go`,
  `interface_contract_test.go` (the conformance test for `TrustedCA`), plus
  `multi_keystore_test.go`, `multi_keystore_pkcs11_test.go`,
  `multi_keystore_tpm2_sim_test.go`.
- **End to end** — `pkg/ca/issuance_e2e_test.go`,
  `pkg/api/rest/init_ceremony_e2e_test.go`.
- **Integration** — `test/integration/certstore`, `test/integration/acme-tpm`,
  `test/integration/cluster` (CA key custody across nodes).
- **Parity** — `CommandDefinition` entries exist for `ca-bundle`,
  `ca-certificate`, `ca-crl`, `ca-issue`, `ca-revoke`, `ca-sign-csr`,
  `ca-status`, `cert-info`, `cert-list`, `tls-cert`.

## Observability

Issuance and revocation emit audit records through `pkg/audit`
(see [`../audit-log/`](../audit-log/engineering.md)); every request carries a
correlation ID. Certificate lifetimes and CRL generation are exposed through
`pkg/metrics`.
