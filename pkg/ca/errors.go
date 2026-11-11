// Package ca provides error definitions for the TrustedCA certificate authority.
//
// All errors are defined as sentinel variables for consistent error checking
// using errors.Is(). Error messages follow Go conventions: lowercase without
// punctuation.
package ca

import "errors"

// Initialization errors indicate issues with CA lifecycle management.
var (
	// ErrNotInitialized indicates the CA has not been initialized.
	ErrNotInitialized = errors.New("ca: not initialized")

	// ErrAlreadyInitialized indicates the CA has already been initialized.
	ErrAlreadyInitialized = errors.New("ca: already initialized")
)

// CSR errors indicate issues with certificate signing requests.
var (
	// ErrInvalidCSR indicates the CSR is malformed or invalid.
	ErrInvalidCSR = errors.New("ca: invalid certificate signing request")

	// ErrCSRGenerationFailed indicates CSR creation failed.
	ErrCSRGenerationFailed = errors.New("ca: csr generation failed")
)

// SubjectAltName errors indicate issues decoding a GeneralNames extension by
// hand. crypto/x509 parses dNSName, iPAddress, rfc822Name and
// uniformResourceIdentifier GeneralNames but silently discards otherName, so
// recovering an RFC 4043 permanentIdentifier or RFC 4108 hardwareModuleName
// from a request or certificate requires decoding the extension directly.
var (
	// ErrSANDecoding indicates a subjectAltName extension's GeneralNames
	// SEQUENCE, or one of its otherName entries, could not be ASN.1 decoded.
	ErrSANDecoding = errors.New("ca: subjectAltName decoding failed")
)

// Certificate errors indicate issues with certificate operations.
var (
	// ErrInvalidCertificate indicates the certificate is malformed or invalid.
	ErrInvalidCertificate = errors.New("ca: invalid certificate")

	// ErrCertificateNotFound indicates the requested certificate does not exist.
	ErrCertificateNotFound = errors.New("ca: certificate not found")

	// ErrCertificateExpired indicates the certificate has expired.
	ErrCertificateExpired = errors.New("ca: certificate expired")

	// ErrCertificateNotYetValid indicates the certificate is not yet valid.
	// The current time is before the certificate's NotBefore time.
	ErrCertificateNotYetValid = errors.New("ca: certificate not yet valid")

	// ErrCertificateAlreadyExists indicates a certificate with the same
	// identifier already exists.
	ErrCertificateAlreadyExists = errors.New("ca: certificate already exists")

	// ErrCertificateEncoding indicates a certificate could not be PEM
	// encoded into a bundle.
	ErrCertificateEncoding = errors.New("ca: certificate pem encoding failed")
)

// Signing errors indicate issues with cryptographic signing operations.
var (
	// ErrSigningFailed indicates the signing operation failed.
	ErrSigningFailed = errors.New("ca: signing failed")

	// ErrInvalidSignature indicates the signature verification failed.
	ErrInvalidSignature = errors.New("ca: invalid signature")

	// ErrInvalidIssuer indicates that a signer was supplied for a signing
	// operation but no accompanying issuer certificate was provided. The
	// issuer cert is required so the issued certificate's Issuer and
	// AuthorityKeyIdentifier fields can be populated.
	ErrInvalidIssuer = errors.New("ca: signer provided without issuer certificate")
)

// Revocation errors indicate issues with certificate revocation.
var (
	// ErrCertificateRevoked indicates the certificate has been revoked.
	ErrCertificateRevoked = errors.New("ca: certificate revoked")

	// ErrCRLNotFound indicates the certificate revocation list was not found.
	ErrCRLNotFound = errors.New("ca: crl not found")

	// ErrCRLGenerationFailed indicates CRL creation failed.
	ErrCRLGenerationFailed = errors.New("ca: crl generation failed")

	// ErrAlreadyRevoked indicates the certificate is already revoked.
	// recordRevocation (go-xkms#1131) returns it wrapped in *errs.Detail,
	// naming the original revocation's time and reason, whenever the
	// existing record was readable; errors.Is still matches the wrapped
	// form.
	ErrAlreadyRevoked = errors.New("ca: certificate already revoked")

	// ErrTransparencyLogAppend indicates an issued certificate's cert-issued
	// entry could not be appended to the CA's transparency log. Issuance
	// fails closed: the certificate is neither stored nor returned.
	ErrTransparencyLogAppend = errors.New("ca: transparency log append failed")

	// ErrTransparencyLogEntryMissing indicates a revocation was recorded
	// but its revoked entry could not be appended to the CA's transparency
	// log. The revocation stands; only its log entry is missing.
	ErrTransparencyLogEntryMissing = errors.New("ca: revocation recorded, transparency log entry missing")

	// ErrRevocationRecordCorrupt indicates a persisted revocation record
	// could not be decoded, or decoded to a serial that does not match the
	// key it is stored under. Every reader of revocation state fails closed
	// on it: a record that cannot be read is never treated as "not
	// revoked", because that would silently un-revoke the certificate.
	ErrRevocationRecordCorrupt = errors.New("ca: corrupt revocation record")
)

// Chain errors indicate issues with certificate chain validation.
var (
	// ErrInvalidCertificateChain indicates the certificate chain is invalid.
	ErrInvalidCertificateChain = errors.New("ca: invalid certificate chain")

	// ErrRootNotFound indicates the root certificate was not found.
	ErrRootNotFound = errors.New("ca: root certificate not found")

	// ErrIntermediateNotFound indicates an intermediate certificate was not found.
	ErrIntermediateNotFound = errors.New("ca: intermediate certificate not found")
)

// Config errors indicate issues with CA configuration.
var (
	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("ca: invalid configuration")

	// ErrInvalidKeyAlgorithm indicates an unsupported key algorithm was specified.
	ErrInvalidKeyAlgorithm = errors.New("ca: invalid key algorithm")

	// ErrPublicKeyRequired indicates a certificate was requested for a key
	// without naming the key's public half.
	ErrPublicKeyRequired = errors.New("ca: public key required")

	// ErrInvalidStoreType indicates an unsupported store type was specified.
	ErrInvalidStoreType = errors.New("ca: invalid store type")

	// ErrNoKeysConfigured indicates no keys are configured for an identity.
	ErrNoKeysConfigured = errors.New("ca: no keys configured for identity")

	// ErrKeyPasswordRequired is returned when a CA key would be generated without
	// a password but RequireKeyPassword is true on the configuration. Set a
	// password on the KeyConfig (or the identity-level Keystores.Software.Password)
	// or set RequireKeyPassword to false to permit plaintext key storage.
	ErrKeyPasswordRequired = errors.New("ca: key password required (RequireKeyPassword=true)")

	// ErrKeyRetrievalFailed indicates the configured backend returned an
	// error other than "key not found" (errors.Is(err, backend.ErrKeyNotFound))
	// while getOrGenerateCAKey checked whether a CA key already exists.
	// getOrGenerateCAKey fails closed on this rather than falling through to
	// generation: a TPM transient fault, a PKCS#11 login failure, cloud KMS
	// throttling, or any other I/O error must never be treated as "no key
	// yet", because doing so would silently generate and persist a
	// replacement for a hardware-backed signing key the backend merely
	// failed to reach.
	ErrKeyRetrievalFailed = errors.New("ca: key retrieval failed")
)

// Storage errors indicate issues with key and certificate storage.
var (
	// ErrKeyStoreRequired indicates a key store must be configured.
	ErrKeyStoreRequired = errors.New("ca: key store required")

	// ErrCertStoreRequired indicates a certificate store must be configured.
	ErrCertStoreRequired = errors.New("ca: certificate store required")

	// ErrObjectStoreRequired indicates an object store must be configured for
	// the invoked operation. CA-adjacent features like cross-signing, AIA
	// trust-chain caching, and attestation evidence persistence require a
	// blob-style store that CertStore's CN-keyed model cannot serve.
	ErrObjectStoreRequired = errors.New("ca: object store required")

	// ErrObjectNotFound indicates the object store holds no blob under the
	// requested key.
	ErrObjectNotFound = errors.New("ca: object not found")

	// ErrRevocationStoreRequired indicates a durable revocation store
	// (Params.RevocationStore) must be configured. Revocation state and the
	// derived CRL artifact are always persisted through RevocationStore; there
	// is no fallback to the object store or to in-memory-only tracking.
	ErrRevocationStoreRequired = errors.New("ca: revocation store required")

	// ErrBackendForStoreRequired indicates Params.BackendForStore (or
	// MultiIdentityParams.BackendForStore) must be supplied. Every CA key is
	// routed to its backend by StoreType through the per-instance keystoreMap
	// built from BackendForStore; there is no fallback to a single shared
	// KeyStore for every StoreType.
	ErrBackendForStoreRequired = errors.New("ca: BackendForStore is required")

	// ErrStorageError indicates a storage operation failed.
	ErrStorageError = errors.New("ca: storage operation failed")
)

// PKI fetch errors indicate a refused or failed download of a certificate or
// CRL named by another certificate's AIA or CRL distribution point extension.
// Those URLs are chosen by whoever issued the certificate, so every fetch is
// treated as attacker-directed.
var (
	// ErrPKIFetchRefused indicates the URL was not fetched: its scheme is not
	// http or https, it resolves to a loopback, private, link-local or
	// otherwise non-public address, or it redirected too many times.
	ErrPKIFetchRefused = errors.New("ca: pki object fetch refused")

	// ErrPKIFetchTooLarge indicates the response body exceeded the size
	// limit for the object being fetched.
	ErrPKIFetchTooLarge = errors.New("ca: pki object response too large")

	// ErrAIALoop indicates an AIA walk fetched a certificate it had already
	// visited, so following it would never terminate.
	ErrAIALoop = errors.New("ca: aia chain loops")

	// ErrAIADepthExceeded indicates an AIA walk reached maxAIADepth issuers
	// without arriving at a self-signed certificate.
	ErrAIADepthExceeded = errors.New("ca: aia chain too deep")

	// ErrAIAIssuerSignatureInvalid indicates a certificate fetched from an
	// AIA URL did not sign the certificate that named it, so it is not that
	// certificate's issuer and is never imported.
	ErrAIAIssuerSignatureInvalid = errors.New("ca: aia certificate did not sign the child certificate")
)

// Serial number errors indicate issues with certificate serial generation.
var (
	// ErrSerialGenerationFailed indicates serial number generation failed.
	ErrSerialGenerationFailed = errors.New("ca: serial number generation failed")

	// ErrSerialCollision indicates a serial number collision was detected.
	ErrSerialCollision = errors.New("ca: serial number collision")

	// ErrInvalidSerial indicates a caller-supplied serial number that is not
	// a positive integer of at most 20 octets (RFC 5280 §4.1.2.2).
	ErrInvalidSerial = errors.New("ca: invalid serial number")

	// ErrSerialNotReserved indicates a caller-supplied serial number this CA
	// did not reserve with ReserveSerial.
	ErrSerialNotReserved = errors.New("ca: serial number not reserved")
)

// Pre-signing lint errors (CA/Browser Forum Baseline Requirements §4.3.1.2).
var (
	// ErrLintKey indicates the CA could not generate the throwaway key that
	// signs the lint certificate.
	ErrLintKey = errors.New("ca: lint key generation failed")

	// ErrLintFailed indicates the linter refused the to-be-signed
	// certificate; the CA did not sign it.
	ErrLintFailed = errors.New("ca: certificate lint failed")
)

// Profile errors indicate issues with certificate profiles.
var (
	// ErrProfileNotFound indicates the requested profile does not exist.
	ErrProfileNotFound = errors.New("ca: profile not found")

	// ErrInvalidProfile indicates the profile configuration is invalid.
	ErrInvalidProfile = errors.New("ca: invalid profile")
)

// TLS errors indicate issues with TLS configuration.
var (
	// ErrTLSConfigFailed indicates TLS configuration creation failed.
	ErrTLSConfigFailed = errors.New("ca: tls configuration failed")

	// ErrInvalidTLSOptions indicates invalid TLS options were specified.
	ErrInvalidTLSOptions = errors.New("ca: invalid tls options")

	// ErrKeyNotFound indicates the private key was not found.
	ErrKeyNotFound = errors.New("ca: private key not found")

	// ErrKeyCertMismatch indicates the private key does not match the certificate.
	ErrKeyCertMismatch = errors.New("ca: private key does not match certificate")

	// ErrInvalidKeyAttributes indicates a caller passed nil or incomplete
	// KeyAttributes to an operation that requires a fully resolved key
	// identity, such as recordIssuedKey.
	ErrInvalidKeyAttributes = errors.New("ca: invalid key attributes")

	// ErrInvalidPEM indicates the PEM data is malformed or invalid.
	ErrInvalidPEM = errors.New("ca: invalid pem data")

	// ErrPeerVerificationFailed indicates peer certificate verification failed.
	ErrPeerVerificationFailed = errors.New("ca: peer certificate verification failed")
)

// Algorithm security errors indicate issues with algorithm strength.
var (
	// ErrWeakSignatureAlgorithm indicates a non-anchor certificate in the chain
	// uses a signature algorithm below the minimum strength threshold
	// (SHA-256 or stronger).  The algorithm name and certificate subject are
	// included in the ErrWeakSignatureAlgorithmDetail type returned by
	// VerifyChainAlgorithms.
	ErrWeakSignatureAlgorithm = errors.New("ca: weak signature algorithm")
)

// ErrWeakSignatureAlgorithmDetail carries the offending algorithm name and
// certificate subject for an ErrWeakSignatureAlgorithm failure.
type ErrWeakSignatureAlgorithmDetail struct {
	// Algorithm is the human-readable name of the offending algorithm.
	Algorithm string

	// Subject is the subject DN of the certificate that used it.
	Subject string
}

// Error implements the error interface.
func (e *ErrWeakSignatureAlgorithmDetail) Error() string {
	return "ca: weak signature algorithm " + e.Algorithm + " in certificate " + e.Subject
}

// Unwrap returns ErrWeakSignatureAlgorithm so that errors.Is works.
func (e *ErrWeakSignatureAlgorithmDetail) Unwrap() error {
	return ErrWeakSignatureAlgorithm
}

// ErrIdentityNotFound indicates no configured CA identity matches the
// requested common name.
type ErrIdentityNotFound struct {
	// CommonName is the identity common name that was requested.
	CommonName string
}

// Error implements the error interface.
func (e *ErrIdentityNotFound) Error() string {
	return "ca: no configured identity with common name " + e.CommonName
}

// ErrUnknownParentCA indicates an intermediate identity references a
// ParentCA common name that is not the root and not an earlier intermediate
// in the Identity list.
type ErrUnknownParentCA struct {
	// Identity is the common name of the identity with the bad reference.
	Identity string

	// ParentCA is the unresolvable parent common name it referenced.
	ParentCA string
}

// Error implements the error interface.
func (e *ErrUnknownParentCA) Error() string {
	return "ca: identity " + e.Identity + " references unknown parent CA " + e.ParentCA +
		" (parent-ca must name the root or an earlier identity in the list)"
}

// Validation errors indicate issues with request validation.
var (
	// ErrSubjectCommonNameRequired indicates the subject common name is missing.
	ErrSubjectCommonNameRequired = errors.New("ca: subject common name required")

	// ErrInvalidValidityPeriod indicates the validity period is invalid.
	ErrInvalidValidityPeriod = errors.New("ca: invalid validity period")

	// ErrInvalidPathLength indicates the path length constraint is invalid.
	ErrInvalidPathLength = errors.New("ca: invalid path length")
)

// TCG enrollment errors indicate issues with TCG Trusted Computing operations.
var (
	// ErrTPMNotConfigured indicates SetTPM has not been called before enrollment.
	ErrTPMNotConfigured = errors.New("ca: tpm not configured for enrollment")

	// ErrTCGCSRVerificationFailed indicates the TCG-CSR-IDEVID verification failed.
	ErrTCGCSRVerificationFailed = errors.New("ca: tcg-csr-idevid verification failed")

	// ErrTCGMakeCredentialFailed indicates MakeCredentialWithExternalEK failed.
	ErrTCGMakeCredentialFailed = errors.New("ca: make credential failed")

	// ErrTCGMissingEKCert indicates the EK certificate is missing from the CSR.
	ErrTCGMissingEKCert = errors.New("ca: missing ek certificate in csr")

	// ErrTCGInvalidEKCert indicates the EK certificate could not be parsed.
	ErrTCGInvalidEKCert = errors.New("ca: invalid ek certificate")

	// ErrTCGExtensionEncoding indicates a TCG extension could not be ASN.1 encoded.
	ErrTCGExtensionEncoding = errors.New("ca: tcg extension encoding failed")

	// ErrTCGExtensionParsing indicates a TCG extension could not be ASN.1 decoded.
	ErrTCGExtensionParsing = errors.New("ca: tcg extension parsing failed")

	// ErrTCGTenantIDEmpty indicates an empty tenant ID was provided.
	ErrTCGTenantIDEmpty = errors.New("ca: tenant id must not be empty")

	// ErrTenantRequired indicates a certificate request that names no tenant.
	// Every certificate the CA issues carries its tenant as the subject's
	// first organizational unit; the system tenant's own certificates name
	// qrdbsdk.SystemTenantID.
	ErrTenantRequired = errors.New("ca: certificate request names no tenant")

	// ErrTCGNetworkZoneEmpty indicates an empty network zone was provided.
	ErrTCGNetworkZoneEmpty = errors.New("ca: network zone must not be empty")

	// ErrTCGInvalidPublicKey indicates the public key is nil or unsupported.
	ErrTCGInvalidPublicKey = errors.New("ca: invalid public key for tcg certificate")

	// ErrTCGInvalidIssuer indicates a signer was provided without an issuer cert.
	ErrTCGInvalidIssuer = errors.New("ca: signer provided without issuer certificate")

	// ErrTCGCertIssuanceFailed indicates TCG certificate creation failed.
	ErrTCGCertIssuanceFailed = errors.New("ca: tcg certificate issuance failed")

	// ErrTCGIAKKeyExtraction indicates the IAK public key could not be extracted.
	ErrTCGIAKKeyExtraction = errors.New("ca: failed to extract iak public key")

	// ErrTCGCSRUnmarshalFailed indicates the packed CSR could not be unmarshaled.
	ErrTCGCSRUnmarshalFailed = errors.New("ca: failed to unmarshal tcg-csr-idevid")

	// ErrTCGEKManufacturerUnknown indicates the TCG TPM manufacturer code
	// cannot be determined for the endorsement key.
	//
	// TCG DevID v1 r12 §8.1 makes the manufacturer code the first component of
	// the hwSerialNum that identifies the TPM inside subjectAltName, and the
	// extension is a SHALL. Issuing without it would put a name in the
	// certificate that does not identify the TPM it claims to.
	ErrTCGEKManufacturerUnknown = errors.New("ca: tcg tpm manufacturer code unknown")

	// ErrTCGInvalidManufacturerCode indicates a TCG TPM manufacturer code is
	// not in the form tcg-at-tpmManufacturer carries: "id:" followed by the
	// 32-bit TPM_PT_MANUFACTURER value as eight uppercase hexadecimal digits.
	ErrTCGInvalidManufacturerCode = errors.New("ca: invalid tcg tpm manufacturer code")

	// ErrTCGMandatoryExtension indicates an extension TCG DevID v1 r12 §8.1
	// requires could not be built, so no certificate was issued.
	//
	// A DevID certificate missing its subjectAltName says nothing about which
	// TPM holds the key; a relying party reading it would conclude only that
	// the CA had verified less than it did. Issuance refuses instead.
	ErrTCGMandatoryExtension = errors.New("ca: mandatory tcg certificate extension could not be built")

	// ErrTCGEKCertUntrusted indicates the endorsement key certificate could
	// not be chained to a configured TPM-manufacturer trust anchor, or does
	// not carry the tcg-kp-EKCertificate extended key usage (or the
	// anyExtendedKeyUsage purpose that subsumes it).
	//
	// TPM 2.0 Keys for Device Identity and Attestation v1.10r9 §6.1.2 step 5b
	// and §6.2.2 step 4b make this a SHALL before the CA issues an IAK or
	// IDevID: TPM2_ActivateCredential proves the requester holds the EK
	// private key, not that the EK belongs to a genuine TPM. A CA with no EK
	// trust anchors configured returns this error for every request rather
	// than skipping the check.
	ErrTCGEKCertUntrusted = errors.New("ca: endorsement key certificate is not chained to a trusted tpm manufacturer root")

	// ErrTCGLAKEvidenceRequired indicates IssueLAKCertificate was called with
	// no LAKCertificationEvidence, or evidence missing the IAK certificate the
	// TPM2_Certify evidence must be verified against (go-xkms#715).
	ErrTCGLAKEvidenceRequired = errors.New("ca: LAK certification evidence requires the IAK certificate")

	// ErrTCGIAKUntrusted indicates the IAK certificate presented as part of a
	// LAK certification request does not chain to the certificate about to
	// sign the LAK -- this CA's own issuing certificate, or the tenant's
	// issuer certificate in multi-tenant mode -- or is outside its validity
	// period. TCG TPM 2.0 Keys for Device Identity and Attestation v1.10 r9
	// §5.3/§6.3 requires the LAK's TPM2_Certify evidence to be verifiable
	// against a trusted IAK before the Owner issues the LAK certificate.
	ErrTCGIAKUntrusted = errors.New("ca: IAK certificate is not chained to a trusted root")

	// ErrTCGLAKDeviceAttributesRequired indicates the request is missing one
	// of the TPM manufacturer, model or firmware version attributes WebAuthn
	// Level 2 §8.3.1 requirement 3 requires in the LAK certificate's critical
	// subjectAltName directoryName.
	ErrTCGLAKDeviceAttributesRequired = errors.New("ca: LAK certificate request requires the TPM manufacturer, model and firmware version")
)

// FIDO2 attestation errors indicate that a certificate signing request cannot
// be issued as a WebAuthn Level 2 section 8.2.1 attestation certificate. Each
// one refuses issuance: a relying party rejects an attestation certificate
// that misses any of these fields, so issuing an incomplete one would only
// move the failure to first registration, where nothing reports why
// attestation stopped working.
var (
	// ErrFIDO2AttestationIssuerIncomplete indicates the issuing CA's own
	// subject carries no country or no organization, so it cannot supply the
	// Subject-C and Subject-O the attestation certificate must assert.
	ErrFIDO2AttestationIssuerIncomplete = errors.New("ca: issuing ca subject cannot supply the fido2 attestation country and organization")

	// ErrFIDO2AttestationSubjectCNRequired indicates the request carries no
	// common name, which section 8.2.1 requires on the attestation certificate.
	ErrFIDO2AttestationSubjectCNRequired = errors.New("ca: fido2 attestation certificate requires a subject common name")

	// ErrFIDO2AttestationAAGUIDMissing indicates the request carries no
	// id-fido-gen-ce-aaguid extension, so the certificate would vouch for no
	// authenticator model.
	ErrFIDO2AttestationAAGUIDMissing = errors.New("ca: request carries no id-fido-gen-ce-aaguid extension")

	// ErrFIDO2AttestationAAGUIDInvalid indicates the id-fido-gen-ce-aaguid
	// extension is not a non-critical DER octet string of exactly 16 bytes.
	ErrFIDO2AttestationAAGUIDInvalid = errors.New("ca: id-fido-gen-ce-aaguid extension is not a 16-byte octet string")

	// ErrFIDO2AttestationAAGUIDNotPermitted indicates the request names an
	// authenticator model the profile does not certify, so nothing was issued.
	//
	// The AAGUID is the certificate's claim about the authenticator's model,
	// and a relying party reads it as the CA's word. The CA can give its word
	// only for the models the operator listed when the profile was built;
	// certifying any other would put a claim in the certificate that nobody
	// vouched for. The accompanying detail names the refused AAGUID.
	ErrFIDO2AttestationAAGUIDNotPermitted = errors.New("ca: id-fido-gen-ce-aaguid extension names an authenticator model this profile does not certify")

	// ErrDICEEvidenceMissing indicates the request carries no
	// tcg-dice-TcbInfo extension, so an IDevID issued from it would assert a
	// device identity while saying nothing about the firmware that identity
	// was derived from.
	ErrDICEEvidenceMissing = errors.New("ca: request carries no tcg-dice-TcbInfo extension")

	// ErrDICEEvidenceInvalid indicates a DICE evidence extension on the
	// request could not be decoded.
	//
	// Evidence the issuer cannot read is never signed. A certificate carrying
	// a DiceTcbInfo the CA could not parse invites a relying party to trust
	// claims nobody checked.
	ErrDICEEvidenceInvalid = errors.New("ca: dice evidence extension could not be decoded")
)
