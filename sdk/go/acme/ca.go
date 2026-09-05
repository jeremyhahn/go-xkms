// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package trustedca re-exports the native go-xkms Certificate Authority
// surface (pkg/ca) for consumers that prefer a single "trustedca" import
// alias. Historically this package re-exported the pkg/acme/ca wrapper; that
// wrapper has been retired and its responsibilities merged into pkg/ca. The
// aliases below therefore point at native types and behave identically.
package trustedca

import (
	pkgerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
)

// =============================================================================
// CA Interface
// =============================================================================

// CACertificateAuthority is the core CA interface providing TCG-compliant
// certificate authority operations including TPM attestation, device identity
// enrollment, and Trusted Computing workflows.
//
// Aliased to pkg/ca.TCGCA — the native TCG-extended TrustedCA interface that
// exposes IssueEKCertificate, IssueAKCertificate, SignTCGCSRIDevID, and the
// full TrustedCA surface (Init, Load, SignCSR, Verify, Revoke, ...).
type CACertificateAuthority = pkgca.TCGCA

// CAIAKCertificateReader returns the Initial Attestation Key certificate a
// CA recorded for a device at TCG-CSR-IDEVID enrollment, looked up by product
// model and serial number. Kept beside CACertificateAuthority so existing
// implementations keep compiling; the CA returned by CANew satisfies both.
// Aliased to pkg/ca.IAKCertificateReader.
type CAIAKCertificateReader = pkgca.IAKCertificateReader

// =============================================================================
// CA Configuration Types
// =============================================================================

// CAConfig defines the multi-identity CA configuration (root + intermediates),
// default validity, and operational settings. Aliased to
// pkg/ca.MultiIdentityCAConfig.
type CAConfig = pkgca.MultiIdentityCAConfig

// CAIdentity represents a CA identity configuration (root or intermediate),
// including its subject, validity period, key configurations, and
// extensions. Aliased to pkg/ca.Identity.
type CAIdentity = pkgca.Identity

// CASubject contains X.509 distinguished name fields for certificate subjects.
// Aliased to pkg/ca.Subject.
type CASubject = pkgca.Subject

// CACertificateRequest defines the parameters for certificate issuance
// including subject, validity, key usage, and TPM enrollment fields.
// Aliased to pkg/ca.CertificateRequest.
type CACertificateRequest = pkgca.CertificateRequest

// CASubjectAlternativeNames contains SAN extension fields for certificates.
// Aliased to pkg/ca.SubjectAlternativeNames.
type CASubjectAlternativeNames = pkgca.SubjectAlternativeNames

// CAHardwareModuleInfo contains hardware identification for IDevID
// certificates per RFC 4108 and TCG specifications. Aliased to
// pkg/ca.HardwareModuleInfo.
type CAHardwareModuleInfo = pkgca.HardwareModuleInfo

// CARevocationInfo contains information about a revoked certificate.
// Aliased to pkg/ca.RevocationInfo.
type CARevocationInfo = pkgca.RevocationInfo

// CAParams holds the parameters for creating a new CA instance via CANew.
// Aliased to pkg/ca.Params.
type CAParams = pkgca.Params

// =============================================================================
// CA Factory Types
// =============================================================================

// CACertStoreFactory resolves a CertStore for a given CA common name.
// Aliased to pkg/ca.CertStoreFactoryFunc.
type CACertStoreFactory = pkgca.CertStoreFactoryFunc

// CAObjectStoreFactory resolves an object store for a given CA common name.
// Aliased to pkg/ca.ObjectStoreFactoryFunc.
type CAObjectStoreFactory = pkgca.ObjectStoreFactoryFunc

// CAKeyStoreFactory resolves a KeyStore for a given CA common name.
// Aliased to pkg/ca.KeyStoreFactoryFunc.
type CAKeyStoreFactory = pkgca.KeyStoreFactoryFunc

// =============================================================================
// CA Constructor Functions
// =============================================================================

// CANew creates a new Certificate Authority instance using the Params struct.
// Aliased to pkg/ca.New.
var CANew = pkgca.New

// CANewParentCA creates a single-identity root CA from params.Identity[0].
// Aliased to pkg/ca.NewParentCA.
var CANewParentCA = pkgca.NewParentCA

// CANewIntermediateCA creates an intermediate CA from params.Identity[1]
// signed by the provided parent. Aliased to pkg/ca.NewIntermediateCA.
var CANewIntermediateCA = pkgca.NewIntermediateCA

// CANewCA builds a root+intermediate pair from params.Identity. Aliased to
// pkg/ca.NewCA.
var CANewCA = pkgca.NewCA

// CAIAKCommonName returns the subject common name ("iak-<model>-<serial>")
// under which SignTCGCSRIDevID issues and stores a device's IAK certificate,
// so a consumer can address the record without spelling the format itself.
// Aliased to pkg/ca.IAKCommonName.
var CAIAKCommonName = pkgca.IAKCommonName

// =============================================================================
// CA Attestation Blob Type Constants
// =============================================================================

const (
	// CAAttestBlobQuote identifies a TPM quote attestation blob.
	CAAttestBlobQuote = pkgca.AttestBlobQuote

	// CAAttestBlobEventLog identifies a TPM event log attestation blob.
	CAAttestBlobEventLog = pkgca.AttestBlobEventLog

	// CAAttestBlobPCRs identifies a TPM PCR values attestation blob.
	CAAttestBlobPCRs = pkgca.AttestBlobPCRs

	// CAAttestBlobRoot identifies the root attestation blob directory.
	CAAttestBlobRoot = pkgca.AttestBlobRoot
)

// =============================================================================
// CA Error Variables (native pkg/ca sentinels)
// =============================================================================
//
// Only sentinels that exist in pkg/ca are re-exported. Legacy wrapper-only
// sentinels were removed along with pkg/acme/ca.

var (
	// CAErrInvalidConfig indicates the CA configuration is invalid.
	CAErrInvalidConfig = pkgca.ErrInvalidConfig

	// CAErrInvalidCSR indicates the supplied CSR is malformed.
	CAErrInvalidCSR = pkgca.ErrInvalidCSR

	// CAErrInvalidCertificate indicates the certificate is malformed.
	CAErrInvalidCertificate = pkgca.ErrInvalidCertificate

	// CAErrCertificateNotFound indicates a certificate lookup missed.
	CAErrCertificateNotFound = pkgca.ErrCertificateNotFound

	// CAErrInvalidSignature indicates the signature failed verification.
	CAErrInvalidSignature = pkgca.ErrInvalidSignature

	// CAErrNotInitialized indicates Init/Load has not completed.
	CAErrNotInitialized = pkgca.ErrNotInitialized

	// CAErrAlreadyInitialized indicates Init/Load was already called.
	CAErrAlreadyInitialized = pkgca.ErrAlreadyInitialized

	// CAErrInvalidKeyAlgorithm indicates the key algorithm is unsupported.
	CAErrInvalidKeyAlgorithm = pkgca.ErrInvalidKeyAlgorithm

	// CAErrSigningFailed indicates a signing operation failed.
	CAErrSigningFailed = pkgca.ErrSigningFailed

	// CAErrStorageError indicates a storage-layer failure.
	CAErrStorageError = pkgca.ErrStorageError

	// CAErrInvalidRequest indicates the request is malformed.
	CAErrInvalidRequest = pkgca.ErrInvalidRequest

	// CAErrCertificateRevoked indicates the certificate is in the CA's CRL.
	CAErrCertificateRevoked = pkgca.ErrCertificateRevoked

	// CAErrAlreadyRevoked indicates the certificate was already revoked.
	CAErrAlreadyRevoked = pkgca.ErrAlreadyRevoked

	// CAErrCRLNotFound indicates no CRL is available for the issuer.
	CAErrCRLNotFound = pkgca.ErrCRLNotFound

	// CAErrCRLGenerationFailed indicates CRL generation failed.
	CAErrCRLGenerationFailed = pkgca.ErrCRLGenerationFailed

	// CAErrInvalidCertificateChain indicates chain validation failed.
	CAErrInvalidCertificateChain = pkgca.ErrInvalidCertificateChain

	// CAErrRootNotFound indicates the root CA certificate is missing.
	CAErrRootNotFound = pkgca.ErrRootNotFound

	// CAErrInvalidIssuer indicates the issuer reference is invalid.
	CAErrInvalidIssuer = pkgca.ErrInvalidIssuer

	// CAErrInvalidStoreType indicates the requested store type is invalid.
	CAErrInvalidStoreType = pkgca.ErrInvalidStoreType

	// CAErrInvalidAttestationBlobType indicates an unknown attestation blob.
	CAErrInvalidAttestationBlobType = pkgca.ErrInvalidAttestationBlobType

	// CAErrInvalidNonce indicates the supplied nonce is invalid.
	CAErrInvalidNonce = pkgca.ErrInvalidNonce

	// CAErrTPMNotConfigured indicates the CA has no TPM backend set.
	CAErrTPMNotConfigured = pkgca.ErrTPMNotConfigured

	// CAErrTenantIDEmpty indicates a tenant-scoped operation received an
	// empty tenant id. Aliased to pkg/ca.ErrTCGTenantIDEmpty.
	CAErrTenantIDEmpty = pkgca.ErrTCGTenantIDEmpty

	// CAErrObjectStoreRequired indicates an operation requiring an object
	// store was attempted on a CA without one configured.
	CAErrObjectStoreRequired = pkgca.ErrObjectStoreRequired

	// CAErrKeyStoreRequired indicates a KeyStore is missing from Params.
	CAErrKeyStoreRequired = pkgca.ErrKeyStoreRequired

	// CAErrCertStoreRequired indicates a CertStore is missing from Params.
	CAErrCertStoreRequired = pkgca.ErrCertStoreRequired

	// CAErrKeyNotFound indicates a key was not found in the KeyStore.
	CAErrKeyNotFound = pkgca.ErrKeyNotFound

	// CAErrInvalidPEM indicates a PEM block could not be decoded.
	CAErrInvalidPEM = pkgca.ErrInvalidPEM

	// CAErrProfileNotFound indicates a profile lookup missed.
	CAErrProfileNotFound = pkgca.ErrProfileNotFound
)

// =============================================================================
// ErrorType - ACME/gRPC Error Category Types
// =============================================================================

// ErrorType is a coarse error category used for ACME protocol and gRPC error
// classification. Aliased to pkg/acme/errors.ErrorType.
type ErrorType = pkgerrors.ErrorType

// ErrorType constants for ACME protocol, CA operations, storage, and
// TPM/attestation. These can be used with errors.Is() for error type
// checking.
var (
	// ErrInternalServer indicates an internal server error.
	ErrInternalServer = pkgerrors.InternalServer

	// ErrMalformed indicates a malformed request.
	ErrMalformed = pkgerrors.Malformed

	// ErrUnauthorized indicates an unauthorized request.
	ErrUnauthorized = pkgerrors.Unauthorized

	// ErrNotFound indicates a requested resource was not found.
	ErrNotFound = pkgerrors.NotFound

	// ErrRateLimit indicates rate limit exceeded.
	ErrRateLimit = pkgerrors.RateLimit

	// ErrRejectedIdentifier indicates an identifier was rejected.
	ErrRejectedIdentifier = pkgerrors.RejectedIdentifier

	// ErrInvalidEmail indicates an invalid email address.
	ErrInvalidEmail = pkgerrors.InvalidEmail

	// ErrConnectionFailure indicates a connection failure.
	ErrConnectionFailure = pkgerrors.ConnectionFailure

	// ErrCAA indicates a CAA record check failure.
	ErrCAA = pkgerrors.CAA

	// ErrMissingSCTs indicates missing signed certificate timestamps.
	ErrMissingSCTs = pkgerrors.MissingSCTs

	// ErrDuplicate indicates a duplicate resource.
	ErrDuplicate = pkgerrors.Duplicate

	// ErrOrderNotReady indicates an order is not ready for finalization.
	ErrOrderNotReady = pkgerrors.OrderNotReady

	// ErrDNS indicates a DNS resolution failure.
	ErrDNS = pkgerrors.DNS

	// ErrBadPublicKey indicates an invalid public key.
	ErrBadPublicKey = pkgerrors.BadPublicKey

	// ErrBadCSR indicates an invalid certificate signing request.
	ErrBadCSR = pkgerrors.BadCSR

	// ErrAlreadyRevoked indicates a certificate was already revoked.
	ErrAlreadyRevoked = pkgerrors.AlreadyRevoked

	// ErrBadRevocationReason indicates an invalid revocation reason.
	ErrBadRevocationReason = pkgerrors.BadRevocationReason

	// ErrUnsupportedContact indicates an unsupported contact URL scheme.
	ErrUnsupportedContact = pkgerrors.UnsupportedContact

	// ErrUnknownSerial indicates the certificate serial is not found.
	ErrUnknownSerial = pkgerrors.UnknownSerial

	// ErrConflict indicates a resource conflict.
	ErrConflict = pkgerrors.Conflict

	// ErrInvalidProfile indicates an invalid certificate profile.
	ErrInvalidProfile = pkgerrors.InvalidProfile

	// ErrAlreadyReplaced indicates a certificate replacement already exists.
	ErrAlreadyReplaced = pkgerrors.AlreadyReplaced

	// ErrBadSignatureAlgorithm indicates an unsupported signature algorithm.
	ErrBadSignatureAlgorithm = pkgerrors.BadSignatureAlgorithm

	// ErrAccountDoesNotExist indicates the account does not exist.
	ErrAccountDoesNotExist = pkgerrors.AccountDoesNotExist

	// ErrBadNonce indicates an invalid or expired nonce.
	ErrBadNonce = pkgerrors.BadNonce

	// ErrExternalAccountRequired indicates external account binding is required.
	ErrExternalAccountRequired = pkgerrors.ExternalAccountRequired

	// ErrIncorrectResponse indicates an incorrect challenge response.
	ErrIncorrectResponse = pkgerrors.IncorrectResponse

	// ErrInvalidContact indicates invalid contact information.
	ErrInvalidContact = pkgerrors.InvalidContact

	// ErrTLSError indicates a TLS-related failure.
	ErrTLSError = pkgerrors.TLSError

	// ErrUnsupportedIdentifier indicates an unsupported identifier type.
	ErrUnsupportedIdentifier = pkgerrors.UnsupportedIdentifier

	// ErrUserActionRequired indicates user action is required.
	ErrUserActionRequired = pkgerrors.UserActionRequired

	// ErrAccountExists indicates the account already exists.
	ErrAccountExists = pkgerrors.AccountExists

	// ErrCompoundError indicates multiple sub-errors.
	ErrCompoundError = pkgerrors.CompoundError

	// ErrBadAttestationStatement indicates an invalid TPM attestation statement.
	ErrBadAttestationStatement = pkgerrors.BadAttestationStatement

	// ErrStorageFailure indicates a storage backend failure.
	ErrStorageFailure = pkgerrors.StorageFailure

	// ErrSerializationFailure indicates a serialization failure.
	ErrSerializationFailure = pkgerrors.SerializationFailure

	// ErrTenantNotFound indicates the tenant does not exist.
	ErrTenantNotFound = pkgerrors.TenantNotFound

	// ErrTenantSuspended indicates the tenant is suspended.
	ErrTenantSuspended = pkgerrors.TenantSuspended

	// ErrTenantQuotaExceeded indicates the tenant quota was exceeded.
	ErrTenantQuotaExceeded = pkgerrors.TenantQuotaExceeded

	// ErrCertificateExpired indicates the certificate has expired.
	ErrCertificateExpired = pkgerrors.CertificateExpired

	// ErrCertificateNotYetValid indicates the certificate is not yet valid.
	ErrCertificateNotYetValid = pkgerrors.CertificateNotYetValid

	// ErrSigningFailure indicates a signing operation failed.
	ErrSigningFailure = pkgerrors.SigningFailure

	// ErrVerificationFailure indicates a verification operation failed.
	ErrVerificationFailure = pkgerrors.VerificationFailure

	// ErrKeyGenerationFailure indicates a key generation failure.
	ErrKeyGenerationFailure = pkgerrors.KeyGenerationFailure

	// ErrTPMError indicates a TPM operation failure.
	ErrTPMError = pkgerrors.TPMError

	// ErrOCSPFailure indicates an OCSP operation failure.
	ErrOCSPFailure = pkgerrors.OCSPFailure

	// ErrCRLFailure indicates a CRL operation failure.
	ErrCRLFailure = pkgerrors.CRLFailure

	// ErrPolicyViolation indicates a policy violation.
	ErrPolicyViolation = pkgerrors.PolicyViolation

	// ErrAuthorizationExpired indicates the authorization has expired.
	ErrAuthorizationExpired = pkgerrors.AuthorizationExpired

	// ErrChallengeTimeout indicates a challenge validation timeout.
	ErrChallengeTimeout = pkgerrors.ChallengeTimeout

	// ErrInvalidToken indicates an invalid token.
	ErrInvalidToken = pkgerrors.InvalidToken
)
