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

package xkms

import (
	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
)

// ---------------------------------------------------------------------------
// Interface aliases
// ---------------------------------------------------------------------------

// XKMSCA is the core Certificate Authority interface that provides certificate
// issuance, signing, revocation, and management operations.
type XKMSCA = pkgca.XKMSCA

// BasicCA is an alias for XKMSCA for backward compatibility.
type BasicCA = pkgca.BasicCA

// TCGCA extends XKMSCA with TCG Trusted Computing certificate operations
// for TPM device identity (IDevID), attestation key (AK), and endorsement
// key (EK) per TCG TPM 2.0 Keys for Device Identity and Attestation.
type TCGCA = pkgca.TCGCA

// ProfileProvider provides certificate profile generation.
type ProfileProvider = pkgca.ProfileProvider

// ProfileRegistry manages certificate profile registrations.
type ProfileRegistry = pkgca.ProfileRegistry

// CABundler creates CA certificate bundles.
type CABundler = pkgca.CABundler

// CertificateProvider supplies certificates for bundle creation.
type CertificateProvider = pkgca.CertificateProvider

// ---------------------------------------------------------------------------
// Struct and concrete type aliases
// ---------------------------------------------------------------------------

// XKMSCAParams holds the parameters for creating a new XKMSCA instance.
type XKMSCAParams = pkgca.Params

// XKMSCAMultiIdentityParams holds parameters for creating a CA from
// a MultiIdentityCAConfig.
type XKMSCAMultiIdentityParams = pkgca.MultiIdentityParams

// XKMSCAConfig configures a single CA identity with flat configuration.
type XKMSCAConfig = pkgca.CAConfig

// XKMSCAMultiIdentityConfig configures a CA with one or more identity
// configurations for different certificate purposes (root and intermediate CAs).
type XKMSCAMultiIdentityConfig = pkgca.MultiIdentityCAConfig

// XKMSCAIdentity represents a certificate identity configuration including
// subject, SANs, validity, and key algorithm settings.
type XKMSCAIdentity = pkgca.Identity

// XKMSCASubject represents an X.509 certificate subject with standard fields.
type XKMSCASubject = pkgca.Subject

// XKMSCASubjectAlternativeNames holds Subject Alternative Name extensions.
type XKMSCASubjectAlternativeNames = pkgca.SubjectAlternativeNames

// XKMSCAHardwareModuleInfo holds hardware module identification for TPM/HSM
// certificate SAN extensions per RFC 4108.
type XKMSCAHardwareModuleInfo = pkgca.HardwareModuleInfo

// XKMSCACertificateRequest contains parameters for requesting a certificate
// from the CA, including subject, SANs, validity, key usage, and TCG fields.
type XKMSCACertificateRequest = pkgca.CertificateRequest

// XKMSCAIssuedCertificate contains the result of a successful certificate
// issuance including the certificate, private key, and chain information.
type XKMSCAIssuedCertificate = pkgca.IssuedCertificate

// XKMSCASignOptions contains optional parameters for certificate signing.
type XKMSCASignOptions = pkgca.SignOptions

// XKMSCARevocationInfo contains information about a revoked certificate.
type XKMSCARevocationInfo = pkgca.RevocationInfo

// DefaultCABundler is the default CA bundle implementation.
type DefaultCABundler = pkgca.DefaultCABundler

// SimpleCertificate is a simple certificate wrapper for bundle operations.
type SimpleCertificate = pkgca.SimpleCertificate

// ConfigBuilder builds MultiIdentityCAConfig programmatically.
type ConfigBuilder = pkgca.ConfigBuilder

// ProfileBuilder builds certificate profiles programmatically.
type ProfileBuilder = pkgca.ProfileBuilder

// RevocationManager manages certificate revocation operations.
type RevocationManager = pkgca.RevocationManager

// TLSConfigOptions configures TLS certificate generation.
type TLSConfigOptions = pkgca.TLSConfigOptions

// TLSCertificateInfo holds information about a TLS certificate.
type TLSCertificateInfo = pkgca.TLSCertificateInfo

// ---------------------------------------------------------------------------
// CA error types
// ---------------------------------------------------------------------------

// CSRSigningError is returned when CSR signing fails.
type CSRSigningError = pkgca.CSRSigningError

// PEMDecodeError is returned when PEM decoding fails.
type PEMDecodeError = pkgca.PEMDecodeError

// CSRParseError is returned when CSR parsing fails.
type CSRParseError = pkgca.CSRParseError

// CSRSignatureError is returned when CSR signature verification fails.
type CSRSignatureError = pkgca.CSRSignatureError

// CertificateCreationError is returned when certificate creation fails.
type CertificateCreationError = pkgca.CertificateCreationError

// CertificateStoreError is returned when certificate store operations fail.
type CertificateStoreError = pkgca.CertificateStoreError

// RevocationError is returned when a revocation operation fails.
type RevocationError = pkgca.RevocationError

// CRLGenerationError is returned when CRL generation fails.
type CRLGenerationError = pkgca.CRLGenerationError

// HybridCertError is returned when hybrid certificate operations fail.
type HybridCertError = pkgca.HybridCertError

// HybridVerificationError is returned when hybrid certificate verification fails.
type HybridVerificationError = pkgca.HybridVerificationError

// ---------------------------------------------------------------------------
// TCG enrollment types
// ---------------------------------------------------------------------------

// TCGEnrollmentResult contains the output of a TCG-CSR-IDEVID enrollment.
// After receiving this result, the caller must complete the ActivateCredential
// challenge/response before delivering the certificates to the device.
type TCGEnrollmentResult = pkgca.TCGEnrollmentResult

// ---------------------------------------------------------------------------
// TCG OID types
// ---------------------------------------------------------------------------

// TCGTPMSpecification represents a TPM specification version per TCG spec.
type TCGTPMSpecification = pkgca.TCGTPMSpecification

// TCGHardwareModuleName represents the SAN otherName for hardware module identity.
type TCGHardwareModuleName = pkgca.TCGHardwareModuleName

// TCGPermanentIdentifier represents a permanent identifier SAN extension.
type TCGPermanentIdentifier = pkgca.TCGPermanentIdentifier

// TCGTenantID represents a tenant identifier for multi-tenant CA operations.
type TCGTenantID = pkgca.TCGTenantID

// TCGAttribute represents a TCG certificate attribute (OID + UTF8 value).
type TCGAttribute = pkgca.TCGAttribute

// ---------------------------------------------------------------------------
// Constructor function re-exports
// ---------------------------------------------------------------------------

// NewXKMSCA creates a new XKMSCA instance with the given parameters.
var NewXKMSCA = pkgca.New

// NewXKMSCAFromMultiIdentityConfig creates a new XKMSCA instance from a
// MultiIdentityCAConfig. This derives the flat CAConfig and KeyAttributes
// from the issuing identity in the multi-identity configuration.
var NewXKMSCAFromMultiIdentityConfig = pkgca.NewFromMultiIdentityConfig

// ---------------------------------------------------------------------------
// TCG OID extension builder function re-exports
// ---------------------------------------------------------------------------

// CreateTPMSpecificationExtension creates a TCG TPM specification extension.
var CreateTPMSpecificationExtension = pkgca.CreateTPMSpecificationExtension

// ParseTPMSpecificationExtension parses a TCG TPM specification extension.
var ParseTPMSpecificationExtension = pkgca.ParseTPMSpecificationExtension

// CreateHardwareModuleNameExtension creates a hardware module name SAN extension.
var CreateHardwareModuleNameExtension = pkgca.CreateHardwareModuleNameExtension

// ParseHardwareModuleNameExtension parses a hardware module name SAN extension.
var ParseHardwareModuleNameExtension = pkgca.ParseHardwareModuleNameExtension

// CreatePermanentIdentifierExtension creates a permanent identifier extension.
var CreatePermanentIdentifierExtension = pkgca.CreatePermanentIdentifierExtension

// ParsePermanentIdentifierExtension parses a permanent identifier extension.
var ParsePermanentIdentifierExtension = pkgca.ParsePermanentIdentifierExtension

// CreateTenantIDExtension creates a tenant identifier extension.
var CreateTenantIDExtension = pkgca.CreateTenantIDExtension

// ---------------------------------------------------------------------------
// CA error re-exports
// ---------------------------------------------------------------------------

var (
	// ErrCertificateAlreadyExists indicates a certificate with the same
	// subject already exists in the certificate store.
	ErrCertificateAlreadyExists = pkgca.ErrCertificateAlreadyExists
)

// ---------------------------------------------------------------------------
// TCG error re-exports
// ---------------------------------------------------------------------------

var (
	// ErrCATPMNotConfigured indicates SetTPM has not been called before enrollment.
	ErrCATPMNotConfigured = pkgca.ErrTPMNotConfigured

	// ErrCATCGCSRVerificationFailed indicates TCG-CSR-IDEVID verification failed.
	ErrCATCGCSRVerificationFailed = pkgca.ErrTCGCSRVerificationFailed

	// ErrCATCGMakeCredentialFailed indicates MakeCredentialWithExternalEK failed.
	ErrCATCGMakeCredentialFailed = pkgca.ErrTCGMakeCredentialFailed

	// ErrCATCGMissingEKCert indicates the EK certificate is missing from the CSR.
	ErrCATCGMissingEKCert = pkgca.ErrTCGMissingEKCert

	// ErrCATCGInvalidEKCert indicates the EK certificate could not be parsed.
	ErrCATCGInvalidEKCert = pkgca.ErrTCGInvalidEKCert

	// ErrCATCGInvalidPublicKey indicates the public key is nil or unsupported.
	ErrCATCGInvalidPublicKey = pkgca.ErrTCGInvalidPublicKey

	// ErrCATCGCertIssuanceFailed indicates TCG certificate creation failed.
	ErrCATCGCertIssuanceFailed = pkgca.ErrTCGCertIssuanceFailed

	// ErrCATCGCSRUnmarshalFailed indicates the packed CSR could not be unmarshaled.
	ErrCATCGCSRUnmarshalFailed = pkgca.ErrTCGCSRUnmarshalFailed
)
