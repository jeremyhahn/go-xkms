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

// TrustedCA is the core Certificate Authority interface that provides certificate
// issuance, signing, revocation, and management operations.
type TrustedCA = pkgca.TrustedCA

// TCGCA extends TrustedCA with TCG Trusted Computing certificate operations
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

// TrustedCAParams holds the parameters for creating a new TrustedCA instance.
type TrustedCAParams = pkgca.Params

// TrustedCAMultiIdentityParams holds parameters for creating a CA from
// a MultiIdentityCAConfig.
type TrustedCAMultiIdentityParams = pkgca.MultiIdentityParams

// TrustedCAConfig configures a single CA identity with flat configuration.
type TrustedCAConfig = pkgca.CAConfig

// TrustedCAMultiIdentityConfig configures a CA with one or more identity
// configurations for different certificate purposes (root and intermediate CAs).
type TrustedCAMultiIdentityConfig = pkgca.MultiIdentityCAConfig

// TrustedCAIdentity represents a certificate identity configuration including
// subject, SANs, validity, and key algorithm settings.
type TrustedCAIdentity = pkgca.Identity

// TrustedCASubject represents an X.509 certificate subject with standard fields.
type TrustedCASubject = pkgca.Subject

// TrustedCASubjectAlternativeNames holds Subject Alternative Name extensions.
type TrustedCASubjectAlternativeNames = pkgca.SubjectAlternativeNames

// TrustedCAHardwareModuleInfo holds hardware module identification for TPM/HSM
// certificate SAN extensions per RFC 4108.
type TrustedCAHardwareModuleInfo = pkgca.HardwareModuleInfo

// TrustedCACertificateRequest contains parameters for requesting a certificate
// from the CA, including subject, SANs, validity, key usage, and TCG fields.
type TrustedCACertificateRequest = pkgca.CertificateRequest

// TrustedCAIssuedCertificate contains the result of a successful certificate
// issuance including the certificate, private key, and chain information.
type TrustedCAIssuedCertificate = pkgca.IssuedCertificate

// TrustedCASignOptions contains optional parameters for certificate signing.
type TrustedCASignOptions = pkgca.SignOptions

// TrustedCARevocationInfo contains information about a revoked certificate.
type TrustedCARevocationInfo = pkgca.RevocationInfo

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

// TCGNetworkZone represents the platform network zone assigned to a
// certificate subject, evaluated by the SDN policy engine at enforcement time.
type TCGNetworkZone = pkgca.TCGNetworkZone

// TCGAttribute represents a TCG certificate attribute (OID + UTF8 value).
type TCGAttribute = pkgca.TCGAttribute

// ---------------------------------------------------------------------------
// Constructor function re-exports
// ---------------------------------------------------------------------------

// NewTrustedCA creates a new TrustedCA instance with the given parameters.
var NewTrustedCA = pkgca.New

// NewTrustedCAFromMultiIdentityConfig creates a new TrustedCA instance from a
// MultiIdentityCAConfig. This derives the flat CAConfig and KeyAttributes
// from the issuing identity in the multi-identity configuration.
var NewTrustedCAFromMultiIdentityConfig = pkgca.NewFromMultiIdentityConfig

// NewCA builds a root+intermediate TrustedCA pair from a Params carrying one
// or two Identity entries. Identity[0] is the root; Identity[1] (if present)
// is the intermediate, signed by the root. When only one identity is
// provided, the intermediate return value is nil.
var NewCA = pkgca.NewCA

// NewParentCA creates only the root TrustedCA from Params.Identity[0]. The
// returned CA is not initialized; callers invoke Init() or Load().
var NewParentCA = pkgca.NewParentCA

// NewIntermediateCA creates the intermediate TrustedCA from
// Params.Identity[1] signed by the given parent. The parent must be
// initialized.
var NewIntermediateCA = pkgca.NewIntermediateCA

// TrustedCAKeyStoreFactoryFunc resolves a KeyStore per-CA CN.
type TrustedCAKeyStoreFactoryFunc = pkgca.KeyStoreFactoryFunc

// TrustedCACertStoreFactoryFunc resolves a CertStore per-CA CN.
type TrustedCACertStoreFactoryFunc = pkgca.CertStoreFactoryFunc

// TrustedCAObjectStoreFactoryFunc resolves an object store per-CA CN.
type TrustedCAObjectStoreFactoryFunc = pkgca.ObjectStoreFactoryFunc

// TrustedCAKeystoresConfig holds per-backend keystore configuration for one CA
// identity (root or intermediate). When set on an Identity, the CA routes each
// key in Keys[*] to the backend matching its StoreType. Aliased to
// pkg/ca.CAKeystoresConfig.
type TrustedCAKeystoresConfig = pkgca.CAKeystoresConfig

// TrustedCAKeystoreSoftwareConfig carries per-identity configuration for the
// software (PKCS#8) keystore backend. Aliased to pkg/ca.CAKeystoreSoftwareConfig.
type TrustedCAKeystoreSoftwareConfig = pkgca.CAKeystoreSoftwareConfig

// TrustedCAKeystoreTPM2Config carries per-identity configuration for the tpm2
// keystore backend (SRK handle, SRK auth, platform policy). Aliased to
// pkg/ca.CAKeystoreTPM2Config.
type TrustedCAKeystoreTPM2Config = pkgca.CAKeystoreTPM2Config

// TrustedCAKeystorePKCS11Config carries per-identity configuration for PKCS#11
// keystore backends. Aliased to pkg/ca.CAKeystorePKCS11Config.
type TrustedCAKeystorePKCS11Config = pkgca.CAKeystorePKCS11Config

// TrustedCABackendForStoreFunc resolves an xkms.Backend for a given CA CN and
// StoreType. It is invoked once per unique StoreType found in an identity's Keys
// slice so each CA key lands in the backend matching its StoreType. Aliased to
// pkg/ca.BackendForStoreFunc.
type TrustedCABackendForStoreFunc = pkgca.BackendForStoreFunc

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

// OIDTPNetworkZone identifies the network zone extension
// (1.3.6.1.4.1.29377.101.21).
var OIDTPNetworkZone = pkgca.OIDTPNetworkZone

// CreateNetworkZoneExtension creates a network zone extension.
var CreateNetworkZoneExtension = pkgca.CreateNetworkZoneExtension

// ParseNetworkZoneExtension parses a network zone extension.
var ParseNetworkZoneExtension = pkgca.ParseNetworkZoneExtension

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

// ---------------------------------------------------------------------------
// Extended re-exports
//
// Bulk-aliased public surface from pkg/ca for downstream consumers. Grouped by
// purpose: types, constants, profile constructors, verification helpers,
// certificate predicates, key-usage checks, certificate utilities, CSR/CRL/PEM
// parsing, TPM extension builders, and defaults.
// ---------------------------------------------------------------------------

// --- Additional types ---

// CA is the concrete certificate authority implementation.
type CA = pkgca.CA

// OCSPResponder serves OCSP responses for certificate revocation queries.
type OCSPResponder = pkgca.OCSPResponder

// OCSPResponderConfig configures an OCSPResponder.
type OCSPResponderConfig = pkgca.OCSPResponderConfig

// OpenSSLConfig represents OpenSSL-compatible CA configuration.
type OpenSSLConfig = pkgca.OpenSSLConfig

// RevokeOptions configures certificate revocation behavior.
type RevokeOptions = pkgca.RevokeOptions

// SerialGenerator issues serial numbers for new certificates.
type SerialGenerator = pkgca.SerialGenerator

// Storage abstracts persistence for serial number tracking.
type Storage = pkgca.Storage

// VerifyOptions configures certificate verification behavior.
type VerifyOptions = pkgca.VerifyOptions

// VerificationError contains structured verification failure detail.
type VerificationError = pkgca.VerificationError

// QuantumAlgorithmError indicates a post-quantum algorithm error.
type QuantumAlgorithmError = pkgca.QuantumAlgorithmError

// QuantumCertError indicates a post-quantum certificate error.
type QuantumCertError = pkgca.QuantumCertError

// QuantumVerificationError indicates a post-quantum verification error.
type QuantumVerificationError = pkgca.QuantumVerificationError

// SerialGenerationError indicates a failure generating a serial number.
type SerialGenerationError = pkgca.SerialGenerationError

// SerialStorageError indicates a failure persisting serial number state.
type SerialStorageError = pkgca.SerialStorageError

// SerialValidationError indicates a failure validating a serial number.
type SerialValidationError = pkgca.SerialValidationError

// --- Constants ---

// DefaultCRLValidityDays is the default validity period (in days) for CRLs.
const DefaultCRLValidityDays = pkgca.DefaultCRLValidityDays

// --- Profile, config, and infrastructure constructors ---

var (
	NewCAProfile                     = pkgca.NewCAProfile
	NewClientProfile                 = pkgca.NewClientProfile
	NewServerProfile                 = pkgca.NewServerProfile
	NewEmailProfile                  = pkgca.NewEmailProfile
	NewCodeSigningProfile            = pkgca.NewCodeSigningProfile
	NewOCSPResponderProfile          = pkgca.NewOCSPResponderProfile
	NewTimestampingProfile           = pkgca.NewTimestampingProfile
	NewConfigBuilder                 = pkgca.NewConfigBuilder
	NewProfileBuilder                = pkgca.NewProfileBuilder
	NewRevocationManager             = pkgca.NewRevocationManager
	NewSerialGenerator               = pkgca.NewSerialGenerator
	NewBackendStorage                = pkgca.NewBackendStorage
	NewMemoryStorage                 = pkgca.NewMemoryStorage
	NewDefaultCABundler              = pkgca.NewDefaultCABundler
	NewDefaultCABundlerWithProviders = pkgca.NewDefaultCABundlerWithProviders
	NewDefaultProfileRegistry        = pkgca.NewDefaultProfileRegistry
	NewOCSPResponder                 = pkgca.NewOCSPResponder
	NewSimpleCertificate             = pkgca.NewSimpleCertificate
)

// --- Verification helpers ---

var (
	VerifyHybridCertificate           = pkgca.VerifyHybridCertificate
	VerifyTBSDeterminism              = pkgca.VerifyTBSDeterminism
	VerifyWithOptions                 = pkgca.VerifyWithOptions
	VerifyChain                       = pkgca.VerifyChain
	VerifyAgainstCRL                  = pkgca.VerifyAgainstCRL
	VerifyCertificateSignature        = pkgca.VerifyCertificateSignature
	VerifyCertificateAgainstPublicKey = pkgca.VerifyCertificateAgainstPublicKey
	ExtractTBSBytes                   = pkgca.ExtractTBSBytes
)

// --- Certificate predicates ---

var (
	IsCA                    = pkgca.IsCA
	IsSelfSigned            = pkgca.IsSelfSigned
	IsExpired               = pkgca.IsExpired
	IsNotYetValid           = pkgca.IsNotYetValid
	IsCurrentlyValid        = pkgca.IsCurrentlyValid
	IsValidAt               = pkgca.IsValidAt
	IsIssuedBy              = pkgca.IsIssuedBy
	IsCRLValid              = pkgca.IsCRLValid
	IsCRLExpired            = pkgca.IsCRLExpired
	IsCertificateInCRL      = pkgca.IsCertificateInCRL
	IsValidCSRPEM           = pkgca.IsValidCSRPEM
	IsValidRevocationReason = pkgca.IsValidRevocationReason
)

// --- Key-usage checks ---

var (
	HasKeyUsage        = pkgca.HasKeyUsage
	HasExtKeyUsage     = pkgca.HasExtKeyUsage
	HasAnyExtKeyUsage  = pkgca.HasAnyExtKeyUsage
	HasAllExtKeyUsages = pkgca.HasAllExtKeyUsages
)

// --- Certificate utilities ---

var (
	CertificateFingerprint = pkgca.CertificateFingerprint
	CertificatesMatch      = pkgca.CertificatesMatch
	SerialNumbersMatch     = pkgca.SerialNumbersMatch
	PathLength             = pkgca.PathLength
	DaysUntilExpiration    = pkgca.DaysUntilExpiration
	RemainingValidity      = pkgca.RemainingValidity
	MatchesDNSName         = pkgca.MatchesDNSName
	GetRevocationReason    = pkgca.GetRevocationReason
	RevocationReasonName   = pkgca.RevocationReasonName
	GetTLSCertificateInfo  = pkgca.GetTLSCertificateInfo
	ValidityPeriod         = pkgca.ValidityPeriod
)

// --- Certificate / CSR / OCSP creation ---

var (
	CreateCSRWithKey        = pkgca.CreateCSRWithKey
	CreateHybridCertificate = pkgca.CreateHybridCertificate
	CreateOCSPRequest       = pkgca.CreateOCSPRequest
)

// --- SAN / CRL / CSR / PEM parsing and loading ---

var (
	ApplySANsToTemplate      = pkgca.ApplySANsToTemplate
	MergeSANs                = pkgca.MergeSANs
	ParseSANsFromCSR         = pkgca.ParseSANsFromCSR
	BuildCRLTemplate         = pkgca.BuildCRLTemplate
	ParseCRLToRevocationInfo = pkgca.ParseCRLToRevocationInfo
	BuildCertPool            = pkgca.BuildCertPool
	SecureCipherSuites       = pkgca.SecureCipherSuites
	ParseCSR                 = pkgca.ParseCSR
	ParsePEMCertificateChain = pkgca.ParsePEMCertificateChain
	LoadOpenSSLConfig        = pkgca.LoadOpenSSLConfig
	LoadTLSCertificate       = pkgca.LoadTLSCertificate
	LoadTLSCertificateFiles  = pkgca.LoadTLSCertificateFiles
	TryLoadOpenSSLDefaults   = pkgca.TryLoadOpenSSLDefaults
)

// --- TPM and platform extension builders ---

var (
	CreatePlatformManufacturerExtension = pkgca.CreatePlatformManufacturerExtension
	CreatePlatformModelExtension        = pkgca.CreatePlatformModelExtension
	CreatePlatformVersionExtension      = pkgca.CreatePlatformVersionExtension
	CreateTPMManufacturerExtension      = pkgca.CreateTPMManufacturerExtension
	CreateTPMModelExtension             = pkgca.CreateTPMModelExtension
	CreateTPMVersionExtension           = pkgca.CreateTPMVersionExtension
	CreateTPFIPS140Extension            = pkgca.CreateTPFIPS140Extension
	CreateTPKeyStoreExtension           = pkgca.CreateTPKeyStoreExtension
	CreateTPIssuerKeyStoreExtension     = pkgca.CreateTPIssuerKeyStoreExtension
	CreateVerifiedTPMFixedExtension     = pkgca.CreateVerifiedTPMFixedExtension
	CreateVerifiedTPMResidencyExtension = pkgca.CreateVerifiedTPMResidencyExtension
)

// --- Defaults ---

var (
	DefaultClientExtKeyUsage                     = pkgca.DefaultClientExtKeyUsage
	DefaultClientKeyUsage                        = pkgca.DefaultClientKeyUsage
	DefaultKeyConfig                             = pkgca.DefaultKeyConfig
	DefaultMultiIdentityCAConfig                 = pkgca.DefaultMultiIdentityCAConfig
	DefaultMultiIdentityCAConfigWithIntermediate = pkgca.DefaultMultiIdentityCAConfigWithIntermediate
	DefaultOCSPResponderConfig                   = pkgca.DefaultOCSPResponderConfig
	DefaultServerClientExtKeyUsage               = pkgca.DefaultServerClientExtKeyUsage
	DefaultServerExtKeyUsage                     = pkgca.DefaultServerExtKeyUsage
	DefaultServerKeyUsage                        = pkgca.DefaultServerKeyUsage
	DefaultTLSConfig                             = pkgca.DefaultTLSConfig
)
