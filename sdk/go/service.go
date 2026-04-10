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

// This file re-exports the XKMS service facade from pkg/xkms so that
// consumers (e.g., go-dragondb, go-trusted-ca) can initialize and manage
// the XKMS service through the SDK instead of importing internal packages.

package xkms

import (
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ========================================================================
// Type Aliases (fully compatible with pkg/xkms types)
// ========================================================================

// ServiceBackend is the unified interface for cryptographic key and certificate
// management. It composes a key provider with certificate storage.
// Aliased from the internal Backend interface so consumers use the SDK package.
//
// Note: This is named ServiceBackend to avoid conflict with the SDK's existing
// BackendConfig type, which configures the client transport layer.
type ServiceBackend = pkgxkms.Backend

// ServiceConfig configures the XKMS service with backend mappings and a
// default backend name.
type ServiceConfig = pkgxkms.ServiceConfig

// XKMSService is the singleton service that provides a simplified API for
// XKMS operations across multiple backends.
type XKMSService = pkgxkms.XKMSService

// SignOptions contains options for signing operations, including the hash
// algorithm and optional RSA-PSS parameters.
type SignOptions = pkgxkms.SignOptions

// ServiceBackendInfo contains information about a registered backend,
// including its type, hardware-backed status, and capabilities.
type ServiceBackendInfo = pkgxkms.BackendInfo

// ServiceBackendConfig provides configuration for creating a new Backend
// instance from a key provider and certificate storage backend.
//
// Note: This is named ServiceBackendConfig to avoid conflict with the SDK's
// existing BackendConfig type, which configures the client transport layer.
type ServiceBackendConfig = pkgxkms.BackendConfig

// AutoConfig configures automatic backend initialization via the registry.
type AutoConfig = pkgxkms.AutoConfig

// KeyID represents a unified key identifier in the extended format
// "backend:type:algo:keyname".
type KeyID = pkgxkms.KeyID

// BackendType represents the type of key storage backend in the registry.
type ServiceBackendType = pkgxkms.BackendType

// BackendFactory creates a KeyProvider from configuration.
type ServiceBackendFactory = pkgxkms.BackendFactory

// ========================================================================
// Backend Type Constants
// ========================================================================

const (
	// ServiceBackendSoftware represents the pure software backend.
	ServiceBackendSoftware = pkgxkms.BackendSoftware

	// ServiceBackendTPM2 represents the TPM 2.0 hardware backend.
	ServiceBackendTPM2 = pkgxkms.BackendTPM2

	// ServiceBackendPKCS11 represents external PKCS#11/HSM backend.
	ServiceBackendPKCS11 = pkgxkms.BackendPKCS11

	// ServiceBackendPKCS8 represents the PKCS#8 file-based backend.
	ServiceBackendPKCS8 = pkgxkms.BackendPKCS8

	// ServiceBackendAWSKMS represents AWS Key Management Service backend.
	ServiceBackendAWSKMS = pkgxkms.BackendAWSKMS

	// ServiceBackendGCPKMS represents Google Cloud KMS backend.
	ServiceBackendGCPKMS = pkgxkms.BackendGCPKMS

	// ServiceBackendAzureKV represents Azure Key Vault backend.
	ServiceBackendAzureKV = pkgxkms.BackendAzureKV

	// ServiceBackendVault represents HashiCorp Vault backend.
	ServiceBackendVault = pkgxkms.BackendVault

	// ServiceBackendQuantum represents post-quantum cryptography backend.
	ServiceBackendQuantum = pkgxkms.BackendQuantum

	// ServiceBackendFROST represents the FROST threshold signing backend.
	ServiceBackendFROST = pkgxkms.BackendFROST

	// ServiceBackendSymmetric represents the symmetric encryption backend.
	ServiceBackendSymmetric = pkgxkms.BackendSymmetric
)

// ========================================================================
// Service Lifecycle Functions
// ========================================================================

var (
	// ServiceInitialize sets up the XKMS service singleton. This should be
	// called once at application startup. Subsequent calls are no-ops due
	// to sync.Once semantics.
	ServiceInitialize = pkgxkms.Initialize

	// ServiceReset clears the service singleton and closes all backends.
	// Primarily useful for testing.
	ServiceReset = pkgxkms.Reset

	// ServiceIsInitialized returns whether the service has been initialized.
	ServiceIsInitialized = pkgxkms.IsInitialized

	// ServiceClose closes all backends. Should be called at application shutdown.
	ServiceClose = pkgxkms.Close

	// ServiceAutoInitialize discovers compiled-in backends via the registry
	// and initializes the XKMS service using registered factory functions.
	ServiceAutoInitialize = pkgxkms.AutoInitialize
)

// ========================================================================
// Backend Discovery Functions
// ========================================================================

var (
	// ServiceDefaultBackend returns the default backend.
	ServiceDefaultBackend = pkgxkms.DefaultBackend

	// ServiceBackendFor returns the appropriate backend for the given key
	// attributes. If StoreType is specified in attrs, that backend is returned.
	// Otherwise, the default backend is returned.
	ServiceBackendFor = pkgxkms.BackendFor

	// ServiceGetBackend returns a specific backend by name.
	ServiceGetBackend = pkgxkms.GetBackend

	// ServiceBackends returns the names of all registered backends.
	ServiceBackends = pkgxkms.Backends
)

// ========================================================================
// Key Operations
// ========================================================================

var (
	// ServiceGenerateKey generates a new key with the given attributes.
	// Uses BackendFor(attrs) to resolve the correct backend based on StoreType.
	ServiceGenerateKey = pkgxkms.GenerateKey

	// ServiceGenerateKeyWithBackend generates a new key on a specific backend.
	ServiceGenerateKeyWithBackend = pkgxkms.GenerateKeyWithBackend

	// ServiceKey retrieves a key by its attributes.
	ServiceKey = pkgxkms.Key

	// ServiceKeyByID retrieves a key by its key ID (kid).
	// Format: "backend:type:algo:keyname" with optional segments.
	ServiceKeyByID = pkgxkms.KeyByID

	// ServiceDeleteKey deletes a key by its attributes.
	ServiceDeleteKey = pkgxkms.DeleteKey

	// ServiceDeleteKeyByID deletes a key by its key ID (kid).
	ServiceDeleteKeyByID = pkgxkms.DeleteKeyByID

	// ServiceListKeys lists all keys across all backends or from a specific backend.
	ServiceListKeys = pkgxkms.ListKeys

	// ServiceRotateKey rotates (replaces) an existing key with a new one.
	ServiceRotateKey = pkgxkms.RotateKey
)

// ========================================================================
// Crypto Operations
// ========================================================================

var (
	// ServiceSigner returns a crypto.Signer for the specified key attributes.
	ServiceSigner = pkgxkms.Signer

	// ServiceSignerByID returns a signer for the specified key ID (kid).
	ServiceSignerByID = pkgxkms.SignerByID

	// ServiceDecrypter returns a crypto.Decrypter for the specified key attributes.
	ServiceDecrypter = pkgxkms.Decrypter

	// ServiceDecrypterByID returns a decrypter for the specified key ID (kid).
	ServiceDecrypterByID = pkgxkms.DecrypterByID

	// ServiceSign signs data using the specified key.
	ServiceSign = pkgxkms.Sign

	// ServiceVerify verifies a signature against data using the specified key.
	ServiceVerify = pkgxkms.Verify

	// ServiceEncrypt encrypts data using a symmetric key.
	ServiceEncrypt = pkgxkms.Encrypt

	// ServiceDecrypt decrypts data using a symmetric key.
	ServiceDecrypt = pkgxkms.Decrypt
)

// ========================================================================
// Certificate Operations
// ========================================================================

var (
	// ServiceCertificate retrieves a certificate by key attributes.
	ServiceCertificate = pkgxkms.Certificate

	// ServiceCertificateByID retrieves a certificate by key ID (kid).
	ServiceCertificateByID = pkgxkms.CertificateByID

	// ServiceSaveCertificate saves a certificate using key attributes.
	ServiceSaveCertificate = pkgxkms.SaveCertificate

	// ServiceSaveCertificateByID saves a certificate by key ID.
	ServiceSaveCertificateByID = pkgxkms.SaveCertificateByID

	// ServiceDeleteCertificate deletes a certificate by key attributes.
	ServiceDeleteCertificate = pkgxkms.DeleteCertificate

	// ServiceDeleteCertificateByID deletes a certificate by key ID (kid).
	ServiceDeleteCertificateByID = pkgxkms.DeleteCertificateByID

	// ServiceCertificateChain retrieves a certificate chain by key attributes.
	ServiceCertificateChain = pkgxkms.CertificateChain

	// ServiceCertificateChainByID retrieves a certificate chain by key ID (kid).
	ServiceCertificateChainByID = pkgxkms.CertificateChainByID

	// ServiceSaveCertificateChain saves a certificate chain using key attributes.
	ServiceSaveCertificateChain = pkgxkms.SaveCertificateChain

	// ServiceSaveCertificateChainByID saves a certificate chain by key ID (kid).
	ServiceSaveCertificateChainByID = pkgxkms.SaveCertificateChainByID

	// ServiceListCertificates lists all certificate IDs across all backends
	// or from a specific backend.
	ServiceListCertificates = pkgxkms.ListCertificates

	// ServiceCertificateExists checks if a certificate exists for the given
	// key attributes.
	ServiceCertificateExists = pkgxkms.CertificateExists

	// ServiceCertificateExistsByID checks if a certificate exists for the
	// given key ID (kid).
	ServiceCertificateExistsByID = pkgxkms.CertificateExistsByID

	// ServiceTLSCertificate returns a complete tls.Certificate for the given
	// key attributes.
	ServiceTLSCertificate = pkgxkms.TLSCertificate

	// ServiceTLSCertificateByID returns a complete tls.Certificate by key ID (kid).
	ServiceTLSCertificateByID = pkgxkms.TLSCertificateByID
)

// ========================================================================
// Seal Operations
// ========================================================================

var (
	// ServiceSeal encrypts/protects data using the default backend's
	// sealing mechanism.
	ServiceSeal = pkgxkms.Seal

	// ServiceSealWithBackend seals data using a specific backend.
	ServiceSealWithBackend = pkgxkms.SealWithBackend

	// ServiceUnseal decrypts/recovers data that was previously sealed.
	ServiceUnseal = pkgxkms.Unseal

	// ServiceUnsealWithBackend unseals data using a specific backend.
	ServiceUnsealWithBackend = pkgxkms.UnsealWithBackend

	// ServiceCanSeal returns true if the specified backend supports sealing
	// operations. If backendName is empty, checks the default backend.
	ServiceCanSeal = pkgxkms.CanSeal
)

// ========================================================================
// Import/Export Operations
// ========================================================================

var (
	// ServiceGetImportParameters retrieves parameters needed to import a key
	// into a backend.
	ServiceGetImportParameters = pkgxkms.GetImportParameters

	// ServiceWrapKey wraps key material for secure transport using the
	// specified parameters.
	ServiceWrapKey = pkgxkms.WrapKey

	// ServiceUnwrapKey unwraps key material that was previously wrapped.
	ServiceUnwrapKey = pkgxkms.UnwrapKey

	// ServiceImportKey imports externally generated key material into a backend.
	ServiceImportKey = pkgxkms.ImportKey

	// ServiceExportKey exports a key in wrapped form for secure transport.
	ServiceExportKey = pkgxkms.ExportKey

	// ServiceCopyKey copies a key from one backend to another.
	ServiceCopyKey = pkgxkms.CopyKey
)

// ========================================================================
// Symmetric Key Operations
// ========================================================================

var (
	// ServiceGenerateSymmetricKey generates a new symmetric key.
	ServiceGenerateSymmetricKey = pkgxkms.GenerateSymmetricKey

	// ServiceGetSymmetricKey retrieves an existing symmetric key.
	ServiceGetSymmetricKey = pkgxkms.GetSymmetricKey
)

// ========================================================================
// Backend Information
// ========================================================================

var (
	// ServiceGetBackendInfo returns information about a specific backend.
	ServiceGetBackendInfo = pkgxkms.GetBackendInfo

	// ServiceGetBackendCapabilities returns the capabilities of a specific backend.
	ServiceGetBackendCapabilities = pkgxkms.GetBackendCapabilities
)

// ========================================================================
// Key ID Operations
// ========================================================================

var (
	// ServiceParseKeyID parses an extended Key ID into its components.
	// Format: backend:type:algo:keyname
	ServiceParseKeyID = pkgxkms.ParseKeyID

	// ServiceNewKeyID creates a new KeyID from components.
	ServiceNewKeyID = pkgxkms.NewKeyID

	// ServiceValidateKeyID validates a Key ID format without retrieving the key.
	ServiceValidateKeyID = pkgxkms.ValidateKeyID

	// ServiceParseKeyIDToAttributes parses a Key ID string and returns
	// KeyAttributes populated with the parsed values.
	ServiceParseKeyIDToAttributes = pkgxkms.ParseKeyIDToAttributes

	// ServiceParseCertificateID parses a certificate ID string into KeyAttributes.
	ServiceParseCertificateID = pkgxkms.ParseCertificateID
)

// ========================================================================
// Registry Operations
// ========================================================================

var (
	// ServiceSupportedBackends returns a slice of all backends compiled
	// into the binary.
	ServiceSupportedBackends = pkgxkms.SupportedBackends

	// ServiceIsBackendSupported returns true if the specified backend was
	// compiled into the binary and is available for use.
	ServiceIsBackendSupported = pkgxkms.IsBackendSupported

	// ServiceBackendCount returns the number of available backends.
	ServiceBackendCount = pkgxkms.BackendCount

	// ServiceRegisterBackend registers a backend as available.
	ServiceRegisterBackend = pkgxkms.RegisterBackend

	// ServiceRegisterBackendFactory registers a factory function for creating
	// a backend's KeyProvider.
	ServiceRegisterBackendFactory = pkgxkms.RegisterBackendFactory

	// ServiceGetBackendFactory returns the factory function for the specified
	// backend type.
	ServiceGetBackendFactory = pkgxkms.GetBackendFactory
)

// ========================================================================
// Backend Construction
// ========================================================================

// NewServiceBackend creates a new Backend instance with the provided
// configuration. This composes a key provider with certificate storage.
var NewServiceBackend = pkgxkms.New

// ========================================================================
// PIV Operations
// ========================================================================

var (
	// ServiceListPIVSlots returns the status of all PIV slots for the specified backend.
	ServiceListPIVSlots = pkgxkms.ListPIVSlots

	// ServiceGetPIVCertificate retrieves a certificate from a PIV slot.
	ServiceGetPIVCertificate = pkgxkms.GetPIVCertificate

	// ServiceStorePIVCertificate stores a certificate in a PIV slot.
	ServiceStorePIVCertificate = pkgxkms.StorePIVCertificate

	// ServiceDeletePIVCertificate removes a certificate from a PIV slot.
	ServiceDeletePIVCertificate = pkgxkms.DeletePIVCertificate

	// ServiceGeneratePIVKey generates a new key pair in a PIV slot.
	ServiceGeneratePIVKey = pkgxkms.GeneratePIVKey

	// ServiceImportPIVCertificate imports a certificate into a PIV slot.
	ServiceImportPIVCertificate = pkgxkms.ImportPIVCertificate

	// ServiceExportPIVCertificate exports a certificate from a PIV slot.
	ServiceExportPIVCertificate = pkgxkms.ExportPIVCertificate

	// ServiceGeneratePIVCSR generates a certificate signing request for a PIV slot key.
	ServiceGeneratePIVCSR = pkgxkms.GeneratePIVCSR

	// ServiceResetPIV clears the PIV manager singleton. Primarily useful for testing.
	ServiceResetPIV = pkgxkms.ResetPIV
)

// PIV error sentinels re-exported from pkg/xkms.
var (
	// ServiceErrPIVNotInitialized is returned when PIV manager is not initialized.
	ServiceErrPIVNotInitialized = pkgxkms.ErrPIVNotInitialized

	// ServiceErrPIVBackendNotFound is returned when the specified PIV backend is not found.
	ServiceErrPIVBackendNotFound = pkgxkms.ErrPIVBackendNotFound

	// ServiceErrPIVInvalidAlgorithm is returned when an invalid algorithm is specified.
	ServiceErrPIVInvalidAlgorithm = pkgxkms.ErrPIVInvalidAlgorithm

	// ServiceErrPIVInvalidSlot is returned when an invalid PIV slot is specified.
	ServiceErrPIVInvalidSlot = pkgxkms.ErrPIVInvalidSlot

	// ServiceErrPIVInvalidFormat is returned when an invalid certificate format is specified.
	ServiceErrPIVInvalidFormat = pkgxkms.ErrPIVInvalidFormat

	// ServiceErrPIVKeyNotFound is returned when no key exists in the specified slot.
	ServiceErrPIVKeyNotFound = pkgxkms.ErrPIVKeyNotFound
)

// ========================================================================
// Version
// ========================================================================

// ServiceVersion returns the XKMS library version string.
var ServiceVersion = pkgxkms.Version

// ========================================================================
// Algorithm Discovery
// ========================================================================

// ServiceDiscoverAlgorithms returns all supported algorithms based on
// compiled backends and their capabilities.
var ServiceDiscoverAlgorithms = pkgxkms.DiscoverAlgorithms

// ServiceBuildAlgorithmsResponse builds an AlgorithmsResponse from the
// given backends and capabilities provider. This is useful for testing
// or when the caller wants to supply custom backends.
var ServiceBuildAlgorithmsResponse = pkgxkms.BuildAlgorithmsResponse

// ========================================================================
// Additional Error Sentinels
// ========================================================================

// ServiceErrOperationNotSupported indicates the operation is not supported.
var ServiceErrOperationNotSupported = pkgxkms.ErrOperationNotSupported
