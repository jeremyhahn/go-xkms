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
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Core keystore errors
var (
	// ErrAlreadyInitialized indicates the xkms has already been initialized.
	ErrAlreadyInitialized = errors.New("keystore: already initialized")

	// ErrNotInitialized indicates the xkms has not been initialized.
	ErrNotInitialized = errors.New("keystore: not initialized")

	// ErrNilConfig indicates a nil configuration was provided.
	ErrNilConfig = errors.New("keystore: config cannot be nil")

	// ErrNoBackendsConfigured indicates no backends were provided in the configuration.
	ErrNoBackendsConfigured = errors.New("keystore: at least one backend must be configured")

	// ErrNoDefaultBackend is returned when no default backend is set.
	ErrNoDefaultBackend = errors.New("keystore: no default backend configured")

	// ErrDefaultBackendNotFound indicates the specified default backend was not found
	// in the configured backends map.
	ErrDefaultBackendNotFound = errors.New("keystore: default backend not found in configured backends")

	// ErrInvalidKeyType indicates an unsupported or invalid key type.
	ErrInvalidKeyType = errors.New("keystore: invalid key type")

	// ErrInvalidKeyAlgorithm indicates an unsupported or invalid key algorithm.
	ErrInvalidKeyAlgorithm = errors.New("keystore: invalid key algorithm")

	// ErrInvalidPassword indicates the provided password is invalid.
	ErrInvalidPassword = errors.New("keystore: invalid password")

	// ErrInvalidPasswordLength indicates the password does not meet length requirements.
	ErrInvalidPasswordLength = errors.New("keystore: invalid password length")

	// ErrPasswordRequired indicates a password is required but was not provided.
	ErrPasswordRequired = errors.New("keystore: password required")

	// ErrSOPinRequired indicates a security officer PIN is required.
	ErrSOPinRequired = errors.New("keystore: security officer PIN required")

	// ErrUserPinRequired indicates a user PIN is required.
	ErrUserPinRequired = errors.New("keystore: user PIN required")

	// ErrInvalidKeyAttributes indicates the key attributes are invalid or incomplete.
	ErrInvalidKeyAttributes = errors.New("keystore: invalid key attributes")

	// ErrInvalidParentAttributes indicates the parent key attributes are invalid.
	ErrInvalidParentAttributes = errors.New("keystore: invalid parent key attributes")

	// ErrInvalidRSAAttributes indicates the RSA key attributes are invalid.
	ErrInvalidRSAAttributes = errors.New("keystore: invalid RSA key attributes")

	// ErrInvalidECCAttributes indicates the ECC key attributes are invalid.
	ErrInvalidECCAttributes = errors.New("keystore: invalid ECC key attributes")

	// ErrInvalidCurve indicates an unsupported elliptic curve.
	ErrInvalidCurve = errors.New("keystore: invalid ECC curve")

	// ErrInvalidHashFunction indicates an unsupported or invalid hash function.
	ErrInvalidHashFunction = errors.New("keystore: invalid hash function")

	// ErrInvalidSignature indicates a malformed or undecodable signature value.
	ErrInvalidSignature = errors.New("keystore: invalid signature encoding")

	// ErrInvalidSignatureAlgorithm indicates an unsupported signature algorithm.
	ErrInvalidSignatureAlgorithm = errors.New("keystore: invalid signature algorithm")

	// ErrInvalidSignatureScheme indicates an invalid signature scheme.
	ErrInvalidSignatureScheme = errors.New("keystore: invalid signature scheme")

	// ErrInvalidPrivateKey indicates the private key is invalid or malformed.
	ErrInvalidPrivateKey = errors.New("keystore: invalid private key")

	// ErrInvalidPrivateKeyRSA indicates the RSA private key is invalid.
	ErrInvalidPrivateKeyRSA = errors.New("keystore: invalid RSA private key")

	// ErrInvalidPrivateKeyECDSA indicates the ECDSA private key is invalid.
	ErrInvalidPrivateKeyECDSA = errors.New("keystore: invalid ECDSA private key")

	// ErrInvalidPrivateKeyEd25519 indicates the Ed25519 private key is invalid.
	ErrInvalidPrivateKeyEd25519 = errors.New("keystore: invalid Ed25519 private key")

	// ErrInvalidOpaquePrivateKey indicates the opaque private key is invalid.
	ErrInvalidOpaquePrivateKey = errors.New("keystore: invalid opaque private key")

	// ErrInvalidPublicKeyRSA indicates the RSA public key is invalid.
	ErrInvalidPublicKeyRSA = errors.New("keystore: invalid RSA public key")

	// ErrInvalidPublicKeyECDSA indicates the ECDSA public key is invalid.
	ErrInvalidPublicKeyECDSA = errors.New("keystore: invalid ECDSA public key")

	// ErrInvalidKeyStore indicates the xkms instance is invalid.
	ErrInvalidKeyStore = errors.New("keystore: invalid key store")

	// ErrInvalidKeyID indicates the key identifier is invalid.
	ErrInvalidKeyID = errors.New("keystore: invalid key ID")

	// ErrKeyAlreadyExists indicates a key with the same identifier already exists.
	ErrKeyAlreadyExists = errors.New("keystore: key already exists")

	// ErrKeyNotFound indicates the requested key was not found.
	ErrKeyNotFound = errors.New("keystore: key not found")

	// ErrInvalidKeyPartition indicates an invalid storage partition.
	ErrInvalidKeyPartition = errors.New("keystore: invalid key partition")

	// ErrInvalidBlobName indicates an invalid blob name.
	ErrInvalidBlobName = errors.New("keystore: invalid blob name")

	// ErrInvalidEncoding indicates invalid base64 or other data encoding.
	ErrInvalidEncoding = errors.New("keystore: invalid data encoding")

	// ErrInvalidEncodingPEM indicates invalid PEM encoding.
	ErrInvalidEncodingPEM = errors.New("keystore: invalid PEM encoding")

	// ErrUnsupportedKeyAlgorithm indicates an unsupported key algorithm.
	ErrUnsupportedKeyAlgorithm = errors.New("keystore: unsupported key algorithm")

	// ErrInvalidSignerOpts indicates invalid signer options.
	ErrInvalidSignerOpts = errors.New("keystore: invalid signer opts")

	// ErrInvalidPermanentIdentifier indicates an invalid permanent identifier.
	ErrInvalidPermanentIdentifier = errors.New("keystore: invalid permanent-identifier")

	// ErrFileIntegrityCheckFailed indicates a file integrity verification failed.
	ErrFileIntegrityCheckFailed = errors.New("keystore: file integrity check failed")

	// ErrSignatureVerification indicates signature verification failed.
	ErrSignatureVerification = errors.New("keystore: signature verification failed")

	// ErrInvalidKeyedHashSecret indicates an invalid keyed hash secret.
	ErrInvalidKeyedHashSecret = errors.New("keystore: invalid keyed hash secret")

	// ErrIssuerAttributeRequired indicates the issuer common name is required.
	ErrIssuerAttributeRequired = errors.New("keystore: issuer common name attribute required")

	// ErrInvalidJOSESignatureAlgorithm indicates an invalid JOSE signature algorithm.
	ErrInvalidJOSESignatureAlgorithm = errors.New("keystore: invalid JOSE signature algorithm")

	// ErrNilCertificate indicates a nil certificate was provided.
	ErrNilCertificate = errors.New("keystore: certificate cannot be nil")

	// ErrNilPrivateKey indicates a nil private key was provided.
	ErrNilPrivateKey = errors.New("keystore: nil private key")
)

// Backend-specific errors
var (
	// ErrFileAlreadyExists indicates a file already exists in the backend.
	ErrFileAlreadyExists = errors.New("keystore: file already exists")

	// ErrFileNotFound indicates a file was not found in the backend.
	ErrFileNotFound = errors.New("keystore: file not found")

	// ErrBackendNotSupported indicates the backend is not supported.
	ErrBackendNotSupported = errors.New("keystore: backend not supported")

	// ErrBackendNotInitialized indicates the backend has not been initialized.
	ErrBackendNotInitialized = errors.New("keystore: backend not initialized")

	// ErrBackendNotFound indicates the backend is not registered in the registry.
	ErrBackendNotFound = errors.New("keystore: backend not found")

	// ErrBackendRequired indicates a backend is required but was not provided.
	ErrBackendRequired = errors.New("keystore: backend is required")

	// ErrBackendClosed indicates the backend has been closed and cannot be used.
	ErrBackendClosed = errors.New("keystore: backend is closed")

	// ErrKeyProviderNotFound indicates the key provider is not registered.
	ErrKeyProviderNotFound = errors.New("keystore: key provider not found")
)

// Storage errors
var (
	// ErrCertStorageRequired indicates certificate storage is required but was not provided.
	ErrCertStorageRequired = errors.New("keystore: certificate storage is required")

	// ErrStorageClosed indicates the storage has been closed and cannot be used.
	ErrStorageClosed = errors.New("keystore: storage is closed")

	// ErrCertNotFound indicates the requested certificate was not found.
	ErrCertNotFound = errors.New("keystore: certificate not found")

	// ErrCertAlreadyExists indicates a certificate with the same identifier already exists.
	ErrCertAlreadyExists = errors.New("keystore: certificate already exists")

	// ErrCertChainNotFound indicates the requested certificate chain was not found.
	ErrCertChainNotFound = errors.New("keystore: certificate chain not found")
)

// Operation errors
var (
	// ErrOperationNotSupported indicates the operation is not supported.
	ErrOperationNotSupported = errors.New("keystore: operation not supported")

	// ErrOperationFailed indicates a generic operation failure.
	ErrOperationFailed = errors.New("keystore: operation failed")

	// ErrDecryptionFailed indicates decryption failed.
	ErrDecryptionFailed = errors.New("keystore: decryption failed")

	// ErrEncryptionFailed indicates encryption failed.
	ErrEncryptionFailed = errors.New("keystore: encryption failed")

	// ErrSigningFailed indicates signing operation failed.
	ErrSigningFailed = errors.New("keystore: signing failed")

	// ErrVerificationFailed indicates verification operation failed.
	ErrVerificationFailed = errors.New("keystore: verification failed")

	// ErrKeySigningNotSupported indicates the key does not support signing operations.
	ErrKeySigningNotSupported = errors.New("keystore: key does not support signing operations")

	// ErrKeyDecryptionNotSupported indicates the key does not support decryption operations.
	ErrKeyDecryptionNotSupported = errors.New("keystore: key does not support decryption operations")

	// ErrSymmetricNotSupported indicates the backend does not support symmetric operations.
	ErrSymmetricNotSupported = errors.New("keystore: backend does not support symmetric operations")

	// ErrImportExportNotSupported indicates the backend does not support import/export operations.
	ErrImportExportNotSupported = errors.New("keystore: backend does not support import/export operations")
)

// Sealing errors
var (
	// ErrSealingNotSupported indicates the backend does not support sealing operations.
	ErrSealingNotSupported = errors.New("keystore: sealing not supported")

	// ErrSealingFailed indicates sealing operation failed.
	ErrSealingFailed = errors.New("keystore: sealing failed")

	// ErrUnsealingFailed indicates unsealing operation failed.
	ErrUnsealingFailed = errors.New("keystore: unsealing failed")

	// ErrInvalidSealedData indicates the sealed data is invalid or malformed.
	ErrInvalidSealedData = errors.New("keystore: invalid sealed data")

	// ErrInvalidPCRIndex indicates a PCR index is out of the valid range (0-23).
	ErrInvalidPCRIndex = errors.New("keystore: invalid PCR index")
)

// ErrPCRHashAlgParse represents a failure to parse a PCR hash algorithm string.
type ErrPCRHashAlgParse struct {
	Algorithm string
	Err       error
}

// Error returns the error message.
func (e *ErrPCRHashAlgParse) Error() string {
	return fmt.Sprintf("keystore: invalid PCR hash algorithm %q: %v", e.Algorithm, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrPCRHashAlgParse) Unwrap() error { return e.Err }

// Subsystem errors
var (
	// ErrNotConfigured is returned when a subsystem method is called but that
	// subsystem has not been wired into the XKMSService via its setter.
	ErrNotConfigured = errors.New("keystore: subsystem not configured")

	// ErrNotSupported is returned when a requested operation is not supported
	// by the current configuration (e.g., TCG operations on a non-TCG CA).
	ErrNotSupported = errors.New("keystore: operation not supported")
)

// Auto-initialization errors
var (
	// ErrNoBackendsAvailable indicates no backends could be initialized during
	// auto-initialization. This occurs when all registered backend factories
	// fail to create their respective KeyProviders.
	ErrNoBackendsAvailable = errors.New("keystore: no backends available")

	// ErrNoFactoriesRegistered indicates no backend factories have been registered.
	// This should not occur in normal operation since software, pkcs8, symmetric,
	// and tpm2 backends always register factories.
	ErrNoFactoriesRegistered = errors.New("keystore: no backend factories registered")
)

// Servicer request validation errors
var (
	// ErrNilRequest indicates a nil request was provided to a servicer method.
	ErrNilRequest = errors.New("keystore: request cannot be nil")

	// ErrNilData indicates nil or empty data was provided where data is required.
	ErrNilData = errors.New("keystore: data cannot be nil or empty")

	// ErrEmptyChain indicates an empty certificate chain was provided.
	ErrEmptyChain = errors.New("keystore: certificate chain cannot be empty")
)

// Tenant errors
var (
	// ErrTenantIDRequired is returned when a tenant ID is empty.
	ErrTenantIDRequired = errors.New("keystore: tenant ID is required")

	// ErrTenantNameRequired is returned when a tenant name is empty.
	ErrTenantNameRequired = errors.New("keystore: tenant name is required")

	// ErrBarrierRegistryNotConfigured is returned when tenant operations are attempted
	// but the barrier registry has not been configured.
	ErrBarrierRegistryNotConfigured = errors.New("keystore: barrier registry not configured")
)

// ========================================================================
// Typed Error Structs
// ========================================================================

// ErrValidation represents a validation error with context about what was invalid.
// It wraps an underlying sentinel error (e.g., ErrInvalidKeyIDFormat, ErrInvalidKeyName).
type ErrValidation struct {
	Sentinel error
	Detail   string
}

// Error returns the error message.
func (e *ErrValidation) Error() string {
	if e.Detail == "" {
		return e.Sentinel.Error()
	}
	return fmt.Sprintf("%s: %s", e.Sentinel.Error(), e.Detail)
}

// Unwrap returns the underlying sentinel error, enabling errors.Is.
func (e *ErrValidation) Unwrap() error { return e.Sentinel }

// ErrBackendLookup represents errors when looking up or resolving backends.
// It wraps an underlying sentinel error (e.g., ErrBackendNotFound, ErrKeyProviderNotFound).
type ErrBackendLookup struct {
	Sentinel error
	Name     string
}

// Error returns the error message.
func (e *ErrBackendLookup) Error() string {
	if e.Name == "" {
		return e.Sentinel.Error()
	}
	return fmt.Sprintf("%s: %s", e.Sentinel.Error(), e.Name)
}

// Unwrap returns the underlying sentinel error.
func (e *ErrBackendLookup) Unwrap() error { return e.Sentinel }

// ErrBackendUnsupported represents errors when a backend does not support
// a required operation (e.g., import/export, symmetric, sealing).
type ErrBackendUnsupported struct {
	Sentinel error
	Backend  string
	Detail   string
}

// Error returns the error message.
func (e *ErrBackendUnsupported) Error() string {
	if e.Backend != "" && e.Detail != "" {
		return fmt.Sprintf("%s: backend %s: %s", e.Sentinel.Error(), e.Backend, e.Detail)
	}
	if e.Backend != "" {
		return fmt.Sprintf("%s: %s", e.Sentinel.Error(), e.Backend)
	}
	return e.Sentinel.Error()
}

// Unwrap returns the underlying sentinel error.
func (e *ErrBackendUnsupported) Unwrap() error { return e.Sentinel }

// ErrOperationWrap represents an operation error that wraps an underlying cause.
// Used for signing, encryption, decryption, verification, and general operation failures.
// It supports Go 1.20+ multi-error unwrapping via Unwrap() []error, exposing both
// the sentinel error and the wrapped cause error to errors.Is/errors.As.
type ErrOperationWrap struct {
	Sentinel error
	Detail   string
	Err      error
}

// Error returns the error message.
func (e *ErrOperationWrap) Error() string {
	parts := e.Sentinel.Error()
	if e.Detail != "" {
		parts += ": " + e.Detail
	}
	if e.Err != nil {
		parts += ": " + e.Err.Error()
	}
	return parts
}

// Unwrap returns both the sentinel and the wrapped cause error, enabling
// errors.Is and errors.As to match against either error in the chain.
// This uses Go 1.20+ multi-error unwrapping.
func (e *ErrOperationWrap) Unwrap() []error {
	if e.Err != nil {
		return []error{e.Sentinel, e.Err}
	}
	return []error{e.Sentinel}
}

// ErrKeyIDParse represents a key ID parsing or validation error.
type ErrKeyIDParse struct {
	Err error
}

// Error returns the error message.
func (e *ErrKeyIDParse) Error() string {
	return fmt.Sprintf("invalid key ID: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrKeyIDParse) Unwrap() error { return e.Err }

// ErrBackendNameValidation represents a backend name validation error.
type ErrBackendNameValidation struct {
	Err error
}

// Error returns the error message.
func (e *ErrBackendNameValidation) Error() string {
	return fmt.Sprintf("invalid backend name: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrBackendNameValidation) Unwrap() error { return e.Err }

// ErrKeyProviderNameValidation represents a key provider name validation error.
type ErrKeyProviderNameValidation struct {
	Err error
}

// Error returns the error message.
func (e *ErrKeyProviderNameValidation) Error() string {
	return fmt.Sprintf("invalid key provider name: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrKeyProviderNameValidation) Unwrap() error { return e.Err }

// ErrCertOperation represents a certificate storage operation error.
type ErrCertOperation struct {
	Operation string
	Err       error
}

// Error returns the error message.
func (e *ErrCertOperation) Error() string {
	return fmt.Sprintf("failed to %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrCertOperation) Unwrap() error { return e.Err }

// ErrKeyOperation represents a key management operation error.
type ErrKeyOperation struct {
	Operation string
	KeyID     string
	Err       error
}

// Error returns the error message.
func (e *ErrKeyOperation) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("failed to %s key %s: %v", e.Operation, e.KeyID, e.Err)
	}
	return fmt.Sprintf("failed to %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrKeyOperation) Unwrap() error { return e.Err }

// ErrCryptoOperation represents a cryptographic operation error (signer, decrypter, etc.).
type ErrCryptoOperation struct {
	Operation string
	KeyID     string
	Err       error
}

// Error returns the error message.
func (e *ErrCryptoOperation) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("failed to get %s for key %s: %v", e.Operation, e.KeyID, e.Err)
	}
	return fmt.Sprintf("failed to get %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrCryptoOperation) Unwrap() error { return e.Err }

// ErrCAOperation represents a CA operation error.
type ErrCAOperation struct {
	Operation string
	Err       error
}

// Error returns the error message.
func (e *ErrCAOperation) Error() string {
	return fmt.Sprintf("ca: %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrCAOperation) Unwrap() error { return e.Err }

// ErrUserOperation represents a user management operation error.
type ErrUserOperation struct {
	Operation string
	Err       error
}

// Error returns the error message.
func (e *ErrUserOperation) Error() string {
	return fmt.Sprintf("keystore: failed to %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrUserOperation) Unwrap() error { return e.Err }

// ErrSealOperation represents a sealing/unsealing operation error.
type ErrSealOperation struct {
	Operation string
	Err       error
}

// Error returns the error message.
func (e *ErrSealOperation) Error() string {
	return fmt.Sprintf("failed to %s data: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrSealOperation) Unwrap() error { return e.Err }

// ErrSealBackendMismatch represents a sealed data backend mismatch error.
type ErrSealBackendMismatch struct {
	SealedBy types.BackendType
	Current  types.BackendType
}

// Error returns the error message.
func (e *ErrSealBackendMismatch) Error() string {
	return fmt.Sprintf("%s: sealed data was created by %s, but current key provider is %s",
		ErrBackendMismatch.Error(), e.SealedBy, e.Current)
}

// Unwrap returns the underlying sentinel error.
func (e *ErrSealBackendMismatch) Unwrap() error { return ErrBackendMismatch }

// ErrBackendClose represents a multi-backend close failure.
type ErrBackendClose struct {
	Errs []error
}

// Error returns the error message.
func (e *ErrBackendClose) Error() string {
	return fmt.Sprintf("failed to close %d backend(s): %v", len(e.Errs), e.Errs)
}

// Unwrap returns nil since this aggregates multiple errors.
func (e *ErrBackendClose) Unwrap() []error { return e.Errs }

// ErrBackendCloseItem represents a single backend close error.
type ErrBackendCloseItem struct {
	Backend string
	Err     error
}

// Error returns the error message.
func (e *ErrBackendCloseItem) Error() string {
	return fmt.Sprintf("backend %s: %v", e.Backend, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrBackendCloseItem) Unwrap() error { return e.Err }

// ErrPEMBlock represents an unexpected PEM block type error.
type ErrPEMBlock struct {
	Expected string
	Got      string
}

// Error returns the error message.
func (e *ErrPEMBlock) Error() string {
	return fmt.Sprintf("%s: expected %s block, got %s", ErrInvalidEncodingPEM.Error(), e.Expected, e.Got)
}

// Unwrap returns the underlying sentinel error.
func (e *ErrPEMBlock) Unwrap() error { return ErrInvalidEncodingPEM }

// ErrCertParseIndex represents a certificate parsing error at a specific index in a chain.
type ErrCertParseIndex struct {
	Index int
	Err   error
}

// Error returns the error message.
func (e *ErrCertParseIndex) Error() string {
	return fmt.Sprintf("failed to parse certificate at index %d: %v", e.Index, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrCertParseIndex) Unwrap() error { return e.Err }

// ErrUnsupportedKeyType represents an unknown key type string.
type ErrUnsupportedKeyType struct {
	KeyType string
}

// Error returns the error message.
func (e *ErrUnsupportedKeyType) Error() string {
	return fmt.Sprintf("unknown key type: %s", e.KeyType)
}

// ErrUnsupportedAlgorithm represents an unknown algorithm string.
type ErrUnsupportedAlgorithm struct {
	Algorithm string
}

// Error returns the error message.
func (e *ErrUnsupportedAlgorithm) Error() string {
	return fmt.Sprintf("unknown algorithm: %s", e.Algorithm)
}

// ErrUnsupportedECDSACurve represents an unknown ECDSA curve.
type ErrUnsupportedECDSACurve struct {
	Algorithm string
}

// Error returns the error message.
func (e *ErrUnsupportedECDSACurve) Error() string {
	return fmt.Sprintf("unknown ECDSA curve in algorithm: %s", e.Algorithm)
}

// ErrUnsupportedPrivateKeyType represents an unsupported private key type.
type ErrUnsupportedPrivateKeyType struct {
	KeyType string
}

// Error returns the error message.
func (e *ErrUnsupportedPrivateKeyType) Error() string {
	return fmt.Sprintf("unsupported private key type: %s", e.KeyType)
}

// ErrPublicKeyExtraction represents a failure to extract the public key from a generated key.
type ErrPublicKeyExtraction struct {
	Algorithm string
}

// Error returns the error message.
func (e *ErrPublicKeyExtraction) Error() string {
	return fmt.Sprintf("failed to extract public key from generated %s key", e.Algorithm)
}

// ErrCopyKeyBackend represents an error resolving a source or destination backend during key copy.
type ErrCopyKeyBackend struct {
	Role string
	Err  error
}

// Error returns the error message.
func (e *ErrCopyKeyBackend) Error() string {
	return fmt.Sprintf("%s backend: %v", e.Role, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrCopyKeyBackend) Unwrap() error { return e.Err }

// ErrUnsupportedPublicKeyAlgorithm represents an unsupported x509.PublicKeyAlgorithm value.
type ErrUnsupportedPublicKeyAlgorithm struct {
	Algorithm fmt.Stringer
}

// Error returns the error message.
func (e *ErrUnsupportedPublicKeyAlgorithm) Error() string {
	return fmt.Sprintf("%s: %v", ErrUnsupportedKeyAlgorithm.Error(), e.Algorithm)
}

// Unwrap returns the sentinel error for errors.Is compatibility.
func (e *ErrUnsupportedPublicKeyAlgorithm) Unwrap() error { return ErrUnsupportedKeyAlgorithm }

// ErrUnsealBackendNotFound represents a failure to find a backend matching sealed data's backend type.
type ErrUnsealBackendNotFound struct {
	BackendType types.BackendType
}

// Error returns the error message.
func (e *ErrUnsealBackendNotFound) Error() string {
	return fmt.Sprintf("%s: no backend found for type %s", ErrBackendNotFound.Error(), e.BackendType)
}

// Unwrap returns the underlying sentinel error.
func (e *ErrUnsealBackendNotFound) Unwrap() error { return ErrBackendNotFound }

// ErrImportExportOperation represents a specific import/export operation error.
type ErrImportExportOperation struct {
	Operation string
	Err       error
}

// Error returns the error message.
func (e *ErrImportExportOperation) Error() string {
	return fmt.Sprintf("failed to %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrImportExportOperation) Unwrap() error { return e.Err }

// ErrMockKeyNotFound represents a key not found error in mock keystores.
type ErrMockKeyNotFound struct {
	KeyID string
}

// Error returns the error message.
func (e *ErrMockKeyNotFound) Error() string {
	return fmt.Sprintf("%s: %s", ErrKeyNotFound.Error(), e.KeyID)
}

// Unwrap returns the underlying sentinel error.
func (e *ErrMockKeyNotFound) Unwrap() error { return ErrKeyNotFound }

// ErrMockCertNotFound represents a certificate not found error in mock keystores.
type ErrMockCertNotFound struct {
	KeyID string
}

// Error returns the error message.
func (e *ErrMockCertNotFound) Error() string {
	return fmt.Sprintf("%s: %s", ErrCertNotFound.Error(), e.KeyID)
}

// Unwrap returns the underlying sentinel error.
func (e *ErrMockCertNotFound) Unwrap() error { return ErrCertNotFound }

// ErrMockCertChainNotFound represents a certificate chain not found error in mock keystores.
type ErrMockCertChainNotFound struct {
	KeyID string
}

// Error returns the error message.
func (e *ErrMockCertChainNotFound) Error() string {
	return fmt.Sprintf("%s: %s", ErrCertChainNotFound.Error(), e.KeyID)
}

// Unwrap returns the underlying sentinel error.
func (e *ErrMockCertChainNotFound) Unwrap() error { return ErrCertChainNotFound }
