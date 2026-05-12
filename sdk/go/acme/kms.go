// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package trustedca

import (
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
)

// =============================================================================
// KMS Interfaces
// =============================================================================

// CAKMSClient provides key management operations including generation,
// retrieval, rotation, listing, and deletion of cryptographic keys.
type CAKMSClient = kms.KMSClient

// CAKMSService provides key management operations for tenant CA signing.
// It abstracts the underlying KMS/go-xkms integration.
type CAKMSService = kms.KMSService

// CAKMSCryptoClient provides cryptographic signing and verification operations.
type CAKMSCryptoClient = kms.CryptoClient

// CAKMSTenantCAFactory creates CA instances for tenants using KMS-managed keys.
type CAKMSTenantCAFactory = kms.TenantCAFactory

// =============================================================================
// KMS Key Algorithm and Usage Types
// =============================================================================

// CAKMSKeyAlgorithm represents supported key algorithms for KMS operations.
type CAKMSKeyAlgorithm = kms.KMSKeyAlgorithm

// CAKMSKeyUsage represents key usage types for KMS operations.
type CAKMSKeyUsage = kms.KMSKeyUsage

// CAKMSKeyPurpose identifies the purpose of a cryptographic key.
type CAKMSKeyPurpose = kms.KeyPurpose

// =============================================================================
// KMS Request/Response Types
// =============================================================================

// CAKMSKeyInfo contains information about a managed key.
type CAKMSKeyInfo = kms.KMSKeyInfo

// CAKMSGenerateKeyRequest contains parameters for key generation.
type CAKMSGenerateKeyRequest = kms.KMSGenerateKeyRequest

// CAKMSGenerateKeyResponse contains the result of key generation.
type CAKMSGenerateKeyResponse = kms.KMSGenerateKeyResponse

// CAKMSRotateKeyResponse contains the result of key rotation.
type CAKMSRotateKeyResponse = kms.KMSRotateKeyResponse

// CAKMSListKeysResponse contains the result of listing keys.
type CAKMSListKeysResponse = kms.KMSListKeysResponse

// CAKMSKeyMetadata describes a managed key with tenant and purpose context.
type CAKMSKeyMetadata = kms.KeyMetadata

// =============================================================================
// KMS Crypto Request/Response Types
// =============================================================================

// CAKMSCryptoHashAlgorithm represents hash algorithms for signing operations.
type CAKMSCryptoHashAlgorithm = kms.CryptoHashAlgorithm

// CAKMSCryptoSignRequest contains parameters for signing operations.
type CAKMSCryptoSignRequest = kms.CryptoSignRequest

// CAKMSCryptoSignResponse contains the result of a signing operation.
type CAKMSCryptoSignResponse = kms.CryptoSignResponse

// CAKMSCryptoVerifyRequest contains parameters for verification operations.
type CAKMSCryptoVerifyRequest = kms.CryptoVerifyRequest

// CAKMSCryptoVerifyResponse contains the result of a verification operation.
type CAKMSCryptoVerifyResponse = kms.CryptoVerifyResponse

// =============================================================================
// KMS Error Types
// =============================================================================

// CAKMSError represents a KMS error with code, message, and optional context.
type CAKMSError = kms.Error

// CAKMSErrorCode represents the type of KMS error.
type CAKMSErrorCode = kms.ErrorCode

// =============================================================================
// KMS Key Algorithm Constants
// =============================================================================

const (
	// CAKMSAlgorithmRSA2048 is RSA with 2048-bit key.
	CAKMSAlgorithmRSA2048 = kms.AlgorithmRSA2048

	// CAKMSAlgorithmRSA4096 is RSA with 4096-bit key.
	CAKMSAlgorithmRSA4096 = kms.AlgorithmRSA4096

	// CAKMSAlgorithmECDSAP256 is ECDSA with P-256 curve.
	CAKMSAlgorithmECDSAP256 = kms.AlgorithmECDSAP256

	// CAKMSAlgorithmECDSAP384 is ECDSA with P-384 curve.
	CAKMSAlgorithmECDSAP384 = kms.AlgorithmECDSAP384

	// CAKMSAlgorithmED25519 is Ed25519 signature algorithm.
	CAKMSAlgorithmED25519 = kms.AlgorithmED25519
)

// =============================================================================
// KMS Key Usage Constants
// =============================================================================

const (
	// CAKMSKeyUsageSign allows signing operations.
	CAKMSKeyUsageSign = kms.KeyUsageSign

	// CAKMSKeyUsageVerify allows verification operations.
	CAKMSKeyUsageVerify = kms.KeyUsageVerify

	// CAKMSKeyUsageEncrypt allows encryption operations.
	CAKMSKeyUsageEncrypt = kms.KeyUsageEncrypt

	// CAKMSKeyUsageDecrypt allows decryption operations.
	CAKMSKeyUsageDecrypt = kms.KeyUsageDecrypt
)

// =============================================================================
// KMS Key Purpose Constants
// =============================================================================

const (
	// CAKMSKeyPurposeTenantRootCA is for tenant root CA signing keys.
	CAKMSKeyPurposeTenantRootCA = kms.KeyPurposeTenantRootCA

	// CAKMSKeyPurposeTenantIntermediateCA is for tenant intermediate CA signing keys.
	CAKMSKeyPurposeTenantIntermediateCA = kms.KeyPurposeTenantIntermediateCA

	// CAKMSKeyPurposeOCSP is for OCSP response signing.
	CAKMSKeyPurposeOCSP = kms.KeyPurposeOCSP

	// CAKMSKeyPurposeCRL is for CRL signing.
	CAKMSKeyPurposeCRL = kms.KeyPurposeCRL
)

// =============================================================================
// KMS Crypto Hash Algorithm Constants
// =============================================================================

const (
	// CAKMSHashSHA256 is SHA-256 hash algorithm.
	CAKMSHashSHA256 = kms.HashSHA256

	// CAKMSHashSHA384 is SHA-384 hash algorithm.
	CAKMSHashSHA384 = kms.HashSHA384

	// CAKMSHashSHA512 is SHA-512 hash algorithm.
	CAKMSHashSHA512 = kms.HashSHA512
)

// =============================================================================
// KMS Error Code Constants
// =============================================================================

const (
	// CAKMSErrorCodeNotFound indicates a resource was not found.
	CAKMSErrorCodeNotFound = kms.ErrorCodeNotFound

	// CAKMSErrorCodeInvalidInput indicates invalid input data.
	CAKMSErrorCodeInvalidInput = kms.ErrorCodeInvalidInput

	// CAKMSErrorCodeInternal indicates an internal error.
	CAKMSErrorCodeInternal = kms.ErrorCodeInternal

	// CAKMSErrorCodeKeyNotFound indicates a cryptographic key was not found.
	CAKMSErrorCodeKeyNotFound = kms.ErrorCodeKeyNotFound
)

// =============================================================================
// KMS Predefined Errors
// =============================================================================

var (
	// CAKMSErrNotFound indicates a resource was not found.
	CAKMSErrNotFound = kms.ErrNotFound

	// CAKMSErrInvalidInput indicates invalid input data.
	CAKMSErrInvalidInput = kms.ErrInvalidInput

	// CAKMSErrInternal indicates an internal error.
	CAKMSErrInternal = kms.ErrInternal

	// CAKMSErrKeyNotFound indicates a cryptographic key was not found.
	CAKMSErrKeyNotFound = kms.ErrKeyNotFound
)

// =============================================================================
// KMS Constructor Functions
// =============================================================================

// NewCAKMSMemoryClient creates a new in-memory KMS client for testing.
var NewCAKMSMemoryClient = kms.NewMemoryKMSClient

// NewCAKMSMemoryCryptoClient creates a new in-memory crypto client for testing.
var NewCAKMSMemoryCryptoClient = kms.NewMemoryCryptoClient

// NewCAKMSError creates a new KMS error with the given code and message.
var NewCAKMSError = kms.NewError

// =============================================================================
// KMS Error Helper Functions
// =============================================================================

// CAKMSIsNotFound checks if the error is a not found error.
var CAKMSIsNotFound = kms.IsNotFound

// CAKMSIsKeyNotFound checks if the error indicates a key was not found.
var CAKMSIsKeyNotFound = kms.IsKeyNotFound
