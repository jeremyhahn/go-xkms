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

// This file re-exports core types from pkg/types so that SDK consumers can
// use the SDK package directly without importing internal packages.

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// =============================================================================
// Core Type Aliases
// =============================================================================

type (
	// Password represents a secret used to authenticate or decrypt protected data.
	Password = types.Password

	// ClearPassword is a simple in-memory implementation of the Password interface.
	ClearPassword = types.ClearPassword

	// KeyAttributes describes a cryptographic key's metadata and configuration.
	KeyAttributes = types.KeyAttributes

	// KeyType identifies the type of key (RSA, ECDSA, Ed25519, etc.).
	KeyType = types.KeyType

	// StoreType identifies the backend storage type.
	StoreType = types.StoreType

	// BackendType represents the type of key storage backend.
	BackendType = types.BackendType

	// SymmetricAlgorithm identifies a symmetric encryption algorithm.
	SymmetricAlgorithm = types.SymmetricAlgorithm

	// AEADOptions configures AEAD encryption parameters.
	AEADOptions = types.AEADOptions

	// ECCAttributes contains ECC-specific key parameters.
	ECCAttributes = types.ECCAttributes

	// RSAAttributes contains RSA-specific key parameters.
	RSAAttributes = types.RSAAttributes

	// X25519Attributes contains X25519-specific key parameters.
	X25519Attributes = types.X25519Attributes

	// QuantumAlgorithm identifies a post-quantum algorithm.
	QuantumAlgorithm = types.QuantumAlgorithm

	// QuantumAttributes contains post-quantum key parameters.
	QuantumAttributes = types.QuantumAttributes

	// ThresholdAlgorithm identifies a threshold signing algorithm.
	ThresholdAlgorithm = types.ThresholdAlgorithm

	// ThresholdAttributes contains threshold key parameters.
	ThresholdAttributes = types.ThresholdAttributes

	// FrostAlgorithm identifies a FROST threshold signing algorithm.
	FrostAlgorithm = types.FrostAlgorithm

	// FrostAttributes contains FROST-specific key parameters.
	FrostAttributes = types.FrostAttributes

	// TPMAttributes contains TPM 2.0-specific key parameters.
	TPMAttributes = types.TPMAttributes

	// KeyConfig represents key configuration for YAML/JSON serialization.
	KeyConfig = types.KeyConfig

	// SealData represents data to be sealed/unsealed.
	SealData = types.SealData

	// Capabilities describes what operations a backend supports.
	Capabilities = types.Capabilities

	// KeyProvider is the interface for key management operations.
	KeyProvider = types.KeyProvider

	// SymmetricKeyProvider extends KeyProvider with symmetric key operations.
	SymmetricKeyProvider = types.SymmetricKeyProvider

	// SymmetricEncrypter provides symmetric encryption and decryption operations.
	SymmetricEncrypter = types.SymmetricEncrypter

	// Sealer provides data sealing/unsealing operations.
	Sealer = types.Sealer

	// KeyAgreement provides key agreement operations (ECDH, X25519).
	KeyAgreement = types.KeyAgreement

	// AEADSafetyTracker provides nonce uniqueness and bytes encrypted tracking
	// for AEAD ciphers to prevent nonce reuse and enforce key rotation.
	AEADSafetyTracker = types.AEADSafetyTracker

	// SecurityLevel indicates the security assurance level of a key or operation.
	SecurityLevel = types.SecurityLevel

	// PasswordCacheConfig configures password caching behavior.
	PasswordCacheConfig = types.PasswordCacheConfig

	// FSExtension is a file system extension identifier.
	FSExtension = types.FSExtension

	// Partition is a storage partition identifier.
	Partition = types.Partition

	// VerifyOpts configures signature verification parameters.
	VerifyOpts = types.VerifyOpts

	// EncryptOptions configures symmetric encryption parameters.
	EncryptOptions = types.EncryptOptions

	// EncryptedData holds the result of a symmetric encryption operation.
	EncryptedData = types.EncryptedData

	// DecryptOptions configures symmetric decryption parameters.
	DecryptOptions = types.DecryptOptions

	// SymmetricKey is the interface for symmetric key operations.
	SymmetricKey = types.SymmetricKey

	// SealOptions configures data sealing parameters.
	SealOptions = types.SealOptions

	// SealedData holds the result of a seal operation.
	SealedData = types.SealedData

	// UnsealOptions configures data unsealing parameters.
	UnsealOptions = types.UnsealOptions

	// KeyAlgorithmString identifies a key algorithm by name.
	KeyAlgorithmString = types.KeyAlgorithmString

	// EllipticCurve identifies an elliptic curve by name.
	EllipticCurve = types.EllipticCurve

	// SignatureAlgorithmName represents signature algorithm identifiers.
	SignatureAlgorithmName = types.SignatureAlgorithmName
)

// =============================================================================
// Additional Type Aliases (backfilled from pkg/types)
// =============================================================================

type (
	// AlgorithmInfo describes a single supported algorithm.
	AlgorithmInfo = types.AlgorithmInfo

	// AlgorithmsResponse holds the full algorithm discovery response.
	AlgorithmsResponse = types.AlgorithmsResponse

	// AEADAlgorithm identifies an AEAD encryption algorithm.
	AEADAlgorithm = types.AEADAlgorithm

	// CLIKeyType identifies a key type for CLI operations.
	CLIKeyType = types.CLIKeyType

	// HashName identifies a hash algorithm by name.
	HashName = types.HashName

	// KeyTypeString identifies a key type by name.
	KeyTypeString = types.KeyTypeString

	// KeyWrapAlgorithm identifies a key wrapping algorithm.
	KeyWrapAlgorithm = types.KeyWrapAlgorithm

	// AttestingKeyProvider extends KeyProvider with TPM attestation.
	AttestingKeyProvider = types.AttestingKeyProvider

	// DerivedKeyHandle holds a derived key and its metadata.
	DerivedKeyHandle = types.DerivedKeyHandle

	// DerivedKeyTemplateParams holds parameters for key derivation templates.
	DerivedKeyTemplateParams = types.DerivedKeyTemplateParams

	// ECDHResult holds the result of an ECDH key agreement operation.
	ECDHResult = types.ECDHResult

	// ECIESEncrypter provides ECIES encryption operations.
	ECIESEncrypter = types.ECIESEncrypter

	// ECIESDecrypter provides ECIES decryption operations.
	ECIESDecrypter = types.ECIESDecrypter

	// KDFAlgorithm identifies a key derivation function algorithm.
	KDFAlgorithm = types.KDFAlgorithm

	// KDFParams configures key derivation function parameters.
	KDFParams = types.KDFParams

	// KeyAgreementProvider is the interface for basic key agreement operations.
	KeyAgreementProvider = types.KeyAgreementProvider

	// KeyDerivationMode identifies the key derivation mode.
	KeyDerivationMode = types.KeyDerivationMode

	// KeyMap is a map representation of key attributes.
	KeyMap = types.KeyMap

	// KeySerializer serializes and deserializes key attributes.
	KeySerializer = types.KeySerializer

	// SerializerType identifies the key serializer format.
	SerializerType = types.SerializerType

	// OpaqueKey is the interface for keys whose private material is not directly accessible.
	OpaqueKey = types.OpaqueKey

	// OperationParams holds parameters for secure key agreement operations.
	OperationParams = types.OperationParams

	// ResidentKeyOperation identifies a resident key operation type.
	ResidentKeyOperation = types.ResidentKeyOperation

	// SecureKeyAgreementProvider extends KeyAgreementProvider with resident
	// key and hardware-bound operations.
	SecureKeyAgreementProvider = types.SecureKeyAgreementProvider

	// SealingKeyProvider extends KeyProvider with sealing operations.
	SealingKeyProvider = types.SealingKeyProvider

	// SimpleVerifier is a simple signature verifier implementation.
	SimpleVerifier = types.SimpleVerifier

	// Verifier is the interface for signature verification operations.
	Verifier = types.Verifier

	// SymmetricKeyProviderWithTracking extends SymmetricKeyProvider with
	// AEAD safety tracking.
	SymmetricKeyProviderWithTracking = types.SymmetricKeyProviderWithTracking

	// TPMDerivedKeyHandle holds a TPM-derived key and its metadata.
	TPMDerivedKeyHandle = types.TPMDerivedKeyHandle

	// TPMKeyAgreementProvider extends KeyAgreementProvider with TPM-specific
	// key agreement operations.
	TPMKeyAgreementProvider = types.TPMKeyAgreementProvider

	// TPMSealPolicy describes a TPM 2.0 seal/unseal policy.
	TPMSealPolicy = types.TPMSealPolicy

	// NOTE: RSAConfig and ECCConfig from pkg/types are not re-exported here
	// because tpm.go already re-exports them from pkg/tpm2/store (which are
	// different struct definitions). Use xkms.RSAConfig / xkms.ECCConfig
	// from tpm.go for TPM store configuration.
)

// =============================================================================
// Constants
// =============================================================================

// Backend type constants.
const (
	BackendTypeSoftware  = types.BackendTypeSoftware
	BackendTypePKCS11    = types.BackendTypePKCS11
	BackendTypeTPM2      = types.BackendTypeTPM2
	BackendTypeAWSKMS    = types.BackendTypeAWSKMS
	BackendTypeGCPKMS    = types.BackendTypeGCPKMS
	BackendTypeAzureKV   = types.BackendTypeAzureKV
	BackendTypeVault     = types.BackendTypeVault
	BackendTypeQuantum   = types.BackendTypeQuantum
	BackendTypeThreshold = types.BackendTypeThreshold
	BackendTypeSymmetric = types.BackendTypeSymmetric
)

// Key type constants.
const (
	KeyTypeEncryption  = types.KeyTypeEncryption
	KeyTypeSigning     = types.KeyTypeSigning
	KeyTypeSecret      = types.KeyTypeSecret
	KeyTypeAttestation = types.KeyTypeAttestation
	KeyTypeCA          = types.KeyTypeCA
	KeyTypeEndorsement = types.KeyTypeEndorsement
	KeyTypeIDevID      = types.KeyTypeIDevID
	KeyTypeLDevID      = types.KeyTypeLDevID
	KeyTypeTLS         = types.KeyTypeTLS
	KeyTypeTPM         = types.KeyTypeTPM
	KeyTypeHMAC        = types.KeyTypeHMAC
	KeyTypeStorage     = types.KeyTypeStorage
)

// Key algorithm constants.
const (
	AlgorithmRSA       = types.AlgorithmRSA
	AlgorithmECDSA     = types.AlgorithmECDSA
	AlgorithmEd25519   = types.AlgorithmEd25519
	AlgorithmDSA       = types.AlgorithmDSA
	AlgorithmSymmetric = types.AlgorithmSymmetric
	AlgorithmAES       = types.AlgorithmAES
)

// Elliptic curve constants.
const (
	CurveP224      = types.CurveP224
	CurveP256      = types.CurveP256
	CurveP384      = types.CurveP384
	CurveP521      = types.CurveP521
	CurveSecp256k1 = types.CurveSecp256k1
	CurveX25519    = types.CurveX25519
	CurveEd25519   = types.CurveEd25519
)

// RSA key size constants.
const (
	RSAKeySize2048 = types.RSAKeySize2048
)

// Store type constants.
const (
	StoreUnknown   = types.StoreUnknown
	StoreSoftware  = types.StoreSoftware
	StorePKCS11    = types.StorePKCS11
	StoreTPM2      = types.StoreTPM2
	StoreAWSKMS    = types.StoreAWSKMS
	StoreGCPKMS    = types.StoreGCPKMS
	StoreAzureKV   = types.StoreAzureKV
	StoreVault     = types.StoreVault
	StoreQuantum   = types.StoreQuantum
	StoreThreshold = types.StoreThreshold
	StoreFrost     = types.StoreFrost
)

// Quantum algorithm constants.
const (
	QuantumAlgorithmMLDSA44 = types.QuantumAlgorithmMLDSA44
	QuantumAlgorithmMLDSA65 = types.QuantumAlgorithmMLDSA65
	QuantumAlgorithmMLDSA87 = types.QuantumAlgorithmMLDSA87
)

// Symmetric algorithm constants.
const (
	SymmetricAES128GCM         = types.SymmetricAES128GCM
	SymmetricAES192GCM         = types.SymmetricAES192GCM
	SymmetricAES256GCM         = types.SymmetricAES256GCM
	SymmetricChaCha20Poly1305  = types.SymmetricChaCha20Poly1305
	SymmetricXChaCha20Poly1305 = types.SymmetricXChaCha20Poly1305
)

// Hash name constants.
const (
	HashMD4         = types.HashMD4
	HashMD5         = types.HashMD5
	HashSHA1        = types.HashSHA1
	HashSHA224      = types.HashSHA224
	HashSHA256      = types.HashSHA256
	HashSHA384      = types.HashSHA384
	HashSHA512      = types.HashSHA512
	HashSHA512_224  = types.HashSHA512_224
	HashSHA512_256  = types.HashSHA512_256
	HashSHA3_224    = types.HashSHA3_224
	HashSHA3_256    = types.HashSHA3_256
	HashSHA3_384    = types.HashSHA3_384
	HashSHA3_512    = types.HashSHA3_512
	HashBLAKE2s_256 = types.HashBLAKE2s_256
	HashBLAKE2b_256 = types.HashBLAKE2b_256
	HashBLAKE2b_384 = types.HashBLAKE2b_384
	HashBLAKE2b_512 = types.HashBLAKE2b_512
)

// Signature algorithm name constants.
const (
	SigMD2WithRSA       = types.SigMD2WithRSA
	SigMD5WithRSA       = types.SigMD5WithRSA
	SigSHA1WithRSA      = types.SigSHA1WithRSA
	SigSHA256WithRSA    = types.SigSHA256WithRSA
	SigSHA384WithRSA    = types.SigSHA384WithRSA
	SigSHA512WithRSA    = types.SigSHA512WithRSA
	SigSHA256WithRSAPSS = types.SigSHA256WithRSAPSS
	SigSHA384WithRSAPSS = types.SigSHA384WithRSAPSS
	SigSHA512WithRSAPSS = types.SigSHA512WithRSAPSS
	SigDSAWithSHA1      = types.SigDSAWithSHA1
	SigDSAWithSHA256    = types.SigDSAWithSHA256
	SigECDSAWithSHA1    = types.SigECDSAWithSHA1
	SigECDSAWithSHA256  = types.SigECDSAWithSHA256
	SigECDSAWithSHA384  = types.SigECDSAWithSHA384
	SigECDSAWithSHA512  = types.SigECDSAWithSHA512
	SigEd25519          = types.SigEd25519
)

// AEAD algorithm constants.
const (
	AEADAES128GCM         = types.AEADAES128GCM
	AEADAES192GCM         = types.AEADAES192GCM
	AEADAES256GCM         = types.AEADAES256GCM
	AEADChaCha20Poly1305  = types.AEADChaCha20Poly1305
	AEADXChaCha20Poly1305 = types.AEADXChaCha20Poly1305
)

// Key wrap algorithm constants.
const (
	WrapRSAOAEPSHA1    = types.WrapRSAOAEPSHA1
	WrapRSAOAEPSHA256  = types.WrapRSAOAEPSHA256
	WrapRSAAESKWSHA1   = types.WrapRSAAESKWSHA1
	WrapRSAAESKWSHA256 = types.WrapRSAAESKWSHA256
	WrapAESKWP         = types.WrapAESKWP
	WrapAES128KWP      = types.WrapAES128KWP
	WrapAES256KWP      = types.WrapAES256KWP
)

// CLI key type constants.
const (
	CLIKeyTypeTLS     = types.CLIKeyTypeTLS
	CLIKeyTypeSigning = types.CLIKeyTypeSigning
)

// Default constants.
const (
	DEFAULT_PASSWORD = types.DEFAULT_PASSWORD
)

// =============================================================================
// Error Variables
// =============================================================================

// Error variables from pkg/types.
var (
	// ErrInvalidKeyStore is returned when an invalid keystore type is specified.
	ErrInvalidKeyStore = types.ErrInvalidKeyStore

	// ErrInvalidKeyAlgorithm is returned when an invalid key algorithm is specified.
	ErrInvalidKeyAlgorithm = types.ErrInvalidKeyAlgorithm
)

// =============================================================================
// Function Variables
// =============================================================================

// Password constructors.
var (
	NewPassword           = types.NewPassword
	NewPasswordFromString = types.NewPasswordFromString
)

// SealData constructor.
var NewSealData = types.NewSealData

// Capability constructors.
var (
	NewSoftwareCapabilities        = types.NewSoftwareCapabilities
	NewHardwareCapabilities        = types.NewHardwareCapabilities
	NewUnifiedSoftwareCapabilities = types.NewUnifiedSoftwareCapabilities
)

// Key and curve parsing functions.
var (
	ParseKeyType            = types.ParseKeyType
	ParseCurve              = types.ParseCurve
	CurveName               = types.CurveName
	ParseSignatureAlgorithm = types.ParseSignatureAlgorithm
	ParseKeyAlgorithm       = types.ParseKeyAlgorithm
	ParseHash               = types.ParseHash
	ParseStoreType          = types.ParseStoreType

	// KeyAttributesFromConfig creates KeyAttributes from a KeyConfig.
	KeyAttributesFromConfig = types.KeyAttributesFromConfig
)

// Additional function exports from pkg/types.
var (
	// EncodePubKeyPEM encodes a public key to PEM format.
	EncodePubKeyPEM = types.EncodePubKeyPEM
)

// =============================================================================
// Key Type String Constants
// =============================================================================

// KeyTypeString constants for YAML/JSON configuration.
const (
	KeyTypeStringAttestation = types.KeyTypeStringAttestation
	KeyTypeStringCA          = types.KeyTypeStringCA
	KeyTypeStringEncryption  = types.KeyTypeStringEncryption
	KeyTypeStringEndorsement = types.KeyTypeStringEndorsement
	KeyTypeStringHMAC        = types.KeyTypeStringHMAC
	KeyTypeStringIDevID      = types.KeyTypeStringIDevID
	KeyTypeStringLDevID      = types.KeyTypeStringLDevID
	KeyTypeStringSecret      = types.KeyTypeStringSecret
	KeyTypeStringSigning     = types.KeyTypeStringSigning
	KeyTypeStringStorage     = types.KeyTypeStringStorage
	KeyTypeStringTLS         = types.KeyTypeStringTLS
	KeyTypeStringTPM         = types.KeyTypeStringTPM
)

// =============================================================================
// Config-level Key Configuration Types
// =============================================================================
//
// These are the YAML/JSON serialization-level configuration structs used in
// KeyConfig, distinct from the runtime types RSAConfig/ECCConfig exported
// from the TPM store package.

// KeyECCConfig holds ECC-specific configuration for YAML serialization.
type KeyECCConfig = types.ECCConfig

// KeyRSAConfig holds RSA-specific configuration for YAML serialization.
type KeyRSAConfig = types.RSAConfig
