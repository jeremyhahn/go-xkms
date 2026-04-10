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

// Package types contains shared type definitions used across the xkms,
// including key attributes, backend interfaces, and cryptographic types.
// This package has no dependencies on pkg/backend or pkg/xkms to prevent
// import cycles.
package types

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
)

// =============================================================================
// Constants
// =============================================================================

// DEFAULT_PASSWORD is the default password for development and testing.
// This should NEVER be used in production environments.
const DEFAULT_PASSWORD = "changeme"

// =============================================================================
// Errors
// =============================================================================

var (
	// ErrUnknownKeyAlgorithm is returned when a key algorithm string is not recognized.
	ErrUnknownKeyAlgorithm = errors.New("unknown key algorithm")

	// ErrUnknownCurve is returned when an elliptic curve string is not recognized.
	ErrUnknownCurve = errors.New("unknown elliptic curve")

	// ErrUnknownSignatureAlgorithm is returned when a signature algorithm string is not recognized.
	ErrUnknownSignatureAlgorithm = errors.New("unknown signature algorithm")

	// ErrAlreadyInitialized is returned when the system is already initialized.
	ErrAlreadyInitialized = errors.New("already initialized")

	// ErrNotInitialized is returned when the system is not initialized.
	ErrNotInitialized = errors.New("not initialized")

	// ErrInvalidPassword is returned when an invalid password is provided.
	ErrInvalidPassword = errors.New("invalid password")

	// ErrFileNotFound is returned when a required file cannot be found.
	ErrFileNotFound = errors.New("file not found")

	// ErrInvalidKeyStore is returned when an invalid keystore type is specified.
	ErrInvalidKeyStore = errors.New("invalid keystore")

	// ErrInvalidEncodingPEM is returned when PEM encoding/decoding fails.
	ErrInvalidEncodingPEM = errors.New("invalid PEM encoding")

	// ErrInvalidKeyAlgorithm is returned when an invalid key algorithm is specified.
	ErrInvalidKeyAlgorithm = errors.New("invalid key algorithm")

	// ErrInvalidPermanentIdentifier is returned when an invalid permanent identifier is provided.
	ErrInvalidPermanentIdentifier = errors.New("invalid permanent identifier")
)

// =============================================================================
// File System Types
// =============================================================================

// FSExtension represents file extension types used by the xkms
// file backend for storing cryptographic material.
type FSExtension string

const (
	// File extension constants for various key storage formats
	FSExtBlob            FSExtension = ""
	FSExtPrivatePKCS8    FSExtension = ".key"
	FSExtPrivatePKCS8PEM FSExtension = ".key.pem"
	FSExtPublicPKCS1     FSExtension = ".pub"
	FSExtPublicPEM       FSExtension = ".pub.pem"
	FSExtPrivateBlob     FSExtension = ".key.bin"
	FSExtPublicBlob      FSExtension = ".pub.bin"
	FSExtDigest          FSExtension = ".digest"
	FSExtSignature       FSExtension = ".sig"
)

// =============================================================================
// Partition Types
// =============================================================================

// Partition represents logical storage partitions within the xkms
// for organizing keys by their purpose.
type Partition string

const (
	// Partition constants for organizing keys by type
	PartitionRoot           Partition = ""
	PartitionTLS            Partition = "issued"
	PartitionEncapsulation  Partition = "encapsulation"
	PartitionEncryptionKeys Partition = "crypto"
	PartitionSigningKeys    Partition = "signing"
	PartitionHMAC           Partition = "hmac"
	PartitionSecrets        Partition = "secrets"
)

// Partitions is a list of all available partitions for iteration.
var Partitions = []Partition{
	PartitionRoot,
	PartitionTLS,
	PartitionEncapsulation,
	PartitionEncryptionKeys,
	PartitionSigningKeys,
	PartitionHMAC,
	PartitionSecrets,
}

// =============================================================================
// Store Type
// =============================================================================

// StoreType identifies the backend storage mechanism for cryptographic keys.
type StoreType string

const (
	// Store type constants
	StoreSoftware  StoreType = "software"
	StorePKCS11    StoreType = "pkcs11"
	StoreTPM2      StoreType = "tpm2"
	StoreAWSKMS    StoreType = "awskms"
	StoreGCPKMS    StoreType = "gcpkms"
	StoreAzureKV   StoreType = "azurekv"
	StoreVault     StoreType = "vault"
	StoreQuantum   StoreType = "quantum"
	StoreThreshold StoreType = "threshold"
	StoreFrost     StoreType = "frost"
	StorePhone     StoreType = "phone"
	StoreUnknown   StoreType = "unknown"
)

// String returns the string representation of the store type.
func (st StoreType) String() string {
	return string(st)
}

// IsValid returns true if the store type is recognized.
func (st StoreType) IsValid() bool {
	switch st {
	case StoreSoftware, StorePKCS11, StoreTPM2, StoreAWSKMS, StoreGCPKMS, StoreAzureKV, StoreVault, StoreQuantum, StoreThreshold, StoreFrost:
		return true
	default:
		return false
	}
}

// ParseStoreType converts a string to a StoreType.
// Returns StoreUnknown if the string is not a valid store type.
func ParseStoreType(s string) StoreType {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "software":
		return StoreSoftware
	case "pkcs11":
		return StorePKCS11
	case "tpm2":
		return StoreTPM2
	case "awskms":
		return StoreAWSKMS
	case "gcpkms":
		return StoreGCPKMS
	case "azurekv":
		return StoreAzureKV
	case "vault":
		return StoreVault
	case "quantum":
		return StoreQuantum
	case "threshold":
		return StoreThreshold
	case "frost":
		return StoreFrost
	default:
		return StoreUnknown
	}
}

// =============================================================================
// Backend Type
// =============================================================================

// BackendType identifies the type of cryptographic backend.
type BackendType string

const (
	BackendTypeSymmetric    BackendType = "symmetric"    // Symmetric encryption (AES-GCM, ChaCha20-Poly1305)
	BackendTypeSoftware     BackendType = "software"     // Unified software backend (asymmetric + symmetric)
	BackendTypePKCS11       BackendType = "pkcs11"       // PKCS#11 hardware security modules
	BackendTypeTPM2         BackendType = "tpm2"         // TPM 2.0 hardware security module
	BackendTypeAWSKMS       BackendType = "awskms"       // AWS Key Management Service
	BackendTypeGCPKMS       BackendType = "gcpkms"       // Google Cloud Key Management Service
	BackendTypeAzureKV      BackendType = "azurekv"      // Azure Key Vault
	BackendTypeVault        BackendType = "vault"        // HashiCorp Vault
	BackendTypeQuantum      BackendType = "quantum"      // Quantum-safe cryptography (ML-DSA, ML-KEM)
	BackendTypeThreshold    BackendType = "threshold"    // Threshold cryptography (Shamir, threshold ECDSA)
	BackendTypeFrost        BackendType = "frost"        // FROST threshold signatures (RFC 9591)
	BackendTypePhone        BackendType = "phone"        // Android phone as HSM via BLE/USB (TEE/StrongBox)
	BackendTypeSmartCardHSM BackendType = "smartcardhsm" // SmartCard-HSM (Nitrokey HSM, CardContact)
	BackendTypeYubiKey      BackendType = "yubikey"      // YubiKey PIV
	BackendTypeSoftHSM      BackendType = "softhsm"      // SoftHSM2 (development/testing)
)

// =============================================================================
// Key Type
// =============================================================================

// KeyType identifies the purpose and usage of a cryptographic key.
type KeyType uint8

const (
	// Key type constants
	KeyTypeAttestation KeyType = 1 + iota
	KeyTypeCA
	KeyTypeEncapsulation
	KeyTypeEncryption
	KeyTypeEndorsement
	KeyTypeHMAC
	KeyTypeIDevID
	KeyTypeLDevID
	KeyTypeSecret
	KeyTypeSigning
	KeyTypeStorage
	KeyTypeTLS
	KeyTypeTPM
)

// String returns the string representation of the key type.
func (kt KeyType) String() string {
	switch kt {
	case KeyTypeAttestation:
		return "ATTESTATION"
	case KeyTypeCA:
		return "CA"
	case KeyTypeEncapsulation:
		return "ENCAPSULATION"
	case KeyTypeEncryption:
		return "ENCRYPTION"
	case KeyTypeEndorsement:
		return "ENDORSEMENT"
	case KeyTypeHMAC:
		return "HMAC"
	case KeyTypeIDevID:
		return "IDevID"
	case KeyTypeLDevID:
		return "LDevID"
	case KeyTypeSecret:
		return "SECRET"
	case KeyTypeSigning:
		return "SIGNING"
	case KeyTypeStorage:
		return "STORAGE"
	case KeyTypeTLS:
		return "TLS"
	case KeyTypeTPM:
		return "TPM"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", kt)
	}
}

// =============================================================================
// Symmetric Algorithm Types
// =============================================================================

// SymmetricAlgorithm represents symmetric encryption algorithms.
type SymmetricAlgorithm string

const (
	// Symmetric algorithms
	SymmetricAES128GCM         SymmetricAlgorithm = "aes128-gcm"
	SymmetricAES192GCM         SymmetricAlgorithm = "aes192-gcm"
	SymmetricAES256GCM         SymmetricAlgorithm = "aes256-gcm"
	SymmetricChaCha20Poly1305  SymmetricAlgorithm = "chacha20-poly1305"
	SymmetricXChaCha20Poly1305 SymmetricAlgorithm = "xchacha20-poly1305"
)

// String returns the string representation of the SymmetricAlgorithm.
func (sa SymmetricAlgorithm) String() string {
	return string(sa)
}

// IsValid checks if the SymmetricAlgorithm is one of the known algorithms.
func (sa SymmetricAlgorithm) IsValid() bool {
	switch sa {
	case SymmetricAES128GCM, SymmetricAES192GCM, SymmetricAES256GCM,
		SymmetricChaCha20Poly1305, SymmetricXChaCha20Poly1305:
		return true
	default:
		return false
	}
}

// KeySize returns the key size in bits for this symmetric algorithm.
// Returns 0 for unknown algorithms.
func (sa SymmetricAlgorithm) KeySize() int {
	switch sa {
	case SymmetricAES128GCM:
		return 128
	case SymmetricAES192GCM:
		return 192
	case SymmetricAES256GCM, SymmetricChaCha20Poly1305, SymmetricXChaCha20Poly1305:
		return 256
	default:
		return 0
	}
}

// NonceSize returns the nonce size in bytes for this symmetric algorithm.
// Returns 0 for unknown algorithms.
func (sa SymmetricAlgorithm) NonceSize() int {
	switch sa {
	case SymmetricXChaCha20Poly1305:
		return 24 // XChaCha20 uses 192-bit (24-byte) nonces
	case SymmetricAES128GCM, SymmetricAES192GCM, SymmetricAES256GCM, SymmetricChaCha20Poly1305:
		return 12 // Standard 96-bit (12-byte) nonces for GCM and ChaCha20
	default:
		return 0
	}
}

// AEADOptions configures AEAD safety tracking for a symmetric key.
type AEADOptions struct {
	// NonceTracking enables nonce uniqueness checking (highly recommended)
	NonceTracking bool

	// BytesTracking enables tracking of bytes encrypted (highly recommended)
	BytesTracking bool

	// BytesTrackingLimit is the maximum number of bytes that can be encrypted
	// with this key before rotation is required. Default: 350GB for AES-GCM.
	// This limit is based on NIST SP 800-38D recommendations for AES-GCM.
	BytesTrackingLimit int64

	// NonceSize is the nonce size in bytes (default: 12 for GCM)
	NonceSize int
}

// Validate validates the AEAD options and sets defaults.
func (opts *AEADOptions) Validate() error {
	if opts.NonceSize == 0 {
		opts.NonceSize = 12 // Default for GCM
	}
	if opts.NonceSize < 12 {
		return fmt.Errorf("nonce size must be at least 12 bytes, got %d", opts.NonceSize)
	}
	if opts.BytesTracking && opts.BytesTrackingLimit <= 0 {
		opts.BytesTrackingLimit = 350 * 1024 * 1024 * 1024 // 350 GB default
	}
	return nil
}

// DefaultAEADOptions returns recommended default AEAD safety options.
//
// Defaults:
//   - NonceTracking: enabled
//   - BytesTracking: enabled
//   - BytesTrackingLimit: 350GB (NIST recommendation for AES-GCM with 96-bit nonces)
//   - NonceSize: 12 bytes (96 bits, standard for GCM)
func DefaultAEADOptions() *AEADOptions {
	return &AEADOptions{
		NonceTracking:      true,
		BytesTracking:      true,
		BytesTrackingLimit: 350 * 1024 * 1024 * 1024, // 350 GB
		NonceSize:          12,                       // 96 bits for GCM
	}
}

// ECCAttributes contains Elliptic Curve Cryptography specific parameters.
type ECCAttributes struct {
	// Curve specifies the elliptic curve to use
	Curve elliptic.Curve
}

// MarshalJSON implements custom JSON marshaling for ECCAttributes.
// Converts elliptic.Curve to a string identifier.
func (e *ECCAttributes) MarshalJSON() ([]byte, error) {
	var curveName string
	if e.Curve != nil {
		switch e.Curve.Params().Name {
		case "P-224":
			curveName = "P-224"
		case "P-256":
			curveName = "P-256"
		case "P-384":
			curveName = "P-384"
		case "P-521":
			curveName = "P-521"
		default:
			curveName = e.Curve.Params().Name
		}
	}
	return json.Marshal(map[string]string{"curve": curveName})
}

// UnmarshalJSON implements custom JSON unmarshaling for ECCAttributes.
// Converts string identifier back to elliptic.Curve.
func (e *ECCAttributes) UnmarshalJSON(data []byte) error {
	var aux struct {
		Curve string `json:"curve"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	switch aux.Curve {
	case "P-224":
		e.Curve = elliptic.P224()
	case "P-256":
		e.Curve = elliptic.P256()
	case "P-384":
		e.Curve = elliptic.P384()
	case "P-521":
		e.Curve = elliptic.P521()
	case "":
		e.Curve = nil
	default:
		return fmt.Errorf("unsupported elliptic curve: %s", aux.Curve)
	}

	return nil
}

// RSAAttributes contains RSA specific parameters.
type RSAAttributes struct {
	// KeySize specifies the RSA key size in bits
	KeySize int
}

// X25519Attributes contains X25519 key agreement specific parameters.
// X25519 is a Curve25519-based ECDH implementation providing:
// - 32-byte (256-bit) keys
// - Fast, constant-time key agreement
// - 128-bit security level
// - Used for establishing shared secrets in modern protocols
type X25519Attributes struct {
	// No additional parameters needed - X25519 keys are always 32 bytes
}

// QuantumAlgorithm identifies a post-quantum cryptographic algorithm.
type QuantumAlgorithm string

const (
	// QuantumAlgorithmMLDSA44 is ML-DSA-44 (Dilithium2) for digital signatures
	// NIST FIPS 204 standard - Security level 2
	QuantumAlgorithmMLDSA44 QuantumAlgorithm = "ML-DSA-44"

	// QuantumAlgorithmMLDSA65 is ML-DSA-65 (Dilithium3) for digital signatures
	// NIST FIPS 204 standard - Security level 3
	QuantumAlgorithmMLDSA65 QuantumAlgorithm = "ML-DSA-65"

	// QuantumAlgorithmMLDSA87 is ML-DSA-87 (Dilithium5) for digital signatures
	// NIST FIPS 204 standard - Security level 5
	QuantumAlgorithmMLDSA87 QuantumAlgorithm = "ML-DSA-87"

	// QuantumAlgorithmMLKEM512 is ML-KEM-512 (Kyber512) for key encapsulation
	// NIST FIPS 203 standard - Security level 1
	QuantumAlgorithmMLKEM512 QuantumAlgorithm = "ML-KEM-512"

	// QuantumAlgorithmMLKEM768 is ML-KEM-768 (Kyber768) for key encapsulation
	// NIST FIPS 203 standard - Security level 3
	QuantumAlgorithmMLKEM768 QuantumAlgorithm = "ML-KEM-768"

	// QuantumAlgorithmMLKEM1024 is ML-KEM-1024 (Kyber1024) for key encapsulation
	// NIST FIPS 203 standard - Security level 5
	QuantumAlgorithmMLKEM1024 QuantumAlgorithm = "ML-KEM-1024"
)

// QuantumAttributes contains quantum-safe cryptography specific parameters.
// Used with ML-DSA (signatures) and ML-KEM (key encapsulation) algorithms.
type QuantumAttributes struct {
	// Algorithm specifies the quantum-safe algorithm to use
	Algorithm QuantumAlgorithm
}

// =============================================================================
// Threshold Cryptography Types
// =============================================================================

// ThresholdAlgorithm identifies the threshold signature or encryption scheme.
type ThresholdAlgorithm string

const (
	// ThresholdAlgorithmShamir uses Shamir Secret Sharing for threshold operations
	// Split/combine for symmetric keys and secrets
	ThresholdAlgorithmShamir ThresholdAlgorithm = "SHAMIR"
)

// ThresholdAttributes contains threshold cryptography configuration for M-of-N operations.
// This enables distributed key management where M participants out of N total must
// collaborate to perform cryptographic operations (signing, decryption, etc.).
type ThresholdAttributes struct {
	// Threshold is the minimum number of shares required for operations (M)
	// Must be: 2 <= Threshold <= Total <= 255
	Threshold int

	// Total is the total number of shares to generate (N)
	// Must be: Threshold <= Total <= 255
	Total int

	// Algorithm specifies the threshold scheme to use
	Algorithm ThresholdAlgorithm

	// Participants contains identifiers for each share holder
	// Length must equal Total. Each participant gets one share.
	// Example: ["node1", "node2", "node3", "node4", "node5"]
	Participants []string

	// ShareID identifies which share this node owns (1 to Total)
	// Only used when loading a key that already has shares distributed
	ShareID int
}

// Validate checks if the threshold attributes are valid
func (ta *ThresholdAttributes) Validate() error {
	if ta.Threshold < 2 {
		return fmt.Errorf("threshold must be at least 2, got %d", ta.Threshold)
	}
	if ta.Total < ta.Threshold {
		return fmt.Errorf("total (%d) must be >= threshold (%d)", ta.Total, ta.Threshold)
	}
	if ta.Threshold > 255 {
		return fmt.Errorf("threshold cannot exceed 255, got %d", ta.Threshold)
	}
	if ta.Total > 255 {
		return fmt.Errorf("total cannot exceed 255, got %d", ta.Total)
	}
	if len(ta.Participants) > 0 && len(ta.Participants) != ta.Total {
		return fmt.Errorf("participants length (%d) must match total (%d)", len(ta.Participants), ta.Total)
	}
	if ta.ShareID != 0 && (ta.ShareID < 1 || ta.ShareID > ta.Total) {
		return fmt.Errorf("shareID (%d) must be between 1 and total (%d)", ta.ShareID, ta.Total)
	}
	return nil
}

// =============================================================================
// FROST Threshold Signature Types (RFC 9591)
// =============================================================================

// FrostAlgorithm identifies a FROST ciphersuite as defined in RFC 9591.
type FrostAlgorithm string

const (
	// FrostAlgorithmEd25519 is FROST-Ed25519-SHA512 (RFC 9591 Section 6.1)
	// Ed25519 curve with SHA-512 hash - General purpose, high performance
	FrostAlgorithmEd25519 FrostAlgorithm = "FROST-Ed25519-SHA512"

	// FrostAlgorithmRistretto255 is FROST-ristretto255-SHA512 (RFC 9591 Section 6.2)
	// ristretto255 group with SHA-512 hash - Enhanced security properties
	FrostAlgorithmRistretto255 FrostAlgorithm = "FROST-ristretto255-SHA512"

	// FrostAlgorithmEd448 is FROST-Ed448-SHAKE256 (RFC 9591 Section 6.3)
	// Ed448 curve with SHAKE256 hash - Higher security level (224-bit)
	FrostAlgorithmEd448 FrostAlgorithm = "FROST-Ed448-SHAKE256"

	// FrostAlgorithmP256 is FROST-P256-SHA256 (RFC 9591 Section 6.4)
	// NIST P-256 curve with SHA-256 hash - FIPS compliance
	FrostAlgorithmP256 FrostAlgorithm = "FROST-P256-SHA256"

	// FrostAlgorithmSecp256k1 is FROST-secp256k1-SHA256 (RFC 9591 Section 6.5)
	// secp256k1 curve with SHA-256 hash - Bitcoin/Ethereum compatibility
	FrostAlgorithmSecp256k1 FrostAlgorithm = "FROST-secp256k1-SHA256"
)

// String returns the string representation of the FROST algorithm.
func (fa FrostAlgorithm) String() string {
	return string(fa)
}

// IsValid returns true if the FROST algorithm is recognized.
func (fa FrostAlgorithm) IsValid() bool {
	switch fa {
	case FrostAlgorithmEd25519, FrostAlgorithmRistretto255, FrostAlgorithmEd448, FrostAlgorithmP256, FrostAlgorithmSecp256k1:
		return true
	default:
		return false
	}
}

// FrostAttributes contains FROST threshold signature configuration for M-of-N operations.
// This enables distributed signing where M participants out of N total must collaborate
// to produce a valid signature without ever reconstructing the private key.
//
// Unlike Shamir-based threshold schemes, FROST provides:
//   - The private key is NEVER reconstructed (even during signing)
//   - Malicious participant detection (identifiable abort)
//   - Two-round signing protocol (RFC 9591)
type FrostAttributes struct {
	// Threshold is the minimum number of signers required (M)
	// Must be: 2 <= Threshold <= Total <= 255
	Threshold int

	// Total is the total number of participants (N)
	// Must be: Threshold <= Total <= 255
	Total int

	// Algorithm specifies the FROST ciphersuite to use
	Algorithm FrostAlgorithm

	// Participants contains identifiers for each share holder
	// Length must equal Total. Each participant gets one key share.
	// Example: ["node1", "node2", "node3", "node4", "node5"]
	Participants []string

	// ParticipantID identifies which participant this node is (1 to Total)
	// This is the FROST identifier used in the signing protocol
	ParticipantID uint32

	// GroupPublicKey is the threshold group public key (optional, set after generation)
	// This is the public key that verifies signatures from any threshold of participants
	GroupPublicKey []byte
}

// Validate checks if the FROST attributes are valid
func (fa *FrostAttributes) Validate() error {
	if fa.Threshold < 2 {
		return fmt.Errorf("frost: threshold must be at least 2, got %d", fa.Threshold)
	}
	if fa.Total < fa.Threshold {
		return fmt.Errorf("frost: total (%d) must be >= threshold (%d)", fa.Total, fa.Threshold)
	}
	if fa.Threshold > 255 {
		return fmt.Errorf("frost: threshold cannot exceed 255, got %d", fa.Threshold)
	}
	if fa.Total > 255 {
		return fmt.Errorf("frost: total cannot exceed 255, got %d", fa.Total)
	}
	if len(fa.Participants) > 0 && len(fa.Participants) != fa.Total {
		return fmt.Errorf("frost: participants length (%d) must match total (%d)", len(fa.Participants), fa.Total)
	}
	if fa.ParticipantID != 0 && (fa.ParticipantID < 1 || fa.ParticipantID > uint32(fa.Total)) {
		return fmt.Errorf("frost: participantID (%d) must be between 1 and total (%d)", fa.ParticipantID, fa.Total)
	}
	if !fa.Algorithm.IsValid() {
		return fmt.Errorf("frost: invalid algorithm: %s", fa.Algorithm)
	}
	return nil
}

// TPMAttributes contains Trusted Platform Module specific configuration.
// This struct intentionally uses interface{} for TPM-specific types to avoid
type TPMAttributes struct {
	// Handle is the TPM handle for the key
	Handle tpm2.TPMHandle

	// HandleType specifies the type of TPM handle
	HandleType tpm2.TPMHT

	// Hierarchy specifies the TPM hierarchy (owner, endorsement, platform)
	Hierarchy tpm2.TPMHandle

	// HierarchyAuth provides authentication for the hierarchy
	HierarchyAuth Password

	// PublicKeyBytes contains the encoded public key
	PublicKeyBytes []byte

	// PrivateKeyBlob contains the encrypted private key blob
	PrivateKeyBlob []byte

	// HashAlg specifies the TPM hash algorithm
	HashAlg tpm2.TPMIAlgHash

	// PCRSelection specifies Platform Configuration Registers to include
	PCRSelection tpm2.TPMLPCRSelection

	// CertHandle is the handle for certificate storage
	CertHandle tpm2.TPMHandle

	// CertifyInfo contains attestation information
	CertifyInfo []byte

	// CreationTicketDigest contains the creation ticket
	CreationTicketDigest []byte

	// Name is the TPM name for the object
	Name tpm2.TPM2BName

	// Public contains the TPM public structure
	Public tpm2.TPMTPublic

	// BPublic contains the TPM2B_PUBLIC structure
	BPublic tpm2.TPM2BPublic

	// Template contains the key template used for creation
	Template tpm2.TPMTPublic

	// Signature contains the signature from attestation
	Signature []byte

	// SessionCloser provides a function to close TPM sessions
	SessionCloser func() error
}

// Password is an interface for accessing key authentication credentials.
//
// Password represents the authentication value (UserAuth) used to authorize
// TPM key operations. When a key is created with a password, that password
// must be provided for signing, decryption, or other key operations.
//
// Key characteristics of Password:
//   - Used for TPM UserAuth (key authentication/authorization)
//   - Supports String() for human-readable passwords
//   - Can be cached via PlatformPassword for performance (see PasswordCacheConfig)
//   - Typically used with KeyAttributes.Password field
//
// For sealed arbitrary data (not key auth), use Secret instead.
type Password interface {
	// Bytes returns the password as a byte slice
	Bytes() []byte

	// String returns the password as a string
	String() (string, error)

	// Clear zeros out the password from memory
	Clear()
}

// ClearPassword is a simple in-memory implementation of the Password interface
// that stores the password in clear text. This implementation should only be
// used in development or testing environments, or where the security model
// explicitly accepts storing passwords in memory.
type ClearPassword struct {
	password []byte
}

// NewPassword creates a new clear text password stored in memory.
// The password is copied to prevent external modification.
//
// Use this for key authentication values that will be passed to TPM
// operations as UserAuth. For sealed arbitrary data, use NewSealData instead.
func NewPassword(password []byte) Password {
	p := make([]byte, len(password))
	copy(p, password)
	return &ClearPassword{password: p}
}

// NewPasswordFromString creates a new clear text password from a string.
// The string is converted to bytes and stored in memory.
func NewPasswordFromString(password string) Password {
	return &ClearPassword{password: []byte(password)}
}

// String returns the password as a string.
func (p *ClearPassword) String() (string, error) {
	return string(p.password), nil
}

// Bytes returns the password as a byte slice.
// A copy is returned to prevent external modification of the internal password.
func (p *ClearPassword) Bytes() []byte {
	// Return a copy to prevent external modification
	b := make([]byte, len(p.password))
	copy(b, p.password)
	return b
}

// Clear overwrites the password memory with zeros.
// This should be called when the password is no longer needed to minimize
// the time sensitive data remains in memory.
func (p *ClearPassword) Clear() {
	for i := range p.password {
		p.password[i] = 0
	}
}

// SealData provides access to arbitrary data for sealing operations.
//
// SealData represents the actual payload being sealed - application
// secrets, encryption keys, random bytes, or any arbitrary data.
// This is used across all backends that support sealing:
//   - TPM2: Stored in TPM2B_SENSITIVE_DATA during seal operations
//   - PKCS#11: Encrypted with HSM-resident AES key
//   - Cloud KMS: Protected via envelope encryption
//   - PKCS#8: Encrypted with HKDF-derived key
//
// Key characteristics of SealData:
//   - Backend-agnostic sealed payload interface
//   - No String() method - seal data is often binary
//   - Used with KeyAttributes.SealData field
//
// Password vs SealData:
//   - Password: Key/object authentication - "the credential to access the key"
//   - SealData: Sealed payload - "the data being protected"
//
// Example: When sealing a database password:
//   - SealData holds the actual database password being sealed
//   - Password (optional) is the auth value to later unseal it
//
// Note: This data will exist in system memory until sealed. For secrets
// that should never touch system memory, use backend-generated keys
// (e.g., TPM keys with SensitiveDataOrigin=true).
type SealData interface {
	// Bytes returns the data as a byte slice.
	// Returns nil if the data cannot be retrieved.
	Bytes() []byte

	// Clear zeros out the data from memory.
	// This should be called when the data is no longer needed.
	Clear()
}

// sealData is an in-memory implementation of the SealData interface.
// The data is stored in memory temporarily before being sealed.
type sealData struct {
	data []byte
}

// NewSealData creates a new SealData instance for data to be sealed.
// The data is copied to prevent external modification.
//
// Use this for arbitrary data being sealed (the payload).
// For key/object authentication values, use NewPassword instead.
//
// Note: This data will exist in system memory until sealed. For secrets
// that should never touch system memory, use backend-generated keys
// (e.g., TPM keys with SensitiveDataOrigin=true).
func NewSealData(data []byte) SealData {
	d := make([]byte, len(data))
	copy(d, data)
	return &sealData{data: d}
}

// Bytes returns the data as a byte slice.
// A copy is returned to prevent external modification.
func (s *sealData) Bytes() []byte {
	if s.data == nil {
		return nil
	}
	b := make([]byte, len(s.data))
	copy(b, s.data)
	return b
}

// Clear overwrites the data memory with zeros.
func (s *sealData) Clear() {
	for i := range s.data {
		s.data[i] = 0
	}
}

// PasswordCacheConfig holds configuration for platform password caching.
// When caching is enabled, the unsealed password is stored in memory
// to avoid repeated TPM unsealing operations.
type PasswordCacheConfig struct {
	// Enabled determines whether password caching is active.
	// When false, every password access will unseal from the TPM.
	Enabled bool

	// TTL is the time-to-live for cached passwords in seconds.
	// After this duration, the cache is invalidated and the password
	// will be unsealed again on the next access.
	// If zero and Enabled is true, defaults to 300 (5 minutes).
	TTL int
}

// KeyAttributes contains all configuration parameters for a cryptographic key,
// including algorithm selection, store configuration, and optional parent keys.
type KeyAttributes struct {
	// CN is the common name identifier for the key
	CN string

	// TenantID optionally identifies the tenant that owns this key.
	// When empty, single-tenant mode is used (existing behavior).
	// When set, storage paths are namespaced by tenant for isolation.
	TenantID string

	// Debug enables detailed logging for this key
	Debug bool

	// Hash specifies the hash function to use with this key
	Hash crypto.Hash

	// KeyAlgorithm specifies the public key algorithm (RSA, ECDSA, Ed25519)
	KeyAlgorithm x509.PublicKeyAlgorithm

	// SymmetricAlgorithm specifies the symmetric encryption algorithm (AES-GCM, ChaCha20-Poly1305)
	// This field is used when KeyAlgorithm is not set (for symmetric keys)
	SymmetricAlgorithm SymmetricAlgorithm

	// KeyType specifies the purpose of the key
	KeyType KeyType

	// Partition specifies the logical storage partition (optional)
	Partition Partition

	// Parent references parent key attributes for hierarchical key structures
	Parent *KeyAttributes

	// Password provides authentication for the key
	Password Password

	// PlatformPolicy indicates if platform-specific policies apply
	PlatformPolicy bool

	// PasswordCache contains configuration for platform password caching.
	// When PlatformPolicy is true and PasswordCache is set with Enabled=true,
	// the unsealed password is cached in memory to avoid repeated TPM operations.
	PasswordCache *PasswordCacheConfig

	// SignatureAlgorithm specifies the signature algorithm to use
	SignatureAlgorithm x509.SignatureAlgorithm

	// StoreType specifies the backend storage type (e.g., "software", "tpm2", "pkcs11").
	// This is both the storage type and the backend name used for registry lookup.
	StoreType StoreType

	// ECCAttributes contains ECC-specific configuration
	ECCAttributes *ECCAttributes

	// RSAAttributes contains RSA-specific configuration
	RSAAttributes *RSAAttributes

	// X25519Attributes contains X25519-specific configuration for key agreement
	X25519Attributes *X25519Attributes

	// QuantumAttributes contains quantum-safe algorithm configuration (ML-DSA, ML-KEM)
	QuantumAttributes *QuantumAttributes

	// ThresholdAttributes contains threshold cryptography configuration (M-of-N signatures)
	ThresholdAttributes *ThresholdAttributes

	// FrostAttributes contains FROST threshold signature configuration (RFC 9591)
	// Used for M-of-N threshold signing where the private key is never reconstructed
	FrostAttributes *FrostAttributes

	// AEADOptions contains AEAD safety tracking options (only for symmetric keys)
	// If nil, default safety options will be applied (tracking enabled).
	AEADOptions *AEADOptions

	// Exportable indicates if the key can be exported from the backend.
	// For hardware-backed keys (TPM, HSM), this may be restricted by policy.
	// Default is false for security - keys must be explicitly marked as exportable.
	Exportable bool

	// TPMAttributes contains TPM-specific configuration
	TPMAttributes *TPMAttributes

	// PIVSlot specifies the target PIV slot for slot-constrained PKCS#11 tokens
	// (e.g., YubiKey PIV). When empty, the backend uses its default CKA_ID
	// derivation. This field is only meaningful for PKCS#11 backends that
	// implement pivcert.SlotModel.
	PIVSlot string `json:"piv_slot,omitempty" yaml:"piv_slot,omitempty"`

	// WrapAttributes specifies key wrapping configuration
	WrapAttributes *KeyAttributes

	// SealData holds the payload data to be sealed (backend-agnostic).
	// This is the actual data being protected - application secrets,
	// user credentials, encryption keys, or arbitrary data.
	//
	// Unlike Password (which authenticates access to the key/sealed object),
	// SealData is the payload being sealed/unsealed.
	//
	// Sealing mechanism depends on the backend:
	//   - TPM2: PCR-bound seal/unseal
	//   - PKCS#11: AES-GCM with HSM-resident key
	//   - Cloud KMS: Envelope encryption
	//   - PKCS#8: HKDF + AES-GCM
	//
	// Note: This data will exist in system memory until sealed. For secrets
	// that should never touch system memory, use backend-generated keys.
	SealData SealData
}

// String returns a human-readable representation of the key attributes.
func (attrs KeyAttributes) String() string {
	var sb strings.Builder

	var password, sealDataStr string
	if attrs.Debug && attrs.Password != nil {
		if p, err := attrs.Password.String(); err == nil {
			password = p
		}
	}
	if attrs.Debug && attrs.SealData != nil {
		if s := attrs.SealData.Bytes(); s != nil {
			sealDataStr = string(s)
		}
	}

	sb.WriteString("Key Attributes\n")
	fmt.Fprintf(&sb, "  Common Name: %s\n", attrs.CN)
	fmt.Fprintf(&sb, "  Debug: %t\n", attrs.Debug)
	fmt.Fprintf(&sb, "  Hash: %s\n", attrs.Hash.String())
	fmt.Fprintf(&sb, "  Key Algorithm: %s\n", attrs.KeyAlgorithm)
	fmt.Fprintf(&sb, "  Platform Policy: %t\n", attrs.PlatformPolicy)
	fmt.Fprintf(&sb, "  Signature Algorithm: %s\n", attrs.SignatureAlgorithm.String())
	fmt.Fprintf(&sb, "  Store: %s\n", attrs.StoreType)
	fmt.Fprintf(&sb, "  Type: %s\n", attrs.KeyType)

	if attrs.ECCAttributes != nil {
		sb.WriteString("ECC Attributes\n")
		fmt.Fprintf(&sb, "  Curve: %s\n", attrs.ECCAttributes.Curve.Params().Name)
	} else if attrs.RSAAttributes != nil {
		sb.WriteString("RSA Attributes\n")
		fmt.Fprintf(&sb, "  Size: %d\n", attrs.RSAAttributes.KeySize)
	} else if attrs.X25519Attributes != nil {
		sb.WriteString("X25519 Attributes\n")
		sb.WriteString("  Curve: X25519 (Curve25519)\n")
	}

	if attrs.Debug {
		sb.WriteString("Secrets\n")
		fmt.Fprintf(&sb, "  Password: %s\n", password)
		fmt.Fprintf(&sb, "  SealData: %s\n", sealDataStr)
	}

	return sb.String()
}

// Validate checks if the KeyAttributes are valid and have all required fields.
func (attrs *KeyAttributes) Validate() error {
	// Validate required fields
	if attrs.CN == "" {
		return fmt.Errorf("common name (CN) is required")
	}

	if attrs.StoreType == "" {
		return fmt.Errorf("store type is required")
	}

	if attrs.KeyType == 0 {
		return fmt.Errorf("key type is required")
	}

	// Validate algorithm-specific attributes
	if attrs.X25519Attributes != nil {
		// X25519 key agreement validation
		// X25519 has no additional attributes to validate beyond the struct itself
	} else if attrs.QuantumAttributes != nil {
		// Quantum-safe key validation
		switch attrs.QuantumAttributes.Algorithm {
		case QuantumAlgorithmMLDSA44, QuantumAlgorithmMLDSA65, QuantumAlgorithmMLDSA87:
			// ML-DSA signatures - no additional attributes required
		case QuantumAlgorithmMLKEM512, QuantumAlgorithmMLKEM768, QuantumAlgorithmMLKEM1024:
			// ML-KEM key encapsulation - no additional attributes required
		default:
			return fmt.Errorf("unsupported quantum algorithm: %s", attrs.QuantumAttributes.Algorithm)
		}
	} else if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		// Asymmetric key validation
		switch attrs.KeyAlgorithm {
		case x509.RSA:
			if attrs.RSAAttributes == nil {
				return fmt.Errorf("RSA attributes are required for RSA keys")
			}
			if attrs.RSAAttributes.KeySize < 2048 {
				return fmt.Errorf("RSA key size must be at least 2048 bits")
			}
		case x509.ECDSA:
			if attrs.ECCAttributes == nil {
				return fmt.Errorf("ECC attributes are required for ECDSA keys")
			}
			if attrs.ECCAttributes.Curve == nil {
				return fmt.Errorf("curve is required for ECDSA keys")
			}
		case x509.Ed25519:
			// Ed25519 has no additional attributes to validate
		default:
			return fmt.Errorf("unsupported key algorithm: %s", attrs.KeyAlgorithm)
		}
	} else if attrs.SymmetricAlgorithm != "" {
		// Symmetric key validation - key size is derived from the algorithm via KeySize() method
		if !attrs.SymmetricAlgorithm.IsValid() {
			return fmt.Errorf("unsupported symmetric algorithm: %s", attrs.SymmetricAlgorithm)
		}
	} else if attrs.FrostAttributes != nil {
		// FROST threshold signature validation (RFC 9591)
		if err := attrs.FrostAttributes.Validate(); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("either KeyAlgorithm, SymmetricAlgorithm, QuantumAttributes, or FrostAttributes must be set")
	}

	return nil
}

// IsSymmetric returns true if this key is a symmetric key (has SymmetricAlgorithm set).
// Returns false for asymmetric keys.
func (attrs *KeyAttributes) IsSymmetric() bool {
	return attrs.SymmetricAlgorithm != ""
}

// ID returns a unique identifier for the key based on its attributes.
// When TenantID is set, it is prefixed: tenantid:[partition:]storetype:keytype:cn:algorithm
// Format for X25519 keys: [tenantid:][partition:]storetype:keytype:cn:x25519
// Format for quantum keys: [tenantid:][partition:]storetype:keytype:cn:quantumalgorithm
// Format for asymmetric keys: [tenantid:][partition:]storetype:keytype:cn:keyalgorithm
// Format for symmetric keys: [tenantid:][partition:]storetype:keytype:cn:symmetricalgorithm
func (attrs *KeyAttributes) ID() string {
	var algorithm string

	// Determine algorithm string
	if attrs.X25519Attributes != nil {
		// X25519 key agreement
		algorithm = "x25519"
	} else if attrs.QuantumAttributes != nil {
		// Quantum-safe key
		algorithm = strings.ToLower(string(attrs.QuantumAttributes.Algorithm))
	} else if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		// Asymmetric key
		algorithm = strings.ToLower(attrs.KeyAlgorithm.String())
	} else if attrs.SymmetricAlgorithm != "" {
		// Symmetric key
		algorithm = string(attrs.SymmetricAlgorithm)
	} else {
		// Fallback to "unknown" if neither is set
		algorithm = "unknown"
	}

	// Build base ID based on whether partition is set
	// Use lowercase for KeyType to ensure consistent key ID format
	keyType := strings.ToLower(attrs.KeyType.String())
	var baseID string
	if attrs.Partition != "" {
		baseID = fmt.Sprintf("%s:%s:%s:%s:%s",
			attrs.Partition,
			attrs.StoreType,
			keyType,
			attrs.CN,
			algorithm)
	} else {
		baseID = fmt.Sprintf("%s:%s:%s:%s",
			attrs.StoreType,
			keyType,
			attrs.CN,
			algorithm)
	}

	// Prefix with TenantID when set for multi-tenant isolation
	if attrs.TenantID != "" {
		return attrs.TenantID + ":" + baseID
	}

	return baseID
}

// KeyID returns the unique identifier for this key in the 4-part format:
// backend:type:algo:keyname (e.g., "tpm2:signing:ecdsa:my-key")
//
// If only the CN is set (no backend, type, or algorithm), returns just the keyname
// as a shorthand. Otherwise returns the full 4-part format with empty segments
// for unspecified fields.
//
// Examples:
//   - Full: "pkcs11:signing:ecdsa:my-key"
//   - Backend only: "pkcs11:::my-key"
//   - Shorthand: "my-key" (when only CN is set)
//
// This is the canonical identifier format used throughout the xkms API.
func (attrs *KeyAttributes) KeyID() string {
	// If only CN is set, return just the keyname as shorthand
	if attrs.StoreType == "" && attrs.KeyType == 0 && attrs.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return attrs.CN
	}

	// Build backend string
	backendStr := string(attrs.StoreType)

	// Build key type string
	var keyTypeStr string
	switch attrs.KeyType {
	case KeyTypeAttestation:
		keyTypeStr = "attestation"
	case KeyTypeCA:
		keyTypeStr = "ca"
	case KeyTypeEncryption:
		keyTypeStr = "encryption"
	case KeyTypeEndorsement:
		keyTypeStr = "endorsement"
	case KeyTypeHMAC:
		keyTypeStr = "hmac"
	case KeyTypeIDevID:
		keyTypeStr = "idevid"
	case KeyTypeSecret:
		keyTypeStr = "secret"
	case KeyTypeSigning:
		keyTypeStr = "signing"
	case KeyTypeStorage:
		keyTypeStr = "storage"
	case KeyTypeTLS:
		keyTypeStr = "tls"
	case KeyTypeTPM:
		keyTypeStr = "tpm"
	}

	// Build algorithm string
	var algoStr string
	if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		switch attrs.KeyAlgorithm {
		case x509.RSA:
			algoStr = "rsa"
		case x509.ECDSA:
			algoStr = "ecdsa"
		case x509.Ed25519:
			algoStr = "ed25519"
		default:
			algoStr = strings.ToLower(attrs.KeyAlgorithm.String())
		}
	}

	// Return 4-part format: backend:type:algo:keyname
	return fmt.Sprintf("%s:%s:%s:%s", backendStr, keyTypeStr, algoStr, attrs.CN)
}

// CertificateID returns the storage identifier for certificates associated with this key.
// This is an alias for KeyID() since certificates are uniquely tied to their keys.
func (attrs *KeyAttributes) CertificateID() string {
	return attrs.KeyID()
}

// =============================================================================
// Backend Capabilities
// =============================================================================

// SecurityLevel indicates the security strength of a backend implementation.
// Higher values indicate more secure implementations with stronger key protection.
type SecurityLevel uint8

const (
	// SecurityLevelLow indicates software-only key protection.
	// Keys are stored on disk with software encryption.
	// Examples: Software/PKCS8 backend
	SecurityLevelLow SecurityLevel = 0

	// SecurityLevelMedium indicates cloud-managed key protection.
	// Keys are protected by remote HSMs via network APIs.
	// Examples: AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault
	SecurityLevelMedium SecurityLevel = 1

	// SecurityLevelHigh indicates local HSM key protection.
	// Keys are protected by hardware security modules under local control.
	// Examples: PKCS#11 HSMs, SmartCards
	SecurityLevelHigh SecurityLevel = 2

	// SecurityLevelVeryHigh indicates hardware-bound non-exportable keys.
	// Keys are generated in and never leave the hardware.
	// Examples: TPM 2.0 (with FixedTPM attribute)
	SecurityLevelVeryHigh SecurityLevel = 3
)

// String returns a human-readable name for the security level.
func (l SecurityLevel) String() string {
	switch l {
	case SecurityLevelLow:
		return "Low"
	case SecurityLevelMedium:
		return "Medium"
	case SecurityLevelHigh:
		return "High"
	case SecurityLevelVeryHigh:
		return "VeryHigh"
	default:
		return "Unknown"
	}
}

// Description returns a detailed description of the security level.
func (l SecurityLevel) Description() string {
	switch l {
	case SecurityLevelLow:
		return "Software-only, keys stored on disk"
	case SecurityLevelMedium:
		return "Cloud KMS, network-dependent HSM protection"
	case SecurityLevelHigh:
		return "Local HSM, hardware-protected keys"
	case SecurityLevelVeryHigh:
		return "TPM 2.0, hardware-bound non-exportable keys"
	default:
		return "Unknown security level"
	}
}

// Capabilities declares what features a backend supports.
type Capabilities struct {
	// Keys indicates if the backend supports key generation and storage.
	// This should always be true for all backends.
	Keys bool

	// HardwareBacked indicates if keys are stored in hardware (HSM, TPM, etc).
	HardwareBacked bool

	// Signing indicates if the backend implements crypto.Signer.
	Signing bool

	// Decryption indicates if the backend implements crypto.Decrypter.
	Decryption bool

	// KeyRotation indicates if the backend supports key rotation.
	KeyRotation bool

	// SymmetricEncryption indicates if the backend supports symmetric encrypt/decrypt operations.
	SymmetricEncryption bool

	// Sealing indicates if the backend supports seal/unseal operations.
	// Sealing protects data using the backend's native mechanism:
	//   - TPM2: PCR-bound sealing
	//   - PKCS#11: HSM-resident key encryption
	//   - Cloud KMS: Envelope encryption
	//   - PKCS#8: HKDF + AES-GCM
	Sealing bool

	// Import indicates if the backend supports importing keys via wrapping.
	// This allows secure transfer of key material into the backend.
	Import bool

	// Export indicates if the backend supports exporting keys via wrapping.
	// Note: Some backends (Azure KV) support Import but not Export for security.
	// Hardware-backed keys (TPM with FixedTPM=true) may not be exportable.
	Export bool

	// KeyAgreement indicates if the backend supports ECDH key agreement.
	KeyAgreement bool

	// ECIES indicates if the backend supports ECIES public key encryption.
	ECIES bool

	// Attestation indicates if the backend supports key attestation.
	// Attesting backends can produce cryptographic proof that keys are hardware-backed.
	Attestation bool

	// QuantumSigning indicates if the backend supports post-quantum digital signatures (ML-DSA).
	QuantumSigning bool

	// KeyEncapsulation indicates if the backend supports key encapsulation mechanisms (ML-KEM).
	KeyEncapsulation bool

	// SecurityLevel indicates the security strength of this backend.
	// Used for sorting backends by security preference in UIs.
	// Values: 0=Low (software), 1=Medium (cloud), 2=High (PKCS11), 3=VeryHigh (TPM2)
	SecurityLevel SecurityLevel
}

// SupportsSymmetricEncryption returns true if the backend implements symmetric operations.
func (c Capabilities) SupportsSymmetricEncryption() bool {
	return c.SymmetricEncryption
}

// SupportsImportExport returns true if the backend implements both import and export operations.
func (c Capabilities) SupportsImportExport() bool {
	return c.Import && c.Export
}

// SupportsKeyAgreement returns true if the backend implements ECDH key agreement.
func (c Capabilities) SupportsKeyAgreement() bool {
	return c.KeyAgreement
}

// SupportsECIES returns true if the backend implements ECIES encryption/decryption.
func (c Capabilities) SupportsECIES() bool {
	return c.ECIES
}

// SupportsQuantumSigning returns true if the backend supports post-quantum digital signatures.
func (c Capabilities) SupportsQuantumSigning() bool {
	return c.QuantumSigning
}

// SupportsKeyEncapsulation returns true if the backend supports key encapsulation mechanisms.
func (c Capabilities) SupportsKeyEncapsulation() bool {
	return c.KeyEncapsulation
}

// HasKeys returns true if the backend supports key storage.
func (c Capabilities) HasKeys() bool {
	return c.Keys
}

// IsHardwareBacked returns true if keys are stored in hardware.
func (c Capabilities) IsHardwareBacked() bool {
	return c.HardwareBacked
}

// SupportsSign returns true if the backend supports signing operations.
func (c Capabilities) SupportsSign() bool {
	return c.Signing
}

// SupportsDecrypt returns true if the backend supports decryption operations.
func (c Capabilities) SupportsDecrypt() bool {
	return c.Decryption
}

// SupportsSealing returns true if the backend supports seal/unseal operations.
func (c Capabilities) SupportsSealing() bool {
	return c.Sealing
}

// SupportsKeyRotation returns true if the backend supports key rotation.
func (c Capabilities) SupportsKeyRotation() bool {
	return c.KeyRotation
}

// GetSecurityLevel returns the security level of this backend.
func (c Capabilities) GetSecurityLevel() SecurityLevel {
	return c.SecurityLevel
}

// String returns a string representation of the capabilities.
func (c Capabilities) String() string {
	return fmt.Sprintf("Capabilities{Keys: %v, HardwareBacked: %v, Signing: %v, Decryption: %v, KeyRotation: %v, SecurityLevel: %v}",
		c.Keys, c.HardwareBacked, c.Signing, c.Decryption, c.KeyRotation, c.SecurityLevel)
}

// NewSoftwareCapabilities returns capabilities for a software-based backend.
// SecurityLevel is set to Low (software-only key protection).
func NewSoftwareCapabilities() Capabilities {
	return Capabilities{
		Keys:           true,
		HardwareBacked: false,
		Signing:        true,
		Decryption:     true,
		KeyRotation:    false,
		SecurityLevel:  SecurityLevelLow,
	}
}

// NewHardwareCapabilities returns capabilities for a hardware-based backend.
// SecurityLevel defaults to High (local HSM) but should be overridden by
// specific backends (e.g., TPM2 sets VeryHigh, Cloud KMS sets Medium).
func NewHardwareCapabilities() Capabilities {
	return Capabilities{
		Keys:           true,
		HardwareBacked: true,
		Signing:        true,
		Decryption:     true,
		KeyRotation:    false,
		SecurityLevel:  SecurityLevelHigh,
	}
}

// NewUnifiedSoftwareCapabilities returns capabilities for the unified software backend
// which supports both asymmetric and symmetric operations.
// SecurityLevel is set to Low (software-only key protection).
func NewUnifiedSoftwareCapabilities() Capabilities {
	return Capabilities{
		Keys:                true,
		HardwareBacked:      false,
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: true,
		SecurityLevel:       SecurityLevelLow,
	}
}

// =============================================================================
// Backend Interfaces
// =============================================================================

// Backend provides cryptographic key operations.
// This interface focuses ONLY on key management - certificate storage
// is handled separately via the storage.CertificateStorage interface.
//
// Implementations must be thread-safe.
//
// Design rationale:
//   - Backends handle crypto operations (generate, sign, decrypt)
//   - Certificate storage is ALWAYS external (even for PKCS#11/TPM2)
//   - This allows maximum flexibility in storage strategies
type KeyProvider interface {
	// Type returns the backend type identifier.
	Type() BackendType

	// Capabilities returns what features this backend supports.
	Capabilities() Capabilities

	// GenerateKey generates a new private key with the given attributes.
	// The key is stored internally by the backend (if it supports native storage)
	// or externally via KeyStorage (for backends like PKCS#8).
	GenerateKey(attrs *KeyAttributes) (crypto.PrivateKey, error)

	// GetKey retrieves an existing private key by its attributes.
	// Returns an error if the key does not exist.
	GetKey(attrs *KeyAttributes) (crypto.PrivateKey, error)

	// DeleteKey removes a key identified by its attributes.
	// Returns an error if the key does not exist.
	DeleteKey(attrs *KeyAttributes) error

	// ListKeys returns attributes for all keys managed by this backend.
	// Returns an empty slice if no keys exist.
	ListKeys() ([]*KeyAttributes, error)

	// Signer returns a crypto.Signer for the key identified by attrs.
	// This allows the key to be used for signing operations without
	// exposing the private key material.
	// Returns an error if the key does not exist or doesn't support signing.
	Signer(attrs *KeyAttributes) (crypto.Signer, error)

	// Decrypter returns a crypto.Decrypter for the key identified by attrs.
	// This allows the key to be used for decryption operations without
	// exposing the private key material.
	// Returns an error if the key does not exist or doesn't support decryption.
	Decrypter(attrs *KeyAttributes) (crypto.Decrypter, error)

	// RotateKey rotates/updates a key identified by attrs.
	// For cloud KMS backends, this typically creates a new key version.
	// For hardware backends, behavior depends on the device capabilities.
	// Returns an error if the key does not exist or rotation is not supported.
	RotateKey(attrs *KeyAttributes) error

	// Close releases any resources held by the backend.
	// After calling Close, the backend should not be used.
	Close() error
}

// AttestingKeyProvider extends KeyProvider with key attestation capabilities.
// Key providers that support hardware key attestation should implement this interface.
// Attestation proves that a key was generated in hardware and never left the secure boundary.
//
// This is critical for zero-trust architectures and compliance requirements
// (FIPS 140-2, Common Criteria, supply chain security).
//
// Only hardware-backed key providers (TPM2, PKCS#11) may implement this interface.
type AttestingKeyProvider interface {
	KeyProvider

	// AttestKey generates an attestation statement proving a key was created in hardware.
	//
	// The attestation includes:
	//   - Signature from hardware's attestation key
	//   - Certificate chain proving authenticity
	//   - Format-specific evidence (TPM2_Certify, HSM data)
	//   - Optional PCR values, nonces, and claims
	//
	// Parameters:
	//   - attrs: Key attributes to attest
	//   - nonce: Optional challenge for freshness (prevents replay attacks)
	//
	// Returns AttestationStatement (from attestation package) or error.
	// May return ErrNotSupported for software backends or unsupported keys.
	AttestKey(attrs *KeyAttributes, nonce []byte) (interface{}, error)
}

// SymmetricKey represents a symmetric encryption key.
// This is the symmetric analog to crypto.PrivateKey for asymmetric operations.
type SymmetricKey interface {
	// Algorithm returns the symmetric algorithm (e.g., "aes128-gcm", "aes256-gcm")
	Algorithm() string

	// KeySize returns the key size in bits (128, 192, or 256 for AES)
	KeySize() int

	// Raw returns the raw key bytes (use with caution - for backend internal use)
	// Most code should use the SymmetricEncrypter interface instead.
	// Returns ErrNotSupported for hardware-backed keys that cannot expose key material.
	Raw() ([]byte, error)
}

// EncryptOptions contains options for symmetric encryption operations.
type EncryptOptions struct {
	// AdditionalData is authenticated but not encrypted (AEAD)
	AdditionalData []byte

	// Nonce is the nonce/IV to use. If nil, a random nonce is generated.
	// For GCM, this should be 12 bytes (96 bits) unless you have a specific reason.
	Nonce []byte
}

// DecryptOptions contains options for symmetric decryption operations.
type DecryptOptions struct {
	// AdditionalData is authenticated data that must match encryption (AEAD)
	AdditionalData []byte
}

// EncryptedData represents the result of an encryption operation.
// For AES-GCM, this includes the ciphertext, nonce, and authentication tag.
type EncryptedData struct {
	// Ciphertext is the encrypted data
	Ciphertext []byte

	// Nonce is the nonce/IV used for encryption (must be stored with ciphertext)
	Nonce []byte

	// Tag is the authentication tag (for AEAD modes like GCM)
	// For GCM, this is typically 16 bytes and may be appended to Ciphertext
	Tag []byte

	// Algorithm identifies the encryption algorithm used
	Algorithm string

	// Metadata contains additional backend-specific data (e.g., encrypted DEK for envelope encryption).
	// Keys should be namespaced for clarity (e.g., "encryptedDEK", "kmsKeyId").
	Metadata map[string][]byte
}

// SymmetricEncrypter provides symmetric encryption and decryption operations.
// This is analogous to crypto.Signer for asymmetric operations.
type SymmetricEncrypter interface {
	// Encrypt encrypts plaintext using the symmetric key.
	// For AES-GCM, this provides authenticated encryption.
	// Returns EncryptedData containing ciphertext, nonce, and tag.
	Encrypt(plaintext []byte, opts *EncryptOptions) (*EncryptedData, error)

	// Decrypt decrypts ciphertext using the symmetric key.
	// For AES-GCM, this verifies authentication before decrypting.
	// Returns an error if authentication fails.
	Decrypt(data *EncryptedData, opts *DecryptOptions) ([]byte, error)
}

// SymmetricKeyProvider extends KeyProvider with symmetric encryption capabilities.
// Key providers that support symmetric operations should implement this interface.
type SymmetricKeyProvider interface {
	KeyProvider

	// GenerateSymmetricKey generates a new symmetric key with the given attributes.
	// The key is stored internally by the backend (if it supports native storage)
	// or externally via KeyStorage (for backends like PKCS#8).
	GenerateSymmetricKey(attrs *KeyAttributes) (SymmetricKey, error)

	// GetSymmetricKey retrieves an existing symmetric key by its attributes.
	// Returns an error if the key does not exist.
	GetSymmetricKey(attrs *KeyAttributes) (SymmetricKey, error)

	// SymmetricEncrypter returns a SymmetricEncrypter for the key identified by attrs.
	// This allows the key to be used for encryption/decryption operations without
	// exposing the key material (especially important for HSM/KMS backends).
	// Returns an error if the key does not exist or doesn't support symmetric operations.
	SymmetricEncrypter(attrs *KeyAttributes) (SymmetricEncrypter, error)
}

// =============================================================================
// Key Agreement Types
// =============================================================================

// KDFAlgorithm identifies the key derivation function to use.
type KDFAlgorithm string

const (
	// KDFAlgorithmHKDF uses HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869).
	// This is the most widely used KDF for key agreement outputs.
	KDFAlgorithmHKDF KDFAlgorithm = "HKDF"

	// KDFAlgorithmSP800108Counter uses NIST SP 800-108 Counter Mode KDF.
	// Required for FIPS-compliant key derivation in some government contexts.
	KDFAlgorithmSP800108Counter KDFAlgorithm = "SP800-108-COUNTER"

	// KDFAlgorithmSP800108Feedback uses NIST SP 800-108 Feedback Mode KDF.
	KDFAlgorithmSP800108Feedback KDFAlgorithm = "SP800-108-FEEDBACK"

	// KDFAlgorithmSP80056A uses NIST SP 800-56A Concatenation KDF.
	// Often used in ECDH key agreement protocols.
	KDFAlgorithmSP80056A KDFAlgorithm = "SP800-56A"

	// KDFAlgorithmX963 uses ANSI X9.63 Key Derivation Function.
	// Compatible with many cryptographic libraries and standards.
	KDFAlgorithmX963 KDFAlgorithm = "X963"
)

// String returns the string representation of the KDF algorithm.
func (k KDFAlgorithm) String() string {
	return string(k)
}

// IsValid returns true if the KDF algorithm is recognized.
func (k KDFAlgorithm) IsValid() bool {
	switch k {
	case KDFAlgorithmHKDF, KDFAlgorithmSP800108Counter, KDFAlgorithmSP800108Feedback,
		KDFAlgorithmSP80056A, KDFAlgorithmX963:
		return true
	default:
		return false
	}
}

// KDFParams contains parameters for key derivation functions used in key agreement.
// These parameters control how the raw shared secret from ECDH is transformed
// into usable cryptographic key material.
type KDFParams struct {
	// Algorithm specifies the KDF algorithm to use (e.g., HKDF, SP800-108-COUNTER).
	// If empty, defaults to HKDF.
	Algorithm KDFAlgorithm

	// Hash specifies the hash algorithm for the KDF (e.g., SHA-256, SHA-384, SHA-512).
	// Must be compatible with the chosen KDF algorithm.
	// If empty, defaults to SHA-256.
	Hash string

	// Salt is the optional salt value for the KDF.
	// For HKDF, this is used in the extract phase.
	// For SP800-108, this may be incorporated into the context.
	// Can be nil for unsalted derivation.
	Salt []byte

	// Info is the optional context and application specific information.
	// For HKDF, this is used in the expand phase.
	// For SP800-108, this is the Label || 0x00 || Context || L structure.
	// Can be nil if no additional context is needed.
	Info []byte

	// KeyLength specifies the desired output key length in bytes.
	// Must be positive and appropriate for the intended use.
	// For example: 16 for AES-128, 32 for AES-256.
	KeyLength int

	// DerivationMode specifies how the derived key should be handled.
	// For standard ECDH operations, this defaults to KeyDerivationModeExport.
	// For secure key agreement operations, this can be set to keep the key
	// within hardware security boundaries.
	DerivationMode KeyDerivationMode

	// DerivedKeyAttributes contains template parameters for HSM-resident keys.
	// Only used when DerivationMode is KeyDerivationModeHSMResident.
	// If nil, default template parameters are used.
	DerivedKeyAttributes *DerivedKeyTemplateParams

	// HSMKDFType specifies the PKCS#11 KDF type for HSM_KDF mode.
	// This is the CKD_* value passed to CKM_ECDH1_DERIVE mechanism.
	// Common values: CKD_SHA256_KDF, CKD_SHA384_KDF, CKD_SHA512_KDF.
	// If zero, the backend selects an appropriate default.
	HSMKDFType uint32
}

// Validate validates the KDF parameters and sets defaults.
func (p *KDFParams) Validate() error {
	// Set defaults
	if p.Algorithm == "" {
		p.Algorithm = KDFAlgorithmHKDF
	}
	if p.Hash == "" {
		p.Hash = "SHA-256"
	}

	// Validate algorithm
	if !p.Algorithm.IsValid() {
		return fmt.Errorf("invalid KDF algorithm: %s", p.Algorithm)
	}

	// Validate hash
	switch p.Hash {
	case "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512":
		// Valid hash algorithms
	default:
		return fmt.Errorf("unsupported hash algorithm: %s", p.Hash)
	}

	// Validate key length
	if p.KeyLength <= 0 {
		return fmt.Errorf("key length must be positive, got %d", p.KeyLength)
	}
	if p.KeyLength > 1024 {
		return fmt.Errorf("key length %d exceeds maximum of 1024 bytes", p.KeyLength)
	}

	// Validate derivation mode
	if !p.DerivationMode.IsValid() {
		return fmt.Errorf("invalid derivation mode: %d", p.DerivationMode)
	}

	return nil
}

// DefaultKDFParams returns recommended default KDF parameters for ECDH key derivation.
// Uses HKDF with SHA-256 and produces a 32-byte (256-bit) key suitable for AES-256.
func DefaultKDFParams() *KDFParams {
	return &KDFParams{
		Algorithm: KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		KeyLength: 32,
	}
}

// KeyAgreementProvider extends KeyProvider with ECDH key agreement capabilities.
// Key providers that support elliptic curve Diffie-Hellman key agreement should
// implement this interface to enable secure key exchange protocols.
//
// Key agreement is essential for:
//   - TLS key exchange
//   - ECIES hybrid encryption
//   - Secure messaging protocols
//   - Key encapsulation mechanisms
//
// Example usage:
//
//	// Derive a shared encryption key using ECDH + HKDF
//	kdfParams := &types.KDFParams{
//	    Algorithm: types.KDFAlgorithmHKDF,
//	    Hash:      "SHA-256",
//	    Info:      []byte("encryption-key-v1"),
//	    KeyLength: 32,
//	}
//	sharedKey, err := backend.DeriveKeyECDH(ctx, myKeyAttrs, peerPublicKeyBytes, kdfParams)
type KeyAgreementProvider interface {
	KeyProvider

	// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key.
	//
	// The operation:
	//   1. Retrieves the private key identified by privateKeyAttrs
	//   2. Parses the peer's public key from peerPublicKey bytes
	//   3. Performs ECDH to compute the raw shared secret
	//   4. Applies the KDF specified in kdfParams to derive the final key
	//
	// Parameters:
	//   - ctx: Context for cancellation and deadline propagation
	//   - privateKeyAttrs: Attributes identifying the local private key
	//   - peerPublicKey: The peer's public key in DER or uncompressed point format
	//   - kdfParams: Parameters for the key derivation function
	//
	// The private key must be an ECDSA key with a curve supported by both parties.
	// The peer public key must use the same curve as the private key.
	//
	// Returns the derived key bytes or an error if the operation fails.
	// Possible errors:
	//   - ErrKeyNotFound if the private key does not exist
	//   - ErrInvalidKeyAlgorithm if the key is not an EC key
	//   - ErrInvalidParameter if the peer public key is malformed
	//   - ErrCurveMismatch if the curves do not match
	DeriveKeyECDH(ctx context.Context, privateKeyAttrs *KeyAttributes, peerPublicKey []byte, kdfParams *KDFParams) ([]byte, error)

	// SupportedCurves returns the list of elliptic curves supported for key agreement.
	//
	// Common curves include:
	//   - "P-256" (secp256r1, prime256v1) - 128-bit security
	//   - "P-384" (secp384r1) - 192-bit security
	//   - "P-521" (secp521r1) - 256-bit security
	//   - "X25519" - Modern curve for key agreement (Curve25519)
	//
	// Returns a slice of curve identifiers. The order may indicate preference.
	SupportedCurves() []string
}

// =============================================================================
// Secure ECDH Key Derivation Types
// =============================================================================

// KeyDerivationMode specifies how the derived key from ECDH is handled.
// Different modes provide varying levels of security and flexibility.
type KeyDerivationMode int

const (
	// KeyDerivationModeExport returns derived key bytes to the caller.
	// This is the default mode compatible with existing DeriveKeyECDH behavior.
	// Security: Application-level protection only - key exists in application memory.
	KeyDerivationModeExport KeyDerivationMode = iota

	// KeyDerivationModeHSMResident keeps the derived key inside the HSM.
	// The key is created with CKA_EXTRACTABLE=false and never leaves the HSM.
	// Security: Maximum - key never exposed, all operations performed by HSM.
	KeyDerivationModeHSMResident

	// KeyDerivationModeHSMKDF runs the KDF inside the HSM, then exports the result.
	// The raw ECDH shared secret never leaves the HSM, only the KDF output does.
	// Security: Raw secret protected - compromise doesn't reveal ECDH secret.
	KeyDerivationModeHSMKDF

	// KeyDerivationModeTPMWrapped seals the derived key using TPM2.
	// Uses TPM2_ECDH_KeyGen for ephemeral key exchange and TPM2_Create for sealing.
	// Security: TPM-bound - key can only be used on the same TPM platform.
	KeyDerivationModeTPMWrapped
)

// String returns the string representation of the KeyDerivationMode.
func (m KeyDerivationMode) String() string {
	switch m {
	case KeyDerivationModeExport:
		return "EXPORT"
	case KeyDerivationModeHSMResident:
		return "HSM_RESIDENT"
	case KeyDerivationModeHSMKDF:
		return "HSM_KDF"
	case KeyDerivationModeTPMWrapped:
		return "TPM_WRAPPED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", m)
	}
}

// IsValid returns true if the mode is a recognized KeyDerivationMode.
func (m KeyDerivationMode) IsValid() bool {
	switch m {
	case KeyDerivationModeExport, KeyDerivationModeHSMResident,
		KeyDerivationModeHSMKDF, KeyDerivationModeTPMWrapped:
		return true
	default:
		return false
	}
}

// ParseKeyDerivationMode converts a string to a KeyDerivationMode.
// Returns KeyDerivationModeExport as default for unrecognized strings.
func ParseKeyDerivationMode(s string) KeyDerivationMode {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "EXPORT", "":
		return KeyDerivationModeExport
	case "HSM_RESIDENT", "HSMRESIDENT":
		return KeyDerivationModeHSMResident
	case "HSM_KDF", "HSMKDF":
		return KeyDerivationModeHSMKDF
	case "TPM_WRAPPED", "TPMWRAPPED":
		return KeyDerivationModeTPMWrapped
	default:
		return KeyDerivationModeExport
	}
}

// DerivedKeyHandle references a key that resides within an HSM or TPM.
// This handle is returned by DeriveKeyECDHSecure when using HSM_RESIDENT
// or TPM_WRAPPED modes, and can be used with UseResidentKey to perform
// cryptographic operations without ever exposing the key material.
type DerivedKeyHandle struct {
	// ID is a unique identifier for this derived key.
	ID string `json:"id"`

	// Backend identifies which backend contains this key.
	Backend string `json:"backend"`

	// Extractable indicates whether the key can be exported.
	// For HSM_RESIDENT mode, this is always false.
	Extractable bool `json:"extractable"`

	// KeyLength is the length of the derived key in bytes.
	KeyLength int `json:"key_length"`

	// Algorithm identifies the key type (e.g., "AES", "HMAC").
	Algorithm string `json:"algorithm"`

	// Ephemeral indicates the key should be destroyed when the session ends.
	Ephemeral bool `json:"ephemeral"`

	// HSMHandle is the PKCS#11 object handle for HSM-resident keys.
	// Only valid when Backend is "pkcs11" or similar.
	HSMHandle uint64 `json:"hsm_handle,omitempty"`

	// TPMHandle contains TPM-specific handle information.
	// Only valid when Backend is "tpm2".
	TPMHandle *TPMDerivedKeyHandle `json:"tpm_handle,omitempty"`
}

// TPMDerivedKeyHandle contains TPM-specific information for derived keys.
type TPMDerivedKeyHandle struct {
	// Handle is the TPM object handle.
	Handle uint32 `json:"handle"`

	// ParentHandle is the handle of the parent storage key.
	ParentHandle uint32 `json:"parent_handle"`

	// Public contains the TPM2B_PUBLIC structure for the key.
	Public []byte `json:"public,omitempty"`

	// Private contains the TPM2B_PRIVATE structure (encrypted).
	Private []byte `json:"private,omitempty"`

	// PolicyDigest is the policy digest if policy-based authorization is used.
	PolicyDigest []byte `json:"policy_digest,omitempty"`
}

// ECDHResult contains the result of a secure ECDH key derivation operation.
// Depending on the DerivationMode, either DerivedKey or Handle will be populated.
type ECDHResult struct {
	// Mode indicates which derivation mode was used.
	Mode KeyDerivationMode `json:"mode"`

	// DerivedKey contains the key bytes for EXPORT and HSM_KDF modes.
	// For HSM_RESIDENT and TPM_WRAPPED modes, this is nil.
	DerivedKey []byte `json:"derived_key,omitempty"`

	// Handle references the HSM/TPM-resident key for HSM_RESIDENT and TPM_WRAPPED modes.
	// For EXPORT and HSM_KDF modes, this is nil.
	Handle *DerivedKeyHandle `json:"handle,omitempty"`

	// EphemeralPublicKey is the ephemeral public key for TPM_WRAPPED mode.
	// This is the public key generated by TPM2_ECDH_KeyGen that the peer
	// needs to compute their half of the shared secret.
	EphemeralPublicKey []byte `json:"ephemeral_public_key,omitempty"`
}

// HasKey returns true if this result contains usable key material or handle.
func (r *ECDHResult) HasKey() bool {
	return len(r.DerivedKey) > 0 || r.Handle != nil
}

// IsExported returns true if the derived key is available as bytes.
func (r *ECDHResult) IsExported() bool {
	return len(r.DerivedKey) > 0
}

// IsResident returns true if the derived key is HSM/TPM-resident.
func (r *ECDHResult) IsResident() bool {
	return r.Handle != nil
}

// DerivedKeyTemplateParams specifies attributes for HSM-resident derived keys.
// These parameters control how the derived key is stored and what operations
// it can perform within the HSM.
type DerivedKeyTemplateParams struct {
	// Label is a human-readable name for the key.
	Label string `json:"label,omitempty"`

	// ID is an optional byte identifier for the key.
	ID string `json:"id,omitempty"`

	// KeyType specifies the type of key to create (e.g., "AES", "GENERIC_SECRET").
	KeyType string `json:"key_type"`

	// Token indicates whether the key should persist on the token.
	// If false, the key is session-only.
	Token bool `json:"token"`

	// Private indicates whether the key requires login to use.
	Private bool `json:"private"`

	// Sensitive indicates the key is sensitive and should never be revealed
	// in plaintext outside the HSM.
	Sensitive bool `json:"sensitive"`

	// AllowEncrypt permits use for encryption operations.
	AllowEncrypt bool `json:"allow_encrypt"`

	// AllowDecrypt permits use for decryption operations.
	AllowDecrypt bool `json:"allow_decrypt"`

	// AllowWrap permits use for key wrapping operations.
	AllowWrap bool `json:"allow_wrap"`

	// AllowUnwrap permits use for key unwrapping operations.
	AllowUnwrap bool `json:"allow_unwrap"`

	// AllowDerive permits use for further key derivation.
	AllowDerive bool `json:"allow_derive"`
}

// DefaultDerivedKeyTemplateParams returns secure default template parameters
// for HSM-resident derived keys.
func DefaultDerivedKeyTemplateParams() *DerivedKeyTemplateParams {
	return &DerivedKeyTemplateParams{
		KeyType:      "AES",
		Token:        false, // Session key by default
		Private:      true,  // Require login
		Sensitive:    true,  // Never reveal plaintext
		AllowEncrypt: true,  // Typical use case
		AllowDecrypt: true,  // Typical use case
		AllowWrap:    false, // Not needed by default
		AllowUnwrap:  false, // Not needed by default
		AllowDerive:  false, // Single derivation by default
	}
}

// ResidentKeyOperation identifies operations that can be performed
// with an HSM/TPM-resident derived key.
type ResidentKeyOperation int

const (
	// ResidentKeyOpEncrypt uses the key for encryption.
	ResidentKeyOpEncrypt ResidentKeyOperation = iota

	// ResidentKeyOpDecrypt uses the key for decryption.
	ResidentKeyOpDecrypt

	// ResidentKeyOpMAC uses the key for MAC computation.
	ResidentKeyOpMAC

	// ResidentKeyOpVerifyMAC uses the key for MAC verification.
	ResidentKeyOpVerifyMAC

	// ResidentKeyOpWrap uses the key to wrap another key.
	ResidentKeyOpWrap

	// ResidentKeyOpUnwrap uses the key to unwrap another key.
	ResidentKeyOpUnwrap
)

// String returns the string representation of the ResidentKeyOperation.
func (op ResidentKeyOperation) String() string {
	switch op {
	case ResidentKeyOpEncrypt:
		return "ENCRYPT"
	case ResidentKeyOpDecrypt:
		return "DECRYPT"
	case ResidentKeyOpMAC:
		return "MAC"
	case ResidentKeyOpVerifyMAC:
		return "VERIFY_MAC"
	case ResidentKeyOpWrap:
		return "WRAP"
	case ResidentKeyOpUnwrap:
		return "UNWRAP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", op)
	}
}

// OperationParams contains parameters for operations using resident keys.
type OperationParams struct {
	// Algorithm specifies the algorithm to use (e.g., "AES-GCM", "AES-CBC").
	Algorithm string `json:"algorithm"`

	// IV is the initialization vector for CBC/CTR modes.
	IV []byte `json:"iv,omitempty"`

	// AAD is additional authenticated data for AEAD modes.
	AAD []byte `json:"aad,omitempty"`

	// TagLength is the authentication tag length in bits for AEAD modes.
	TagLength int `json:"tag_length,omitempty"`
}

// SecureKeyAgreementProvider extends KeyAgreementProvider with secure key
// derivation modes that keep derived keys within hardware security boundaries.
//
// This interface supports four derivation modes:
//   - EXPORT: Returns derived key bytes (compatible with DeriveKeyECDH)
//   - HSM_RESIDENT: Keeps key in HSM with CKA_EXTRACTABLE=false
//   - HSM_KDF: Runs KDF inside HSM, exports only KDF output
//   - TPM_WRAPPED: Uses TPM2_ECDH_KeyGen with TPM-sealed secrets
//
// Backends should implement this interface when they can provide enhanced
// security guarantees for derived key material.
type SecureKeyAgreementProvider interface {
	KeyAgreementProvider

	// DeriveKeyECDHSecure performs ECDH key agreement with configurable security modes.
	//
	// The operation varies based on kdfParams.DerivationMode:
	//   - EXPORT: Same as DeriveKeyECDH, returns key bytes in ECDHResult.DerivedKey
	//   - HSM_RESIDENT: Derives key inside HSM, returns handle in ECDHResult.Handle
	//   - HSM_KDF: Runs KDF in HSM, returns KDF output in ECDHResult.DerivedKey
	//   - TPM_WRAPPED: Seals derived key in TPM, returns handle in ECDHResult.Handle
	//
	// Parameters:
	//   - ctx: Context for cancellation and deadline propagation
	//   - privateKeyAttrs: Attributes identifying the local private key
	//   - peerPublicKey: The peer's public key in DER or uncompressed point format
	//   - kdfParams: Parameters for KDF including DerivationMode
	//
	// Returns ECDHResult containing either key bytes or a handle, depending on mode.
	DeriveKeyECDHSecure(ctx context.Context, privateKeyAttrs *KeyAttributes,
		peerPublicKey []byte, kdfParams *KDFParams) (*ECDHResult, error)

	// SupportedDerivationModes returns the list of derivation modes supported
	// by this backend. Not all backends support all modes.
	//
	// Returns a slice of supported KeyDerivationMode values.
	SupportedDerivationModes() []KeyDerivationMode

	// UseResidentKey performs a cryptographic operation using an HSM/TPM-resident key.
	//
	// Parameters:
	//   - ctx: Context for cancellation and deadline propagation
	//   - handle: The DerivedKeyHandle from a previous DeriveKeyECDHSecure call
	//   - operation: The operation to perform (encrypt, decrypt, MAC, etc.)
	//   - data: Input data for the operation
	//   - params: Additional parameters for the operation
	//
	// Returns the operation result (ciphertext, plaintext, MAC, etc.) or error.
	UseResidentKey(ctx context.Context, handle *DerivedKeyHandle,
		operation ResidentKeyOperation, data []byte, params *OperationParams) ([]byte, error)

	// DestroyResidentKey destroys an HSM/TPM-resident derived key.
	// This should be called when the key is no longer needed to free resources.
	//
	// Parameters:
	//   - ctx: Context for cancellation and deadline propagation
	//   - handle: The DerivedKeyHandle to destroy
	//
	// Returns nil on success or error if destruction fails.
	DestroyResidentKey(ctx context.Context, handle *DerivedKeyHandle) error
}

// TPMKeyAgreementProvider extends SecureKeyAgreementProvider with TPM-specific
// ECDH operations using TPM2_ECDH_KeyGen and TPM2_ECDH_ZGen commands.
//
// This interface enables TPM-bound key exchange where:
//   - The raw ECDH shared secret never leaves the TPM
//   - Derived keys can be sealed to the TPM's platform state
//   - Ephemeral key generation provides forward secrecy
type TPMKeyAgreementProvider interface {
	SecureKeyAgreementProvider

	// GenerateEphemeralECDH generates an ephemeral ECDH key pair inside the TPM
	// and derives a shared secret with the peer's static public key.
	//
	// This implements the initiator side of a one-pass ECDH protocol using
	// TPM2_ECDH_KeyGen. The ephemeral public key is returned so the peer
	// can compute the same shared secret.
	//
	// Parameters:
	//   - ctx: Context for cancellation and deadline propagation
	//   - keyAttrs: Attributes for the ephemeral key (curve, etc.)
	//   - peerStaticPublicKey: The peer's static public key
	//   - kdfParams: Parameters for the KDF including DerivationMode
	//
	// Returns ECDHResult with Handle and EphemeralPublicKey populated.
	GenerateEphemeralECDH(ctx context.Context, keyAttrs *KeyAttributes,
		peerStaticPublicKey []byte, kdfParams *KDFParams) (*ECDHResult, error)

	// RecoverWrappedSecret recovers a shared secret from the peer's ephemeral
	// public key using the local static private key.
	//
	// This implements the responder side of a one-pass ECDH protocol using
	// TPM2_ECDH_ZGen. The peer's ephemeral public key is used with our
	// static private key to compute the same shared secret.
	//
	// Parameters:
	//   - ctx: Context for cancellation and deadline propagation
	//   - privateKeyAttrs: Attributes identifying our static private key in the TPM
	//   - ephemeralPublicKey: The peer's ephemeral public key
	//   - kdfParams: Parameters for the KDF including DerivationMode
	//
	// Returns the derived key bytes or error.
	RecoverWrappedSecret(ctx context.Context, privateKeyAttrs *KeyAttributes,
		ephemeralPublicKey []byte, kdfParams *KDFParams) ([]byte, error)
}

// KeyAgreement provides ECDH (Elliptic Curve Diffie-Hellman) key agreement.
// This interface allows two parties to establish a shared secret using their
// public and private keys without transmitting the shared secret.
//
// The shared secret can then be used with a KDF (Key Derivation Function)
// to generate encryption keys.
//
// Example usage:
//
//	// Alice and Bob exchange public keys
//	// Alice derives shared secret using her private key and Bob's public key
//	sharedSecret, _ := backend.DeriveSharedSecret(aliceAttrs, bobPublicKey)
//
//	// Bob derives the same shared secret using his private key and Alice's public key
//	// The shared secrets will be identical
type KeyAgreement interface {
	// DeriveSharedSecret performs ECDH key agreement between the private key
	// identified by attrs and the provided public key.
	//
	// Both keys must use compatible elliptic curves (P-256, P-384, or P-521).
	// The shared secret is the raw output of ECDH - use a KDF to derive
	// encryption keys from it.
	//
	// Returns the shared secret or an error if the operation fails.
	DeriveSharedSecret(attrs *KeyAttributes, publicKey crypto.PublicKey) ([]byte, error)
}

// ECIESEncrypter provides public key encryption using ECIES
// (Elliptic Curve Integrated Encryption Scheme).
//
// ECIES combines:
//   - ECDH for key agreement
//   - HKDF for key derivation
//   - AES-256-GCM for authenticated encryption
//
// This allows encrypting data with someone's public key, and only they
// can decrypt it with their private key.
type ECIESEncrypter interface {
	// EncryptECIES encrypts plaintext using ECIES with the recipient's public key.
	//
	// The encryption format is:
	//   [ephemeral_public_key || nonce || tag || ciphertext]
	//
	// Parameters:
	//   - publicKey: Recipient's ECDSA public key (P-256, P-384, or P-521)
	//   - plaintext: Data to encrypt
	//   - aad: Optional additional authenticated data (not encrypted, but authenticated)
	//
	// Returns encrypted data that can only be decrypted by the private key holder.
	EncryptECIES(publicKey crypto.PublicKey, plaintext, aad []byte) ([]byte, error)
}

// ECIESDecrypter provides decryption for ECIES-encrypted data.
type ECIESDecrypter interface {
	// DecryptECIES decrypts ECIES ciphertext using the private key identified by attrs.
	//
	// Parameters:
	//   - attrs: Attributes identifying the private key to use for decryption
	//   - ciphertext: Encrypted data from EncryptECIES
	//   - aad: Optional additional authenticated data (must match encryption)
	//
	// Returns the original plaintext or an error if decryption fails.
	DecryptECIES(attrs *KeyAttributes, ciphertext, aad []byte) ([]byte, error)
}

// AEADSafetyTracker provides nonce uniqueness and bytes encrypted tracking
// for AEAD encryption operations (AES-GCM, ChaCha20-Poly1305, etc).
//
// This interface must be implemented by backends that support symmetric encryption
// to ensure cryptographic safety limits are enforced.
//
// NIST SP 800-38D recommendations:
//   - Maximum nonce reuse: NEVER (catastrophic security failure)
//   - Maximum bytes encrypted with 96-bit nonce: ~350 GB (2^32 blocks)
//   - Recommended action at limit: Key rotation
type AEADSafetyTracker interface {
	// CheckNonce verifies that a nonce has not been used before for the given key.
	// Returns ErrNonceReused if the nonce has been used previously.
	// This MUST be called before encryption to prevent nonce reuse attacks.
	CheckNonce(keyID string, nonce []byte) error

	// RecordNonce records a nonce as used for the given key.
	// This MUST be called after successful encryption to track nonce usage.
	// The nonce should be stored persistently to survive restarts.
	RecordNonce(keyID string, nonce []byte) error

	// IncrementBytes increments the bytes encrypted counter for the given key.
	// Returns ErrBytesLimitExceeded if adding numBytes would exceed the configured limit.
	// This MUST be called before encryption to enforce byte limits.
	IncrementBytes(keyID string, numBytes int64) error

	// GetBytesEncrypted returns the total bytes encrypted with the given key.
	GetBytesEncrypted(keyID string) (int64, error)

	// GetAEADOptions returns the AEAD safety options for the given key.
	// Returns nil if no options are configured (tracking disabled).
	GetAEADOptions(keyID string) (*AEADOptions, error)

	// SetAEADOptions sets the AEAD safety options for the given key.
	// This should be called when creating or importing a key.
	SetAEADOptions(keyID string, opts *AEADOptions) error

	// ResetTracking resets all tracking state for a key (used after rotation).
	// This clears nonce history and resets byte counters.
	ResetTracking(keyID string) error
}

// SymmetricKeyProviderWithTracking extends SymmetricKeyProvider with AEAD safety tracking.
// Key providers that support symmetric encryption should implement this interface to
// provide nonce uniqueness checking and bytes encrypted tracking.
//
// This interface is optional - key providers can implement basic SymmetricKeyProvider
// without tracking, but implementing tracking is HIGHLY RECOMMENDED for
// production systems to prevent nonce reuse and enforce cryptographic limits.
type SymmetricKeyProviderWithTracking interface {
	SymmetricKeyProvider

	// GetTracker returns the AEAD safety tracker for this backend.
	// Returns nil if tracking is not supported or disabled.
	GetTracker() AEADSafetyTracker
}

// =============================================================================
// Sealer Interface - Unified Sealing Across Backends
// =============================================================================

// Sealer provides a unified interface for sealing/unsealing data across backends.
// Each backend implements sealing using its native mechanism:
//   - TPM2: PCR-bound seal/unseal with platform policy
//   - PKCS#11: AES-GCM encryption with HSM-resident key
//   - AWS KMS: Envelope encryption with GenerateDataKey
//   - Azure KV: Wrap/Unwrap with managed keys
//   - GCP KMS: Encrypt/Decrypt with KEK
//   - PKCS#8: HKDF-derived key + AES-GCM (software fallback)
//
// The Sealer interface provides consistent API while allowing each backend
// to use its optimal protection mechanism.
type Sealer interface {
	// Seal encrypts/protects data using the backend's native sealing mechanism.
	// The sealed data can only be unsealed by the same backend (and for TPM,
	// only when the same PCR state is present).
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - data: The plaintext data to seal
	//   - opts: Backend-specific sealing options (may be nil for defaults)
	//
	// Returns SealedData containing encrypted payload and metadata, or error.
	Seal(ctx context.Context, data []byte, opts *SealOptions) (*SealedData, error)

	// Unseal decrypts/recovers data using the backend's native unsealing mechanism.
	// For TPM backends, this requires the same PCR state as when the data was sealed.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - sealed: The sealed data from a previous Seal operation
	//   - opts: Backend-specific unsealing options (may be nil for defaults)
	//
	// Returns the original plaintext data, or error if unsealing fails.
	Unseal(ctx context.Context, sealed *SealedData, opts *UnsealOptions) ([]byte, error)

	// CanSeal returns true if this backend supports sealing operations.
	// Some backends may not support sealing (e.g., read-only key stores).
	CanSeal() bool
}

// SealOptions configures seal operations with backend-specific options.
type SealOptions struct {
	// KeyAttributes identifies the key to use for sealing (required for most backends).
	// For TPM, this identifies the SRK or sealing key.
	// For PKCS#11/Cloud KMS, this identifies the encryption key.
	KeyAttributes *KeyAttributes

	// TPMPolicy contains TPM-specific sealing policy (PCR selection, etc).
	// Only used by TPM2 backend; ignored by other backends.
	TPMPolicy *TPMSealPolicy

	// AAD is Additional Authenticated Data for AEAD encryption.
	// This data is authenticated but not encrypted.
	// Supported by PKCS#11, Cloud KMS, and PKCS#8 backends.
	AAD []byte

	// Password provides authentication for the sealed object (TPM-specific).
	// This is the UserAuth value set during sealing.
	Password Password

	// Backend specifies the storage backend for sealed data.
	// For TPM2, this should be a store.KeyBackend implementation.
	// If nil, the backend configured on the sealer instance is used.
	Backend any
}

// UnsealOptions configures unseal operations with backend-specific options.
type UnsealOptions struct {
	// KeyAttributes identifies the key to use for unsealing (required for most backends).
	KeyAttributes *KeyAttributes

	// AAD is Additional Authenticated Data that must match what was used during sealing.
	AAD []byte

	// Password provides authentication for the sealed object (TPM-specific).
	// This is the UserAuth value, not the sealed data itself.
	Password Password

	// Backend specifies the storage backend for sealed data.
	// For TPM2, this should be a store.KeyBackend implementation.
	// If nil, the backend configured on the sealer instance is used.
	Backend any
}

// TPMSealPolicy contains TPM-specific sealing policy configuration.
type TPMSealPolicy struct {
	// PCRSelection specifies which PCRs to bind the sealed data to.
	// The data can only be unsealed when these PCRs have the same values.
	PCRSelection tpm2.TPMLPCRSelection

	// HashAlg specifies the hash algorithm for PCR policy.
	HashAlg tpm2.TPMIAlgHash

	// AuthPolicy contains a pre-computed authorization policy digest.
	// If set, this is used instead of computing from PCRSelection.
	AuthPolicy []byte
}

// SealedData represents the result of a seal operation.
// This structure is serializable and can be stored/transmitted.
type SealedData struct {
	// Backend identifies which backend created this sealed data.
	// Required for proper unsealing - data must be unsealed by the same backend type.
	Backend BackendType `json:"backend"`

	// Ciphertext is the encrypted payload.
	Ciphertext []byte `json:"ciphertext"`

	// Nonce is the IV/nonce used for encryption (for AEAD modes).
	// Not used by TPM backend (TPM handles nonce internally).
	Nonce []byte `json:"nonce,omitempty"`

	// Tag is the authentication tag for AEAD modes.
	// May be appended to Ciphertext depending on backend.
	Tag []byte `json:"tag,omitempty"`

	// WrappedDEK contains a wrapped Data Encryption Key (for envelope encryption).
	// Used by cloud KMS backends (AWS, Azure, GCP).
	WrappedDEK []byte `json:"wrapped_dek,omitempty"`

	// KeyID identifies the key used for sealing.
	// Format is backend-specific (e.g., ARN for AWS, key path for GCP).
	KeyID string `json:"key_id,omitempty"`

	// TPMPublic contains the TPM public area for sealed objects.
	// Only used by TPM2 backend.
	TPMPublic []byte `json:"tpm_public,omitempty"`

	// TPMPrivate contains the TPM private area (encrypted) for sealed objects.
	// Only used by TPM2 backend.
	TPMPrivate []byte `json:"tpm_private,omitempty"`

	// Metadata contains additional backend-specific data.
	// Keys should be namespaced (e.g., "tpm:creation_ticket", "aws:encryption_context").
	Metadata map[string][]byte `json:"metadata,omitempty"`
}

// SealingKeyProvider extends KeyProvider with sealing capabilities.
// Key providers that support data sealing should implement this interface.
type SealingKeyProvider interface {
	KeyProvider
	Sealer
}

// =============================================================================
// Helper Functions
// =============================================================================

// AvailableHashes returns a map of all supported hash functions.
// Supports both standard Go crypto.Hash.String() format (e.g., "SHA-256")
// and common aliases (e.g., "sha256", "SHA256").
func AvailableHashes() map[string]crypto.Hash {
	return map[string]crypto.Hash{
		// Standard format (crypto.Hash.String())
		crypto.MD4.String():         crypto.MD4,
		crypto.MD5.String():         crypto.MD5,
		crypto.SHA1.String():        crypto.SHA1,
		crypto.SHA224.String():      crypto.SHA224,
		crypto.SHA256.String():      crypto.SHA256,
		crypto.SHA384.String():      crypto.SHA384,
		crypto.SHA512.String():      crypto.SHA512,
		crypto.MD5SHA1.String():     crypto.MD5SHA1,
		crypto.RIPEMD160.String():   crypto.RIPEMD160,
		crypto.SHA3_224.String():    crypto.SHA3_224,
		crypto.SHA3_256.String():    crypto.SHA3_256,
		crypto.SHA3_384.String():    crypto.SHA3_384,
		crypto.SHA3_512.String():    crypto.SHA3_512,
		crypto.SHA512_224.String():  crypto.SHA512_224,
		crypto.SHA512_256.String():  crypto.SHA512_256,
		crypto.BLAKE2s_256.String(): crypto.BLAKE2s_256,
		crypto.BLAKE2b_256.String(): crypto.BLAKE2b_256,
		crypto.BLAKE2b_384.String(): crypto.BLAKE2b_384,
		crypto.BLAKE2b_512.String(): crypto.BLAKE2b_512,
		// Common aliases (lowercase without hyphens)
		"md4":        crypto.MD4,
		"md5":        crypto.MD5,
		"sha1":       crypto.SHA1,
		"sha224":     crypto.SHA224,
		"sha256":     crypto.SHA256,
		"sha384":     crypto.SHA384,
		"sha512":     crypto.SHA512,
		"sha3-224":   crypto.SHA3_224,
		"sha3-256":   crypto.SHA3_256,
		"sha3-384":   crypto.SHA3_384,
		"sha3-512":   crypto.SHA3_512,
		"sha512-224": crypto.SHA512_224,
		"sha512-256": crypto.SHA512_256,
		// Uppercase without hyphens
		"MD4":        crypto.MD4,
		"MD5":        crypto.MD5,
		"SHA1":       crypto.SHA1,
		"SHA224":     crypto.SHA224,
		"SHA256":     crypto.SHA256,
		"SHA384":     crypto.SHA384,
		"SHA512":     crypto.SHA512,
		"SHA3_224":   crypto.SHA3_224,
		"SHA3_256":   crypto.SHA3_256,
		"SHA3_384":   crypto.SHA3_384,
		"SHA3_512":   crypto.SHA3_512,
		"SHA512_224": crypto.SHA512_224,
		"SHA512_256": crypto.SHA512_256,
	}
}

// AvailableSignatureAlgorithms returns a map of all supported signature algorithms.
func AvailableSignatureAlgorithms() map[string]x509.SignatureAlgorithm {
	return map[string]x509.SignatureAlgorithm{
		x509.SHA256WithRSA.String():    x509.SHA256WithRSA,
		x509.SHA384WithRSA.String():    x509.SHA384WithRSA,
		x509.SHA512WithRSA.String():    x509.SHA512WithRSA,
		x509.ECDSAWithSHA256.String():  x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384.String():  x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512.String():  x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS.String(): x509.SHA256WithRSAPSS,
		x509.SHA384WithRSAPSS.String(): x509.SHA384WithRSAPSS,
		x509.SHA512WithRSAPSS.String(): x509.SHA512WithRSAPSS,
		x509.PureEd25519.String():      x509.PureEd25519,
	}
}

// SignatureAlgorithmHashes maps signature algorithms to their hash functions.
func SignatureAlgorithmHashes() map[x509.SignatureAlgorithm]crypto.Hash {
	return map[x509.SignatureAlgorithm]crypto.Hash{
		x509.SHA256WithRSA:    crypto.SHA256,
		x509.SHA384WithRSA:    crypto.SHA384,
		x509.SHA512WithRSA:    crypto.SHA512,
		x509.ECDSAWithSHA256:  crypto.SHA256,
		x509.ECDSAWithSHA384:  crypto.SHA384,
		x509.ECDSAWithSHA512:  crypto.SHA512,
		x509.SHA256WithRSAPSS: crypto.SHA256,
		x509.SHA384WithRSAPSS: crypto.SHA384,
		x509.SHA512WithRSAPSS: crypto.SHA512,
		x509.PureEd25519:      0,
	}
}

// AvailableKeyAlgorithms returns a map of all supported key algorithms.
func AvailableKeyAlgorithms() map[string]x509.PublicKeyAlgorithm {
	return map[string]x509.PublicKeyAlgorithm{
		x509.RSA.String():     x509.RSA,
		x509.ECDSA.String():   x509.ECDSA,
		x509.Ed25519.String(): x509.Ed25519,
	}
}

// IsRSAPSS returns true if the signature algorithm uses RSA-PSS padding.
func IsRSAPSS(sigAlgo x509.SignatureAlgorithm) bool {
	return sigAlgo == x509.SHA256WithRSAPSS ||
		sigAlgo == x509.SHA384WithRSAPSS ||
		sigAlgo == x509.SHA512WithRSAPSS
}

// IsECDSA returns true if the signature algorithm is ECDSA.
func IsECDSA(sigAlgo x509.SignatureAlgorithm) bool {
	return sigAlgo == x509.ECDSAWithSHA256 ||
		sigAlgo == x509.ECDSAWithSHA384 ||
		sigAlgo == x509.ECDSAWithSHA512
}

// KeyAlgorithmFromSignatureAlgorithm derives the key algorithm from a signature algorithm.
func KeyAlgorithmFromSignatureAlgorithm(sigAlgo x509.SignatureAlgorithm) (x509.PublicKeyAlgorithm, error) {
	switch sigAlgo {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return x509.ECDSA, nil
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS,
		x509.SHA384WithRSA, x509.SHA384WithRSAPSS,
		x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		return x509.RSA, nil
	case x509.PureEd25519:
		return x509.Ed25519, nil
	default:
		return 0, fmt.Errorf("invalid signature algorithm: %v", sigAlgo)
	}
}

// FSHashName converts a crypto.Hash to a filesystem-safe name.
func FSHashName(hash crypto.Hash) string {
	name := strings.ToLower(hash.String())
	name = strings.ReplaceAll(name, "-", "")
	return strings.ReplaceAll(name, "/", "")
}

// FSExtKeyAlgorithm converts a key algorithm to a file extension.
func FSExtKeyAlgorithm(algo x509.PublicKeyAlgorithm) string {
	return fmt.Sprintf(".%s", strings.ToLower(algo.String()))
}

// KeyFileExtension creates a complete file extension including key algorithm prefix.
func KeyFileExtension(algo x509.PublicKeyAlgorithm, extension FSExtension, keyType *KeyType) FSExtension {
	keyExt := FSExtKeyAlgorithm(algo)
	if keyType != nil && *keyType == KeyTypeHMAC {
		return FSExtension(fmt.Sprintf(".hmac%s", extension))
	}
	return FSExtension(fmt.Sprintf("%s%s", keyExt, extension))
}

// HashFileExtension creates a file extension for hash digest files.
func HashFileExtension(hash crypto.Hash) string {
	return fmt.Sprintf(".%s", FSHashName(hash))
}

// Digest creates a cryptographic hash of the provided data using the specified hash function.
func Digest(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("hash function not available: %v", hash)
	}
	hasher := hash.New()
	n, err := hasher.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to hasher: %w", err)
	}
	if n != len(data) {
		return nil, fmt.Errorf("incomplete write to hasher: wrote %d of %d bytes", n, len(data))
	}
	return hasher.Sum(nil), nil
}

// ParseCurve converts a curve name string to an elliptic.Curve.
// Supported curves: P-224, P-256, P-384, P-521
// Returns an error if the curve name is not recognized.
func ParseCurve(curveName string) (elliptic.Curve, error) {
	curveName = strings.ToUpper(strings.TrimSpace(curveName))
	switch curveName {
	case "P-224", "P224", "SECP224R1":
		return elliptic.P224(), nil
	case "P-256", "P256", "SECP256R1", "PRIME256V1":
		return elliptic.P256(), nil
	case "P-384", "P384", "SECP384R1":
		return elliptic.P384(), nil
	case "P-521", "P521", "SECP521R1":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownCurve, curveName)
	}
}

// ParseKeyAlgorithm converts a string to a x509.PublicKeyAlgorithm.
// Returns an error if the string is not recognized.
func ParseKeyAlgorithm(s string) (x509.PublicKeyAlgorithm, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "rsa", "rsa-2048", "rsa-4096":
		return x509.RSA, nil
	case "ecdsa", "ec", "ecc":
		return x509.ECDSA, nil
	case "ed25519":
		return x509.Ed25519, nil
	default:
		return x509.UnknownPublicKeyAlgorithm, fmt.Errorf("%w: %s", ErrUnknownKeyAlgorithm, s)
	}
}

// ParseKeyType converts a string to a KeyType.
// Returns 0 if the string is not recognized.
func ParseKeyType(s string) KeyType {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "ATTESTATION":
		return KeyTypeAttestation
	case "CA":
		return KeyTypeCA
	case "ENCAPSULATION":
		return KeyTypeEncapsulation
	case "ENCRYPTION":
		return KeyTypeEncryption
	case "ENDORSEMENT":
		return KeyTypeEndorsement
	case "HMAC":
		return KeyTypeHMAC
	case "IDEVID":
		return KeyTypeIDevID
	case "LDEVID":
		return KeyTypeLDevID
	case "SECRET":
		return KeyTypeSecret
	case "SIGNING":
		return KeyTypeSigning
	case "STORAGE":
		return KeyTypeStorage
	case "TLS":
		return KeyTypeTLS
	case "TPM":
		return KeyTypeTPM
	default:
		return 0
	}
}

// ParseHash converts a hash algorithm name string to a crypto.Hash.
// Returns 0 (invalid) if the string is not recognized.
func ParseHash(s string) crypto.Hash {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "_")

	switch s {
	case "MD4":
		return crypto.MD4
	case "MD5":
		return crypto.MD5
	case "SHA1", "SHA_1":
		return crypto.SHA1
	case "SHA224", "SHA_224":
		return crypto.SHA224
	case "SHA256", "SHA_256":
		return crypto.SHA256
	case "SHA384", "SHA_384":
		return crypto.SHA384
	case "SHA512", "SHA_512":
		return crypto.SHA512
	case "MD5SHA1":
		return crypto.MD5SHA1
	case "RIPEMD160":
		return crypto.RIPEMD160
	case "SHA3_224":
		return crypto.SHA3_224
	case "SHA3_256":
		return crypto.SHA3_256
	case "SHA3_384":
		return crypto.SHA3_384
	case "SHA3_512":
		return crypto.SHA3_512
	case "SHA512_224":
		return crypto.SHA512_224
	case "SHA512_256":
		return crypto.SHA512_256
	case "BLAKE2S_256":
		return crypto.BLAKE2s_256
	case "BLAKE2B_256":
		return crypto.BLAKE2b_256
	case "BLAKE2B_384":
		return crypto.BLAKE2b_384
	case "BLAKE2B_512":
		return crypto.BLAKE2b_512
	default:
		return 0
	}
}

// ParseSignatureAlgorithm converts a signature algorithm string to x509.SignatureAlgorithm.
// Returns an error if the string is not recognized.
func ParseSignatureAlgorithm(s string) (x509.SignatureAlgorithm, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "SHA256-RSA", "SHA256WITHRSA":
		return x509.SHA256WithRSA, nil
	case "SHA384-RSA", "SHA384WITHRSA":
		return x509.SHA384WithRSA, nil
	case "SHA512-RSA", "SHA512WITHRSA":
		return x509.SHA512WithRSA, nil
	case "SHA256-RSA-PSS", "SHA256-RSAPSS", "SHA256WITHRSAPSS":
		return x509.SHA256WithRSAPSS, nil
	case "SHA384-RSA-PSS", "SHA384-RSAPSS", "SHA384WITHRSAPSS":
		return x509.SHA384WithRSAPSS, nil
	case "SHA512-RSA-PSS", "SHA512-RSAPSS", "SHA512WITHRSAPSS":
		return x509.SHA512WithRSAPSS, nil
	case "ECDSA-SHA256", "ECDSAWITHSHA256":
		return x509.ECDSAWithSHA256, nil
	case "ECDSA-SHA384", "ECDSAWITHSHA384":
		return x509.ECDSAWithSHA384, nil
	case "ECDSA-SHA512", "ECDSAWITHSHA512":
		return x509.ECDSAWithSHA512, nil
	case "ED25519", "PUREED25519":
		return x509.PureEd25519, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("%w: %s", ErrUnknownSignatureAlgorithm, s)
	}
}

// CurveName returns the standard name for an elliptic curve.
// Returns empty string if the curve is nil or not recognized.
func CurveName(curve elliptic.Curve) string {
	if curve == nil {
		return ""
	}

	params := curve.Params()
	if params == nil {
		return ""
	}

	return params.Name
}

// =============================================================================
// Keystore Interfaces
// =============================================================================

// OpaqueKey represents a cryptographic key that may be hardware-backed
// and implements both crypto.Signer and crypto.Decrypter interfaces.
// The underlying private key material may not be exportable.
type OpaqueKey interface {
	crypto.Signer
	crypto.Decrypter

	// Public returns the public key portion of this key
	Public() crypto.PublicKey

	// Attributes returns the key attributes
	Attributes() *KeyAttributes

	// Type returns the backend type that owns this key
	Type() BackendType
}

// VerifyOpts provides options for signature verification operations.
type VerifyOpts struct {
	// KeyAttributes specifies the key to use for verification
	KeyAttributes *KeyAttributes

	// Hash specifies the hash function to use
	Hash crypto.Hash

	// PSSSaltLength for RSA-PSS signatures (-1 for auto)
	PSSSaltLength int

	// PublicKey can be provided directly if not using KeyAttributes
	PublicKey crypto.PublicKey

	// PSSOptions for RSA-PSS signatures
	PSSOptions *rsa.PSSOptions
}

// Verifier provides signature verification capabilities.
type Verifier interface {
	// Verify verifies a signature against a digest
	Verify(publicKey crypto.PublicKey, digest, signature []byte) error
}

// ParseHashFromSignatureAlgorithm returns the hash function for a signature algorithm.
func ParseHashFromSignatureAlgorithm(sigAlgo *x509.SignatureAlgorithm) (crypto.Hash, error) {
	if sigAlgo == nil {
		return 0, fmt.Errorf("signature algorithm is nil")
	}
	hashes := SignatureAlgorithmHashes()
	if hash, ok := hashes[*sigAlgo]; ok {
		return hash, nil
	}
	return 0, fmt.Errorf("unknown signature algorithm: %v", *sigAlgo)
}

// PublicKeyToString returns a string representation of a public key.
func PublicKeyToString(pub crypto.PublicKey) string {
	if pub == nil {
		return "<nil>"
	}
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", key.Params().Name)
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", key.Size()*8)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", pub)
	}
}

// SimpleVerifier is a basic signature verifier implementation
type SimpleVerifier struct {
	opts *VerifyOpts
}

// NewVerifier creates a new signature verifier
func NewVerifier(opts *VerifyOpts) Verifier {
	if opts == nil {
		opts = &VerifyOpts{}
	}
	return &SimpleVerifier{opts: opts}
}

// Verify verifies a signature against a digest
func (v *SimpleVerifier) Verify(publicKey crypto.PublicKey, digest, signature []byte) error {
	if publicKey == nil {
		return fmt.Errorf("public key is nil")
	}
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if v.opts.PSSOptions != nil {
			return rsa.VerifyPSS(pub, v.opts.PSSOptions.Hash, digest, signature, v.opts.PSSOptions)
		}
		return rsa.VerifyPKCS1v15(pub, v.opts.Hash, digest, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, digest, signature) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// ECCConfig holds ECC-specific configuration for YAML serialization.
type ECCConfig struct {
	Curve EllipticCurve `yaml:"curve" json:"curve" mapstructure:"curve"`
}

// RSAConfig holds RSA-specific configuration for YAML serialization.
type RSAConfig struct {
	KeySize int `yaml:"size" json:"size" mapstructure:"size"`
}

// KeyConfig represents key configuration for YAML/JSON serialization.
// It uses typed string fields and nested algorithm-specific structs
// for type safety at the configuration boundary.
type KeyConfig struct {
	CN                 string                 `yaml:"cn,omitempty" json:"cn,omitempty" mapstructure:"cn"`
	KeyAlgorithm       KeyAlgorithmString     `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Hash               HashName               `yaml:"hash,omitempty" json:"hash,omitempty" mapstructure:"hash"`
	SignatureAlgorithm SignatureAlgorithmName `yaml:"signature-algorithm,omitempty" json:"signature-algorithm,omitempty" mapstructure:"signature-algorithm"`
	StoreType          StoreType              `yaml:"store,omitempty" json:"store,omitempty" mapstructure:"store"`
	KeyType            KeyTypeString          `yaml:"key-type,omitempty" json:"key-type,omitempty" mapstructure:"key-type"`
	ECCConfig          *ECCConfig             `yaml:"ecc,omitempty" json:"ecc,omitempty" mapstructure:"ecc"`
	RSAConfig          *RSAConfig             `yaml:"rsa,omitempty" json:"rsa,omitempty" mapstructure:"rsa"`
	Parent             *KeyConfig             `yaml:"parent,omitempty" json:"parent,omitempty" mapstructure:"parent"`
	Password           string                 `yaml:"password,omitempty" json:"password,omitempty" mapstructure:"password"`
	Secret             string                 `yaml:"secret,omitempty" json:"secret,omitempty" mapstructure:"secret"`
	PlatformPolicy     bool                   `yaml:"platform-policy,omitempty" json:"platform_policy,omitempty" mapstructure:"platform-policy"`
	Debug              bool                   `yaml:"debug,omitempty" json:"debug,omitempty" mapstructure:"debug"`
	Default            bool                   `yaml:"default,omitempty" json:"default,omitempty" mapstructure:"default"`
}

// KeySerializer provides key serialization capabilities
type KeySerializer interface {
	Serialize(key crypto.PublicKey) ([]byte, error)
	Deserialize(data []byte) (crypto.PublicKey, error)
	Type() SerializerType
}

// KeyAttributesFromConfig creates KeyAttributes from a KeyConfig.
// This is the boundary parser that converts typed config strings to
// runtime crypto types.
func KeyAttributesFromConfig(config *KeyConfig) (*KeyAttributes, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	keyAlgo, err := ParseKeyAlgorithm(string(config.KeyAlgorithm))
	if err != nil {
		return nil, err
	}

	hash := ParseHash(string(config.Hash))

	sigAlgo, err := ParseSignatureAlgorithm(string(config.SignatureAlgorithm))
	if err != nil {
		sigAlgo = x509.UnknownSignatureAlgorithm
	}

	// Preserve custom backend names (e.g., "pkcs8-ca2") instead of
	// converting them to "unknown" via ParseStoreType. This allows the
	// xkms facade to route operations to the correct registered backend.
	storeType := config.StoreType
	if storeType == "" {
		storeType = StoreSoftware // Default to software if not specified
	}

	attrs := &KeyAttributes{
		CN:                 config.CN,
		Debug:              config.Debug,
		Hash:               hash,
		KeyAlgorithm:       keyAlgo,
		PlatformPolicy:     config.PlatformPolicy,
		SignatureAlgorithm: sigAlgo,
		StoreType:          storeType,
		KeyType:            ParseKeyType(string(config.KeyType)),
	}

	// Parse algorithm-specific config from nested structs
	if config.ECCConfig != nil {
		curve, err := ParseCurve(string(config.ECCConfig.Curve))
		if err != nil {
			curve = elliptic.P256()
		}
		attrs.ECCAttributes = &ECCAttributes{Curve: curve}
	} else if keyAlgo == x509.ECDSA {
		// Default to P-256 for ECDSA if no ECCConfig provided
		attrs.ECCAttributes = &ECCAttributes{Curve: elliptic.P256()}
	}

	if config.RSAConfig != nil {
		keySize := config.RSAConfig.KeySize
		if keySize == 0 {
			keySize = 2048
		}
		attrs.RSAAttributes = &RSAAttributes{KeySize: keySize}
	} else if keyAlgo == x509.RSA {
		// Default to 2048 for RSA if no RSAConfig provided
		attrs.RSAAttributes = &RSAAttributes{KeySize: 2048}
	}

	// Parse parent config recursively
	if config.Parent != nil {
		parent, err := KeyAttributesFromConfig(config.Parent)
		if err != nil {
			return nil, err
		}
		attrs.Parent = parent
	}

	return attrs, nil
}

// EncodePubKeyPEM encodes a public key to PEM format
func EncodePubKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// SerializerType represents the type of serializer
type SerializerType int

const (
	SerializerJSON SerializerType = iota
	SerializerYAML
)

// jsonKeySerializer implements KeySerializer using JSON encoding
type jsonKeySerializer struct{}

func (s *jsonKeySerializer) Serialize(key crypto.PublicKey) ([]byte, error) {
	return json.Marshal(key)
}

func (s *jsonKeySerializer) Deserialize(data []byte) (crypto.PublicKey, error) {
	var key crypto.PublicKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *jsonKeySerializer) Type() SerializerType {
	return SerializerJSON
}

// NewKeySerializer creates a new KeySerializer for the given type
func NewKeySerializer(serializerType SerializerType) (KeySerializer, error) {
	switch serializerType {
	case SerializerJSON:
		return &jsonKeySerializer{}, nil
	case SerializerYAML:
		return &jsonKeySerializer{}, nil // Use JSON for both since YAML is JSON-compatible
	default:
		return nil, fmt.Errorf("unsupported serializer type: %d", serializerType)
	}
}

// KeyMap represents a JWK-like map for ACME key operations
type KeyMap map[string]interface{}

// ParseKeyMap parses a JSON string into a KeyMap
func ParseKeyMap(data string) (KeyMap, error) {
	var km KeyMap
	if err := json.Unmarshal([]byte(data), &km); err != nil {
		return nil, err
	}
	return km, nil
}

// JOSESignatureAlgorithm returns the JOSE signature algorithm name for this key as a string
func (km KeyMap) JOSESignatureAlgorithm() (string, error) {
	kty, ok := km["kty"].(string)
	if !ok {
		return "", fmt.Errorf("missing or invalid kty field")
	}
	switch kty {
	case "RSA":
		return "RS256", nil
	case "EC":
		crv, _ := km["crv"].(string)
		switch crv {
		case "P-256":
			return "ES256", nil
		case "P-384":
			return "ES384", nil
		case "P-521":
			return "ES512", nil
		default:
			return "ES256", nil
		}
	case "OKP":
		return "EdDSA", nil
	default:
		return "", fmt.Errorf("unsupported key type: %s", kty)
	}
}

// Equal compares two KeyMaps for equality
func (km KeyMap) Equal(other KeyMap) bool {
	if len(km) != len(other) {
		return false
	}
	for k, v := range km {
		otherV, ok := other[k]
		if !ok {
			return false
		}
		// Compare as strings for simple comparison
		if fmt.Sprintf("%v", v) != fmt.Sprintf("%v", otherV) {
			return false
		}
	}
	return true
}

// Deserialize deserializes a public key from a string using JSON encoding
func Deserialize(data string) (crypto.PublicKey, error) {
	serializer := &jsonKeySerializer{}
	return serializer.Deserialize([]byte(data))
}

// PublicKeyID generates a unique ID from a public key
func PublicKeyID(pub crypto.PublicKey, serializerType SerializerType) uint64 {
	serializer, err := NewKeySerializer(serializerType)
	if err != nil {
		return 0
	}
	data, err := serializer.Serialize(pub)
	if err != nil {
		return 0
	}
	// Use FNV-1a hash for a quick, stable ID
	var h uint64 = 14695981039346656037 // FNV offset basis
	for _, b := range data {
		h ^= uint64(b)
		h *= 1099511628211 // FNV prime
	}
	return h
}
