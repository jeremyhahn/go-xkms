// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package types contains shared type definitions used across the keychain,
// including key attributes, backend interfaces, and cryptographic types.
// This package has no dependencies on pkg/backend or pkg/keychain to prevent
// import cycles.
package types

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
)

// =============================================================================
// File System Types
// =============================================================================

// FSExtension represents file extension types used by the keychain
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

// Partition represents logical storage partitions within the keychain
// for organizing keys by their purpose.
type Partition string

const (
	// Partition constants for organizing keys by type
	PartitionRoot           Partition = ""
	PartitionTLS            Partition = "issued"
	PartitionEncryptionKeys Partition = "crypto"
	PartitionSigningKeys    Partition = "signing"
	PartitionHMAC           Partition = "hmac"
	PartitionSecrets        Partition = "secrets"
)

// Partitions is a list of all available partitions for iteration.
var Partitions = []Partition{
	PartitionRoot,
	PartitionTLS,
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
	StorePKCS8     StoreType = "pkcs8"
	StorePKCS11    StoreType = "pkcs11"
	StoreTPM2      StoreType = "tpm2"
	StoreAWSKMS    StoreType = "awskms"
	StoreGCPKMS    StoreType = "gcpkms"
	StoreAzureKV   StoreType = "azurekv"
	StoreVault     StoreType = "vault"
	StoreQuantum   StoreType = "quantum"
	StoreThreshold StoreType = "threshold"
	StoreUnknown   StoreType = "unknown"
)

// String returns the string representation of the store type.
func (st StoreType) String() string {
	return string(st)
}

// IsValid returns true if the store type is recognized.
func (st StoreType) IsValid() bool {
	switch st {
	case StorePKCS8, StorePKCS11, StoreTPM2, StoreAWSKMS, StoreGCPKMS, StoreAzureKV, StoreVault, StoreQuantum:
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
	case "pkcs8":
		return StorePKCS8
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
	BackendTypeAES          BackendType = "aes"          // AES symmetric encryption (software)
	BackendTypePKCS8        BackendType = "pkcs8"        // PKCS#8 asymmetric keys (RSA, ECDSA, Ed25519)
	BackendTypeSoftware     BackendType = "software"     // Unified software backend (asymmetric + symmetric)
	BackendTypePKCS11       BackendType = "pkcs11"       // PKCS#11 hardware security modules
	BackendTypeSmartCardHSM BackendType = "smartcardhsm" // SmartCard-HSM with DKEK support
	BackendTypeTPM2         BackendType = "tpm2"         // TPM 2.0 hardware security module
	BackendTypeAWSKMS       BackendType = "awskms"       // AWS Key Management Service
	BackendTypeGCPKMS       BackendType = "gcpkms"       // Google Cloud Key Management Service
	BackendTypeAzureKV      BackendType = "azurekv"      // Azure Key Vault
	BackendTypeVault        BackendType = "vault"        // HashiCorp Vault
	BackendTypeQuantum      BackendType = "quantum"      // Quantum-safe cryptography (ML-DSA, ML-KEM)
	BackendTypeThreshold    BackendType = "threshold"    // Threshold cryptography (Shamir, threshold ECDSA)
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

// =============================================================================
// Key Attribute Types
// =============================================================================

// AESAttributes contains AES-specific key generation parameters.
type AESAttributes struct {
	// KeySize is the AES key size in bits (128, 192, or 256)
	KeySize int

	// NonceSize is the nonce size in bytes (default: 12 for GCM)
	// Most implementations should use the default of 12 bytes (96 bits)
	NonceSize int
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

// TPMAttributes contains Trusted Platform Module specific configuration.
// This struct intentionally uses interface{} for TPM-specific types to avoid
// requiring TPM dependencies in the core keystore package.
type TPMAttributes struct {
	// Handle is the TPM handle for the key
	Handle interface{}

	// HandleType specifies the type of TPM handle
	HandleType interface{}

	// Hierarchy specifies the TPM hierarchy (owner, endorsement, platform)
	Hierarchy interface{}

	// HierarchyAuth provides authentication for the hierarchy
	HierarchyAuth Password

	// PublicKeyBytes contains the encoded public key
	PublicKeyBytes []byte

	// PrivateKeyBlob contains the encrypted private key blob
	PrivateKeyBlob []byte

	// HashAlg specifies the TPM hash algorithm
	HashAlg interface{}

	// PCRSelection specifies Platform Configuration Registers to include
	PCRSelection interface{}

	// CertHandle is the handle for certificate storage
	CertHandle interface{}

	// CertifyInfo contains attestation information
	CertifyInfo []byte

	// CreationTicketDigest contains the creation ticket
	CreationTicketDigest []byte

	// Name is the TPM name for the object
	Name interface{}

	// Public contains the TPM public structure
	Public interface{}

	// BPublic contains the TPM2B_PUBLIC structure
	BPublic interface{}

	// Template contains the key template used for creation
	Template interface{}

	// Signature contains the signature from attestation
	Signature []byte

	// SessionCloser provides a function to close TPM sessions
	SessionCloser func() error
}

// Password is an interface for accessing sensitive password data.
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

// NewClearPassword creates a new clear text password stored in memory.
// The password is stored as-is without any encryption or obfuscation.
// If password is nil or empty, an empty password is created.
func NewClearPassword(password []byte) Password {
	// Make a defensive copy to prevent external modification
	p := make([]byte, len(password))
	copy(p, password)
	return &ClearPassword{password: p}
}

// NewClearPasswordFromString creates a new clear text password from a string.
// The string is converted to bytes and stored in memory.
func NewClearPasswordFromString(password string) Password {
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

// KeyAttributes contains all configuration parameters for a cryptographic key,
// including algorithm selection, store configuration, and optional parent keys.
type KeyAttributes struct {
	// CN is the common name identifier for the key
	CN string

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

	// SignatureAlgorithm specifies the signature algorithm to use
	SignatureAlgorithm x509.SignatureAlgorithm

	// StoreType specifies the backend storage type
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

	// AESAttributes contains AES-specific parameters (only for AES keys)
	AESAttributes *AESAttributes

	// AEADOptions contains AEAD safety tracking options (only for symmetric keys)
	// If nil, default safety options will be applied (tracking enabled).
	AEADOptions *AEADOptions

	// Exportable indicates if the key can be exported from the backend.
	// For hardware-backed keys (TPM, HSM), this may be restricted by policy.
	// Default is false for security - keys must be explicitly marked as exportable.
	Exportable bool

	// TPMAttributes contains TPM-specific configuration
	TPMAttributes *TPMAttributes

	// Secret provides additional secret material for specific key types
	Secret Password

	// WrapAttributes specifies key wrapping configuration
	WrapAttributes *KeyAttributes
}

// String returns a human-readable representation of the key attributes.
func (attrs KeyAttributes) String() string {
	var sb strings.Builder

	var password, secret string
	if attrs.Debug && attrs.Password != nil {
		if p, err := attrs.Password.String(); err == nil {
			password = p
		}
		if attrs.Secret != nil {
			if s, err := attrs.Secret.String(); err == nil {
				secret = s
			}
		}
	}

	sb.WriteString("Key Attributes\n")
	sb.WriteString(fmt.Sprintf("  Common Name: %s\n", attrs.CN))
	sb.WriteString(fmt.Sprintf("  Debug: %t\n", attrs.Debug))
	sb.WriteString(fmt.Sprintf("  Hash: %s\n", attrs.Hash.String()))
	sb.WriteString(fmt.Sprintf("  Key Algorithm: %s\n", attrs.KeyAlgorithm))
	sb.WriteString(fmt.Sprintf("  Platform Policy: %t\n", attrs.PlatformPolicy))
	sb.WriteString(fmt.Sprintf("  Signature Algorithm: %s\n", attrs.SignatureAlgorithm.String()))
	sb.WriteString(fmt.Sprintf("  Store: %s\n", attrs.StoreType))
	sb.WriteString(fmt.Sprintf("  Type: %s\n", attrs.KeyType))

	if attrs.ECCAttributes != nil {
		sb.WriteString("ECC Attributes\n")
		sb.WriteString(fmt.Sprintf("  Curve: %s\n", attrs.ECCAttributes.Curve.Params().Name))
	} else if attrs.RSAAttributes != nil {
		sb.WriteString("RSA Attributes\n")
		sb.WriteString(fmt.Sprintf("  Size: %d\n", attrs.RSAAttributes.KeySize))
	} else if attrs.X25519Attributes != nil {
		sb.WriteString("X25519 Attributes\n")
		sb.WriteString("  Curve: X25519 (Curve25519)\n")
	}

	if attrs.Debug {
		sb.WriteString("Secrets\n")
		sb.WriteString(fmt.Sprintf("  Password: %s\n", password))
		sb.WriteString(fmt.Sprintf("  Secret: %s\n", secret))
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
		// Symmetric key validation
		switch attrs.SymmetricAlgorithm {
		case SymmetricAES128GCM, SymmetricAES192GCM, SymmetricAES256GCM:
			if attrs.AESAttributes == nil {
				return fmt.Errorf("AES attributes are required for AES keys")
			}
			if attrs.AESAttributes.KeySize != 128 && attrs.AESAttributes.KeySize != 192 && attrs.AESAttributes.KeySize != 256 {
				return fmt.Errorf("AES key size must be 128, 192, or 256 bits")
			}
		case SymmetricChaCha20Poly1305, SymmetricXChaCha20Poly1305:
			// ChaCha20-Poly1305 uses fixed 256-bit keys, no additional validation needed
		default:
			return fmt.Errorf("unsupported symmetric algorithm: %s", attrs.SymmetricAlgorithm)
		}
	} else {
		return fmt.Errorf("either KeyAlgorithm, SymmetricAlgorithm, or QuantumAttributes must be set")
	}

	return nil
}

// IsSymmetric returns true if this key is a symmetric key (has SymmetricAlgorithm set).
// Returns false for asymmetric keys.
func (attrs *KeyAttributes) IsSymmetric() bool {
	return attrs.SymmetricAlgorithm != ""
}

// ID returns a unique identifier for the key based on its attributes.
// Format for X25519 keys: [partition:]storetype:keytype:cn:x25519
// Format for quantum keys: [partition:]storetype:keytype:cn:quantumalgorithm
// Format for asymmetric keys: [partition:]storetype:keytype:cn:keyalgorithm
// Format for symmetric keys: [partition:]storetype:keytype:cn:symmetricalgorithm
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

	// Build ID based on whether partition is set
	if attrs.Partition != "" {
		return fmt.Sprintf("%s:%s:%s:%s:%s",
			attrs.Partition,
			attrs.StoreType,
			attrs.KeyType,
			attrs.CN,
			algorithm)
	}

	return fmt.Sprintf("%s:%s:%s:%s",
		attrs.StoreType,
		attrs.KeyType,
		attrs.CN,
		algorithm)
}

// =============================================================================
// Backend Capabilities
// =============================================================================

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

// SupportsKeyRotation returns true if the backend supports key rotation.
func (c Capabilities) SupportsKeyRotation() bool {
	return c.KeyRotation
}

// String returns a string representation of the capabilities.
func (c Capabilities) String() string {
	return fmt.Sprintf("Capabilities{Keys: %v, HardwareBacked: %v, Signing: %v, Decryption: %v, KeyRotation: %v}",
		c.Keys, c.HardwareBacked, c.Signing, c.Decryption, c.KeyRotation)
}

// NewSoftwareCapabilities returns capabilities for a software-based backend.
func NewSoftwareCapabilities() Capabilities {
	return Capabilities{
		Keys:           true,
		HardwareBacked: false,
		Signing:        true,
		Decryption:     true,
		KeyRotation:    false,
	}
}

// NewHardwareCapabilities returns capabilities for a hardware-based backend.
func NewHardwareCapabilities() Capabilities {
	return Capabilities{
		Keys:           true,
		HardwareBacked: true,
		Signing:        true,
		Decryption:     true,
		KeyRotation:    false,
	}
}

// NewUnifiedSoftwareCapabilities returns capabilities for the unified software backend
// which supports both asymmetric and symmetric operations.
func NewUnifiedSoftwareCapabilities() Capabilities {
	return Capabilities{
		Keys:                true,
		HardwareBacked:      false,
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: true,
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
type Backend interface {
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

// AttestingBackend extends Backend with key attestation capabilities.
// Backends that support hardware key attestation should implement this interface.
// Attestation proves that a key was generated in hardware and never left the secure boundary.
//
// This is critical for zero-trust architectures and compliance requirements
// (FIPS 140-2, Common Criteria, supply chain security).
//
// Only hardware-backed backends (TPM2, PKCS#11) may implement this interface.
type AttestingBackend interface {
	Backend

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

// SymmetricBackend extends Backend with symmetric encryption capabilities.
// Backends that support symmetric operations should implement this interface.
type SymmetricBackend interface {
	Backend

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

// SymmetricBackendWithTracking extends SymmetricBackend with AEAD safety tracking.
// Backends that support symmetric encryption should implement this interface to
// provide nonce uniqueness checking and bytes encrypted tracking.
//
// This interface is optional - backends can implement basic SymmetricBackend
// without tracking, but implementing tracking is HIGHLY RECOMMENDED for
// production systems to prevent nonce reuse and enforce cryptographic limits.
type SymmetricBackendWithTracking interface {
	SymmetricBackend

	// GetTracker returns the AEAD safety tracker for this backend.
	// Returns nil if tracking is not supported or disabled.
	GetTracker() AEADSafetyTracker
}

// =============================================================================
// Helper Functions
// =============================================================================

// AvailableHashes returns a map of all supported hash functions.
func AvailableHashes() map[string]crypto.Hash {
	return map[string]crypto.Hash{
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
	case "SHA1":
		return crypto.SHA1
	case "SHA224":
		return crypto.SHA224
	case "SHA256":
		return crypto.SHA256
	case "SHA384":
		return crypto.SHA384
	case "SHA512":
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
