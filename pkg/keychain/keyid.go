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

package keychain

import (
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// KeyID represents a unified key identifier in the extended format "backend:type:algo:keyname".
// It provides a complete, human-readable way to reference keys across all backends.
//
// Format: backend:type:algo:keyname
//
// All segments except keyname are optional. Users can omit segments by leaving them empty:
//   - "my-key" - shorthand for just keyname (uses defaults)
//   - ":::my-key" - explicit form of above
//   - "pkcs11:::my-key" - specify backend only
//   - "pkcs11:signing::my-key" - specify backend and type
//   - "pkcs11:signing:ecdsa-p256:my-key" - full specification
//   - "::rsa:my-key" - specify algorithm only
//
// Examples of full Key IDs:
//   - pkcs8:signing:rsa:server-key
//   - pkcs11:signing:ecdsa-p256:hsm-key
//   - tpm2:attestation:rsa:device-attestation
//   - awskms:encryption:aes256-gcm:prod-key
type KeyID string

// String returns the string representation of the KeyID.
func (k KeyID) String() string {
	return string(k)
}

// Key ID validation errors
var (
	// ErrInvalidKeyIDFormat indicates the Key ID doesn't match "backend:type:algo:keyname" format.
	ErrInvalidKeyIDFormat = errors.New("keystore: invalid key ID format - expected 'backend:type:algo:keyname'")

	// ErrInvalidBackendType indicates an unrecognized backend type.
	ErrInvalidBackendType = errors.New("keystore: invalid backend type")

	// ErrBackendMismatch indicates the Key ID references a different backend.
	ErrBackendMismatch = errors.New("keystore: key ID backend does not match keystore backend")

	// ErrInvalidKeyName indicates the keyname component is invalid.
	ErrInvalidKeyName = errors.New("keystore: invalid key name")

	// ErrKeyIDTooLong indicates the Key ID exceeds maximum length.
	ErrKeyIDTooLong = errors.New("keystore: key ID too long (max 512 characters)")
)

const (
	// maxKeyIDLength is the maximum allowed length for a Key ID.
	maxKeyIDLength = 512

	// maxKeyNameLength is the maximum allowed length for a key name.
	maxKeyNameLength = 255
)

// validBackends contains all supported backend types for Key IDs.
var validBackends = map[string]bool{
	"pkcs8":    true, // File-based PKCS#8 asymmetric keys
	"aes":      true, // File-based AES symmetric keys
	"software": true, // Unified software backend (asymmetric + symmetric)
	"pkcs11":   true, // PKCS#11 Hardware Security Module
	"tpm2":     true, // Trusted Platform Module 2.0
	"awskms":   true, // AWS Key Management Service
	"gcpkms":   true, // Google Cloud KMS
	"azurekv":  true, // Azure Key Vault
	"vault":    true, // HashiCorp Vault
}

// keynameRegex validates keyname characters (alphanumeric, hyphens, underscores only).
var keynameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ParseKeyID parses an extended Key ID into its components.
//
// The Key ID format is: backend:type:algo:keyname
// - backend: One of the supported backend types (case-insensitive), or empty for default
// - type: The key type (signing, encryption, attestation, etc.), or empty for any
// - algo: The algorithm (rsa, ecdsa-p256, ed25519, aes256-gcm, etc.), or empty for any
// - keyname: The key's identifier within that backend (alphanumeric, hyphens, underscores)
//
// Shorthand: If the input contains no colons, it is treated as just the keyname.
// This allows users to specify "my-key" instead of ":::my-key".
//
// Optional segments: Any segment except keyname can be empty (e.g., "pkcs11:::my-key").
// Empty segments are returned as empty strings, allowing the caller to apply defaults.
//
// Returns the components (backend, type, algo, keyname) and any error.
// Empty strings indicate the segment was omitted and should use defaults.
//
// Examples:
//
//	// Full specification
//	backend, keyType, algo, keyname, err := ParseKeyID("pkcs11:signing:ecdsa-p256:my-key")
//	// backend = "pkcs11", keyType = "signing", algo = "ecdsa-p256", keyname = "my-key"
//
//	// Shorthand (just keyname)
//	backend, keyType, algo, keyname, err := ParseKeyID("my-key")
//	// backend = "", keyType = "", algo = "", keyname = "my-key"
//
//	// Backend only
//	backend, keyType, algo, keyname, err := ParseKeyID("pkcs11:::my-key")
//	// backend = "pkcs11", keyType = "", algo = "", keyname = "my-key"
func ParseKeyID(keyID string) (backend, keyType, algo, keyname string, err error) {
	if keyID == "" {
		return "", "", "", "", fmt.Errorf("%w: key ID cannot be empty", ErrInvalidKeyIDFormat)
	}

	// Length check
	if len(keyID) > maxKeyIDLength {
		return "", "", "", "", ErrKeyIDTooLong
	}

	// Check for shorthand (no colons = just keyname)
	if !strings.Contains(keyID, ":") {
		keyname = strings.TrimSpace(keyID)
		if err := validateKeyName(keyname); err != nil {
			return "", "", "", "", err
		}
		return "", "", "", keyname, nil
	}

	// Split on colons - expect exactly 4 parts
	parts := strings.Split(keyID, ":")
	if len(parts) != 4 {
		return "", "", "", "", fmt.Errorf("%w: expected format backend:type:algo:keyname, got %s", ErrInvalidKeyIDFormat, keyID)
	}

	// Extract and normalize components (empty strings are valid for optional segments)
	backend = strings.ToLower(strings.TrimSpace(parts[0]))
	keyType = strings.ToLower(strings.TrimSpace(parts[1]))
	algo = strings.ToLower(strings.TrimSpace(parts[2]))
	keyname = strings.TrimSpace(parts[3])

	// Keyname is required
	if keyname == "" {
		return "", "", "", "", fmt.Errorf("%w: keyname cannot be empty", ErrInvalidKeyIDFormat)
	}

	// Validate non-empty components only
	if backend != "" {
		if err := validateBackend(backend); err != nil {
			return "", "", "", "", err
		}
	}
	if keyType != "" {
		if err := validateKeyType(keyType); err != nil {
			return "", "", "", "", err
		}
	}
	if algo != "" {
		if err := validateAlgorithm(algo); err != nil {
			return "", "", "", "", err
		}
	}
	if err := validateKeyName(keyname); err != nil {
		return "", "", "", "", err
	}

	return backend, keyType, algo, keyname, nil
}

// NewKeyID creates a new KeyID from components.
// It validates all components and returns a properly formatted extended KeyID.
// Empty strings are allowed for backend, keyType, and algo to indicate defaults.
//
// Example:
//
//	// Full specification
//	keyID, err := NewKeyID("pkcs11", "signing", "ecdsa-p256", "my-key")
//	// keyID = "pkcs11:signing:ecdsa-p256:my-key"
//
//	// With optional components
//	keyID, err := NewKeyID("pkcs11", "", "", "my-key")
//	// keyID = "pkcs11:::my-key"
func NewKeyID(backend, keyType, algo, keyname string) (KeyID, error) {
	// Normalize components
	backend = strings.ToLower(strings.TrimSpace(backend))
	keyType = strings.ToLower(strings.TrimSpace(keyType))
	algo = strings.ToLower(strings.TrimSpace(algo))
	keyname = strings.TrimSpace(keyname)

	// Validate keyname (required)
	if err := validateKeyName(keyname); err != nil {
		return "", err
	}

	// Validate non-empty optional components
	if backend != "" {
		if err := validateBackend(backend); err != nil {
			return "", err
		}
	}
	if keyType != "" {
		if err := validateKeyType(keyType); err != nil {
			return "", err
		}
	}
	if algo != "" {
		if err := validateAlgorithm(algo); err != nil {
			return "", err
		}
	}

	// Construct Key ID
	keyID := KeyID(fmt.Sprintf("%s:%s:%s:%s", backend, keyType, algo, keyname))

	// Length check
	if len(keyID) > maxKeyIDLength {
		return "", ErrKeyIDTooLong
	}

	return keyID, nil
}

// ValidateKeyID validates a Key ID format without retrieving the key.
// It checks:
//   - Format: backend:type:algo:keyname
//   - Backend type is recognized
//   - Key type is valid
//   - Algorithm is valid
//   - Keyname uses valid characters
//   - Length constraints
//
// This function does NOT check if the key exists in the backend.
//
// Example:
//
//	err := ValidateKeyID("pkcs8:signing:rsa:valid-key")    // nil
//	err := ValidateKeyID("invalid:key:format")              // error
func ValidateKeyID(keyID string) error {
	_, _, _, _, err := ParseKeyID(keyID)
	return err
}

// validateBackend checks if a backend type is supported.
func validateBackend(backend string) error {
	if !validBackends[backend] {
		return fmt.Errorf("%w: %s", ErrInvalidBackendType, backend)
	}
	return nil
}

// validateKeyType validates the key type component of a Key ID.
// Valid types: attestation, ca, encryption, endorsement, hmac, idevid, ldevid,
// secret, signing, storage, tls, tpm
func validateKeyType(keyType string) error {
	validTypes := []string{
		"attestation", "ca", "encryption", "endorsement",
		"hmac", "idevid", "secret",
		"signing", "storage", "tls", "tpm",
	}
	keyType = strings.ToLower(keyType)
	for _, valid := range validTypes {
		if keyType == valid {
			return nil
		}
	}
	return fmt.Errorf("%w: invalid key type: %s", ErrInvalidKeyIDFormat, keyType)
}

// validateAlgorithm validates the algorithm component of a Key ID.
// Valid algorithms: rsa, ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519,
// aes128-gcm, aes192-gcm, aes256-gcm
func validateAlgorithm(algo string) error {
	validAlgos := []string{
		// Asymmetric algorithms
		"rsa",
		"ecdsa-p256", "ecdsa-p-256", "p256", "p-256",
		"ecdsa-p384", "ecdsa-p-384", "p384", "p-384",
		"ecdsa-p521", "ecdsa-p-521", "p521", "p-521",
		"ed25519",
		// Symmetric algorithms
		"aes128-gcm", "aes128",
		"aes192-gcm", "aes192",
		"aes256-gcm", "aes256",
	}
	algo = strings.ToLower(algo)
	for _, valid := range validAlgos {
		if algo == valid {
			return nil
		}
	}
	return fmt.Errorf("%w: invalid algorithm: %s", ErrInvalidKeyIDFormat, algo)
}

// validateKeyName validates the keyname component of a Key ID.
// It ensures:
//   - Non-empty
//   - Length <= 255 characters
//   - Only alphanumeric, hyphens, and underscores
//   - No path traversal characters (/, .., \)
func validateKeyName(keyname string) error {
	if keyname == "" {
		return fmt.Errorf("%w: keyname cannot be empty", ErrInvalidKeyName)
	}

	if len(keyname) > maxKeyNameLength {
		return fmt.Errorf("%w: keyname too long (max %d characters)", ErrInvalidKeyName, maxKeyNameLength)
	}

	// Check for path traversal
	if strings.Contains(keyname, "..") || strings.Contains(keyname, "/") || strings.Contains(keyname, "\\") {
		return fmt.Errorf("%w: keyname cannot contain path traversal characters", ErrInvalidKeyName)
	}

	// Check character whitelist
	if !keynameRegex.MatchString(keyname) {
		return fmt.Errorf("%w: keyname must contain only alphanumeric, hyphens, and underscores", ErrInvalidKeyName)
	}

	return nil
}

// keyIDToBackendType converts a backend string from a Key ID to a BackendType.
// This is used internally to map Key IDs to types.BackendType.
func keyIDToBackendType(backendStr string) (types.BackendType, error) {
	// Normalize to lowercase
	backendStr = strings.ToLower(backendStr)

	// Map Key ID backend names to BackendType constants
	switch backendStr {
	case "pkcs8", "sw":
		return types.BackendTypePKCS8, nil
	case "aes":
		return types.BackendTypeAES, nil
	case "software":
		return types.BackendTypeSoftware, nil
	case "pkcs11":
		return types.BackendTypePKCS11, nil
	case "tpm2":
		return types.BackendTypeTPM2, nil
	case "awskms":
		return types.BackendTypeAWSKMS, nil
	case "gcpkms":
		return types.BackendTypeGCPKMS, nil
	case "azurekv":
		return types.BackendTypeAzureKV, nil
	case "vault":
		return types.BackendTypeVault, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidBackendType, backendStr)
	}
}

// backendTypeToKeyIDString converts a types.BackendType to the backend string used in Key IDs.
// This is the inverse of keyIDToBackendType.
func backendTypeToKeyIDString(bt types.BackendType) string {
	// BackendType string representation matches Key ID backend names directly
	return string(bt)
}

// keyTypeToEnum converts a string key type to types.KeyType.
func keyTypeToEnum(keyType string) (types.KeyType, error) {
	switch strings.ToLower(keyType) {
	case "attestation":
		return types.KeyTypeAttestation, nil
	case "ca":
		return types.KeyTypeCA, nil
	case "encryption":
		return types.KeyTypeEncryption, nil
	case "endorsement":
		return types.KeyTypeEndorsement, nil
	case "hmac":
		return types.KeyTypeHMAC, nil
	case "idevid":
		return types.KeyTypeIDevID, nil
	case "secret":
		return types.KeyTypeSecret, nil
	case "signing":
		return types.KeyTypeSigning, nil
	case "storage":
		return types.KeyTypeStorage, nil
	case "tls":
		return types.KeyTypeTLS, nil
	case "tpm":
		return types.KeyTypeTPM, nil
	default:
		return 0, fmt.Errorf("unknown key type: %s", keyType)
	}
}

// algorithmToEnum converts a string algorithm to x509.PublicKeyAlgorithm or types.SymmetricAlgorithm.
// For asymmetric algorithms, it returns x509.PublicKeyAlgorithm.
// For symmetric algorithms, it returns types.SymmetricAlgorithm.
// The caller needs to check the type and handle appropriately.
func algorithmToEnum(algo string) (interface{}, error) {
	switch strings.ToLower(algo) {
	case "rsa":
		return x509.RSA, nil
	case "ecdsa", "ecdsa-p256", "ecdsa-p-256", "p256", "p-256",
		"ecdsa-p384", "ecdsa-p-384", "p384", "p-384",
		"ecdsa-p521", "ecdsa-p-521", "p521", "p-521":
		// Return ECDSA - curve will be extracted separately
		return x509.ECDSA, nil
	case "ed25519":
		return x509.Ed25519, nil
	case "aes128-gcm", "aes128":
		return types.SymmetricAES128GCM, nil
	case "aes192-gcm", "aes192":
		return types.SymmetricAES192GCM, nil
	case "aes256-gcm", "aes256":
		return types.SymmetricAES256GCM, nil
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algo)
	}
}

// extractECDSACurve extracts the ECDSA curve from an algorithm string.
// Returns the curve name (e.g., "P-256", "P-384", "P-521").
func extractECDSACurve(algo string) (string, error) {
	algo = strings.ToLower(algo)
	switch {
	case strings.Contains(algo, "p256") || strings.Contains(algo, "p-256"):
		return "P-256", nil
	case strings.Contains(algo, "p384") || strings.Contains(algo, "p-384"):
		return "P-384", nil
	case strings.Contains(algo, "p521") || strings.Contains(algo, "p-521"):
		return "P-521", nil
	default:
		return "", fmt.Errorf("unknown ECDSA curve in algorithm: %s", algo)
	}
}

// backendTypeToStoreType converts a BackendType to StoreType.
func backendTypeToStoreType(bt types.BackendType) types.StoreType {
	switch bt {
	case types.BackendTypePKCS8, types.BackendTypeSoftware, types.BackendTypeAES:
		return types.StorePKCS8
	case types.BackendTypePKCS11:
		return types.StorePKCS11
	case types.BackendTypeTPM2:
		return types.StoreTPM2
	case types.BackendTypeAWSKMS:
		return types.StoreAWSKMS
	case types.BackendTypeGCPKMS:
		return types.StoreGCPKMS
	case types.BackendTypeAzureKV:
		return types.StoreAzureKV
	case types.BackendTypeVault:
		return types.StoreVault
	default:
		return types.StorePKCS8
	}
}

// ParseKeyIDToAttributes parses a Key ID string and returns KeyAttributes.
// This is a convenience function that combines ParseKeyID with attribute conversion.
//
// The Key ID format is: backend:type:algo:keyname
// All segments except keyname are optional:
//   - "my-key" - shorthand for just keyname (uses defaults)
//   - ":::my-key" - explicit form of above
//   - "pkcs11:::my-key" - specify backend only
//   - "pkcs11:signing:ecdsa-p256:my-key" - full specification
//
// Returns KeyAttributes populated with the parsed values.
// Empty segments result in zero values in the attributes.
func ParseKeyIDToAttributes(keyID string) (*types.KeyAttributes, error) {
	backend, keyType, algo, keyname, err := ParseKeyID(keyID)
	if err != nil {
		return nil, err
	}

	attrs := &types.KeyAttributes{
		CN: keyname,
	}

	// Set StoreType if backend was specified
	if backend != "" {
		bt, err := keyIDToBackendType(backend)
		if err != nil {
			return nil, err
		}
		attrs.StoreType = backendTypeToStoreType(bt)
	}

	// Set KeyType if type was specified
	if keyType != "" {
		kt, err := keyTypeToEnum(keyType)
		if err != nil {
			return nil, err
		}
		attrs.KeyType = kt
	}

	// Set algorithm if specified
	if algo != "" {
		algoEnum, err := algorithmToEnum(algo)
		if err != nil {
			return nil, err
		}

		switch a := algoEnum.(type) {
		case x509.PublicKeyAlgorithm:
			attrs.KeyAlgorithm = a
		case types.SymmetricAlgorithm:
			attrs.SymmetricAlgorithm = a
		}
	}

	return attrs, nil
}
