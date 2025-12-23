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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseKeyID_Valid tests parsing of valid Key IDs using the extended format.
func TestParseKeyID_Valid(t *testing.T) {
	tests := []struct {
		name            string
		keyID           string
		expectedBackend string
		expectedKeyType string
		expectedAlgo    string
		expectedKeyname string
	}{
		{
			name:            "software RSA signing key",
			keyID:           "software:signing:rsa:my-key",
			expectedBackend: "software",
			expectedKeyType: "signing",
			expectedAlgo:    "rsa",
			expectedKeyname: "my-key",
		},
		{
			name:            "software ECDSA P-256 signing key",
			keyID:           "software:signing:ecdsa-p256:api-key",
			expectedBackend: "software",
			expectedKeyType: "signing",
			expectedAlgo:    "ecdsa-p256",
			expectedKeyname: "api-key",
		},
		{
			name:            "pkcs11 ECDSA P-384 signing key",
			keyID:           "pkcs11:signing:ecdsa-p384:hsm-key",
			expectedBackend: "pkcs11",
			expectedKeyType: "signing",
			expectedAlgo:    "ecdsa-p384",
			expectedKeyname: "hsm-key",
		},
		{
			name:            "pkcs11 ECDSA P-521 signing key",
			keyID:           "pkcs11:signing:ecdsa-p521:hsm-key-521",
			expectedBackend: "pkcs11",
			expectedKeyType: "signing",
			expectedAlgo:    "ecdsa-p521",
			expectedKeyname: "hsm-key-521",
		},
		{
			name:            "tpm2 RSA attestation key",
			keyID:           "tpm2:attestation:rsa:attestation",
			expectedBackend: "tpm2",
			expectedKeyType: "attestation",
			expectedAlgo:    "rsa",
			expectedKeyname: "attestation",
		},
		{
			name:            "awskms AES256 encryption key",
			keyID:           "awskms:encryption:aes256-gcm:data-key",
			expectedBackend: "awskms",
			expectedKeyType: "encryption",
			expectedAlgo:    "aes256-gcm",
			expectedKeyname: "data-key",
		},
		{
			name:            "software Ed25519 signing key",
			keyID:           "software:signing:ed25519:ed-key",
			expectedBackend: "software",
			expectedKeyType: "signing",
			expectedAlgo:    "ed25519",
			expectedKeyname: "ed-key",
		},
		{
			name:            "software AES128 secret key",
			keyID:           "software:secret:aes128-gcm:my-secret",
			expectedBackend: "software",
			expectedKeyType: "secret",
			expectedAlgo:    "aes128-gcm",
			expectedKeyname: "my-secret",
		},
		{
			name:            "software RSA encryption key",
			keyID:           "software:encryption:rsa:backup-key",
			expectedBackend: "software",
			expectedKeyType: "encryption",
			expectedAlgo:    "rsa",
			expectedKeyname: "backup-key",
		},
		{
			name:            "software RSA TLS key",
			keyID:           "software:tls:rsa:server-tls",
			expectedBackend: "software",
			expectedKeyType: "tls",
			expectedAlgo:    "rsa",
			expectedKeyname: "server-tls",
		},
		{
			name:            "pkcs11 RSA CA key",
			keyID:           "pkcs11:ca:rsa:root-ca",
			expectedBackend: "pkcs11",
			expectedKeyType: "ca",
			expectedAlgo:    "rsa",
			expectedKeyname: "root-ca",
		},
		{
			name:            "tpm2 RSA endorsement key",
			keyID:           "tpm2:endorsement:rsa:ek",
			expectedBackend: "tpm2",
			expectedKeyType: "endorsement",
			expectedAlgo:    "rsa",
			expectedKeyname: "ek",
		},
		{
			name:            "tpm2 RSA storage key",
			keyID:           "tpm2:storage:rsa:srk",
			expectedBackend: "tpm2",
			expectedKeyType: "storage",
			expectedAlgo:    "rsa",
			expectedKeyname: "srk",
		},
		{
			name:            "uppercase normalization",
			keyID:           "PKCS11:SIGNING:RSA:MY-KEY",
			expectedBackend: "pkcs11",
			expectedKeyType: "signing",
			expectedAlgo:    "rsa",
			expectedKeyname: "MY-KEY",
		},
		{
			name:            "mixed case normalization",
			keyID:           "Software:Signing:Rsa:Test-Key",
			expectedBackend: "software",
			expectedKeyType: "signing",
			expectedAlgo:    "rsa",
			expectedKeyname: "Test-Key",
		},
		{
			name:            "keyname with underscores",
			keyID:           "software:signing:rsa:my_test_key",
			expectedBackend: "software",
			expectedKeyType: "signing",
			expectedAlgo:    "rsa",
			expectedKeyname: "my_test_key",
		},
		{
			name:            "keyname with numbers",
			keyID:           "software:signing:rsa:key-2024-v1",
			expectedBackend: "software",
			expectedKeyType: "signing",
			expectedAlgo:    "rsa",
			expectedKeyname: "key-2024-v1",
		},
		{
			name:            "AES192 GCM key",
			keyID:           "software:secret:aes192-gcm:test-key",
			expectedBackend: "software",
			expectedKeyType: "secret",
			expectedAlgo:    "aes192-gcm",
			expectedKeyname: "test-key",
		},
		{
			name:            "HMAC key type",
			keyID:           "software:hmac:aes256-gcm:hmac-key",
			expectedBackend: "software",
			expectedKeyType: "hmac",
			expectedAlgo:    "aes256-gcm",
			expectedKeyname: "hmac-key",
		},
		{
			name:            "IDevID key type",
			keyID:           "tpm2:idevid:rsa:device-id",
			expectedBackend: "tpm2",
			expectedKeyType: "idevid",
			expectedAlgo:    "rsa",
			expectedKeyname: "device-id",
		},
		{
			name:            "TPM key type",
			keyID:           "tpm2:tpm:rsa:tpm-key",
			expectedBackend: "tpm2",
			expectedKeyType: "tpm",
			expectedAlgo:    "rsa",
			expectedKeyname: "tpm-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, keyType, algo, keyname, err := ParseKeyID(tt.keyID)
			require.NoError(t, err, "ParseKeyID should not return error for valid input")
			assert.Equal(t, tt.expectedBackend, backend, "Backend mismatch")
			assert.Equal(t, tt.expectedKeyType, keyType, "KeyType mismatch")
			assert.Equal(t, tt.expectedAlgo, algo, "Algorithm mismatch")
			assert.Equal(t, tt.expectedKeyname, keyname, "Keyname mismatch")
		})
	}
}

// TestParseKeyID_Shorthand tests parsing of shorthand Key IDs (just keyname).
func TestParseKeyID_Shorthand(t *testing.T) {
	tests := []struct {
		name            string
		keyID           string
		expectedKeyname string
	}{
		{
			name:            "simple keyname",
			keyID:           "my-key",
			expectedKeyname: "my-key",
		},
		{
			name:            "keyname with underscores",
			keyID:           "my_test_key",
			expectedKeyname: "my_test_key",
		},
		{
			name:            "keyname with numbers",
			keyID:           "key-2024-v1",
			expectedKeyname: "key-2024-v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, keyType, algo, keyname, err := ParseKeyID(tt.keyID)
			require.NoError(t, err, "ParseKeyID should not return error for shorthand")
			assert.Empty(t, backend, "Backend should be empty for shorthand")
			assert.Empty(t, keyType, "KeyType should be empty for shorthand")
			assert.Empty(t, algo, "Algorithm should be empty for shorthand")
			assert.Equal(t, tt.expectedKeyname, keyname, "Keyname mismatch")
		})
	}
}

// TestParseKeyID_OptionalSegments tests parsing of Key IDs with optional segments.
func TestParseKeyID_OptionalSegments(t *testing.T) {
	tests := []struct {
		name            string
		keyID           string
		expectedBackend string
		expectedKeyType string
		expectedAlgo    string
		expectedKeyname string
	}{
		{
			name:            "all segments empty except keyname",
			keyID:           ":::my-key",
			expectedBackend: "",
			expectedKeyType: "",
			expectedAlgo:    "",
			expectedKeyname: "my-key",
		},
		{
			name:            "backend only",
			keyID:           "pkcs11:::my-key",
			expectedBackend: "pkcs11",
			expectedKeyType: "",
			expectedAlgo:    "",
			expectedKeyname: "my-key",
		},
		{
			name:            "backend and type only",
			keyID:           "pkcs11:signing::my-key",
			expectedBackend: "pkcs11",
			expectedKeyType: "signing",
			expectedAlgo:    "",
			expectedKeyname: "my-key",
		},
		{
			name:            "backend and algo only",
			keyID:           "pkcs11::rsa:my-key",
			expectedBackend: "pkcs11",
			expectedKeyType: "",
			expectedAlgo:    "rsa",
			expectedKeyname: "my-key",
		},
		{
			name:            "type and algo only",
			keyID:           ":signing:rsa:my-key",
			expectedBackend: "",
			expectedKeyType: "signing",
			expectedAlgo:    "rsa",
			expectedKeyname: "my-key",
		},
		{
			name:            "algo only",
			keyID:           "::rsa:my-key",
			expectedBackend: "",
			expectedKeyType: "",
			expectedAlgo:    "rsa",
			expectedKeyname: "my-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, keyType, algo, keyname, err := ParseKeyID(tt.keyID)
			require.NoError(t, err, "ParseKeyID should not return error for optional segments")
			assert.Equal(t, tt.expectedBackend, backend, "Backend mismatch")
			assert.Equal(t, tt.expectedKeyType, keyType, "KeyType mismatch")
			assert.Equal(t, tt.expectedAlgo, algo, "Algorithm mismatch")
			assert.Equal(t, tt.expectedKeyname, keyname, "Keyname mismatch")
		})
	}
}

// TestParseKeyID_Invalid tests parsing of invalid Key IDs.
func TestParseKeyID_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		expectedErr error
	}{
		{
			name:        "only 2 fields (old format)",
			keyID:       "software:my-key",
			expectedErr: ErrInvalidKeyIDFormat,
		},
		{
			name:        "only 3 fields",
			keyID:       "software:signing:my-key",
			expectedErr: ErrInvalidKeyIDFormat,
		},
		{
			name:        "5 fields",
			keyID:       "software:signing:rsa:my-key:extra",
			expectedErr: ErrInvalidKeyIDFormat,
		},
		{
			name:        "empty keyname",
			keyID:       "software:signing:rsa:",
			expectedErr: ErrInvalidKeyIDFormat,
		},
		{
			name:        "all empty",
			keyID:       ":::",
			expectedErr: ErrInvalidKeyIDFormat,
		},
		{
			name:        "invalid backend type",
			keyID:       "unknown:signing:rsa:my-key",
			expectedErr: ErrInvalidBackendType,
		},
		{
			name:        "invalid backend characters",
			keyID:       "pkcs-8:signing:rsa:my-key",
			expectedErr: ErrInvalidBackendType,
		},
		{
			name:        "invalid key type",
			keyID:       "software:invalid-type:rsa:my-key",
			expectedErr: ErrInvalidKeyIDFormat,
		},
		{
			name:        "invalid algorithm",
			keyID:       "software:signing:invalid-algo:my-key",
			expectedErr: ErrInvalidKeyIDFormat,
		},
		{
			name:        "keyname with path traversal (..)",
			keyID:       "software:signing:rsa:../../../etc/passwd",
			expectedErr: ErrInvalidKeyName,
		},
		{
			name:        "keyname with forward slash",
			keyID:       "software:signing:rsa:path/to/key",
			expectedErr: ErrInvalidKeyName,
		},
		{
			name:        "keyname with backslash",
			keyID:       "software:signing:rsa:path\\to\\key",
			expectedErr: ErrInvalidKeyName,
		},
		{
			name:        "keyname with special characters",
			keyID:       "software:signing:rsa:key@#$%",
			expectedErr: ErrInvalidKeyName,
		},
		{
			name:        "keyname with spaces",
			keyID:       "software:signing:rsa:my key",
			expectedErr: ErrInvalidKeyName,
		},
		{
			name:        "too long key ID",
			keyID:       "software:signing:rsa:" + strings.Repeat("a", 600),
			expectedErr: ErrKeyIDTooLong,
		},
		{
			name:        "too long keyname",
			keyID:       "software:signing:rsa:" + strings.Repeat("a", 300),
			expectedErr: ErrInvalidKeyName,
		},
		{
			name:        "empty string",
			keyID:       "",
			expectedErr: ErrInvalidKeyIDFormat,
		},
		{
			name:        "shorthand only whitespace",
			keyID:       "   ",
			expectedErr: ErrInvalidKeyName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, keyType, algo, keyname, err := ParseKeyID(tt.keyID)
			require.Error(t, err, "ParseKeyID should return error for invalid input")
			assert.ErrorIs(t, err, tt.expectedErr, "Expected specific error type")
			assert.Empty(t, backend, "Backend should be empty on error")
			assert.Empty(t, keyType, "KeyType should be empty on error")
			assert.Empty(t, algo, "Algorithm should be empty on error")
			assert.Empty(t, keyname, "Keyname should be empty on error")
		})
	}
}

// TestNewKeyID_Valid tests creating valid Key IDs using the extended format.
func TestNewKeyID_Valid(t *testing.T) {
	tests := []struct {
		name          string
		backend       string
		keyType       string
		algo          string
		keyname       string
		expectedKeyID string
	}{
		{
			name:          "software RSA signing",
			backend:       "software",
			keyType:       "signing",
			algo:          "rsa",
			keyname:       "my-key",
			expectedKeyID: "software:signing:rsa:my-key",
		},
		{
			name:          "pkcs11 ECDSA P-256",
			backend:       "pkcs11",
			keyType:       "signing",
			algo:          "ecdsa-p256",
			keyname:       "hsm-signing-key",
			expectedKeyID: "pkcs11:signing:ecdsa-p256:hsm-signing-key",
		},
		{
			name:          "tpm2 attestation",
			backend:       "tpm2",
			keyType:       "attestation",
			algo:          "rsa",
			keyname:       "attestation_key",
			expectedKeyID: "tpm2:attestation:rsa:attestation_key",
		},
		{
			name:          "backend normalization",
			backend:       "PKCS11",
			keyType:       "SIGNING",
			algo:          "RSA",
			keyname:       "MY-KEY",
			expectedKeyID: "pkcs11:signing:rsa:MY-KEY",
		},
		{
			name:          "whitespace trimming",
			backend:       " software ",
			keyType:       " signing ",
			algo:          " rsa ",
			keyname:       " my-key ",
			expectedKeyID: "software:signing:rsa:my-key",
		},
		{
			name:          "AES encryption key",
			backend:       "software",
			keyType:       "secret",
			algo:          "aes256-gcm",
			keyname:       "my-secret",
			expectedKeyID: "software:secret:aes256-gcm:my-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, err := NewKeyID(tt.backend, tt.keyType, tt.algo, tt.keyname)
			require.NoError(t, err, "NewKeyID should not return error for valid input")
			assert.Equal(t, tt.expectedKeyID, keyID.String(), "Key ID mismatch")
		})
	}
}

// TestNewKeyID_OptionalSegments tests creating Key IDs with optional segments.
func TestNewKeyID_OptionalSegments(t *testing.T) {
	tests := []struct {
		name          string
		backend       string
		keyType       string
		algo          string
		keyname       string
		expectedKeyID string
	}{
		{
			name:          "empty backend",
			backend:       "",
			keyType:       "signing",
			algo:          "rsa",
			keyname:       "my-key",
			expectedKeyID: ":signing:rsa:my-key",
		},
		{
			name:          "empty key type",
			backend:       "software",
			keyType:       "",
			algo:          "rsa",
			keyname:       "my-key",
			expectedKeyID: "software::rsa:my-key",
		},
		{
			name:          "empty algorithm",
			backend:       "software",
			keyType:       "signing",
			algo:          "",
			keyname:       "my-key",
			expectedKeyID: "software:signing::my-key",
		},
		{
			name:          "all optional segments empty",
			backend:       "",
			keyType:       "",
			algo:          "",
			keyname:       "my-key",
			expectedKeyID: ":::my-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, err := NewKeyID(tt.backend, tt.keyType, tt.algo, tt.keyname)
			require.NoError(t, err, "NewKeyID should not return error for optional segments")
			assert.Equal(t, tt.expectedKeyID, keyID.String(), "Key ID mismatch")
		})
	}
}

// TestNewKeyID_Invalid tests creating invalid Key IDs.
func TestNewKeyID_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		backend     string
		keyType     string
		algo        string
		keyname     string
		expectedErr error
	}{
		{
			name:        "invalid backend",
			backend:     "unknown",
			keyType:     "signing",
			algo:        "rsa",
			keyname:     "my-key",
			expectedErr: ErrInvalidBackendType,
		},
		{
			name:        "invalid key type",
			backend:     "software",
			keyType:     "invalid-type",
			algo:        "rsa",
			keyname:     "my-key",
			expectedErr: ErrInvalidKeyIDFormat,
		},
		{
			name:        "invalid algorithm",
			backend:     "software",
			keyType:     "signing",
			algo:        "invalid-algo",
			keyname:     "my-key",
			expectedErr: ErrInvalidKeyIDFormat,
		},
		{
			name:        "empty keyname",
			backend:     "software",
			keyType:     "signing",
			algo:        "rsa",
			keyname:     "",
			expectedErr: ErrInvalidKeyName,
		},
		{
			name:        "keyname with special chars",
			backend:     "software",
			keyType:     "signing",
			algo:        "rsa",
			keyname:     "key@test",
			expectedErr: ErrInvalidKeyName,
		},
		{
			name:        "keyname too long",
			backend:     "software",
			keyType:     "signing",
			algo:        "rsa",
			keyname:     strings.Repeat("a", 300),
			expectedErr: ErrInvalidKeyName,
		},
		{
			name:        "keyname with path traversal",
			backend:     "software",
			keyType:     "signing",
			algo:        "rsa",
			keyname:     "../etc/passwd",
			expectedErr: ErrInvalidKeyName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, err := NewKeyID(tt.backend, tt.keyType, tt.algo, tt.keyname)
			require.Error(t, err, "NewKeyID should return error for invalid input")
			assert.ErrorIs(t, err, tt.expectedErr, "Expected specific error type")
			assert.Empty(t, keyID, "Key ID should be empty on error")
		})
	}
}

// TestValidateKeyID tests Key ID validation.
func TestValidateKeyID(t *testing.T) {
	validKeyIDs := []string{
		// Full specification
		"software:signing:rsa:server-key",
		"pkcs11:signing:ecdsa-p256:hsm-key",
		"tpm2:attestation:rsa:ak-key",
		"awskms:encryption:aes256-gcm:prod-key",
		"gcpkms:signing:ed25519:signing-key",
		"azurekv:encryption:rsa:master-key",
		"vault:secret:aes256-gcm:transit-key",
		"software:signing:rsa:dev-key",
		// Shorthand (just keyname)
		"my-key",
		"server-key",
		"test_key_123",
		// Optional segments
		":::my-key",
		"pkcs11:::my-key",
		"pkcs11:signing::my-key",
		":signing:rsa:my-key",
	}

	for _, keyID := range validKeyIDs {
		t.Run("valid_"+keyID, func(t *testing.T) {
			err := ValidateKeyID(keyID)
			assert.NoError(t, err, "Valid Key ID should pass validation")
		})
	}

	invalidKeyIDs := []string{
		"software:my-key",                      // Old 2-field format
		"software:signing:my-key",              // Only 3 fields
		"unknown:signing:rsa:key",           // Invalid backend
		"software:invalid-type:rsa:key",        // Invalid key type
		"software:signing:invalid-algo:key",    // Invalid algorithm
		"software:signing:rsa:",                // Empty keyname
		":::",                               // All empty including keyname
		"software:signing:rsa:../etc/passwd",   // Path traversal
		"software:signing:rsa:key/path",        // Forward slash
		"software:signing:rsa:key with spaces", // Spaces in keyname
	}

	for _, keyID := range invalidKeyIDs {
		t.Run("invalid_"+keyID, func(t *testing.T) {
			err := ValidateKeyID(keyID)
			assert.Error(t, err, "Invalid Key ID should fail validation")
		})
	}
}

// TestKeyID_String tests the String method.
func TestKeyID_String(t *testing.T) {
	keyID := KeyID("software:my-key")
	assert.Equal(t, "software:my-key", keyID.String())
}

// TestKeyIDToBackendType tests conversion from Key ID backend to BackendType.
func TestKeyIDToBackendType(t *testing.T) {
	tests := []struct {
		name                string
		backend             string
		expectedBackendType types.BackendType
	}{
		{
			name:                "software to BackendTypeSoftware",
			backend:             "software",
			expectedBackendType: backend.BackendTypeSoftware,
		},
		{
			name:                "sw to BackendTypeSoftware",
			backend:             "sw",
			expectedBackendType: backend.BackendTypeSoftware,
		},
		{
			name:                "pkcs11 to BackendTypePKCS11",
			backend:             "pkcs11",
			expectedBackendType: backend.BackendTypePKCS11,
		},
		{
			name:                "tpm2 to BackendTypeTPM2",
			backend:             "tpm2",
			expectedBackendType: backend.BackendTypeTPM2,
		},
		{
			name:                "awskms to BackendTypeAWSKMS",
			backend:             "awskms",
			expectedBackendType: backend.BackendTypeAWSKMS,
		},
		{
			name:                "gcpkms to BackendTypeGCPKMS",
			backend:             "gcpkms",
			expectedBackendType: backend.BackendTypeGCPKMS,
		},
		{
			name:                "azurekv to BackendTypeAzureKV",
			backend:             "azurekv",
			expectedBackendType: backend.BackendTypeAzureKV,
		},
		{
			name:                "vault to BackendTypeVault",
			backend:             "vault",
			expectedBackendType: backend.BackendTypeVault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backendType, err := keyIDToBackendType(tt.backend)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedBackendType, backendType)
		})
	}

	// Test invalid backend
	_, err := keyIDToBackendType("invalid")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidBackendType)
}

// TestBackendTypeToKeyIDString tests conversion from BackendType to Key ID backend string.
func TestBackendTypeToKeyIDString(t *testing.T) {
	tests := []struct {
		name            string
		backendType     types.BackendType
		expectedBackend string
	}{
		{
			name:            "BackendTypeSoftware to software",
			backendType:     backend.BackendTypeSoftware,
			expectedBackend: "software",
		},
		{
			name:            "BackendTypePKCS11 to pkcs11",
			backendType:     backend.BackendTypePKCS11,
			expectedBackend: "pkcs11",
		},
		{
			name:            "BackendTypeTPM2 to tpm2",
			backendType:     backend.BackendTypeTPM2,
			expectedBackend: "tpm2",
		},
		{
			name:            "BackendTypeAWSKMS to awskms",
			backendType:     backend.BackendTypeAWSKMS,
			expectedBackend: "awskms",
		},
		{
			name:            "BackendTypeGCPKMS to gcpkms",
			backendType:     backend.BackendTypeGCPKMS,
			expectedBackend: "gcpkms",
		},
		{
			name:            "BackendTypeAzureKV to azurekv",
			backendType:     backend.BackendTypeAzureKV,
			expectedBackend: "azurekv",
		},
		{
			name:            "BackendTypeVault to vault",
			backendType:     backend.BackendTypeVault,
			expectedBackend: "vault",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backendStr := backendTypeToKeyIDString(tt.backendType)
			assert.Equal(t, tt.expectedBackend, backendStr)
		})
	}
}

// TestParseKeyID_RoundTrip tests round-trip conversion.
func TestParseKeyID_RoundTrip(t *testing.T) {
	testCases := []struct {
		backend string
		keyType string
		algo    string
		keyname string
	}{
		{"software", "signing", "rsa", "my-key"},
		{"pkcs11", "signing", "ecdsa-p256", "hsm-signing-key"},
		{"tpm2", "attestation", "rsa", "attestation"},
		{"awskms", "encryption", "aes256-gcm", "prod-key"},
		{"software", "secret", "aes192-gcm", "dev-secret"},
		{"software", "tls", "ed25519", "server-key"},
	}

	for _, tc := range testCases {
		t.Run(tc.backend+"_"+tc.keyType+"_"+tc.algo+"_"+tc.keyname, func(t *testing.T) {
			// Create Key ID
			keyID, err := NewKeyID(tc.backend, tc.keyType, tc.algo, tc.keyname)
			require.NoError(t, err)

			// Parse it back
			parsedBackend, parsedKeyType, parsedAlgo, parsedKeyname, err := ParseKeyID(keyID.String())
			require.NoError(t, err)

			// Verify round-trip
			assert.Equal(t, tc.backend, parsedBackend)
			assert.Equal(t, tc.keyType, parsedKeyType)
			assert.Equal(t, tc.algo, parsedAlgo)
			assert.Equal(t, tc.keyname, parsedKeyname)
		})
	}
}

// TestValidateBackend tests the validateBackend helper function.
func TestValidateBackend(t *testing.T) {
	validBackends := []string{
		"software", "pkcs11", "tpm2",
		"awskms", "gcpkms", "azurekv", "vault",
	}

	for _, backend := range validBackends {
		t.Run("valid_"+backend, func(t *testing.T) {
			err := validateBackend(backend)
			assert.NoError(t, err, "Backend should be valid: %s", backend)
		})
	}

	invalidBackends := []string{
		"unknown", "pkcs8", "pkcs-8", "PKCS8", "symmetric", "tpm", "aws", "",
	}

	for _, backend := range invalidBackends {
		t.Run("invalid_"+backend, func(t *testing.T) {
			err := validateBackend(backend)
			assert.Error(t, err, "Backend should be invalid: %s", backend)
		})
	}
}

// TestValidateKeyName tests the validateKeyName helper function.
func TestValidateKeyName(t *testing.T) {
	validKeynames := []string{
		"a", "my-key", "my_key", "key123", "KEY-2024-v1",
		"test_key_123", strings.Repeat("a", 255),
	}

	for _, keyname := range validKeynames {
		t.Run("valid_"+keyname[:min(len(keyname), 20)], func(t *testing.T) {
			err := validateKeyName(keyname)
			assert.NoError(t, err, "Keyname should be valid: %s", keyname)
		})
	}

	invalidKeynames := []string{
		"", " ", "key with spaces", "key@test", "key/path",
		"key\\path", "../etc/passwd", "key:name",
		strings.Repeat("a", 256),
	}

	for _, keyname := range invalidKeynames {
		t.Run("invalid_"+keyname[:min(len(keyname), 20)], func(t *testing.T) {
			err := validateKeyName(keyname)
			assert.Error(t, err, "Keyname should be invalid: %s", keyname)
		})
	}
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestKeyTypeToEnum tests conversion from string to KeyType enum.
func TestKeyTypeToEnum(t *testing.T) {
	tests := []struct {
		name     string
		keyType  string
		expected types.KeyType
		wantErr  bool
	}{
		{"attestation", "attestation", backend.KEY_TYPE_ATTESTATION, false},
		{"ca", "ca", backend.KEY_TYPE_CA, false},
		{"encryption", "encryption", backend.KEY_TYPE_ENCRYPTION, false},
		{"endorsement", "endorsement", backend.KEY_TYPE_ENDORSEMENT, false},
		{"hmac", "hmac", backend.KEY_TYPE_HMAC, false},
		{"idevid", "idevid", backend.KEY_TYPE_IDEVID, false},
		{"secret", "secret", backend.KEY_TYPE_SECRET, false},
		{"signing", "signing", backend.KEY_TYPE_SIGNING, false},
		{"storage", "storage", backend.KEY_TYPE_STORAGE, false},
		{"tls", "tls", backend.KEY_TYPE_TLS, false},
		{"tpm", "tpm", backend.KEY_TYPE_TPM, false},
		{"SIGNING uppercase", "SIGNING", backend.KEY_TYPE_SIGNING, false},
		{"invalid type", "invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keyTypeToEnum(tt.keyType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

// TestAlgorithmToEnum tests conversion from string to Algorithm enum.
func TestAlgorithmToEnum(t *testing.T) {
	tests := []struct {
		name     string
		algo     string
		expected interface{}
		wantErr  bool
	}{
		{"rsa", "rsa", x509.RSA, false},
		{"ecdsa", "ecdsa", x509.ECDSA, false},
		{"ecdsa-p256", "ecdsa-p256", x509.ECDSA, false},
		{"ecdsa-p384", "ecdsa-p384", x509.ECDSA, false},
		{"ecdsa-p521", "ecdsa-p521", x509.ECDSA, false},
		{"p256", "p256", x509.ECDSA, false},
		{"ed25519", "ed25519", x509.Ed25519, false},
		{"aes128-gcm", "aes128-gcm", types.SymmetricAES128GCM, false},
		{"aes192-gcm", "aes192-gcm", types.SymmetricAES192GCM, false},
		{"aes256-gcm", "aes256-gcm", types.SymmetricAES256GCM, false},
		{"aes256", "aes256", types.SymmetricAES256GCM, false},
		{"RSA uppercase", "RSA", x509.RSA, false},
		{"invalid algo", "invalid", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := algorithmToEnum(tt.algo)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

// TestExtractECDSACurve tests ECDSA curve extraction.
func TestExtractECDSACurve(t *testing.T) {
	tests := []struct {
		name     string
		algo     string
		expected string
		wantErr  bool
	}{
		{"ecdsa-p256", "ecdsa-p256", "P-256", false},
		{"ecdsa-p384", "ecdsa-p384", "P-384", false},
		{"ecdsa-p521", "ecdsa-p521", "P-521", false},
		{"p256", "p256", "P-256", false},
		{"P-256", "P-256", "P-256", false},
		{"invalid curve", "ecdsa", "", true},
		{"rsa", "rsa", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractECDSACurve(tt.algo)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

// TestBackendTypeToStoreType tests backend type to store type conversion.
func TestBackendTypeToStoreType(t *testing.T) {
	tests := []struct {
		name        string
		backendType types.BackendType
		expected    types.StoreType
	}{
		{"PKCS8", backend.BackendTypeSoftware, backend.STORE_SW},
		{"Software", backend.BackendTypeSoftware, backend.STORE_SW},
		{"AES", backend.BackendTypeSymmetric, backend.STORE_SW},
		{"PKCS11", backend.BackendTypePKCS11, backend.STORE_PKCS11},
		{"TPM2", backend.BackendTypeTPM2, backend.STORE_TPM2},
		{"AWSKMS", backend.BackendTypeAWSKMS, backend.STORE_AWSKMS},
		{"GCPKMS", backend.BackendTypeGCPKMS, backend.STORE_GCPKMS},
		{"AzureKV", backend.BackendTypeAzureKV, backend.STORE_AZUREKV},
		{"Vault", backend.BackendTypeVault, backend.STORE_VAULT},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := backendTypeToStoreType(tt.backendType)
			assert.Equal(t, tt.expected, got)
		})
	}
}
