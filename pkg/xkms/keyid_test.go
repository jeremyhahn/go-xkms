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
	"crypto/elliptic"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ParseKeyID tests ---

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
			name:            "pkcs11 Ed25519 attestation key",
			keyID:           "pkcs11:attestation:ed25519:device-attestation",
			expectedBackend: "pkcs11",
			expectedKeyType: "attestation",
			expectedAlgo:    "ed25519",
			expectedKeyname: "device-attestation",
		},
		{
			name:            "tpm2 encryption AES key",
			keyID:           "tpm2:encryption:aes256-gcm:data-key",
			expectedBackend: "tpm2",
			expectedKeyType: "encryption",
			expectedAlgo:    "aes256-gcm",
			expectedKeyname: "data-key",
		},
		{
			name:            "shorthand key (no colons)",
			keyID:           "my-simple-key",
			expectedBackend: "",
			expectedKeyType: "",
			expectedAlgo:    "",
			expectedKeyname: "my-simple-key",
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
			name:            "algo only",
			keyID:           "::rsa:my-key",
			expectedBackend: "",
			expectedKeyType: "",
			expectedAlgo:    "rsa",
			expectedKeyname: "my-key",
		},
		{
			name:            "all empty except keyname",
			keyID:           ":::my-key",
			expectedBackend: "",
			expectedKeyType: "",
			expectedAlgo:    "",
			expectedKeyname: "my-key",
		},
		{
			name:            "awskms backend",
			keyID:           "awskms:encryption:aes256-gcm:prod-key",
			expectedBackend: "awskms",
			expectedKeyType: "encryption",
			expectedAlgo:    "aes256-gcm",
			expectedKeyname: "prod-key",
		},
		{
			name:            "gcpkms backend",
			keyID:           "gcpkms:signing:rsa:gcp-key",
			expectedBackend: "gcpkms",
			expectedKeyType: "signing",
			expectedAlgo:    "rsa",
			expectedKeyname: "gcp-key",
		},
		{
			name:            "azurekv backend",
			keyID:           "azurekv:signing:ecdsa-p384:azure-key",
			expectedBackend: "azurekv",
			expectedKeyType: "signing",
			expectedAlgo:    "ecdsa-p384",
			expectedKeyname: "azure-key",
		},
		{
			name:            "vault backend",
			keyID:           "vault:signing:ed25519:vault-key",
			expectedBackend: "vault",
			expectedKeyType: "signing",
			expectedAlgo:    "ed25519",
			expectedKeyname: "vault-key",
		},
		{
			name:            "quantum backend",
			keyID:           "quantum:signing:ml-dsa-65:pq-key",
			expectedBackend: "quantum",
			expectedKeyType: "signing",
			expectedAlgo:    "ml-dsa-65",
			expectedKeyname: "pq-key",
		},
		{
			name:            "threshold backend",
			keyID:           "threshold:signing:frost-ed25519:threshold-key",
			expectedBackend: "threshold",
			expectedKeyType: "signing",
			expectedAlgo:    "frost-ed25519",
			expectedKeyname: "threshold-key",
		},
		{
			name:            "frost backend",
			keyID:           "frost:signing:frost-ristretto255:frost-key",
			expectedBackend: "frost",
			expectedKeyType: "signing",
			expectedAlgo:    "frost-ristretto255",
			expectedKeyname: "frost-key",
		},
		{
			name:            "case insensitive backend",
			keyID:           "SOFTWARE:SIGNING:RSA:my-key",
			expectedBackend: "software",
			expectedKeyType: "signing",
			expectedAlgo:    "rsa",
			expectedKeyname: "my-key",
		},
		{
			name:            "keyname with dots",
			keyID:           "software:signing:rsa:my.key.name",
			expectedBackend: "software",
			expectedKeyType: "signing",
			expectedAlgo:    "rsa",
			expectedKeyname: "my.key.name",
		},
		{
			name:            "keyname with underscores",
			keyID:           "software:signing:rsa:my_key_name",
			expectedBackend: "software",
			expectedKeyType: "signing",
			expectedAlgo:    "rsa",
			expectedKeyname: "my_key_name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, keyType, algo, keyname, err := ParseKeyID(tt.keyID)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedBackend, backend)
			assert.Equal(t, tt.expectedKeyType, keyType)
			assert.Equal(t, tt.expectedAlgo, algo)
			assert.Equal(t, tt.expectedKeyname, keyname)
		})
	}
}

func TestParseKeyID_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		keyID string
	}{
		{"empty string", ""},
		{"too many colons", "a:b:c:d:e"},
		{"only two colons", "a:b:c"},
		{"empty keyname with colons", "software:signing:rsa:"},
		{"invalid backend", "badbackend:signing:rsa:my-key"},
		{"invalid key type", "software:badtype:rsa:my-key"},
		{"invalid algorithm", "software:signing:badalgo:my-key"},
		{"keyname with slash", "software:signing:rsa:my/key"},
		{"keyname with path traversal", "software:signing:rsa:../my-key"},
		{"keyname with backslash", "software:signing:rsa:my\\key"},
		{"keyname with spaces", "software:signing:rsa:my key"},
		{"keyname with special chars", "software:signing:rsa:my@key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := ParseKeyID(tt.keyID)
			assert.Error(t, err)
		})
	}
}

func TestParseKeyID_TooLong(t *testing.T) {
	// Create a key ID that exceeds max length
	longKeyID := strings.Repeat("a", maxKeyIDLength+1)
	_, _, _, _, err := ParseKeyID(longKeyID)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyIDTooLong)
}

// --- NewKeyID tests ---

func TestNewKeyID_Full(t *testing.T) {
	keyID, err := NewKeyID("software", "signing", "rsa", "my-key")
	require.NoError(t, err)
	assert.Equal(t, KeyID("software:signing:rsa:my-key"), keyID)
}

func TestNewKeyID_BackendOnly(t *testing.T) {
	keyID, err := NewKeyID("pkcs11", "", "", "my-key")
	require.NoError(t, err)
	assert.Equal(t, KeyID("pkcs11:::my-key"), keyID)
}

func TestNewKeyID_Empty(t *testing.T) {
	keyID, err := NewKeyID("", "", "", "my-key")
	require.NoError(t, err)
	assert.Equal(t, KeyID(":::my-key"), keyID)
}

func TestNewKeyID_InvalidKeyname(t *testing.T) {
	_, err := NewKeyID("software", "signing", "rsa", "")
	require.Error(t, err)
}

func TestNewKeyID_InvalidBackend(t *testing.T) {
	_, err := NewKeyID("badbackend", "signing", "rsa", "my-key")
	require.Error(t, err)
}

func TestNewKeyID_InvalidKeyType(t *testing.T) {
	_, err := NewKeyID("software", "badtype", "rsa", "my-key")
	require.Error(t, err)
}

func TestNewKeyID_InvalidAlgorithm(t *testing.T) {
	_, err := NewKeyID("software", "signing", "badalgo", "my-key")
	require.Error(t, err)
}

func TestNewKeyID_KeynameTooLong(t *testing.T) {
	longName := strings.Repeat("a", maxKeyNameLength+1)
	_, err := NewKeyID("software", "signing", "rsa", longName)
	require.Error(t, err)
}

func TestNewKeyID_KeynamePathTraversal(t *testing.T) {
	_, err := NewKeyID("software", "signing", "rsa", "../evil")
	require.Error(t, err)
}

// --- ValidateKeyID tests ---

func TestValidateKeyID_Valid(t *testing.T) {
	err := ValidateKeyID("software:signing:rsa:my-key")
	assert.NoError(t, err)
}

func TestValidateKeyID_InvalidFormat(t *testing.T) {
	err := ValidateKeyID("")
	assert.Error(t, err)
}

func TestValidateKeyID_Shorthand(t *testing.T) {
	err := ValidateKeyID("my-key")
	assert.NoError(t, err)
}

// --- KeyID.String() ---

func TestKeyID_String(t *testing.T) {
	kid := KeyID("software:signing:rsa:my-key")
	assert.Equal(t, "software:signing:rsa:my-key", kid.String())
}

// --- keyIDToBackendType tests ---

func TestKeyIDToBackendType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected types.BackendType
	}{
		{"software", "software", types.BackendTypeSoftware},
		{"sw alias", "sw", types.BackendTypeSoftware},
		{"pkcs11", "pkcs11", types.BackendTypePKCS11},
		{"tpm2", "tpm2", types.BackendTypeTPM2},
		{"awskms", "awskms", types.BackendTypeAWSKMS},
		{"gcpkms", "gcpkms", types.BackendTypeGCPKMS},
		{"azurekv", "azurekv", types.BackendTypeAzureKV},
		{"vault", "vault", types.BackendTypeVault},
		{"quantum", "quantum", types.BackendTypeQuantum},
		{"threshold", "threshold", types.BackendTypeThreshold},
		{"frost", "frost", types.BackendTypeFrost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keyIDToBackendType(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestKeyIDToBackendType_Invalid(t *testing.T) {
	_, err := keyIDToBackendType("invalid")
	require.Error(t, err)
}

func TestKeyIDToBackendType_CaseInsensitive(t *testing.T) {
	got, err := keyIDToBackendType("SOFTWARE")
	require.NoError(t, err)
	assert.Equal(t, types.BackendTypeSoftware, got)
}

// --- backendTypeToKeyIDString tests ---

func TestBackendTypeToKeyIDString(t *testing.T) {
	got := backendTypeToKeyIDString(types.BackendTypeSoftware)
	assert.Equal(t, string(types.BackendTypeSoftware), got)
}

// --- keyTypeToEnum tests ---

func TestKeyTypeToEnum(t *testing.T) {
	tests := []struct {
		input    string
		expected types.KeyType
	}{
		{"attestation", types.KeyTypeAttestation},
		{"ca", types.KeyTypeCA},
		{"encryption", types.KeyTypeEncryption},
		{"endorsement", types.KeyTypeEndorsement},
		{"hmac", types.KeyTypeHMAC},
		{"idevid", types.KeyTypeIDevID},
		{"ldevid", types.KeyTypeLDevID},
		{"secret", types.KeyTypeSecret},
		{"signing", types.KeyTypeSigning},
		{"storage", types.KeyTypeStorage},
		{"tls", types.KeyTypeTLS},
		{"tpm", types.KeyTypeTPM},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := keyTypeToEnum(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestKeyTypeToEnum_Invalid(t *testing.T) {
	_, err := keyTypeToEnum("invalid")
	require.Error(t, err)
}

func TestKeyTypeToEnum_CaseInsensitive(t *testing.T) {
	got, err := keyTypeToEnum("SIGNING")
	require.NoError(t, err)
	assert.Equal(t, types.KeyTypeSigning, got)
}

// --- algorithmToEnum tests ---

func TestAlgorithmToEnum_RSA(t *testing.T) {
	result, err := algorithmToEnum("rsa")
	require.NoError(t, err)
	assert.Equal(t, x509.RSA, result)
}

func TestAlgorithmToEnum_ECDSA(t *testing.T) {
	tests := []string{"ecdsa", "ecdsa-p256", "ecdsa-p-256", "p256", "p-256",
		"ecdsa-p384", "ecdsa-p-384", "p384", "p-384",
		"ecdsa-p521", "ecdsa-p-521", "p521", "p-521"}
	for _, algo := range tests {
		t.Run(algo, func(t *testing.T) {
			result, err := algorithmToEnum(algo)
			require.NoError(t, err)
			assert.Equal(t, x509.ECDSA, result)
		})
	}
}

func TestAlgorithmToEnum_Ed25519(t *testing.T) {
	result, err := algorithmToEnum("ed25519")
	require.NoError(t, err)
	assert.Equal(t, x509.Ed25519, result)
}

func TestAlgorithmToEnum_AES(t *testing.T) {
	tests := []struct {
		algo     string
		expected types.SymmetricAlgorithm
	}{
		{"aes128-gcm", types.SymmetricAES128GCM},
		{"aes128", types.SymmetricAES128GCM},
		{"aes192-gcm", types.SymmetricAES192GCM},
		{"aes192", types.SymmetricAES192GCM},
		{"aes256-gcm", types.SymmetricAES256GCM},
		{"aes256", types.SymmetricAES256GCM},
	}
	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			result, err := algorithmToEnum(tt.algo)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAlgorithmToEnum_ChaCha20Poly1305(t *testing.T) {
	result, err := algorithmToEnum("chacha20-poly1305")
	require.NoError(t, err)
	assert.Equal(t, types.SymmetricChaCha20Poly1305, result)
}

func TestAlgorithmToEnum_ChaCha20Alias(t *testing.T) {
	result, err := algorithmToEnum("chacha20")
	require.NoError(t, err)
	assert.Equal(t, types.SymmetricChaCha20Poly1305, result)
}

func TestAlgorithmToEnum_XChaCha20Poly1305(t *testing.T) {
	result, err := algorithmToEnum("xchacha20-poly1305")
	require.NoError(t, err)
	assert.Equal(t, types.SymmetricXChaCha20Poly1305, result)
}

func TestAlgorithmToEnum_XChaCha20Alias(t *testing.T) {
	result, err := algorithmToEnum("xchacha20")
	require.NoError(t, err)
	assert.Equal(t, types.SymmetricXChaCha20Poly1305, result)
}

func TestAlgorithmToEnum_Invalid(t *testing.T) {
	_, err := algorithmToEnum("invalid")
	require.Error(t, err)
}

func TestAlgorithmToEnum_CaseInsensitive(t *testing.T) {
	result, err := algorithmToEnum("RSA")
	require.NoError(t, err)
	assert.Equal(t, x509.RSA, result)
}

// --- extractECDSACurve tests ---

func TestExtractECDSACurve(t *testing.T) {
	tests := []struct {
		algo     string
		expected string
	}{
		{"ecdsa-p256", "P-256"},
		{"ecdsa-p-256", "P-256"},
		{"p256", "P-256"},
		{"p-256", "P-256"},
		{"ecdsa-p384", "P-384"},
		{"ecdsa-p-384", "P-384"},
		{"p384", "P-384"},
		{"p-384", "P-384"},
		{"ecdsa-p521", "P-521"},
		{"ecdsa-p-521", "P-521"},
		{"p521", "P-521"},
		{"p-521", "P-521"},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			curve, err := extractECDSACurve(tt.algo)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, curve)
		})
	}
}

func TestExtractECDSACurve_Unsupported(t *testing.T) {
	_, err := extractECDSACurve("ecdsa")
	require.Error(t, err)
}

// --- backendTypeToStoreType tests ---

func TestBackendTypeToStoreType(t *testing.T) {
	tests := []struct {
		name        string
		backendType types.BackendType
		expected    types.StoreType
	}{
		{"Software", types.BackendTypeSoftware, types.StoreSoftware},
		{"Symmetric", types.BackendTypeSymmetric, types.StoreSoftware},
		{"PKCS11", types.BackendTypePKCS11, types.StorePKCS11},
		{"TPM2", types.BackendTypeTPM2, types.StoreTPM2},
		{"AWSKMS", types.BackendTypeAWSKMS, types.StoreAWSKMS},
		{"GCPKMS", types.BackendTypeGCPKMS, types.StoreGCPKMS},
		{"AzureKV", types.BackendTypeAzureKV, types.StoreAzureKV},
		{"Vault", types.BackendTypeVault, types.StoreVault},
		{"Quantum", types.BackendTypeQuantum, types.StoreQuantum},
		{"Threshold", types.BackendTypeThreshold, types.StoreThreshold},
		{"Frost", types.BackendTypeFrost, types.StoreFrost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := backendTypeToStoreType(tt.backendType)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestBackendTypeToStoreType_UnknownType(t *testing.T) {
	// An unknown BackendType should fall back to StoreSoftware.
	got := backendTypeToStoreType(types.BackendType("unknown-backend-type"))
	assert.Equal(t, types.StoreSoftware, got)
}

// --- algorithmToECCAttributes tests ---

func TestAlgorithmToECCAttributes_DefaultP256(t *testing.T) {
	attrs := algorithmToECCAttributes("ecdsa")
	assert.Equal(t, elliptic.P256(), attrs.Curve)
}

func TestAlgorithmToECCAttributes_P256(t *testing.T) {
	attrs := algorithmToECCAttributes("ecdsa-p256")
	assert.Equal(t, elliptic.P256(), attrs.Curve)
}

func TestAlgorithmToECCAttributes_P384(t *testing.T) {
	attrs := algorithmToECCAttributes("ecdsa-p384")
	assert.Equal(t, elliptic.P384(), attrs.Curve)
}

func TestAlgorithmToECCAttributes_P521(t *testing.T) {
	attrs := algorithmToECCAttributes("ecdsa-p521")
	assert.Equal(t, elliptic.P521(), attrs.Curve)
}

// --- algorithmToRSAAttributes tests ---

func TestAlgorithmToRSAAttributes(t *testing.T) {
	attrs := algorithmToRSAAttributes()
	assert.Equal(t, 2048, attrs.KeySize)
}

// --- ParseKeyIDToAttributes tests ---

func TestParseKeyIDToAttributes_Full(t *testing.T) {
	attrs, err := ParseKeyIDToAttributes("software:signing:rsa:my-key")
	require.NoError(t, err)
	assert.Equal(t, "my-key", attrs.CN)
	assert.Equal(t, types.StoreSoftware, attrs.StoreType)
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
	assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.RSAAttributes)
	assert.Equal(t, 2048, attrs.RSAAttributes.KeySize)
}

func TestParseKeyIDToAttributes_ECDSA(t *testing.T) {
	attrs, err := ParseKeyIDToAttributes("pkcs11:signing:ecdsa-p384:ec-key")
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.ECCAttributes)
	assert.Equal(t, elliptic.P384(), attrs.ECCAttributes.Curve)
}

func TestParseKeyIDToAttributes_Ed25519(t *testing.T) {
	attrs, err := ParseKeyIDToAttributes("software:signing:ed25519:ed-key")
	require.NoError(t, err)
	assert.Equal(t, x509.Ed25519, attrs.KeyAlgorithm)
}

func TestParseKeyIDToAttributes_Symmetric(t *testing.T) {
	attrs, err := ParseKeyIDToAttributes("software:encryption:aes256-gcm:sym-key")
	require.NoError(t, err)
	assert.Equal(t, types.SymmetricAES256GCM, attrs.SymmetricAlgorithm)
}

func TestParseKeyIDToAttributes_Shorthand(t *testing.T) {
	attrs, err := ParseKeyIDToAttributes("my-key")
	require.NoError(t, err)
	assert.Equal(t, "my-key", attrs.CN)
}

func TestParseKeyIDToAttributes_EmptyOptionals(t *testing.T) {
	attrs, err := ParseKeyIDToAttributes(":::my-key")
	require.NoError(t, err)
	assert.Equal(t, "my-key", attrs.CN)
}

func TestParseKeyIDToAttributes_BackendOnly(t *testing.T) {
	attrs, err := ParseKeyIDToAttributes("tpm2:::my-key")
	require.NoError(t, err)
	assert.Equal(t, types.StoreTPM2, attrs.StoreType)
}

func TestParseKeyIDToAttributes_Invalid(t *testing.T) {
	_, err := ParseKeyIDToAttributes("")
	require.Error(t, err)
}

func TestParseKeyIDToAttributes_InvalidBackend(t *testing.T) {
	_, err := ParseKeyIDToAttributes("badbackend:signing:rsa:mykey")
	require.Error(t, err)
}

func TestParseKeyIDToAttributes_InvalidKeyType(t *testing.T) {
	_, err := ParseKeyIDToAttributes("software:badtype:rsa:mykey")
	require.Error(t, err)
}

func TestParseKeyIDToAttributes_InvalidAlgo(t *testing.T) {
	_, err := ParseKeyIDToAttributes("software:signing:badalgo:mykey")
	require.Error(t, err)
}

// --- validateKeyName tests ---

func TestValidateKeyName_Valid(t *testing.T) {
	err := validateKeyName("my-key-123.test_name")
	assert.NoError(t, err)
}

func TestValidateKeyName_Empty(t *testing.T) {
	err := validateKeyName("")
	assert.Error(t, err)
}

func TestValidateKeyName_TooLong(t *testing.T) {
	longName := strings.Repeat("a", maxKeyNameLength+1)
	err := validateKeyName(longName)
	assert.Error(t, err)
}

func TestValidateKeyName_PathTraversal(t *testing.T) {
	err := validateKeyName("../evil")
	assert.Error(t, err)
}

func TestValidateKeyName_Slash(t *testing.T) {
	err := validateKeyName("my/key")
	assert.Error(t, err)
}

func TestValidateKeyName_Backslash(t *testing.T) {
	err := validateKeyName("my\\key")
	assert.Error(t, err)
}

func TestValidateKeyName_InvalidChars(t *testing.T) {
	err := validateKeyName("my@key!")
	assert.Error(t, err)
}

// --- validateBackend tests ---

func TestValidateBackend_Valid(t *testing.T) {
	for backend := range validBackends {
		err := validateBackend(backend)
		assert.NoError(t, err, "backend %s should be valid", backend)
	}
}

func TestValidateBackend_Invalid(t *testing.T) {
	err := validateBackend("nonexistent")
	assert.Error(t, err)
}

// --- validateKeyType tests ---

func TestValidateKeyType_Valid(t *testing.T) {
	validTypes := []string{
		"attestation", "ca", "encryption", "endorsement",
		"hmac", "idevid", "ldevid", "secret",
		"signing", "storage", "tls", "tpm",
	}
	for _, kt := range validTypes {
		err := validateKeyType(kt)
		assert.NoError(t, err, "key type %s should be valid", kt)
	}
}

func TestValidateKeyType_Invalid(t *testing.T) {
	err := validateKeyType("invalid")
	assert.Error(t, err)
}

// --- validateAlgorithm tests ---

func TestValidateAlgorithm_Valid(t *testing.T) {
	validAlgos := []string{
		"rsa", "ecdsa-p256", "ed25519", "aes256-gcm",
		"chacha20-poly1305", "xchacha20-poly1305",
		"ml-dsa-65", "ml-kem-768", "hmac-sha256",
		"frost-ed25519", "x25519",
	}
	for _, algo := range validAlgos {
		err := validateAlgorithm(algo)
		assert.NoError(t, err, "algorithm %s should be valid", algo)
	}
}

func TestValidateAlgorithm_Invalid(t *testing.T) {
	err := validateAlgorithm("invalid-algo")
	assert.Error(t, err)
}

// --- Various all-backend type parsing ---

func TestParseKeyID_AllBackends(t *testing.T) {
	for backend := range validBackends {
		keyID := backend + ":signing:rsa:test-key"
		b, kt, algo, kn, err := ParseKeyID(keyID)
		require.NoError(t, err, "backend %s should parse", backend)
		assert.Equal(t, backend, b)
		assert.Equal(t, "signing", kt)
		assert.Equal(t, "rsa", algo)
		assert.Equal(t, "test-key", kn)
	}
}

// --- Round-trip test ---

func TestNewKeyID_ParseKeyID_RoundTrip(t *testing.T) {
	original, err := NewKeyID("pkcs11", "signing", "ecdsa-p256", "my-key")
	require.NoError(t, err)

	backend, keyType, algo, keyname, err := ParseKeyID(string(original))
	require.NoError(t, err)
	assert.Equal(t, "pkcs11", backend)
	assert.Equal(t, "signing", keyType)
	assert.Equal(t, "ecdsa-p256", algo)
	assert.Equal(t, "my-key", keyname)
}

// --- ParseKeyIDToAttributes with ChaCha20 symmetric ---

func TestParseKeyIDToAttributes_ChaCha20(t *testing.T) {
	attrs, err := ParseKeyIDToAttributes("software:encryption:chacha20-poly1305:stream-key")
	require.NoError(t, err)
	assert.Equal(t, types.SymmetricChaCha20Poly1305, attrs.SymmetricAlgorithm)
}

func TestParseKeyIDToAttributes_XChaCha20(t *testing.T) {
	attrs, err := ParseKeyIDToAttributes("software:encryption:xchacha20-poly1305:xstream-key")
	require.NoError(t, err)
	assert.Equal(t, types.SymmetricXChaCha20Poly1305, attrs.SymmetricAlgorithm)
}

// --- ParseKeyID shorthand with invalid keyname ---

func TestParseKeyID_ShorthandInvalidChars(t *testing.T) {
	// Shorthand (no colons) with invalid characters exercises the
	// validateKeyName error branch inside the shorthand path.
	_, _, _, _, err := ParseKeyID("my@invalid!key")
	require.Error(t, err)
}

func TestParseKeyID_ShorthandPathTraversal(t *testing.T) {
	_, _, _, _, err := ParseKeyID("..evil-key")
	require.Error(t, err)
}
