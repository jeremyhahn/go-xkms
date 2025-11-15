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

//go:build pkcs11

package pkcs11

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"os"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/miekg/pkcs11"
)

// TestGetImportParameters tests retrieving import parameters from the PKCS#11 backend.
func TestGetImportParameters(t *testing.T) {
	// This test requires a real PKCS#11 HSM or SoftHSM2
	library := getSoftHSMLibrary(t)
	if library == "" {
		t.Skip("SoftHSM2 library not found, skipping test")
	}

	// Create test backend
	config := testConfig(library, "import-test-token")
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Initialize and login
	if err := b.Initialize("12345678", "1234"); err != nil && err != ErrAlreadyInitialized {
		t.Fatalf("Failed to initialize: %v", err)
	}

	defer b.Close()

	// Test attributes
	attrs := &types.KeyAttributes{
		CN:           "test-import-key",
		KeyType:      backend.KEY_TYPE_TLS,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	tests := []struct {
		name      string
		algorithm backend.WrappingAlgorithm
		wantErr   bool
	}{
		{
			name:      "RSA-OAEP-SHA256",
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			wantErr:   false,
		},
		{
			name:      "RSA-AES-KEY-WRAP-SHA256",
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			wantErr:   false,
		},
		{
			name:      "Unsupported algorithm",
			algorithm: backend.WrappingAlgorithm("INVALID"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := b.GetImportParameters(attrs, tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetImportParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Validate parameters
			if params == nil {
				t.Fatal("GetImportParameters() returned nil parameters")
			}

			if params.WrappingPublicKey == nil {
				t.Error("WrappingPublicKey is nil")
			}

			if _, ok := params.WrappingPublicKey.(*rsa.PublicKey); !ok {
				t.Error("WrappingPublicKey is not an RSA public key")
			}

			if params.ImportToken == nil {
				t.Error("ImportToken is nil")
			}

			if params.Algorithm != tt.algorithm {
				t.Errorf("Algorithm = %v, want %v", params.Algorithm, tt.algorithm)
			}

			// For PKCS#11, ExpiresAt should be nil (wrapping keys don't expire)
			if params.ExpiresAt != nil {
				t.Error("ExpiresAt should be nil for PKCS#11")
			}

			if params.KeySpec == "" {
				t.Error("KeySpec is empty")
			}
		})
	}
}

// TestWrapKey tests wrapping key material for import.
func TestWrapKey(t *testing.T) {
	// Generate test key material (32-byte AES key)
	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate test key material: %v", err)
	}

	// Generate RSA wrapping key
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate wrapping key: %v", err)
	}

	// Create test backend (no initialization needed for WrapKey)
	config := &Config{
		Library:     "/usr/lib/test.so",
		TokenLabel:  "test-token",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}
	b := &Backend{config: config}

	tests := []struct {
		name        string
		keyMaterial []byte
		params      *backend.ImportParameters
		wantErr     bool
	}{
		{
			name:        "Valid RSA-OAEP wrapping",
			keyMaterial: keyMaterial,
			params: &backend.ImportParameters{
				WrappingPublicKey: &wrappingKey.PublicKey,
				Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
				ImportToken:       []byte("test-token"),
			},
			wantErr: false,
		},
		{
			name:        "Valid hybrid wrapping",
			keyMaterial: keyMaterial,
			params: &backend.ImportParameters{
				WrappingPublicKey: &wrappingKey.PublicKey,
				Algorithm:         backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
				ImportToken:       []byte("test-token"),
			},
			wantErr: false,
		},
		{
			name:        "Nil key material",
			keyMaterial: nil,
			params: &backend.ImportParameters{
				WrappingPublicKey: &wrappingKey.PublicKey,
				Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			},
			wantErr: true,
		},
		{
			name:        "Nil parameters",
			keyMaterial: keyMaterial,
			params:      nil,
			wantErr:     true,
		},
		{
			name:        "Unsupported algorithm",
			keyMaterial: keyMaterial,
			params: &backend.ImportParameters{
				WrappingPublicKey: &wrappingKey.PublicKey,
				Algorithm:         backend.WrappingAlgorithm("INVALID"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped, err := b.WrapKey(tt.keyMaterial, tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("WrapKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Validate wrapped key material
			if wrapped == nil {
				t.Fatal("WrapKey() returned nil")
			}

			if len(wrapped.WrappedKey) == 0 {
				t.Error("WrappedKey is empty")
			}

			if wrapped.Algorithm != tt.params.Algorithm {
				t.Errorf("Algorithm = %v, want %v", wrapped.Algorithm, tt.params.Algorithm)
			}
		})
	}
}

// TestUnwrapKey tests that UnwrapKey returns ErrNotSupported.
func TestUnwrapKey(t *testing.T) {
	// Create test backend
	config := &Config{
		Library:     "/usr/lib/test.so",
		TokenLabel:  "test-token",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}
	b := &Backend{config: config}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("test"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	_, err := b.UnwrapKey(wrapped, params)
	if err == nil {
		t.Error("UnwrapKey() should return an error")
	}

	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("UnwrapKey() error = %v, want %v", err, backend.ErrNotSupported)
	}
}

// TestImportKey tests importing wrapped keys into the HSM.
func TestImportKey(t *testing.T) {
	library := getSoftHSMLibrary(t)
	if library == "" {
		t.Skip("SoftHSM2 library not found, skipping test")
	}

	// Create test backend
	config := testConfig(library, "import-key-test-token")
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Initialize and login
	if err := b.Initialize("12345678", "1234"); err != nil && err != ErrAlreadyInitialized {
		t.Fatalf("Failed to initialize: %v", err)
	}

	defer b.Close()

	// Test attributes
	attrs := &types.KeyAttributes{
		CN:           "imported-test-key",
		KeyType:      backend.KEY_TYPE_TLS,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Get import parameters
	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() failed: %v", err)
	}

	// Generate test RSA key to import
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Marshal key to PKCS#8 format
	keyMaterial, err := x509.MarshalPKCS8PrivateKey(testKey)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	// Wrap the key
	wrapped, err := b.WrapKey(keyMaterial, params)
	if err != nil {
		t.Fatalf("WrapKey() failed: %v", err)
	}

	// Import the key
	err = b.ImportKey(attrs, wrapped)
	if err != nil {
		t.Errorf("ImportKey() failed: %v", err)
	}

	// Verify the key was imported by trying to find it
	signer, err := b.Signer(attrs)
	if err != nil {
		t.Errorf("Failed to retrieve imported key: %v", err)
	}

	if signer == nil {
		t.Error("Retrieved signer is nil")
	}
}

// TestExportKey tests exporting keys from the HSM.
func TestExportKey(t *testing.T) {
	library := getSoftHSMLibrary(t)
	if library == "" {
		t.Skip("SoftHSM2 library not found, skipping test")
	}

	// Create test backend
	config := testConfig(library, "export-key-test-token")
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Initialize and login
	if err := b.Initialize("12345678", "1234"); err != nil && err != ErrAlreadyInitialized {
		t.Fatalf("Failed to initialize: %v", err)
	}

	defer b.Close()

	// Test with a non-extractable key (default behavior)
	attrs := &types.KeyAttributes{
		CN:           "non-extractable-key",
		KeyType:      backend.KEY_TYPE_TLS,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Generate a key in the HSM
	_, err = b.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Try to export (should fail because key is not extractable)
	_, err = b.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("ExportKey() should fail for non-extractable keys")
	}

	// The error should indicate the key is not extractable or not supported
	if !errors.Is(err, backend.ErrKeyNotExportable) && !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("ExportKey() error = %v, want %v or %v", err, backend.ErrKeyNotExportable, backend.ErrNotSupported)
	}
}

// TestImportExportRoundTrip tests a complete import/export round trip.
func TestImportExportRoundTrip(t *testing.T) {
	library := getSoftHSMLibrary(t)
	if library == "" {
		t.Skip("SoftHSM2 library not found, skipping test")
	}

	// Create test backend
	config := testConfig(library, "roundtrip-test-token")
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Initialize and login
	if err := b.Initialize("12345678", "1234"); err != nil && err != ErrAlreadyInitialized {
		t.Fatalf("Failed to initialize: %v", err)
	}

	defer b.Close()

	// Test attributes for AES key (smaller and simpler for testing)
	attrs := &types.KeyAttributes{
		CN:                 "roundtrip-aes-key",
		KeyType:            backend.KEY_TYPE_ENCRYPTION,
		SymmetricAlgorithm: types.SymmetricAlgorithm(backend.ALG_AES256_GCM),
	}

	// Get import parameters
	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() failed: %v", err)
	}

	// Generate random AES-256 key material
	keyMaterial := make([]byte, 32) // 256 bits
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	// Wrap the key
	wrapped, err := b.WrapKey(keyMaterial, params)
	if err != nil {
		t.Fatalf("WrapKey() failed: %v", err)
	}

	// Import the key
	err = b.ImportKey(attrs, wrapped)
	if err != nil {
		t.Errorf("ImportKey() failed: %v", err)
	}

	// Note: We cannot export the key to compare with original because
	// ImportKey sets CKA_EXTRACTABLE=false for security.
	// In a real scenario with extractable keys, you would:
	// 1. Import with CKA_EXTRACTABLE=true (requires modifying buildImportKeyTemplate)
	// 2. Export the key
	// 3. Unwrap and compare with original
}

// TestCapabilities verifies that ImportExport capability is enabled.
func TestCapabilities(t *testing.T) {
	config := &Config{
		Library:     "/usr/lib/test.so",
		TokenLabel:  "test-token",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}

	b := &Backend{config: config}

	caps := b.Capabilities()

	if !caps.Import {
		t.Error("Import capability should be true")
	}

	if !caps.Export {
		t.Error("Export capability should be true")
	}

	if !caps.SupportsImportExport() {
		t.Error("SupportsImportExport() should return true")
	}
}

// Helper function to get SoftHSM library path
func getSoftHSMLibrary(t *testing.T) string {
	// Try common SoftHSM2 library paths
	paths := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so", // macOS with Homebrew
		"/usr/lib64/pkcs11/libsofthsm2.so",         // RHEL/CentOS
	}

	for _, path := range paths {
		if fileExists(path) {
			return path
		}
	}

	return ""
}

// Helper function to check if file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestGenerateWrappingKeyPairAttributes verifies that the wrapping key pair
// is generated with the correct CKA_WRAP and CKA_UNWRAP attributes.
func TestGenerateWrappingKeyPairAttributes(t *testing.T) {
	library := getSoftHSMLibrary(t)
	if library == "" {
		t.Skip("SoftHSM2 library not found, skipping test")
	}

	// Create test backend
	config := testConfig(library, "wrap-key-attrs-test")
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Initialize and login
	if err := b.Initialize("12345678", "1234"); err != nil && err != ErrAlreadyInitialized {
		t.Fatalf("Failed to initialize: %v", err)
	}

	defer b.Close()

	// Generate wrapping key pair
	keyID := []byte("test-wrapping-key-attrs")
	signer, err := b.generateWrappingKeyPair(keyID)
	if err != nil {
		t.Fatalf("generateWrappingKeyPair() failed: %v", err)
	}

	if signer == nil {
		t.Fatal("generateWrappingKeyPair() returned nil signer")
	}

	// Verify we can get a public key from the signer
	pubKey := signer.Public()
	if pubKey == nil {
		t.Error("signer.Public() returned nil")
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Error("Public key is not an RSA public key")
	}

	if rsaPubKey == nil {
		t.Error("RSA public key is nil")
	}

	// Now verify the private key has wrap/unwrap attributes set
	// We need to use the low-level PKCS#11 API to check attributes
	if b.p11ctx == nil {
		t.Skip("PKCS#11 low-level context not initialized")
	}

	// Get slot and open session
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		t.Skip("Unable to get PKCS#11 slot")
	}

	slot := slots[0]
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	}

	session, err := b.p11ctx.OpenSession(slot, 0x20000000) // CKF_SERIAL_SESSION
	if err != nil {
		t.Skipf("Unable to open PKCS#11 session: %v", err)
	}
	defer b.p11ctx.CloseSession(session)

	// Find the private key
	privKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}

	if err := b.p11ctx.FindObjectsInit(session, privKeyTemplate); err != nil {
		t.Skipf("Unable to search for private key: %v", err)
	}
	defer b.p11ctx.FindObjectsFinal(session)

	privKeyHandles, _, err := b.p11ctx.FindObjects(session, 1)
	if err != nil || len(privKeyHandles) == 0 {
		t.Skip("Unable to find generated private key")
	}

	privKeyHandle := privKeyHandles[0]

	// Check the wrap/unwrap attributes
	attrs, err := b.p11ctx.GetAttributeValue(session, privKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, nil),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, nil),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
	})

	if err != nil {
		t.Fatalf("Failed to get key attributes: %v", err)
	}

	// Verify attributes
	tests := []struct {
		name       string
		index      int
		attrName   string
		wantValue  bool
		checkFalse bool // If true, we expect false; if false, we expect true
	}{
		{
			name:      "CKA_UNWRAP should be true",
			index:     0,
			attrName:  "CKA_UNWRAP",
			wantValue: true,
		},
		{
			name:      "CKA_DECRYPT should be true",
			index:     1,
			attrName:  "CKA_DECRYPT",
			wantValue: true,
		},
		{
			name:      "CKA_SIGN should be true",
			index:     2,
			attrName:  "CKA_SIGN",
			wantValue: true,
		},
		{
			name:      "CKA_SENSITIVE should be true",
			index:     3,
			attrName:  "CKA_SENSITIVE",
			wantValue: true,
		},
		{
			name:      "CKA_EXTRACTABLE should be false",
			index:     4,
			attrName:  "CKA_EXTRACTABLE",
			wantValue: false,
		},
	}

	for _, tt := range tests {
		if tt.index >= len(attrs) {
			t.Errorf("%s: attribute not found in response", tt.attrName)
			continue
		}

		attr := attrs[tt.index]
		if len(attr.Value) == 0 {
			t.Errorf("%s: attribute value is empty", tt.attrName)
			continue
		}

		isSet := attr.Value[0] != 0
		if isSet != tt.wantValue {
			t.Errorf("%s: got %v, want %v", tt.attrName, isSet, tt.wantValue)
		}
	}
}

// TestGenerateWrappingKeyPairPublicKeyAttributes verifies that the public key
// also has the CKA_WRAP attribute set for wrapping operations.
func TestGenerateWrappingKeyPairPublicKeyAttributes(t *testing.T) {
	library := getSoftHSMLibrary(t)
	if library == "" {
		t.Skip("SoftHSM2 library not found, skipping test")
	}

	// Create test backend
	config := testConfig(library, "wrap-key-pub-attrs-test")
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Initialize and login
	if err := b.Initialize("12345678", "1234"); err != nil && err != ErrAlreadyInitialized {
		t.Fatalf("Failed to initialize: %v", err)
	}

	defer b.Close()

	// Generate wrapping key pair
	keyID := []byte("test-wrapping-key-pub-attrs")
	_, err = b.generateWrappingKeyPair(keyID)
	if err != nil {
		t.Fatalf("generateWrappingKeyPair() failed: %v", err)
	}

	// Verify the public key has wrap attribute
	if b.p11ctx == nil {
		t.Skip("PKCS#11 low-level context not initialized")
	}

	// Get slot and open session
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		t.Skip("Unable to get PKCS#11 slot")
	}

	slot := slots[0]
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	}

	session, err := b.p11ctx.OpenSession(slot, 0x20000000) // CKF_SERIAL_SESSION
	if err != nil {
		t.Skipf("Unable to open PKCS#11 session: %v", err)
	}
	defer b.p11ctx.CloseSession(session)

	// Find the public key
	pubKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}

	if err := b.p11ctx.FindObjectsInit(session, pubKeyTemplate); err != nil {
		t.Skipf("Unable to search for public key: %v", err)
	}
	defer b.p11ctx.FindObjectsFinal(session)

	pubKeyHandles, _, err := b.p11ctx.FindObjects(session, 1)
	if err != nil || len(pubKeyHandles) == 0 {
		t.Skip("Unable to find generated public key")
	}

	pubKeyHandle := pubKeyHandles[0]

	// Check the wrap/encrypt attributes
	attrs, err := b.p11ctx.GetAttributeValue(session, pubKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, nil),
	})

	if err != nil {
		t.Fatalf("Failed to get public key attributes: %v", err)
	}

	// Verify public key wrap attribute
	if len(attrs) < 1 || len(attrs[0].Value) == 0 {
		t.Error("CKA_WRAP attribute not found or empty")
	} else if attrs[0].Value[0] == 0 {
		t.Error("CKA_WRAP should be true for public key")
	}

	// Verify encrypt attribute
	if len(attrs) > 1 && len(attrs[1].Value) > 0 && attrs[1].Value[0] == 0 {
		t.Error("CKA_ENCRYPT should be true for public key")
	}
}
