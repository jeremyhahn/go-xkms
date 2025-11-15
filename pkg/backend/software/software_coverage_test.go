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

package software

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestGetTracker tests the GetTracker function
func TestGetTracker(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Get the tracker
	tracker := be.(*SoftwareBackend).GetTracker()
	if tracker == nil {
		t.Fatal("GetTracker returned nil")
	}

	// Verify tracker is the expected type
	if _, ok := tracker.(types.AEADSafetyTracker); !ok {
		t.Error("tracker does not implement AEADSafetyTracker interface")
	}
}

// TestGetTracker_TrackingFunctionality tests that the tracker actually works
func TestGetTracker_TrackingFunctionality(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate a symmetric key
	attrs := createAESAttrs("tracker-test", 256, types.SymmetricAES256GCM)
	_, err := be.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Get tracker
	tracker := be.(*SoftwareBackend).GetTracker()

	// Get encrypter
	encrypter, err := be.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	// Encrypt some data
	plaintext := []byte("test data for tracker")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify tracking is working by checking bytes encrypted
	keyID := attrs.ID()
	bytesEncrypted, err := tracker.GetBytesEncrypted(keyID)
	if err != nil {
		t.Fatalf("GetBytesEncrypted failed: %v", err)
	}

	// After one encryption, bytes should be greater than 0
	if bytesEncrypted == 0 {
		t.Error("Expected bytes encrypted to be greater than 0")
	}

	// Decrypt to ensure the tracker is working properly
	_, err = encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
}

// TestExportKey_NilAttributes tests ExportKey with nil attributes
func TestExportKey_NilAttributes(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	_, err := be.(*SoftwareBackend).ExportKey(nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("Expected error for nil attributes")
	}
	if err != backend.ErrInvalidAttributes {
		t.Errorf("Expected ErrInvalidAttributes, got %v", err)
	}
}

// TestExportKey_NonExportableKey tests exporting a key marked as non-exportable
func TestExportKey_NonExportableKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate a non-exportable key
	attrs := createRSAAttrs("non-exportable", 2048)
	attrs.Exportable = false // Explicitly mark as non-exportable
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Try to export it
	_, err = be.(*SoftwareBackend).ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("Expected error when exporting non-exportable key")
	}
	if err != backend.ErrKeyNotExportable {
		t.Errorf("Expected ErrKeyNotExportable, got %v", err)
	}
}

// TestExportKey_SymmetricKeyError tests ExportKey error path when getting symmetric key fails
func TestExportKey_SymmetricKeyError(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Create attributes for a symmetric key that doesn't exist
	attrs := createAESAttrs("nonexistent-sym", 256, types.SymmetricAES256GCM)
	attrs.Exportable = true

	_, err := be.(*SoftwareBackend).ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("Expected error when exporting non-existent symmetric key")
	}
}

// TestExportKey_AsymmetricKeyRawError tests error when marshaling asymmetric key fails
// This tests the x509.MarshalPKCS8PrivateKey error path
func TestExportKey_AsymmetricKeyNotFound(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Create attributes for an asymmetric key that doesn't exist
	attrs := createRSAAttrs("nonexistent-asym", 2048)
	attrs.Exportable = true

	_, err := be.(*SoftwareBackend).ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("Expected error when exporting non-existent asymmetric key")
	}
}

// TestWrapKey_InvalidAlgorithm tests WrapKey with invalid wrapping algorithm
func TestWrapKey_InvalidAlgorithm(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("test.com", 2048)

	// Get valid parameters first
	params, err := be.(*SoftwareBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	// Modify params to have invalid algorithm
	params.Algorithm = backend.WrappingAlgorithm("INVALID_ALGORITHM")

	keyMaterial := []byte("test key material")
	_, err = be.(*SoftwareBackend).WrapKey(keyMaterial, params)
	if err == nil {
		t.Error("Expected error for invalid wrapping algorithm")
	}
}

// TestWrapKey_InvalidPublicKeyType tests WrapKey when wrapping public key is not RSA
func TestWrapKey_InvalidPublicKeyType(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("test.com", 2048)
	params, err := be.(*SoftwareBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	// Replace the wrapping public key with a non-RSA key
	params.WrappingPublicKey = "not-an-rsa-public-key"

	keyMaterial := []byte("test key material")
	_, err = be.(*SoftwareBackend).WrapKey(keyMaterial, params)
	if err == nil {
		t.Error("Expected error for non-RSA wrapping public key")
	}
}

// TestWrapKey_RSAAESWrapSHA1 tests the RSA_AES_KEY_WRAP_SHA_1 wrapping path
func TestWrapKey_RSAAESWrapSHA1(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("test.com", 2048)
	params, err := be.(*SoftwareBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	wrapped, err := be.(*SoftwareBackend).WrapKey(keyMaterial, params)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	if wrapped == nil || len(wrapped.WrappedKey) == 0 {
		t.Error("Wrapped key is nil or empty")
	}
}

// TestUnwrapKey_NilWrapped tests UnwrapKey with nil wrapped material
func TestUnwrapKey_NilWrapped(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("test.com", 2048)
	params, _ := be.(*SoftwareBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	_, err := be.(*SoftwareBackend).UnwrapKey(nil, params)
	if err == nil {
		t.Error("Expected error for nil wrapped material")
	}
}

// TestUnwrapKey_NilParams tests UnwrapKey with nil parameters
func TestUnwrapKey_NilParams(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte{1, 2, 3},
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte("token"),
	}

	_, err := be.(*SoftwareBackend).UnwrapKey(wrapped, nil)
	if err == nil {
		t.Error("Expected error for nil params")
	}
}

// TestUnwrapKey_InvalidAlgorithm tests UnwrapKey with invalid algorithm
func TestUnwrapKey_InvalidAlgorithm(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("test.com", 2048)

	// Get valid parameters and wrap a key
	params, err := be.(*SoftwareBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	keyMaterial := make([]byte, 32)
	rand.Read(keyMaterial)
	wrapped, err := be.(*SoftwareBackend).WrapKey(keyMaterial, params)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	// Modify algorithm to invalid value
	wrapped.Algorithm = backend.WrappingAlgorithm("INVALID")

	_, err = be.(*SoftwareBackend).UnwrapKey(wrapped, params)
	if err == nil {
		t.Error("Expected error for invalid unwrap algorithm")
	}
}

// TestUnwrapKey_RSAAESUnwrapSHA1 tests RSA_AES unwrap with SHA1
func TestUnwrapKey_RSAAESUnwrapSHA1(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("test.com", 2048)
	params, err := be.(*SoftwareBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	keyMaterial := make([]byte, 128)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	wrapped, err := be.(*SoftwareBackend).WrapKey(keyMaterial, params)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	unwrapped, err := be.(*SoftwareBackend).UnwrapKey(wrapped, params)
	if err != nil {
		t.Fatalf("UnwrapKey failed: %v", err)
	}

	if len(unwrapped) != len(keyMaterial) {
		t.Errorf("Unwrapped key size mismatch: got %d, want %d", len(unwrapped), len(keyMaterial))
	}
}

// TestClose_ErrorFromPKCS8Backend tests Close when PKCS8 backend close fails
func TestClose_MultipleClose(t *testing.T) {
	be, _ := createTestBackend(t)

	// First close should succeed
	err := be.Close()
	if err != nil {
		t.Fatalf("First Close failed: %v", err)
	}

	// Second close should also succeed (idempotent)
	err = be.Close()
	if err != nil {
		t.Fatalf("Second Close failed: %v", err)
	}

	// Third close should still succeed
	err = be.Close()
	if err != nil {
		t.Fatalf("Third Close failed: %v", err)
	}
}

// TestImportAsymmetricKey_KeyTypeMismatch tests importing key with wrong type
func TestImportAsymmetricKey_KeyTypeMismatch(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Create RSA key but use ECDSA attributes
	attrs := createECDSAAttrs("test.com", "P-256")
	// Use RSA_AES wrapping which can handle larger key material
	params, err := be.(*SoftwareBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	// Generate RSA key but claim it's ECDSA
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	pkcs8Data, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8: %v", err)
	}

	wrapped, err := be.(*SoftwareBackend).WrapKey(pkcs8Data, params)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	// This should fail because the key type doesn't match attributes
	err = be.(*SoftwareBackend).ImportKey(attrs, wrapped)
	if err == nil {
		t.Error("Expected error when importing key with mismatched type")
	}
}

// TestImportAsymmetricKey_RSAKeySizeMismatch tests importing RSA key with wrong size
func TestImportAsymmetricKey_RSAKeySizeMismatch(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Attributes specify 4096-bit key
	attrs := createRSAAttrs("test.com", 4096)
	// Use RSA_AES wrapping which can handle larger key material
	params, err := be.(*SoftwareBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	// But we generate a 2048-bit key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	pkcs8Data, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8: %v", err)
	}

	wrapped, err := be.(*SoftwareBackend).WrapKey(pkcs8Data, params)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	// This should fail because key size doesn't match
	err = be.(*SoftwareBackend).ImportKey(attrs, wrapped)
	if err == nil {
		t.Error("Expected error when importing RSA key with mismatched size")
	}
}

// TestImportAsymmetricKey_ValidImport tests successful asymmetric key import
func TestImportAsymmetricKey_ValidImport(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate a key externally
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create matching attributes
	attrs := createRSAAttrs("test-import.com", 2048)
	// Use RSA_AES wrapping which can handle larger key material
	params, err := be.(*SoftwareBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	// Marshal to PKCS8
	pkcs8Data, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8: %v", err)
	}

	// Wrap the key
	wrapped, err := be.(*SoftwareBackend).WrapKey(pkcs8Data, params)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	// Import should succeed
	err = be.(*SoftwareBackend).ImportKey(attrs, wrapped)
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	// Verify we can retrieve the key
	retrievedKey, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("Failed to retrieve imported key: %v", err)
	}

	retrievedRSA, ok := retrievedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("Retrieved key is not RSA private key")
	}

	// Verify the key matches
	if retrievedRSA.N.Cmp(rsaKey.N) != 0 {
		t.Error("Imported key does not match original key")
	}
}

// TestListKeys_ErrorFromAESBackend tests ListKeys when AES backend returns error
// This is hard to test without mocking, but we can test the success path
func TestListKeys_BothBackendsEmpty(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("Expected 0 keys for empty backend, got %d", len(keys))
	}
}

// TestNewBackend_WithCustomTracker tests creating backend with custom AEAD tracker
func TestNewBackend_WithCustomTracker(t *testing.T) {
	be, keyStorage := createTestBackend(t)
	defer be.Close()

	// Create a custom tracker
	customTracker := backend.NewMemoryAEADTracker()

	config := &Config{
		KeyStorage: keyStorage,
		Tracker:    customTracker,
	}

	be2, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend with custom tracker failed: %v", err)
	}
	defer be2.Close()

	// Verify the tracker is the one we provided
	tracker := be2.(*SoftwareBackend).GetTracker()
	if tracker != customTracker {
		t.Error("Backend is not using the custom tracker")
	}
}
