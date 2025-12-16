//go:build integration

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

package backend

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// skipIfNoTPM skips the test if no TPM is available
func skipIfNoTPM(t *testing.T) {
	t.Helper()

	// Check for simulator mode via environment
	if os.Getenv("TPM2_SIMULATOR_HOST") != "" {
		return // Simulator available
	}

	// Check for hardware TPM
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return // Hardware TPM available
	}

	t.Skip("No TPM available (set TPM2_SIMULATOR_HOST or have /dev/tpmrm0)")
}

// createTPM2Backend creates a test TPM2 backend
func createTPM2Backend(t *testing.T) *tpm2.Backend {
	t.Helper()
	skipIfNoTPM(t)

	keyDir := t.TempDir()

	config := &tpm2.Config{
		KeyDir: keyDir,
	}

	// Use simulator if configured
	if os.Getenv("TPM2_SIMULATOR_HOST") != "" {
		config.UseSimulator = true
	} else {
		config.Device = "/dev/tpmrm0"
	}

	be, err := tpm2.NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create TPM2 backend: %v", err)
	}

	return be
}

// createTPM2RSAAttrs creates RSA key attributes for TPM2
func createTPM2RSAAttrs(cn string, keySize int) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    types.StoreTPM2,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: keySize,
		},
		Hash: crypto.SHA256,
	}
}

// createTPM2ECDSAAttrs creates ECDSA key attributes for TPM2
func createTPM2ECDSAAttrs(cn, curve string) *types.KeyAttributes {
	parsedCurve, _ := types.ParseCurve(curve)
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    types.StoreTPM2,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: parsedCurve,
		},
		Hash: crypto.SHA256,
	}
}

// TestTPM2_BackendType tests the backend type identifier
func TestTPM2_BackendType(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	if be.Type() != backend.BackendTypeTPM2 {
		t.Errorf("Expected backend type %s, got %s", backend.BackendTypeTPM2, be.Type())
	}
}

// TestTPM2_Capabilities tests the backend capabilities
func TestTPM2_Capabilities(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	caps := be.Capabilities()

	if !caps.HardwareBacked {
		t.Error("Expected HardwareBacked to be true for TPM2 backend")
	}

	if !caps.Keys {
		t.Error("Expected Keys capability to be true")
	}

	if !caps.Signing {
		t.Error("Expected Signing capability to be true")
	}

	if !caps.Sealing {
		t.Error("Expected Sealing capability to be true")
	}

	// TPM2 does not support key rotation (hardware-backed keys)
	if caps.KeyRotation {
		t.Error("Expected KeyRotation to be false for TPM2")
	}
}

// TestTPM2_RSA_GenerateKey tests RSA key generation
func TestTPM2_RSA_GenerateKey(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	// TPM2 typically supports 2048-bit RSA keys
	attrs := createTPM2RSAAttrs("test-rsa-2048", 2048)

	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if key == nil {
		t.Fatal("Generated key is nil")
	}

	// For TPM2, we get a crypto.Signer, not the raw key
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("Expected crypto.Signer, got %T", key)
	}

	// Verify public key type
	pub := signer.Public()
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Expected RSA public key, got %T", pub)
	}

	if rsaPub.N.BitLen() != 2048 {
		t.Errorf("Key size = %d, want 2048", rsaPub.N.BitLen())
	}

	// Clean up
	if err := be.DeleteKey(attrs); err != nil {
		t.Logf("DeleteKey failed: %v", err)
	}
}

// TestTPM2_ECDSA_GenerateKey tests ECDSA key generation
func TestTPM2_ECDSA_GenerateKey(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	// TPM2 supports P-256 ECDSA
	attrs := createTPM2ECDSAAttrs("test-ecdsa-p256", "P-256")

	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if key == nil {
		t.Fatal("Generated key is nil")
	}

	// For TPM2, we get a crypto.Signer, not the raw key
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("Expected crypto.Signer, got %T", key)
	}

	// Verify public key type
	pub := signer.Public()
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Expected ECDSA public key, got %T", pub)
	}

	if ecPub.Curve.Params().Name != "P-256" {
		t.Errorf("Curve = %s, want P-256", ecPub.Curve.Params().Name)
	}

	// Clean up
	if err := be.DeleteKey(attrs); err != nil {
		t.Logf("DeleteKey failed: %v", err)
	}
}

// TestTPM2_RSA_Sign tests RSA signing
func TestTPM2_RSA_Sign(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	attrs := createTPM2RSAAttrs("test-rsa-sign", 2048)

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer be.DeleteKey(attrs)

	// Get signer
	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	// Sign some data
	message := []byte("Test message for TPM2 RSA signing")
	hash := sha256.Sum256(message)

	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is empty")
	}

	// Verify signature using public key
	pub := signer.Public()
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Expected RSA public key, got %T", pub)
	}

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], signature)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

// TestTPM2_ECDSA_Sign tests ECDSA signing
func TestTPM2_ECDSA_Sign(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	attrs := createTPM2ECDSAAttrs("test-ecdsa-sign", "P-256")

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer be.DeleteKey(attrs)

	// Get signer
	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	// Sign some data
	message := []byte("Test message for TPM2 ECDSA signing")
	hash := sha256.Sum256(message)

	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is empty")
	}

	// Verify signature using public key
	pub := signer.Public()
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Expected ECDSA public key, got %T", pub)
	}

	if !ecdsa.VerifyASN1(ecPub, hash[:], signature) {
		t.Error("ECDSA signature verification failed")
	}
}

// TestTPM2_GetKey tests key retrieval
func TestTPM2_GetKey(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	attrs := createTPM2RSAAttrs("test-rsa-get", 2048)

	// Generate key
	originalKey, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer be.DeleteKey(attrs)

	originalSigner := originalKey.(crypto.Signer)
	originalPub := originalSigner.Public().(*rsa.PublicKey)

	// Retrieve key
	retrievedKey, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	retrievedSigner := retrievedKey.(crypto.Signer)
	retrievedPub := retrievedSigner.Public().(*rsa.PublicKey)

	// Verify public keys match
	if originalPub.N.Cmp(retrievedPub.N) != 0 {
		t.Error("Retrieved public key doesn't match original")
	}
}

// TestTPM2_DeleteKey tests key deletion
func TestTPM2_DeleteKey(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	attrs := createTPM2RSAAttrs("test-rsa-delete", 2048)

	// Generate key
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Delete key
	if err := be.DeleteKey(attrs); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Verify key is deleted
	_, err = be.GetKey(attrs)
	if err == nil {
		t.Error("Expected error when getting deleted key")
	}
}

// TestTPM2_ListKeys tests key listing
func TestTPM2_ListKeys(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	// Generate some keys
	rsaAttrs := createTPM2RSAAttrs("test-list-rsa", 2048)
	_, err := be.GenerateKey(rsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey RSA failed: %v", err)
	}
	defer be.DeleteKey(rsaAttrs)

	ecdsaAttrs := createTPM2ECDSAAttrs("test-list-ecdsa", "P-256")
	_, err = be.GenerateKey(ecdsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey ECDSA failed: %v", err)
	}
	defer be.DeleteKey(ecdsaAttrs)

	// List keys
	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) < 2 {
		t.Errorf("Expected at least 2 keys, got %d", len(keys))
	}

	// Verify our keys are in the list
	foundRSA := false
	foundECDSA := false
	for _, k := range keys {
		if k.CN == "test-list-rsa" {
			foundRSA = true
		}
		if k.CN == "test-list-ecdsa" {
			foundECDSA = true
		}
	}

	if !foundRSA {
		t.Error("RSA key not found in list")
	}
	if !foundECDSA {
		t.Error("ECDSA key not found in list")
	}
}

// TestTPM2_RotateKey tests that key rotation fails (as expected for TPM2)
func TestTPM2_RotateKey(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	attrs := createTPM2RSAAttrs("test-rotate", 2048)

	// Generate key
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer be.DeleteKey(attrs)

	// Rotate should fail for hardware-backed keys
	err = be.RotateKey(attrs)
	if err == nil {
		t.Error("Expected error for RotateKey on TPM2 backend")
	}
	if err != tpm2.ErrKeyRotationNotSupported {
		t.Errorf("Expected ErrKeyRotationNotSupported, got %v", err)
	}
}

// TestTPM2_Close tests backend closure
func TestTPM2_Close(t *testing.T) {
	be := createTPM2Backend(t)

	// Close the backend
	if err := be.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Operations after close should fail
	attrs := createTPM2RSAAttrs("test-after-close", 2048)
	_, err := be.GenerateKey(attrs)
	if err == nil {
		t.Error("Expected error after close")
	}
	if err != tpm2.ErrNotInitialized {
		t.Errorf("Expected ErrNotInitialized, got %v", err)
	}
}

// TestTPM2_DoubleClose tests that closing twice is safe
func TestTPM2_DoubleClose(t *testing.T) {
	be := createTPM2Backend(t)

	// First close
	if err := be.Close(); err != nil {
		t.Fatalf("First Close failed: %v", err)
	}

	// Second close should be safe
	if err := be.Close(); err != nil {
		t.Errorf("Second Close failed: %v", err)
	}
}

// TestTPM2_ErrorHandling_NilAttributes tests error handling with nil attributes
func TestTPM2_ErrorHandling_NilAttributes(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	// GenerateKey with nil attrs
	_, err := be.GenerateKey(nil)
	if err == nil {
		t.Error("Expected error for nil attributes")
	}

	// GetKey with nil attrs
	_, err = be.GetKey(nil)
	if err == nil {
		t.Error("Expected error for nil attributes")
	}

	// DeleteKey with nil attrs
	err = be.DeleteKey(nil)
	if err == nil {
		t.Error("Expected error for nil attributes")
	}
}

// TestTPM2_ErrorHandling_NonExistentKey tests error handling for non-existent keys
func TestTPM2_ErrorHandling_NonExistentKey(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	attrs := createTPM2RSAAttrs("nonexistent-key", 2048)

	// GetKey should fail
	_, err := be.GetKey(attrs)
	if err == nil {
		t.Error("Expected error for non-existent key")
	}

	// Signer should fail
	_, err = be.Signer(attrs)
	if err == nil {
		t.Error("Expected error for non-existent key")
	}

	// Decrypter should fail
	_, err = be.Decrypter(attrs)
	if err == nil {
		t.Error("Expected error for non-existent key")
	}
}

// TestTPM2_UnsupportedAlgorithm tests error handling for unsupported algorithms
func TestTPM2_UnsupportedAlgorithm(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	// Try to create a key with unsupported algorithm (DSA)
	attrs := &types.KeyAttributes{
		CN:           "test-unsupported",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    types.StoreTPM2,
		KeyAlgorithm: x509.DSA, // Not supported by TPM2
	}

	_, err := be.GenerateKey(attrs)
	if err == nil {
		t.Error("Expected error for unsupported algorithm")
	}
}

// TestTPM2_TPMAccessor tests access to underlying TPM instance
func TestTPM2_TPMAccessor(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	// Access underlying TPM
	tpm := be.TPM()
	if tpm == nil {
		t.Error("TPM() returned nil")
	}

	// Access key backend
	keyBackend := be.KeyBackend()
	if keyBackend == nil {
		t.Error("KeyBackend() returned nil")
	}

	// Access SRK attributes
	srkAttrs := be.SRKAttributes()
	if srkAttrs == nil {
		t.Error("SRKAttributes() returned nil")
	}
}

// TestTPM2_EndToEnd_RSA tests complete RSA workflow
func TestTPM2_EndToEnd_RSA(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	attrs := createTPM2RSAAttrs("test-e2e-rsa", 2048)

	// Generate key
	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	signer := key.(crypto.Signer)
	pub := signer.Public().(*rsa.PublicKey)

	// Get key
	retrieved, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	retrievedSigner := retrieved.(crypto.Signer)
	retrievedPub := retrievedSigner.Public().(*rsa.PublicKey)

	if pub.N.Cmp(retrievedPub.N) != 0 {
		t.Error("Retrieved public key doesn't match")
	}

	// Sign
	signerFromBackend, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	message := []byte("End-to-end test message")
	hash := sha256.Sum256(message)

	signature, err := signerFromBackend.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify signature
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], signature)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

	// List keys
	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	found := false
	for _, k := range keys {
		if k.CN == attrs.CN {
			found = true
			break
		}
	}
	if !found {
		t.Error("Key not found in list")
	}

	// Delete key
	if err := be.DeleteKey(attrs); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Verify deletion
	_, err = be.GetKey(attrs)
	if err == nil {
		t.Error("Expected error for deleted key")
	}
}

// TestTPM2_EndToEnd_ECDSA tests complete ECDSA workflow
func TestTPM2_EndToEnd_ECDSA(t *testing.T) {
	be := createTPM2Backend(t)
	defer be.Close()

	attrs := createTPM2ECDSAAttrs("test-e2e-ecdsa", "P-256")

	// Generate key
	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	signer := key.(crypto.Signer)
	pub := signer.Public().(*ecdsa.PublicKey)

	// Get key
	retrieved, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	retrievedSigner := retrieved.(crypto.Signer)
	retrievedPub := retrievedSigner.Public().(*ecdsa.PublicKey)

	if pub.X.Cmp(retrievedPub.X) != 0 || pub.Y.Cmp(retrievedPub.Y) != 0 {
		t.Error("Retrieved public key doesn't match")
	}

	// Sign
	signerFromBackend, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	message := []byte("End-to-end ECDSA test message")
	hash := sha256.Sum256(message)

	signature, err := signerFromBackend.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify signature
	if !ecdsa.VerifyASN1(pub, hash[:], signature) {
		t.Error("ECDSA signature verification failed")
	}

	// Delete key
	if err := be.DeleteKey(attrs); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Verify deletion
	_, err = be.GetKey(attrs)
	if err == nil {
		t.Error("Expected error for deleted key")
	}
}
