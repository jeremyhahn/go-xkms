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

//go:build integration
// +build integration

package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

const (
	testTokenName = "test-token"
	testSOPIN     = "1234567890"
	testUserPIN   = "0987654321"
)

// getTestLibrary returns the PKCS#11 library path from environment or tries common paths
func getTestLibrary() string {
	// Try environment variable first (used in Docker)
	if lib := os.Getenv("PKCS11_MODULE"); lib != "" {
		return lib
	}

	// Try common installation paths
	commonPaths := []string{
		"/usr/lib/softhsm/libsofthsm2.so",                        // Debian/Ubuntu
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",       // Ubuntu 64-bit
		"/usr/local/lib/softhsm/libsofthsm2.so",                  // Source install
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",               // macOS Homebrew
		"/usr/local/Cellar/softhsm/*/lib/softhsm/libsofthsm2.so", // macOS Homebrew (versioned)
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Default fallback
	return "/usr/lib/softhsm/libsofthsm2.so"
}

// setupSoftHSM initializes a SoftHSM environment for testing.
func setupSoftHSM(t *testing.T) (*pkcs11.Config, func()) {
	t.Helper()

	// Create temp directory for SoftHSM tokens
	tempDir := t.TempDir()
	tokenDir := filepath.Join(tempDir, "tokens")
	if err := os.MkdirAll(tokenDir, 0755); err != nil {
		t.Fatalf("failed to create token directory: %v", err)
	}

	// Create SoftHSM config file
	configPath := filepath.Join(tempDir, "softhsm2.conf")
	configContent := pkcs11.SoftHSMConfig(tokenDir)
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write SoftHSM config: %v", err)
	}

	// Set SOFTHSM2_CONF environment variable
	oldConf := os.Getenv("SOFTHSM2_CONF")
	os.Setenv("SOFTHSM2_CONF", configPath)

	// Initialize token using softhsm2-util
	cmd := exec.Command("softhsm2-util", "--init-token",
		"--slot", "0",
		"--label", testTokenName,
		"--so-pin", testSOPIN,
		"--pin", testUserPIN)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("softhsm2-util output: %s", output)
		t.Fatalf("failed to initialize SoftHSM token: %v", err)
	}

	// Create storage backends
	keyStorage := storage.New()
	certStorage := storage.New()

	config := &pkcs11.Config{
		CN:            "test-hsm",
		Library:       getTestLibrary(),
		LibraryConfig: configPath,
		TokenLabel:    testTokenName,
		PIN:           testUserPIN,
		SOPIN:         testSOPIN,
		KeyStorage:    keyStorage,
		CertStorage:   certStorage,
	}

	// Cleanup function
	cleanup := func() {
		os.Setenv("SOFTHSM2_CONF", oldConf)
	}

	return config, cleanup
}

// TestIntegration_Initialize verifies token initialization.
func TestIntegration_Initialize(t *testing.T) {
	config, cleanup := setupSoftHSM(t)
	defer cleanup()

	b, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}
	defer b.Close()

	// Login to the already initialized token
	err = b.Login()
	if err != nil {
		t.Fatalf("Login() failed: %v", err)
	}

	// Verify context is available
	ctx, err := b.Context()
	if err != nil {
		t.Fatalf("Context() failed: %v", err)
	}
	if ctx == nil {
		t.Fatal("Context() returned nil")
	}
}

// TestIntegration_GenerateRSA tests RSA key generation on HSM.
func TestIntegration_GenerateRSA(t *testing.T) {
	config, cleanup := setupSoftHSM(t)
	defer cleanup()

	b, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}
	defer b.Close()

	if err := b.Login(); err != nil {
		t.Fatalf("Login() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-rsa-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_PKCS11,
	}

	// Generate RSA key
	signer, err := b.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("GenerateRSA() failed: %v", err)
	}

	// Verify signer
	if signer == nil {
		t.Fatal("GenerateRSA() returned nil signer")
	}

	// Verify public key
	pubKey := signer.Public()
	if pubKey == nil {
		t.Fatal("signer.Public() returned nil")
	}

	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not *rsa.PublicKey, got %T", pubKey)
	}

	if rsaPub.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit RSA key, got %d bits", rsaPub.N.BitLen())
	}

	// Test signing
	digest := sha256.Sum256([]byte("test message"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Sign() returned empty signature")
	}

	// Verify signature
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature)
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

// TestIntegration_GenerateECDSA tests ECDSA key generation on HSM.
func TestIntegration_GenerateECDSA(t *testing.T) {
	config, cleanup := setupSoftHSM(t)
	defer cleanup()

	b, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}
	defer b.Close()

	if err := b.Login(); err != nil {
		t.Fatalf("Login() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa-key",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_PKCS11,
	}

	// Generate ECDSA key
	signer, err := b.GenerateECDSA(attrs)
	if err != nil {
		t.Fatalf("GenerateECDSA() failed: %v", err)
	}

	// Verify signer
	if signer == nil {
		t.Fatal("GenerateECDSA() returned nil signer")
	}

	// Verify public key
	pubKey := signer.Public()
	if pubKey == nil {
		t.Fatal("signer.Public() returned nil")
	}

	ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not *ecdsa.PublicKey, got %T", pubKey)
	}

	if ecdsaPub.Curve.Params().Name != "P-256" {
		t.Errorf("expected P-256 curve, got %s", ecdsaPub.Curve.Params().Name)
	}

	// Test signing
	digest := sha256.Sum256([]byte("test message"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Sign() returned empty signature")
	}

	// Verify signature
	valid := ecdsa.VerifyASN1(ecdsaPub, digest[:], signature)
	if !valid {
		t.Fatal("signature verification failed")
	}
}

// TestIntegration_FindKeyPair tests key retrieval.
func TestIntegration_FindKeyPair(t *testing.T) {
	config, cleanup := setupSoftHSM(t)
	defer cleanup()

	b, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}
	defer b.Close()

	if err := b.Login(); err != nil {
		t.Fatalf("Login() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-find-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_PKCS11,
	}

	// Generate key
	originalSigner, err := b.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("GenerateRSA() failed: %v", err)
	}

	// Find the key
	foundSigner, err := b.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer() failed: %v", err)
	}

	if foundSigner == nil {
		t.Fatal("Signer() returned nil")
	}

	// Compare public keys
	origPub := originalSigner.Public().(*rsa.PublicKey)
	foundPub := foundSigner.Public().(*rsa.PublicKey)

	if origPub.N.Cmp(foundPub.N) != 0 {
		t.Error("found key has different modulus")
	}
	if origPub.E != foundPub.E {
		t.Error("found key has different exponent")
	}
}

// TestIntegration_Sign tests signing with stored key.
func TestIntegration_Sign(t *testing.T) {
	config, cleanup := setupSoftHSM(t)
	defer cleanup()

	b, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}
	defer b.Close()

	if err := b.Login(); err != nil {
		t.Fatalf("Login() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-sign-key",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_PKCS11,
	}

	// Generate key
	signer, err := b.GenerateECDSA(attrs)
	if err != nil {
		t.Fatalf("GenerateECDSA() failed: %v", err)
	}

	// Sign using backend.Sign method
	message := []byte("test message for signing")
	digest := sha256.Sum256(message)

	signature, err := b.Sign(attrs, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify signature
	pubKey := signer.Public().(*ecdsa.PublicKey)
	valid := ecdsa.VerifyASN1(pubKey, digest[:], signature)
	if !valid {
		t.Fatal("signature verification failed")
	}
}

// TestIntegration_Verify tests signature verification.
func TestIntegration_Verify(t *testing.T) {
	config, cleanup := setupSoftHSM(t)
	defer cleanup()

	b, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}
	defer b.Close()

	if err := b.Login(); err != nil {
		t.Fatalf("Login() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-verify-key",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_PKCS11,
	}

	// Generate key
	signer, err := b.GenerateECDSA(attrs)
	if err != nil {
		t.Fatalf("GenerateECDSA() failed: %v", err)
	}

	// Create signature
	message := []byte("test message for verification")
	digest := sha256.Sum256(message)

	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify using backend.Verify method
	err = b.Verify(attrs, digest[:], signature)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}

	// Test with invalid signature
	invalidSignature := make([]byte, len(signature))
	copy(invalidSignature, signature)
	invalidSignature[0] ^= 0xFF // Flip bits to make invalid

	err = b.Verify(attrs, digest[:], invalidSignature)
	if err == nil {
		t.Fatal("Verify() should fail for invalid signature")
	}
}

// TestIntegration_GenerateKey_Dispatcher tests GenerateKey dispatcher.
func TestIntegration_GenerateKey_Dispatcher(t *testing.T) {
	config, cleanup := setupSoftHSM(t)
	defer cleanup()

	b, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}
	defer b.Close()

	if err := b.Login(); err != nil {
		t.Fatalf("Login() failed: %v", err)
	}

	tests := []struct {
		name      string
		algorithm x509.PublicKeyAlgorithm
		wantErr   bool
	}{
		{
			name:      "RSA",
			algorithm: x509.RSA,
			wantErr:   false,
		},
		{
			name:      "ECDSA",
			algorithm: x509.ECDSA,
			wantErr:   false,
		},
		{
			name:      "Ed25519 unsupported",
			algorithm: x509.Ed25519,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           fmt.Sprintf("test-dispatch-%s", tt.algorithm),
				KeyAlgorithm: tt.algorithm,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_PKCS11,
			}

			_, err := b.GenerateKey(attrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
			}

		})
	}
}

// TestIntegration_MultipleKeys tests creating multiple keys.
func TestIntegration_MultipleKeys(t *testing.T) {
	config, cleanup := setupSoftHSM(t)
	defer cleanup()

	b, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}
	defer b.Close()

	if err := b.Login(); err != nil {
		t.Fatalf("Login() failed: %v", err)
	}

	// Generate multiple keys
	keys := []struct {
		cn   string
		algo x509.PublicKeyAlgorithm
	}{
		{"key1", x509.RSA},
		{"key2", x509.ECDSA},
		{"key3", x509.RSA},
		{"key4", x509.ECDSA},
	}

	for _, k := range keys {
		attrs := &types.KeyAttributes{
			CN:           k.cn,
			KeyAlgorithm: k.algo,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_PKCS11,
		}

		_, err := b.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey() for %s failed: %v", k.cn, err)
		}
	}

	// Retrieve and verify each key
	for _, k := range keys {
		attrs := &types.KeyAttributes{
			CN:           k.cn,
			KeyAlgorithm: k.algo,
		}

		signer, err := b.Signer(attrs)
		if err != nil {
			t.Fatalf("Signer() for %s failed: %v", k.cn, err)
		}

		// Test signing with retrieved key
		digest := sha256.Sum256([]byte(k.cn))
		_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign() for %s failed: %v", k.cn, err)
		}
	}
}

// TestIntegration_ConcurrentOperations tests concurrent key operations.
func TestIntegration_ConcurrentOperations(t *testing.T) {
	config, cleanup := setupSoftHSM(t)
	defer cleanup()

	b, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}
	defer b.Close()

	if err := b.Login(); err != nil {
		t.Fatalf("Login() failed: %v", err)
	}

	// Create a key first
	attrs := &types.KeyAttributes{
		CN:           "concurrent-test-key",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_PKCS11,
	}

	_, err = b.GenerateECDSA(attrs)
	if err != nil {
		t.Fatalf("GenerateECDSA() failed: %v", err)
	}

	// Perform concurrent signing operations
	const numGoroutines = 10
	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			signer, err := b.Signer(attrs)
			if err != nil {
				done <- fmt.Errorf("goroutine %d: Signer() failed: %w", id, err)
				return
			}

			digest := sha256.Sum256([]byte(fmt.Sprintf("message-%d", id)))
			_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				done <- fmt.Errorf("goroutine %d: Sign() failed: %w", id, err)
				return
			}

			done <- nil
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
}

// TestIntegration_Delete tests key deletion.
func TestIntegration_Delete(t *testing.T) {
	config, cleanup := setupSoftHSM(t)
	defer cleanup()

	b, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}
	defer b.Close()

	if err := b.Login(); err != nil {
		t.Fatalf("Login() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-delete-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_PKCS11,
	}

	// Generate key
	_, err = b.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("GenerateRSA() failed: %v", err)
	}

	// Verify key exists
	_, err = b.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer() failed: %v", err)
	}

	// Delete key
	err = b.Delete(attrs)
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}

	// Note: The current Delete implementation is a placeholder
	// In a full implementation, this would verify the key is actually deleted
}

// TestIntegration_Close tests proper cleanup.
func TestIntegration_Close(t *testing.T) {
	config, cleanup := setupSoftHSM(t)
	defer cleanup()

	b, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	if err := b.Login(); err != nil {
		t.Fatalf("Login() failed: %v", err)
	}

	// Close should succeed
	err = b.Close()
	if err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	// Second close should also succeed (idempotent)
	err = b.Close()
	if err != nil {
		t.Fatalf("second Close() failed: %v", err)
	}

	// Operations after close should fail
	attrs := &types.KeyAttributes{
		CN:           "test-after-close",
		KeyAlgorithm: x509.RSA,
	}

	_, err = b.GenerateRSA(attrs)
	if err == nil {
		t.Error("GenerateRSA() should fail after Close()")
	}
}
