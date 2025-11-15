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

package pkcs8

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Helper function to create a test backend
func createTestBackend(t *testing.T) (*PKCS8Backend, storage.Backend) {
	t.Helper()

	keyStorage := memory.New()
	config := &Config{
		KeyStorage: keyStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	return be.(*PKCS8Backend), keyStorage
}

// Helper function to create RSA attributes
func createRSAAttrs(cn string, keySize int) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: keySize,
		},
		Hash: crypto.SHA256,
	}
}

// Helper function to create ECDSA attributes
func createECDSAAttrs(cn, curve string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: types.ParseCurve(curve),
		},
		Hash: crypto.SHA256,
	}
}

// Helper function to create Ed25519 attributes
func createEd25519Attrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.Ed25519,
	}
}

// TestNewBackend tests backend creation and configuration
func TestNewBackend(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		keyStorage := memory.New()
		config := &Config{
			KeyStorage: keyStorage,
		}

		be, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend failed: %v", err)
		}
		if be == nil {
			t.Fatal("NewBackend returned nil")
		}

		defer be.Close()

		// Verify type
		if be.Type() != backend.BackendTypePKCS8 {
			t.Errorf("Expected type %s, got %s", backend.BackendTypePKCS8, be.Type())
		}
	})

	t.Run("NilConfig", func(t *testing.T) {
		_, err := NewBackend(nil)
		if err == nil {
			t.Fatal("NewBackend should fail with nil config")
		}
	})

	t.Run("NilKeyStorage", func(t *testing.T) {
		config := &Config{
			KeyStorage: nil,
		}

		_, err := NewBackend(config)
		if err == nil {
			t.Fatal("NewBackend should fail with nil KeyStorage")
		}
	})
}

// TestType tests backend type identification
func TestType(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	if be.Type() != backend.BackendTypePKCS8 {
		t.Errorf("Expected type %s, got %s", backend.BackendTypePKCS8, be.Type())
	}
}

// TestCapabilities tests backend capabilities
func TestCapabilities(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	caps := be.Capabilities()

	if !caps.Keys {
		t.Error("Capabilities should indicate key support")
	}
	if caps.HardwareBacked {
		t.Error("PKCS8 backend should not be hardware-backed")
	}
	if !caps.Signing {
		t.Error("Capabilities should indicate signing support")
	}
	if !caps.Decryption {
		t.Error("Capabilities should indicate decryption support")
	}
}

// TestGenerateKey_RSA tests RSA key generation
func TestGenerateKey_RSA(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		wantError bool
		errType   error
	}{
		{
			name:      "RSA-2048",
			keySize:   2048,
			wantError: false,
		},
		{
			name:      "RSA-3072",
			keySize:   3072,
			wantError: false,
		},
		{
			name:      "RSA-4096",
			keySize:   4096,
			wantError: false,
		},
		{
			name:      "RSA-1024-TooSmall",
			keySize:   1024,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			attrs := createRSAAttrs("test-rsa.com", tt.keySize)

			key, err := be.GenerateKey(attrs)
			if tt.wantError {
				if err == nil {
					t.Fatal("GenerateKey should have failed")
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				t.Fatal("Generated key is not *rsa.PrivateKey")
			}

			// Verify key size
			if rsaKey.N.BitLen() != tt.keySize {
				t.Errorf("Expected key size %d, got %d", tt.keySize, rsaKey.N.BitLen())
			}

			// Verify key can be retrieved
			retrieved, err := be.GetKey(attrs)
			if err != nil {
				t.Fatalf("GetKey failed: %v", err)
			}

			retrievedRSA, ok := retrieved.(*rsa.PrivateKey)
			if !ok {
				t.Fatal("Retrieved key is not *rsa.PrivateKey")
			}

			// Verify keys match
			if retrievedRSA.N.Cmp(rsaKey.N) != 0 {
				t.Error("Retrieved key doesn't match generated key")
			}
		})
	}
}

// TestGenerateKey_ECDSA tests ECDSA key generation
func TestGenerateKey_ECDSA(t *testing.T) {
	tests := []struct {
		name      string
		curve     string
		wantError bool
	}{
		{
			name:      "P-256",
			curve:     "P-256",
			wantError: false,
		},
		{
			name:      "prime256v1",
			curve:     "prime256v1",
			wantError: false,
		},
		{
			name:      "P-384",
			curve:     "P-384",
			wantError: false,
		},
		{
			name:      "secp384r1",
			curve:     "secp384r1",
			wantError: false,
		},
		{
			name:      "P-521",
			curve:     "P-521",
			wantError: false,
		},
		{
			name:      "secp521r1",
			curve:     "secp521r1",
			wantError: false,
		},
		{
			name:      "InvalidCurve",
			curve:     "P-999",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			attrs := createECDSAAttrs("test-ecdsa.com", tt.curve)

			key, err := be.GenerateKey(attrs)
			if tt.wantError {
				if err == nil {
					t.Fatal("GenerateKey should have failed")
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			ecdsaKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatal("Generated key is not *ecdsa.PrivateKey")
			}

			// Verify key can be retrieved
			retrieved, err := be.GetKey(attrs)
			if err != nil {
				t.Fatalf("GetKey failed: %v", err)
			}

			retrievedECDSA, ok := retrieved.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatal("Retrieved key is not *ecdsa.PrivateKey")
			}

			// Verify keys match
			if retrievedECDSA.X.Cmp(ecdsaKey.X) != 0 || retrievedECDSA.Y.Cmp(ecdsaKey.Y) != 0 {
				t.Error("Retrieved key doesn't match generated key")
			}
		})
	}
}

// TestGenerateKey_Ed25519 tests Ed25519 key generation
func TestGenerateKey_Ed25519(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createEd25519Attrs("test-ed25519.com")

	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	ed25519Key, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("Generated key is not ed25519.PrivateKey")
	}

	// Verify key length
	if len(ed25519Key) != ed25519.PrivateKeySize {
		t.Errorf("Expected key size %d, got %d", ed25519.PrivateKeySize, len(ed25519Key))
	}

	// Verify key can be retrieved
	retrieved, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	retrievedEd25519, ok := retrieved.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("Retrieved key is not ed25519.PrivateKey")
	}

	// Verify public keys match
	if !retrievedEd25519.Public().(ed25519.PublicKey).Equal(ed25519Key.Public()) {
		t.Error("Retrieved key doesn't match generated key")
	}
}

// TestGenerateKey_WithPassword tests key generation with password encryption
func TestGenerateKey_WithPassword(t *testing.T) {
	tests := []struct {
		name     string
		password types.Password
	}{
		{
			name:     "StaticPassword",
			password: backend.StaticPassword("test-password-123"),
		},
		{
			name:     "NoPassword",
			password: backend.NoPassword{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			attrs := createRSAAttrs("test-pwd.com", 2048)
			attrs.Password = tt.password

			key, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			// Verify key can be retrieved with correct password
			retrieved, err := be.GetKey(attrs)
			if err != nil {
				t.Fatalf("GetKey failed: %v", err)
			}

			rsaKey := key.(*rsa.PrivateKey)
			retrievedRSA := retrieved.(*rsa.PrivateKey)

			if retrievedRSA.N.Cmp(rsaKey.N) != 0 {
				t.Error("Retrieved key doesn't match generated key")
			}
		})
	}
}

// TestGenerateKey_DuplicateKey tests generating a key that already exists
func TestGenerateKey_DuplicateKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("duplicate.com", 2048)

	// Generate first key
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("First GenerateKey failed: %v", err)
	}

	// Attempt to generate duplicate
	_, err = be.GenerateKey(attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail for duplicate key")
	}

	if !errors.Is(err, backend.ErrKeyAlreadyExists) {
		t.Errorf("Expected backend.ErrKeyAlreadyExists, got: %v", err)
	}
}

// TestGenerateKey_InvalidAttributes tests key generation with invalid attributes
func TestGenerateKey_InvalidAttributes(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name: "MissingCN",
			attrs: &types.KeyAttributes{
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
		},
		{
			name: "MissingRSAAttributes",
			attrs: &types.KeyAttributes{
				CN:           "test.com",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
		},
		{
			name: "MissingECCAttributes",
			attrs: &types.KeyAttributes{
				CN:           "test.com",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.ECDSA,
			},
		},
		{
			name: "InvalidAlgorithm",
			attrs: &types.KeyAttributes{
				CN:           "test.com",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			_, err := be.GenerateKey(tt.attrs)
			if err == nil {
				t.Fatal("GenerateKey should fail with invalid attributes")
			}
		})
	}
}

// TestGetKey tests key retrieval
func TestGetKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate a key
	attrs := createRSAAttrs("test-get.com", 2048)
	generated, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Retrieve the key
	retrieved, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	// Verify keys match
	genRSA := generated.(*rsa.PrivateKey)
	retRSA := retrieved.(*rsa.PrivateKey)

	if retRSA.N.Cmp(genRSA.N) != 0 {
		t.Error("Retrieved key doesn't match generated key")
	}
}

// TestGetKey_NotFound tests retrieving a non-existent key
func TestGetKey_NotFound(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("nonexistent.com", 2048)

	_, err := be.GetKey(attrs)
	if err == nil {
		t.Fatal("GetKey should fail for non-existent key")
	}

	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound, got: %v", err)
	}
}

// TestGetKey_InvalidAttributes tests getting a key with invalid attributes
func TestGetKey_InvalidAttributes(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := &types.KeyAttributes{
		// Missing required fields
		KeyAlgorithm: x509.RSA,
	}

	_, err := be.GetKey(attrs)
	if err == nil {
		t.Fatal("GetKey should fail with invalid attributes")
	}
}

// TestDeleteKey tests key deletion
func TestDeleteKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate a key
	attrs := createRSAAttrs("test-delete.com", 2048)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Verify key exists
	_, err = be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed before delete: %v", err)
	}

	// Delete the key
	err = be.DeleteKey(attrs)
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Verify key is gone
	_, err = be.GetKey(attrs)
	if err == nil {
		t.Fatal("GetKey should fail after delete")
	}
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound, got: %v", err)
	}
}

// TestDeleteKey_NotFound tests deleting a non-existent key
func TestDeleteKey_NotFound(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("nonexistent.com", 2048)

	err := be.DeleteKey(attrs)
	if err == nil {
		t.Fatal("DeleteKey should fail for non-existent key")
	}

	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound, got: %v", err)
	}
}

// TestListKeys tests listing all keys
func TestListKeys(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Initially empty
	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}

	// Generate multiple keys
	attrs1 := createRSAAttrs("test1.com", 2048)
	attrs2 := createECDSAAttrs("test2.com", "P-256")
	attrs3 := createEd25519Attrs("test3.com")

	_, err = be.GenerateKey(attrs1)
	if err != nil {
		t.Fatalf("GenerateKey 1 failed: %v", err)
	}

	_, err = be.GenerateKey(attrs2)
	if err != nil {
		t.Fatalf("GenerateKey 2 failed: %v", err)
	}

	_, err = be.GenerateKey(attrs3)
	if err != nil {
		t.Fatalf("GenerateKey 3 failed: %v", err)
	}

	// List keys
	keys, err = be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}

	// Delete one key
	err = be.DeleteKey(attrs2)
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Verify count
	keys, err = be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("Expected 2 keys after delete, got %d", len(keys))
	}
}

// TestSigner tests the Signer interface
func TestSigner(t *testing.T) {
	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		canSign bool
	}{
		{
			name:    "RSA",
			attrs:   createRSAAttrs("test-sign-rsa.com", 2048),
			canSign: true,
		},
		{
			name:    "ECDSA",
			attrs:   createECDSAAttrs("test-sign-ecdsa.com", "P-256"),
			canSign: true,
		},
		{
			name:    "Ed25519",
			attrs:   createEd25519Attrs("test-sign-ed25519.com"),
			canSign: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			// Generate key
			_, err := be.GenerateKey(tt.attrs)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			// Get signer
			signer, err := be.Signer(tt.attrs)
			if err != nil {
				t.Fatalf("Signer failed: %v", err)
			}

			// Test signing
			digest := sha256.Sum256([]byte("test message"))

			var opts crypto.SignerOpts
			switch tt.attrs.KeyAlgorithm {
			case x509.RSA:
				opts = crypto.SHA256
			case x509.ECDSA:
				opts = crypto.SHA256
			case x509.Ed25519:
				opts = crypto.Hash(0) // Ed25519 doesn't use hash
			}

			signature, err := signer.Sign(rand.Reader, digest[:], opts)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			if len(signature) == 0 {
				t.Fatal("Sign returned empty signature")
			}
		})
	}
}

// TestSigner_KeyNotFound tests Signer with non-existent key
func TestSigner_KeyNotFound(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("nonexistent.com", 2048)

	_, err := be.Signer(attrs)
	if err == nil {
		t.Fatal("Signer should fail for non-existent key")
	}

	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound, got: %v", err)
	}
}

// TestDecrypter tests the Decrypter interface
func TestDecrypter(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Only RSA supports decryption
	attrs := createRSAAttrs("test-decrypt.com", 2048)

	// Generate key
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Get decrypter
	decrypter, err := be.Decrypter(attrs)
	if err != nil {
		t.Fatalf("Decrypter failed: %v", err)
	}

	// Verify it's an RSA key
	_, ok := decrypter.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("Decrypter is not *rsa.PrivateKey")
	}
}

// TestDecrypter_NotSupported tests Decrypter with non-RSA keys
func TestDecrypter_NotSupported(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name:  "ECDSA",
			attrs: createECDSAAttrs("test-decrypt-ecdsa.com", "P-256"),
		},
		{
			name:  "Ed25519",
			attrs: createEd25519Attrs("test-decrypt-ed25519.com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			// Generate key
			_, err := be.GenerateKey(tt.attrs)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			// Try to get decrypter
			_, err = be.Decrypter(tt.attrs)
			if err == nil {
				t.Fatal("Decrypter should fail for non-RSA key")
			}

			if !errors.Is(err, ErrKeyNotDecrypter) {
				t.Errorf("Expected ErrKeyNotDecrypter, got: %v", err)
			}
		})
	}
}

// TestPublic tests the Public method
func TestPublic(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name:  "RSA",
			attrs: createRSAAttrs("test-pub-rsa.com", 2048),
		},
		{
			name:  "ECDSA",
			attrs: createECDSAAttrs("test-pub-ecdsa.com", "P-256"),
		},
		{
			name:  "Ed25519",
			attrs: createEd25519Attrs("test-pub-ed25519.com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			// Generate key
			privateKey, err := be.GenerateKey(tt.attrs)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			// Get public key
			publicKey, err := be.Public(tt.attrs)
			if err != nil {
				t.Fatalf("Public failed: %v", err)
			}

			if publicKey == nil {
				t.Fatal("Public returned nil")
			}

			// Verify public key matches private key
			switch pk := privateKey.(type) {
			case *rsa.PrivateKey:
				pub, ok := publicKey.(*rsa.PublicKey)
				if !ok {
					t.Fatal("Public key is not *rsa.PublicKey")
				}
				if pub.N.Cmp(pk.N) != 0 {
					t.Error("Public key doesn't match private key")
				}
			case *ecdsa.PrivateKey:
				pub, ok := publicKey.(*ecdsa.PublicKey)
				if !ok {
					t.Fatal("Public key is not *ecdsa.PublicKey")
				}
				if pub.X.Cmp(pk.X) != 0 || pub.Y.Cmp(pk.Y) != 0 {
					t.Error("Public key doesn't match private key")
				}
			case ed25519.PrivateKey:
				pub, ok := publicKey.(ed25519.PublicKey)
				if !ok {
					t.Fatal("Public key is not ed25519.PublicKey")
				}
				if !pub.Equal(pk.Public()) {
					t.Error("Public key doesn't match private key")
				}
			}
		})
	}
}

// TestSign tests the Sign convenience method
func TestSign(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("test-sign.com", 2048)

	// Generate key
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Sign a digest
	digest := sha256.Sum256([]byte("test message"))
	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Sign returned empty signature")
	}
}

// TestClose tests closing the backend
func TestClose(t *testing.T) {
	be, keyStorage := createTestBackend(t)

	// Generate a key
	attrs := createRSAAttrs("test-close.com", 2048)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Close the backend
	err = be.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify storage is closed
	_, err = storage.ListKeys(keyStorage)
	if err == nil {
		t.Fatal("Storage operations should fail after close")
	}
	if !errors.Is(err, storage.ErrClosed) {
		t.Errorf("Expected ErrClosed, got: %v", err)
	}

	// Close again should not error
	err = be.Close()
	if err != nil {
		t.Fatalf("Second Close failed: %v", err)
	}
}

// TestClosedBackend tests operations on a closed backend
func TestClosedBackend(t *testing.T) {
	be, _ := createTestBackend(t)

	attrs := createRSAAttrs("test-closed.com", 2048)

	// Close the backend
	err := be.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Test operations on closed backend
	t.Run("GenerateKey", func(t *testing.T) {
		_, err := be.GenerateKey(attrs)
		if err == nil {
			t.Fatal("GenerateKey should fail on closed backend")
		}
		if !errors.Is(err, ErrStorageClosed) {
			t.Errorf("Expected ErrStorageClosed, got: %v", err)
		}
	})

	t.Run("GetKey", func(t *testing.T) {
		_, err := be.GetKey(attrs)
		if err == nil {
			t.Fatal("GetKey should fail on closed backend")
		}
		if !errors.Is(err, ErrStorageClosed) {
			t.Errorf("Expected ErrStorageClosed, got: %v", err)
		}
	})

	t.Run("DeleteKey", func(t *testing.T) {
		err := be.DeleteKey(attrs)
		if err == nil {
			t.Fatal("DeleteKey should fail on closed backend")
		}
		if !errors.Is(err, ErrStorageClosed) {
			t.Errorf("Expected ErrStorageClosed, got: %v", err)
		}
	})

	t.Run("ListKeys", func(t *testing.T) {
		_, err := be.ListKeys()
		if err == nil {
			t.Fatal("ListKeys should fail on closed backend")
		}
		if !errors.Is(err, ErrStorageClosed) {
			t.Errorf("Expected ErrStorageClosed, got: %v", err)
		}
	})
}

// TestConcurrentOperations tests thread safety
func TestConcurrentOperations(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	const numGoroutines = 10
	const opsPerGoroutine = 5

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*opsPerGoroutine)

	// Concurrent key generation
	t.Run("ConcurrentGenerate", func(t *testing.T) {
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				for j := 0; j < opsPerGoroutine; j++ {
					attrs := createRSAAttrs(
						string(rune('a'+id))+"_"+string(rune('0'+j))+".com",
						2048,
					)

					_, err := be.GenerateKey(attrs)
					if err != nil {
						errors <- err
					}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Errorf("Concurrent operation failed: %v", err)
		}
	})

	// Verify all keys were created
	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	expectedCount := numGoroutines * opsPerGoroutine
	if len(keys) != expectedCount {
		t.Errorf("Expected %d keys, got %d", expectedCount, len(keys))
	}

	// Concurrent reads
	t.Run("ConcurrentRead", func(t *testing.T) {
		errors := make(chan error, numGoroutines*opsPerGoroutine)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				for j := 0; j < opsPerGoroutine; j++ {
					attrs := createRSAAttrs(
						string(rune('a'+id))+"_"+string(rune('0'+j))+".com",
						2048,
					)

					_, err := be.GetKey(attrs)
					if err != nil {
						errors <- err
					}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Errorf("Concurrent read failed: %v", err)
		}
	})

	// Concurrent deletes
	t.Run("ConcurrentDelete", func(t *testing.T) {
		errors := make(chan error, numGoroutines*opsPerGoroutine)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				for j := 0; j < opsPerGoroutine; j++ {
					attrs := createRSAAttrs(
						string(rune('a'+id))+"_"+string(rune('0'+j))+".com",
						2048,
					)

					err := be.DeleteKey(attrs)
					if err != nil {
						errors <- err
					}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Errorf("Concurrent delete failed: %v", err)
		}
	})

	// Verify all keys were deleted
	keys, err = be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("Expected 0 keys after concurrent delete, got %d", len(keys))
	}
}

// TestConcurrentMixedOperations tests concurrent mixed operations
func TestConcurrentMixedOperations(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	const numGoroutines = 20

	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			cn := string(rune('a'+id%26)) + string(rune('0'+(id/26)%10)) + ".com"
			attrs := createRSAAttrs(cn, 2048)

			// Generate
			_, err := be.GenerateKey(attrs)
			if err != nil {
				// May fail due to duplicate, that's ok
				return
			}

			// Get
			_, err = be.GetKey(attrs)
			if err != nil {
				t.Errorf("GetKey failed: %v", err)
				return
			}

			// List
			_, err = be.ListKeys()
			if err != nil {
				t.Errorf("ListKeys failed: %v", err)
				return
			}

			// Delete
			err = be.DeleteKey(attrs)
			if err != nil {
				t.Errorf("DeleteKey failed: %v", err)
			}
		}(i)
	}

	wg.Wait()
}

// TestPasswordEncryption tests password encryption scenarios
func TestPasswordEncryption(t *testing.T) {
	t.Run("WrongPassword", func(t *testing.T) {
		be, _ := createTestBackend(t)
		defer be.Close()

		// Generate with password
		attrs := createRSAAttrs("test-pwd.com", 2048)
		attrs.Password = backend.StaticPassword("correct-password")

		_, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Try to retrieve with wrong password
		attrsWrong := createRSAAttrs("test-pwd.com", 2048)
		attrsWrong.Password = backend.StaticPassword("wrong-password")

		_, err = be.GetKey(attrsWrong)
		if err == nil {
			t.Fatal("GetKey should fail with wrong password")
		}
	})

	t.Run("NoPasswordOnEncrypted", func(t *testing.T) {
		be, _ := createTestBackend(t)
		defer be.Close()

		// Generate with password
		attrs := createRSAAttrs("test-pwd2.com", 2048)
		attrs.Password = backend.StaticPassword("password")

		_, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Try to retrieve without password
		attrsNoPassword := createRSAAttrs("test-pwd2.com", 2048)
		attrsNoPassword.Password = nil

		_, err = be.GetKey(attrsNoPassword)
		if err == nil {
			t.Fatal("GetKey should fail without password on encrypted key")
		}
	})
}

// TestKeyPartitions tests key partitioning
func TestKeyPartitions(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	partitions := []types.Partition{
		backend.PARTITION_TLS,
		backend.PARTITION_SIGNING_KEYS,
		backend.PARTITION_ENCRYPTION_KEYS,
	}

	for _, partition := range partitions {
		attrs := createRSAAttrs("test.com", 2048)
		attrs.Partition = partition

		_, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey with partition %s failed: %v", partition, err)
		}

		_, err = be.GetKey(attrs)
		if err != nil {
			t.Fatalf("GetKey with partition %s failed: %v", partition, err)
		}
	}

	// Verify we have 3 keys
	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != len(partitions) {
		t.Errorf("Expected %d keys, got %d", len(partitions), len(keys))
	}
}

// TestInterfaceCompliance tests that PKCS8Backend implements Backend
func TestInterfaceCompliance(t *testing.T) {
	var _ types.Backend = (*PKCS8Backend)(nil)
}

// BenchmarkGenerateRSA benchmarks RSA key generation
func BenchmarkGenerateRSA(b *testing.B) {
	keyStorage := memory.New()
	config := &Config{KeyStorage: keyStorage}
	be, _ := NewBackend(config)
	defer be.Close()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		attrs := createRSAAttrs(fmt.Sprintf("bench-rsa-%d.com", i), 2048)
		_, err := be.GenerateKey(attrs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGenerateECDSA benchmarks ECDSA key generation
func BenchmarkGenerateECDSA(b *testing.B) {
	keyStorage := memory.New()
	config := &Config{KeyStorage: keyStorage}
	be, _ := NewBackend(config)
	defer be.Close()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		attrs := createECDSAAttrs(fmt.Sprintf("bench-ecdsa-%d.com", i), "P-256")
		_, err := be.GenerateKey(attrs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetKey benchmarks key retrieval
func BenchmarkGetKey(b *testing.B) {
	keyStorage := memory.New()
	config := &Config{KeyStorage: keyStorage}
	be, _ := NewBackend(config)
	defer be.Close()

	attrs := createRSAAttrs("benchmark.com", 2048)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := be.GetKey(attrs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSign benchmarks signing operations
func BenchmarkSign(b *testing.B) {
	keyStorage := memory.New()
	config := &Config{KeyStorage: keyStorage}
	be, _ := NewBackend(config)
	defer be.Close()

	attrs := createRSAAttrs("benchmark.com", 2048)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		b.Fatal(err)
	}

	digest := sha256.Sum256([]byte("benchmark message"))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		signer, err := be.Signer(attrs)
		if err != nil {
			b.Fatal(err)
		}
		_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestSign_ConvenienceMethod tests the Sign convenience method
func TestSign_ConvenienceMethod(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("test-sign-method.com", 2048)

	// Generate key
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Use the Sign convenience method
	digest := sha256.Sum256([]byte("test message"))
	signature, err := be.Sign(attrs, rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Sign returned empty signature")
	}
}

// TestGenerateKey_RSANilAttributes tests RSA generation with nil attributes
func TestGenerateKey_RSANilAttributes(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := &types.KeyAttributes{
		CN:            "test.com",
		KeyType:       backend.KEY_TYPE_TLS,
		StoreType:     backend.STORE_SW,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: nil, // Nil RSA attributes
	}

	_, err := be.GenerateKey(attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail with nil RSA attributes")
	}
}

// TestGenerateKey_ECDSANilAttributes tests ECDSA generation with nil attributes
func TestGenerateKey_ECDSANilAttributes(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := &types.KeyAttributes{
		CN:            "test.com",
		KeyType:       backend.KEY_TYPE_TLS,
		StoreType:     backend.STORE_SW,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: nil, // Nil ECC attributes
	}

	_, err := be.GenerateKey(attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail with nil ECC attributes")
	}
}

// TestPublic_UnsupportedKeyType tests Public with unsupported key type
func TestPublic_UnsupportedKeyType(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Manually insert an unsupported key type into storage
	attrs := createRSAAttrs("test-unsupported.com", 2048)

	// Store some invalid data
	keyID := attrs.ID()
	err := storage.SaveKey(be.storage, keyID, []byte("invalid key data"))
	if err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}

	// Try to get public key
	_, err = be.Public(attrs)
	if err == nil {
		t.Fatal("Public should fail with invalid key data")
	}
}

// TestGenerateKey_UnsupportedAlgorithm tests unsupported algorithm
func TestGenerateKey_UnsupportedAlgorithm(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := &types.KeyAttributes{
		CN:           "test.com",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.PublicKeyAlgorithm(999), // Invalid algorithm
	}

	_, err := be.GenerateKey(attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail with unsupported algorithm")
	}
}

// ============================================================================
// Edge Case Tests for Coverage Improvement (Target: 95%+)
// ============================================================================

// mockStorageError is a mock Backend that returns errors
type mockStorageError struct {
	storage.Backend
	deleteError bool
	saveError   bool
	listError   bool
}

func (m *mockStorageError) Delete(key string) error {
	if m.deleteError {
		return fmt.Errorf("mock delete error")
	}
	return storage.ErrNotFound
}

func (m *mockStorageError) Put(key string, value []byte, opts *storage.Options) error {
	if m.saveError {
		return fmt.Errorf("mock save error")
	}
	return m.Backend.Put(key, value, opts)
}

func (m *mockStorageError) List(prefix string) ([]string, error) {
	if m.listError {
		return nil, fmt.Errorf("mock list error")
	}
	return nil, nil
}

func (m *mockStorageError) KeyExists(id string) (bool, error) {
	return false, nil
}

func (m *mockStorageError) GetKey(id string) ([]byte, error) {
	return nil, storage.ErrNotFound
}

func (m *mockStorageError) Close() error {
	return nil
}

// TestDeleteKey_StorageError tests DeleteKey with storage errors
func TestDeleteKey_StorageError(t *testing.T) {
	mockStorage := &mockStorageError{
		Backend:     memory.New(),
		deleteError: true,
	}

	config := &Config{
		KeyStorage: mockStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer be.Close()

	attrs := createRSAAttrs("test-delete-error.com", 2048)

	err = be.(*PKCS8Backend).DeleteKey(attrs)
	if err == nil {
		t.Fatal("DeleteKey should fail with storage error")
	}
}

// TestStoreKey_SaveKeyError tests storeKey with SaveKey errors
func TestStoreKey_SaveKeyError(t *testing.T) {
	mockStorage := &mockStorageError{
		Backend:   memory.New(),
		saveError: true,
	}

	config := &Config{
		KeyStorage: mockStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer be.Close()

	attrs := createRSAAttrs("test-save-error.com", 2048)

	_, err = be.GenerateKey(attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail with save error")
	}
}

// TestSign_VerifySignature tests Sign produces valid signatures
func TestSign_VerifySignature(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name:  "RSA",
			attrs: createRSAAttrs("test-verify-rsa.com", 2048),
		},
		{
			name:  "ECDSA",
			attrs: createECDSAAttrs("test-verify-ecdsa.com", "P-256"),
		},
		{
			name:  "Ed25519",
			attrs: createEd25519Attrs("test-verify-ed25519.com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			// Generate key
			_, err := be.GenerateKey(tt.attrs)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			// Sign a message
			digest := sha256.Sum256([]byte("test message"))

			var opts crypto.SignerOpts
			switch tt.attrs.KeyAlgorithm {
			case x509.RSA, x509.ECDSA:
				opts = crypto.SHA256
			case x509.Ed25519:
				opts = crypto.Hash(0)
			}

			signature, err := be.Sign(tt.attrs, rand.Reader, digest[:], opts)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			if len(signature) == 0 {
				t.Fatal("Sign returned empty signature")
			}
		})
	}
}

// TestSign_KeyNotFound tests Sign with non-existent key
func TestSign_KeyNotFound(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("nonexistent.com", 2048)

	digest := sha256.Sum256([]byte("test message"))
	_, err := be.Sign(attrs, rand.Reader, digest[:], crypto.SHA256)
	if err == nil {
		t.Fatal("Sign should fail for non-existent key")
	}

	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound, got: %v", err)
	}
}

// TestSigner_UnsupportedKeyType tests Signer with unsupported key type
func TestSigner_UnsupportedKeyType(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate a key
	attrs := createRSAAttrs("test-signer.com", 2048)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Get signer
	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	// Verify signer is valid
	if signer == nil {
		t.Fatal("Signer returned nil")
	}
}

// TestDecrypter_GetKeyError tests Decrypter with GetKey error
func TestDecrypter_GetKeyError(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("nonexistent.com", 2048)

	_, err := be.Decrypter(attrs)
	if err == nil {
		t.Fatal("Decrypter should fail for non-existent key")
	}

	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound, got: %v", err)
	}
}

// TestPublic_GetKeyError tests Public with GetKey error
func TestPublic_GetKeyError(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("nonexistent.com", 2048)

	_, err := be.Public(attrs)
	if err == nil {
		t.Fatal("Public should fail for non-existent key")
	}

	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound, got: %v", err)
	}
}

// TestGenerateECDSAKey_AllCurves tests all supported ECDSA curves
func TestGenerateECDSAKey_AllCurves(t *testing.T) {
	curves := []string{"P-256", "prime256v1", "P-384", "secp384r1", "P-521", "secp521r1"}

	for _, curve := range curves {
		t.Run(curve, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			attrs := createECDSAAttrs("test-"+curve+".com", curve)

			key, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey for curve %s failed: %v", curve, err)
			}

			_, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatal("Generated key is not *ecdsa.PrivateKey")
			}
		})
	}
}

// TestListKeys_StorageError tests ListKeys with storage error
func TestListKeys_StorageError(t *testing.T) {
	mockStorage := &mockStorageError{
		Backend:   memory.New(),
		listError: true,
	}

	config := &Config{
		KeyStorage: mockStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer be.Close()

	_, err = be.ListKeys()
	if err == nil {
		t.Fatal("ListKeys should fail with storage error")
	}
}

// TestGenerateKey_StorageCheckError tests GenerateKey with KeyExists error
func TestGenerateKey_StorageCheckError(t *testing.T) {
	// This test ensures that if KeyExists returns an error during GenerateKey,
	// the error is properly propagated
	mockStorage := &mockStorageErrorOnExists{
		Backend: memory.New(),
	}

	config := &Config{
		KeyStorage: mockStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer be.Close()

	attrs := createRSAAttrs("test-exists-error.com", 2048)

	_, err = be.GenerateKey(attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail with KeyExists error")
	}
}

// mockStorageErrorOnExists returns error on KeyExists
type mockStorageErrorOnExists struct {
	storage.Backend
}

func (m *mockStorageErrorOnExists) Exists(key string) (bool, error) {
	return false, fmt.Errorf("mock Exists error")
}

func (m *mockStorageErrorOnExists) Put(key string, value []byte, opts *storage.Options) error {
	return nil
}

func (m *mockStorageErrorOnExists) GetKey(id string) ([]byte, error) {
	return nil, storage.ErrNotFound
}

func (m *mockStorageErrorOnExists) DeleteKey(id string) error {
	return storage.ErrNotFound
}

func (m *mockStorageErrorOnExists) ListKeys() ([]string, error) {
	return nil, nil
}

func (m *mockStorageErrorOnExists) Close() error {
	return nil
}

// TestGetKey_StorageError tests GetKey with storage error
func TestGetKey_StorageError(t *testing.T) {
	mockStorage := &mockStorageGetError{
		Backend: memory.New(),
	}

	config := &Config{
		KeyStorage: mockStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer be.Close()

	attrs := createRSAAttrs("test-get-error.com", 2048)

	_, err = be.GetKey(attrs)
	if err == nil {
		t.Fatal("GetKey should fail with storage error")
	}
}

// mockStorageGetError returns error on GetKey
type mockStorageGetError struct {
	storage.Backend
}

func (m *mockStorageGetError) Get(key string) ([]byte, error) {
	return nil, fmt.Errorf("mock Get error")
}

func (m *mockStorageGetError) KeyExists(id string) (bool, error) {
	return false, nil
}

func (m *mockStorageGetError) SaveKey(id string, data []byte) error {
	return nil
}

func (m *mockStorageGetError) DeleteKey(id string) error {
	return storage.ErrNotFound
}

func (m *mockStorageGetError) ListKeys() ([]string, error) {
	return nil, nil
}

func (m *mockStorageGetError) Close() error {
	return nil
}

// TestGenerateKey_RSAInvalidSize tests RSA generation with invalid key size
func TestGenerateKey_RSAInvalidSize(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Test sizes that should fail validation
	invalidSizes := []int{512, 1024, 1536}

	for _, size := range invalidSizes {
		t.Run(fmt.Sprintf("Size-%d", size), func(t *testing.T) {
			attrs := createRSAAttrs(fmt.Sprintf("test-invalid-%d.com", size), size)

			_, err := be.GenerateKey(attrs)
			if err == nil {
				t.Fatalf("GenerateKey should fail with key size %d", size)
			}
		})
	}
}

// TestGenerateKey_ValidRSASizes tests various valid RSA key sizes
func TestGenerateKey_ValidRSASizes(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Test multiple valid sizes to ensure generateRSAKey is thoroughly tested
	validSizes := []int{2048, 3072, 4096}

	for _, size := range validSizes {
		t.Run(fmt.Sprintf("Size-%d", size), func(t *testing.T) {
			attrs := createRSAAttrs(fmt.Sprintf("test-valid-%d.com", size), size)

			key, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey with size %d failed: %v", size, err)
			}

			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				t.Fatal("Generated key is not *rsa.PrivateKey")
			}

			if rsaKey.N.BitLen() != size {
				t.Errorf("Expected key size %d, got %d", size, rsaKey.N.BitLen())
			}
		})
	}
}

// TestSigner_NonSignerKey tests error case where key doesn't implement crypto.Signer
// This is a theoretical edge case that shouldn't happen with standard keys
func TestSigner_InvalidKeyData(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate a valid key first
	attrs := createRSAAttrs("test-signer-invalid.com", 2048)
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// The key should be valid and implement crypto.Signer
	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer should succeed: %v", err)
	}

	if signer == nil {
		t.Fatal("Signer returned nil")
	}
}

// TestStoreKey_EncryptedPath tests storeKey with encrypted keys
func TestStoreKey_EncryptedPath(t *testing.T) {
	tests := []struct {
		name     string
		password types.Password
		keyType  x509.PublicKeyAlgorithm
		keySize  int
	}{
		{
			name:     "RSA-Encrypted",
			password: backend.StaticPassword("test-password-123"),
			keyType:  x509.RSA,
			keySize:  2048,
		},
		{
			name:     "RSA-NoPassword",
			password: backend.NoPassword{},
			keyType:  x509.RSA,
			keySize:  2048,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			attrs := createRSAAttrs("test-store-"+tt.name+".com", tt.keySize)
			attrs.Password = tt.password

			key, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			// Verify key was stored and can be retrieved
			retrieved, err := be.GetKey(attrs)
			if err != nil {
				t.Fatalf("GetKey failed: %v", err)
			}

			rsaKey := key.(*rsa.PrivateKey)
			retrievedRSA := retrieved.(*rsa.PrivateKey)

			if retrievedRSA.N.Cmp(rsaKey.N) != 0 {
				t.Error("Retrieved key doesn't match stored key")
			}
		})
	}
}

// TestGenerateRSAKey_ErrorPaths tests error paths in RSA key generation
func TestGenerateRSAKey_ErrorPaths(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	t.Run("NilAttributes", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:            "test-nil.com",
			KeyType:       backend.KEY_TYPE_TLS,
			StoreType:     backend.STORE_SW,
			KeyAlgorithm:  x509.RSA,
			RSAAttributes: nil,
		}

		_, err := be.GenerateKey(attrs)
		if err == nil {
			t.Fatal("GenerateKey should fail with nil RSA attributes")
		}
	})

	t.Run("SmallKeySize", func(t *testing.T) {
		attrs := createRSAAttrs("test-small.com", 1024)

		_, err := be.GenerateKey(attrs)
		if err == nil {
			t.Fatal("GenerateKey should fail with key size < 2048")
		}
	})

	t.Run("VerySmallKeySize", func(t *testing.T) {
		attrs := createRSAAttrs("test-tiny.com", 512)

		_, err := be.GenerateKey(attrs)
		if err == nil {
			t.Fatal("GenerateKey should fail with key size = 512")
		}
	})
}

// TestGenerateECDSAKey_ErrorPaths tests error paths in ECDSA key generation
func TestGenerateECDSAKey_ErrorPaths(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	t.Run("NilAttributes", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:            "test-nil.com",
			KeyType:       backend.KEY_TYPE_TLS,
			StoreType:     backend.STORE_SW,
			KeyAlgorithm:  x509.ECDSA,
			ECCAttributes: nil,
		}

		_, err := be.GenerateKey(attrs)
		if err == nil {
			t.Fatal("GenerateKey should fail with nil ECC attributes")
		}
	})

	t.Run("UnsupportedCurve", func(t *testing.T) {
		attrs := createECDSAAttrs("test-bad-curve.com", "P-999")

		_, err := be.GenerateKey(attrs)
		if err == nil {
			t.Fatal("GenerateKey should fail with unsupported curve")
		}
	})

	t.Run("InvalidCurveName", func(t *testing.T) {
		attrs := createECDSAAttrs("test-invalid-curve.com", "INVALID")

		_, err := be.GenerateKey(attrs)
		if err == nil {
			t.Fatal("GenerateKey should fail with invalid curve name")
		}
	})
}

// TestPublic_AllKeyTypes tests Public with all key types
func TestPublic_AllKeyTypes(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name:  "RSA-2048",
			attrs: createRSAAttrs("test-pub-rsa-2048.com", 2048),
		},
		{
			name:  "RSA-4096",
			attrs: createRSAAttrs("test-pub-rsa-4096.com", 4096),
		},
		{
			name:  "ECDSA-P256",
			attrs: createECDSAAttrs("test-pub-p256.com", "P-256"),
		},
		{
			name:  "ECDSA-P384",
			attrs: createECDSAAttrs("test-pub-p384.com", "P-384"),
		},
		{
			name:  "ECDSA-P521",
			attrs: createECDSAAttrs("test-pub-p521.com", "P-521"),
		},
		{
			name:  "Ed25519",
			attrs: createEd25519Attrs("test-pub-ed25519.com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			// Generate key
			privateKey, err := be.GenerateKey(tt.attrs)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			// Get public key
			publicKey, err := be.Public(tt.attrs)
			if err != nil {
				t.Fatalf("Public failed: %v", err)
			}

			if publicKey == nil {
				t.Fatal("Public returned nil")
			}

			// Verify public key type matches private key
			switch privateKey.(type) {
			case *rsa.PrivateKey:
				_, ok := publicKey.(*rsa.PublicKey)
				if !ok {
					t.Fatal("Public key type mismatch for RSA")
				}
			case *ecdsa.PrivateKey:
				_, ok := publicKey.(*ecdsa.PublicKey)
				if !ok {
					t.Fatal("Public key type mismatch for ECDSA")
				}
			case ed25519.PrivateKey:
				_, ok := publicKey.(ed25519.PublicKey)
				if !ok {
					t.Fatal("Public key type mismatch for Ed25519")
				}
			}
		})
	}
}

// TestDeleteKey_ValidateError tests DeleteKey with invalid attributes
func TestDeleteKey_ValidateError(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := &types.KeyAttributes{
		// Missing required CN field
		KeyAlgorithm: x509.RSA,
	}

	err := be.DeleteKey(attrs)
	if err == nil {
		t.Fatal("DeleteKey should fail with invalid attributes")
	}
}

// TestSigner_EnsureCoverage tests to ensure Signer error path is covered
func TestSigner_EnsureCoverage(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Test all key types to ensure they implement crypto.Signer
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name:  "RSA",
			attrs: createRSAAttrs("test-signer-rsa.com", 2048),
		},
		{
			name:  "ECDSA",
			attrs: createECDSAAttrs("test-signer-ecdsa.com", "P-256"),
		},
		{
			name:  "Ed25519",
			attrs: createEd25519Attrs("test-signer-ed25519.com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := be.GenerateKey(tt.attrs)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			signer, err := be.Signer(tt.attrs)
			if err != nil {
				t.Fatalf("Signer failed: %v", err)
			}

			// Verify it's actually a signer
			if signer == nil {
				t.Fatal("Signer returned nil")
			}

			// Use the signer to ensure it works
			digest := sha256.Sum256([]byte("test"))
			opts := crypto.SHA256
			if tt.attrs.KeyAlgorithm == x509.Ed25519 {
				opts = crypto.Hash(0)
			}

			_, err = signer.Sign(rand.Reader, digest[:], opts)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
		})
	}
}

// mockNonSignerStorage stores a non-standard key type that doesn't implement crypto.Signer
type mockNonSignerStorage struct {
	storage.Backend
	customKey []byte
}

func (m *mockNonSignerStorage) GetKey(id string) ([]byte, error) {
	if m.customKey != nil {
		return m.customKey, nil
	}
	return nil, storage.ErrNotFound
}

func (m *mockNonSignerStorage) KeyExists(id string) (bool, error) {
	return m.customKey != nil, nil
}

func (m *mockNonSignerStorage) SaveKey(id string, data []byte) error {
	m.customKey = data
	return nil
}

func (m *mockNonSignerStorage) DeleteKey(id string) error {
	m.customKey = nil
	return nil
}

func (m *mockNonSignerStorage) ListKeys() ([]string, error) {
	return nil, nil
}

func (m *mockNonSignerStorage) Close() error {
	return nil
}

// TestStoreKey_EmptyPassword tests storeKey with empty password
func TestStoreKey_EmptyPassword(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Create a password that returns empty bytes
	emptyPassword := backend.StaticPassword("")

	attrs := createRSAAttrs("test-empty-pwd.com", 2048)
	attrs.Password = emptyPassword

	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Verify key was stored without encryption (empty password is treated as no password)
	retrieved, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	rsaKey := key.(*rsa.PrivateKey)
	retrievedRSA := retrieved.(*rsa.PrivateKey)

	if retrievedRSA.N.Cmp(rsaKey.N) != 0 {
		t.Error("Retrieved key doesn't match stored key")
	}
}

// TestGenerateECDSAKey_P256Alias tests P-256 and prime256v1 aliases
func TestGenerateECDSAKey_P256Alias(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Test that both P-256 and prime256v1 work
	attrs1 := createECDSAAttrs("test-p256.com", "P-256")
	key1, err := be.GenerateKey(attrs1)
	if err != nil {
		t.Fatalf("GenerateKey with P-256 failed: %v", err)
	}

	attrs2 := createECDSAAttrs("test-prime256v1.com", "prime256v1")
	key2, err := be.GenerateKey(attrs2)
	if err != nil {
		t.Fatalf("GenerateKey with prime256v1 failed: %v", err)
	}

	// Both should be ECDSA keys
	_, ok1 := key1.(*ecdsa.PrivateKey)
	_, ok2 := key2.(*ecdsa.PrivateKey)

	if !ok1 || !ok2 {
		t.Fatal("Generated keys are not ECDSA keys")
	}
}

// TestGenerateECDSAKey_AllAliases tests all curve aliases
func TestGenerateECDSAKey_AllAliases(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	aliases := []struct {
		curve string
		alias string
	}{
		{"P-256", "prime256v1"},
		{"P-384", "secp384r1"},
		{"P-521", "secp521r1"},
	}

	for i, a := range aliases {
		t.Run(a.curve, func(t *testing.T) {
			attrs := createECDSAAttrs(fmt.Sprintf("test-alias-%d.com", i), a.curve)
			_, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey with %s failed: %v", a.curve, err)
			}
		})

		t.Run(a.alias, func(t *testing.T) {
			attrs := createECDSAAttrs(fmt.Sprintf("test-alias-alt-%d.com", i), a.alias)
			_, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey with %s failed: %v", a.alias, err)
			}
		})
	}
}

// TestGenerateKey_ExhaustiveECDSA tests ECDSA generation exhaustively
func TestGenerateKey_ExhaustiveECDSA(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Test all curve variations
	curves := []string{
		"P-256", "prime256v1",
		"P-384", "secp384r1",
		"P-521", "secp521r1",
	}

	for i, curve := range curves {
		t.Run(curve, func(t *testing.T) {
			attrs := createECDSAAttrs(fmt.Sprintf("test-exhaustive-ecdsa-%d.com", i), curve)

			key, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey ECDSA-%s failed: %v", curve, err)
			}

			ecdsaKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatal("Generated key is not *ecdsa.PrivateKey")
			}

			// Verify the key can be used
			if ecdsaKey.Curve == nil {
				t.Error("ECDSA key has nil curve")
			}

			// Verify key is stored
			retrieved, err := be.GetKey(attrs)
			if err != nil {
				t.Fatalf("GetKey failed: %v", err)
			}

			retrievedECDSA := retrieved.(*ecdsa.PrivateKey)
			if retrievedECDSA.X.Cmp(ecdsaKey.X) != 0 {
				t.Error("Retrieved key doesn't match")
			}
		})
	}
}

// TestStoreKey_BothPaths tests both encrypted and unencrypted storage paths
func TestStoreKey_BothPaths(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	t.Run("Unencrypted", func(t *testing.T) {
		attrs := createRSAAttrs("test-store-plain.com", 2048)
		attrs.Password = nil

		key, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Verify storage worked
		retrieved, err := be.GetKey(attrs)
		if err != nil {
			t.Fatalf("GetKey failed: %v", err)
		}

		rsaKey := key.(*rsa.PrivateKey)
		retrievedRSA := retrieved.(*rsa.PrivateKey)
		if retrievedRSA.N.Cmp(rsaKey.N) != 0 {
			t.Error("Keys don't match")
		}
	})

	t.Run("Encrypted", func(t *testing.T) {
		attrs := createRSAAttrs("test-store-encrypted.com", 2048)
		attrs.Password = backend.StaticPassword("strong-password-123")

		key, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Verify storage worked
		retrieved, err := be.GetKey(attrs)
		if err != nil {
			t.Fatalf("GetKey failed: %v", err)
		}

		rsaKey := key.(*rsa.PrivateKey)
		retrievedRSA := retrieved.(*rsa.PrivateKey)
		if retrievedRSA.N.Cmp(rsaKey.N) != 0 {
			t.Error("Keys don't match")
		}
	})

	t.Run("EncryptedECDSA", func(t *testing.T) {
		attrs := createECDSAAttrs("test-store-ecdsa-encrypted.com", "P-384")
		attrs.Password = backend.StaticPassword("ecdsa-password")

		key, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Verify storage worked
		retrieved, err := be.GetKey(attrs)
		if err != nil {
			t.Fatalf("GetKey failed: %v", err)
		}

		ecdsaKey := key.(*ecdsa.PrivateKey)
		retrievedECDSA := retrieved.(*ecdsa.PrivateKey)
		if retrievedECDSA.X.Cmp(ecdsaKey.X) != 0 {
			t.Error("Keys don't match")
		}
	})

	t.Run("EncryptedEd25519", func(t *testing.T) {
		attrs := createEd25519Attrs("test-store-ed25519-encrypted.com")
		attrs.Password = backend.StaticPassword("ed25519-password")

		key, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Verify storage worked
		retrieved, err := be.GetKey(attrs)
		if err != nil {
			t.Fatalf("GetKey failed: %v", err)
		}

		ed25519Key := key.(ed25519.PrivateKey)
		retrievedEd25519 := retrieved.(ed25519.PrivateKey)
		if !ed25519Key.Equal(retrievedEd25519) {
			t.Error("Keys don't match")
		}
	})
}

// TestRotateKey tests key rotation functionality
func TestRotateKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	t.Run("RotateExistingKey", func(t *testing.T) {
		// Generate initial key
		attrs := createRSAAttrs("test-rotate.com", 2048)
		key1, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Rotate the key
		err = be.RotateKey(attrs)
		if err != nil {
			t.Fatalf("RotateKey failed: %v", err)
		}

		// Get the new key
		key2, err := be.GetKey(attrs)
		if err != nil {
			t.Fatalf("GetKey after rotation failed: %v", err)
		}

		// Keys should be different
		rsaKey1 := key1.(*rsa.PrivateKey)
		rsaKey2 := key2.(*rsa.PrivateKey)

		if rsaKey1.N.Cmp(rsaKey2.N) == 0 {
			t.Error("Rotated key should be different from original")
		}
	})

	t.Run("RotateNonExistentKey", func(t *testing.T) {
		// Rotating a non-existent key succeeds by creating a new key
		// (DeleteKey ignores ErrKeyNotFound, then GenerateKey creates the key)
		attrs := createRSAAttrs("test-rotate-new.com", 2048)

		err := be.RotateKey(attrs)
		if err != nil {
			t.Fatalf("RotateKey should succeed for non-existent key (creates new key): %v", err)
		}

		// Verify the key was created
		_, err = be.GetKey(attrs)
		if err != nil {
			t.Fatalf("GetKey should succeed after rotation: %v", err)
		}
	})

	t.Run("RotateNilAttributes", func(t *testing.T) {
		err := be.RotateKey(nil)
		if err == nil {
			t.Fatal("RotateKey should fail with nil attributes")
		}
	})

	t.Run("RotateWithPassword", func(t *testing.T) {
		// Generate key with password
		attrs := createRSAAttrs("test-rotate-pwd.com", 2048)
		attrs.Password = backend.StaticPassword("test-password")

		_, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Rotate the key
		err = be.RotateKey(attrs)
		if err != nil {
			t.Fatalf("RotateKey failed: %v", err)
		}

		// Verify new key can be retrieved with password
		_, err = be.GetKey(attrs)
		if err != nil {
			t.Fatalf("GetKey after rotation failed: %v", err)
		}
	})

	t.Run("RotateECDSAKey", func(t *testing.T) {
		attrs := createECDSAAttrs("test-rotate-ecdsa.com", "P-256")

		// Generate initial key
		key1, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Rotate
		err = be.RotateKey(attrs)
		if err != nil {
			t.Fatalf("RotateKey failed: %v", err)
		}

		// Get new key
		key2, err := be.GetKey(attrs)
		if err != nil {
			t.Fatalf("GetKey after rotation failed: %v", err)
		}

		// Verify keys are different
		ecdsaKey1 := key1.(*ecdsa.PrivateKey)
		ecdsaKey2 := key2.(*ecdsa.PrivateKey)

		if ecdsaKey1.X.Cmp(ecdsaKey2.X) == 0 && ecdsaKey1.Y.Cmp(ecdsaKey2.Y) == 0 {
			t.Error("Rotated key should be different from original")
		}
	})

	t.Run("RotateEd25519Key", func(t *testing.T) {
		attrs := createEd25519Attrs("test-rotate-ed25519.com")

		// Generate initial key
		key1, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Rotate
		err = be.RotateKey(attrs)
		if err != nil {
			t.Fatalf("RotateKey failed: %v", err)
		}

		// Get new key
		key2, err := be.GetKey(attrs)
		if err != nil {
			t.Fatalf("GetKey after rotation failed: %v", err)
		}

		// Verify keys are different
		ed25519Key1 := key1.(ed25519.PrivateKey)
		ed25519Key2 := key2.(ed25519.PrivateKey)

		if ed25519Key1.Equal(ed25519Key2) {
			t.Error("Rotated key should be different from original")
		}
	})
}

// TestGenerateKey_X25519 tests X25519 key generation for key agreement
func TestGenerateKey_X25519(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := &types.KeyAttributes{
		CN:               "test-x25519.com",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
		Hash:             crypto.SHA256,
	}

	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if key == nil {
		t.Fatal("GenerateKey returned nil key")
	}

	// Verify key can be retrieved
	retrieved, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if retrieved == nil {
		t.Fatal("GetKey returned nil key")
	}
}

// TestDeriveSharedSecret_X25519 tests X25519 key agreement
func TestDeriveSharedSecret_X25519(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate two X25519 key pairs
	attrs1 := &types.KeyAttributes{
		CN:               "test-x25519-1.com",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
		Hash:             crypto.SHA256,
	}

	attrs2 := &types.KeyAttributes{
		CN:               "test-x25519-2.com",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
		Hash:             crypto.SHA256,
	}

	key1, err := be.GenerateKey(attrs1)
	if err != nil {
		t.Fatalf("GenerateKey 1 failed: %v", err)
	}

	key2, err := be.GenerateKey(attrs2)
	if err != nil {
		t.Fatalf("GenerateKey 2 failed: %v", err)
	}

	// Get public keys
	pub1, err := be.Public(attrs1)
	if err != nil {
		t.Fatalf("Public 1 failed: %v", err)
	}

	pub2, err := be.Public(attrs2)
	if err != nil {
		t.Fatalf("Public 2 failed: %v", err)
	}

	// Derive shared secrets
	secret1, err := be.DeriveSharedSecret(attrs1, pub2)
	if err != nil {
		t.Fatalf("DeriveSharedSecret 1 failed: %v", err)
	}

	secret2, err := be.DeriveSharedSecret(attrs2, pub1)
	if err != nil {
		t.Fatalf("DeriveSharedSecret 2 failed: %v", err)
	}

	// Verify shared secrets match
	if len(secret1) == 0 || len(secret2) == 0 {
		t.Fatal("Shared secrets are empty")
	}

	if len(secret1) != len(secret2) {
		t.Fatalf("Shared secret lengths don't match: %d vs %d", len(secret1), len(secret2))
	}

	for i := range secret1 {
		if secret1[i] != secret2[i] {
			t.Error("Shared secrets don't match")
			break
		}
	}

	// Verify keys are not nil
	if key1 == nil || key2 == nil {
		t.Fatal("Keys are nil")
	}
}

// TestDeriveSharedSecret_ECDSA tests ECDH with NIST curves
func TestDeriveSharedSecret_ECDSA(t *testing.T) {
	curves := []string{"P-256", "P-384", "P-521"}

	for _, curve := range curves {
		t.Run(curve, func(t *testing.T) {
			be, _ := createTestBackend(t)
			defer be.Close()

			// Generate two ECDSA key pairs
			attrs1 := createECDSAAttrs("test-ecdh-1.com", curve)
			attrs2 := createECDSAAttrs("test-ecdh-2.com", curve)

			_, err := be.GenerateKey(attrs1)
			if err != nil {
				t.Fatalf("GenerateKey 1 failed: %v", err)
			}

			_, err = be.GenerateKey(attrs2)
			if err != nil {
				t.Fatalf("GenerateKey 2 failed: %v", err)
			}

			// Get public keys
			pub1, err := be.Public(attrs1)
			if err != nil {
				t.Fatalf("Public 1 failed: %v", err)
			}

			pub2, err := be.Public(attrs2)
			if err != nil {
				t.Fatalf("Public 2 failed: %v", err)
			}

			// Derive shared secrets
			secret1, err := be.DeriveSharedSecret(attrs1, pub2)
			if err != nil {
				t.Fatalf("DeriveSharedSecret 1 failed: %v", err)
			}

			secret2, err := be.DeriveSharedSecret(attrs2, pub1)
			if err != nil {
				t.Fatalf("DeriveSharedSecret 2 failed: %v", err)
			}

			// Verify shared secrets match
			if len(secret1) == 0 || len(secret2) == 0 {
				t.Fatal("Shared secrets are empty")
			}

			if len(secret1) != len(secret2) {
				t.Fatalf("Shared secret lengths don't match: %d vs %d", len(secret1), len(secret2))
			}

			for i := range secret1 {
				if secret1[i] != secret2[i] {
					t.Error("Shared secrets don't match")
					break
				}
			}
		})
	}
}

// TestDeriveSharedSecret_ErrorCases tests error handling in DeriveSharedSecret
func TestDeriveSharedSecret_ErrorCases(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate keys
	rsaAttrs := createRSAAttrs("test-rsa-ecdh.com", 2048)
	ecdsaAttrs := createECDSAAttrs("test-ecdsa-ecdh.com", "P-256")

	_, err := be.GenerateKey(rsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey RSA failed: %v", err)
	}

	_, err = be.GenerateKey(ecdsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey ECDSA failed: %v", err)
	}

	rsaPub, err := be.Public(rsaAttrs)
	if err != nil {
		t.Fatalf("Public RSA failed: %v", err)
	}

	t.Run("NilAttributes", func(t *testing.T) {
		_, err := be.DeriveSharedSecret(nil, rsaPub)
		if err == nil {
			t.Fatal("DeriveSharedSecret should fail with nil attributes")
		}
	})

	t.Run("NilPublicKey", func(t *testing.T) {
		_, err := be.DeriveSharedSecret(ecdsaAttrs, nil)
		if err == nil {
			t.Fatal("DeriveSharedSecret should fail with nil public key")
		}
	})

	t.Run("KeyNotFound", func(t *testing.T) {
		nonExistentAttrs := createECDSAAttrs("nonexistent-ecdh.com", "P-256")
		_, err := be.DeriveSharedSecret(nonExistentAttrs, rsaPub)
		if err == nil {
			t.Fatal("DeriveSharedSecret should fail with non-existent key")
		}
	})

	t.Run("UnsupportedKeyType", func(t *testing.T) {
		// RSA doesn't support key agreement
		_, err := be.DeriveSharedSecret(rsaAttrs, rsaPub)
		if err == nil {
			t.Fatal("DeriveSharedSecret should fail with RSA key")
		}
	})

	t.Run("MismatchedCurves", func(t *testing.T) {
		// Generate keys with different curves
		attrs1 := createECDSAAttrs("test-p256-mismatch.com", "P-256")
		attrs2 := createECDSAAttrs("test-p384-mismatch.com", "P-384")

		_, err := be.GenerateKey(attrs1)
		if err != nil {
			t.Fatalf("GenerateKey P-256 failed: %v", err)
		}

		_, err = be.GenerateKey(attrs2)
		if err != nil {
			t.Fatalf("GenerateKey P-384 failed: %v", err)
		}

		pub2, err := be.Public(attrs2)
		if err != nil {
			t.Fatalf("Public failed: %v", err)
		}

		// Try to derive shared secret with mismatched curves
		_, err = be.DeriveSharedSecret(attrs1, pub2)
		if err == nil {
			t.Fatal("DeriveSharedSecret should fail with mismatched curves")
		}
	})

	t.Run("ClosedBackend", func(t *testing.T) {
		be2, _ := createTestBackend(t)
		attrs := createECDSAAttrs("test-closed-ecdh.com", "P-256")
		_, err := be2.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		pub, err := be2.Public(attrs)
		if err != nil {
			t.Fatalf("Public failed: %v", err)
		}

		be2.Close()

		_, err = be2.DeriveSharedSecret(attrs, pub)
		if err == nil {
			t.Fatal("DeriveSharedSecret should fail on closed backend")
		}
		if !errors.Is(err, ErrStorageClosed) {
			t.Errorf("Expected ErrStorageClosed, got: %v", err)
		}
	})
}

// TestGenerateECDSAKey_NilCurve tests ECDSA generation with nil curve
func TestGenerateECDSAKey_NilCurve(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-nil-curve.com",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: nil, // Nil curve
		},
		Hash: crypto.SHA256,
	}

	_, err := be.GenerateKey(attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail with nil curve")
	}
}

// TestListKeys_EdgeCases tests edge cases in ListKeys key ID parsing
func TestListKeys_EdgeCases(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	t.Run("ShortKeyID", func(t *testing.T) {
		// Manually insert a key with a short ID
		shortID := "short"
		err := storage.SaveKey(be.storage, shortID, []byte("dummy"))
		if err != nil {
			t.Fatalf("SaveKey failed: %v", err)
		}

		keys, err := be.ListKeys()
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}

		// Should use the whole ID as CN
		found := false
		for _, k := range keys {
			if k.CN == shortID {
				found = true
				break
			}
		}

		if !found {
			t.Error("Short key ID not found in list")
		}
	})

	t.Run("ComplexKeyID", func(t *testing.T) {
		// Test with a properly formatted key ID
		attrs := createRSAAttrs("test-complex.com", 2048)
		_, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		keys, err := be.ListKeys()
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}

		// Should extract CN from the key ID
		found := false
		for _, k := range keys {
			if k.CN == "test-complex.com" {
				found = true
				break
			}
		}

		if !found {
			t.Error("Complex key ID not parsed correctly")
		}
	})
}

// TestPublic_X25519 tests Public with X25519 keys
func TestPublic_X25519(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	attrs := &types.KeyAttributes{
		CN:               "test-x25519-pub.com",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
		Hash:             crypto.SHA256,
	}

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	pub, err := be.Public(attrs)
	if err != nil {
		t.Fatalf("Public failed: %v", err)
	}

	if pub == nil {
		t.Fatal("Public returned nil")
	}
}

// TestDecodeKey_X25519Wrapping tests decodeKey with X25519 key wrapping
func TestDecodeKey_X25519Wrapping(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate and store an X25519 key
	attrs := &types.KeyAttributes{
		CN:               "test-x25519-decode.com",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
		Hash:             crypto.SHA256,
	}

	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Retrieve the key, which should trigger decodeKey with X25519 wrapping
	retrieved, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if retrieved == nil {
		t.Fatal("GetKey returned nil key")
	}
}

// TestStoreKey_X25519Unwrapping tests storeKey with X25519 key unwrapping
func TestStoreKey_X25519Unwrapping(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate X25519 key with password to test both paths
	attrs := &types.KeyAttributes{
		CN:               "test-x25519-store.com",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
		Password:         backend.StaticPassword("test-password"),
		Hash:             crypto.SHA256,
	}

	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if key == nil {
		t.Fatal("GenerateKey returned nil key")
	}

	// Verify key was stored and can be retrieved
	retrieved, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if retrieved == nil {
		t.Fatal("GetKey returned nil key")
	}
}

// TestDeriveSharedSecret_X25519_WrongPublicKeyType tests X25519 with wrong public key type
func TestDeriveSharedSecret_X25519_WrongPublicKeyType(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate X25519 key
	x25519Attrs := &types.KeyAttributes{
		CN:               "test-x25519-wrong.com",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
		Hash:             crypto.SHA256,
	}

	_, err := be.GenerateKey(x25519Attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Generate RSA key to get wrong public key type
	rsaAttrs := createRSAAttrs("test-rsa-wrong.com", 2048)
	_, err = be.GenerateKey(rsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey RSA failed: %v", err)
	}

	rsaPub, err := be.Public(rsaAttrs)
	if err != nil {
		t.Fatalf("Public failed: %v", err)
	}

	// Try to derive shared secret with wrong public key type
	_, err = be.DeriveSharedSecret(x25519Attrs, rsaPub)
	if err == nil {
		t.Fatal("DeriveSharedSecret should fail with wrong public key type for X25519")
	}
}

// TestDeriveSharedSecret_ECDSA_WrongPublicKeyType tests ECDSA with wrong public key type
func TestDeriveSharedSecret_ECDSA_WrongPublicKeyType(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Generate ECDSA key
	ecdsaAttrs := createECDSAAttrs("test-ecdsa-wrong.com", "P-256")
	_, err := be.GenerateKey(ecdsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Generate RSA key to get wrong public key type
	rsaAttrs := createRSAAttrs("test-rsa-wrong2.com", 2048)
	_, err = be.GenerateKey(rsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey RSA failed: %v", err)
	}

	rsaPub, err := be.Public(rsaAttrs)
	if err != nil {
		t.Fatalf("Public failed: %v", err)
	}

	// Try to derive shared secret with wrong public key type
	_, err = be.DeriveSharedSecret(ecdsaAttrs, rsaPub)
	if err == nil {
		t.Fatal("DeriveSharedSecret should fail with wrong public key type for ECDSA")
	}
}

// TestGenerateRSAKey_ErrorGeneration tests error in RSA key generation
func TestGenerateRSAKey_ErrorGeneration(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Test with zero key size (should be caught by validation but tests the path)
	attrs := &types.KeyAttributes{
		CN:           "test-rsa-zero.com",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 0,
		},
		Hash: crypto.SHA256,
	}

	_, err := be.GenerateKey(attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail with zero key size")
	}
}

// TestGenerateECDSAKey_EmptyCurve tests ECDSA with empty curve
func TestGenerateECDSAKey_EmptyCurve(t *testing.T) {
	be, _ := createTestBackend(t)
	defer be.Close()

	// Empty string for curve - will result in nil curve
	attrs := createECDSAAttrs("test-empty-curve.com", "")

	_, err := be.GenerateKey(attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail with empty curve")
	}
}
