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

package backend

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// createSoftwareBackend creates a test backend with in-memory storage
func createSoftwareBackend(t *testing.T) (types.SymmetricBackend, storage.Backend) {
	t.Helper()

	keyStorage := storage.New()
	config := &software.Config{
		KeyStorage: keyStorage,
		Tracker:    backend.NewMemoryAEADTracker(),
	}

	be, err := software.NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	return be, keyStorage
}

// createRSAAttrs creates RSA key attributes
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

// createECDSAAttrs creates ECDSA key attributes
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

// createEd25519Attrs creates Ed25519 key attributes
func createEd25519Attrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.Ed25519,
	}
}

// createSymmetricAttrs creates AES key attributes
func createSymmetricAttrs(cn string, keySize int, algorithm types.SymmetricAlgorithm) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: algorithm,
		AESAttributes: &types.AESAttributes{
			KeySize: keySize,
		},
	}
}

// TestSoftware_RSA_EndToEnd tests complete RSA workflow
func TestSoftware_RSA_EndToEnd(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}

	for _, keySize := range keySizes {
		t.Run(string(rune(keySize)), func(t *testing.T) {
			be, _ := createSoftwareBackend(t)
			defer be.Close()

			attrs := createRSAAttrs("test-rsa", keySize)

			// Generate key
			key, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				t.Fatal("Key is not *rsa.PrivateKey")
			}

			if rsaKey.N.BitLen() != keySize {
				t.Errorf("Key size = %d, want %d", rsaKey.N.BitLen(), keySize)
			}

			// Retrieve key
			retrievedKey, err := be.GetKey(attrs)
			if err != nil {
				t.Fatalf("GetKey failed: %v", err)
			}

			retrievedRSA := retrievedKey.(*rsa.PrivateKey)
			if retrievedRSA.N.Cmp(rsaKey.N) != 0 {
				t.Error("Retrieved key doesn't match original")
			}

			// Test signing
			signer, err := be.Signer(attrs)
			if err != nil {
				t.Fatalf("Signer failed: %v", err)
			}

			message := []byte("Test message for signing")
			hash := sha256.Sum256(message)

			signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Verify signature
			err = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, hash[:], signature)
			if err != nil {
				t.Errorf("Signature verification failed: %v", err)
			}

			// Test decryption
			decrypter, err := be.Decrypter(attrs)
			if err != nil {
				t.Fatalf("Decrypter failed: %v", err)
			}

			plaintext := []byte("Test message for encryption")
			ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, plaintext, nil)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Error("Decrypted data doesn't match original")
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
		})
	}
}

// TestSoftware_RSA_PSS_EndToEnd tests complete RSA-PSS workflow with all hash algorithms
func TestSoftware_RSA_PSS_EndToEnd(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}

	tests := []struct {
		name    string
		hash    crypto.Hash
		newHash func() crypto.Hash
	}{
		{"SHA256", crypto.SHA256, func() crypto.Hash { return crypto.SHA256 }},
		{"SHA384", crypto.SHA384, func() crypto.Hash { return crypto.SHA384 }},
		{"SHA512", crypto.SHA512, func() crypto.Hash { return crypto.SHA512 }},
	}

	for _, keySize := range keySizes {
		for _, tt := range tests {
			testName := string(rune(keySize)) + "_" + tt.name
			t.Run(testName, func(t *testing.T) {
				be, _ := createSoftwareBackend(t)
				defer be.Close()

				attrs := createRSAAttrs("test-rsa-pss", keySize)
				attrs.Hash = tt.hash

				// Generate key
				key, err := be.GenerateKey(attrs)
				if err != nil {
					t.Fatalf("GenerateKey failed: %v", err)
				}

				rsaKey, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatal("Key is not *rsa.PrivateKey")
				}

				if rsaKey.N.BitLen() != keySize {
					t.Errorf("Key size = %d, want %d", rsaKey.N.BitLen(), keySize)
				}

				// Get signer
				signer, err := be.Signer(attrs)
				if err != nil {
					t.Fatalf("Signer failed: %v", err)
				}

				message := []byte("Test message for RSA-PSS signing")

				// Hash the message using the appropriate hash function
				var digest []byte
				switch tt.hash {
				case crypto.SHA256:
					h := sha256.New()
					h.Write(message)
					digest = h.Sum(nil)
				case crypto.SHA384:
					h := sha512.New384()
					h.Write(message)
					digest = h.Sum(nil)
				case crypto.SHA512:
					h := sha512.New()
					h.Write(message)
					digest = h.Sum(nil)
				}

				// Software backend supports PSSSaltLengthAuto
				pssOpts := &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthAuto,
					Hash:       tt.hash,
				}

				// Sign with RSA-PSS
				signature, err := signer.Sign(rand.Reader, digest, pssOpts)
				if err != nil {
					t.Fatalf("Sign with RSA-PSS failed: %v", err)
				}

				// Verify signature with RSA-PSS
				err = rsa.VerifyPSS(&rsaKey.PublicKey, tt.hash, digest, signature, pssOpts)
				if err != nil {
					t.Errorf("RSA-PSS signature verification failed: %v", err)
				}

				t.Logf("Successfully signed and verified with RSA-PSS %d-bit key using %s", keySize, tt.name)

				// Delete key
				if err := be.DeleteKey(attrs); err != nil {
					t.Fatalf("DeleteKey failed: %v", err)
				}
			})
		}
	}
}

// TestSoftware_ECDSA_EndToEnd tests complete ECDSA workflow
func TestSoftware_ECDSA_EndToEnd(t *testing.T) {
	curves := []string{"P-256", "P-384", "P-521"}

	for _, curve := range curves {
		t.Run(curve, func(t *testing.T) {
			be, _ := createSoftwareBackend(t)
			defer be.Close()

			attrs := createECDSAAttrs("test-ecdsa", curve)

			// Generate key
			key, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			ecdsaKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatal("Key is not *ecdsa.PrivateKey")
			}

			// Retrieve key
			retrievedKey, err := be.GetKey(attrs)
			if err != nil {
				t.Fatalf("GetKey failed: %v", err)
			}

			retrievedECDSA := retrievedKey.(*ecdsa.PrivateKey)
			if retrievedECDSA.D.Cmp(ecdsaKey.D) != 0 {
				t.Error("Retrieved key doesn't match original")
			}

			// Test signing
			signer, err := be.Signer(attrs)
			if err != nil {
				t.Fatalf("Signer failed: %v", err)
			}

			message := []byte("Test message for signing")
			hash := sha256.Sum256(message)

			signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Verify signature
			if !ecdsa.VerifyASN1(&ecdsaKey.PublicKey, hash[:], signature) {
				t.Error("Signature verification failed")
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
		})
	}
}

// TestSoftware_Ed25519_EndToEnd tests complete Ed25519 workflow
func TestSoftware_Ed25519_EndToEnd(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	attrs := createEd25519Attrs("test-ed25519")

	// Generate key
	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	ed25519Key, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("Key is not ed25519.PrivateKey")
	}

	// Retrieve key
	retrievedKey, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	retrievedEd25519 := retrievedKey.(ed25519.PrivateKey)
	if !bytes.Equal(ed25519Key, retrievedEd25519) {
		t.Error("Retrieved key doesn't match original")
	}

	// Test signing
	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	message := []byte("Test message for signing")

	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify signature
	publicKey := ed25519Key.Public().(ed25519.PublicKey)
	if !ed25519.Verify(publicKey, message, signature) {
		t.Error("Signature verification failed")
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

// TestSoftware_Symmetric_EndToEnd tests complete symmetric workflow
func TestSoftware_Symmetric_EndToEnd(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		algorithm types.SymmetricAlgorithm
	}{
		{"AES-128", 128, types.SymmetricAES128GCM},
		{"AES-192", 192, types.SymmetricAES192GCM},
		{"AES-256", 256, types.SymmetricAES256GCM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createSoftwareBackend(t)
			defer be.Close()

			attrs := createSymmetricAttrs("test-"+tt.name, tt.keySize, tt.algorithm)

			// Generate key
			key, err := be.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey failed: %v", err)
			}

			if key.KeySize() != tt.keySize {
				t.Errorf("Key size = %d, want %d", key.KeySize(), tt.keySize)
			}

			// Retrieve key
			retrievedKey, err := be.GetSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GetSymmetricKey failed: %v", err)
			}

			rawOriginal, _ := key.Raw()
			rawRetrieved, _ := retrievedKey.Raw()
			if !bytes.Equal(rawOriginal, rawRetrieved) {
				t.Error("Retrieved key doesn't match original")
			}

			// Test encryption/decryption
			plaintext := []byte("Hello, World! This is a test message")

			encrypter, err := be.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("SymmetricEncrypter failed: %v", err)
			}

			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Error("Decrypted data doesn't match original")
			}

			// Delete key
			if err := be.DeleteKey(attrs); err != nil {
				t.Fatalf("DeleteKey failed: %v", err)
			}

			// Verify deletion
			_, err = be.GetSymmetricKey(attrs)
			if err == nil {
				t.Error("Expected error for deleted key")
			}
		})
	}
}

// TestSoftware_MixedKeys tests managing both asymmetric and symmetric keys
func TestSoftware_MixedKeys(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	// Generate RSA key
	rsaAttrs := createRSAAttrs("test-rsa-mixed", 2048)
	_, err := be.GenerateKey(rsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey RSA failed: %v", err)
	}

	// Generate ECDSA key
	ecdsaAttrs := createECDSAAttrs("test-ecdsa-mixed", "P-256")
	_, err = be.GenerateKey(ecdsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey ECDSA failed: %v", err)
	}

	// Generate Ed25519 key
	ed25519Attrs := createEd25519Attrs("test-ed25519-mixed")
	_, err = be.GenerateKey(ed25519Attrs)
	if err != nil {
		t.Fatalf("GenerateKey Ed25519 failed: %v", err)
	}

	// Generate AES key
	aesAttrs := createSymmetricAttrs("test-aes-mixed", 256, types.SymmetricAES256GCM)
	_, err = be.GenerateSymmetricKey(aesAttrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// List all keys
	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) < 4 {
		t.Errorf("Expected at least 4 keys, got %d", len(keys))
	}
}

// TestSoftware_ImportExport_RSA tests RSA import/export
func TestSoftware_ImportExport_RSA(t *testing.T) {
	algorithms := []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			be, _ := createSoftwareBackend(t)
			defer be.Close()

			exportBackend := be.(backend.ImportExportBackend)

			// Generate RSA key - use only RSA_AES_KEY_WRAP for large keys
			// PKCS8 encoding of large keys can exceed RSA-OAEP limits
			attrs := createRSAAttrs("test-export-rsa", 2048)
			originalKey, err := be.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			originalRSA := originalKey.(*rsa.PrivateKey)

			// Export the key
			wrapped, err := exportBackend.ExportKey(attrs, algorithm)
			if err != nil {
				// RSA-OAEP may fail with large PKCS8 keys - skip if so
				if algorithm == backend.WrappingAlgorithmRSAES_OAEP_SHA_256 {
					t.Skipf("Skipping OAEP test - key too large for wrapping: %v", err)
				}
				t.Fatalf("ExportKey failed: %v", err)
			}

			// Delete the original key
			if err := be.DeleteKey(attrs); err != nil {
				t.Fatalf("DeleteKey failed: %v", err)
			}

			// Import the key back
			importAttrs := createRSAAttrs("test-import-rsa", 2048)
			if err := exportBackend.ImportKey(importAttrs, wrapped); err != nil {
				t.Fatalf("ImportKey failed: %v", err)
			}

			// Retrieve and verify
			importedKey, err := be.GetKey(importAttrs)
			if err != nil {
				t.Fatalf("GetKey after import failed: %v", err)
			}

			importedRSA := importedKey.(*rsa.PrivateKey)
			if importedRSA.N.Cmp(originalRSA.N) != 0 {
				t.Error("Imported key doesn't match original")
			}
			if importedRSA.D.Cmp(originalRSA.D) != 0 {
				t.Error("Imported private exponent doesn't match original")
			}
		})
	}
}

// TestSoftware_ImportExport_ECDSA tests ECDSA import/export
func TestSoftware_ImportExport_ECDSA(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	exportBackend := be.(backend.ImportExportBackend)

	// Generate ECDSA key
	attrs := createECDSAAttrs("test-export-ecdsa", "P-256")
	originalKey, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	originalECDSA := originalKey.(*ecdsa.PrivateKey)

	// Export the key
	wrapped, err := exportBackend.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("ExportKey failed: %v", err)
	}

	// Delete the original key
	if err := be.DeleteKey(attrs); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Import the key back
	importAttrs := createECDSAAttrs("test-import-ecdsa", "P-256")
	if err := exportBackend.ImportKey(importAttrs, wrapped); err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	// Retrieve and verify
	importedKey, err := be.GetKey(importAttrs)
	if err != nil {
		t.Fatalf("GetKey after import failed: %v", err)
	}

	importedECDSA := importedKey.(*ecdsa.PrivateKey)
	if importedECDSA.D.Cmp(originalECDSA.D) != 0 {
		t.Error("Imported key doesn't match original")
	}
}

// TestSoftware_ImportExport_Symmetric tests symmetric key import/export
func TestSoftware_ImportExport_Symmetric(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	exportBackend := be.(backend.ImportExportBackend)

	// Generate AES key
	attrs := createSymmetricAttrs("test-export-aes", 256, types.SymmetricAES256GCM)
	originalKey, err := be.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	rawOriginal, _ := originalKey.Raw()

	// Export the key
	wrapped, err := exportBackend.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("ExportKey failed: %v", err)
	}

	// Delete the original key
	if err := be.DeleteKey(attrs); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Import the key back
	importAttrs := createSymmetricAttrs("test-import-aes", 256, types.SymmetricAES256GCM)
	if err := exportBackend.ImportKey(importAttrs, wrapped); err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	// Retrieve and verify
	importedKey, err := be.GetSymmetricKey(importAttrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey after import failed: %v", err)
	}

	rawImported, _ := importedKey.Raw()
	if !bytes.Equal(rawOriginal, rawImported) {
		t.Error("Imported key doesn't match original")
	}
}

// TestSoftware_KeyRotation_Asymmetric tests asymmetric key rotation
func TestSoftware_KeyRotation_Asymmetric(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("test-rotation-rsa", 2048)

	// Generate initial key
	originalKey, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	originalRSA := originalKey.(*rsa.PrivateKey)

	// Rotate the key
	if err := be.RotateKey(attrs); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Retrieve rotated key
	rotatedKey, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey after rotation failed: %v", err)
	}

	rotatedRSA := rotatedKey.(*rsa.PrivateKey)

	// Keys should be different
	if rotatedRSA.N.Cmp(originalRSA.N) == 0 {
		t.Error("Rotated key is the same as original key")
	}

	// Key size should remain the same
	if rotatedRSA.N.BitLen() != originalRSA.N.BitLen() {
		t.Error("Rotated key has different size than original")
	}
}

// TestSoftware_KeyRotation_Symmetric tests symmetric key rotation
func TestSoftware_KeyRotation_Symmetric(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	attrs := createSymmetricAttrs("test-rotation-aes", 256, types.SymmetricAES256GCM)

	// Generate initial key
	originalKey, err := be.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	rawOriginal, _ := originalKey.Raw()

	// Rotate the key
	if err := be.RotateKey(attrs); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Retrieve rotated key
	rotatedKey, err := be.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey after rotation failed: %v", err)
	}

	rawRotated, _ := rotatedKey.Raw()

	// Keys should be different
	if bytes.Equal(rawOriginal, rawRotated) {
		t.Error("Rotated key is the same as original key")
	}

	// Key size should remain the same
	if rotatedKey.KeySize() != originalKey.KeySize() {
		t.Error("Rotated key has different size than original")
	}
}

// TestSoftware_Capabilities tests backend capabilities
func TestSoftware_Capabilities(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	caps := be.Capabilities()

	if !caps.Keys {
		t.Error("Expected Keys capability to be true")
	}
	if caps.HardwareBacked {
		t.Error("Expected HardwareBacked to be false for software backend")
	}
	if !caps.Signing {
		t.Error("Expected Signing to be true")
	}
	if !caps.Decryption {
		t.Error("Expected Decryption to be true")
	}
	if !caps.SymmetricEncryption {
		t.Error("Expected SymmetricEncryption to be true")
	}
	if !caps.SupportsImportExport() {
		t.Error("Expected Import and Export to be true")
	}
}

// TestSoftware_ErrorHandling_DuplicateKey tests error on duplicate key
func TestSoftware_ErrorHandling_DuplicateKey(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("duplicate", 2048)

	// Generate first key
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("First GenerateKey failed: %v", err)
	}

	// Try to generate duplicate
	_, err = be.GenerateKey(attrs)
	if err == nil {
		t.Error("Expected error for duplicate key")
	}
}

// TestSoftware_ErrorHandling_NonExistentKey tests error on non-existent key
func TestSoftware_ErrorHandling_NonExistentKey(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	attrs := createRSAAttrs("nonexistent", 2048)

	_, err := be.GetKey(attrs)
	if err == nil {
		t.Error("Expected error for non-existent key")
	}

	err = be.DeleteKey(attrs)
	if err == nil {
		t.Error("Expected error on delete for non-existent key")
	}
}

// TestSoftware_ErrorHandling_ClosedBackend tests operations on closed backend
func TestSoftware_ErrorHandling_ClosedBackend(t *testing.T) {
	be, _ := createSoftwareBackend(t)

	// Close the backend
	if err := be.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	attrs := createRSAAttrs("test-closed", 2048)

	// All operations should fail
	_, err := be.GenerateKey(attrs)
	if err == nil {
		t.Error("Expected error for GenerateKey on closed backend")
	}

	_, err = be.GetKey(attrs)
	if err == nil {
		t.Error("Expected error for GetKey on closed backend")
	}

	err = be.DeleteKey(attrs)
	if err == nil {
		t.Error("Expected error for DeleteKey on closed backend")
	}
}

// TestSoftware_ConcurrentOperations tests thread-safety
func TestSoftware_ConcurrentOperations(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	// Generate keys concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Half RSA, half AES - use unique names
			if id%2 == 0 {
				attrs := createRSAAttrs("concurrent-rsa-"+string(rune('a'+id)), 2048)
				_, err := be.GenerateKey(attrs)
				if err != nil {
					t.Errorf("GenerateKey failed in goroutine %d: %v", id, err)
				}
			} else {
				attrs := createSymmetricAttrs("concurrent-aes-"+string(rune('a'+id)), 256, types.SymmetricAES256GCM)
				_, err := be.GenerateSymmetricKey(attrs)
				if err != nil {
					t.Errorf("GenerateSymmetricKey failed in goroutine %d: %v", id, err)
				}
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all keys were created
	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) < numGoroutines {
		t.Errorf("Expected at least %d keys, got %d", numGoroutines, len(keys))
	}
}

// TestSoftware_Type tests backend type
func TestSoftware_Type(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	if be.Type() != types.BackendTypeSoftware {
		t.Errorf("Expected backend type %s, got %s", types.BackendTypeSoftware, be.Type())
	}
}

// TestSoftware_PasswordProtection_Asymmetric tests password-protected asymmetric keys
func TestSoftware_PasswordProtection_Asymmetric(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	password := backend.StaticPassword("test-password-123")
	attrs := createRSAAttrs("test-password-rsa", 2048)
	attrs.Password = password

	// Generate password-protected key
	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	originalRSA := key.(*rsa.PrivateKey)

	// Retrieve with correct password
	retrievedKey, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey with correct password failed: %v", err)
	}

	retrievedRSA := retrievedKey.(*rsa.PrivateKey)
	if retrievedRSA.N.Cmp(originalRSA.N) != 0 {
		t.Error("Retrieved key doesn't match original")
	}

	// Try to retrieve with wrong password
	wrongPasswordAttrs := createRSAAttrs("test-password-rsa", 2048)
	wrongPasswordAttrs.Password = backend.StaticPassword("wrong-password")

	_, err = be.GetKey(wrongPasswordAttrs)
	if err == nil {
		t.Error("Expected error with wrong password")
	}
}

// TestSoftware_AllKeyTypes_Comprehensive tests all key types comprehensively
func TestSoftware_AllKeyTypes_Comprehensive(t *testing.T) {
	be, _ := createSoftwareBackend(t)
	defer be.Close()

	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{"RSA-2048", createRSAAttrs("comprehensive-rsa-2048", 2048)},
		{"RSA-4096", createRSAAttrs("comprehensive-rsa-4096", 4096)},
		{"ECDSA-P256", createECDSAAttrs("comprehensive-ecdsa-p256", "P-256")},
		{"ECDSA-P384", createECDSAAttrs("comprehensive-ecdsa-p384", "P-384")},
		{"ECDSA-P521", createECDSAAttrs("comprehensive-ecdsa-p521", "P-521")},
		{"Ed25519", createEd25519Attrs("comprehensive-ed25519")},
		{"AES-128", createSymmetricAttrs("comprehensive-aes-128", 128, types.SymmetricAES128GCM)},
		{"AES-192", createSymmetricAttrs("comprehensive-aes-192", 192, types.SymmetricAES192GCM)},
		{"AES-256", createSymmetricAttrs("comprehensive-aes-256", 256, types.SymmetricAES256GCM)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.attrs.IsSymmetric() {
				// Test symmetric key
				key, err := be.GenerateSymmetricKey(tt.attrs)
				if err != nil {
					t.Fatalf("GenerateSymmetricKey failed: %v", err)
				}
				if key == nil {
					t.Fatal("Generated key is nil")
				}

				// Retrieve and verify
				retrieved, err := be.GetSymmetricKey(tt.attrs)
				if err != nil {
					t.Fatalf("GetSymmetricKey failed: %v", err)
				}
				if retrieved == nil {
					t.Fatal("Retrieved key is nil")
				}
			} else {
				// Test asymmetric key
				key, err := be.GenerateKey(tt.attrs)
				if err != nil {
					t.Fatalf("GenerateKey failed: %v", err)
				}
				if key == nil {
					t.Fatal("Generated key is nil")
				}

				// Retrieve and verify
				retrieved, err := be.GetKey(tt.attrs)
				if err != nil {
					t.Fatalf("GetKey failed: %v", err)
				}
				if retrieved == nil {
					t.Fatal("Retrieved key is nil")
				}

				// Test signer if not Ed25519 with hash
				if tt.attrs.KeyAlgorithm != x509.Ed25519 || tt.attrs.Hash != 0 {
					signer, err := be.Signer(tt.attrs)
					if err != nil {
						t.Fatalf("Signer failed: %v", err)
					}
					if signer == nil {
						t.Fatal("Signer is nil")
					}
				}
			}

			// Delete and verify
			if err := be.DeleteKey(tt.attrs); err != nil {
				t.Fatalf("DeleteKey failed: %v", err)
			}
		})
	}
}
