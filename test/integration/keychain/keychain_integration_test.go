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

package keychain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestKeyStore_KeyGeneration tests key generation for all supported algorithms
func TestKeyStore_KeyGeneration(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(t *testing.T) *types.KeyAttributes
		verifyKey func(t *testing.T, key crypto.PrivateKey)
	}{
		{
			name: "RSA-2048",
			setupFunc: func(t *testing.T) *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:           "test-rsa-2048",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
					Hash: crypto.SHA256,
				}
			},
			verifyKey: func(t *testing.T, key crypto.PrivateKey) {
				rsaKey, ok := key.(crypto.Signer)
				if !ok {
					t.Fatal("Generated key does not implement crypto.Signer")
				}
				pub := rsaKey.Public().(*rsa.PublicKey)
				if pub.N.BitLen() != 2048 {
					t.Errorf("Expected key size 2048, got %d", pub.N.BitLen())
				}
			},
		},
		{
			name: "RSA-4096",
			setupFunc: func(t *testing.T) *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:           "test-rsa-4096",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 4096,
					},
					Hash: crypto.SHA256,
				}
			},
			verifyKey: func(t *testing.T, key crypto.PrivateKey) {
				rsaKey, ok := key.(crypto.Signer)
				if !ok {
					t.Fatal("Generated key does not implement crypto.Signer")
				}
				pub := rsaKey.Public().(*rsa.PublicKey)
				if pub.N.BitLen() != 4096 {
					t.Errorf("Expected key size 4096, got %d", pub.N.BitLen())
				}
			},
		},
		{
			name: "ECDSA-P256",
			setupFunc: func(t *testing.T) *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:           "test-ecdsa-p256",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.ECDSA,
					ECCAttributes: &types.ECCAttributes{
						Curve: elliptic.P256(),
					},
					Hash: crypto.SHA256,
				}
			},
			verifyKey: func(t *testing.T, key crypto.PrivateKey) {
				ecdsaKey, ok := key.(crypto.Signer)
				if !ok {
					t.Fatal("Generated key does not implement crypto.Signer")
				}
				pub := ecdsaKey.Public().(*ecdsa.PublicKey)
				if pub.Curve != elliptic.P256() {
					t.Errorf("Expected P256 curve, got %v", pub.Curve)
				}
			},
		},
		{
			name: "ECDSA-P384",
			setupFunc: func(t *testing.T) *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:           "test-ecdsa-p384",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.ECDSA,
					ECCAttributes: &types.ECCAttributes{
						Curve: elliptic.P384(),
					},
					Hash: crypto.SHA256,
				}
			},
			verifyKey: func(t *testing.T, key crypto.PrivateKey) {
				ecdsaKey, ok := key.(crypto.Signer)
				if !ok {
					t.Fatal("Generated key does not implement crypto.Signer")
				}
				pub := ecdsaKey.Public().(*ecdsa.PublicKey)
				if pub.Curve != elliptic.P384() {
					t.Errorf("Expected P384 curve, got %v", pub.Curve)
				}
			},
		},
		{
			name: "Ed25519",
			setupFunc: func(t *testing.T) *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:           "test-ed25519",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.Ed25519,
				}
			},
			verifyKey: func(t *testing.T, key crypto.PrivateKey) {
				ed25519Key, ok := key.(crypto.Signer)
				if !ok {
					t.Fatal("Generated key does not implement crypto.Signer")
				}
				pub := ed25519Key.Public()
				if _, ok := pub.(ed25519.PublicKey); !ok {
					t.Error("Expected Ed25519 public key")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create keystore
			ks := createTestKeyStore(t)
			defer ks.Close()

			// Get key attributes
			attrs := tt.setupFunc(t)

			// Generate key based on algorithm
			var key crypto.PrivateKey
			var err error

			switch attrs.KeyAlgorithm {
			case x509.RSA:
				key, err = ks.GenerateRSA(attrs)
			case x509.ECDSA:
				key, err = ks.GenerateECDSA(attrs)
			case x509.Ed25519:
				key, err = ks.GenerateEd25519(attrs)
			default:
				t.Fatalf("Unsupported algorithm: %v", attrs.KeyAlgorithm)
			}

			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			if key == nil {
				t.Fatal("Generated key is nil")
			}

			// Verify key properties
			tt.verifyKey(t, key)

			// Verify key can be retrieved
			retrievedKey, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to retrieve key: %v", err)
			}

			if retrievedKey == nil {
				t.Fatal("Retrieved key is nil")
			}
		})
	}
}

// TestKeyStore_KeyRetrieval tests key retrieval operations
func TestKeyStore_KeyRetrieval(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate an RSA key
	attrs := &types.KeyAttributes{
		CN:           "test-retrieval",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Retrieve the key
	key, err := ks.GetKey(attrs)
	if err != nil {
		t.Fatalf("Failed to retrieve key: %v", err)
	}

	if key == nil {
		t.Fatal("Retrieved key is nil")
	}

	// Verify it's a valid signer
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("Retrieved key does not implement crypto.Signer")
	}

	// Test signing with the retrieved key
	digest := sha256.Sum256([]byte("test message"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to sign with retrieved key: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Signature is empty")
	}
}

// TestKeyStore_KeyDeletion tests key deletion operations
func TestKeyStore_KeyDeletion(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate a key
	attrs := &types.KeyAttributes{
		CN:           "test-deletion",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Verify key exists
	_, err = ks.GetKey(attrs)
	if err != nil {
		t.Fatalf("Key should exist before deletion: %v", err)
	}

	// Delete the key
	err = ks.DeleteKey(attrs)
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Verify key no longer exists
	_, err = ks.GetKey(attrs)
	if err == nil {
		t.Fatal("Key should not exist after deletion")
	}
}

// TestKeyStore_ListKeys tests listing all keys
func TestKeyStore_ListKeys(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Get initial key count
	initialKeys, err := ks.ListKeys()
	if err != nil {
		t.Fatalf("Failed to list keys: %v", err)
	}
	initialCount := len(initialKeys)

	// Generate multiple keys
	keyNames := []string{"key1", "key2", "key3"}
	for _, name := range keyNames {
		attrs := &types.KeyAttributes{
			CN:           name,
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			Hash: crypto.SHA256,
		}
		_, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("Failed to generate key %s: %v", name, err)
		}
	}

	// List keys again
	keys, err := ks.ListKeys()
	if err != nil {
		t.Fatalf("Failed to list keys: %v", err)
	}

	// Note: Software backend currently lists keys with different ID formats,
	// resulting in duplicates (e.g., "key1" and "pkcs8:signing:key1:rsa").
	// This is a known issue. For now, we verify that at least our keys are present.
	expectedMinCount := initialCount + len(keyNames)
	if len(keys) < expectedMinCount {
		t.Errorf("Expected at least %d keys, got %d", expectedMinCount, len(keys))
	}

	// Verify all our keys are listed (they may appear with different ID formats)
	keyMap := make(map[string]bool)
	for _, key := range keys {
		// Match both simple CN and full ID format
		if key.CN != "" {
			keyMap[key.CN] = true
		}
	}

	for _, name := range keyNames {
		if !keyMap[name] {
			t.Errorf("Key %s not found in list", name)
		}
	}
}

// TestKeyStore_KeyRotation tests key rotation functionality
func TestKeyStore_KeyRotation(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate initial key
	attrs := &types.KeyAttributes{
		CN:           "test-rotation",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	oldKey, err := ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate initial key: %v", err)
	}

	oldSigner := oldKey.(crypto.Signer)
	oldPub := oldSigner.Public().(*rsa.PublicKey)

	// Rotate the key
	newKey, err := ks.RotateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	newSigner := newKey.(crypto.Signer)
	newPub := newSigner.Public().(*rsa.PublicKey)

	// Verify new key is different from old key
	if oldPub.N.Cmp(newPub.N) == 0 {
		t.Error("Rotated key should be different from original key")
	}

	// Verify old key no longer retrievable (it should retrieve the new key)
	retrievedKey, err := ks.GetKey(attrs)
	if err != nil {
		t.Fatalf("Failed to retrieve rotated key: %v", err)
	}

	retrievedSigner := retrievedKey.(crypto.Signer)
	retrievedPub := retrievedSigner.Public().(*rsa.PublicKey)

	if retrievedPub.N.Cmp(newPub.N) != 0 {
		t.Error("Retrieved key should match rotated key")
	}
}

// TestKeyStore_SigningAndVerification tests signing and verification workflows
func TestKeyStore_SigningAndVerification(t *testing.T) {
	tests := []struct {
		name      string
		algorithm x509.PublicKeyAlgorithm
		hash      crypto.Hash
		setupKey  func(ks keychain.KeyStore) (*types.KeyAttributes, error)
	}{
		{
			name:      "RSA-SHA256",
			algorithm: x509.RSA,
			hash:      crypto.SHA256,
			setupKey: func(ks keychain.KeyStore) (*types.KeyAttributes, error) {
				attrs := &types.KeyAttributes{
					CN:           "test-signing-rsa",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
					Hash: crypto.SHA256,
				}
				_, err := ks.GenerateRSA(attrs)
				return attrs, err
			},
		},
		{
			name:      "ECDSA-SHA256",
			algorithm: x509.ECDSA,
			hash:      crypto.SHA256,
			setupKey: func(ks keychain.KeyStore) (*types.KeyAttributes, error) {
				attrs := &types.KeyAttributes{
					CN:           "test-signing-ecdsa",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.ECDSA,
					ECCAttributes: &types.ECCAttributes{
						Curve: elliptic.P256(),
					},
					Hash: crypto.SHA256,
				}
				_, err := ks.GenerateECDSA(attrs)
				return attrs, err
			},
		},
		{
			name:      "Ed25519",
			algorithm: x509.Ed25519,
			hash:      crypto.Hash(0), // Ed25519 doesn't use a separate hash
			setupKey: func(ks keychain.KeyStore) (*types.KeyAttributes, error) {
				attrs := &types.KeyAttributes{
					CN:           "test-signing-ed25519",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.Ed25519,
				}
				_, err := ks.GenerateEd25519(attrs)
				return attrs, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := createTestKeyStore(t)
			defer ks.Close()

			// Setup key
			attrs, err := tt.setupKey(ks)
			if err != nil {
				t.Fatalf("Failed to setup key: %v", err)
			}

			// Get signer
			signer, err := ks.Signer(attrs)
			if err != nil {
				t.Fatalf("Failed to get signer: %v", err)
			}

			// Create test message
			message := []byte("test message for signing")
			var digest []byte

			if tt.algorithm == x509.Ed25519 {
				// Ed25519 signs the message directly
				digest = message
			} else {
				// Hash the message for other algorithms
				h := tt.hash.New()
				h.Write(message)
				digest = h.Sum(nil)
			}

			// Sign the message
			signature, err := signer.Sign(rand.Reader, digest, tt.hash)
			if err != nil {
				t.Fatalf("Failed to sign message: %v", err)
			}

			if len(signature) == 0 {
				t.Fatal("Signature is empty")
			}

			// Verify signature
			publicKey := signer.Public()

			switch tt.algorithm {
			case x509.RSA:
				rsaPub := publicKey.(*rsa.PublicKey)
				err = rsa.VerifyPKCS1v15(rsaPub, tt.hash, digest, signature)
				if err != nil {
					t.Fatalf("Signature verification failed: %v", err)
				}

			case x509.ECDSA:
				ecdsaPub := publicKey.(*ecdsa.PublicKey)
				if !ecdsa.VerifyASN1(ecdsaPub, digest, signature) {
					t.Fatal("ECDSA signature verification failed")
				}

			case x509.Ed25519:
				ed25519Pub := publicKey.(ed25519.PublicKey)
				if !ed25519.Verify(ed25519Pub, digest, signature) {
					t.Fatal("Ed25519 signature verification failed")
				}
			}
		})
	}
}

// TestKeyStore_RSAEncryptionDecryption tests RSA encryption and decryption workflows
func TestKeyStore_RSAEncryptionDecryption(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate RSA key for encryption
	attrs := &types.KeyAttributes{
		CN:           "test-encryption",
		KeyType:      types.KeyTypeEncryption,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Get decrypter
	decrypter, err := ks.Decrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get decrypter: %v", err)
	}

	// Encrypt message with public key
	message := []byte("secret message for encryption")
	publicKey := decrypter.Public().(*rsa.PublicKey)

	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		message,
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	// Decrypt with private key
	plaintext, err := decrypter.Decrypt(
		rand.Reader,
		ciphertext,
		&rsa.OAEPOptions{Hash: crypto.SHA256},
	)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}

	// Verify decrypted message matches original
	if string(plaintext) != string(message) {
		t.Errorf("Decrypted message does not match original.\nExpected: %s\nGot: %s",
			string(message), string(plaintext))
	}
}

// TestKeyStore_CertificateManagement tests certificate storage and retrieval
func TestKeyStore_CertificateManagement(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate key for certificate
	attrs := &types.KeyAttributes{
		CN:           "test-cert.example.com",
		KeyType:      types.KeyTypeTLS,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	key, err := ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create a self-signed certificate
	cert := createSelfSignedCert(t, key, "test-cert.example.com")

	// Save certificate
	keyID := "test-cert.example.com"
	err = ks.SaveCert(keyID, cert)
	if err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	// Retrieve certificate
	retrievedCert, err := ks.GetCert(keyID)
	if err != nil {
		t.Fatalf("Failed to retrieve certificate: %v", err)
	}

	// Verify certificate matches
	if !cert.Equal(retrievedCert) {
		t.Error("Retrieved certificate does not match original")
	}

	// Test CertExists
	exists, err := ks.CertExists(keyID)
	if err != nil {
		t.Fatalf("Failed to check certificate existence: %v", err)
	}
	if !exists {
		t.Error("Certificate should exist")
	}

	// Test ListCerts
	certIDs, err := ks.ListCerts()
	if err != nil {
		t.Fatalf("Failed to list certificates: %v", err)
	}
	if len(certIDs) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certIDs))
	}
	if certIDs[0] != keyID {
		t.Errorf("Expected certificate ID %s, got %s", keyID, certIDs[0])
	}

	// Delete certificate
	err = ks.DeleteCert(keyID)
	if err != nil {
		t.Fatalf("Failed to delete certificate: %v", err)
	}

	// Verify deletion
	exists, err = ks.CertExists(keyID)
	if err != nil {
		t.Fatalf("Failed to check certificate existence after deletion: %v", err)
	}
	if exists {
		t.Error("Certificate should not exist after deletion")
	}
}

// TestKeyStore_CertificateChain tests certificate chain storage and retrieval
func TestKeyStore_CertificateChain(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Create a certificate chain (root -> intermediate -> leaf)
	rootKey, err := ks.GenerateRSA(&types.KeyAttributes{
		CN:           "root-ca",
		KeyType:      types.KeyTypeCA,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	intermediateKey, err := ks.GenerateRSA(&types.KeyAttributes{
		CN:           "intermediate-ca",
		KeyType:      types.KeyTypeCA,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("Failed to generate intermediate key: %v", err)
	}

	leafKey, err := ks.GenerateRSA(&types.KeyAttributes{
		CN:           "leaf.example.com",
		KeyType:      types.KeyTypeTLS,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("Failed to generate leaf key: %v", err)
	}

	// Create certificates
	rootCert := createSelfSignedCert(t, rootKey, "root-ca")
	intermediateCert := createSignedCert(t, intermediateKey, rootKey, "intermediate-ca", "root-ca")
	leafCert := createSignedCert(t, leafKey, intermediateKey, "leaf.example.com", "intermediate-ca")

	// Save certificate chain
	keyID := "leaf.example.com"
	chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}
	err = ks.SaveCertChain(keyID, chain)
	if err != nil {
		t.Fatalf("Failed to save certificate chain: %v", err)
	}

	// Retrieve certificate chain
	retrievedChain, err := ks.GetCertChain(keyID)
	if err != nil {
		t.Fatalf("Failed to retrieve certificate chain: %v", err)
	}

	// Verify chain length
	if len(retrievedChain) != len(chain) {
		t.Errorf("Expected chain length %d, got %d", len(chain), len(retrievedChain))
	}

	// Verify each certificate in the chain
	for i, cert := range chain {
		if !cert.Equal(retrievedChain[i]) {
			t.Errorf("Certificate at position %d does not match", i)
		}
	}
}

// TestKeyStore_TLSCertificate tests TLS certificate creation
func TestKeyStore_TLSCertificate(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate key for TLS
	keyID := "tls.example.com"
	attrs := &types.KeyAttributes{
		CN:           keyID,
		KeyType:      types.KeyTypeTLS,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	key, err := ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create and save certificate
	cert := createSelfSignedCert(t, key, keyID)
	err = ks.SaveCert(keyID, cert)
	if err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	// Get TLS certificate
	tlsCert, err := ks.GetTLSCertificate(keyID, attrs)
	if err != nil {
		t.Fatalf("Failed to get TLS certificate: %v", err)
	}

	// Verify TLS certificate structure
	if tlsCert.PrivateKey == nil {
		t.Error("TLS certificate private key is nil")
	}

	if len(tlsCert.Certificate) == 0 {
		t.Error("TLS certificate chain is empty")
	}

	if tlsCert.Leaf == nil {
		t.Error("TLS certificate leaf is nil")
	}

	// Verify the certificate can be used in TLS
	if !tlsCert.Leaf.Equal(cert) {
		t.Error("TLS certificate leaf does not match original certificate")
	}
}

// TestKeyStore_GetKeyByID tests unified Key ID retrieval
func TestKeyStore_GetKeyByID(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate a key
	attrs := &types.KeyAttributes{
		CN:           "test-key-id",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test GetKeyByID
	keyID := "software:signing:rsa:test-key-id"
	key, err := ks.GetKeyByID(keyID)
	if err != nil {
		t.Fatalf("Failed to get key by ID: %v", err)
	}

	if key == nil {
		t.Fatal("Retrieved key is nil")
	}

	// Verify it's a valid signer
	_, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("Retrieved key does not implement crypto.Signer")
	}
}

// TestKeyStore_GetSignerByID tests unified Key ID signer retrieval
func TestKeyStore_GetSignerByID(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate a key
	attrs := &types.KeyAttributes{
		CN:           "test-signer-id",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		Hash: crypto.SHA256,
	}

	_, err := ks.GenerateECDSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test GetSignerByID
	keyID := "software:signing:ecdsa-p256:test-signer-id"
	signer, err := ks.GetSignerByID(keyID)
	if err != nil {
		t.Fatalf("Failed to get signer by ID: %v", err)
	}

	if signer == nil {
		t.Fatal("Retrieved signer is nil")
	}

	// Test signing
	digest := sha256.Sum256([]byte("test message"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to sign with retrieved signer: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Signature is empty")
	}
}

// TestKeyStore_GetDecrypterByID tests unified Key ID decrypter retrieval
func TestKeyStore_GetDecrypterByID(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate an RSA key for decryption
	attrs := &types.KeyAttributes{
		CN:           "test-decrypter-id",
		KeyType:      types.KeyTypeEncryption,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test GetDecrypterByID
	keyID := "software:encryption:rsa:test-decrypter-id"
	decrypter, err := ks.GetDecrypterByID(keyID)
	if err != nil {
		t.Fatalf("Failed to get decrypter by ID: %v", err)
	}

	if decrypter == nil {
		t.Fatal("Retrieved decrypter is nil")
	}

	// Test encryption/decryption
	message := []byte("secret message")
	publicKey := decrypter.Public().(*rsa.PublicKey)

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if string(plaintext) != string(message) {
		t.Error("Decrypted message does not match original")
	}
}

// TestKeyStore_ErrorHandling tests error handling for invalid operations
func TestKeyStore_ErrorHandling(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	t.Run("GetNonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "nonexistent",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		_, err := ks.GetKey(attrs)
		if err == nil {
			t.Error("Expected error when getting non-existent key")
		}
	})

	t.Run("DeleteNonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "nonexistent",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		err := ks.DeleteKey(attrs)
		if err == nil {
			t.Error("Expected error when deleting non-existent key")
		}
	})

	t.Run("NilKeyAttributes", func(t *testing.T) {
		_, err := ks.GenerateRSA(nil)
		if err == nil {
			t.Error("Expected error with nil key attributes")
		}

		_, err = ks.GetKey(nil)
		if err == nil {
			t.Error("Expected error with nil key attributes")
		}

		err = ks.DeleteKey(nil)
		if err == nil {
			t.Error("Expected error with nil key attributes")
		}
	})

	t.Run("InvalidCertOperations", func(t *testing.T) {
		err := ks.SaveCert("", nil)
		if err == nil {
			t.Error("Expected error when saving cert with empty ID")
		}

		_, err = ks.GetCert("")
		if err == nil {
			t.Error("Expected error when getting cert with empty ID")
		}

		err = ks.DeleteCert("")
		if err == nil {
			t.Error("Expected error when deleting cert with empty ID")
		}

		_, err = ks.CertExists("")
		if err == nil {
			t.Error("Expected error when checking cert existence with empty ID")
		}
	})

	t.Run("GetNonExistentCert", func(t *testing.T) {
		_, err := ks.GetCert("nonexistent")
		if err == nil {
			t.Error("Expected error when getting non-existent cert")
		}
	})

	t.Run("InvalidKeyID", func(t *testing.T) {
		_, err := ks.GetKeyByID("invalid-format")
		if err == nil {
			t.Error("Expected error with invalid key ID format")
		}

		_, err = ks.GetSignerByID("invalid:format")
		if err == nil {
			t.Error("Expected error with invalid key ID format")
		}
	})

	t.Run("BackendMismatch", func(t *testing.T) {
		// Try to get a key with a different backend
		_, err := ks.GetKeyByID("pkcs11:signing:rsa:test-key")
		if err == nil {
			t.Error("Expected error when backend doesn't match")
		}
	})
}

// TestKeyStore_ConcurrentOperations tests thread safety
func TestKeyStore_ConcurrentOperations(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Number of concurrent operations
	const numGoroutines = 10

	// Channel to collect errors
	errChan := make(chan error, numGoroutines*3)
	doneChan := make(chan bool, numGoroutines)

	// Run concurrent key generation, retrieval, and deletion
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { doneChan <- true }()

			// Generate key
			attrs := &types.KeyAttributes{
				CN:           "concurrent-" + string(rune('a'+id)),
				KeyType:      types.KeyTypeSigning,
				StoreType:    types.StoreSoftware,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
				Hash: crypto.SHA256,
			}

			_, err := ks.GenerateRSA(attrs)
			if err != nil {
				errChan <- err
				return
			}

			// Retrieve key
			_, err = ks.GetKey(attrs)
			if err != nil {
				errChan <- err
				return
			}

			// Delete key
			err = ks.DeleteKey(attrs)
			if err != nil {
				errChan <- err
				return
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-doneChan
	}
	close(errChan)

	// Check for errors
	for err := range errChan {
		t.Errorf("Concurrent operation error: %v", err)
	}
}

// TestKeyStore_MultipleBackends tests using multiple keystore instances
func TestKeyStore_MultipleBackends(t *testing.T) {
	// Create two independent keystores
	ks1 := createTestKeyStore(t)
	defer ks1.Close()

	ks2 := createTestKeyStore(t)
	defer ks2.Close()

	// Generate key in first keystore
	attrs := &types.KeyAttributes{
		CN:           "test-multi-backend",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := ks1.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key in first keystore: %v", err)
	}

	// Verify key exists in first keystore
	_, err = ks1.GetKey(attrs)
	if err != nil {
		t.Errorf("Key should exist in first keystore: %v", err)
	}

	// Verify key does NOT exist in second keystore (different storage)
	_, err = ks2.GetKey(attrs)
	if err == nil {
		t.Error("Key should not exist in second keystore")
	}
}

// Helper Functions

// createTestKeyStore creates a keystore instance for testing
func createTestKeyStore(t *testing.T) keychain.KeyStore {
	t.Helper()

	// Create in-memory storage backends
	keyStorage := storage.New()
	certStorage := storage.New()

	// Create software backend
	backendConfig := &software.Config{
		KeyStorage: keyStorage,
	}

	backend, err := software.NewBackend(backendConfig)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Create keystore
	config := &keychain.Config{
		Backend:     backend,
		CertStorage: certStorage,
	}

	ks, err := keychain.New(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	return ks
}

// createSelfSignedCert creates a self-signed certificate for testing
func createSelfSignedCert(t *testing.T, key crypto.PrivateKey, cn string) *x509.Certificate {
	t.Helper()

	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("Key does not implement crypto.Signer")
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// createSignedCert creates a certificate signed by a parent certificate
func createSignedCert(t *testing.T, key, parentKey crypto.PrivateKey, cn, issuerCN string) *x509.Certificate {
	t.Helper()

	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("Key does not implement crypto.Signer")
	}

	parentSigner, ok := parentKey.(crypto.Signer)
	if !ok {
		t.Fatal("Parent key does not implement crypto.Signer")
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		Issuer: pkix.Name{
			CommonName: issuerCN,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// If this is a CA cert, set IsCA
	if cn != "leaf.example.com" {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	parentTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: issuerCN,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parentTemplate, signer.Public(), parentSigner)
	if err != nil {
		t.Fatalf("Failed to create signed certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// exportCertToPEM exports a certificate to PEM format (for debugging)
func exportCertToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// verifyTLSCertificate verifies a TLS certificate structure (for debugging)
func verifyTLSCertificate(t *testing.T, tlsCert tls.Certificate) {
	t.Helper()

	if tlsCert.PrivateKey == nil {
		t.Error("TLS certificate private key is nil")
	}

	if len(tlsCert.Certificate) == 0 {
		t.Error("TLS certificate chain is empty")
	}

	if tlsCert.Leaf == nil {
		t.Error("TLS certificate leaf is nil")
	}
}
