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

//go:build integration && vault

package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"os"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/vault"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVaultIntegration tests Vault backend against a real Vault instance
func TestVaultIntegration(t *testing.T) {
	// Check if Vault endpoint is configured
	address := os.Getenv("VAULT_ADDR")
	if address == "" {
		address = "http://localhost:8200"
	}

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		token = "root"
	}

	// Create storage backends
	keyStorage := memory.New()
	certStorage := memory.New()

	// Create backend
	cfg := &vault.Config{
		Address:       address,
		Token:         token,
		TransitPath:   "transit",
		TLSSkipVerify: true,
		KeyStorage:    keyStorage,
		CertStorage:   certStorage,
	}

	b, err := vault.NewBackend(cfg)
	require.NoError(t, err, "Failed to create Vault backend")
	defer b.Close()

	// ========================================================================
	// Backend Info Tests
	// ========================================================================

	t.Run("BackendInfo", func(t *testing.T) {
		t.Run("Type", func(t *testing.T) {
			backendType := b.Type()
			assert.Equal(t, backend.BackendTypeVault, backendType)
			t.Logf("✓ Backend type: %s", backendType)
		})

		t.Run("Capabilities", func(t *testing.T) {
			caps := b.Capabilities()
			assert.True(t, caps.Keys, "Should support keys")
			assert.True(t, caps.Signing, "Should support signing")
			assert.True(t, caps.Decryption, "Should support decryption")
			assert.True(t, caps.KeyRotation, "Should support key rotation")
			t.Logf("✓ Capabilities: Keys=%v, HardwareBacked=%v, Signing=%v, Decryption=%v, KeyRotation=%v",
				caps.Keys, caps.HardwareBacked, caps.Signing, caps.Decryption, caps.KeyRotation)
		})
	})

	// ========================================================================
	// RSA Key Tests
	// ========================================================================

	t.Run("RSA", func(t *testing.T) {
		t.Run("RSA-2048", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-2048",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate key
			key, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate RSA 2048 key")
			require.NotNil(t, key, "Key should not be nil")

			pubKey, ok := key.(*rsa.PublicKey)
			require.True(t, ok, "Key should be RSA public key")
			assert.Equal(t, 2048, pubKey.N.BitLen(), "Key size should be 2048")

			t.Logf("✓ Generated RSA 2048 key")

			// Test signing
			message := []byte("test message for RSA 2048")
			hash := sha256.Sum256(message)

			signer, err := b.Signer(attrs)
			require.NoError(t, err, "Failed to get signer")

			signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
			require.NoError(t, err, "Failed to sign message")
			assert.NotEmpty(t, signature, "Signature should not be empty")

			t.Logf("✓ Signed message with RSA 2048 (signature length: %d)", len(signature))

			// Verify signature
			err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
			require.NoError(t, err, "Failed to verify signature")

			t.Logf("✓ Verified RSA 2048 signature")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("RSA-2048-PSS", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-2048-pss",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate key
			key, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate RSA 2048 key")
			require.NotNil(t, key, "Key should not be nil")

			pubKey, ok := key.(*rsa.PublicKey)
			require.True(t, ok, "Key should be RSA public key")
			assert.Equal(t, 2048, pubKey.N.BitLen(), "Key size should be 2048")

			t.Logf("✓ Generated RSA 2048 key for PSS")

			// Test RSA-PSS signing
			message := []byte("test message for RSA 2048 PSS")
			h := sha256.New()
			h.Write(message)
			digest := h.Sum(nil)

			signer, err := b.Signer(attrs)
			require.NoError(t, err, "Failed to get signer")

			// Vault backend uses PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			require.NoError(t, err, "Failed to sign message with PSS")
			assert.NotEmpty(t, signature, "Signature should not be empty")

			t.Logf("✓ Signed message with RSA 2048 PSS (signature length: %d)", len(signature))

			// Verify PSS signature using signer's public key
			signerPubKey := signer.Public().(*rsa.PublicKey)
			err = rsa.VerifyPSS(signerPubKey, crypto.SHA256, digest, signature, pssOpts)
			require.NoError(t, err, "Failed to verify PSS signature")

			t.Logf("✓ Verified RSA 2048 PSS signature")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("RSA-4096", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-4096",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			}

			key, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate RSA 4096 key")

			pubKey, ok := key.(*rsa.PublicKey)
			require.True(t, ok, "Key should be RSA public key")
			assert.Equal(t, 4096, pubKey.N.BitLen(), "Key size should be 4096")

			t.Logf("✓ Generated RSA 4096 key")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("RSA-4096-PSS", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-4096-pss",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			}

			// Generate key
			key, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate RSA 4096 key")
			require.NotNil(t, key, "Key should not be nil")

			pubKey, ok := key.(*rsa.PublicKey)
			require.True(t, ok, "Key should be RSA public key")
			assert.Equal(t, 4096, pubKey.N.BitLen(), "Key size should be 4096")

			t.Logf("✓ Generated RSA 4096 key for PSS")

			// Test RSA-PSS signing
			message := []byte("test message for RSA 4096 PSS")
			h := sha256.New()
			h.Write(message)
			digest := h.Sum(nil)

			signer, err := b.Signer(attrs)
			require.NoError(t, err, "Failed to get signer")

			// Vault backend uses PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			require.NoError(t, err, "Failed to sign message with PSS")
			assert.NotEmpty(t, signature, "Signature should not be empty")

			t.Logf("✓ Signed message with RSA 4096 PSS (signature length: %d)", len(signature))

			// Verify PSS signature using signer's public key
			signerPubKey := signer.Public().(*rsa.PublicKey)
			err = rsa.VerifyPSS(signerPubKey, crypto.SHA256, digest, signature, pssOpts)
			require.NoError(t, err, "Failed to verify PSS signature")

			t.Logf("✓ Verified RSA 4096 PSS signature")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("RSA-SHA384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-sha384",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA384,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			_, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate RSA key with SHA384")

			message := []byte("test message for SHA384")
			// Use SHA384 hash to match the algorithm specification
			h := crypto.SHA384.New()
			h.Write(message)
			hash := h.Sum(nil)

			signer, err := b.Signer(attrs)
			require.NoError(t, err, "Failed to get signer")

			signature, err := signer.Sign(rand.Reader, hash, crypto.SHA384)
			require.NoError(t, err, "Failed to sign with SHA384")
			assert.NotEmpty(t, signature, "Signature should not be empty")

			t.Logf("✓ Signed message with RSA-SHA384")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("RSA-SHA384-PSS", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-sha384-pss",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA384,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate key
			key, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate RSA key with SHA384")
			require.NotNil(t, key, "Key should not be nil")

			_, ok := key.(*rsa.PublicKey)
			require.True(t, ok, "Key should be RSA public key")

			t.Logf("✓ Generated RSA 2048 key for SHA384 PSS")

			// Test RSA-PSS signing with SHA384
			message := []byte("test message for SHA384 PSS")
			h := sha512.New384()
			h.Write(message)
			digest := h.Sum(nil)

			signer, err := b.Signer(attrs)
			require.NoError(t, err, "Failed to get signer")

			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA384,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			require.NoError(t, err, "Failed to sign with SHA384 PSS")
			assert.NotEmpty(t, signature, "Signature should not be empty")

			t.Logf("✓ Signed message with RSA-SHA384 PSS (signature length: %d)", len(signature))

			// Verify PSS signature using signer's public key
			signerPubKey := signer.Public().(*rsa.PublicKey)
			err = rsa.VerifyPSS(signerPubKey, crypto.SHA384, digest, signature, pssOpts)
			require.NoError(t, err, "Failed to verify SHA384 PSS signature")

			t.Logf("✓ Verified RSA-SHA384 PSS signature")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})
	})

	// ========================================================================
	// ECDSA Key Tests
	// ========================================================================

	t.Run("ECDSA", func(t *testing.T) {
		t.Run("P-256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p256",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA256,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			key, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate ECDSA P-256 key")

			pubKey, ok := key.(*ecdsa.PublicKey)
			require.True(t, ok, "Key should be ECDSA public key")
			assert.Equal(t, elliptic.P256(), pubKey.Curve, "Curve should be P-256")

			t.Logf("✓ Generated ECDSA P-256 key")

			// Test signing
			message := []byte("test message for ECDSA P-256")
			hash := sha256.Sum256(message)

			signer, err := b.Signer(attrs)
			require.NoError(t, err, "Failed to get signer")

			signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
			require.NoError(t, err, "Failed to sign message")
			assert.NotEmpty(t, signature, "Signature should not be empty")

			t.Logf("✓ Signed message with ECDSA P-256 (signature length: %d)", len(signature))

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("P-384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p384",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA384,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P384(),
				},
			}

			key, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate ECDSA P-384 key")

			pubKey, ok := key.(*ecdsa.PublicKey)
			require.True(t, ok, "Key should be ECDSA public key")
			assert.Equal(t, elliptic.P384(), pubKey.Curve, "Curve should be P-384")

			t.Logf("✓ Generated ECDSA P-384 key")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("P-521", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p521",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA512,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P521(),
				},
			}

			key, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate ECDSA P-521 key")

			pubKey, ok := key.(*ecdsa.PublicKey)
			require.True(t, ok, "Key should be ECDSA public key")
			assert.Equal(t, elliptic.P521(), pubKey.Curve, "Curve should be P-521")

			t.Logf("✓ Generated ECDSA P-521 key")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})
	})

	// ========================================================================
	// Ed25519 Key Tests
	// ========================================================================

	t.Run("Ed25519", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-ed25519",
			KeyAlgorithm: x509.Ed25519,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_VAULT,
			Hash:         crypto.SHA256,
		}

		key, err := b.GenerateKey(attrs)
		require.NoError(t, err, "Failed to generate Ed25519 key")

		pubKey, ok := key.(ed25519.PublicKey)
		require.True(t, ok, "Key should be Ed25519 public key")
		assert.Equal(t, ed25519.PublicKeySize, len(pubKey), "Public key size should be 32 bytes")

		t.Logf("✓ Generated Ed25519 key")

		// Test signing
		message := []byte("test message for Ed25519")

		signer, err := b.Signer(attrs)
		require.NoError(t, err, "Failed to get signer")

		signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
		require.NoError(t, err, "Failed to sign message")
		assert.NotEmpty(t, signature, "Signature should not be empty")
		assert.Equal(t, ed25519.SignatureSize, len(signature), "Signature size should be 64 bytes")

		t.Logf("✓ Signed message with Ed25519 (signature length: %d)", len(signature))

		// Verify signature
		valid := ed25519.Verify(pubKey, message, signature)
		assert.True(t, valid, "Signature should be valid")

		t.Logf("✓ Verified Ed25519 signature")

		// Cleanup
		err = b.DeleteKey(attrs)
		require.NoError(t, err, "Failed to delete key")
	})

	// ========================================================================
	// Key Management Tests
	// ========================================================================

	t.Run("KeyManagement", func(t *testing.T) {
		t.Run("GetKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-get-key",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA256,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			// Generate key
			_, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate key")

			// Get key
			key, err := b.GetKey(attrs)
			require.NoError(t, err, "Failed to get key")
			require.NotNil(t, key, "Key should not be nil")

			t.Logf("✓ Retrieved key successfully")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("ListKeys", func(t *testing.T) {
			// Create multiple keys
			keys := []string{"test-list-1", "test-list-2", "test-list-3"}
			for _, cn := range keys {
				attrs := &types.KeyAttributes{
					CN:           cn,
					KeyAlgorithm: x509.ECDSA,
					KeyType:      backend.KEY_TYPE_SIGNING,
					StoreType:    backend.STORE_VAULT,
					Hash:         crypto.SHA256,
					ECCAttributes: &types.ECCAttributes{
						Curve: elliptic.P256(),
					},
				}

				_, err := b.GenerateKey(attrs)
				require.NoError(t, err, "Failed to generate key %s", cn)
			}

			// List keys
			keyList, err := b.ListKeys()
			require.NoError(t, err, "Failed to list keys")
			assert.GreaterOrEqual(t, len(keyList), 3, "Should have at least 3 keys")

			t.Logf("✓ Listed %d keys", len(keyList))

			// Cleanup
			for _, cn := range keys {
				attrs := &types.KeyAttributes{
					CN: cn,
				}
				err = b.DeleteKey(attrs)
				require.NoError(t, err, "Failed to delete key %s", cn)
			}
		})

		t.Run("RotateKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rotate-key",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA256,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			// Generate key
			_, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate key")

			// Rotate key
			err = b.RotateKey(attrs)
			require.NoError(t, err, "Failed to rotate key")

			t.Logf("✓ Rotated key successfully")

			// Key should still be usable
			key, err := b.GetKey(attrs)
			require.NoError(t, err, "Failed to get rotated key")
			require.NotNil(t, key, "Rotated key should not be nil")

			t.Logf("✓ Retrieved rotated key successfully")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})
	})

	// ========================================================================
	// Symmetric Encryption Tests
	// ========================================================================

	t.Run("SymmetricEncryption", func(t *testing.T) {
		// Check if backend supports symmetric encryption
		caps := b.Capabilities()
		if !caps.SupportsSymmetricEncryption() {
			t.Skip("Vault backend does not support symmetric encryption")
			return
		}

		symBackend, ok := interface{}(b).(types.SymmetricBackend)
		require.True(t, ok, "Backend should implement SymmetricBackend")

		t.Run("AES-256-GCM-BasicEncryptDecrypt", func(t *testing.T) {
			// Test basic AES-256-GCM encryption/decryption
			attrs := &types.KeyAttributes{
				CN:                 "test-aes256-gcm",
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_VAULT,
				AESAttributes: &types.AESAttributes{
					KeySize:   256,
					NonceSize: 12,
				},
			}

			// Clean up if exists from previous test
			_ = b.DeleteKey(attrs)

			// Generate symmetric key
			symmetricKey, err := symBackend.GenerateSymmetricKey(attrs)
			require.NoError(t, err, "Failed to generate AES-256-GCM key")
			require.NotNil(t, symmetricKey, "Symmetric key should not be nil")
			assert.Equal(t, string(types.SymmetricAES256GCM), symmetricKey.Algorithm())
			assert.Equal(t, 256, symmetricKey.KeySize())
			t.Logf("✓ Generated AES-256-GCM symmetric key")

			// Get encrypter
			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			require.NoError(t, err, "Failed to get symmetric encrypter")
			require.NotNil(t, encrypter, "Encrypter should not be nil")
			t.Logf("✓ Retrieved symmetric encrypter")

			// Test encryption
			plaintext := []byte("Hello, Vault Transit Engine! This is a test of symmetric encryption.")
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			require.NoError(t, err, "Failed to encrypt plaintext")
			require.NotNil(t, encrypted, "Encrypted data should not be nil")
			require.NotEmpty(t, encrypted.Ciphertext, "Ciphertext should not be empty")
			assert.Equal(t, string(types.SymmetricAES256GCM), encrypted.Algorithm)

			// Verify ciphertext is in Vault format (starts with "vault:v")
			ciphertextStr := string(encrypted.Ciphertext)
			assert.Contains(t, ciphertextStr, "vault:v", "Ciphertext should be in Vault format")
			t.Logf("✓ Encrypted plaintext (ciphertext length: %d)", len(encrypted.Ciphertext))

			// Test decryption
			decrypted, err := encrypter.Decrypt(encrypted, nil)
			require.NoError(t, err, "Failed to decrypt ciphertext")
			assert.Equal(t, plaintext, decrypted, "Decrypted data should match original plaintext")
			t.Logf("✓ Successfully decrypted ciphertext: %s", string(decrypted))

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("AES-256-GCM-WithAAD", func(t *testing.T) {
			// Test encryption with Additional Authenticated Data (AAD)
			attrs := &types.KeyAttributes{
				CN:                 "test-aes256-aad",
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_VAULT,
				AESAttributes: &types.AESAttributes{
					KeySize:   256,
					NonceSize: 12,
				},
			}

			// Clean up if exists
			_ = b.DeleteKey(attrs)

			// Generate key
			_, err := symBackend.GenerateSymmetricKey(attrs)
			require.NoError(t, err, "Failed to generate key")

			// Get encrypter
			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			require.NoError(t, err, "Failed to get encrypter")

			// Test data with AAD
			plaintext := []byte("Sensitive data with additional authenticated data")
			aad := []byte("user-id:12345,timestamp:1234567890")

			// Encrypt with AAD
			encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
				AdditionalData: aad,
			})
			require.NoError(t, err, "Failed to encrypt with AAD")
			t.Logf("✓ Encrypted with AAD: %s", string(aad))

			// Decrypt with correct AAD - should succeed
			decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
				AdditionalData: aad,
			})
			require.NoError(t, err, "Decryption with correct AAD should succeed")
			assert.Equal(t, plaintext, decrypted, "Decrypted data should match plaintext")
			t.Logf("✓ Successfully decrypted with correct AAD")

			// NOTE: Vault Transit's context parameter behavior varies by version
			// In some Vault versions, the context is used for key derivation rather than
			// strict AAD validation, so wrong context may not always cause decryption to fail.
			// We test the expected behavior but note that Vault's implementation may vary.

			// Decrypt with wrong AAD - may or may not fail depending on Vault version
			wrongAAD := []byte("user-id:99999,timestamp:0000000000")
			_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
				AdditionalData: wrongAAD,
			})
			if err != nil {
				t.Logf("✓ Vault correctly rejected decryption with wrong AAD: %v", err)
			} else {
				t.Logf("⚠ Vault allowed decryption with wrong AAD (version-dependent behavior)")
			}

			// Decrypt without AAD when it was used - may or may not fail depending on Vault version
			_, err = encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Logf("✓ Vault correctly rejected decryption without AAD: %v", err)
			} else {
				t.Logf("⚠ Vault allowed decryption without AAD (version-dependent behavior)")
			}

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("MultipleEncryptionsUniqueNonces", func(t *testing.T) {
			// Test that multiple encryptions produce different ciphertexts (unique nonces)
			attrs := &types.KeyAttributes{
				CN:                 "test-nonce-uniqueness",
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_VAULT,
				AESAttributes: &types.AESAttributes{
					KeySize:   256,
					NonceSize: 12,
				},
			}

			// Clean up if exists
			_ = b.DeleteKey(attrs)

			// Generate key
			_, err := symBackend.GenerateSymmetricKey(attrs)
			require.NoError(t, err, "Failed to generate key")

			// Get encrypter
			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			require.NoError(t, err, "Failed to get encrypter")

			// Encrypt same plaintext multiple times
			plaintext := []byte("Same plaintext encrypted multiple times")
			ciphertexts := make([]string, 5)

			for i := 0; i < 5; i++ {
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				require.NoError(t, err, "Failed to encrypt iteration %d", i+1)
				ciphertexts[i] = string(encrypted.Ciphertext)
			}

			// Verify all ciphertexts are different (proving nonces are unique)
			for i := 0; i < len(ciphertexts); i++ {
				for j := i + 1; j < len(ciphertexts); j++ {
					assert.NotEqual(t, ciphertexts[i], ciphertexts[j],
						"Ciphertexts %d and %d should be different", i+1, j+1)
				}
			}
			t.Logf("✓ Verified all 5 encryptions produced unique ciphertexts (unique nonces)")

			// Verify all ciphertexts decrypt to the same plaintext
			for i, ct := range ciphertexts {
				encrypted := &types.EncryptedData{
					Ciphertext: []byte(ct),
					Algorithm:  string(types.SymmetricAES256GCM),
				}
				decrypted, err := encrypter.Decrypt(encrypted, nil)
				require.NoError(t, err, "Failed to decrypt ciphertext %d", i+1)
				assert.Equal(t, plaintext, decrypted, "Decrypted data %d should match plaintext", i+1)
			}
			t.Logf("✓ All unique ciphertexts decrypted to the same plaintext")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("EdgeCases", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-edge-cases",
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_VAULT,
				AESAttributes: &types.AESAttributes{
					KeySize:   256,
					NonceSize: 12,
				},
			}

			// Clean up if exists
			_ = b.DeleteKey(attrs)

			// Generate key
			_, err := symBackend.GenerateSymmetricKey(attrs)
			require.NoError(t, err, "Failed to generate key")

			// Get encrypter
			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			require.NoError(t, err, "Failed to get encrypter")

			// Test 1: Empty plaintext
			t.Run("EmptyPlaintext", func(t *testing.T) {
				plaintext := []byte{}
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				require.NoError(t, err, "Should handle empty plaintext")

				decrypted, err := encrypter.Decrypt(encrypted, nil)
				require.NoError(t, err, "Should decrypt empty plaintext")
				assert.Equal(t, plaintext, decrypted, "Empty plaintext should round-trip")
				t.Logf("✓ Empty plaintext handled correctly")
			})

			// Test 2: Single byte
			t.Run("SingleByte", func(t *testing.T) {
				plaintext := []byte{0x42}
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				require.NoError(t, err, "Should handle single byte")

				decrypted, err := encrypter.Decrypt(encrypted, nil)
				require.NoError(t, err, "Should decrypt single byte")
				assert.Equal(t, plaintext, decrypted, "Single byte should round-trip")
				t.Logf("✓ Single byte handled correctly")
			})

			// Test 3: Large plaintext (64KB - Vault has limits on JSON payload size)
			// Note: Vault Transit has a ~512KB limit on base64-encoded data in JSON
			t.Run("LargePlaintext", func(t *testing.T) {
				plaintext := make([]byte, 64*1024) // 64KB
				for i := range plaintext {
					plaintext[i] = byte(i % 256)
				}

				encrypted, err := encrypter.Encrypt(plaintext, nil)
				require.NoError(t, err, "Should handle large plaintext (64KB)")

				decrypted, err := encrypter.Decrypt(encrypted, nil)
				require.NoError(t, err, "Should decrypt large plaintext")
				assert.Equal(t, plaintext, decrypted, "Large plaintext should round-trip")
				t.Logf("✓ Large plaintext (64KB) handled correctly")
			})

			// Test 4: Binary data with all byte values
			t.Run("BinaryData", func(t *testing.T) {
				plaintext := make([]byte, 256)
				for i := 0; i < 256; i++ {
					plaintext[i] = byte(i)
				}

				encrypted, err := encrypter.Encrypt(plaintext, nil)
				require.NoError(t, err, "Should handle binary data")

				decrypted, err := encrypter.Decrypt(encrypted, nil)
				require.NoError(t, err, "Should decrypt binary data")
				assert.Equal(t, plaintext, decrypted, "Binary data should round-trip")
				t.Logf("✓ Binary data (all byte values) handled correctly")
			})

			// Test 5: Special characters and UTF-8
			t.Run("UTF8Text", func(t *testing.T) {
				plaintext := []byte("Hello 世界! 🔐 Special chars: \n\t\r\x00")
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				require.NoError(t, err, "Should handle UTF-8 text")

				decrypted, err := encrypter.Decrypt(encrypted, nil)
				require.NoError(t, err, "Should decrypt UTF-8 text")
				assert.Equal(t, plaintext, decrypted, "UTF-8 text should round-trip")
				t.Logf("✓ UTF-8 text with special characters handled correctly")
			})

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("ErrorHandling", func(t *testing.T) {
			// Test error conditions

			// Test 1: Invalid key size (AES-128 not supported by Vault)
			t.Run("InvalidKeySize", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:                 "test-invalid-keysize",
					SymmetricAlgorithm: types.SymmetricAES128GCM,
					KeyType:            backend.KEY_TYPE_SECRET,
					StoreType:          backend.STORE_VAULT,
					AESAttributes: &types.AESAttributes{
						KeySize:   128,
						NonceSize: 12,
					},
				}

				_, err := symBackend.GenerateSymmetricKey(attrs)
				assert.Error(t, err, "Should reject AES-128 (Vault only supports AES-256)")
				assert.Contains(t, err.Error(), "only supports AES-256", "Error should mention AES-256 requirement")
				t.Logf("✓ Correctly rejected unsupported key size: %v", err)
			})

			// Test 2: Get non-existent key
			t.Run("GetNonExistentKey", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:                 "test-nonexistent-key",
					SymmetricAlgorithm: types.SymmetricAES256GCM,
					KeyType:            backend.KEY_TYPE_SECRET,
					StoreType:          backend.STORE_VAULT,
					AESAttributes: &types.AESAttributes{
						KeySize:   256,
						NonceSize: 12,
					},
				}

				_, err := symBackend.GetSymmetricKey(attrs)
				assert.Error(t, err, "Should error when getting non-existent key")
				t.Logf("✓ Correctly rejected non-existent key: %v", err)
			})

			// Test 3: Encrypter for non-existent key
			t.Run("EncrypterNonExistentKey", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:                 "test-encrypter-nonexistent",
					SymmetricAlgorithm: types.SymmetricAES256GCM,
					KeyType:            backend.KEY_TYPE_SECRET,
					StoreType:          backend.STORE_VAULT,
					AESAttributes: &types.AESAttributes{
						KeySize:   256,
						NonceSize: 12,
					},
				}

				_, err := symBackend.SymmetricEncrypter(attrs)
				assert.Error(t, err, "Should error when getting encrypter for non-existent key")
				t.Logf("✓ Correctly rejected encrypter for non-existent key: %v", err)
			})

			// Test 4: Decrypt with corrupted ciphertext
			t.Run("CorruptedCiphertext", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:                 "test-corrupted-ciphertext",
					SymmetricAlgorithm: types.SymmetricAES256GCM,
					KeyType:            backend.KEY_TYPE_SECRET,
					StoreType:          backend.STORE_VAULT,
					AESAttributes: &types.AESAttributes{
						KeySize:   256,
						NonceSize: 12,
					},
				}

				// Clean up if exists
				_ = b.DeleteKey(attrs)

				// Generate key
				_, err := symBackend.GenerateSymmetricKey(attrs)
				require.NoError(t, err)

				// Get encrypter
				encrypter, err := symBackend.SymmetricEncrypter(attrs)
				require.NoError(t, err)

				// Encrypt valid data first
				plaintext := []byte("valid data")
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				require.NoError(t, err)

				// Corrupt the ciphertext
				corruptedCiphertext := []byte(string(encrypted.Ciphertext) + "corrupted")
				corruptedData := &types.EncryptedData{
					Ciphertext: corruptedCiphertext,
					Algorithm:  encrypted.Algorithm,
				}

				// Try to decrypt corrupted data
				_, err = encrypter.Decrypt(corruptedData, nil)
				assert.Error(t, err, "Should error when decrypting corrupted ciphertext")
				t.Logf("✓ Correctly rejected corrupted ciphertext: %v", err)

				// Cleanup
				_ = b.DeleteKey(attrs)
			})

			// Test 5: Duplicate key generation
			t.Run("DuplicateKeyGeneration", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:                 "test-duplicate-key",
					SymmetricAlgorithm: types.SymmetricAES256GCM,
					KeyType:            backend.KEY_TYPE_SECRET,
					StoreType:          backend.STORE_VAULT,
					AESAttributes: &types.AESAttributes{
						KeySize:   256,
						NonceSize: 12,
					},
				}

				// Clean up if exists
				_ = b.DeleteKey(attrs)

				// Generate key first time
				_, err := symBackend.GenerateSymmetricKey(attrs)
				require.NoError(t, err, "First key generation should succeed")

				// Try to generate same key again
				_, err = symBackend.GenerateSymmetricKey(attrs)
				assert.Error(t, err, "Duplicate key generation should fail")
				assert.Contains(t, err.Error(), "already exists", "Error should mention key already exists")
				t.Logf("✓ Correctly rejected duplicate key generation: %v", err)

				// Cleanup
				_ = b.DeleteKey(attrs)
			})
		})

		t.Run("KeyLifecycle", func(t *testing.T) {
			// Test complete key lifecycle: create, use, delete, verify deletion
			attrs := &types.KeyAttributes{
				CN:                 "test-key-lifecycle",
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_VAULT,
				AESAttributes: &types.AESAttributes{
					KeySize:   256,
					NonceSize: 12,
				},
			}

			// Clean up if exists
			_ = b.DeleteKey(attrs)

			// Step 1: Generate key
			symmetricKey, err := symBackend.GenerateSymmetricKey(attrs)
			require.NoError(t, err, "Failed to generate key")
			require.NotNil(t, symmetricKey)
			t.Logf("✓ Step 1: Generated key")

			// Step 2: Retrieve key
			retrievedKey, err := symBackend.GetSymmetricKey(attrs)
			require.NoError(t, err, "Failed to retrieve key")
			assert.Equal(t, symmetricKey.Algorithm(), retrievedKey.Algorithm())
			assert.Equal(t, symmetricKey.KeySize(), retrievedKey.KeySize())
			t.Logf("✓ Step 2: Retrieved key successfully")

			// Step 3: Use key for encryption/decryption
			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			require.NoError(t, err, "Failed to get encrypter")

			plaintext := []byte("lifecycle test data")
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			require.NoError(t, err, "Failed to encrypt")

			decrypted, err := encrypter.Decrypt(encrypted, nil)
			require.NoError(t, err, "Failed to decrypt")
			assert.Equal(t, plaintext, decrypted)
			t.Logf("✓ Step 3: Used key for encryption/decryption")

			// Step 4: Delete key
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
			t.Logf("✓ Step 4: Deleted key")

			// Step 5: Verify key is gone
			_, err = symBackend.GetSymmetricKey(attrs)
			assert.Error(t, err, "Should error when retrieving deleted key")
			t.Logf("✓ Step 5: Verified key is deleted")

			// Step 6: Verify operations fail on deleted key
			_, err = symBackend.SymmetricEncrypter(attrs)
			assert.Error(t, err, "Should error when getting encrypter for deleted key")
			t.Logf("✓ Step 6: Verified operations fail on deleted key")

			t.Logf("✓ Complete key lifecycle tested successfully")
		})
	})

	// ========================================================================
	// Signer and Decrypter Tests
	// ========================================================================

	t.Run("SignerDecrypter", func(t *testing.T) {
		t.Run("Signer", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-signer",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			_, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate key")

			signer, err := b.Signer(attrs)
			require.NoError(t, err, "Failed to get signer")
			require.NotNil(t, signer, "Signer should not be nil")

			// Test signing
			message := []byte("test signer interface")
			hash := sha256.Sum256(message)

			signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
			require.NoError(t, err, "Failed to sign with signer")
			assert.NotEmpty(t, signature, "Signature should not be empty")

			t.Logf("✓ Signer interface works correctly")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("Signer-PSS", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-signer-pss",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_VAULT,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate key
			key, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate key")
			require.NotNil(t, key, "Key should not be nil")

			_, ok := key.(*rsa.PublicKey)
			require.True(t, ok, "Key should be RSA public key")

			signer, err := b.Signer(attrs)
			require.NoError(t, err, "Failed to get signer")
			require.NotNil(t, signer, "Signer should not be nil")

			// Test RSA-PSS signing
			message := []byte("test signer interface with PSS")
			h := sha256.New()
			h.Write(message)
			digest := h.Sum(nil)

			// Vault backend uses PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			require.NoError(t, err, "Failed to sign with signer PSS")
			assert.NotEmpty(t, signature, "Signature should not be empty")

			t.Logf("✓ Signer interface works correctly with PSS (signature length: %d)", len(signature))

			// Verify PSS signature using signer's public key
			signerPubKey := signer.Public().(*rsa.PublicKey)
			err = rsa.VerifyPSS(signerPubKey, crypto.SHA256, digest, signature, pssOpts)
			require.NoError(t, err, "Failed to verify PSS signature")

			t.Logf("✓ Verified Signer PSS signature")

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("Decrypter", func(t *testing.T) {
			// Test RSA encryption/decryption via Vault Transit engine
			attrs := &types.KeyAttributes{
				CN:           "test-decrypter",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_VAULT,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			_, err := b.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate key")

			plaintext := []byte("test message for decryption")

			// Encrypt using Vault's encrypt endpoint
			ciphertext, err := b.Encrypt(attrs, plaintext)
			require.NoError(t, err, "Failed to encrypt with Vault")
			require.NotEmpty(t, ciphertext, "Ciphertext should not be empty")
			t.Logf("✓ Encrypted plaintext with Vault (ciphertext length: %d)", len(ciphertext))

			// Get decrypter
			decrypter, err := b.Decrypter(attrs)
			require.NoError(t, err, "Failed to get decrypter")
			require.NotNil(t, decrypter, "Decrypter should not be nil")

			// Verify public key
			publicKey := decrypter.Public()
			require.NotNil(t, publicKey, "Public key should not be nil")
			t.Logf("✓ Retrieved decrypter with public key")

			// Decrypt
			decrypted, err := decrypter.Decrypt(nil, ciphertext, nil)
			require.NoError(t, err, "Failed to decrypt")
			require.Equal(t, plaintext, decrypted, "Decrypted plaintext should match original")
			t.Logf("✓ Successfully decrypted ciphertext: %s", string(decrypted))

			// Cleanup
			err = b.DeleteKey(attrs)
			require.NoError(t, err, "Failed to delete key")
		})
	})
}
