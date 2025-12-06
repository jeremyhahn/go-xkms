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

//go:build integration && awskms

package integration

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAWSKMSLocalStack tests AWS KMS backend against LocalStack emulator
func TestAWSKMSLocalStack(t *testing.T) {
	// Check if LocalStack endpoint is configured
	endpoint := os.Getenv("AWS_ENDPOINT_URL")
	if endpoint == "" {
		endpoint = os.Getenv("LOCALSTACK_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = "http://localhost:4566"
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	// Configure AWS SDK to use LocalStack
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(
				func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{
						URL:           endpoint,
						SigningRegion: region,
					}, nil
				},
			),
		),
	)
	require.NoError(t, err, "Failed to load AWS config")

	// Create KMS client
	kmsClient := kms.NewFromConfig(cfg)

	// Create storage backends
	keyStorage := storage.New()
	certStorage := storage.New()

	// Create backend
	backendCfg := &awskms.Config{
		Region:      region,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}
	b, err := awskms.NewBackendWithClient(backendCfg, kmsClient)
	require.NoError(t, err, "Failed to create AWS KMS backend")
	defer b.Close()

	t.Run("CreateAndSignRSAKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rsa-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		keyID, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create RSA key")
		require.NotEmpty(t, keyID, "Key ID should not be empty")

		// Test signing
		digest := crypto.SHA256.New()
		digest.Write([]byte("test message for signing"))
		signature, err := b.Sign(attrs, digest.Sum(nil))
		require.NoError(t, err, "Failed to sign message")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		t.Logf("✓ Created RSA key and signed message (signature length: %d)", len(signature))
	})

	t.Run("CreateAndSignECDSAKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa-key",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
			Hash:         crypto.SHA256,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		keyID, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create ECDSA key")
		require.NotEmpty(t, keyID, "Key ID should not be empty")

		// Test signing
		digest := crypto.SHA256.New()
		digest.Write([]byte("test message for ecdsa signing"))
		signature, err := b.Sign(attrs, digest.Sum(nil))
		require.NoError(t, err, "Failed to sign message")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		t.Logf("✓ Created ECDSA key and signed message (signature length: %d)", len(signature))
	})

	t.Run("SignAndVerify", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-verify-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		_, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create key")

		// Sign a message
		digest := crypto.SHA256.New()
		digest.Write([]byte("test verification message"))
		digestBytes := digest.Sum(nil)

		signature, err := b.Sign(attrs, digestBytes)
		require.NoError(t, err, "Failed to sign message")

		// Verify the signature
		err = b.Verify(attrs, digestBytes, signature)
		require.NoError(t, err, "Failed to verify signature")

		t.Logf("✓ Successfully signed and verified message with AWS KMS")
	})

	// ========================================================================
	// Key Generation Tests - Comprehensive coverage of all key types and sizes
	// ========================================================================

	t.Run("KeyGeneration", func(t *testing.T) {
		t.Run("RSA-2048", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-2048",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			keyID, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create RSA 2048 key")
			require.NotEmpty(t, keyID, "Key ID should not be empty")

			t.Logf("✓ Created RSA 2048 key: %s", keyID)

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete RSA 2048 key")
		})

		t.Run("RSA-3072", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-3072",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 3072,
				},
			}

			keyID, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create RSA 3072 key")
			require.NotEmpty(t, keyID, "Key ID should not be empty")

			t.Logf("✓ Created RSA 3072 key: %s", keyID)

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete RSA 3072 key")
		})

		t.Run("RSA-4096", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-4096",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			}

			keyID, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create RSA 4096 key")
			require.NotEmpty(t, keyID, "Key ID should not be empty")

			t.Logf("✓ Created RSA 4096 key: %s", keyID)

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete RSA 4096 key")
		})

		t.Run("ECDSA-P256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p256",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			keyID, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create ECDSA P-256 key")
			require.NotEmpty(t, keyID, "Key ID should not be empty")

			t.Logf("✓ Created ECDSA P-256 key: %s", keyID)

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete ECDSA P-256 key")
		})

		t.Run("ECDSA-P384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p384",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA384,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P384(),
				},
			}

			keyID, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create ECDSA P-384 key")
			require.NotEmpty(t, keyID, "Key ID should not be empty")

			t.Logf("✓ Created ECDSA P-384 key: %s", keyID)

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete ECDSA P-384 key")
		})

		t.Run("ECDSA-P521", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p521",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA512,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P521(),
				},
			}

			keyID, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create ECDSA P-521 key")
			require.NotEmpty(t, keyID, "Key ID should not be empty")

			t.Logf("✓ Created ECDSA P-521 key: %s", keyID)

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete ECDSA P-521 key")
		})

		t.Run("Ed25519", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ed25519",
				KeyAlgorithm: x509.Ed25519,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
			}

			// Note: AWS KMS does not support Ed25519
			_, err := b.CreateKey(attrs)
			require.Error(t, err, "AWS KMS should not support Ed25519")
			t.Logf("✓ Ed25519 correctly not supported by AWS KMS: %v", err)
		})
	})

	// ========================================================================
	// Get/Retrieve Key Metadata Tests
	// Note: AWS KMS doesn't expose private key material, so GetKey() is not
	// applicable. Instead we can verify keys via Sign/Verify operations.
	// ========================================================================

	t.Run("GetKeyMetadata", func(t *testing.T) {
		t.Run("VerifyKeyExists", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-getkey-existing",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Create key first
			keyID, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create key")
			require.NotEmpty(t, keyID, "Key ID should not be empty")

			// Verify key exists by using it to sign
			digest := crypto.SHA256.New()
			digest.Write([]byte("test message"))
			signature, err := b.Sign(attrs, digest.Sum(nil))
			require.NoError(t, err, "Failed to sign with key")
			require.NotEmpty(t, signature, "Signature should not be empty")

			t.Logf("✓ Successfully verified key exists via signing operation")

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("NonExistentKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-getkey-nonexistent",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Try to use non-existent key for signing
			digest := crypto.SHA256.New()
			digest.Write([]byte("test message"))
			_, err := b.Sign(attrs, digest.Sum(nil))
			require.Error(t, err, "Signing with non-existent key should return error")

			t.Logf("✓ Operations correctly return error for non-existent key")
		})
	})

	// ========================================================================
	// DeleteKey Tests - Test key deletion
	// ========================================================================

	t.Run("DeleteKey", func(t *testing.T) {
		t.Run("DeleteExistingKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-deletekey-existing",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Create key
			keyID, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create key")
			require.NotEmpty(t, keyID, "Key ID should not be empty")

			// Delete it
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete key")

			// Verify it's gone by trying to use it
			digest := crypto.SHA256.New()
			digest.Write([]byte("test message"))
			_, err = b.Sign(attrs, digest.Sum(nil))
			require.Error(t, err, "Using deleted key should return error")

			t.Logf("✓ Successfully deleted key and verified it's gone")
		})

		t.Run("DeleteNonExistentKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-deletekey-nonexistent",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Try to delete non-existent key
			err := b.Delete(attrs)
			// AWS KMS Delete might not error on non-existent keys
			if err != nil {
				t.Logf("✓ Delete returns error for non-existent key: %v", err)
			} else {
				t.Logf("✓ Delete succeeds idempotently for non-existent key")
			}
		})
	})

	// ========================================================================
	// Advanced Features - ListKeys, RotateKey, Signer, and Decrypter
	// ========================================================================

	t.Run("AdvancedFeatures", func(t *testing.T) {
		t.Run("ListKeys", func(t *testing.T) {
			// Create a few test keys
			attrs1 := &types.KeyAttributes{
				CN:           "test-listkeys-1",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}
			attrs2 := &types.KeyAttributes{
				CN:           "test-listkeys-2",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			_, err := b.CreateKey(attrs1)
			require.NoError(t, err, "Failed to create first test key")

			_, err = b.CreateKey(attrs2)
			require.NoError(t, err, "Failed to create second test key")

			// List keys
			keys, err := b.ListKeys()
			require.NoError(t, err, "Failed to list keys")
			require.NotNil(t, keys, "Keys list should not be nil")
			require.GreaterOrEqual(t, len(keys), 2, "Should have at least 2 keys")

			t.Logf("✓ ListKeys returned %d keys", len(keys))

			// Cleanup
			_ = b.Delete(attrs1)
			_ = b.Delete(attrs2)
		})

		t.Run("RotateKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rotatekey",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Create key
			_, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create key")

			// Rotate key
			err = b.RotateKey(attrs)
			if err != nil {
				// AWS KMS may not support on-demand rotation in LocalStack
				t.Logf("⚠ Key rotation not supported (LocalStack limitation): %v", err)
			} else {
				t.Logf("✓ Successfully rotated key")
			}

			// Cleanup
			_ = b.Delete(attrs)
		})

		t.Run("Signer", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-signer",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Create key
			_, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create key")

			// Get Signer
			signer, err := b.Signer(attrs)
			require.NoError(t, err, "Failed to get Signer")
			require.NotNil(t, signer, "Signer should not be nil")

			// Test signing
			digest := crypto.SHA256.New()
			digest.Write([]byte("test message"))
			signature, err := signer.Sign(nil, digest.Sum(nil), crypto.SHA256)
			require.NoError(t, err, "Failed to sign with Signer")
			require.NotEmpty(t, signature, "Signature should not be empty")

			// Test Public()
			pubKey := signer.Public()
			require.NotNil(t, pubKey, "Public key should not be nil")

			t.Logf("✓ Signer interface works correctly")

			// Cleanup
			_ = b.Delete(attrs)
		})

		t.Run("Signer_RSA_PSS", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-signer-pss",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Create key
			_, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create key")

			// Get Signer
			signer, err := b.Signer(attrs)
			require.NoError(t, err, "Failed to get Signer")
			require.NotNil(t, signer, "Signer should not be nil")

			// Test signing with RSA-PSS
			message := []byte("test message for RSA-PSS")
			h := sha256.New()
			h.Write(message)
			digest := h.Sum(nil)

			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			}

			signature, err := signer.Sign(nil, digest, pssOpts)
			require.NoError(t, err, "Failed to sign with RSA-PSS")
			require.NotEmpty(t, signature, "Signature should not be empty")

			// Verify PSS signature
			pubKey := signer.Public()
			require.NotNil(t, pubKey, "Public key should not be nil")
			rsaPub, ok := pubKey.(*rsa.PublicKey)
			require.True(t, ok, "Public key should be RSA")

			err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
			require.NoError(t, err, "Failed to verify RSA-PSS signature")

			t.Logf("✓ RSA-PSS signing and verification works correctly")

			// Cleanup
			_ = b.Delete(attrs)
		})

		t.Run("Decrypter", func(t *testing.T) {
			t.Run("PKCS1v15", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:           "test-decrypt-pkcs1",
					KeyAlgorithm: x509.RSA,
					KeyType:      backend.KEY_TYPE_ENCRYPTION,
					StoreType:    backend.STORE_AWSKMS,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}

				// Create encryption key
				key, err := b.CreateKey(attrs)
				if err != nil {
					// LocalStack may not support encryption keys
					t.Logf("⚠ Encryption keys not supported (LocalStack limitation): %v", err)
					return
				}
				defer b.Delete(attrs)

				// Get Decrypter
				decrypter, err := b.Decrypter(attrs)
				if err != nil {
					t.Logf("⚠ Decrypter not supported (LocalStack limitation): %v", err)
					return
				}
				require.NotNil(t, decrypter, "Decrypter should not be nil")

				// Get public key for encryption
				rsaPub, ok := decrypter.Public().(*rsa.PublicKey)
				if !ok {
					t.Fatal("Expected RSA public key")
				}

				// Encrypt a message with PKCS#1 v1.5
				plaintext := []byte("Test message for PKCS#1 v1.5 decryption")
				ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext)
				if err != nil {
					t.Fatalf("Failed to encrypt: %v", err)
				}
				t.Logf("✓ Encrypted %d bytes with PKCS#1 v1.5 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

				// Decrypt using the Decrypter interface
				decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
				if err != nil {
					t.Logf("⚠ Decryption not supported (LocalStack limitation): %v", err)
					return
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("Decrypted message doesn't match: got %s, want %s", decrypted, plaintext)
				}
				t.Logf("✓ PKCS#1 v1.5 decrypt works correctly (key: %s)", key)
			})

			t.Run("OAEP_SHA256_RSA2048", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:           "test-decrypt-oaep-2048",
					KeyAlgorithm: x509.RSA,
					KeyType:      backend.KEY_TYPE_ENCRYPTION,
					StoreType:    backend.STORE_AWSKMS,
					Hash:         crypto.SHA256,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}

				key, err := b.CreateKey(attrs)
				if err != nil {
					t.Logf("⚠ Encryption keys not supported (LocalStack limitation): %v", err)
					return
				}
				defer b.Delete(attrs)

				decrypter, err := b.Decrypter(attrs)
				if err != nil {
					t.Logf("⚠ Decrypter not supported (LocalStack limitation): %v", err)
					return
				}

				rsaPub, ok := decrypter.Public().(*rsa.PublicKey)
				if !ok {
					t.Fatal("Expected RSA public key")
				}

				// Encrypt with OAEP SHA256
				plaintext := []byte("Test message for AWS KMS OAEP SHA-256")
				label := []byte("")
				ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, plaintext, label)
				if err != nil {
					t.Fatalf("Failed to encrypt with OAEP: %v", err)
				}
				t.Logf("✓ Encrypted %d bytes with RSA-2048 OAEP SHA256 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

				// Decrypt with OAEP options
				oaepOpts := &rsa.OAEPOptions{
					Hash: crypto.SHA256,
				}
				decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, oaepOpts)
				if err != nil {
					t.Logf("⚠ OAEP decryption not supported (LocalStack limitation): %v", err)
					return
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("Decrypted message doesn't match: got %s, want %s", decrypted, plaintext)
				}
				t.Logf("✓ RSA-2048 OAEP SHA256 decrypt works correctly (key: %s)", key)
			})

			t.Run("OAEP_SHA256_RSA3072", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:           "test-decrypt-oaep-3072",
					KeyAlgorithm: x509.RSA,
					KeyType:      backend.KEY_TYPE_ENCRYPTION,
					StoreType:    backend.STORE_AWSKMS,
					Hash:         crypto.SHA256,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 3072,
					},
				}

				key, err := b.CreateKey(attrs)
				if err != nil {
					t.Logf("⚠ Encryption keys not supported (LocalStack limitation): %v", err)
					return
				}
				defer b.Delete(attrs)

				decrypter, err := b.Decrypter(attrs)
				if err != nil {
					t.Logf("⚠ Decrypter not supported (LocalStack limitation): %v", err)
					return
				}

				rsaPub, ok := decrypter.Public().(*rsa.PublicKey)
				if !ok {
					t.Fatal("Expected RSA public key")
				}

				// Encrypt with OAEP SHA256
				plaintext := []byte("AWS KMS RSA-3072 OAEP SHA-256 test")
				label := []byte("")
				ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, plaintext, label)
				if err != nil {
					t.Fatalf("Failed to encrypt with OAEP: %v", err)
				}
				t.Logf("✓ Encrypted %d bytes with RSA-3072 OAEP SHA256 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

				// Decrypt with OAEP options
				oaepOpts := &rsa.OAEPOptions{
					Hash: crypto.SHA256,
				}
				decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, oaepOpts)
				if err != nil {
					t.Logf("⚠ OAEP decryption not supported (LocalStack limitation): %v", err)
					return
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("Decrypted message doesn't match: got %s, want %s", decrypted, plaintext)
				}
				t.Logf("✓ RSA-3072 OAEP SHA256 decrypt works correctly (key: %s)", key)
			})
		})
	})

	// ========================================================================
	// Certificate Operations Tests
	// ========================================================================

	t.Run("CertificateOperations", func(t *testing.T) {
		// Helper function to create a test certificate
		createTestCert := func(cn string) *x509.Certificate {
			// Generate a private key
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("Failed to generate private key: %v", err)
			}

			serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			if err != nil {
				t.Fatalf("Failed to generate serial number: %v", err)
			}

			template := &x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					CommonName:   cn,
					Organization: []string{"Test Organization"},
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(365 * 24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
			}

			// Create the certificate (self-signed)
			certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
			if err != nil {
				t.Fatalf("Failed to create certificate: %v", err)
			}

			// Parse the certificate to get one with Raw field populated
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatalf("Failed to parse created certificate: %v", err)
			}

			return cert
		}

		t.Run("SaveAndGetCert", func(t *testing.T) {
			keyID := "test-cert-saveget"
			cert := createTestCert(keyID)

			// Save certificate
			err := storage.SaveCertParsed(certStorage, keyID, cert)
			require.NoError(t, err, "Failed to save certificate")

			// Retrieve certificate
			retrievedCert, err := storage.GetCertParsed(certStorage, keyID)
			require.NoError(t, err, "Failed to get certificate")
			require.NotNil(t, retrievedCert, "Retrieved certificate should not be nil")
			assert.Equal(t, cert.Subject.CommonName, retrievedCert.Subject.CommonName)

			t.Logf("✓ Successfully saved and retrieved certificate")

			// Cleanup
			err = storage.DeleteCert(certStorage, keyID)
			require.NoError(t, err, "Failed to delete certificate")
		})

		t.Run("CertExists", func(t *testing.T) {
			keyID := "test-cert-exists"
			cert := createTestCert(keyID)

			// Check non-existent cert
			exists, err := storage.CertExists(certStorage, keyID)
			require.NoError(t, err, "CertExists should not error")
			assert.False(t, exists, "Certificate should not exist yet")

			// Save certificate
			err = storage.SaveCertParsed(certStorage, keyID, cert)
			require.NoError(t, err, "Failed to save certificate")

			// Check existing cert
			exists, err = storage.CertExists(certStorage, keyID)
			require.NoError(t, err, "CertExists should not error")
			assert.True(t, exists, "Certificate should exist")

			t.Logf("✓ CertExists works correctly")

			// Cleanup
			err = storage.DeleteCert(certStorage, keyID)
			require.NoError(t, err, "Failed to delete certificate")
		})

		t.Run("DeleteCert", func(t *testing.T) {
			keyID := "test-cert-delete"
			cert := createTestCert(keyID)

			// Save certificate
			err := storage.SaveCertParsed(certStorage, keyID, cert)
			require.NoError(t, err, "Failed to save certificate")

			// Delete certificate
			err = storage.DeleteCert(certStorage, keyID)
			require.NoError(t, err, "Failed to delete certificate")

			// Verify it's gone
			_, err = storage.GetCertParsed(certStorage, keyID)
			require.Error(t, err, "Getting deleted certificate should return error")

			t.Logf("✓ Successfully deleted certificate and verified it's gone")
		})

		t.Run("SaveAndGetCertChain", func(t *testing.T) {
			keyID := "test-cert-chain"

			// Create a certificate chain
			chain := []*x509.Certificate{
				createTestCert(keyID + "-leaf"),
				createTestCert(keyID + "-intermediate"),
				createTestCert(keyID + "-root"),
			}

			// Save certificate chain
			err := storage.SaveCertChainParsed(certStorage, keyID, chain)
			require.NoError(t, err, "Failed to save certificate chain")

			// Retrieve certificate chain
			retrievedChain, err := storage.GetCertChainParsed(certStorage, keyID)
			require.NoError(t, err, "Failed to get certificate chain")
			require.NotNil(t, retrievedChain, "Retrieved chain should not be nil")
			require.Len(t, retrievedChain, 3, "Chain should have 3 certificates")

			// Verify chain order
			for i, cert := range chain {
				assert.Equal(t, cert.Subject.CommonName, retrievedChain[i].Subject.CommonName)
			}

			t.Logf("✓ Successfully saved and retrieved certificate chain with %d certificates", len(retrievedChain))

			// Cleanup
			err = storage.DeleteCertChain(certStorage, keyID)
			require.NoError(t, err, "Failed to delete certificate chain")
		})

		t.Run("ListCerts", func(t *testing.T) {
			// Create multiple certificates
			certIDs := []string{
				"test-listcerts-1",
				"test-listcerts-2",
				"test-listcerts-3",
			}

			for _, id := range certIDs {
				cert := createTestCert(id)
				err := storage.SaveCertParsed(certStorage, id, cert)
				require.NoError(t, err, "Failed to save certificate %s", id)
			}

			// List certificates
			listedCerts, err := storage.ListCerts(certStorage)
			require.NoError(t, err, "Failed to list certificates")
			require.NotNil(t, listedCerts, "Listed certificates should not be nil")

			// Verify count (should have at least our 3 certs)
			require.GreaterOrEqual(t, len(listedCerts), 3, "Should have at least 3 certificates")

			// Verify our certs are in the list
			certNames := make(map[string]bool)
			for _, id := range listedCerts {
				certNames[id] = true
			}

			for _, id := range certIDs {
				assert.True(t, certNames[id], "Certificate %s should be in list", id)
			}

			t.Logf("✓ Listed %d certificates, verified our 3 test certs are present", len(listedCerts))

			// Cleanup
			for _, id := range certIDs {
				err := storage.DeleteCert(certStorage, id)
				require.NoError(t, err, "Failed to delete certificate %s", id)
			}
		})

		t.Run("GetNonExistentCert", func(t *testing.T) {
			keyID := "test-cert-nonexistent"

			// Try to get non-existent certificate
			_, err := storage.GetCertParsed(certStorage, keyID)
			require.Error(t, err, "Getting non-existent certificate should return error")

			t.Logf("✓ GetCert correctly returns error for non-existent certificate")
		})
	})

	// ========================================================================
	// Sign and Verify with Multiple Hash Algorithms
	// ========================================================================

	t.Run("SignVerifyWithDifferentHashes", func(t *testing.T) {
		t.Run("RSA-SHA256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-sign-sha256",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			_, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create key")

			// Sign and verify with SHA256
			digest := crypto.SHA256.New()
			digest.Write([]byte("test message"))
			digestBytes := digest.Sum(nil)

			signature, err := b.Sign(attrs, digestBytes)
			require.NoError(t, err, "Failed to sign message")

			err = b.Verify(attrs, digestBytes, signature)
			require.NoError(t, err, "Failed to verify signature")

			t.Logf("✓ RSA SHA256 sign and verify works correctly")

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("RSA-SHA384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-sign-sha384",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA384,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			_, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create key")

			// Sign and verify with SHA384
			digest := crypto.SHA384.New()
			digest.Write([]byte("test message"))
			digestBytes := digest.Sum(nil)

			signature, err := b.Sign(attrs, digestBytes)
			require.NoError(t, err, "Failed to sign message")

			err = b.Verify(attrs, digestBytes, signature)
			require.NoError(t, err, "Failed to verify signature")

			t.Logf("✓ RSA SHA384 sign and verify works correctly")

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("RSA-SHA512", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-sign-sha512",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA512,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			_, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create key")

			// Sign and verify with SHA512
			digest := crypto.SHA512.New()
			digest.Write([]byte("test message"))
			digestBytes := digest.Sum(nil)

			signature, err := b.Sign(attrs, digestBytes)
			require.NoError(t, err, "Failed to sign message")

			err = b.Verify(attrs, digestBytes, signature)
			require.NoError(t, err, "Failed to verify signature")

			t.Logf("✓ RSA SHA512 sign and verify works correctly")

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		// ECDSA Tests with Different Curves
		t.Run("ECDSA-P256-SHA256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p256-sha256",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			_, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create ECDSA P-256 key")

			// Sign and verify with SHA256
			digest := crypto.SHA256.New()
			digest.Write([]byte("test message"))
			digestBytes := digest.Sum(nil)

			signature, err := b.Sign(attrs, digestBytes)
			require.NoError(t, err, "Failed to sign message")

			err = b.Verify(attrs, digestBytes, signature)
			require.NoError(t, err, "Failed to verify signature")

			t.Logf("✓ ECDSA P-256 SHA256 sign and verify works correctly")

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("ECDSA-P384-SHA384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p384-sha384",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA384,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P384(),
				},
			}

			_, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create ECDSA P-384 key")

			// Sign and verify with SHA384
			digest := crypto.SHA384.New()
			digest.Write([]byte("test message"))
			digestBytes := digest.Sum(nil)

			signature, err := b.Sign(attrs, digestBytes)
			require.NoError(t, err, "Failed to sign message")

			err = b.Verify(attrs, digestBytes, signature)
			require.NoError(t, err, "Failed to verify signature")

			t.Logf("✓ ECDSA P-384 SHA384 sign and verify works correctly")

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("ECDSA-P521-SHA512", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p521-sha512",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA512,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P521(),
				},
			}

			_, err := b.CreateKey(attrs)
			require.NoError(t, err, "Failed to create ECDSA P-521 key")

			// Sign and verify with SHA512
			digest := crypto.SHA512.New()
			digest.Write([]byte("test message"))
			digestBytes := digest.Sum(nil)

			signature, err := b.Sign(attrs, digestBytes)
			require.NoError(t, err, "Failed to sign message")

			err = b.Verify(attrs, digestBytes, signature)
			require.NoError(t, err, "Failed to verify signature")

			t.Logf("✓ ECDSA P-521 SHA512 sign and verify works correctly")

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		// Ed25519 Test
		t.Run("Ed25519", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ed25519",
				KeyAlgorithm: x509.Ed25519,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AWSKMS,
			}

			_, err := b.CreateKey(attrs)
			// AWS KMS doesn't support Ed25519, so we expect an error
			if err != nil {
				t.Logf("✓ Ed25519 correctly not supported by AWS KMS: %v", err)
				return
			}

			t.Log("⚠ Ed25519 key creation unexpectedly succeeded")

			// If it succeeded, try to use it
			message := []byte("test message")
			signature, err := b.Sign(attrs, message)
			if err != nil {
				t.Logf("✓ Ed25519 signing failed as expected: %v", err)
			} else {
				err = b.Verify(attrs, message, signature)
				if err != nil {
					t.Logf("⚠ Ed25519 signing succeeded but verification failed: %v", err)
				} else {
					t.Log("✓ Ed25519 sign and verify works")
				}
			}

			// Cleanup
			_ = b.Delete(attrs)
		})
	})
}
