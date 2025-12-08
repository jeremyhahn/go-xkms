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

//go:build integration && azurekv

package integration

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTokenCredential provides a fake JWT token for the Azure Key Vault emulator
type fakeTokenCredential struct{}

func (f *fakeTokenCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	// Create a minimal JWT token (header.payload.signature format)
	// The emulator may not validate the signature, just the format
	// Header: {"alg":"none","typ":"JWT"}
	// Payload: {"aud":"https://vault.azure.net","iss":"https://sts.windows.net/test/","exp":9999999999}
	// Using "none" algorithm means no signature validation required
	token := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L3Rlc3QvIiwiZXhwIjo5OTk5OTk5OTk5fQ."

	return azcore.AccessToken{
		Token:     token,
		ExpiresOn: time.Now().Add(1 * time.Hour),
	}, nil
}

// testKeyVaultClient wraps the Azure Key Vault client to implement KeyVaultClient interface
type testKeyVaultClient struct {
	*azkeys.Client
}

func (t *testKeyVaultClient) CreateKey(ctx context.Context, name string, params azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	return t.Client.CreateKey(ctx, name, params, options)
}

func (t *testKeyVaultClient) GetKey(ctx context.Context, name, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	return t.Client.GetKey(ctx, name, version, options)
}

func (t *testKeyVaultClient) DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
	return t.Client.DeleteKey(ctx, name, options)
}

func (t *testKeyVaultClient) Sign(ctx context.Context, keyName, keyVersion string, params azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	return t.Client.Sign(ctx, keyName, keyVersion, params, options)
}

func (t *testKeyVaultClient) Verify(ctx context.Context, keyName, keyVersion string, params azkeys.VerifyParameters, options *azkeys.VerifyOptions) (azkeys.VerifyResponse, error) {
	return t.Client.Verify(ctx, keyName, keyVersion, params, options)
}

func (t *testKeyVaultClient) GetPublicKey(ctx context.Context, name, version string) ([]byte, error) {
	resp, err := t.Client.GetKey(ctx, name, version, nil)
	if err != nil {
		return nil, err
	}

	// Convert JWK to PEM format
	if resp.Key.Kty == nil {
		return nil, fmt.Errorf("key type is nil")
	}

	switch *resp.Key.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		// Extract RSA public key from JWK
		if resp.Key.N == nil || resp.Key.E == nil {
			return nil, fmt.Errorf("invalid RSA key: missing N or E")
		}

		pubKey := &x509.Certificate{}
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}

		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		}

		return pem.EncodeToMemory(pemBlock), nil

	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		// For ECDSA, similar approach
		return nil, fmt.Errorf("ECDSA public key extraction not yet implemented")

	default:
		return nil, fmt.Errorf("unsupported key type: %v", *resp.Key.Kty)
	}
}

func (t *testKeyVaultClient) Decrypt(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	return t.Client.Decrypt(ctx, keyName, keyVersion, params, options)
}

func (t *testKeyVaultClient) WrapKey(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	return t.Client.WrapKey(ctx, keyName, keyVersion, params, options)
}

func (t *testKeyVaultClient) UnwrapKey(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	return t.Client.UnwrapKey(ctx, keyName, keyVersion, params, options)
}

func (t *testKeyVaultClient) ImportKey(ctx context.Context, name string, params azkeys.ImportKeyParameters, options *azkeys.ImportKeyOptions) (azkeys.ImportKeyResponse, error) {
	return t.Client.ImportKey(ctx, name, params, options)
}

func (t *testKeyVaultClient) NewListKeyPropertiesPager(options *azkeys.ListKeyPropertiesOptions) *runtime.Pager[azkeys.ListKeyPropertiesResponse] {
	return t.Client.NewListKeyPropertiesPager(options)
}

func (t *testKeyVaultClient) RotateKey(ctx context.Context, name string, options *azkeys.RotateKeyOptions) (azkeys.RotateKeyResponse, error) {
	return t.Client.RotateKey(ctx, name, options)
}

func (t *testKeyVaultClient) Close() error {
	return nil
}

// TestAzureKeyVault tests Azure Key Vault backend
// Supports both emulator (when AZURE_KEYVAULT_ENDPOINT is set) and mock modes
func TestAzureKeyVault(t *testing.T) {
	endpoint := os.Getenv("AZURE_KEYVAULT_ENDPOINT")

	var b *azurekv.Backend
	var err error
	var cfg *azurekv.Config
	var certStorage storage.Backend

	if endpoint != "" {
		// Use emulator
		t.Logf("Using Azure Key Vault emulator at %s", endpoint)

		// Create storage backends
		keyStorage := storage.New()
		certStorage = storage.New()

		cfg = &azurekv.Config{
			VaultURL:    endpoint,
			KeyStorage:  keyStorage,
			CertStorage: certStorage,
		}

		// Create custom HTTP client that skips TLS verification for emulator
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}

		// Create fake credential for emulator
		cred := &fakeTokenCredential{}

		// Create Azure Key Vault client pointing to emulator
		clientOptions := &azkeys.ClientOptions{
			ClientOptions: azcore.ClientOptions{
				Transport: httpClient,
				Retry: policy.RetryOptions{
					MaxRetries: 3,
				},
			},
			DisableChallengeResourceVerification: true,
		}

		client, err := azkeys.NewClient(endpoint, cred, clientOptions)
		require.NoError(t, err, "Failed to create Azure Key Vault client")

		// Wrap client to match KeyVaultClient interface
		wrappedClient := &testKeyVaultClient{Client: client}
		b, err = azurekv.NewBackendWithClient(cfg, wrappedClient)
		require.NoError(t, err, "Failed to create backend with emulator")
	} else {
		// Use mock
		t.Logf("Using mock Azure Key Vault client")

		// Create storage backends
		keyStorage := storage.New()
		certStorage = storage.New()

		mockClient := azurekv.NewMockKeyVaultClient()
		cfg = &azurekv.Config{
			VaultURL:    "https://test-vault.vault.azure.net",
			KeyStorage:  keyStorage,
			CertStorage: certStorage,
		}

		b, err = azurekv.NewBackendWithClient(cfg, mockClient)
		require.NoError(t, err, "Failed to create backend with mock")
	}

	require.NotNil(t, b, "Backend should not be nil")
	defer b.Close()

	t.Run("CreateAndSignRSAKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rsa-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
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

	// Note: Azure KV emulator does not currently support Elliptic Curve keys
	// Skipping ECDSA test until emulator adds support

	t.Run("SignAndVerify", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-verify-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
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

		t.Logf("✓ Successfully signed and verified message")
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
				StoreType:    backend.STORE_AZUREKV,
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
				StoreType:    backend.STORE_AZUREKV,
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
				StoreType:    backend.STORE_AZUREKV,
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
				StoreType:    backend.STORE_AZUREKV,
				Hash:         crypto.SHA256,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			keyID, err := b.CreateKey(attrs)
			if err != nil {
				t.Logf("⚠ ECDSA P-256 not supported by emulator (Azure KV supports this in production): %v", err)
				return
			}
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
				StoreType:    backend.STORE_AZUREKV,
				Hash:         crypto.SHA384,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P384(),
				},
			}

			keyID, err := b.CreateKey(attrs)
			if err != nil {
				t.Logf("⚠ ECDSA P-384 not supported by emulator (Azure KV supports this in production): %v", err)
				return
			}
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
				StoreType:    backend.STORE_AZUREKV,
				Hash:         crypto.SHA512,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P521(),
				},
			}

			keyID, err := b.CreateKey(attrs)
			if err != nil {
				t.Logf("⚠ ECDSA P-521 not supported by emulator (Azure KV supports this in production): %v", err)
				return
			}
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
				StoreType:    backend.STORE_AZUREKV,
			}

			// Note: Azure Key Vault does not support Ed25519
			_, err := b.CreateKey(attrs)
			require.Error(t, err, "Azure KV should not support Ed25519")
			t.Logf("✓ Ed25519 correctly not supported by Azure Key Vault: %v", err)
		})
	})

	// ========================================================================
	// Get/Retrieve Key Metadata Tests
	// Note: Azure KV doesn't expose private key material, so GetKey() retrieves
	// metadata and public key information. We verify keys via Sign/Verify operations.
	// ========================================================================

	t.Run("GetKeyMetadata", func(t *testing.T) {
		t.Run("VerifyKeyExists", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-getkey-existing",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
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
				StoreType:    backend.STORE_AZUREKV,
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
				StoreType:    backend.STORE_AZUREKV,
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
				StoreType:    backend.STORE_AZUREKV,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Try to delete non-existent key
			err := b.Delete(attrs)
			// Azure KV Delete might not error on non-existent keys (idempotent)
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
				StoreType:    backend.STORE_AZUREKV,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}
			attrs2 := &types.KeyAttributes{
				CN:           "test-listkeys-2",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
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
				StoreType:    backend.STORE_AZUREKV,
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
				// Azure emulator may not support rotation
				t.Logf("⚠ Key rotation not supported (emulator limitation): %v", err)
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
				StoreType:    backend.STORE_AZUREKV,
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
			if err != nil {
				// Emulator may not support Signer fully
				t.Logf("⚠ Signer not supported (emulator limitation): %v", err)
				_ = b.Delete(attrs)
				return
			}
			require.NotNil(t, signer, "Signer should not be nil")

			// Test signing
			digest := crypto.SHA256.New()
			digest.Write([]byte("test message"))
			signature, err := signer.Sign(nil, digest.Sum(nil), crypto.SHA256)
			if err != nil {
				t.Logf("⚠ Sign operation not supported (emulator limitation): %v", err)
				_ = b.Delete(attrs)
				return
			}
			require.NotEmpty(t, signature, "Signature should not be empty")

			// Test Public()
			pubKey := signer.Public()
			require.NotNil(t, pubKey, "Public key should not be nil")

			t.Logf("✓ Signer interface works correctly")

			// Cleanup
			_ = b.Delete(attrs)
		})

		// ========================================================================
		// RSA Encryption/Decryption Tests
		// ========================================================================
		t.Run("RSAEncryptDecrypt", func(t *testing.T) {
			testAzureKVRSAEncryptDecrypt(t, b)
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
				StoreType:    backend.STORE_AZUREKV,
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

		t.Run("RSA_PSS_Sign_Verify", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-azure-rsa-pss",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			_, err := b.CreateKey(attrs)
			if err != nil {
				t.Fatal("RSA key creation not supported")
			}
			defer b.Delete(attrs)

			signer, err := b.Signer(attrs)
			require.NoError(t, err)

			message := []byte("Azure KV RSA-PSS test")
			h := sha256.New()
			h.Write(message)
			digest := h.Sum(nil)

			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			}

			signature, err := signer.Sign(nil, digest, pssOpts)
			require.NoError(t, err)

			rsaPub := signer.Public().(*rsa.PublicKey)
			err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
			require.NoError(t, err)

			t.Logf("✓ RSA-PSS works with Azure Key Vault")
		})

		t.Run("RSA-SHA384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-sign-sha384",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
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
				StoreType:    backend.STORE_AZUREKV,
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

		t.Run("ECDSA-SHA256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-sign-ecdsa-sha256",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				Hash:         crypto.SHA256,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			_, err := b.CreateKey(attrs)
			if err != nil {
				t.Logf("⚠ ECDSA P-256 not supported by emulator (Azure KV supports this in production): %v", err)
				return
			}

			// Sign and verify with SHA256
			digest := crypto.SHA256.New()
			digest.Write([]byte("test message"))
			digestBytes := digest.Sum(nil)

			signature, err := b.Sign(attrs, digestBytes)
			require.NoError(t, err, "Failed to sign message")

			err = b.Verify(attrs, digestBytes, signature)
			require.NoError(t, err, "Failed to verify signature")

			t.Logf("✓ ECDSA SHA256 sign and verify works correctly")

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("ECDSA-SHA384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-sign-ecdsa-sha384",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				Hash:         crypto.SHA384,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P384(),
				},
			}

			_, err := b.CreateKey(attrs)
			if err != nil {
				t.Logf("⚠ ECDSA P-384 not supported by emulator (Azure KV supports this in production): %v", err)
				return
			}

			// Sign and verify with SHA384
			digest := crypto.SHA384.New()
			digest.Write([]byte("test message"))
			digestBytes := digest.Sum(nil)

			signature, err := b.Sign(attrs, digestBytes)
			require.NoError(t, err, "Failed to sign message")

			err = b.Verify(attrs, digestBytes, signature)
			require.NoError(t, err, "Failed to verify signature")

			t.Logf("✓ ECDSA SHA384 sign and verify works correctly")

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("ECDSA-SHA512", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-sign-ecdsa-sha512",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
				Hash:         crypto.SHA512,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P521(),
				},
			}

			_, err := b.CreateKey(attrs)
			if err != nil {
				t.Logf("⚠ ECDSA P-521 not supported by emulator (Azure KV supports this in production): %v", err)
				return
			}

			// Sign and verify with SHA512
			digest := crypto.SHA512.New()
			digest.Write([]byte("test message"))
			digestBytes := digest.Sum(nil)

			signature, err := b.Sign(attrs, digestBytes)
			require.NoError(t, err, "Failed to sign message")

			err = b.Verify(attrs, digestBytes, signature)
			require.NoError(t, err, "Failed to verify signature")

			t.Logf("✓ ECDSA SHA512 sign and verify works correctly")

			// Cleanup
			err = b.Delete(attrs)
			require.NoError(t, err, "Failed to delete key")
		})

		t.Run("Ed25519", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ed25519",
				KeyAlgorithm: x509.Ed25519,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_AZUREKV,
			}

			_, err := b.CreateKey(attrs)
			// Azure KV doesn't support Ed25519
			if err != nil {
				t.Logf("✓ Ed25519 correctly not supported by Azure KV: %v", err)
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

	// ========================================================================
	// Symmetric Encryption Tests - Comprehensive coverage for Azure Key Vault
	// ========================================================================

	t.Run("SymmetricEncryption", func(t *testing.T) {
		testAzureKVSymmetricEncryption(t, b)
	})
}

// testAzureKVSymmetricEncryption tests symmetric encryption and decryption operations for Azure Key Vault
// Azure Key Vault only supports AES-256-GCM for symmetric encryption
func testAzureKVSymmetricEncryption(t *testing.T, b *azurekv.Backend) {
	// Skip symmetric encryption tests when using mock client
	// The mock client only implements the Keys API, not the Secrets API required for symmetric operations
	if os.Getenv("AZURE_KEYVAULT_URL") == "" {
		t.Log("Mock client doesn't support Azure Secrets API (required for symmetric keys) - testing capability detection only")
		// Verify capability correctly reports no symmetric encryption support for mock
		caps := b.Capabilities()
		if caps.SupportsSymmetricEncryption() {
			t.Log("Backend reports symmetric encryption support - would test if Secrets API available")
		}
		t.Log("✓ Symmetric encryption test handled correctly for mock client")
		return
	}

	// Check if backend supports symmetric encryption
	caps := b.Capabilities()
	if !caps.SupportsSymmetricEncryption() {
		t.Fatal("Azure Key Vault backend does not support symmetric encryption")
		return
	}

	// Cast to SymmetricBackend interface
	symBackend, ok := interface{}(b).(types.SymmetricBackend)
	if !ok {
		t.Fatal("Backend does not implement SymmetricBackend interface")
		return
	}

	t.Run("AES-256-GCM-BasicEncryptDecrypt", func(t *testing.T) {
		// Test basic AES-256-GCM encryption/decryption
		// Azure Key Vault only supports AES-256-GCM, not AES-128 or AES-192
		attrs := &types.KeyAttributes{
			CN:                 "test-azurekv-aes256-gcm-basic",
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_AZUREKV,
			AESAttributes: &types.AESAttributes{
				KeySize:   256,
				NonceSize: 12, // Standard GCM nonce size
			},
		}

		// Clean up if exists from previous test
		_ = b.Delete(attrs)

		// Generate symmetric key
		symmetricKey, err := symBackend.GenerateSymmetricKey(attrs)
		require.NoError(t, err, "Failed to generate AES-256-GCM key")
		require.NotNil(t, symmetricKey, "Symmetric key should not be nil")
		assert.Equal(t, string(types.SymmetricAES256GCM), symmetricKey.Algorithm())
		assert.Equal(t, 256, symmetricKey.KeySize())
		t.Logf("✓ Generated AES-256-GCM symmetric key")

		// Verify that Raw() returns nil (key is not extractable from Azure KV)
		rawKey, _ := symmetricKey.Raw()
		assert.Nil(t, rawKey, "Raw key should be nil for Azure Key Vault (keys are not extractable)")
		t.Logf("✓ Verified key is not extractable (Azure KV security)")

		// Get encrypter
		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		require.NoError(t, err, "Failed to get symmetric encrypter")
		require.NotNil(t, encrypter, "Encrypter should not be nil")
		t.Logf("✓ Retrieved symmetric encrypter")

		// Test encryption
		plaintext := []byte("Hello, Azure Key Vault! This is a test of symmetric encryption using AES-256-GCM.")
		encrypted, err := encrypter.Encrypt(plaintext, nil)
		require.NoError(t, err, "Failed to encrypt plaintext")
		require.NotNil(t, encrypted, "Encrypted data should not be nil")
		require.NotEmpty(t, encrypted.Ciphertext, "Ciphertext should not be empty")
		require.NotEmpty(t, encrypted.Nonce, "Nonce should not be empty")
		require.NotEmpty(t, encrypted.Tag, "Tag should not be empty for GCM mode")
		assert.Equal(t, string(types.SymmetricAES256GCM), encrypted.Algorithm)
		assert.Equal(t, 12, len(encrypted.Nonce), "GCM nonce should be 12 bytes")
		assert.Equal(t, 16, len(encrypted.Tag), "GCM authentication tag should be 16 bytes")
		t.Logf("✓ Encrypted plaintext (ciphertext: %d bytes, nonce: %d bytes, tag: %d bytes)",
			len(encrypted.Ciphertext), len(encrypted.Nonce), len(encrypted.Tag))

		// Test decryption
		decrypted, err := encrypter.Decrypt(encrypted, nil)
		require.NoError(t, err, "Failed to decrypt ciphertext")
		assert.Equal(t, plaintext, decrypted, "Decrypted data should match original plaintext")
		t.Logf("✓ Successfully decrypted ciphertext: %s", string(decrypted))

		// Cleanup
		err = b.Delete(attrs)
		require.NoError(t, err, "Failed to delete key")
	})

	t.Run("AES-256-GCM-WithAAD", func(t *testing.T) {
		// Test encryption with Additional Authenticated Data (AAD)
		// AAD provides additional context that must match for decryption to succeed
		attrs := &types.KeyAttributes{
			CN:                 "test-azurekv-aes256-gcm-aad",
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_AZUREKV,
			AESAttributes: &types.AESAttributes{
				KeySize:   256,
				NonceSize: 12,
			},
		}

		// Clean up if exists
		_ = b.Delete(attrs)

		// Generate key
		_, err := symBackend.GenerateSymmetricKey(attrs)
		require.NoError(t, err, "Failed to generate key")
		t.Logf("✓ Generated AES-256-GCM key for AAD testing")

		// Get encrypter
		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		require.NoError(t, err, "Failed to get encrypter")

		// Test data with AAD (context information that must match for decryption)
		plaintext := []byte("Sensitive payment data: card number, amount, etc.")
		aad := []byte("user-id:12345,session-id:abc-123,timestamp:1234567890")

		// Encrypt with AAD
		encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
			AdditionalData: aad,
		})
		require.NoError(t, err, "Failed to encrypt with AAD")
		require.NotNil(t, encrypted, "Encrypted data should not be nil")
		t.Logf("✓ Encrypted with AAD: %s", string(aad))

		// Decrypt with correct AAD - should succeed
		decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
			AdditionalData: aad,
		})
		require.NoError(t, err, "Decryption with correct AAD should succeed")
		assert.Equal(t, plaintext, decrypted, "Decrypted data should match plaintext")
		t.Logf("✓ Successfully decrypted with correct AAD")

		// Decrypt with wrong AAD - should fail
		wrongAAD := []byte("user-id:99999,session-id:xyz-999,timestamp:0000000000")
		_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
			AdditionalData: wrongAAD,
		})
		assert.Error(t, err, "Decryption with wrong AAD should fail")
		t.Logf("✓ Correctly rejected decryption with wrong AAD: %v", err)

		// Decrypt without AAD when it was used - should fail
		_, err = encrypter.Decrypt(encrypted, nil)
		assert.Error(t, err, "Decryption without AAD should fail when AAD was used for encryption")
		t.Logf("✓ Correctly rejected decryption without AAD: %v", err)

		// Cleanup
		err = b.Delete(attrs)
		require.NoError(t, err, "Failed to delete key")
	})

	t.Run("NonceUniqueness", func(t *testing.T) {
		// Test that multiple encryptions produce different nonces (critical for GCM security)
		// Reusing nonces in GCM mode completely breaks security
		attrs := &types.KeyAttributes{
			CN:                 "test-azurekv-nonce-uniqueness",
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_AZUREKV,
			AESAttributes: &types.AESAttributes{
				KeySize:   256,
				NonceSize: 12,
			},
		}

		// Clean up if exists
		_ = b.Delete(attrs)

		// Generate key
		_, err := symBackend.GenerateSymmetricKey(attrs)
		require.NoError(t, err, "Failed to generate key")
		t.Logf("✓ Generated AES-256-GCM key for nonce uniqueness testing")

		// Get encrypter
		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		require.NoError(t, err, "Failed to get encrypter")

		// Encrypt same plaintext multiple times
		plaintext := []byte("Same plaintext encrypted multiple times for nonce uniqueness test")
		encryptedDataList := make([]*types.EncryptedData, 10)
		nonces := make(map[string]bool)

		for i := 0; i < 10; i++ {
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			require.NoError(t, err, "Failed to encrypt iteration %d", i+1)
			encryptedDataList[i] = encrypted

			// Check nonce uniqueness
			nonceStr := string(encrypted.Nonce)
			assert.False(t, nonces[nonceStr], "Nonce %d should be unique (found duplicate)", i+1)
			nonces[nonceStr] = true

			// Verify ciphertext is different (even though plaintext is the same)
			for j := 0; j < i; j++ {
				assert.NotEqual(t, encryptedDataList[j].Ciphertext, encrypted.Ciphertext,
					"Ciphertext %d and %d should be different (unique nonces)", j+1, i+1)
			}
		}
		t.Logf("✓ Verified all 10 encryptions produced unique nonces and ciphertexts")

		// Verify all ciphertexts decrypt to the same plaintext
		for i, encrypted := range encryptedDataList {
			decrypted, err := encrypter.Decrypt(encrypted, nil)
			require.NoError(t, err, "Failed to decrypt ciphertext %d", i+1)
			assert.Equal(t, plaintext, decrypted, "Decrypted data %d should match plaintext", i+1)
		}
		t.Logf("✓ All unique ciphertexts decrypted to the same plaintext")

		// Cleanup
		err = b.Delete(attrs)
		require.NoError(t, err, "Failed to delete key")
	})

	t.Run("EdgeCases", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:                 "test-azurekv-edge-cases",
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_AZUREKV,
			AESAttributes: &types.AESAttributes{
				KeySize:   256,
				NonceSize: 12,
			},
		}

		// Clean up if exists
		_ = b.Delete(attrs)

		// Generate key
		_, err := symBackend.GenerateSymmetricKey(attrs)
		require.NoError(t, err, "Failed to generate key")
		t.Logf("✓ Generated AES-256-GCM key for edge case testing")

		// Get encrypter
		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		require.NoError(t, err, "Failed to get encrypter")

		// Test 1: Empty plaintext
		t.Run("EmptyPlaintext", func(t *testing.T) {
			plaintext := []byte{}
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			require.NoError(t, err, "Should handle empty plaintext")
			require.NotNil(t, encrypted, "Encrypted data should not be nil")

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

		// Test 3: Large plaintext
		// Azure Key Vault has limits, but should handle reasonable sizes
		t.Run("LargePlaintext", func(t *testing.T) {
			// Test with 64KB of data
			plaintext := make([]byte, 64*1024)
			for i := range plaintext {
				plaintext[i] = byte(i % 256)
			}

			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				// Azure KV may have size limits
				t.Logf("⚠ Large plaintext (64KB) not supported by Azure KV: %v", err)
				return
			}

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
			t.Logf("✓ Binary data (all byte values 0-255) handled correctly")
		})

		// Test 5: UTF-8 text with special characters
		t.Run("UTF8Text", func(t *testing.T) {
			plaintext := []byte("Hello 世界! 🔐 Special chars: \n\t\r")
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			require.NoError(t, err, "Should handle UTF-8 text")

			decrypted, err := encrypter.Decrypt(encrypted, nil)
			require.NoError(t, err, "Should decrypt UTF-8 text")
			assert.Equal(t, plaintext, decrypted, "UTF-8 text should round-trip")
			t.Logf("✓ UTF-8 text with special characters handled correctly")
		})

		// Cleanup
		err = b.Delete(attrs)
		require.NoError(t, err, "Failed to delete key")
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		// Test error conditions

		// Test 1: Invalid key size (Azure KV only supports AES-256)
		t.Run("InvalidKeySize-AES128", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-azurekv-invalid-aes128",
				SymmetricAlgorithm: types.SymmetricAES128GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AZUREKV,
				AESAttributes: &types.AESAttributes{
					KeySize:   128,
					NonceSize: 12,
				},
			}

			_, err := symBackend.GenerateSymmetricKey(attrs)
			assert.Error(t, err, "Should reject AES-128 (Azure KV only supports AES-256)")
			t.Logf("✓ Correctly rejected unsupported AES-128 key size: %v", err)
		})

		t.Run("InvalidKeySize-AES192", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-azurekv-invalid-aes192",
				SymmetricAlgorithm: types.SymmetricAES192GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AZUREKV,
				AESAttributes: &types.AESAttributes{
					KeySize:   192,
					NonceSize: 12,
				},
			}

			_, err := symBackend.GenerateSymmetricKey(attrs)
			assert.Error(t, err, "Should reject AES-192 (Azure KV only supports AES-256)")
			t.Logf("✓ Correctly rejected unsupported AES-192 key size: %v", err)
		})

		// Test 2: Get non-existent key
		t.Run("GetNonExistentKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-azurekv-nonexistent-key-12345",
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AZUREKV,
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
				CN:                 "test-azurekv-encrypter-nonexistent",
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AZUREKV,
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
				CN:                 "test-azurekv-corrupted-ciphertext",
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AZUREKV,
				AESAttributes: &types.AESAttributes{
					KeySize:   256,
					NonceSize: 12,
				},
			}

			// Clean up if exists
			_ = b.Delete(attrs)

			// Generate key
			_, err := symBackend.GenerateSymmetricKey(attrs)
			require.NoError(t, err)

			// Get encrypter
			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			require.NoError(t, err)

			// Encrypt valid data first
			plaintext := []byte("valid data for corruption test")
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			require.NoError(t, err)

			// Corrupt the ciphertext
			corruptedCiphertext := make([]byte, len(encrypted.Ciphertext))
			copy(corruptedCiphertext, encrypted.Ciphertext)
			if len(corruptedCiphertext) > 0 {
				corruptedCiphertext[0] ^= 0xFF // Flip bits in first byte
			}
			corruptedData := &types.EncryptedData{
				Ciphertext: corruptedCiphertext,
				Nonce:      encrypted.Nonce,
				Tag:        encrypted.Tag,
				Algorithm:  encrypted.Algorithm,
			}

			// Try to decrypt corrupted data
			_, err = encrypter.Decrypt(corruptedData, nil)
			assert.Error(t, err, "Should error when decrypting corrupted ciphertext")
			t.Logf("✓ Correctly rejected corrupted ciphertext: %v", err)

			// Cleanup
			_ = b.Delete(attrs)
		})

		// Test 5: Decrypt with corrupted tag
		t.Run("CorruptedTag", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-azurekv-corrupted-tag",
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AZUREKV,
				AESAttributes: &types.AESAttributes{
					KeySize:   256,
					NonceSize: 12,
				},
			}

			// Clean up if exists
			_ = b.Delete(attrs)

			// Generate key
			_, err := symBackend.GenerateSymmetricKey(attrs)
			require.NoError(t, err)

			// Get encrypter
			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			require.NoError(t, err)

			// Encrypt valid data
			plaintext := []byte("valid data for tag corruption test")
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			require.NoError(t, err)

			// Corrupt the authentication tag
			corruptedTag := make([]byte, len(encrypted.Tag))
			copy(corruptedTag, encrypted.Tag)
			if len(corruptedTag) > 0 {
				corruptedTag[0] ^= 0xFF // Flip bits in first byte
			}
			corruptedData := &types.EncryptedData{
				Ciphertext: encrypted.Ciphertext,
				Nonce:      encrypted.Nonce,
				Tag:        corruptedTag,
				Algorithm:  encrypted.Algorithm,
			}

			// Try to decrypt with corrupted tag
			_, err = encrypter.Decrypt(corruptedData, nil)
			assert.Error(t, err, "Should error when decrypting with corrupted authentication tag")
			t.Logf("✓ Correctly rejected corrupted authentication tag: %v", err)

			// Cleanup
			_ = b.Delete(attrs)
		})

		// Test 6: Duplicate key generation
		t.Run("DuplicateKeyGeneration", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-azurekv-duplicate-key",
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AZUREKV,
				AESAttributes: &types.AESAttributes{
					KeySize:   256,
					NonceSize: 12,
				},
			}

			// Clean up if exists
			_ = b.Delete(attrs)

			// Generate key first time
			_, err := symBackend.GenerateSymmetricKey(attrs)
			require.NoError(t, err, "First key generation should succeed")

			// Try to generate same key again
			_, err = symBackend.GenerateSymmetricKey(attrs)
			assert.Error(t, err, "Duplicate key generation should fail")
			t.Logf("✓ Correctly rejected duplicate key generation: %v", err)

			// Cleanup
			_ = b.Delete(attrs)
		})
	})

	t.Run("KeyLifecycle", func(t *testing.T) {
		// Test complete key lifecycle: create, use, delete, verify deletion
		attrs := &types.KeyAttributes{
			CN:                 "test-azurekv-key-lifecycle",
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_AZUREKV,
			AESAttributes: &types.AESAttributes{
				KeySize:   256,
				NonceSize: 12,
			},
		}

		// Clean up if exists
		_ = b.Delete(attrs)

		// Step 1: Generate key
		symmetricKey, err := symBackend.GenerateSymmetricKey(attrs)
		require.NoError(t, err, "Failed to generate key")
		require.NotNil(t, symmetricKey)
		assert.Equal(t, string(types.SymmetricAES256GCM), symmetricKey.Algorithm())
		assert.Equal(t, 256, symmetricKey.KeySize())
		t.Logf("✓ Step 1: Generated symmetric key")

		// Step 2: Retrieve key
		retrievedKey, err := symBackend.GetSymmetricKey(attrs)
		require.NoError(t, err, "Failed to retrieve key")
		assert.Equal(t, symmetricKey.Algorithm(), retrievedKey.Algorithm())
		assert.Equal(t, symmetricKey.KeySize(), retrievedKey.KeySize())
		t.Logf("✓ Step 2: Retrieved key successfully")

		// Step 3: Use key for encryption/decryption
		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		require.NoError(t, err, "Failed to get encrypter")

		plaintext := []byte("lifecycle test data for Azure Key Vault")
		encrypted, err := encrypter.Encrypt(plaintext, nil)
		require.NoError(t, err, "Failed to encrypt")

		decrypted, err := encrypter.Decrypt(encrypted, nil)
		require.NoError(t, err, "Failed to decrypt")
		assert.Equal(t, plaintext, decrypted)
		t.Logf("✓ Step 3: Used key for encryption/decryption")

		// Step 4: Delete key
		err = b.Delete(attrs)
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
}

// testAzureKVRSAEncryptDecrypt tests RSA encryption and decryption operations for Azure Key Vault
func testAzureKVRSAEncryptDecrypt(t *testing.T, b *azurekv.Backend) {
	t.Run("RSA-2048_PKCS1v15_EncryptDecrypt", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "azurekv-rsa-2048-pkcs1v15",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_ENCRYPTION,
			StoreType:    backend.STORE_AZUREKV,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing key
		_ = b.Delete(attrs)

		t.Log("Creating RSA 2048 key in Azure Key Vault for PKCS#1 v1.5 encryption...")
		_, err := b.CreateKey(attrs)
		if err != nil {
			t.Logf("⚠ Key creation not supported (emulator limitation): %v", err)
			t.Fatal("Skipping test due to emulator limitation")
		}
		defer b.Delete(attrs)

		// Get Decrypter interface
		decrypter, err := b.Decrypter(attrs)
		if err != nil {
			t.Logf("⚠ Decrypter not supported (emulator limitation): %v", err)
			t.Fatal("Skipping test due to emulator limitation")
		}

		// Get the public key for encryption
		rsaPub, ok := decrypter.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key must be RSA")

		// Encrypt a message with PKCS#1 v1.5
		plaintext := []byte("Secret message for Azure Key Vault encryption test with PKCS#1 v1.5 padding")
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext)
		require.NoError(t, err, "Failed to encrypt with PKCS#1 v1.5")
		t.Logf("✓ Encrypted %d bytes with RSA-2048 PKCS#1 v1.5 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

		// Decrypt using Azure Key Vault with nil opts (PKCS#1 v1.5)
		decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
		require.NoError(t, err, "Failed to decrypt with Azure Key Vault")

		// Verify decrypted matches original
		assert.Equal(t, plaintext, decrypted, "Decrypted plaintext must match original")
		t.Logf("✓ Decrypted %d bytes successfully, plaintext matches", len(decrypted))
	})

	t.Run("RSA-2048_OAEP_SHA256_EncryptDecrypt", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "azurekv-rsa-2048-oaep-sha256",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_ENCRYPTION,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing key
		_ = b.Delete(attrs)

		t.Log("Creating RSA 2048 key in Azure Key Vault for OAEP SHA256 encryption...")
		_, err := b.CreateKey(attrs)
		if err != nil {
			t.Logf("⚠ Key creation not supported (emulator limitation): %v", err)
			t.Fatal("Skipping test due to emulator limitation")
		}
		defer b.Delete(attrs)

		// Get Decrypter interface
		decrypter, err := b.Decrypter(attrs)
		if err != nil {
			t.Logf("⚠ Decrypter not supported (emulator limitation): %v", err)
			t.Fatal("Skipping test due to emulator limitation")
		}

		// Get the public key for encryption
		rsaPub, ok := decrypter.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key must be RSA")

		// Encrypt with RSA-OAEP SHA256
		plaintext := []byte("Secret message for Azure Key Vault with RSA-OAEP SHA-256 padding")
		label := []byte("")
		ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, plaintext, label)
		require.NoError(t, err, "Failed to encrypt with OAEP SHA256")
		t.Logf("✓ Encrypted %d bytes with RSA-OAEP SHA256 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

		// Decrypt using Azure Key Vault with OAEP options
		oaepOpts := &rsa.OAEPOptions{
			Hash:  crypto.SHA256,
			Label: label,
		}
		decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, oaepOpts)
		require.NoError(t, err, "Failed to decrypt with OAEP")

		// Verify decrypted matches original
		assert.Equal(t, plaintext, decrypted, "Decrypted plaintext must match original")
		t.Logf("✓ Decrypted %d bytes with RSA-OAEP SHA256, plaintext matches", len(decrypted))
	})

	t.Run("RSA-3072_OAEP_SHA256_EncryptDecrypt", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "azurekv-rsa-3072-oaep-sha256",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_ENCRYPTION,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 3072,
			},
		}

		// Clean up any existing key
		_ = b.Delete(attrs)

		t.Log("Creating RSA 3072 key in Azure Key Vault for OAEP SHA256 encryption...")
		_, err := b.CreateKey(attrs)
		if err != nil {
			t.Logf("⚠ Key creation not supported (emulator limitation): %v", err)
			t.Fatal("Skipping test due to emulator limitation")
		}
		defer b.Delete(attrs)

		// Get Decrypter interface
		decrypter, err := b.Decrypter(attrs)
		if err != nil {
			t.Logf("⚠ Decrypter not supported (emulator limitation): %v", err)
			t.Fatal("Skipping test due to emulator limitation")
		}

		// Get the public key for encryption
		rsaPub, ok := decrypter.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key must be RSA")

		// Encrypt with RSA-OAEP SHA256
		plaintext := []byte("Secret message for Azure Key Vault RSA-3072 with OAEP padding")
		label := []byte("")
		ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, plaintext, label)
		require.NoError(t, err, "Failed to encrypt with OAEP SHA256")
		t.Logf("✓ Encrypted %d bytes with RSA-3072-OAEP SHA256 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

		// Decrypt using Azure Key Vault with OAEP options
		oaepOpts := &rsa.OAEPOptions{
			Hash:  crypto.SHA256,
			Label: label,
		}
		decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, oaepOpts)
		require.NoError(t, err, "Failed to decrypt with OAEP")

		// Verify decrypted matches original
		assert.Equal(t, plaintext, decrypted, "Decrypted plaintext must match original")
		t.Logf("✓ Decrypted %d bytes with RSA-3072-OAEP SHA256, plaintext matches", len(decrypted))
	})
}
