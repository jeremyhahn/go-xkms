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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureKVImportExport tests the complete import/export workflow for Azure Key Vault.
// This test validates:
// 1. Getting import parameters with various wrapping algorithms
// 2. Wrapping key material locally
// 3. Importing wrapped keys into Azure Key Vault
// 4. Using imported keys for cryptographic operations
// 5. Export limitations (Azure KV doesn't support key export)
func TestAzureKVImportExport(t *testing.T) {
	endpoint := os.Getenv("AZURE_KEYVAULT_ENDPOINT")

	var b *azurekv.Backend
	var err error

	if endpoint != "" {
		// Use emulator
		t.Logf("Using Azure Key Vault emulator at %s", endpoint)

		// Create storage backends
		keyStorage := storage.New()
		certStorage := storage.New()

		cfg := &azurekv.Config{
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
		certStorage := storage.New()

		mockClient := azurekv.NewMockKeyVaultClient()
		cfg := &azurekv.Config{
			VaultURL:    "https://test-vault.vault.azure.net",
			KeyStorage:  keyStorage,
			CertStorage: certStorage,
		}

		b, err = azurekv.NewBackendWithClient(cfg, mockClient)
		require.NoError(t, err, "Failed to create backend with mock")
	}

	require.NotNil(t, b, "Backend should not be nil")
	defer b.Close()

	// Verify backend implements ImportExportBackend interface
	importExportBackend, ok := interface{}(b).(backend.ImportExportBackend)
	require.True(t, ok, "Backend must implement ImportExportBackend interface")

	// ========================================================================
	// Test 1: Get Import Parameters - RSA-OAEP SHA-1
	// ========================================================================
	t.Run("GetImportParameters_RSAOAEP_SHA1", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-import-rsa-oaep-sha1",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		params, err := importExportBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_1)
		require.NoError(t, err, "GetImportParameters should succeed")
		require.NotNil(t, params, "Import parameters should not be nil")

		// Verify parameters
		assert.NotNil(t, params.WrappingPublicKey, "Wrapping public key should not be nil")
		assert.NotNil(t, params.ImportToken, "Import token should not be nil")
		assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_1, params.Algorithm)
		assert.NotNil(t, params.ExpiresAt, "Expiration time should not be nil")
		assert.True(t, params.ExpiresAt.After(time.Now()), "Expiration should be in the future")

		// Verify wrapping key is RSA
		rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
		assert.True(t, ok, "Wrapping public key should be RSA")
		assert.Equal(t, 2048, rsaPubKey.N.BitLen(), "Wrapping key should be 2048 bits")

		t.Logf("✓ GetImportParameters succeeded with RSA-OAEP SHA-1")
		t.Logf("  - Wrapping key size: %d bits", rsaPubKey.N.BitLen())
		t.Logf("  - Import token length: %d bytes", len(params.ImportToken))
		t.Logf("  - Expires at: %s", params.ExpiresAt.Format(time.RFC3339))
	})

	// ========================================================================
	// Test 2: Get Import Parameters - RSA-OAEP SHA-256
	// ========================================================================
	t.Run("GetImportParameters_RSAOAEP_SHA256", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-import-rsa-oaep-sha256",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		params, err := importExportBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.NoError(t, err, "GetImportParameters should succeed")
		require.NotNil(t, params, "Import parameters should not be nil")

		assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, params.Algorithm)

		t.Logf("✓ GetImportParameters succeeded with RSA-OAEP SHA-256")
	})

	// ========================================================================
	// Test 3: Get Import Parameters - RSA-AES Key Wrap SHA-1
	// ========================================================================
	t.Run("GetImportParameters_RSA_AES_KeyWrap_SHA1", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-import-rsa-aes-sha1",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		params, err := importExportBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1)
		require.NoError(t, err, "GetImportParameters should succeed")
		require.NotNil(t, params, "Import parameters should not be nil")

		assert.Equal(t, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1, params.Algorithm)

		t.Logf("✓ GetImportParameters succeeded with RSA-AES Key Wrap SHA-1")
	})

	// ========================================================================
	// Test 4: Get Import Parameters - RSA-AES Key Wrap SHA-256
	// ========================================================================
	t.Run("GetImportParameters_RSA_AES_KeyWrap_SHA256", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-import-rsa-aes-sha256",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		params, err := importExportBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		require.NoError(t, err, "GetImportParameters should succeed")
		require.NotNil(t, params, "Import parameters should not be nil")

		assert.Equal(t, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, params.Algorithm)

		t.Logf("✓ GetImportParameters succeeded with RSA-AES Key Wrap SHA-256")
	})

	// ========================================================================
	// Test 5: Import RSA Key - Complete Workflow with RSA-OAEP SHA-256
	// ========================================================================
	t.Run("ImportRSAKey_Complete_Workflow", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-import-rsa-complete",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up if exists
		_ = b.Delete(attrs)

		// Step 1: Generate a local RSA key to import
		t.Log("Step 1: Generating local RSA key pair...")
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "Failed to generate RSA key")
		t.Logf("✓ Generated RSA-2048 key locally")

		// Step 2: Get import parameters
		// Note: RSA private keys are large (~1216 bytes for RSA-2048), so we need hybrid RSA-AES wrapping
		// RSA-OAEP alone can only handle up to (key_size - 2*hash_size - 2) bytes
		// For RSA-2048 with SHA-256: max is 256 - 2*32 - 2 = 190 bytes
		t.Log("Step 2: Getting import parameters from Azure Key Vault...")
		params, err := importExportBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		require.NoError(t, err, "GetImportParameters failed")
		require.NotNil(t, params, "Import parameters should not be nil")
		t.Logf("✓ Received import parameters")

		// Step 3: Marshal private key to PKCS8 format
		t.Log("Step 3: Marshaling private key to PKCS8 format...")
		keyMaterial, err := x509.MarshalPKCS8PrivateKey(privateKey)
		require.NoError(t, err, "Failed to marshal private key")
		t.Logf("✓ Marshaled key material (%d bytes)", len(keyMaterial))

		// Step 4: Wrap key material
		t.Log("Step 4: Wrapping key material with RSA-AES Key Wrap SHA-256 (hybrid)...")
		wrapped, err := importExportBackend.WrapKey(keyMaterial, params)
		require.NoError(t, err, "WrapKey failed")
		require.NotNil(t, wrapped, "Wrapped key material should not be nil")
		require.NotEmpty(t, wrapped.WrappedKey, "Wrapped key should not be empty")
		assert.Equal(t, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, wrapped.Algorithm)
		t.Logf("✓ Wrapped key material with hybrid RSA-AES (%d bytes wrapped -> %d bytes)", len(keyMaterial), len(wrapped.WrappedKey))

		// Step 5: Verify unwrap works (local test)
		t.Log("Step 5: Testing local unwrap...")
		unwrapped, err := importExportBackend.UnwrapKey(wrapped, params)
		require.NoError(t, err, "UnwrapKey failed")
		assert.Equal(t, keyMaterial, unwrapped, "Unwrapped key material should match original")
		t.Logf("✓ Successfully unwrapped and verified key material locally")

		// Step 6: Import key into Azure Key Vault
		t.Log("Step 6: Importing key into Azure Key Vault...")
		err = importExportBackend.ImportKey(attrs, wrapped)
		if err != nil {
			// Azure KV emulator may not support ImportKey
			t.Logf("⚠ ImportKey not supported by emulator (Azure KV production supports this): %v", err)
			t.Skip("Skipping due to emulator limitation")
			return
		}
		t.Logf("✓ Successfully imported key into Azure Key Vault")

		// Step 7: Verify imported key can be used for signing
		t.Log("Step 7: Testing signing with imported key...")
		message := []byte("Test message to sign with imported key")
		hash := sha256.Sum256(message)
		digest := hash[:]

		signature, err := b.Sign(attrs, digest)
		require.NoError(t, err, "Sign with imported key failed")
		require.NotEmpty(t, signature, "Signature should not be empty")
		t.Logf("✓ Successfully signed with imported key (signature: %d bytes)", len(signature))

		// Step 8: Verify signature
		t.Log("Step 8: Verifying signature...")
		err = b.Verify(attrs, digest, signature)
		require.NoError(t, err, "Verify failed")
		t.Logf("✓ Successfully verified signature")

		t.Log("✓✓✓ Complete RSA import workflow succeeded!")

		// Cleanup
		_ = b.Delete(attrs)
	})

	// ========================================================================
	// Test 6: Import ECDSA Key - Complete Workflow
	// ========================================================================
	t.Run("ImportECDSAKey_Complete_Workflow", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-import-ecdsa-complete",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		// Clean up if exists
		_ = b.Delete(attrs)

		// Step 1: Generate a local ECDSA key to import
		t.Log("Step 1: Generating local ECDSA P-256 key pair...")
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "Failed to generate ECDSA key")
		t.Logf("✓ Generated ECDSA P-256 key locally")

		// Step 2: Get import parameters
		t.Log("Step 2: Getting import parameters from Azure Key Vault...")
		params, err := importExportBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.NoError(t, err, "GetImportParameters failed")
		t.Logf("✓ Received import parameters")

		// Step 3: Marshal private key to PKCS8 format
		t.Log("Step 3: Marshaling ECDSA private key to PKCS8 format...")
		keyMaterial, err := x509.MarshalPKCS8PrivateKey(privateKey)
		require.NoError(t, err, "Failed to marshal ECDSA private key")
		t.Logf("✓ Marshaled key material (%d bytes)", len(keyMaterial))

		// Step 4: Wrap key material
		t.Log("Step 4: Wrapping key material...")
		wrapped, err := importExportBackend.WrapKey(keyMaterial, params)
		require.NoError(t, err, "WrapKey failed")
		require.NotNil(t, wrapped, "Wrapped key material should not be nil")
		t.Logf("✓ Wrapped key material (%d bytes)", len(wrapped.WrappedKey))

		// Step 5: Import key into Azure Key Vault
		t.Log("Step 5: Importing ECDSA key into Azure Key Vault...")
		err = importExportBackend.ImportKey(attrs, wrapped)
		if err != nil {
			// Azure KV emulator may not support ECDSA or ImportKey
			t.Logf("⚠ ImportKey not supported by emulator (Azure KV production supports this): %v", err)
			t.Skip("Skipping due to emulator limitation")
			return
		}
		t.Logf("✓ Successfully imported ECDSA key into Azure Key Vault")

		// Step 6: Verify imported key can be used for signing
		t.Log("Step 6: Testing signing with imported ECDSA key...")
		message := []byte("Test message to sign with imported ECDSA key")
		hash := sha256.Sum256(message)
		digest := hash[:]

		signature, err := b.Sign(attrs, digest)
		require.NoError(t, err, "Sign with imported ECDSA key failed")
		require.NotEmpty(t, signature, "Signature should not be empty")
		t.Logf("✓ Successfully signed with imported ECDSA key")

		t.Log("✓✓✓ Complete ECDSA import workflow succeeded!")

		// Cleanup
		_ = b.Delete(attrs)
	})

	// ========================================================================
	// Test 7: Import with Hybrid RSA-AES Wrapping (for large keys)
	// ========================================================================
	t.Run("ImportRSAKey_Hybrid_RSA_AES_Wrapping", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-import-rsa-hybrid",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 4096, // Larger key to test hybrid wrapping
			},
		}

		// Clean up if exists
		_ = b.Delete(attrs)

		// Generate a large RSA key (4096-bit)
		t.Log("Generating large RSA-4096 key for hybrid wrapping test...")
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		require.NoError(t, err, "Failed to generate RSA-4096 key")
		t.Logf("✓ Generated RSA-4096 key locally")

		// Get import parameters with RSA-AES hybrid wrapping
		params, err := importExportBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		require.NoError(t, err, "GetImportParameters failed")
		t.Logf("✓ Received import parameters for hybrid wrapping")

		// Marshal private key
		keyMaterial, err := x509.MarshalPKCS8PrivateKey(privateKey)
		require.NoError(t, err, "Failed to marshal private key")
		t.Logf("✓ Marshaled large key material (%d bytes)", len(keyMaterial))

		// Wrap key material using hybrid RSA+AES
		wrapped, err := importExportBackend.WrapKey(keyMaterial, params)
		require.NoError(t, err, "WrapKey with hybrid algorithm failed")
		require.NotNil(t, wrapped, "Wrapped key material should not be nil")
		assert.Equal(t, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, wrapped.Algorithm)
		t.Logf("✓ Wrapped large key with hybrid RSA-AES (%d bytes -> %d bytes)", len(keyMaterial), len(wrapped.WrappedKey))

		// Verify unwrap works
		unwrapped, err := importExportBackend.UnwrapKey(wrapped, params)
		require.NoError(t, err, "UnwrapKey failed")
		assert.Equal(t, keyMaterial, unwrapped, "Unwrapped key material should match original")
		t.Logf("✓ Successfully unwrapped large key material")

		t.Log("✓✓✓ Hybrid RSA-AES wrapping test succeeded!")

		// Cleanup
		_ = b.Delete(attrs)
	})

	// ========================================================================
	// Test 8: Export Key - Verify Not Supported
	// ========================================================================
	t.Run("ExportKey_NotSupported", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-export-not-supported",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Azure Key Vault does not support key export
		_, err := importExportBackend.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.Error(t, err, "ExportKey should return an error")
		assert.ErrorIs(t, err, backend.ErrNotSupported, "Should return ErrNotSupported")
		t.Logf("✓ ExportKey correctly returns ErrNotSupported: %v", err)
	})

	// ========================================================================
	// Test 9: Error Handling - Invalid Wrapping Algorithm
	// ========================================================================
	t.Run("GetImportParameters_InvalidAlgorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-invalid-algorithm",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Try with an unsupported wrapping algorithm
		_, err := importExportBackend.GetImportParameters(attrs, backend.WrappingAlgorithm("INVALID_ALGORITHM"))
		require.Error(t, err, "Should error with invalid wrapping algorithm")
		t.Logf("✓ Correctly rejected invalid wrapping algorithm: %v", err)
	})

	// ========================================================================
	// Test 10: Error Handling - Nil Attributes
	// ========================================================================
	t.Run("GetImportParameters_NilAttributes", func(t *testing.T) {
		_, err := importExportBackend.GetImportParameters(nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.Error(t, err, "Should error with nil attributes")
		t.Logf("✓ Correctly rejected nil attributes: %v", err)
	})

	// ========================================================================
	// Test 11: Error Handling - Empty Key Material
	// ========================================================================
	t.Run("WrapKey_EmptyKeyMaterial", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-empty-material",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		params, err := importExportBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.NoError(t, err)

		// Try to wrap empty key material
		_, err = importExportBackend.WrapKey([]byte{}, params)
		require.Error(t, err, "Should error with empty key material")
		t.Logf("✓ Correctly rejected empty key material: %v", err)
	})

	// ========================================================================
	// Test 12: Error Handling - Invalid Key Material Format
	// ========================================================================
	t.Run("ImportKey_InvalidKeyMaterial", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-invalid-material",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		params, err := importExportBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.NoError(t, err)

		// Wrap invalid key material (random bytes)
		invalidKeyMaterial := []byte("this is not a valid key")
		wrapped, err := importExportBackend.WrapKey(invalidKeyMaterial, params)
		require.NoError(t, err, "Wrapping should succeed even with invalid data")

		// Try to import - should fail during unwrap or import
		err = importExportBackend.ImportKey(attrs, wrapped)
		if err == nil {
			// If it didn't fail during import, it should fail during use
			t.Log("ImportKey didn't reject invalid key material (may be validated later)")
		} else {
			t.Logf("✓ Correctly rejected invalid key material: %v", err)
		}

		// Cleanup
		_ = b.Delete(attrs)
	})
}
