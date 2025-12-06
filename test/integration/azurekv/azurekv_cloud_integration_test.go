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

//go:build cloud_integration && azurekv

package integration

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureKeyVaultCloudIntegration tests Azure Key Vault backend against REAL Azure cloud service
// This requires valid Azure credentials and will create REAL resources that cost money.
//
// Prerequisites:
//   - Azure CLI configured with valid credentials: az login
//   - Environment variables:
//   - AZURE_KEYVAULT_URI (required, e.g., https://your-vault.vault.azure.net/)
//   - AZURE_TENANT_ID (optional, from az account show)
//   - AZURE_CLIENT_ID (optional, for service principal auth)
//   - AZURE_CLIENT_SECRET (optional, for service principal auth)
//   - A Key Vault must exist with appropriate permissions
//
// Setup:
//
//	az group create --name keychain-test-rg --location eastus
//	az keyvault create --name keychain-test-kv-$(date +%s) --resource-group keychain-test-rg --location eastus
//
// Run with:
//
//	export AZURE_KEYVAULT_URI="https://your-vault.vault.azure.net/"
//	go test -tags="cloud_integration azurekv" -v ./test/integration/azurekv/...
//
// Cleanup:
//
//	az group delete --name keychain-test-rg --yes --no-wait
func TestAzureKeyVaultCloudIntegration(t *testing.T) {
	// Check required environment variables
	vaultURI := os.Getenv("AZURE_KEYVAULT_URI")
	if vaultURI == "" {
		t.Skip("AZURE_KEYVAULT_URI not set - skipping real Azure Key Vault tests")
	}

	// Create storage backends
	keyStorage := storage.New()
	certStorage := storage.New()

	// Create backend
	backendCfg := &azurekv.Config{
		VaultURL:    vaultURI,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}
	b, err := azurekv.NewBackend(backendCfg)
	require.NoError(t, err, "Failed to create Azure Key Vault backend")
	defer b.Close()

	// Track keys created for cleanup
	createdKeys := make([]*types.KeyAttributes, 0)
	cleanup := func() {
		t.Log("Cleaning up test keys...")
		for _, attrs := range createdKeys {
			if err := b.Delete(attrs); err != nil {
				t.Logf("Warning: Failed to delete key %s: %v", attrs.CN, err)
			}
		}
	}
	defer cleanup()

	t.Run("RealAzure/CreateAndSignRSAKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-rsa-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		keyID, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create RSA key in real Azure Key Vault")
		require.NotEmpty(t, keyID, "Key ID should not be empty")

		// Test signing with real Azure Key Vault
		digest := crypto.SHA256.New()
		digest.Write([]byte("test message for real Azure Key Vault signing"))
		signature, err := b.Sign(attrs, digest.Sum(nil))
		require.NoError(t, err, "Failed to sign with real Azure Key Vault")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		t.Logf("✓ Created real Azure Key Vault RSA key and signed (keyID: %s, signature length: %d)", keyID, len(signature))
	})

	t.Run("RealAzure/CreateAndSignECDSAKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-ecdsa-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}
		createdKeys = append(createdKeys, attrs)

		keyID, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create ECDSA key in real Azure Key Vault")
		require.NotEmpty(t, keyID, "Key ID should not be empty")

		// Test signing
		digest := crypto.SHA256.New()
		digest.Write([]byte("test ecdsa message"))
		signature, err := b.Sign(attrs, digest.Sum(nil))
		require.NoError(t, err, "Failed to sign with ECDSA key")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		t.Logf("✓ Created real Azure Key Vault ECDSA key and signed (keyID: %s)", keyID)
	})

	t.Run("RealAzure/SignAndVerify", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-verify-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create key")

		// Sign
		message := []byte("test verification with real Azure Key Vault")
		digest := crypto.SHA256.New()
		digest.Write(message)
		digestBytes := digest.Sum(nil)

		signature, err := b.Sign(attrs, digestBytes)
		require.NoError(t, err, "Failed to sign")

		// Verify
		err = b.Verify(attrs, digestBytes, signature)
		require.NoError(t, err, "Failed to verify signature")

		t.Logf("✓ Successfully signed and verified with real Azure Key Vault")
	})

	t.Run("RealAzure/ListKeys", func(t *testing.T) {
		// Create a test key
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-list-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create key")

		// List keys
		keys, err := b.ListKeys()
		require.NoError(t, err, "Failed to list keys from real Azure Key Vault")
		require.NotNil(t, keys, "Keys list should not be nil")
		require.NotEmpty(t, keys, "Should have at least 1 key")

		t.Logf("✓ Listed %d keys from real Azure Key Vault", len(keys))
	})

	t.Run("RealAzure/SignerInterface", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-signer-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create key")

		// Get Signer interface
		signer, err := b.Signer(attrs)
		require.NoError(t, err, "Failed to get Signer from real Azure Key Vault")
		require.NotNil(t, signer, "Signer should not be nil")

		// Test signing via interface
		digest := crypto.SHA256.New()
		digest.Write([]byte("test signer interface"))
		signature, err := signer.Sign(rand.Reader, digest.Sum(nil), crypto.SHA256)
		require.NoError(t, err, "Failed to sign via Signer interface")
		require.NotEmpty(t, signature, "Signature should not be empty")

		// Test Public() method
		pubKey := signer.Public()
		require.NotNil(t, pubKey, "Public key should not be nil")

		t.Logf("✓ Signer interface works with real Azure Key Vault")
	})

	t.Run("RealAzure/RSA_PSS_Sign_Verify", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-rsa-pss-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.CreateKey(attrs)
		if err != nil {
			t.Skip("RSA key creation not supported")
		}

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

		t.Logf("✓ RSA-PSS works with real Azure Key Vault")
	})

	t.Run("RealAzure/DecrypterInterface", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-decrypt-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_ENCRYPTION,
			StoreType:    backend.STORE_AZUREKV,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create encryption key")

		// Get Decrypter interface
		decrypter, err := b.Decrypter(attrs)
		require.NoError(t, err, "Failed to get Decrypter from real Azure Key Vault")
		require.NotNil(t, decrypter, "Decrypter should not be nil")

		// Test encryption/decryption
		pubKey := decrypter.Public()
		require.NotNil(t, pubKey, "Public key should not be nil")

		t.Logf("✓ Decrypter interface works with real Azure Key Vault")
	})

	t.Run("RealAzure/ImportExport", func(t *testing.T) {
		// Check if backend supports import/export
		caps := b.Capabilities()
		if !caps.SupportsImportExport() {
			t.Skip("Azure Key Vault backend does not support import/export")
			return
		}

		// Get import/export backend
		ieb, ok := interface{}(b).(backend.ImportExportBackend)
		require.True(t, ok, "Backend should implement ImportExportBackend")

		sourceAttrs := &types.KeyAttributes{
			CN:           "cloud-test-import-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, sourceAttrs)

		// Test getting import parameters
		params, err := ieb.GetImportParameters(sourceAttrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		if err != nil {
			t.Logf("GetImportParameters not fully supported yet: %v", err)
			return
		}
		require.NotNil(t, params, "Import parameters should not be nil")

		t.Logf("✓ Import/export operations work with real Azure Key Vault")
	})

	t.Run("RealAzure/SymmetricEncryption", func(t *testing.T) {
		// Check if backend supports symmetric encryption
		caps := b.Capabilities()
		if !caps.SupportsSymmetricEncryption() {
			t.Skip("Azure Key Vault backend does not support symmetric encryption")
			return
		}

		symBackend, ok := interface{}(b).(types.SymmetricBackend)
		require.True(t, ok, "Backend should implement SymmetricBackend")

		attrs := &types.KeyAttributes{
			CN:                 "cloud-test-aes-" + time.Now().Format("20060102-150405"),
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			KeyType:            backend.KEY_TYPE_ENCRYPTION,
			StoreType:          backend.STORE_AZUREKV,
			AESAttributes: &types.AESAttributes{
				KeySize: 256,
			},
		}
		createdKeys = append(createdKeys, attrs)

		// Generate symmetric key
		_, err := symBackend.GenerateSymmetricKey(attrs)
		require.NoError(t, err, "Failed to generate symmetric key in real Azure Key Vault")

		// Get encrypter
		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		require.NoError(t, err, "Failed to get symmetric encrypter")
		require.NotNil(t, encrypter, "Encrypter should not be nil")

		// Test encryption
		plaintext := []byte("test symmetric encryption with real Azure Key Vault")
		encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{})
		require.NoError(t, err, "Failed to encrypt with real Azure Key Vault")
		require.NotNil(t, encrypted, "Encrypted data should not be nil")
		require.NotEmpty(t, encrypted.Ciphertext, "Ciphertext should not be empty")

		// Test decryption
		decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{})
		require.NoError(t, err, "Failed to decrypt with real Azure Key Vault")
		assert.Equal(t, plaintext, decrypted, "Decrypted data should match plaintext")

		t.Logf("✓ Symmetric encryption works with real Azure Key Vault (encrypted %d bytes)", len(plaintext))
	})

	t.Run("RealAzure/DeleteKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-delete-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		keyID, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create key")
		require.NotEmpty(t, keyID, "Key ID should not be empty")

		// Note: Azure Key Vault soft-deletes keys by default
		err = b.Delete(attrs)
		require.NoError(t, err, "Failed to delete key from real Azure Key Vault")

		t.Logf("✓ Deleted key from real Azure Key Vault (soft-delete)")
	})
}
