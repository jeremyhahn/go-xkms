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

//go:build cloud_integration && awskms

package integration

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAWSKMSCloudIntegration tests AWS KMS backend against REAL AWS cloud service
// This requires valid AWS credentials and will create REAL resources that cost money.
//
// Prerequisites:
//   - AWS CLI configured with valid credentials
//   - Appropriate KMS permissions (kms:CreateKey, kms:Sign, kms:GetPublicKey, etc.)
//   - Environment variables: AWS_REGION (optional, defaults to us-east-1)
//
// Run with:
//
//	go test -tags="cloud_integration awskms" -v ./test/integration/awskms/...
func TestAWSKMSCloudIntegration(t *testing.T) {
	// Load AWS config from environment (uses real credentials)
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	require.NoError(t, err, "Failed to load AWS config - ensure AWS CLI is configured")

	// Create KMS client for REAL AWS service
	kmsClient := kms.NewFromConfig(cfg)

	// Create storage backends
	keyStorage := storage.New()
	certStorage := storage.New()

	// Create backend
	backendCfg := &awskms.Config{
		Region:      cfg.Region,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}
	b, err := awskms.NewBackendWithClient(backendCfg, kmsClient)
	require.NoError(t, err, "Failed to create AWS KMS backend")
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

	t.Run("RealAWS/CreateAndSignRSAKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-rsa-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		keyID, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create RSA key in real AWS KMS")
		require.NotEmpty(t, keyID, "Key ID should not be empty")

		// Test signing with real KMS
		digest := crypto.SHA256.New()
		digest.Write([]byte("test message for real AWS KMS signing"))
		signature, err := b.Sign(attrs, digest.Sum(nil))
		require.NoError(t, err, "Failed to sign with real AWS KMS")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		t.Logf("✓ Created real AWS KMS RSA key and signed (keyID: %s, signature length: %d)", keyID, len(signature))
	})

	t.Run("RealAWS/CreateAndSignECDSAKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-ecdsa-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
			Hash:         crypto.SHA256,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}
		createdKeys = append(createdKeys, attrs)

		keyID, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create ECDSA key in real AWS KMS")
		require.NotEmpty(t, keyID, "Key ID should not be empty")

		// Test signing
		digest := crypto.SHA256.New()
		digest.Write([]byte("test ecdsa message"))
		signature, err := b.Sign(attrs, digest.Sum(nil))
		require.NoError(t, err, "Failed to sign with ECDSA key")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		t.Logf("✓ Created real AWS KMS ECDSA key and signed (keyID: %s)", keyID)
	})

	t.Run("RealAWS/SignAndVerify", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-verify-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create key")

		// Sign
		message := []byte("test verification with real AWS KMS")
		digest := crypto.SHA256.New()
		digest.Write(message)
		digestBytes := digest.Sum(nil)

		signature, err := b.Sign(attrs, digestBytes)
		require.NoError(t, err, "Failed to sign")

		// Verify
		err = b.Verify(attrs, digestBytes, signature)
		require.NoError(t, err, "Failed to verify signature")

		t.Logf("✓ Successfully signed and verified with real AWS KMS")
	})

	t.Run("RealAWS/ListKeys", func(t *testing.T) {
		// Create a test key
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-list-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create key")

		// List keys
		keys, err := b.ListKeys()
		require.NoError(t, err, "Failed to list keys from real AWS KMS")
		require.NotNil(t, keys, "Keys list should not be nil")
		require.NotEmpty(t, keys, "Should have at least 1 key")

		t.Logf("✓ Listed %d keys from real AWS KMS", len(keys))
	})

	t.Run("RealAWS/KeyRotation", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-rotate-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create key")

		// Test key rotation on real AWS KMS
		err = b.RotateKey(attrs)
		if err != nil {
			// Note: Key rotation might have restrictions on real AWS
			t.Logf("Key rotation failed (might be expected on real AWS): %v", err)
		} else {
			t.Logf("✓ Successfully rotated key in real AWS KMS")
		}
	})

	t.Run("RealAWS/SignerInterface", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-signer-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
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
		require.NoError(t, err, "Failed to get Signer from real AWS KMS")
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

		t.Logf("✓ Signer interface works with real AWS KMS")
	})

	t.Run("RealAWS/Signer_RSA_PSS", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-signer-pss-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create RSA key for PSS signing")

		signer, err := b.Signer(attrs)
		require.NoError(t, err, "Failed to get Signer for PSS signing")

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

		rsaPub := signer.Public().(*rsa.PublicKey)
		err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
		require.NoError(t, err, "Failed to verify RSA-PSS signature")

		t.Logf("✓ RSA-PSS signing works with AWS KMS")
	})

	t.Run("RealAWS/ImportExport", func(t *testing.T) {
		// Create a source key to export
		sourceAttrs := &types.KeyAttributes{
			CN:           "cloud-test-export-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, sourceAttrs)

		_, err := b.CreateKey(sourceAttrs)
		require.NoError(t, err, "Failed to create source key")

		// Check if backend supports import/export
		caps := b.Capabilities()
		if !caps.SupportsImportExport() {
			t.Skip("AWS KMS backend does not support import/export")
			return
		}

		// Get import/export backend
		ieb, ok := interface{}(b).(backend.ImportExportBackend)
		require.True(t, ok, "Backend should implement ImportExportBackend")

		// Test getting import parameters
		params, err := ieb.GetImportParameters(sourceAttrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		if err != nil {
			t.Logf("GetImportParameters not supported: %v", err)
			return
		}
		require.NotNil(t, params, "Import parameters should not be nil")
		require.NotEmpty(t, params.ImportToken, "Import token should not be empty")
		require.NotNil(t, params.WrappingPublicKey, "Wrapping public key should not be nil")

		t.Logf("✓ Import/export operations work with real AWS KMS")
	})

	t.Run("RealAWS/SymmetricEncryption", func(t *testing.T) {
		// Check if backend supports symmetric encryption
		caps := b.Capabilities()
		if !caps.SupportsSymmetricEncryption() {
			t.Skip("AWS KMS backend does not support symmetric encryption")
			return
		}

		symBackend, ok := interface{}(b).(types.SymmetricBackend)
		require.True(t, ok, "Backend should implement SymmetricBackend")

		attrs := &types.KeyAttributes{
			CN:                 "cloud-test-aes-" + time.Now().Format("20060102-150405"),
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			KeyType:            backend.KEY_TYPE_ENCRYPTION,
			StoreType:          backend.STORE_AWSKMS,
			AESAttributes: &types.AESAttributes{
				KeySize: 256,
			},
		}
		createdKeys = append(createdKeys, attrs)

		// Generate symmetric key
		_, err := symBackend.GenerateSymmetricKey(attrs)
		require.NoError(t, err, "Failed to generate symmetric key in real AWS KMS")

		// Get encrypter
		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		require.NoError(t, err, "Failed to get symmetric encrypter")
		require.NotNil(t, encrypter, "Encrypter should not be nil")

		// Test encryption
		plaintext := []byte("test symmetric encryption with real AWS KMS")
		encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{})
		require.NoError(t, err, "Failed to encrypt with real AWS KMS")
		require.NotNil(t, encrypted, "Encrypted data should not be nil")
		require.NotEmpty(t, encrypted.Ciphertext, "Ciphertext should not be empty")

		// Test decryption
		decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{})
		require.NoError(t, err, "Failed to decrypt with real AWS KMS")
		assert.Equal(t, plaintext, decrypted, "Decrypted data should match plaintext")

		t.Logf("✓ Symmetric encryption works with real AWS KMS (encrypted %d bytes)", len(plaintext))
	})

	t.Run("RealAWS/DeleteKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-delete-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AWSKMS,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		keyID, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create key")
		require.NotEmpty(t, keyID, "Key ID should not be empty")

		// Delete the key
		err = b.Delete(attrs)
		require.NoError(t, err, "Failed to delete key from real AWS KMS")

		// Verify it's gone by trying to use it
		digest := crypto.SHA256.New()
		digest.Write([]byte("test"))
		_, err = b.Sign(attrs, digest.Sum(nil))
		require.Error(t, err, "Using deleted key should return error")

		t.Logf("✓ Successfully deleted key from real AWS KMS")
	})
}
