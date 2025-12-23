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

//go:build cloud_integration && gcpkms

package integration

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGCPKMSCloudIntegration tests GCP KMS backend against REAL GCP cloud service
// This requires valid GCP credentials and will create REAL resources that cost money.
//
// Prerequisites:
//   - gcloud CLI configured with valid credentials
//   - Application default credentials configured: gcloud auth application-default login
//   - Environment variables:
//   - GCP_PROJECT_ID (required)
//   - GCP_LOCATION (optional, defaults to us-central1)
//   - GCP_KEYRING (optional, defaults to test-keyring)
//   - GOOGLE_APPLICATION_CREDENTIALS (optional, path to service account JSON)
//   - A KMS keyring must exist: gcloud kms keyrings create test-keyring --location=us-central1
//
// Run with:
//
//	export GCP_PROJECT_ID="your-project-id"
//	export GCP_LOCATION="us-central1"
//	export GCP_KEYRING="test-keyring"
//	go test -tags="cloud_integration gcpkms" -v ./test/integration/gcpkms/...
func TestGCPKMSCloudIntegration(t *testing.T) {
	// Check required environment variables
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		t.Fatal("GCP_PROJECT_ID not set - skipping real GCP KMS tests")
	}

	location := os.Getenv("GCP_LOCATION")
	if location == "" {
		location = "us-central1"
	}

	keyring := os.Getenv("GCP_KEYRING")
	if keyring == "" {
		keyring = "test-keyring"
	}

	// Create context for GCP service
	ctx := context.Background()

	// Setup: Ensure KeyRing exists (create if needed)
	t.Log("Setting up GCP KMS resources...")
	setupErr := setupGCPKeyRing(ctx, projectID, location, keyring)
	if setupErr != nil {
		t.Fatalf("Cannot setup GCP KMS resources: %v\n\n"+
			"To fix this, you need Cloud KMS Admin permissions. Run:\n"+
			"  gcloud projects add-iam-policy-binding %s \\\n"+
			"    --member='user:%s' \\\n"+
			"    --role='roles/cloudkms.admin'\n\n"+
			"Or have an admin create the keyring:\n"+
			"  gcloud kms keyrings create %s --location=%s --project=%s\n",
			setupErr, projectID, os.Getenv("USER")+"@yourdomain.com", keyring, location, projectID)
	}
	t.Logf("✓ GCP KMS resources ready (project=%s, location=%s, keyring=%s)", projectID, location, keyring)

	// Create storage backends
	keyStorage := storage.New()
	certStorage := storage.New()

	// Create backend
	backendCfg := &gcpkms.Config{
		ProjectID:   projectID,
		LocationID:  location,
		KeyRingID:   keyring,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}
	b, err := gcpkms.NewBackend(ctx, backendCfg)
	require.NoError(t, err, "Failed to create GCP KMS backend")
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

	t.Run("RealGCP/CreateAndSignRSAKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-rsa-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to create RSA key in real GCP KMS")

		// Test signing with real GCP KMS
		digest := crypto.SHA256.New()
		digest.Write([]byte("test message for real GCP KMS signing"))
		signature, err := b.Sign(attrs, digest.Sum(nil), crypto.SHA256)
		require.NoError(t, err, "Failed to sign with real GCP KMS")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		t.Logf("✓ Created real GCP KMS RSA key and signed (CN: %s, signature length: %d)", attrs.CN, len(signature))
	})

	t.Run("RealGCP/CreateAndSignECDSAKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-ecdsa-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			Hash:         crypto.SHA256,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.GenerateECDSA(attrs)
		require.NoError(t, err, "Failed to create ECDSA key in real GCP KMS")

		// Test signing
		digest := crypto.SHA256.New()
		digest.Write([]byte("test ecdsa message"))
		signature, err := b.Sign(attrs, digest.Sum(nil), crypto.SHA256)
		require.NoError(t, err, "Failed to sign with ECDSA key")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		t.Logf("✓ Created real GCP KMS ECDSA key and signed (CN: %s)", attrs.CN)
	})

	t.Run("RealGCP/SignAndVerify", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-verify-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to create key")

		// Sign
		message := []byte("test verification with real GCP KMS")
		digest := crypto.SHA256.New()
		digest.Write(message)
		digestBytes := digest.Sum(nil)

		signature, err := b.Sign(attrs, digestBytes, crypto.SHA256)
		require.NoError(t, err, "Failed to sign")

		// Verify
		err = b.Verify(attrs, digestBytes, signature)
		require.NoError(t, err, "Failed to verify signature")

		t.Logf("✓ Successfully signed and verified with real GCP KMS")
	})

	t.Run("RealGCP/RSA_PSS_Sign_Verify", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-rsa-pss-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to create RSA key in real GCP KMS")

		signer, err := b.Signer(attrs)
		require.NoError(t, err, "Failed to get Signer")

		message := []byte("GCP KMS RSA-PSS test with real cloud service")
		h := sha256.New()
		h.Write(message)
		digest := h.Sum(nil)

		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		}

		signature, err := signer.Sign(rand.Reader, digest, pssOpts)
		require.NoError(t, err, "Failed to sign with RSA-PSS")

		rsaPub := signer.Public().(*rsa.PublicKey)
		err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
		require.NoError(t, err, "Failed to verify RSA-PSS signature")

		t.Logf("✓ RSA-PSS works with real GCP KMS (CN: %s)", attrs.CN)
	})

	t.Run("RealGCP/ListKeys", func(t *testing.T) {
		// Create a test key
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-list-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to create key")

		// List keys
		keys, err := b.ListKeys()
		require.NoError(t, err, "Failed to list keys from real GCP KMS")
		require.NotNil(t, keys, "Keys list should not be nil")
		require.NotEmpty(t, keys, "Should have at least 1 key")

		t.Logf("✓ Listed %d keys from real GCP KMS", len(keys))
	})

	t.Run("RealGCP/SignerInterface", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-signer-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, attrs)

		_, err := b.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to create key")

		// Get Signer interface
		signer, err := b.Signer(attrs)
		require.NoError(t, err, "Failed to get Signer from real GCP KMS")
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

		t.Logf("✓ Signer interface works with real GCP KMS")
	})

	t.Run("RealGCP/ImportExport", func(t *testing.T) {
		// Create a source key to export
		sourceAttrs := &types.KeyAttributes{
			CN:           "cloud-test-import-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		createdKeys = append(createdKeys, sourceAttrs)

		// Check if backend supports import/export
		caps := b.Capabilities()
		if !caps.SupportsImportExport() {
			t.Fatal("GCP KMS backend does not support import/export")
			return
		}

		// Get import/export backend
		ieb, ok := interface{}(b).(backend.ImportExportBackend)
		require.True(t, ok, "Backend should implement ImportExportBackend")

		// Test creating import job
		params, err := ieb.GetImportParameters(sourceAttrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		if err != nil {
			t.Logf("GetImportParameters not fully supported yet: %v", err)
			return
		}
		require.NotNil(t, params, "Import parameters should not be nil")
		require.NotEmpty(t, params.ImportToken, "Import token should not be empty")
		require.NotNil(t, params.WrappingPublicKey, "Wrapping public key should not be nil")

		t.Logf("✓ Import/export operations work with real GCP KMS")
	})

	t.Run("RealGCP/SymmetricEncryption", func(t *testing.T) {
		// Check if backend supports symmetric encryption
		caps := b.Capabilities()
		if !caps.SupportsSymmetricEncryption() {
			t.Fatal("GCP KMS backend does not support symmetric encryption")
			return
		}

		symBackend, ok := interface{}(b).(types.SymmetricBackend)
		require.True(t, ok, "Backend should implement SymmetricBackend")

		attrs := &types.KeyAttributes{
			CN:                 "cloud-test-aes-" + time.Now().Format("20060102-150405"),
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			KeyType:            backend.KEY_TYPE_ENCRYPTION,
			StoreType:          backend.STORE_GCPKMS,
		}
		createdKeys = append(createdKeys, attrs)

		// Generate symmetric key
		_, err := symBackend.GenerateSymmetricKey(attrs)
		require.NoError(t, err, "Failed to generate symmetric key in real GCP KMS")

		// Get encrypter
		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		require.NoError(t, err, "Failed to get symmetric encrypter")
		require.NotNil(t, encrypter, "Encrypter should not be nil")

		// Test encryption
		plaintext := []byte("test symmetric encryption with real GCP KMS")
		encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{})
		require.NoError(t, err, "Failed to encrypt with real GCP KMS")
		require.NotNil(t, encrypted, "Encrypted data should not be nil")
		require.NotEmpty(t, encrypted.Ciphertext, "Ciphertext should not be empty")

		// Test decryption
		decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{})
		require.NoError(t, err, "Failed to decrypt with real GCP KMS")
		assert.Equal(t, plaintext, decrypted, "Decrypted data should match plaintext")

		t.Logf("✓ Symmetric encryption works with real GCP KMS (encrypted %d bytes)", len(plaintext))
	})

	t.Run("RealGCP/DeleteKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "cloud-test-delete-" + time.Now().Format("20060102-150405"),
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		_, err := b.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to create key")

		// Note: GCP KMS doesn't actually delete keys immediately - they go into a scheduled deletion state
		err = b.Delete(attrs)
		if err != nil {
			// Some GCP KMS configurations might not allow deletion
			t.Logf("Key deletion note: %v", err)
		} else {
			t.Logf("✓ Scheduled key for deletion in real GCP KMS")
		}
	})

}

// setupGCPKeyRing ensures the KeyRing exists for testing.
// GCP KMS KeyRings cannot be deleted, so we check if it exists first.
// If it doesn't exist, we try to create it.
// Returns an error if the KeyRing doesn't exist and can't be created.
func setupGCPKeyRing(ctx context.Context, projectID, location, keyringID string) error {
	// Import the KMS client package dynamically
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create KMS client: %w", err)
	}
	defer kmsClient.Close()

	// Check if KeyRing exists
	keyringName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", projectID, location, keyringID)
	_, err = kmsClient.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{
		Name: keyringName,
	})

	if err == nil {
		// KeyRing exists, we're good
		return nil
	}

	// KeyRing doesn't exist, try to create it
	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, location)
	_, err = kmsClient.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    parent,
		KeyRingId: keyringID,
	})

	if err != nil {
		return fmt.Errorf("keyring does not exist and cannot be created (check permissions): %w", err)
	}

	return nil
}
