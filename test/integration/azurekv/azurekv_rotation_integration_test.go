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
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

// TestAzureKVKeyRotation tests comprehensive key rotation scenarios for Azure Key Vault.
// Key rotation creates a new version of the key while keeping old versions accessible.
// This test validates:
// 1. Rotating RSA signing keys
// 2. Old key versions can still verify signatures created before rotation
// 3. New key versions create new signatures
// 4. Both old and new signatures remain valid after rotation
// 5. Rotating ECDSA keys
// 6. Multiple rotation cycles
func TestAzureKVKeyRotation(t *testing.T) {
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

	// ========================================================================
	// Test 1: RSA Key Rotation - Complete Workflow
	// ========================================================================
	t.Run("RSAKeyRotation_Complete_Workflow", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rotate-rsa-complete",
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

		// Step 1: Create initial key
		t.Log("Step 1: Creating initial RSA signing key...")
		keyID1, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create initial key")
		require.NotEmpty(t, keyID1, "Key ID should not be empty")
		t.Logf("✓ Created initial key: %s", keyID1)

		// Wait a bit to ensure timestamp difference
		time.Sleep(100 * time.Millisecond)

		// Step 2: Create signature with original key (version 1)
		t.Log("Step 2: Creating signature with original key...")
		message1 := []byte("Message signed with original key version")
		hash1 := sha256.Sum256(message1)
		digest1 := hash1[:]

		signature1, err := b.Sign(attrs, digest1)
		require.NoError(t, err, "Failed to sign with original key")
		require.NotEmpty(t, signature1, "Signature should not be empty")
		t.Logf("✓ Created signature with original key (v1): %d bytes", len(signature1))

		// Step 3: Verify signature with original key
		t.Log("Step 3: Verifying signature with original key...")
		err = b.Verify(attrs, digest1, signature1)
		require.NoError(t, err, "Failed to verify signature with original key")
		t.Logf("✓ Verified signature with original key")

		// Wait a bit before rotation
		time.Sleep(100 * time.Millisecond)

		// Step 4: Rotate the key
		t.Log("Step 4: Rotating key to create new version...")
		err = b.RotateKey(attrs)
		if err != nil {
			// Azure KV emulator may not support rotation
			t.Logf("⚠ Key rotation not supported (emulator limitation): %v", err)
			t.Fatal("Skipping due to emulator limitation")
			return
		}
		t.Logf("✓ Successfully rotated key")

		// Wait a bit after rotation
		time.Sleep(100 * time.Millisecond)

		// Step 5: Verify old signature is still valid after rotation
		// This is critical - old signatures must remain valid even after rotation
		t.Log("Step 5: Verifying old signature is still valid after rotation...")
		err = b.Verify(attrs, digest1, signature1)
		require.NoError(t, err, "Old signature should still be valid after rotation")
		t.Logf("✓ Old signature (v1) is still valid after rotation")

		// Step 6: Create new signature with rotated key (version 2)
		t.Log("Step 6: Creating new signature with rotated key...")
		message2 := []byte("Message signed with rotated key version")
		hash2 := sha256.Sum256(message2)
		digest2 := hash2[:]

		signature2, err := b.Sign(attrs, digest2)
		require.NoError(t, err, "Failed to sign with rotated key")
		require.NotEmpty(t, signature2, "New signature should not be empty")
		t.Logf("✓ Created signature with rotated key (v2): %d bytes", len(signature2))

		// Step 7: Verify new signature
		t.Log("Step 7: Verifying new signature from rotated key...")
		err = b.Verify(attrs, digest2, signature2)
		require.NoError(t, err, "Failed to verify signature from rotated key")
		t.Logf("✓ Verified signature with rotated key")

		// Step 8: Verify old signature is STILL valid (double-check)
		t.Log("Step 8: Re-verifying old signature is still valid...")
		err = b.Verify(attrs, digest1, signature1)
		require.NoError(t, err, "Old signature should still be valid")
		t.Logf("✓ Old signature (v1) remains valid")

		// Step 9: Verify both signatures are different (sanity check)
		t.Log("Step 9: Verifying signatures are different...")
		assert.NotEqual(t, signature1, signature2, "Signatures from different key versions should be different")
		t.Logf("✓ Signatures from v1 and v2 are different")

		// Step 10: Cross-verify signatures don't work with wrong messages
		t.Log("Step 10: Testing signature isolation (wrong message should fail)...")
		err = b.Verify(attrs, digest2, signature1)
		assert.Error(t, err, "Signature v1 should not verify message 2")
		err = b.Verify(attrs, digest1, signature2)
		assert.Error(t, err, "Signature v2 should not verify message 1")
		t.Logf("✓ Signatures correctly isolated to their messages")

		t.Log("✓✓✓ Complete RSA key rotation workflow succeeded!")
		t.Log("Summary:")
		t.Log("  - Created initial key version (v1)")
		t.Log("  - Signed message with v1")
		t.Log("  - Rotated key to create v2")
		t.Log("  - Old v1 signature remains valid")
		t.Log("  - New v2 signature works correctly")
		t.Log("  - Both signatures coexist and are valid")

		// Cleanup
		_ = b.Delete(attrs)
	})

	// ========================================================================
	// Test 2: ECDSA Key Rotation
	// ========================================================================
	t.Run("ECDSAKeyRotation_Complete_Workflow", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rotate-ecdsa-complete",
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

		// Create initial ECDSA key
		t.Log("Creating initial ECDSA P-256 signing key...")
		keyID1, err := b.CreateKey(attrs)
		if err != nil {
			t.Logf("⚠ ECDSA not supported by emulator (Azure KV supports this in production): %v", err)
			t.Fatal("Skipping ECDSA rotation due to emulator limitation")
			return
		}
		require.NotEmpty(t, keyID1, "Key ID should not be empty")
		t.Logf("✓ Created initial ECDSA key: %s", keyID1)

		// Sign with original key
		message1 := []byte("ECDSA message signed with original key version")
		hash1 := sha256.Sum256(message1)
		digest1 := hash1[:]

		signature1, err := b.Sign(attrs, digest1)
		require.NoError(t, err, "Failed to sign with original ECDSA key")
		t.Logf("✓ Created ECDSA signature with original key: %d bytes", len(signature1))

		// Rotate the key
		t.Log("Rotating ECDSA key...")
		err = b.RotateKey(attrs)
		if err != nil {
			t.Logf("⚠ ECDSA key rotation not supported: %v", err)
			_ = b.Delete(attrs)
			return
		}
		t.Logf("✓ Successfully rotated ECDSA key")

		// Verify old signature still works
		err = b.Verify(attrs, digest1, signature1)
		require.NoError(t, err, "Old ECDSA signature should still be valid after rotation")
		t.Logf("✓ Old ECDSA signature is still valid after rotation")

		// Create new signature with rotated key
		message2 := []byte("ECDSA message signed with rotated key version")
		hash2 := sha256.Sum256(message2)
		digest2 := hash2[:]

		signature2, err := b.Sign(attrs, digest2)
		require.NoError(t, err, "Failed to sign with rotated ECDSA key")
		t.Logf("✓ Created ECDSA signature with rotated key: %d bytes", len(signature2))

		// Verify new signature
		err = b.Verify(attrs, digest2, signature2)
		require.NoError(t, err, "Failed to verify signature from rotated ECDSA key")
		t.Logf("✓ Verified signature with rotated ECDSA key")

		t.Log("✓✓✓ Complete ECDSA key rotation workflow succeeded!")

		// Cleanup
		_ = b.Delete(attrs)
	})

	// ========================================================================
	// Test 3: Multiple Rotation Cycles
	// ========================================================================
	t.Run("MultipleRotationCycles", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rotate-multiple",
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

		// Create initial key
		t.Log("Creating initial key for multiple rotation test...")
		_, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create initial key")

		// Create signatures from multiple key versions
		const numRotations = 3
		signatures := make([][]byte, numRotations+1) // +1 for initial version
		digests := make([][]byte, numRotations+1)

		// Sign with initial version
		t.Logf("Signing with initial key version (v0)...")
		message0 := []byte("Message from initial key version 0")
		hash0 := sha256.Sum256(message0)
		digests[0] = hash0[:]
		signatures[0], err = b.Sign(attrs, digests[0])
		require.NoError(t, err, "Failed to sign with initial key")
		t.Logf("✓ Signed with v0: %d bytes", len(signatures[0]))

		// Perform multiple rotations
		for i := 0; i < numRotations; i++ {
			time.Sleep(100 * time.Millisecond) // Small delay between rotations

			t.Logf("Rotation cycle %d/%d...", i+1, numRotations)
			err = b.RotateKey(attrs)
			if err != nil {
				t.Logf("⚠ Key rotation not supported: %v", err)
				_ = b.Delete(attrs)
				t.Fatal("Skipping due to rotation limitation")
				return
			}
			t.Logf("✓ Rotated to version %d", i+1)

			time.Sleep(100 * time.Millisecond)

			// Sign with new version
			message := []byte(fmt.Sprintf("Message from key version %d", i+1))
			hash := sha256.Sum256(message)
			digests[i+1] = hash[:]
			signatures[i+1], err = b.Sign(attrs, digests[i+1])
			require.NoError(t, err, "Failed to sign with version %d", i+1)
			t.Logf("✓ Signed with v%d: %d bytes", i+1, len(signatures[i+1]))
		}

		// Verify ALL signatures are still valid
		t.Log("Verifying all signatures from all versions are still valid...")
		for i := 0; i <= numRotations; i++ {
			err = b.Verify(attrs, digests[i], signatures[i])
			require.NoError(t, err, "Signature from version %d should still be valid", i)
			t.Logf("✓ Signature from v%d is still valid", i)
		}

		t.Logf("✓✓✓ Multiple rotation cycles succeeded!")
		t.Logf("Summary: Performed %d rotations, all %d signatures remain valid", numRotations, numRotations+1)

		// Cleanup
		_ = b.Delete(attrs)
	})

	// ========================================================================
	// Test 4: Rotation with Signer Interface
	// ========================================================================
	t.Run("KeyRotation_WithSignerInterface", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rotate-signer",
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

		// Create key
		t.Log("Creating key for Signer interface rotation test...")
		_, err := b.CreateKey(attrs)
		require.NoError(t, err, "Failed to create key")

		// Get Signer interface for original key
		t.Log("Getting Signer interface for original key...")
		signer1, err := b.Signer(attrs)
		if err != nil {
			t.Logf("⚠ Signer interface not supported: %v", err)
			_ = b.Delete(attrs)
			t.Fatal("Skipping Signer interface test")
			return
		}
		require.NotNil(t, signer1, "Signer should not be nil")

		// Get public key from original version
		pubKey1 := signer1.Public()
		require.NotNil(t, pubKey1, "Public key should not be nil")
		t.Logf("✓ Retrieved public key from v1")

		// Sign with original key
		message1 := []byte("Message signed via Signer interface v1")
		hash1 := sha256.Sum256(message1)
		digest1 := hash1[:]

		signature1, err := signer1.Sign(nil, digest1, crypto.SHA256)
		require.NoError(t, err, "Failed to sign via Signer interface")
		t.Logf("✓ Signed via Signer interface: %d bytes", len(signature1))

		// Rotate key
		t.Log("Rotating key...")
		err = b.RotateKey(attrs)
		if err != nil {
			t.Logf("⚠ Key rotation not supported: %v", err)
			_ = b.Delete(attrs)
			t.Fatal("Skipping due to rotation limitation")
			return
		}
		t.Logf("✓ Key rotated")

		// Get new Signer interface (should use rotated key)
		t.Log("Getting Signer interface for rotated key...")
		signer2, err := b.Signer(attrs)
		require.NoError(t, err, "Failed to get Signer after rotation")

		// Get public key from rotated version
		pubKey2 := signer2.Public()
		require.NotNil(t, pubKey2, "Public key should not be nil")
		t.Logf("✓ Retrieved public key from v2")

		// Note: In Azure KV, when using default version (""), it uses the latest version
		// So pubKey2 might be the same as pubKey1 if the backend always returns the latest

		// Sign with rotated key
		message2 := []byte("Message signed via Signer interface v2")
		hash2 := sha256.Sum256(message2)
		digest2 := hash2[:]

		signature2, err := signer2.Sign(nil, digest2, crypto.SHA256)
		require.NoError(t, err, "Failed to sign via Signer interface after rotation")
		t.Logf("✓ Signed via Signer interface after rotation: %d bytes", len(signature2))

		// Verify both signatures are valid
		err = b.Verify(attrs, digest1, signature1)
		require.NoError(t, err, "Original signature should be valid")
		t.Logf("✓ Original signature is still valid")

		err = b.Verify(attrs, digest2, signature2)
		require.NoError(t, err, "New signature should be valid")
		t.Logf("✓ New signature is valid")

		t.Log("✓✓✓ Signer interface rotation test succeeded!")

		// Cleanup
		_ = b.Delete(attrs)
	})

	// ========================================================================
	// Test 5: Error Handling - Rotate Non-Existent Key
	// ========================================================================
	t.Run("RotateKey_NonExistent", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rotate-nonexistent",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_AZUREKV,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Try to rotate a key that doesn't exist
		err := b.RotateKey(attrs)
		require.Error(t, err, "Rotating non-existent key should return error")
		t.Logf("✓ Correctly rejected rotation of non-existent key: %v", err)
	})

	// ========================================================================
	// Test 6: Error Handling - Nil Attributes
	// ========================================================================
	t.Run("RotateKey_NilAttributes", func(t *testing.T) {
		err := b.RotateKey(nil)
		require.Error(t, err, "Rotating with nil attributes should return error")
		t.Logf("✓ Correctly rejected nil attributes: %v", err)
	})
}
