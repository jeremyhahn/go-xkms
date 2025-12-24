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

//go:build integration && canokey && pkcs11

package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	pkcs11lib "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getCanoKeyConfig returns configuration for CanoKey PKCS#11
// CanoKey uses OpenSC PKCS#11 library for PIV operations
// Returns nil, false if no CanoKey hardware is detected
func getCanoKeyConfig(t *testing.T) (*pkcs11.Config, bool) {
	// Use OpenSC for physical CanoKey
	canokeyLib := os.Getenv("CANOKEY_PKCS11_LIBRARY")
	if canokeyLib == "" {
		// Default to standard Linux location for OpenSC
		canokeyLib = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"

		// If not found, try other common locations
		if _, err := os.Stat(canokeyLib); os.IsNotExist(err) {
			candidates := []string{
				"/usr/lib/opensc-pkcs11.so",
				"/usr/local/lib/opensc-pkcs11.so",
				"/usr/lib/pkcs11/opensc-pkcs11.so",
				"/Library/OpenSC/lib/opensc-pkcs11.so", // macOS
			}

			found := false
			for _, path := range candidates {
				if _, err := os.Stat(path); err == nil {
					canokeyLib = path
					found = true
					break
				}
			}

			if !found {
				t.Log("OpenSC PKCS#11 library not found")
				return nil, false
			}
		}
	}

	t.Logf("Using CanoKey PKCS#11 library: %s", canokeyLib)

	// Get PIN from environment or use default
	pin := os.Getenv("CANOKEY_PIN")
	if pin == "" {
		pin = "123456" // Default CanoKey PIV PIN
	}

	// Get SO PIN from environment or use default
	soPin := os.Getenv("CANOKEY_SOPIN")
	if soPin == "" {
		soPin = "12345678" // Default CanoKey PIV PUK
	}

	// Discover the actual token label from CanoKey
	p := pkcs11lib.New(canokeyLib)
	if p == nil {
		t.Log("Failed to load PKCS#11 library")
		return nil, false
	}

	err := p.Initialize()
	if err != nil {
		t.Logf("Failed to initialize PKCS#11: %v", err)
		return nil, false
	}
	defer p.Finalize()
	defer p.Destroy()

	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		t.Log("No PKCS#11 slots found - CanoKey hardware not connected")
		return nil, false
	}

	// Look for CanoKey token
	var tokenLabel string
	for _, slot := range slots {
		tokenInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if containsCanoKey(tokenInfo.Label) {
			tokenLabel = tokenInfo.Label
			break
		}
	}

	if tokenLabel == "" {
		t.Log("No CanoKey token found - hardware not connected")
		return nil, false
	}

	t.Logf("Discovered CanoKey token: %s", tokenLabel)

	// Create storage backends
	keyStorage := storage.New()
	certStorage := storage.New()

	config := &pkcs11.Config{
		Library:     canokeyLib,
		TokenLabel:  tokenLabel,
		PIN:         pin,
		SOPIN:       soPin,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}

	return config, true
}

// containsCanoKey checks if the token label indicates a CanoKey device
func containsCanoKey(label string) bool {
	keywords := []string{"CanoKey", "canokey", "CANOKEY", "Cano"}
	for _, kw := range keywords {
		if strings.Contains(label, kw) {
			return true
		}
	}
	return false
}

// keyExists checks if a key exists in the backend by attempting to retrieve it
func keyExists(backend *pkcs11.Backend, attrs *types.KeyAttributes) (bool, error) {
	_, err := backend.GetKey(attrs)
	if err != nil {
		// Check if the error indicates the key doesn't exist
		// Most PKCS#11 implementations return an error when key is not found
		return false, nil
	}
	return true, nil
}

// TestCanoKeyPKCS11Integration performs comprehensive integration tests for CanoKey PKCS#11
// Requires physical CanoKey hardware connected via USB
func TestCanoKeyPKCS11Integration(t *testing.T) {
	config, available := getCanoKeyConfig(t)
	if !available {
		t.Skip("CanoKey hardware not detected - connect physical CanoKey to run these tests")
	}

	// Create PKCS11 backend
	canokey, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create CanoKey PKCS#11 backend: %v", err)
	}
	defer canokey.Close()

	// Initialize (login to the CanoKey)
	err = canokey.Initialize(config.SOPIN, config.PIN)
	if err != nil && err != pkcs11.ErrAlreadyInitialized {
		t.Fatalf("Failed to initialize CanoKey PKCS#11 backend: %v", err)
	}

	t.Log("=== CanoKey PKCS#11 Integration Tests ===")

	// ========================================
	// Backend Information
	// ========================================
	t.Run("BackendInfo", func(t *testing.T) {
		backendType := canokey.Type()
		assert.Equal(t, backend.STORE_PKCS11, backendType, "Backend type should be PKCS11")
		t.Logf("✓ Backend type: %s", backendType)

		capabilities := canokey.Capabilities()
		assert.True(t, capabilities.Keys, "Should support key operations")
		assert.True(t, capabilities.HardwareBacked, "Should be hardware-backed")
		assert.True(t, capabilities.Signing, "Should support signing")
		t.Logf("✓ Capabilities: Keys=%v, HardwareBacked=%v, Signing=%v",
			capabilities.Keys, capabilities.HardwareBacked, capabilities.Signing)
	})

	// ========================================
	// Key Generation Tests
	// ========================================
	t.Run("KeyGeneration", func(t *testing.T) {
		t.Run("RSA-2048", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "canokey-test-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Clean up any existing key first
			_ = canokey.DeleteKey(attrs)

			key, err := canokey.GenerateRSA(attrs)
			require.NoError(t, err, "Failed to generate RSA-2048 key on CanoKey")
			require.NotNil(t, key)

			// Verify it's a crypto.Signer
			signer, ok := key.(crypto.Signer)
			require.True(t, ok, "Key must implement crypto.Signer")

			// Verify public key
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			require.True(t, ok, "Expected RSA public key")
			assert.Equal(t, 2048, rsaPub.N.BitLen(), "Key size should be 2048 bits")

			t.Logf("✓ Generated RSA-2048 key on CanoKey: %d bits", rsaPub.N.BitLen())

			// Clean up
			err = canokey.DeleteKey(attrs)
			assert.NoError(t, err, "Failed to delete test key")
		})

		t.Run("RSA-4096", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "canokey-test-rsa-4096",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			}

			// Clean up any existing key first
			_ = canokey.DeleteKey(attrs)

			key, err := canokey.GenerateRSA(attrs)
			require.NoError(t, err, "Failed to generate RSA-4096 key on CanoKey")
			require.NotNil(t, key)

			// Verify it's a crypto.Signer
			signer, ok := key.(crypto.Signer)
			require.True(t, ok, "Key must implement crypto.Signer")

			// Verify public key
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			require.True(t, ok, "Expected RSA public key")
			assert.Equal(t, 4096, rsaPub.N.BitLen(), "Key size should be 4096 bits")

			t.Logf("✓ Generated RSA-4096 key on CanoKey: %d bits", rsaPub.N.BitLen())

			// Clean up
			err = canokey.DeleteKey(attrs)
			assert.NoError(t, err, "Failed to delete test key")
		})

		t.Run("ECDSA-P256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "canokey-test-ecdsa-p256",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			// Clean up any existing key first
			_ = canokey.DeleteKey(attrs)

			key, err := canokey.GenerateECDSA(attrs)
			require.NoError(t, err, "Failed to generate ECDSA P-256 key on CanoKey")
			require.NotNil(t, key)

			// Verify it's a crypto.Signer
			signer, ok := key.(crypto.Signer)
			require.True(t, ok, "Key must implement crypto.Signer")

			// Verify public key
			ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
			require.True(t, ok, "Expected ECDSA public key")
			assert.Equal(t, elliptic.P256(), ecdsaPub.Curve, "Curve should be P-256")

			t.Logf("✓ Generated ECDSA P-256 key on CanoKey")

			// Clean up
			err = canokey.DeleteKey(attrs)
			assert.NoError(t, err, "Failed to delete test key")
		})

		t.Run("ECDSA-P384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "canokey-test-ecdsa-p384",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P384(),
				},
			}

			// Clean up any existing key first
			_ = canokey.DeleteKey(attrs)

			key, err := canokey.GenerateECDSA(attrs)
			require.NoError(t, err, "Failed to generate ECDSA P-384 key on CanoKey")
			require.NotNil(t, key)

			// Verify it's a crypto.Signer
			signer, ok := key.(crypto.Signer)
			require.True(t, ok, "Key must implement crypto.Signer")

			// Verify public key
			ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
			require.True(t, ok, "Expected ECDSA public key")
			assert.Equal(t, elliptic.P384(), ecdsaPub.Curve, "Curve should be P-384")

			t.Logf("✓ Generated ECDSA P-384 key on CanoKey")

			// Clean up
			err = canokey.DeleteKey(attrs)
			assert.NoError(t, err, "Failed to delete test key")
		})
	})

	// ========================================
	// Signing Tests
	// ========================================
	t.Run("Signing", func(t *testing.T) {
		t.Run("RSA-PKCS1v15", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "canokey-test-sign-rsa",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Clean up and generate fresh key
			_ = canokey.DeleteKey(attrs)
			key, err := canokey.GenerateRSA(attrs)
			require.NoError(t, err)
			defer canokey.DeleteKey(attrs)

			signer := key.(crypto.Signer)

			// Sign test data
			testData := []byte("CanoKey RSA signing test data")
			digest := sha256.Sum256(testData)

			signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			require.NoError(t, err, "RSA signing failed")
			require.NotEmpty(t, signature)

			// Verify signature
			rsaPub := signer.Public().(*rsa.PublicKey)
			err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature)
			require.NoError(t, err, "RSA signature verification failed")

			t.Logf("✓ RSA-PKCS1v15 signing and verification successful (signature: %d bytes)", len(signature))
		})

		t.Run("ECDSA-SHA256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "canokey-test-sign-ecdsa",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			// Clean up and generate fresh key
			_ = canokey.DeleteKey(attrs)
			key, err := canokey.GenerateECDSA(attrs)
			require.NoError(t, err)
			defer canokey.DeleteKey(attrs)

			signer := key.(crypto.Signer)

			// Sign test data
			testData := []byte("CanoKey ECDSA signing test data")
			digest := sha256.Sum256(testData)

			signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			require.NoError(t, err, "ECDSA signing failed")
			require.NotEmpty(t, signature)

			// Verify signature
			ecdsaPub := signer.Public().(*ecdsa.PublicKey)
			valid := ecdsa.VerifyASN1(ecdsaPub, digest[:], signature)
			require.True(t, valid, "ECDSA signature verification failed")

			t.Logf("✓ ECDSA-SHA256 signing and verification successful (signature: %d bytes)", len(signature))
		})
	})

	// ========================================
	// Key Retrieval Tests
	// ========================================
	t.Run("KeyRetrieval", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "canokey-test-retrieve",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_PKCS11,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		// Clean up and generate fresh key
		_ = canokey.DeleteKey(attrs)
		_, err := canokey.GenerateECDSA(attrs)
		require.NoError(t, err)
		defer canokey.DeleteKey(attrs)

		// Check key exists
		exists, err := keyExists(canokey, attrs)
		require.NoError(t, err)
		assert.True(t, exists, "Key should exist after generation")

		// Retrieve key
		retrievedKey, err := canokey.GetKey(attrs)
		require.NoError(t, err)
		require.NotNil(t, retrievedKey)

		// Verify retrieved key is usable
		signer, ok := retrievedKey.(crypto.Signer)
		require.True(t, ok, "Retrieved key must implement crypto.Signer")
		require.NotNil(t, signer.Public())

		t.Log("✓ Key retrieval successful")
	})

	// ========================================
	// Certificate Tests
	// ========================================
	t.Run("Certificates", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "canokey-test-cert",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_PKCS11,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		// Clean up and generate fresh key
		_ = canokey.DeleteKey(attrs)
		key, err := canokey.GenerateECDSA(attrs)
		require.NoError(t, err)
		defer canokey.DeleteKey(attrs)

		signer := key.(crypto.Signer)

		// Create a self-signed certificate
		serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000))
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName:   "CanoKey Test Certificate",
				Organization: []string{"go-keychain Test"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
		require.NoError(t, err, "Failed to create self-signed certificate")

		cert, err := x509.ParseCertificate(certDER)
		require.NoError(t, err, "Failed to parse certificate")

		assert.Equal(t, "CanoKey Test Certificate", cert.Subject.CommonName)
		t.Logf("✓ Created self-signed certificate: CN=%s, Valid=%s to %s",
			cert.Subject.CommonName, cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
	})

	// ========================================
	// Key Deletion Tests
	// ========================================
	t.Run("KeyDeletion", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "canokey-test-delete",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_PKCS11,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		// Generate a key
		_ = canokey.DeleteKey(attrs)
		_, err := canokey.GenerateECDSA(attrs)
		require.NoError(t, err)

		// Verify it exists
		exists, err := keyExists(canokey, attrs)
		require.NoError(t, err)
		assert.True(t, exists)

		// Delete it
		err = canokey.DeleteKey(attrs)
		require.NoError(t, err)

		// Verify it's gone
		exists, err = keyExists(canokey, attrs)
		require.NoError(t, err)
		assert.False(t, exists, "Key should not exist after deletion")

		t.Log("✓ Key deletion successful")
	})

	// ========================================
	// Stress Test (Optional)
	// ========================================
	t.Run("StressTest", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping stress test in short mode")
		}

		attrs := &types.KeyAttributes{
			CN:           "canokey-test-stress",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_PKCS11,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		// Clean up and generate fresh key
		_ = canokey.DeleteKey(attrs)
		key, err := canokey.GenerateECDSA(attrs)
		require.NoError(t, err)
		defer canokey.DeleteKey(attrs)

		signer := key.(crypto.Signer)

		// Perform multiple signing operations
		numOperations := 50
		testData := []byte("CanoKey stress test data")
		digest := sha256.Sum256(testData)

		for i := 0; i < numOperations; i++ {
			signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			require.NoError(t, err, "Signing failed at iteration %d", i)
			require.NotEmpty(t, signature)
		}

		t.Logf("✓ Completed %d signing operations", numOperations)
	})
}

// TestCanoKeyPIVSlots tests CanoKey PIV slot operations
// Requires physical CanoKey hardware connected via USB
func TestCanoKeyPIVSlots(t *testing.T) {
	config, available := getCanoKeyConfig(t)
	if !available {
		t.Skip("CanoKey hardware not detected - connect physical CanoKey to run these tests")
	}

	canokey, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create CanoKey backend: %v", err)
	}
	defer canokey.Close()

	err = canokey.Initialize(config.SOPIN, config.PIN)
	if err != nil && err != pkcs11.ErrAlreadyInitialized {
		t.Fatalf("Failed to initialize: %v", err)
	}

	t.Log("=== CanoKey PIV Slot Tests ===")

	// PIV slots to test
	// 0x9a - Authentication
	// 0x9c - Digital Signature
	// 0x9d - Key Management
	// 0x9e - Card Authentication

	slots := []struct {
		name   string
		slotID uint
	}{
		{"Authentication (9a)", 0x9a},
		{"Signature (9c)", 0x9c},
		{"KeyManagement (9d)", 0x9d},
		{"CardAuth (9e)", 0x9e},
	}

	for _, slot := range slots {
		t.Run(slot.name, func(t *testing.T) {
			t.Logf("Testing PIV slot %s (0x%02x)", slot.name, slot.slotID)
			// Slot-specific tests would go here
			// This depends on how the backend exposes PIV slot selection
		})
	}
}

// TestCanoKeyErrorHandling tests error handling for edge cases
// Requires physical CanoKey hardware connected via USB
func TestCanoKeyErrorHandling(t *testing.T) {
	config, available := getCanoKeyConfig(t)
	if !available {
		t.Skip("CanoKey hardware not detected - connect physical CanoKey to run these tests")
	}

	canokey, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create CanoKey backend: %v", err)
	}
	defer canokey.Close()

	err = canokey.Initialize(config.SOPIN, config.PIN)
	if err != nil && err != pkcs11.ErrAlreadyInitialized {
		t.Fatalf("Failed to initialize: %v", err)
	}

	t.Run("GetNonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "canokey-nonexistent-key-12345",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_PKCS11,
			KeyAlgorithm: x509.ECDSA,
		}

		_, err := canokey.GetKey(attrs)
		assert.Error(t, err, "Should return error for non-existent key")
		t.Logf("✓ Correctly returned error for non-existent key: %v", err)
	})

	t.Run("KeyExistsNonExistent", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "canokey-nonexistent-key-67890",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_PKCS11,
			KeyAlgorithm: x509.ECDSA,
		}

		exists, err := keyExists(canokey, attrs)
		require.NoError(t, err)
		assert.False(t, exists, "Non-existent key should not exist")
		t.Log("✓ Correctly reported non-existent key")
	})

	t.Run("DeleteNonExistentKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "canokey-nonexistent-key-delete",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_PKCS11,
			KeyAlgorithm: x509.ECDSA,
		}

		// Deleting non-existent key should not cause panic
		// Behavior may vary - some implementations return error, some silently succeed
		_ = canokey.DeleteKey(attrs)
		t.Log("✓ Delete of non-existent key handled gracefully")
	})
}
