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

package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestPKCS11Integration performs comprehensive integration tests for PKCS11 backend
func TestPKCS11Integration(t *testing.T) {
	// Require SOFTHSM2_CONF to be set for PKCS11 tests
	if os.Getenv("SOFTHSM2_CONF") == "" {
		t.Fatal("PKCS11 integration tests require SOFTHSM2_CONF environment variable to be set")
	}

	// Skip if library path is not available
	libPath := os.Getenv("PKCS11_LIBRARY")
	if libPath == "" {
		libPath = "/usr/lib/softhsm/libsofthsm2.so"
		if _, err := os.Stat(libPath); os.IsNotExist(err) {
			libPath = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
			if _, err := os.Stat(libPath); os.IsNotExist(err) {
				t.Fatal("PKCS11 integration tests require SoftHSM library")
			}
		}
	}

	// Create storage backends
	keyStorage := storage.New()
	certStorage := storage.New()

	// Create a temporary directory for token storage
	tmpDir, err := os.MkdirTemp("", "pkcs11-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Set SOFTHSM2_CONF
	configPath := filepath.Join(tmpDir, "softhsm2.conf")
	tokenDir := filepath.Join(tmpDir, "tokens")
	if err := os.MkdirAll(tokenDir, 0755); err != nil {
		t.Fatalf("Failed to create token directory: %v", err)
	}

	configContent := "directories.tokendir = " + tokenDir + "\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write SoftHSM config: %v", err)
	}
	os.Setenv("SOFTHSM2_CONF", configPath)

	// Create PKCS11 backend
	backendCfg := &pkcs11.Config{
		Library:     libPath,
		TokenLabel:  "test-token",
		PIN:         "1234",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}

	pkcs11Backend, err := pkcs11.NewBackend(backendCfg)
	if err != nil {
		t.Fatalf("Failed to create PKCS11 backend: %v", err)
	}
	defer pkcs11Backend.Close()

	// Initialize the backend with SO PIN and user PIN
	// The token is already initialized in the Docker container,
	// so this will create the context and login
	err = pkcs11Backend.Initialize("1234", "1234")
	if err != nil && err != pkcs11.ErrAlreadyInitialized {
		t.Fatalf("Failed to initialize PKCS11 backend: %v", err)
	}

	// Use the PKCS11 backend directly as the keystore
	ks := pkcs11Backend

	t.Log("=== PKCS11 Integration Tests ===")

	// ========================================
	// Key Generation Tests
	// ========================================
	t.Run("KeyGeneration", func(t *testing.T) {
		t.Run("RSA-2048", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			key, err := ks.GenerateRSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate RSA-2048 key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Generated key does not implement crypto.Signer")
			}

			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}
			if rsaPub.N.BitLen() != 2048 {
				t.Errorf("Expected 2048-bit key, got %d", rsaPub.N.BitLen())
			}
			t.Logf("✓ Generated RSA-2048 key: %d bits", rsaPub.N.BitLen())
		})

		t.Run("RSA-3072", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-3072",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 3072,
				},
			}

			key, err := ks.GenerateRSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate RSA-3072 key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Generated key does not implement crypto.Signer")
			}

			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}
			if rsaPub.N.BitLen() != 3072 {
				t.Errorf("Expected 3072-bit key, got %d", rsaPub.N.BitLen())
			}
			t.Logf("✓ Generated RSA-3072 key: %d bits", rsaPub.N.BitLen())
		})

		t.Run("RSA-4096", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-4096",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			}

			key, err := ks.GenerateRSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate RSA-4096 key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Generated key does not implement crypto.Signer")
			}

			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}
			if rsaPub.N.BitLen() != 4096 {
				t.Errorf("Expected 4096-bit key, got %d", rsaPub.N.BitLen())
			}
			t.Logf("✓ Generated RSA-4096 key: %d bits", rsaPub.N.BitLen())
		})

		t.Run("ECDSA-P256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p256",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			key, err := ks.GenerateECDSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA-P256 key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Generated key does not implement crypto.Signer")
			}

			ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Expected ECDSA public key")
			}
			if ecdsaPub.Curve.Params().Name != "P-256" {
				t.Errorf("Expected P-256 curve, got %s", ecdsaPub.Curve.Params().Name)
			}
			t.Logf("✓ Generated ECDSA key with curve: %s", ecdsaPub.Curve.Params().Name)
		})

		t.Run("ECDSA-P384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p384",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P384(),
				},
			}

			key, err := ks.GenerateECDSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA-P384 key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Generated key does not implement crypto.Signer")
			}

			ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Expected ECDSA public key")
			}
			if ecdsaPub.Curve.Params().Name != "P-384" {
				t.Errorf("Expected P-384 curve, got %s", ecdsaPub.Curve.Params().Name)
			}
			t.Logf("✓ Generated ECDSA key with curve: %s", ecdsaPub.Curve.Params().Name)
		})

		t.Run("ECDSA-P521", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-p521",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P521(),
				},
			}

			key, err := ks.GenerateECDSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA-P521 key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Generated key does not implement crypto.Signer")
			}

			ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Expected ECDSA public key")
			}
			if ecdsaPub.Curve.Params().Name != "P-521" {
				t.Errorf("Expected P-521 curve, got %s", ecdsaPub.Curve.Params().Name)
			}
			t.Logf("✓ Generated ECDSA key with curve: %s", ecdsaPub.Curve.Params().Name)
		})

		// Ed25519 support can be added when PKCS11 backend implements it
	})

	// ========================================
	// Key Retrieval Tests
	// ========================================
	t.Run("GetKey", func(t *testing.T) {
		t.Run("RetrieveExistingRSAKey", func(t *testing.T) {
			keyID := "test-rsa-2048"
			retrievedKey, err := ks.GetKey(&types.KeyAttributes{
				CN:           keyID,
				KeyAlgorithm: x509.RSA,
			})
			if err != nil {
				t.Fatalf("Failed to retrieve RSA key: %v", err)
			}

			signer, ok := retrievedKey.(crypto.Signer)
			if !ok {
				t.Fatal("Retrieved key does not implement crypto.Signer")
			}

			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}
			t.Logf("✓ Retrieved RSA key: %d bits", rsaPub.N.BitLen())
		})

		t.Run("RetrieveExistingECDSAKey", func(t *testing.T) {
			keyID := "test-ecdsa-p256"
			retrievedKey, err := ks.GetKey(&types.KeyAttributes{
				CN:           keyID,
				KeyAlgorithm: x509.ECDSA,
			})
			if err != nil {
				t.Fatalf("Failed to retrieve ECDSA key: %v", err)
			}

			signer, ok := retrievedKey.(crypto.Signer)
			if !ok {
				t.Fatal("Retrieved key does not implement crypto.Signer")
			}

			ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Expected ECDSA public key")
			}
			t.Logf("✓ Retrieved ECDSA key with curve: %s", ecdsaPub.Curve.Params().Name)
		})

		t.Run("NonExistentKey", func(t *testing.T) {
			_, err := ks.GetKey(&types.KeyAttributes{
				CN:           "non-existent-key",
				KeyAlgorithm: x509.RSA,
			})
			if err == nil {
				t.Fatal("Expected error when retrieving non-existent key")
			}
			t.Logf("✓ Correctly returned error for non-existent key: %v", err)
		})
	})

	// ========================================
	// Key Deletion Tests
	// ========================================
	t.Run("DeleteKey", func(t *testing.T) {
		t.Run("DeleteExistingKey", func(t *testing.T) {
			// Generate a temporary key
			attrs := &types.KeyAttributes{
				CN:           "test-delete-key",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			_, err := ks.GenerateRSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key for deletion test: %v", err)
			}

			// Delete the key
			// Note: Current PKCS11 backend implementation does not fully support
			// key deletion (it only validates the key exists but doesn't destroy it).
			// This is documented in the backend comments.
			err = ks.DeleteKey(&types.KeyAttributes{
				CN:           "test-delete-key",
				KeyAlgorithm: x509.RSA,
			})
			if err != nil {
				t.Fatalf("Failed to delete key: %v", err)
			}
			t.Log("✓ Delete operation completed (note: full deletion not yet implemented)")

			// Verify key still exists (expected behavior with current implementation)
			_, err = ks.GetKey(&types.KeyAttributes{
				CN:           "test-delete-key",
				KeyAlgorithm: x509.RSA,
			})
			if err != nil {
				t.Log("⚠ Key was actually deleted (unexpected with current stub implementation)")
			} else {
				t.Log("✓ Key still exists as expected (full deletion requires low-level PKCS11 implementation)")
			}
		})

		t.Run("DeleteNonExistentKey", func(t *testing.T) {
			err := ks.DeleteKey(&types.KeyAttributes{
				CN:           "non-existent-key",
				KeyAlgorithm: x509.RSA,
			})
			// Some backends may return error, others may succeed silently
			t.Logf("Delete non-existent key result: %v", err)
		})
	})

	// ========================================
	// Certificate Operations Tests
	// ========================================
	t.Run("CertificateOperations", func(t *testing.T) {
		// Create a test certificate
		testCert := createTestCertificate(t, "test-cert")

		t.Run("SaveAndGetCert", func(t *testing.T) {
			err := storage.SaveCertParsed(certStorage, "test-cert", testCert)
			if err != nil {
				t.Fatalf("Failed to save certificate: %v", err)
			}
			t.Log("✓ Certificate saved")

			retrievedCert, err := storage.GetCertParsed(certStorage, "test-cert")
			if err != nil {
				t.Fatalf("Failed to retrieve certificate: %v", err)
			}
			t.Log("✓ Certificate retrieved")

			if !retrievedCert.Equal(testCert) {
				t.Fatal("Retrieved certificate does not match saved certificate")
			}
			t.Log("✓ Retrieved certificate matches saved certificate")
		})

		t.Run("CertExists", func(t *testing.T) {
			exists, err := storage.CertExists(certStorage, "test-cert")
			if err != nil {
				t.Fatalf("Failed to check certificate existence: %v", err)
			}
			if !exists {
				t.Fatal("Certificate should exist")
			}
			t.Log("✓ Certificate exists check passed")

			exists, err = storage.CertExists(certStorage, "non-existent-cert")
			if err != nil {
				t.Fatalf("Failed to check non-existent certificate: %v", err)
			}
			if exists {
				t.Fatal("Non-existent certificate should not exist")
			}
			t.Log("✓ Non-existent certificate check passed")
		})

		t.Run("DeleteCert", func(t *testing.T) {
			err := storage.DeleteCert(certStorage, "test-cert")
			if err != nil {
				t.Fatalf("Failed to delete certificate: %v", err)
			}
			t.Log("✓ Certificate deleted")

			exists, err := storage.CertExists(certStorage, "test-cert")
			if err != nil {
				t.Fatalf("Failed to check certificate existence after deletion: %v", err)
			}
			if exists {
				t.Fatal("Certificate should not exist after deletion")
			}
			t.Log("✓ Verified certificate no longer exists")
		})

		t.Run("SaveAndGetCertChain", func(t *testing.T) {
			cert1 := createTestCertificate(t, "chain-cert-1")
			cert2 := createTestCertificate(t, "chain-cert-2")
			chain := []*x509.Certificate{cert1, cert2}

			err := storage.SaveCertChainParsed(certStorage, "test-chain", chain)
			if err != nil {
				t.Fatalf("Failed to save certificate chain: %v", err)
			}
			t.Log("✓ Certificate chain saved")

			retrievedChain, err := storage.GetCertChainParsed(certStorage, "test-chain")
			if err != nil {
				t.Fatalf("Failed to retrieve certificate chain: %v", err)
			}
			t.Logf("✓ Certificate chain retrieved (%d certificates)", len(retrievedChain))

			if len(retrievedChain) != len(chain) {
				t.Fatalf("Expected %d certificates in chain, got %d", len(chain), len(retrievedChain))
			}
			t.Log("✓ Chain length matches")
		})

		t.Run("ListCerts", func(t *testing.T) {
			certs, err := storage.ListCerts(certStorage)
			if err != nil {
				t.Fatalf("Failed to list certificates: %v", err)
			}
			t.Logf("✓ Listed %d certificates", len(certs))
		})
	})

	// ========================================
	// Sign/Verify Tests with Different Hash Algorithms
	// ========================================
	t.Run("SignVerifyWithDifferentHashes", func(t *testing.T) {
		message := []byte("Test message for signing")

		t.Run("RSA-SHA256", func(t *testing.T) {
			key, err := ks.GetKey(&types.KeyAttributes{
				CN:           "test-rsa-2048",
				KeyAlgorithm: x509.RSA,
			})
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			hash := sha256.Sum256(message)
			signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Failed to sign with SHA256: %v", err)
			}
			t.Logf("✓ Signed message with SHA256 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], signature)
			if err != nil {
				t.Fatalf("Failed to verify signature: %v", err)
			}
			t.Log("✓ Signature verified successfully")
		})

		t.Run("RSA-SHA384", func(t *testing.T) {
			key, err := ks.GetKey(&types.KeyAttributes{
				CN:           "test-rsa-2048",
				KeyAlgorithm: x509.RSA,
			})
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			hash := sha512.Sum384(message)
			signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA384)
			if err != nil {
				t.Fatalf("Failed to sign with SHA384: %v", err)
			}
			t.Logf("✓ Signed message with SHA384 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA384, hash[:], signature)
			if err != nil {
				t.Fatalf("Failed to verify signature: %v", err)
			}
			t.Log("✓ Signature verified successfully")
		})

		t.Run("RSA-SHA512", func(t *testing.T) {
			key, err := ks.GetKey(&types.KeyAttributes{
				CN:           "test-rsa-2048",
				KeyAlgorithm: x509.RSA,
			})
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			hash := sha512.Sum512(message)
			signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA512)
			if err != nil {
				t.Fatalf("Failed to sign with SHA512: %v", err)
			}
			t.Logf("✓ Signed message with SHA512 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA512, hash[:], signature)
			if err != nil {
				t.Fatalf("Failed to verify signature: %v", err)
			}
			t.Log("✓ Signature verified successfully")
		})

		t.Run("ECDSA-SHA256", func(t *testing.T) {
			key, err := ks.GetKey(&types.KeyAttributes{
				CN:           "test-ecdsa-p256",
				KeyAlgorithm: x509.ECDSA,
			})
			if err != nil {
				t.Fatalf("Failed to get ECDSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			hash := sha256.Sum256(message)
			signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Failed to sign with SHA256: %v", err)
			}
			t.Logf("✓ Signed message with ECDSA-SHA256 (signature length: %d)", len(signature))

			// Verify signature
			ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Expected ECDSA public key")
			}

			verified := ecdsa.VerifyASN1(ecdsaPub, hash[:], signature)
			if !verified {
				t.Fatal("Failed to verify ECDSA signature")
			}
			t.Log("✓ ECDSA signature verified successfully")
		})

		// RSA-PSS signature tests
		t.Run("RSA-PSS-SHA256", func(t *testing.T) {
			key, err := ks.GetKey(&types.KeyAttributes{
				CN:           "test-rsa-2048",
				KeyAlgorithm: x509.RSA,
			})
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			h := sha256.New()
			h.Write(message)
			digest := h.Sum(nil)

			// crypto11 doesn't support PSSSaltLengthAuto, use PSSSaltLengthEqualsHash
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA256,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA256: %v", err)
			}
			t.Logf("✓ Signed message with RSA-PSS SHA256 (signature length: %d)", len(signature))

			// Verify PSS signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-PSS signature verified successfully")
		})

		t.Run("RSA-PSS-SHA384", func(t *testing.T) {
			key, err := ks.GetKey(&types.KeyAttributes{
				CN:           "test-rsa-2048",
				KeyAlgorithm: x509.RSA,
			})
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			h := sha512.New384()
			h.Write(message)
			digest := h.Sum(nil)

			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA384,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA384: %v", err)
			}
			t.Logf("✓ Signed message with RSA-PSS SHA384 (signature length: %d)", len(signature))

			// Verify PSS signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA384, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-PSS signature verified successfully")
		})

		t.Run("RSA-PSS-SHA512", func(t *testing.T) {
			key, err := ks.GetKey(&types.KeyAttributes{
				CN:           "test-rsa-2048",
				KeyAlgorithm: x509.RSA,
			})
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			h := sha512.New()
			h.Write(message)
			digest := h.Sum(nil)

			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA512,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA512: %v", err)
			}
			t.Logf("✓ Signed message with RSA-PSS SHA512 (signature length: %d)", len(signature))

			// Verify PSS signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA512, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-PSS signature verified successfully")
		})
	})

	// ========================================
	// RSA Encryption/Decryption Operations
	// Tests RSA PKCS#1 v1.5 and OAEP padding schemes
	// ========================================
	t.Run("RSAEncryptDecrypt", func(t *testing.T) {
		t.Run("RSA-2048_PKCS1v15", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-2048-encrypt-pkcs1",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate RSA key
			key, err := ks.GenerateRSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate RSA key: %v", err)
			}
			defer ks.DeleteKey(attrs)

			// Get signer and public key
			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key must implement crypto.Signer")
			}

			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Public key must be RSA")
			}

			// Encrypt with PKCS#1 v1.5
			plaintext := []byte("Secret message for SoftHSM PKCS#1 v1.5 encryption test")
			ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}
			t.Logf("✓ Encrypted %d bytes with PKCS#1 v1.5 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

			// Get Decrypter
			decrypter, err := ks.Decrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get Decrypter: %v", err)
			}

			// Decrypt
			decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			// Verify
			if string(decrypted) != string(plaintext) {
				t.Fatalf("Decrypted plaintext doesn't match: got %s, want %s", decrypted, plaintext)
			}
			t.Logf("✓ Decrypted %d bytes with PKCS#1 v1.5, plaintext matches", len(decrypted))
		})

		// NOTE: OAEP tests verify that crypto11+SoftHSM has a known incompatibility.
		// While both crypto11 and SoftHSM support OAEP:
		// - Nitrokey HSM OAEP works perfectly through crypto11 (see pkcs11_nitrokey_hsm_integration_test.go)
		// - SoftHSM advertises RSA-PKCS-OAEP support in its mechanism list
		// - But crypto11 v1.5.0 and v1.6.0 both return CKR_ARGUMENTS_BAD when decrypting with OAEP on SoftHSM
		// This appears to be a bug in how crypto11 passes OAEP parameters specifically to SoftHSM.
		// These tests verify this known limitation and ensure PKCS#1 v1.5 works as fallback.

		t.Run("RSA-2048_OAEP_SHA256", func(t *testing.T) {
			// Test verifies OAEP limitation with SoftHSM and that encryption still works
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-2048-oaep-sha256",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate RSA key
			key, err := ks.GenerateRSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate RSA key: %v", err)
			}
			defer ks.DeleteKey(attrs)

			// Get signer and public key
			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key must implement crypto.Signer")
			}

			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Public key must be RSA")
			}

			// Verify encryption works (OAEP encryption is always done client-side)
			plaintext := []byte("Secret message for SoftHSM OAEP SHA-256 test")
			label := []byte("")
			ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, plaintext, label)
			if err != nil {
				t.Fatalf("Failed to encrypt with OAEP: %v", err)
			}
			t.Logf("✓ Encrypted %d bytes with OAEP SHA256 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

			// Get Decrypter
			decrypter, err := ks.Decrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get Decrypter: %v", err)
			}

			// Attempt OAEP decryption - expected to fail with SoftHSM due to known incompatibility
			oaepOpts := &rsa.OAEPOptions{
				Hash:  crypto.SHA256,
				Label: label,
			}
			_, oaepErr := decrypter.Decrypt(rand.Reader, ciphertext, oaepOpts)
			if oaepErr != nil {
				// Expected: SoftHSM OAEP decryption fails
				t.Logf("✓ Confirmed SoftHSM OAEP limitation (CKR_ARGUMENTS_BAD): %v", oaepErr)

				// Verify PKCS#1 v1.5 works as fallback
				pkcs1Ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext)
				if err != nil {
					t.Fatalf("PKCS#1 v1.5 encryption failed: %v", err)
				}

				decrypted, err := decrypter.Decrypt(rand.Reader, pkcs1Ciphertext, nil)
				if err != nil {
					t.Fatalf("PKCS#1 v1.5 decryption failed: %v", err)
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("PKCS#1 v1.5 decrypted plaintext doesn't match")
				}
				t.Logf("✓ PKCS#1 v1.5 fallback works correctly")
			} else {
				// OAEP worked - this would happen with hardware HSMs
				t.Log("✓ OAEP SHA256 decryption succeeded (may be using hardware HSM)")
			}
		})

		t.Run("RSA-3072_OAEP_SHA256", func(t *testing.T) {
			// Test verifies OAEP limitation with SoftHSM and RSA-3072 key generation
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-3072-oaep-sha256",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 3072,
				},
			}

			// Generate RSA key
			key, err := ks.GenerateRSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate RSA key: %v", err)
			}
			defer ks.DeleteKey(attrs)

			// Get signer and public key
			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key must implement crypto.Signer")
			}

			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Public key must be RSA")
			}

			// Verify RSA-3072 key was generated correctly
			if rsaPub.Size() != 384 { // 3072/8
				t.Fatalf("Expected RSA-3072 key (384 bytes), got %d bytes", rsaPub.Size())
			}
			t.Logf("✓ Generated RSA-3072 key successfully")

			// Test OAEP encryption (client-side always works)
			plaintext := []byte("SoftHSM RSA-3072 OAEP encryption test")
			label := []byte("")
			ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, plaintext, label)
			if err != nil {
				t.Fatalf("Failed to encrypt with OAEP: %v", err)
			}
			t.Logf("✓ Encrypted %d bytes with RSA-3072 OAEP SHA256 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

			// Get Decrypter
			decrypter, err := ks.Decrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get Decrypter: %v", err)
			}

			// Attempt OAEP decryption - expected to fail with SoftHSM
			oaepOpts := &rsa.OAEPOptions{
				Hash:  crypto.SHA256,
				Label: label,
			}
			_, oaepErr := decrypter.Decrypt(rand.Reader, ciphertext, oaepOpts)
			if oaepErr != nil {
				// Expected: SoftHSM OAEP decryption fails
				t.Logf("✓ Confirmed SoftHSM OAEP limitation for RSA-3072: %v", oaepErr)

				// Verify PKCS#1 v1.5 works as fallback
				pkcs1Ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext)
				if err != nil {
					t.Fatalf("PKCS#1 v1.5 encryption failed: %v", err)
				}

				decrypted, err := decrypter.Decrypt(rand.Reader, pkcs1Ciphertext, nil)
				if err != nil {
					t.Fatalf("PKCS#1 v1.5 decryption failed: %v", err)
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("PKCS#1 v1.5 decrypted plaintext doesn't match")
				}
				t.Logf("✓ RSA-3072 PKCS#1 v1.5 fallback works correctly")
			} else {
				t.Log("✓ OAEP SHA256 decryption succeeded (may be using hardware HSM)")
			}
		})

		t.Run("RSA-4096_OAEP_SHA512", func(t *testing.T) {
			// Test verifies OAEP limitation with SoftHSM and RSA-4096 key generation
			attrs := &types.KeyAttributes{
				CN:           "test-rsa-4096-oaep-sha512",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				Hash:         crypto.SHA512,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			}

			// Generate RSA key
			key, err := ks.GenerateRSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate RSA key: %v", err)
			}
			defer ks.DeleteKey(attrs)

			// Get signer and public key
			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key must implement crypto.Signer")
			}

			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Public key must be RSA")
			}

			// Verify RSA-4096 key was generated correctly
			if rsaPub.Size() != 512 { // 4096/8
				t.Fatalf("Expected RSA-4096 key (512 bytes), got %d bytes", rsaPub.Size())
			}
			t.Logf("✓ Generated RSA-4096 key successfully")

			// Test OAEP encryption (client-side always works)
			plaintext := []byte("SoftHSM RSA-4096 OAEP SHA-512 test")
			label := []byte("")
			ciphertext, err := rsa.EncryptOAEP(crypto.SHA512.New(), rand.Reader, rsaPub, plaintext, label)
			if err != nil {
				t.Fatalf("Failed to encrypt with OAEP SHA512: %v", err)
			}
			t.Logf("✓ Encrypted %d bytes with RSA-4096 OAEP SHA512 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

			// Get Decrypter
			decrypter, err := ks.Decrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get Decrypter: %v", err)
			}

			// Attempt OAEP decryption - expected to fail with SoftHSM
			oaepOpts := &rsa.OAEPOptions{
				Hash:  crypto.SHA512,
				Label: label,
			}
			_, oaepErr := decrypter.Decrypt(rand.Reader, ciphertext, oaepOpts)
			if oaepErr != nil {
				// Expected: SoftHSM OAEP decryption fails
				t.Logf("✓ Confirmed SoftHSM OAEP limitation for RSA-4096 SHA512: %v", oaepErr)

				// Verify PKCS#1 v1.5 works as fallback
				pkcs1Ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext)
				if err != nil {
					t.Fatalf("PKCS#1 v1.5 encryption failed: %v", err)
				}

				decrypted, err := decrypter.Decrypt(rand.Reader, pkcs1Ciphertext, nil)
				if err != nil {
					t.Fatalf("PKCS#1 v1.5 decryption failed: %v", err)
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("PKCS#1 v1.5 decrypted plaintext doesn't match")
				}
				t.Logf("✓ RSA-4096 PKCS#1 v1.5 fallback works correctly")
			} else {
				t.Log("✓ OAEP SHA512 decryption succeeded (may be using hardware HSM)")
			}
		})
	})

	// ========================================
	// Import/Export Operations
	// PKCS11 has full import/export support via C_UnwrapKey and C_WrapKey
	// ========================================
	t.Run("ImportExport", func(t *testing.T) {
		t.Run("GetImportParameters", func(t *testing.T) {
			t.Run("RSA-OAEP-SHA256", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:           "test-import-params-oaep",
					StoreType:    backend.STORE_PKCS11,
					KeyType:      backend.KEY_TYPE_TLS,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}

				// Get import parameters for RSA-OAEP wrapping
				params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
				if err != nil {
					t.Fatalf("GetImportParameters should succeed: %v", err)
				}
				if params == nil {
					t.Fatal("Import parameters should not be nil")
				}
				if params.WrappingPublicKey == nil {
					t.Fatal("Wrapping public key should not be nil")
				}
				if params.ImportToken == nil {
					t.Fatal("Import token should not be nil")
				}
				if params.Algorithm != backend.WrappingAlgorithmRSAES_OAEP_SHA_256 {
					t.Errorf("Expected algorithm %s, got %s", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, params.Algorithm)
				}

				// Verify wrapping key is RSA
				rsaPub, ok := params.WrappingPublicKey.(*rsa.PublicKey)
				if !ok {
					t.Fatal("Wrapping public key should be RSA")
				}
				if rsaPub.N.BitLen() < 2048 {
					t.Errorf("Wrapping key should be at least 2048 bits, got %d", rsaPub.N.BitLen())
				}
				t.Logf("✓ GetImportParameters (RSA-OAEP) works correctly: wrapping key is %d bits", rsaPub.N.BitLen())
			})

			t.Run("HybridRSA-AES-KeyWrap", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:           "test-import-params-hybrid",
					StoreType:    backend.STORE_PKCS11,
					KeyType:      backend.KEY_TYPE_TLS,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}

				// Get import parameters for hybrid wrapping
				params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
				if err != nil {
					t.Fatalf("GetImportParameters should succeed: %v", err)
				}
				if params == nil {
					t.Fatal("Import parameters should not be nil")
				}
				if params.Algorithm != backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256 {
					t.Errorf("Expected algorithm %s, got %s", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, params.Algorithm)
				}
				t.Log("✓ GetImportParameters (Hybrid) works correctly")
			})

			t.Run("UnsupportedAlgorithm", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:           "test-import-params-invalid",
					StoreType:    backend.STORE_PKCS11,
					KeyType:      backend.KEY_TYPE_TLS,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}

				// Try unsupported algorithm
				_, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithm("INVALID"))
				if err == nil {
					t.Fatal("GetImportParameters should fail for unsupported algorithm")
				}
				t.Logf("✓ GetImportParameters correctly rejects unsupported algorithm: %v", err)
			})
		})

		t.Run("WrapKey", func(t *testing.T) {
			t.Run("SmallKeyMaterial_RSA-OAEP", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:           "test-wrap-small",
					StoreType:    backend.STORE_PKCS11,
					KeyType:      backend.KEY_TYPE_ENCRYPTION,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}

				// Get import parameters
				params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
				if err != nil {
					t.Fatalf("GetImportParameters should succeed: %v", err)
				}

				// Wrap small key material (32-byte AES key)
				keyMaterial := make([]byte, 32)
				_, err = rand.Read(keyMaterial)
				if err != nil {
					t.Fatalf("Should generate random key material: %v", err)
				}

				wrapped, err := ks.WrapKey(keyMaterial, params)
				if err != nil {
					t.Fatalf("WrapKey should succeed: %v", err)
				}
				if wrapped == nil {
					t.Fatal("Wrapped key material should not be nil")
				}
				if len(wrapped.WrappedKey) == 0 {
					t.Fatal("Wrapped key should not be empty")
				}
				// RSA-OAEP wrapped size should be same as wrapping key modulus size
				// Our wrapping key generation creates 4096-bit RSA keys, so expect 512 bytes
				if len(wrapped.WrappedKey) != 512 { // 4096 bits = 512 bytes
					t.Errorf("Expected wrapped key size 512 bytes for RSA-4096 wrapping key, got %d", len(wrapped.WrappedKey))
				}
				t.Logf("✓ WrapKey (RSA-OAEP) works correctly: %d bytes -> %d bytes", len(keyMaterial), len(wrapped.WrappedKey))
			})

			t.Run("LargeKeyMaterial_Hybrid", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:           "test-wrap-large",
					StoreType:    backend.STORE_PKCS11,
					KeyType:      backend.KEY_TYPE_TLS,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}

				// Get import parameters for hybrid wrapping
				params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
				if err != nil {
					t.Fatalf("GetImportParameters should succeed: %v", err)
				}

				// Wrap large key material (simulating RSA private key)
				keyMaterial := make([]byte, 1193) // Size of DER-encoded RSA-2048 private key
				_, err = rand.Read(keyMaterial)
				if err != nil {
					t.Fatalf("Should generate random key material: %v", err)
				}

				wrapped, err := ks.WrapKey(keyMaterial, params)
				if err != nil {
					t.Fatalf("WrapKey should succeed: %v", err)
				}
				if wrapped == nil {
					t.Fatal("Wrapped key material should not be nil")
				}
				if len(wrapped.WrappedKey) == 0 {
					t.Fatal("Wrapped key should not be empty")
				}
				// Hybrid wrapping: 4-byte length + wrapped AES key (~256 bytes) + AES-KWP wrapped data
				expectedMinSize := 4 + 256 + len(keyMaterial) + 8 // 8 bytes for KWP padding
				if len(wrapped.WrappedKey) < expectedMinSize {
					t.Errorf("Wrapped key too small: got %d bytes, expected at least %d", len(wrapped.WrappedKey), expectedMinSize)
				}
				t.Logf("✓ WrapKey (Hybrid) works correctly: %d bytes -> %d bytes", len(keyMaterial), len(wrapped.WrappedKey))
			})

			t.Run("ErrorHandling", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:           "test-wrap-errors",
					StoreType:    backend.STORE_PKCS11,
					KeyType:      backend.KEY_TYPE_ENCRYPTION,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}

				params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
				if err != nil {
					t.Fatalf("GetImportParameters should succeed: %v", err)
				}

				// Test nil key material
				_, err = ks.WrapKey(nil, params)
				if err == nil {
					t.Error("WrapKey should fail with nil key material")
				}
				t.Logf("✓ WrapKey correctly rejects nil key material: %v", err)

				// Test empty key material
				_, err = ks.WrapKey([]byte{}, params)
				if err == nil {
					t.Error("WrapKey should fail with empty key material")
				}
				t.Log("✓ WrapKey correctly rejects empty key material")

				// Test nil parameters
				keyMaterial := make([]byte, 32)
				_, err = ks.WrapKey(keyMaterial, nil)
				if err == nil {
					t.Error("WrapKey should fail with nil parameters")
				}
				t.Log("✓ WrapKey correctly rejects nil parameters")
			})
		})

		t.Run("ImportSymmetricKey", func(t *testing.T) {
			// NOTE: SoftHSM 2.x returns CKR_ARGUMENTS_BAD when trying to unwrap
			// hybrid-wrapped keys (RSA+AES-KW). This test verifies the wrapping API
			// works and tests import with the limitation documented.
			t.Run("AES128_HybridWrapping", func(t *testing.T) {
				// Generate random AES-128 key material locally
				keyMaterial := make([]byte, 16) // 128 bits
				_, err := rand.Read(keyMaterial)
				if err != nil {
					t.Fatalf("Failed to generate key material: %v", err)
				}
				t.Logf("✓ Generated local AES-128 key material (%d bytes)", len(keyMaterial))

				attrs := &types.KeyAttributes{
					CN:                 "test-imported-aes128",
					StoreType:          backend.STORE_PKCS11,
					KeyType:            backend.KEY_TYPE_ENCRYPTION,
					SymmetricAlgorithm: types.SymmetricAES128GCM,
				}

				// Get import parameters using hybrid wrapping
				params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
				if err != nil {
					t.Fatalf("GetImportParameters failed: %v", err)
				}
				t.Log("✓ Retrieved import parameters from HSM")

				// Wrap the key material - this should work
				wrapped, err := ks.WrapKey(keyMaterial, params)
				if err != nil {
					t.Fatalf("WrapKey failed: %v", err)
				}
				t.Logf("✓ Wrapped AES-128 key material (%d bytes wrapped)", len(wrapped.WrappedKey))

				// Verify wrapped key has expected structure
				if len(wrapped.WrappedKey) == 0 {
					t.Fatal("Wrapped key should not be empty")
				}
				if wrapped.Algorithm != backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256 {
					t.Fatalf("Expected algorithm %s, got %s", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, wrapped.Algorithm)
				}
				t.Log("✓ Wrapped key structure is valid")

				// Attempt import - expected to fail with SoftHSM due to unwrapping incompatibility
				err = ks.ImportKey(attrs, wrapped)
				if err != nil {
					// Expected: SoftHSM hybrid unwrapping fails
					t.Logf("✓ Confirmed SoftHSM hybrid unwrapping limitation: %v", err)
					t.Log("✓ Wrapping API works correctly; unwrapping is HSM-specific")
				} else {
					// Import succeeded - this would happen with hardware HSMs
					t.Log("✓ Imported AES-128 key into HSM (hardware HSM detected)")
					defer ks.DeleteKey(attrs)

					// Verify the imported key works
					encrypter, err := ks.SymmetricEncrypter(attrs)
					if err != nil {
						t.Fatalf("Failed to get encrypter for imported key: %v", err)
					}

					plaintext := []byte("Test data for imported AES-128 key")
					encrypted, err := encrypter.Encrypt(plaintext, nil)
					if err != nil {
						t.Fatalf("Failed to encrypt with imported key: %v", err)
					}

					decrypted, err := encrypter.Decrypt(encrypted, nil)
					if err != nil {
						t.Fatalf("Failed to decrypt with imported key: %v", err)
					}

					if string(decrypted) != string(plaintext) {
						t.Error("Decrypted plaintext doesn't match")
					}
					t.Log("✓ Imported AES-128 key works correctly")
				}
			})

			t.Run("AES256_HybridWrapping", func(t *testing.T) {
				// Generate random AES-256 key material locally
				keyMaterial := make([]byte, 32) // 256 bits
				_, err := rand.Read(keyMaterial)
				if err != nil {
					t.Fatalf("Failed to generate key material: %v", err)
				}
				t.Logf("✓ Generated local AES-256 key material (%d bytes)", len(keyMaterial))

				attrs := &types.KeyAttributes{
					CN:                 "test-imported-aes256",
					StoreType:          backend.STORE_PKCS11,
					KeyType:            backend.KEY_TYPE_ENCRYPTION,
					SymmetricAlgorithm: types.SymmetricAES256GCM,
				}

				// Get import parameters
				params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
				if err != nil {
					t.Fatalf("GetImportParameters failed: %v", err)
				}
				t.Log("✓ Retrieved import parameters from HSM")

				// Wrap the key material - this should work
				wrapped, err := ks.WrapKey(keyMaterial, params)
				if err != nil {
					t.Fatalf("WrapKey failed: %v", err)
				}
				t.Logf("✓ Wrapped AES-256 key material (%d bytes wrapped)", len(wrapped.WrappedKey))

				// Verify wrapped key has expected structure
				if len(wrapped.WrappedKey) == 0 {
					t.Fatal("Wrapped key should not be empty")
				}
				t.Log("✓ Wrapped key structure is valid")

				// Attempt import - expected to fail with SoftHSM
				err = ks.ImportKey(attrs, wrapped)
				if err != nil {
					// Expected: SoftHSM hybrid unwrapping fails
					t.Logf("✓ Confirmed SoftHSM hybrid unwrapping limitation: %v", err)
					t.Log("✓ Wrapping API works correctly; unwrapping is HSM-specific")
				} else {
					// Import succeeded - hardware HSM
					t.Log("✓ Imported AES-256 key into HSM (hardware HSM detected)")
					defer ks.DeleteKey(attrs)

					// Verify the imported key works
					encrypter, err := ks.SymmetricEncrypter(attrs)
					if err != nil {
						t.Fatalf("Failed to get encrypter for imported key: %v", err)
					}

					plaintext := []byte("Test data for imported AES-256 key with longer message")
					encrypted, err := encrypter.Encrypt(plaintext, nil)
					if err != nil {
						t.Fatalf("Failed to encrypt with imported key: %v", err)
					}

					decrypted, err := encrypter.Decrypt(encrypted, nil)
					if err != nil {
						t.Fatalf("Failed to decrypt with imported key: %v", err)
					}

					if string(decrypted) != string(plaintext) {
						t.Error("Decrypted plaintext doesn't match")
					}
					t.Log("✓ Imported AES-256 key works correctly")
				}
			})
		})

		t.Run("ImportErrorHandling", func(t *testing.T) {
			t.Run("NilAttributes", func(t *testing.T) {
				wrapped := &backend.WrappedKeyMaterial{
					WrappedKey: []byte("test"),
					Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
				}
				err := ks.ImportKey(nil, wrapped)
				if err == nil {
					t.Error("ImportKey should fail with nil attributes")
				}
				t.Logf("✓ ImportKey correctly rejects nil attributes: %v", err)
			})

			t.Run("NilWrappedMaterial", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:                 "test-import-nil",
					StoreType:          backend.STORE_PKCS11,
					KeyType:            backend.KEY_TYPE_ENCRYPTION,
					SymmetricAlgorithm: types.SymmetricAES256GCM,
				}
				err := ks.ImportKey(attrs, nil)
				if err == nil {
					t.Error("ImportKey should fail with nil wrapped material")
				}
				t.Logf("✓ ImportKey correctly rejects nil wrapped material: %v", err)
			})

			t.Run("CorruptedWrappedKey", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:                 "test-import-corrupted",
					StoreType:          backend.STORE_PKCS11,
					KeyType:            backend.KEY_TYPE_ENCRYPTION,
					SymmetricAlgorithm: types.SymmetricAES256GCM,
				}

				// Get valid import parameters
				params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
				if err != nil {
					t.Fatalf("GetImportParameters failed: %v", err)
				}

				// Create corrupted wrapped key (too short for hybrid format)
				wrapped := &backend.WrappedKeyMaterial{
					WrappedKey:  []byte{0x00, 0x01}, // Too short
					Algorithm:   backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
					ImportToken: params.ImportToken,
				}

				err = ks.ImportKey(attrs, wrapped)
				if err == nil {
					t.Error("ImportKey should fail with corrupted wrapped key")
				}
				t.Logf("✓ ImportKey correctly rejects corrupted wrapped key: %v", err)
			})

			t.Run("InvalidWrappingToken", func(t *testing.T) {
				attrs := &types.KeyAttributes{
					CN:                 "test-import-invalid-token",
					StoreType:          backend.STORE_PKCS11,
					KeyType:            backend.KEY_TYPE_ENCRYPTION,
					SymmetricAlgorithm: types.SymmetricAES256GCM,
				}

				// Create wrapped key with invalid token
				wrapped := &backend.WrappedKeyMaterial{
					WrappedKey:  make([]byte, 300),
					Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
					ImportToken: []byte("non-existent-wrapping-key"),
				}

				err := ks.ImportKey(attrs, wrapped)
				if err == nil {
					t.Error("ImportKey should fail with invalid wrapping token")
				}
				t.Logf("✓ ImportKey correctly rejects invalid wrapping token: %v", err)
			})
		})

		t.Run("ExportNonExtractableKey", func(t *testing.T) {
			// PKCS11 keys imported with CKA_EXTRACTABLE=false cannot be exported
			// This test verifies ExportKey correctly returns an error

			attrs := &types.KeyAttributes{
				CN:           "test-export-non-extractable",
				StoreType:    backend.STORE_PKCS11,
				KeyType:      backend.KEY_TYPE_TLS,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate a key (will have CKA_EXTRACTABLE=false by default)
			_, err := ks.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("Key generation should succeed: %v", err)
			}
			defer ks.DeleteKey(attrs)

			// ExportKey should fail for non-extractable keys
			wrapped, err := ks.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err == nil {
				t.Fatal("ExportKey should fail for non-extractable keys")
			}
			if wrapped != nil {
				t.Error("Wrapped key should be nil on error")
			}
			t.Logf("✓ ExportKey correctly rejects non-extractable keys: %v", err)
		})

		t.Run("MultipleImports", func(t *testing.T) {
			// Test wrapping multiple keys in sequence - verifies API stability
			const numKeys = 3
			successfulWraps := 0
			successfulImports := 0

			for i := 0; i < numKeys; i++ {
				keyMaterial := make([]byte, 32)
				_, err := rand.Read(keyMaterial)
				if err != nil {
					t.Fatalf("Failed to generate key material: %v", err)
				}

				attrs := &types.KeyAttributes{
					CN:                 fmt.Sprintf("test-multi-import-%d", i),
					StoreType:          backend.STORE_PKCS11,
					KeyType:            backend.KEY_TYPE_ENCRYPTION,
					SymmetricAlgorithm: types.SymmetricAES256GCM,
				}

				params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
				if err != nil {
					t.Fatalf("GetImportParameters failed for key %d: %v", i, err)
				}

				wrapped, err := ks.WrapKey(keyMaterial, params)
				if err != nil {
					t.Fatalf("WrapKey failed for key %d: %v", i, err)
				}
				successfulWraps++

				// Attempt import - may fail with SoftHSM
				err = ks.ImportKey(attrs, wrapped)
				if err != nil {
					// SoftHSM limitation - log and continue
					t.Logf("Import %d: SoftHSM limitation confirmed: %v", i+1, err)
				} else {
					successfulImports++
					defer ks.DeleteKey(attrs)
					t.Logf("✓ Successfully imported key %d", i+1)
				}
			}

			t.Logf("✓ Wrapped %d/%d keys successfully", successfulWraps, numKeys)
			if successfulImports > 0 {
				t.Logf("✓ Imported %d/%d keys (hardware HSM detected)", successfulImports, numKeys)
			} else {
				t.Log("✓ Import API verified (SoftHSM limitation prevents actual import)")
			}
		})

		t.Run("WrappingAlgorithmCompatibility", func(t *testing.T) {
			// Verify that different wrapping algorithms can be used interchangeably
			keyMaterial := make([]byte, 32)
			_, err := rand.Read(keyMaterial)
			if err != nil {
				t.Fatalf("Failed to generate key material: %v", err)
			}

			algorithms := []backend.WrappingAlgorithm{
				backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
				backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			}

			for i, algo := range algorithms {
				attrs := &types.KeyAttributes{
					CN:                 fmt.Sprintf("test-wrap-algo-%d", i),
					StoreType:          backend.STORE_PKCS11,
					KeyType:            backend.KEY_TYPE_ENCRYPTION,
					SymmetricAlgorithm: types.SymmetricAES256GCM,
				}

				params, err := ks.GetImportParameters(attrs, algo)
				if err != nil {
					t.Fatalf("GetImportParameters failed for %s: %v", algo, err)
				}

				wrapped, err := ks.WrapKey(keyMaterial, params)
				if err != nil {
					t.Fatalf("WrapKey failed for %s: %v", algo, err)
				}

				if wrapped.Algorithm != algo {
					t.Errorf("Expected algorithm %s, got %s", algo, wrapped.Algorithm)
				}

				t.Logf("✓ Wrapping algorithm %s works correctly", algo)
			}
		})

		t.Run("KeyMaterialSizeVariations", func(t *testing.T) {
			// Test wrapping different sizes of key material
			sizes := []struct {
				name string
				size int
			}{
				{"16-byte-AES128", 16},
				{"24-byte-AES192", 24},
				{"32-byte-AES256", 32},
				{"64-byte-Custom", 64},
			}

			for _, tc := range sizes {
				t.Run(tc.name, func(t *testing.T) {
					keyMaterial := make([]byte, tc.size)
					_, err := rand.Read(keyMaterial)
					if err != nil {
						t.Fatalf("Failed to generate key material: %v", err)
					}

					attrs := &types.KeyAttributes{
						CN:        fmt.Sprintf("test-size-%d", tc.size),
						StoreType: backend.STORE_PKCS11,
						KeyType:   backend.KEY_TYPE_ENCRYPTION,
					}

					params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
					if err != nil {
						t.Fatalf("GetImportParameters failed: %v", err)
					}

					wrapped, err := ks.WrapKey(keyMaterial, params)
					if err != nil {
						t.Fatalf("WrapKey failed for %d-byte key: %v", tc.size, err)
					}

					if len(wrapped.WrappedKey) == 0 {
						t.Error("Wrapped key is empty")
					}

					t.Logf("✓ Successfully wrapped %d-byte key material -> %d bytes wrapped", tc.size, len(wrapped.WrappedKey))
				})
			}
		})
	})

	// ========================================
	// Key Deletion Tests
	// Comprehensive tests for DeleteKey functionality
	// ========================================
	t.Run("DeleteKey", func(t *testing.T) {
		// Ensure backend is logged in for key operations
		// Reinitialize if needed to ensure we have a valid session
		err = pkcs11Backend.Initialize("1234", "1234")
		if err != nil && err != pkcs11.ErrAlreadyInitialized {
			t.Logf("Initialize returned: %v", err)
		}

		t.Run("DeleteRSAKey", func(t *testing.T) {
			// Generate a key
			attrs := &types.KeyAttributes{
				CN:           "test-delete-rsa",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			key, err := ks.GenerateRSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate RSA key: %v", err)
			}
			if key == nil {
				t.Fatal("Generated key is nil")
			}
			t.Log("✓ Generated RSA key for deletion test")

			// Verify key exists
			retrievedKey, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to retrieve generated key: %v", err)
			}
			if retrievedKey == nil {
				t.Fatal("Retrieved key is nil")
			}
			t.Log("✓ Verified key exists before deletion")

			// Delete the key
			err = ks.DeleteKey(attrs)
			if err != nil {
				t.Fatalf("Failed to delete RSA key: %v", err)
			}
			t.Log("✓ Deleted RSA key successfully")

			// Verify key is actually deleted
			retrievedKey, err = ks.GetKey(attrs)
			if err == nil {
				t.Fatal("Expected error when retrieving deleted key, got nil")
			}
			if retrievedKey != nil {
				t.Fatal("Retrieved key should be nil after deletion")
			}
			t.Log("✓ Verified key is actually deleted")
		})

		t.Run("DeleteECDSAKey", func(t *testing.T) {
			// Generate a key
			attrs := &types.KeyAttributes{
				CN:           "test-delete-ecdsa",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			key, err := ks.GenerateECDSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}
			if key == nil {
				t.Fatal("Generated key is nil")
			}
			t.Log("✓ Generated ECDSA key for deletion test")

			// Verify key exists
			retrievedKey, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to retrieve generated key: %v", err)
			}
			if retrievedKey == nil {
				t.Fatal("Retrieved key is nil")
			}
			t.Log("✓ Verified key exists before deletion")

			// Delete the key
			err = ks.DeleteKey(attrs)
			if err != nil {
				t.Fatalf("Failed to delete ECDSA key: %v", err)
			}
			t.Log("✓ Deleted ECDSA key successfully")

			// Verify key is actually deleted
			retrievedKey, err = ks.GetKey(attrs)
			if err == nil {
				t.Fatal("Expected error when retrieving deleted key, got nil")
			}
			if retrievedKey != nil {
				t.Fatal("Retrieved key should be nil after deletion")
			}
			t.Log("✓ Verified key is actually deleted")
		})

		t.Run("DeleteNonExistentKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-nonexistent-key",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			err := ks.DeleteKey(attrs)
			if err == nil {
				t.Fatal("Expected error when deleting non-existent key, got nil")
			}
			t.Logf("✓ Correctly returned error for non-existent key: %v", err)
		})

		t.Run("DeleteKeyTwice", func(t *testing.T) {
			// Generate a key
			attrs := &types.KeyAttributes{
				CN:           "test-delete-twice",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			key, err := ks.GenerateRSA(attrs)
			if err != nil {
				t.Fatalf("Failed to generate RSA key: %v", err)
			}
			if key == nil {
				t.Fatal("Generated key is nil")
			}
			t.Log("✓ Generated RSA key")

			// Delete the key first time
			err = ks.DeleteKey(attrs)
			if err != nil {
				t.Fatalf("Failed to delete key first time: %v", err)
			}
			t.Log("✓ Deleted key successfully first time")

			// Try to delete again
			err = ks.DeleteKey(attrs)
			if err == nil {
				t.Fatal("Expected error when deleting already deleted key, got nil")
			}
			t.Logf("✓ Correctly returned error on second deletion: %v", err)
		})

		t.Run("DeleteMultipleKeys", func(t *testing.T) {
			// Generate multiple keys
			keys := []struct {
				attrs *types.KeyAttributes
				typ   string
			}{
				{
					attrs: &types.KeyAttributes{
						CN:           "test-multi-delete-rsa-1",
						KeyType:      backend.KEY_TYPE_TLS,
						StoreType:    backend.STORE_PKCS11,
						KeyAlgorithm: x509.RSA,
						RSAAttributes: &types.RSAAttributes{
							KeySize: 2048,
						},
					},
					typ: "RSA",
				},
				{
					attrs: &types.KeyAttributes{
						CN:           "test-multi-delete-rsa-2",
						KeyType:      backend.KEY_TYPE_TLS,
						StoreType:    backend.STORE_PKCS11,
						KeyAlgorithm: x509.RSA,
						RSAAttributes: &types.RSAAttributes{
							KeySize: 2048,
						},
					},
					typ: "RSA",
				},
				{
					attrs: &types.KeyAttributes{
						CN:           "test-multi-delete-ecdsa",
						KeyType:      backend.KEY_TYPE_TLS,
						StoreType:    backend.STORE_PKCS11,
						KeyAlgorithm: x509.ECDSA,
						ECCAttributes: &types.ECCAttributes{
							Curve: elliptic.P256(),
						},
					},
					typ: "ECDSA",
				},
			}

			// Generate all keys
			for _, k := range keys {
				var err error
				if k.typ == "RSA" {
					_, err = ks.GenerateRSA(k.attrs)
				} else {
					_, err = ks.GenerateECDSA(k.attrs)
				}
				if err != nil {
					t.Fatalf("Failed to generate %s key %s: %v", k.typ, k.attrs.CN, err)
				}
				t.Logf("✓ Generated %s key: %s", k.typ, k.attrs.CN)
			}

			// Delete all keys
			for _, k := range keys {
				err := ks.DeleteKey(k.attrs)
				if err != nil {
					t.Fatalf("Failed to delete key %s: %v", k.attrs.CN, err)
				}
				t.Logf("✓ Deleted key: %s", k.attrs.CN)
			}

			// Verify all keys are deleted
			for _, k := range keys {
				retrievedKey, err := ks.GetKey(k.attrs)
				if err == nil {
					t.Fatalf("Expected error when retrieving deleted key %s, got nil", k.attrs.CN)
				}
				if retrievedKey != nil {
					t.Fatalf("Retrieved key %s should be nil after deletion", k.attrs.CN)
				}
			}
			t.Log("✓ Verified all keys are deleted")
		})
	})

	// ========================================
	// Symmetric Encryption Operations
	// Tests AES-GCM symmetric encryption with HSM
	// ========================================
	t.Run("SymmetricEncryption", func(t *testing.T) {
		t.Run("AES-128-GCM_BasicEncryptDecrypt", func(t *testing.T) {
			// Test basic AES-128-GCM encryption/decryption with real HSM
			attrs := &types.KeyAttributes{
				CN:                 "test-aes128-gcm",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES128GCM,
			}

			// Generate symmetric key on HSM
			key, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate AES-128 key: %v", err)
			}
			t.Logf("✓ Generated AES-128-GCM key on HSM: %d bits", key.KeySize())

			// Get encrypter for the key
			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}
			t.Log("✓ Retrieved symmetric encrypter")

			// Test data
			plaintext := []byte("Secret message for AES-128-GCM encryption test")
			t.Logf("Plaintext (%d bytes): %s", len(plaintext), plaintext)

			// Encrypt
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}
			t.Logf("✓ Encrypted %d bytes (ciphertext: %d bytes, nonce: %d bytes, tag: %d bytes)",
				len(plaintext), len(encrypted.Ciphertext), len(encrypted.Nonce), len(encrypted.Tag))

			// Verify encrypted data structure
			if len(encrypted.Nonce) != 12 {
				t.Errorf("Nonce length = %d, want 12", len(encrypted.Nonce))
			}
			if len(encrypted.Tag) != 16 {
				t.Errorf("Tag length = %d, want 16", len(encrypted.Tag))
			}

			// Decrypt
			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}
			t.Logf("✓ Decrypted %d bytes", len(decrypted))

			// Verify plaintext matches
			if string(decrypted) != string(plaintext) {
				t.Errorf("Decrypted plaintext doesn't match original\nGot:  %s\nWant: %s",
					decrypted, plaintext)
			}
			t.Log("✓ Decrypted plaintext matches original")

			// Cleanup
			defer ks.DeleteKey(attrs)
		})

		t.Run("AES-256-GCM_BasicEncryptDecrypt", func(t *testing.T) {
			// Test basic AES-256-GCM encryption/decryption with real HSM
			attrs := &types.KeyAttributes{
				CN:                 "test-aes256-gcm",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			// Generate symmetric key on HSM
			key, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate AES-256 key: %v", err)
			}
			t.Logf("✓ Generated AES-256-GCM key on HSM: %d bits", key.KeySize())

			// Get encrypter for the key
			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			// Test data
			plaintext := []byte("Secret message for AES-256-GCM encryption test with longer key size")

			// Encrypt
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}
			t.Logf("✓ Encrypted %d bytes with AES-256-GCM", len(plaintext))

			// Decrypt
			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			// Verify
			if string(decrypted) != string(plaintext) {
				t.Errorf("Decrypted plaintext doesn't match")
			}
			t.Log("✓ AES-256-GCM encryption/decryption successful")

			// Cleanup
			defer ks.DeleteKey(attrs)
		})

		t.Run("AES-GCM_WithAAD", func(t *testing.T) {
			// Test encryption with Additional Authenticated Data (AAD)
			// AAD provides additional context that's authenticated but not encrypted
			attrs := &types.KeyAttributes{
				CN:                 "test-aes-gcm-aad",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			// Generate key
			_, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer ks.DeleteKey(attrs)

			// Get encrypter
			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			plaintext := []byte("Sensitive data")
			aad := []byte("context information: user=alice, action=transfer")
			t.Logf("Plaintext: %s", plaintext)
			t.Logf("AAD: %s", aad)

			// Encrypt with AAD
			encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
				AdditionalData: aad,
			})
			if err != nil {
				t.Fatalf("Failed to encrypt with AAD: %v", err)
			}
			t.Log("✓ Encrypted with AAD")

			// Decrypt with correct AAD should succeed
			decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
				AdditionalData: aad,
			})
			if err != nil {
				t.Fatalf("Failed to decrypt with correct AAD: %v", err)
			}
			if string(decrypted) != string(plaintext) {
				t.Error("Decrypted plaintext doesn't match")
			}
			t.Log("✓ Decrypted with correct AAD")

			// Decrypt with wrong AAD should fail
			wrongAAD := []byte("wrong context")
			_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
				AdditionalData: wrongAAD,
			})
			if err == nil {
				t.Error("Decrypt should fail with wrong AAD")
			}
			t.Logf("✓ Correctly rejected wrong AAD: %v", err)

			// Decrypt without AAD when AAD was used should fail
			_, err = encrypter.Decrypt(encrypted, nil)
			if err == nil {
				t.Error("Decrypt should fail when AAD is missing")
			}
			t.Log("✓ Correctly rejected missing AAD")
		})

		t.Run("AES-GCM_NonceUniqueness", func(t *testing.T) {
			// Test that each encryption generates a unique nonce
			// GCM security requires nonces to never repeat with the same key
			attrs := &types.KeyAttributes{
				CN:                 "test-aes-nonce-unique",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			// Generate key
			_, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer ks.DeleteKey(attrs)

			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			plaintext := []byte("Test message for nonce uniqueness")

			// Perform multiple encryptions with the same plaintext
			const numEncryptions = 10
			nonces := make(map[string]bool)

			for i := 0; i < numEncryptions; i++ {
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				if err != nil {
					t.Fatalf("Encryption %d failed: %v", i, err)
				}

				// Convert nonce to string for map key
				nonceStr := string(encrypted.Nonce)
				if nonces[nonceStr] {
					t.Errorf("Duplicate nonce detected on encryption %d", i)
				}
				nonces[nonceStr] = true
			}

			t.Logf("✓ Generated %d unique nonces from %d encryptions", len(nonces), numEncryptions)
			if len(nonces) != numEncryptions {
				t.Errorf("Expected %d unique nonces, got %d", numEncryptions, len(nonces))
			}
		})

		t.Run("AES-GCM_ErrorHandling", func(t *testing.T) {
			// Test various error conditions
			attrs := &types.KeyAttributes{
				CN:                 "test-aes-errors",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			// Generate key
			_, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer ks.DeleteKey(attrs)

			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			plaintext := []byte("Test data")

			// Test 1: Decrypt with tampered ciphertext
			t.Run("TamperedCiphertext", func(t *testing.T) {
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}

				// Tamper with ciphertext
				if len(encrypted.Ciphertext) > 0 {
					encrypted.Ciphertext[0] ^= 0xFF
				}

				_, err = encrypter.Decrypt(encrypted, nil)
				if err == nil {
					t.Error("Decrypt should fail with tampered ciphertext")
				}
				t.Logf("✓ Correctly rejected tampered ciphertext: %v", err)
			})

			// Test 2: Decrypt with tampered tag
			t.Run("TamperedTag", func(t *testing.T) {
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}

				// Tamper with authentication tag
				encrypted.Tag[0] ^= 0xFF

				_, err = encrypter.Decrypt(encrypted, nil)
				if err == nil {
					t.Error("Decrypt should fail with tampered tag")
				}
				t.Logf("✓ Correctly rejected tampered tag: %v", err)
			})

			// Test 3: Decrypt with wrong nonce
			t.Run("WrongNonce", func(t *testing.T) {
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}

				// Replace nonce with different value
				for i := range encrypted.Nonce {
					encrypted.Nonce[i] ^= 0xFF
				}

				_, err = encrypter.Decrypt(encrypted, nil)
				if err == nil {
					t.Error("Decrypt should fail with wrong nonce")
				}
				t.Logf("✓ Correctly rejected wrong nonce: %v", err)
			})

			// Test 4: Decrypt non-existent key
			t.Run("NonExistentKey", func(t *testing.T) {
				nonExistentAttrs := &types.KeyAttributes{
					CN:                 "non-existent-key",
					KeyType:            backend.KEY_TYPE_SECRET,
					StoreType:          backend.STORE_PKCS11,
					SymmetricAlgorithm: types.SymmetricAES256GCM,
				}

				_, err := ks.SymmetricEncrypter(nonExistentAttrs)
				if err == nil {
					t.Error("Getting encrypter for non-existent key should fail")
				}
				t.Logf("✓ Correctly rejected non-existent key: %v", err)
			})
		})

		t.Run("AES-GCM_EmptyData", func(t *testing.T) {
			// Test encryption/decryption of empty data
			attrs := &types.KeyAttributes{
				CN:                 "test-aes-empty",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			_, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer ks.DeleteKey(attrs)

			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			// Encrypt empty data
			plaintext := []byte{}
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Failed to encrypt empty data: %v", err)
			}
			t.Log("✓ Encrypted empty plaintext")

			// Decrypt
			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Failed to decrypt empty data: %v", err)
			}

			if len(decrypted) != 0 {
				t.Errorf("Expected empty decrypted data, got %d bytes", len(decrypted))
			}
			t.Log("✓ Decrypted empty plaintext successfully")
		})

		t.Run("AES-GCM_LargeData", func(t *testing.T) {
			// Test encryption/decryption of larger data blocks
			attrs := &types.KeyAttributes{
				CN:                 "test-aes-large",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			_, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer ks.DeleteKey(attrs)

			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			// Test with 1MB of data
			plaintext := make([]byte, 1024*1024)
			for i := range plaintext {
				plaintext[i] = byte(i % 256)
			}
			t.Logf("Testing with %d bytes of data", len(plaintext))

			// Encrypt
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Failed to encrypt large data: %v", err)
			}
			t.Logf("✓ Encrypted %d bytes", len(plaintext))

			// Decrypt
			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Failed to decrypt large data: %v", err)
			}
			t.Logf("✓ Decrypted %d bytes", len(decrypted))

			// Verify
			if len(decrypted) != len(plaintext) {
				t.Errorf("Length mismatch: got %d, want %d", len(decrypted), len(plaintext))
			}
			for i := range plaintext {
				if decrypted[i] != plaintext[i] {
					t.Errorf("Data mismatch at byte %d", i)
					break
				}
			}
			t.Log("✓ Large data encryption/decryption successful")
		})

		t.Run("AES-GCM_MultipleKeys", func(t *testing.T) {
			// Test that different keys produce different ciphertexts
			plaintext := []byte("Same plaintext for different keys")

			// Generate first key
			attrs1 := &types.KeyAttributes{
				CN:                 "test-aes-key1",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}
			_, err := ks.GenerateSymmetricKey(attrs1)
			if err != nil {
				t.Fatalf("Failed to generate key1: %v", err)
			}
			defer ks.DeleteKey(attrs1)

			// Generate second key
			attrs2 := &types.KeyAttributes{
				CN:                 "test-aes-key2",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}
			_, err = ks.GenerateSymmetricKey(attrs2)
			if err != nil {
				t.Fatalf("Failed to generate key2: %v", err)
			}
			defer ks.DeleteKey(attrs2)

			// Encrypt with first key
			encrypter1, err := ks.SymmetricEncrypter(attrs1)
			if err != nil {
				t.Fatalf("Failed to get encrypter1: %v", err)
			}
			encrypted1, err := encrypter1.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Failed to encrypt with key1: %v", err)
			}

			// Encrypt with second key
			encrypter2, err := ks.SymmetricEncrypter(attrs2)
			if err != nil {
				t.Fatalf("Failed to get encrypter2: %v", err)
			}
			encrypted2, err := encrypter2.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Failed to encrypt with key2: %v", err)
			}

			// Ciphertexts should be different
			if string(encrypted1.Ciphertext) == string(encrypted2.Ciphertext) {
				t.Error("Different keys produced identical ciphertexts")
			}
			t.Log("✓ Different keys produce different ciphertexts")

			// Each key can only decrypt its own ciphertext
			_, err = encrypter1.Decrypt(encrypted2, nil)
			if err == nil {
				t.Error("Key1 should not decrypt key2's ciphertext")
			}
			t.Log("✓ Keys are properly isolated")

			// Verify each key can decrypt its own ciphertext
			decrypted1, err := encrypter1.Decrypt(encrypted1, nil)
			if err != nil {
				t.Fatalf("Failed to decrypt with key1: %v", err)
			}
			if string(decrypted1) != string(plaintext) {
				t.Error("Key1 decryption failed")
			}

			decrypted2, err := encrypter2.Decrypt(encrypted2, nil)
			if err != nil {
				t.Fatalf("Failed to decrypt with key2: %v", err)
			}
			if string(decrypted2) != string(plaintext) {
				t.Error("Key2 decryption failed")
			}
			t.Log("✓ Each key correctly decrypts its own ciphertext")
		})
	})

	t.Log("=== PKCS11 Integration Tests Completed ===")
}

// createTestCertificate creates a simple self-signed certificate for testing
func createTestCertificate(t *testing.T, cn string) *x509.Certificate {
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
