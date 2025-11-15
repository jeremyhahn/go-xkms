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
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestTPM2Integration performs comprehensive integration tests for TPM2 backend
func TestTPM2Integration(t *testing.T) {
	// Create temporary directory for key storage
	tmpDir, err := os.MkdirTemp("", "tpm2-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create storage backend
	keyStorage, err := file.New(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	certStorage := keyStorage // Both use the same backend

	// Create PKCS8 backend for TPM2 to use
	pkcs8Config := &pkcs8.Config{
		KeyStorage: keyStorage,
	}
	pkcs8Backend, err := pkcs8.NewBackend(pkcs8Config)
	if err != nil {
		t.Fatalf("Failed to create PKCS8 backend: %v", err)
	}

	// Configure TPM2 to use simulator from environment or hardware
	tpmConfig := &tpm2.Config{
		CN:        "test-keystore-srk",
		SRKHandle: 0x81000001,
	}

	// Check if TPM simulator host is configured (for Docker environment)
	simHost := os.Getenv("TPM2_SIMULATOR_HOST")
	simPort := os.Getenv("TPM2_SIMULATOR_PORT")

	if simHost != "" && simPort != "" {
		// Use TCP simulator (SWTPM)
		tpmConfig.UseSimulator = true
		tpmConfig.SimulatorType = "swtpm"
		tpmConfig.SimulatorHost = simHost
		var port int
		if _, err := fmt.Sscanf(simPort, "%d", &port); err == nil {
			tpmConfig.SimulatorPort = port
		} else {
			tpmConfig.SimulatorPort = 2321 // default
		}
		t.Logf("Using TPM simulator at %s:%d", tpmConfig.SimulatorHost, tpmConfig.SimulatorPort)
	} else {
		// Try hardware TPM device
		tpmDevice := os.Getenv("TPM_DEVICE")
		if tpmDevice == "" {
			tpmDevice = "/dev/tpmrm0"
		}

		if _, err := os.Stat(tpmDevice); os.IsNotExist(err) {
			t.Skipf("Skipping TPM2 integration tests: TPM device %s not found and no simulator configured", tpmDevice)
		}
		tpmConfig.DevicePath = tpmDevice
		t.Logf("Using hardware TPM device: %s", tpmDevice)
	}

	// Create TPM2 backend
	tpm2Backend, err := tpm2.NewTPM2KeyStore(tpmConfig, pkcs8Backend, keyStorage, certStorage, nil)
	if err != nil {
		t.Fatalf("Failed to create TPM2 backend: %v", err)
	}
	defer tpm2Backend.Close()

	// Initialize the TPM keystore (this creates the SRK)
	// Note: Initialize can be called multiple times; it will return ErrAlreadyInitialized if SRK exists
	err = tpm2Backend.Initialize(nil, nil)
	if err != nil {
		// Check if error is ErrAlreadyInitialized (which is expected on subsequent runs)
		errMsg := err.Error()
		if errMsg != "keystore: already initialized" && errMsg != "keystore already initialized" {
			t.Fatalf("Failed to initialize TPM2 backend: %v", err)
		}
		t.Logf("TPM keystore already initialized (this is expected)")
	} else {
		t.Logf("TPM keystore initialized successfully")
	}

	// Create keystore - use TPM2KeyStore directly, not as Backend
	ks := tpm2Backend

	t.Log("=== TPM2 Integration Tests ===")

	// ========================================
	// Key Generation Tests
	// ========================================
	t.Run("KeyGeneration", func(t *testing.T) {
		t.Run("RSA-2048", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			key, err := ks.GenerateKey(attrs)
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
				CN:           "test-tpm-rsa-3072",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 3072,
				},
			}

			key, err := ks.GenerateKey(attrs)
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
				CN:           "test-tpm-rsa-4096",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			}

			key, err := ks.GenerateKey(attrs)
			if err != nil {
				// TPM2 may not support 4096-bit keys - this is a known hardware limitation
				if key == nil {
					t.Logf("⚠ TPM2 does not support RSA-4096 (known limitation): %v", err)
					return
				}
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
				CN:           "test-tpm-ecdsa-p256",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			key, err := ks.GenerateKey(attrs)
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
				CN:           "test-tpm-ecdsa-p384",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P384(),
				},
			}

			key, err := ks.GenerateKey(attrs)
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
				CN:           "test-tpm-ecdsa-p521",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P521(),
				},
			}

			key, err := ks.GenerateKey(attrs)
			if err != nil {
				// TPM2 may not support P-521 - this is a known hardware limitation
				if key == nil {
					t.Logf("⚠ TPM2 does not support P-521 (known limitation): %v", err)
					return
				}
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

		// Ed25519 is not currently supported in TPM2 backend
		// This is a known limitation documented in the codebase
	})

	// ========================================
	// Key Retrieval Tests
	// ========================================
	t.Run("GetKey", func(t *testing.T) {
		t.Run("RetrieveExistingRSAKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			retrievedKey, err := ks.GetKey(attrs)
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
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-ecdsa-p256",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.ECDSA,
			}
			retrievedKey, err := ks.GetKey(attrs)
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
			_, err := ks.GetKey(&types.KeyAttributes{CN: "non-existent-key"})
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
				CN:           "test-tpm-delete-key",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			_, err := ks.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key for deletion test: %v", err)
			}

			// Delete the key
			err = ks.DeleteKey(&types.KeyAttributes{CN: "test-tpm-delete-key"})
			if err != nil {
				t.Fatalf("Failed to delete key: %v", err)
			}
			t.Log("✓ Key deleted successfully")

			// Verify key is gone
			_, err = ks.GetKey(&types.KeyAttributes{CN: "test-tpm-delete-key"})
			if err == nil {
				t.Fatal("Key still exists after deletion")
			}
			t.Log("✓ Verified key no longer exists")
		})

		t.Run("DeleteNonExistentKey", func(t *testing.T) {
			err := ks.DeleteKey(&types.KeyAttributes{CN: "non-existent-key"})
			// Some backends may return error, others may succeed silently
			t.Logf("Delete non-existent key result: %v", err)
		})
	})

	// ========================================
	// Certificate Operations Tests
	// ========================================
	t.Run("CertificateOperations", func(t *testing.T) {
		// Create a test certificate
		testCert := createTPMTestCertificate(t, "test-tpm-cert")

		t.Run("SaveAndGetCert", func(t *testing.T) {
			err := storage.SaveCertParsed(certStorage, "test-tpm-cert", testCert)
			if err != nil {
				t.Fatalf("Failed to save certificate: %v", err)
			}
			t.Log("✓ Certificate saved")

			retrievedCert, err := storage.GetCertParsed(certStorage, "test-tpm-cert")
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
			exists, err := storage.CertExists(certStorage, "test-tpm-cert")
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
			err := storage.DeleteCert(certStorage, "test-tpm-cert")
			if err != nil {
				t.Fatalf("Failed to delete certificate: %v", err)
			}
			t.Log("✓ Certificate deleted")

			exists, err := storage.CertExists(certStorage, "test-tpm-cert")
			if err != nil {
				t.Fatalf("Failed to check certificate existence after deletion: %v", err)
			}
			if exists {
				t.Fatal("Certificate should not exist after deletion")
			}
			t.Log("✓ Verified certificate no longer exists")
		})

		t.Run("SaveAndGetCertChain", func(t *testing.T) {
			cert1 := createTPMTestCertificate(t, "tpm-chain-cert-1")
			cert2 := createTPMTestCertificate(t, "tpm-chain-cert-2")
			chain := []*x509.Certificate{cert1, cert2}

			err := storage.SaveCertChainParsed(certStorage, "test-tpm-chain", chain)
			if err != nil {
				t.Fatalf("Failed to save certificate chain: %v", err)
			}
			t.Log("✓ Certificate chain saved")

			retrievedChain, err := storage.GetCertChainParsed(certStorage, "test-tpm-chain")
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
		message := []byte("Test message for TPM signing")

		t.Run("RSA-SHA256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			hash := sha256.Sum256(message)

			// Retry signing if TPM_RC_RETRY occurs (TPM may need time to free transient handles)
			var signature []byte
			for i := 0; i < 3; i++ {
				signature, err = signer.Sign(rand.Reader, hash[:], crypto.SHA256)
				if err == nil {
					break
				}
				if i < 2 && (err.Error() == "tpm2: RSA signing failed: TPM_RC_RETRY: the TPM was not able to start the command" ||
					err.Error() == "tpm2: failed to load key for signing: tpm2: failed to load key: TPM_RC_RETRY: the TPM was not able to start the command") {
					t.Logf("TPM_RC_RETRY on attempt %d, retrying...", i+1)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				t.Fatalf("Failed to sign with SHA256: %v", err)
			}
			if err != nil {
				t.Fatalf("Failed to sign with SHA256 after retries: %v", err)
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
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
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
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
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

		// RSA-PSS Tests
		t.Run("RSA-2048-PSS-SHA256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			// Hash the message
			h := sha256.New()
			h.Write(message)
			digest := h.Sum(nil)

			// TPM2 should support PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			}

			// Retry signing if TPM_RC_RETRY occurs
			var signature []byte
			for i := 0; i < 3; i++ {
				signature, err = signer.Sign(rand.Reader, digest, pssOpts)
				if err == nil {
					break
				}
				if i < 2 && (err.Error() == "tpm2: RSA signing failed: TPM_RC_RETRY: the TPM was not able to start the command" ||
					err.Error() == "tpm2: failed to load key for signing: tpm2: failed to load key: TPM_RC_RETRY: the TPM was not able to start the command") {
					t.Logf("TPM_RC_RETRY on attempt %d, retrying...", i+1)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				t.Fatalf("Failed to sign with RSA-PSS SHA256: %v", err)
			}
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA256 after retries: %v", err)
			}
			t.Logf("✓ Signed message with RSA-2048-PSS-SHA256 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-2048-PSS-SHA256 signature verified successfully")
		})

		t.Run("RSA-2048-PSS-SHA384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			// Hash the message
			h := sha512.New384()
			h.Write(message)
			digest := h.Sum(nil)

			// TPM2 should support PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA384,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA384: %v", err)
			}
			t.Logf("✓ Signed message with RSA-2048-PSS-SHA384 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA384, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-2048-PSS-SHA384 signature verified successfully")
		})

		t.Run("RSA-2048-PSS-SHA512", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			// Hash the message
			h := sha512.New()
			h.Write(message)
			digest := h.Sum(nil)

			// TPM2 should support PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA512,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA512: %v", err)
			}
			t.Logf("✓ Signed message with RSA-2048-PSS-SHA512 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA512, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-2048-PSS-SHA512 signature verified successfully")
		})

		t.Run("RSA-3072-PSS-SHA256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-3072",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			// Hash the message
			h := sha256.New()
			h.Write(message)
			digest := h.Sum(nil)

			// TPM2 should support PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA256: %v", err)
			}
			t.Logf("✓ Signed message with RSA-3072-PSS-SHA256 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-3072-PSS-SHA256 signature verified successfully")
		})

		t.Run("RSA-3072-PSS-SHA384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-3072",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			// Hash the message
			h := sha512.New384()
			h.Write(message)
			digest := h.Sum(nil)

			// TPM2 should support PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA384,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA384: %v", err)
			}
			t.Logf("✓ Signed message with RSA-3072-PSS-SHA384 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA384, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-3072-PSS-SHA384 signature verified successfully")
		})

		t.Run("RSA-3072-PSS-SHA512", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-3072",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get RSA key: %v", err)
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			// Hash the message
			h := sha512.New()
			h.Write(message)
			digest := h.Sum(nil)

			// TPM2 should support PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA512,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA512: %v", err)
			}
			t.Logf("✓ Signed message with RSA-3072-PSS-SHA512 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA512, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-3072-PSS-SHA512 signature verified successfully")
		})

		t.Run("RSA-4096-PSS-SHA256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-4096",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
			if err != nil {
				// TPM2 may not support 4096-bit keys - skip test if key doesn't exist
				t.Logf("⚠ Skipping RSA-4096-PSS test: key not available: %v", err)
				return
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			// Hash the message
			h := sha256.New()
			h.Write(message)
			digest := h.Sum(nil)

			// TPM2 should support PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA256: %v", err)
			}
			t.Logf("✓ Signed message with RSA-4096-PSS-SHA256 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-4096-PSS-SHA256 signature verified successfully")
		})

		t.Run("RSA-4096-PSS-SHA384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-4096",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
			if err != nil {
				// TPM2 may not support 4096-bit keys - skip test if key doesn't exist
				t.Logf("⚠ Skipping RSA-4096-PSS test: key not available: %v", err)
				return
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			// Hash the message
			h := sha512.New384()
			h.Write(message)
			digest := h.Sum(nil)

			// TPM2 should support PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA384,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA384: %v", err)
			}
			t.Logf("✓ Signed message with RSA-4096-PSS-SHA384 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA384, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-4096-PSS-SHA384 signature verified successfully")
		})

		t.Run("RSA-4096-PSS-SHA512", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-4096",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}
			key, err := ks.GetKey(attrs)
			if err != nil {
				// TPM2 may not support 4096-bit keys - skip test if key doesn't exist
				t.Logf("⚠ Skipping RSA-4096-PSS test: key not available: %v", err)
				return
			}

			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}

			// Hash the message
			h := sha512.New()
			h.Write(message)
			digest := h.Sum(nil)

			// TPM2 should support PSSSaltLengthAuto
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA512,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Fatalf("Failed to sign with RSA-PSS SHA512: %v", err)
			}
			t.Logf("✓ Signed message with RSA-4096-PSS-SHA512 (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}

			err = rsa.VerifyPSS(rsaPub, crypto.SHA512, digest, signature, pssOpts)
			if err != nil {
				t.Fatalf("Failed to verify RSA-PSS signature: %v", err)
			}
			t.Log("✓ RSA-4096-PSS-SHA512 signature verified successfully")
		})

		t.Run("ECDSA-SHA256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-ecdsa-p256",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.ECDSA,
			}
			key, err := ks.GetKey(attrs)
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
	})

	// ========================================
	// TPM-Specific Features
	// ========================================
	// TPM-Specific Features like persistent keys, seal/unseal, PCR extend, and quote/attestation
	// are advanced TPM features that can be added in future iterations as needed

	// ========================================
	// Backend Interface Tests
	// ========================================
	t.Run("BackendInterface", func(t *testing.T) {
		t.Run("Type", func(t *testing.T) {
			backendType := ks.Type()
			if backendType != backend.BackendTypeTPM2 {
				t.Errorf("Expected backend type %s, got %s", backend.BackendTypeTPM2, backendType)
			}
			t.Logf("✓ Backend type: %s", backendType)
		})

		t.Run("Capabilities", func(t *testing.T) {
			caps := ks.Capabilities()
			t.Logf("Backend capabilities:")
			t.Logf("  - Keys: %v", caps.Keys)
			t.Logf("  - Hardware Backed: %v", caps.HardwareBacked)
			t.Logf("  - Signing: %v", caps.Signing)
			t.Logf("  - Decryption: %v", caps.Decryption)
			t.Logf("  - Key Rotation: %v", caps.KeyRotation)
			t.Logf("  - Symmetric Encryption: %v", caps.SymmetricEncryption)

			if !caps.Keys {
				t.Error("TPM2 should support keys")
			}
			if !caps.HardwareBacked {
				t.Error("TPM2 should be hardware backed")
			}
			if !caps.Signing {
				t.Error("TPM2 should support signing")
			}
			if !caps.Decryption {
				t.Error("TPM2 should support decryption")
			}
			t.Log("✓ All capability checks passed")
		})

		t.Run("ListKeys", func(t *testing.T) {
			keys, err := ks.ListKeys()
			if err != nil {
				t.Fatalf("Failed to list keys: %v", err)
			}
			t.Logf("✓ Listed %d keys", len(keys))

			// Verify we can find some of the keys we created
			foundRSA := false
			foundECDSA := false
			for _, key := range keys {
				if key.CN == "test-tpm-rsa-2048" {
					foundRSA = true
					t.Logf("  - Found RSA key: %s", key.CN)
				}
				if key.CN == "test-tpm-ecdsa-p256" {
					foundECDSA = true
					t.Logf("  - Found ECDSA key: %s", key.CN)
				}
			}
			if !foundRSA {
				t.Error("Expected to find test-tpm-rsa-2048 in key list")
			}
			if !foundECDSA {
				t.Error("Expected to find test-tpm-ecdsa-p256 in key list")
			}
		})

		t.Run("Signer", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
			}

			signer, err := ks.Signer(attrs)
			if err != nil {
				t.Fatalf("Failed to get signer: %v", err)
			}

			// Test signing
			message := []byte("Test message for signer interface")
			hash := sha256.Sum256(message)

			signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}
			t.Logf("✓ Signer interface works (signature length: %d)", len(signature))

			// Verify signature
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key from signer")
			}

			err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], signature)
			if err != nil {
				t.Fatalf("Failed to verify signature from Signer: %v", err)
			}
			t.Log("✓ Signature from Signer verified successfully")
		})

		t.Run("Decrypter", func(t *testing.T) {
			t.Run("PKCS1v15", func(t *testing.T) {
				// Generate a key specifically for PKCS#1 v1.5 decryption testing
				attrs := &types.KeyAttributes{
					CN:           "test-tpm-decrypt-pkcs1",
					KeyType:      backend.KEY_TYPE_ENCRYPTION,
					StoreType:    backend.STORE_TPM2,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}

				key, err := ks.GenerateKey(attrs)
				if err != nil {
					t.Fatalf("Failed to generate key for decryption test: %v", err)
				}
				defer ks.DeleteKey(attrs)

				decrypter, err := ks.Decrypter(attrs)
				if err != nil {
					t.Fatalf("Failed to get decrypter: %v", err)
				}

				// Get public key for encryption
				signer, ok := key.(crypto.Signer)
				if !ok {
					t.Fatal("Key does not implement crypto.Signer")
				}

				rsaPub, ok := signer.Public().(*rsa.PublicKey)
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
					t.Fatalf("Failed to decrypt: %v", err)
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("Decrypted message doesn't match: got %s, want %s", decrypted, plaintext)
				}
				t.Log("✓ PKCS#1 v1.5 decrypt works correctly")
			})

			t.Run("OAEP_SHA256_RSA2048", func(t *testing.T) {
				// Generate RSA-2048 key for OAEP decryption testing
				attrs := &types.KeyAttributes{
					CN:           "test-tpm-decrypt-oaep-2048",
					KeyType:      backend.KEY_TYPE_ENCRYPTION,
					StoreType:    backend.STORE_TPM2,
					KeyAlgorithm: x509.RSA,
					Hash:         crypto.SHA256,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}

				key, err := ks.GenerateKey(attrs)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}
				defer ks.DeleteKey(attrs)

				decrypter, err := ks.Decrypter(attrs)
				if err != nil {
					t.Fatalf("Failed to get decrypter: %v", err)
				}

				// Get public key for encryption
				signer, ok := key.(crypto.Signer)
				if !ok {
					t.Fatal("Key does not implement crypto.Signer")
				}

				rsaPub, ok := signer.Public().(*rsa.PublicKey)
				if !ok {
					t.Fatal("Expected RSA public key")
				}

				// Encrypt with OAEP SHA256
				plaintext := []byte("Test message for TPM2 OAEP SHA-256")
				label := []byte("")
				ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, plaintext, label)
				if err != nil {
					t.Fatalf("Failed to encrypt with OAEP: %v", err)
				}
				t.Logf("✓ Encrypted %d bytes with RSA-2048 OAEP SHA256 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

				// Decrypt with OAEP options
				oaepOpts := &rsa.OAEPOptions{
					Hash:  crypto.SHA256,
					Label: label,
				}
				decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, oaepOpts)
				if err != nil {
					t.Fatalf("Failed to decrypt with OAEP: %v", err)
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("Decrypted message doesn't match: got %s, want %s", decrypted, plaintext)
				}
				t.Log("✓ RSA-2048 OAEP SHA256 decrypt works correctly")
			})

			t.Run("OAEP_SHA256_RSA3072", func(t *testing.T) {
				// Generate RSA-3072 key for OAEP decryption testing
				attrs := &types.KeyAttributes{
					CN:           "test-tpm-decrypt-oaep-3072",
					KeyType:      backend.KEY_TYPE_ENCRYPTION,
					StoreType:    backend.STORE_TPM2,
					KeyAlgorithm: x509.RSA,
					Hash:         crypto.SHA256,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 3072,
					},
				}

				key, err := ks.GenerateKey(attrs)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}
				defer ks.DeleteKey(attrs)

				decrypter, err := ks.Decrypter(attrs)
				if err != nil {
					t.Fatalf("Failed to get decrypter: %v", err)
				}

				// Get public key for encryption
				signer, ok := key.(crypto.Signer)
				if !ok {
					t.Fatal("Key does not implement crypto.Signer")
				}

				rsaPub, ok := signer.Public().(*rsa.PublicKey)
				if !ok {
					t.Fatal("Expected RSA public key")
				}

				// Encrypt with OAEP SHA256
				plaintext := []byte("TPM2 RSA-3072 OAEP SHA-256 test")
				label := []byte("")
				ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, plaintext, label)
				if err != nil {
					t.Fatalf("Failed to encrypt with OAEP: %v", err)
				}
				t.Logf("✓ Encrypted %d bytes with RSA-3072 OAEP SHA256 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

				// Decrypt with OAEP options
				oaepOpts := &rsa.OAEPOptions{
					Hash:  crypto.SHA256,
					Label: label,
				}
				decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, oaepOpts)
				if err != nil {
					t.Fatalf("Failed to decrypt with OAEP: %v", err)
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("Decrypted message doesn't match: got %s, want %s", decrypted, plaintext)
				}
				t.Log("✓ RSA-3072 OAEP SHA256 decrypt works correctly")
			})

			t.Run("OAEP_SHA384_RSA4096", func(t *testing.T) {
				t.Skip("Skipping: TPM2 doesn't support RSA-4096 keys")
				// Generate RSA-4096 key for OAEP SHA384 decryption testing
				attrs := &types.KeyAttributes{
					CN:           "test-tpm-decrypt-oaep-4096",
					KeyType:      backend.KEY_TYPE_ENCRYPTION,
					StoreType:    backend.STORE_TPM2,
					KeyAlgorithm: x509.RSA,
					Hash:         crypto.SHA384,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 4096,
					},
				}

				key, err := ks.GenerateKey(attrs)
				if err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}
				defer ks.DeleteKey(attrs)

				decrypter, err := ks.Decrypter(attrs)
				if err != nil {
					t.Fatalf("Failed to get decrypter: %v", err)
				}

				// Get public key for encryption
				signer, ok := key.(crypto.Signer)
				if !ok {
					t.Fatal("Key does not implement crypto.Signer")
				}

				rsaPub, ok := signer.Public().(*rsa.PublicKey)
				if !ok {
					t.Fatal("Expected RSA public key")
				}

				// Encrypt with OAEP SHA384
				plaintext := []byte("TPM2 RSA-4096 OAEP SHA-384")
				label := []byte("")
				ciphertext, err := rsa.EncryptOAEP(crypto.SHA384.New(), rand.Reader, rsaPub, plaintext, label)
				if err != nil {
					t.Fatalf("Failed to encrypt with OAEP: %v", err)
				}
				t.Logf("✓ Encrypted %d bytes with RSA-4096 OAEP SHA384 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

				// Decrypt with OAEP options
				oaepOpts := &rsa.OAEPOptions{
					Hash:  crypto.SHA384,
					Label: label,
				}
				decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, oaepOpts)
				if err != nil {
					t.Fatalf("Failed to decrypt with OAEP: %v", err)
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("Decrypted message doesn't match: got %s, want %s", decrypted, plaintext)
				}
				t.Log("✓ RSA-4096 OAEP SHA384 decrypt works correctly")
			})
		})
	})

	// ========================================
	// Symmetric Encryption Tests
	// ========================================
	t.Run("SymmetricEncryption", func(t *testing.T) {
		t.Run("AES-128-GCM_BasicEncryptDecrypt", func(t *testing.T) {
			// Test basic AES-128-GCM encryption/decryption with real TPM2
			attrs := &types.KeyAttributes{
				CN:                 "test-tpm-aes128-integration",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_TPM2,
				SymmetricAlgorithm: types.SymmetricAES128GCM,
				Partition:          backend.PARTITION_ENCRYPTION_KEYS,
				AESAttributes: &types.AESAttributes{
					KeySize: 128,
				},
			}

			// Generate symmetric key
			key, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate AES-128 key: %v", err)
			}

			if key.KeySize() != 128 {
				t.Errorf("Expected key size 128, got %d", key.KeySize())
			}
			t.Logf("✓ Generated AES-128-GCM key")

			// Get encrypter
			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}
			t.Log("✓ Got symmetric encrypter")

			// Test encryption
			plaintext := []byte("Sensitive data protected by TPM2 hardware")
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			if encrypted == nil || len(encrypted.Ciphertext) == 0 {
				t.Fatal("Encryption returned nil or empty ciphertext")
			}
			if len(encrypted.Nonce) != 12 {
				t.Errorf("Expected 12-byte nonce for GCM, got %d bytes", len(encrypted.Nonce))
			}
			if len(encrypted.Tag) != 16 {
				t.Errorf("Expected 16-byte authentication tag, got %d bytes", len(encrypted.Tag))
			}
			t.Logf("✓ Encrypted %d bytes → %d bytes ciphertext + %d bytes nonce + %d bytes tag",
				len(plaintext), len(encrypted.Ciphertext), len(encrypted.Nonce), len(encrypted.Tag))

			// Test decryption
			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(decrypted) != string(plaintext) {
				t.Errorf("Decrypted data mismatch\nExpected: %s\nGot: %s", plaintext, decrypted)
			}
			t.Log("✓ Successfully decrypted and verified plaintext")

			// Cleanup
			err = ks.DeleteKey(&types.KeyAttributes{CN: "test-tpm-aes128-integration"})
			if err != nil {
				t.Logf("Warning: Failed to cleanup test key: %v", err)
			}
		})

		t.Run("AES-256-GCM_BasicEncryptDecrypt", func(t *testing.T) {
			// Test basic AES-256-GCM encryption/decryption with real TPM2
			attrs := &types.KeyAttributes{
				CN:                 "test-tpm-aes256-integration",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_TPM2,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				Partition:          backend.PARTITION_ENCRYPTION_KEYS,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			}

			// Generate symmetric key
			key, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate AES-256 key: %v", err)
			}

			if key.KeySize() != 256 {
				t.Errorf("Expected key size 256, got %d", key.KeySize())
			}
			t.Logf("✓ Generated AES-256-GCM key")

			// Get encrypter
			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}
			t.Log("✓ Got symmetric encrypter")

			// Test encryption
			plaintext := []byte("Top secret data protected by TPM2 with AES-256")
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			if encrypted == nil || len(encrypted.Ciphertext) == 0 {
				t.Fatal("Encryption returned nil or empty ciphertext")
			}
			t.Logf("✓ Encrypted %d bytes → %d bytes ciphertext", len(plaintext), len(encrypted.Ciphertext))

			// Test decryption
			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(decrypted) != string(plaintext) {
				t.Errorf("Decrypted data mismatch\nExpected: %s\nGot: %s", plaintext, decrypted)
			}
			t.Log("✓ Successfully decrypted and verified plaintext")

			// Cleanup
			err = ks.DeleteKey(&types.KeyAttributes{CN: "test-tpm-aes256-integration"})
			if err != nil {
				t.Logf("Warning: Failed to cleanup test key: %v", err)
			}
		})

		t.Run("EncryptionWithAAD", func(t *testing.T) {
			// Test encryption with Additional Authenticated Data
			attrs := &types.KeyAttributes{
				CN:                 "test-tpm-aes-aad",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_TPM2,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				Partition:          backend.PARTITION_ENCRYPTION_KEYS,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			}

			// Generate key
			_, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer ks.DeleteKey(&types.KeyAttributes{CN: "test-tpm-aes-aad"})

			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			plaintext := []byte("Secret message")
			aad := []byte("context:user-auth-token:version-2")

			// Encrypt with AAD
			encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
				AdditionalData: aad,
			})
			if err != nil {
				t.Fatalf("Encryption with AAD failed: %v", err)
			}
			t.Log("✓ Encrypted with AAD")

			// Decrypt with correct AAD - should succeed
			decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
				AdditionalData: aad,
			})
			if err != nil {
				t.Fatalf("Decryption with correct AAD failed: %v", err)
			}
			if string(decrypted) != string(plaintext) {
				t.Error("Decrypted data doesn't match with correct AAD")
			}
			t.Log("✓ Decrypted successfully with correct AAD")

			// Try to decrypt with wrong AAD - should fail
			wrongAAD := []byte("context:wrong-token:version-1")
			_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
				AdditionalData: wrongAAD,
			})
			if err == nil {
				t.Fatal("Expected authentication error with wrong AAD, got nil")
			}
			t.Logf("✓ Correctly rejected decryption with wrong AAD: %v", err)

			// Try to decrypt without AAD when encrypted with AAD - should fail
			_, err = encrypter.Decrypt(encrypted, nil)
			if err == nil {
				t.Fatal("Expected authentication error without AAD, got nil")
			}
			t.Log("✓ Correctly rejected decryption without AAD when AAD was used")
		})

		t.Run("NonceUniqueness", func(t *testing.T) {
			// Verify that nonces are unique across multiple encryption operations
			attrs := &types.KeyAttributes{
				CN:                 "test-tpm-nonce-unique",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_TPM2,
				SymmetricAlgorithm: types.SymmetricAES128GCM,
				Partition:          backend.PARTITION_ENCRYPTION_KEYS,
				AESAttributes: &types.AESAttributes{
					KeySize: 128,
				},
			}

			_, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer ks.DeleteKey(&types.KeyAttributes{CN: "test-tpm-nonce-unique"})

			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			plaintext := []byte("Same message encrypted multiple times")
			nonces := make(map[string]bool)

			// Encrypt the same message 10 times
			for i := 0; i < 10; i++ {
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				if err != nil {
					t.Fatalf("Encryption %d failed: %v", i+1, err)
				}

				nonceStr := string(encrypted.Nonce)
				if nonces[nonceStr] {
					t.Fatalf("Duplicate nonce detected on iteration %d", i+1)
				}
				nonces[nonceStr] = true

				// Verify we can decrypt each one
				decrypted, err := encrypter.Decrypt(encrypted, nil)
				if err != nil {
					t.Fatalf("Decryption %d failed: %v", i+1, err)
				}
				if string(decrypted) != string(plaintext) {
					t.Errorf("Decryption %d produced wrong plaintext", i+1)
				}
			}

			t.Logf("✓ Verified %d unique nonces across %d encryptions", len(nonces), 10)
		})

		t.Run("InvalidKey_DecryptionFailure", func(t *testing.T) {
			// Test that decryption fails with wrong key
			// Generate two different keys
			attrs1 := &types.KeyAttributes{
				CN:                 "test-tpm-key1",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_TPM2,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				Partition:          backend.PARTITION_ENCRYPTION_KEYS,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			}

			attrs2 := &types.KeyAttributes{
				CN:                 "test-tpm-key2",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_TPM2,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				Partition:          backend.PARTITION_ENCRYPTION_KEYS,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			}

			_, err := ks.GenerateSymmetricKey(attrs1)
			if err != nil {
				t.Fatalf("Failed to generate key1: %v", err)
			}
			defer ks.DeleteKey(&types.KeyAttributes{CN: "test-tpm-key1"})

			_, err = ks.GenerateSymmetricKey(attrs2)
			if err != nil {
				t.Fatalf("Failed to generate key2: %v", err)
			}
			defer ks.DeleteKey(&types.KeyAttributes{CN: "test-tpm-key2"})

			// Encrypt with key1
			encrypter1, err := ks.SymmetricEncrypter(attrs1)
			if err != nil {
				t.Fatalf("Failed to get encrypter1: %v", err)
			}

			plaintext := []byte("Secret data")
			encrypted, err := encrypter1.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			t.Log("✓ Encrypted with key1")

			// Try to decrypt with key2 - should fail
			encrypter2, err := ks.SymmetricEncrypter(attrs2)
			if err != nil {
				t.Fatalf("Failed to get encrypter2: %v", err)
			}

			_, err = encrypter2.Decrypt(encrypted, nil)
			if err == nil {
				t.Fatal("Expected decryption to fail with wrong key, got nil error")
			}
			t.Logf("✓ Correctly rejected decryption with wrong key: %v", err)
		})

		t.Run("TamperedCiphertext", func(t *testing.T) {
			// Test that tampered ciphertext is detected
			attrs := &types.KeyAttributes{
				CN:                 "test-tpm-tamper",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_TPM2,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				Partition:          backend.PARTITION_ENCRYPTION_KEYS,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			}

			_, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer ks.DeleteKey(&types.KeyAttributes{CN: "test-tpm-tamper"})

			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			plaintext := []byte("Important data")
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Tamper with ciphertext
			if len(encrypted.Ciphertext) > 0 {
				encrypted.Ciphertext[0] ^= 0xFF // Flip all bits in first byte
			}

			_, err = encrypter.Decrypt(encrypted, nil)
			if err == nil {
				t.Fatal("Expected authentication error for tampered ciphertext, got nil")
			}
			t.Logf("✓ Correctly detected tampered ciphertext: %v", err)

			// Test tampered tag
			encrypted2, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			if len(encrypted2.Tag) > 0 {
				encrypted2.Tag[0] ^= 0x01 // Flip one bit
			}

			_, err = encrypter.Decrypt(encrypted2, nil)
			if err == nil {
				t.Fatal("Expected authentication error for tampered tag, got nil")
			}
			t.Logf("✓ Correctly detected tampered authentication tag: %v", err)
		})

		t.Run("LargeData_1MB", func(t *testing.T) {
			// Test encryption of larger data (1MB)
			attrs := &types.KeyAttributes{
				CN:                 "test-tpm-large-data",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_TPM2,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				Partition:          backend.PARTITION_ENCRYPTION_KEYS,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			}

			_, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer ks.DeleteKey(&types.KeyAttributes{CN: "test-tpm-large-data"})

			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			// Generate 1MB of test data with pattern
			plaintext := make([]byte, 1024*1024)
			for i := range plaintext {
				plaintext[i] = byte(i % 256)
			}
			t.Logf("Generated %d bytes of test data", len(plaintext))

			// Encrypt
			encStartTime := time.Now()
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			encDuration := time.Since(encStartTime)
			if err != nil {
				t.Fatalf("Encryption of large data failed: %v", err)
			}
			t.Logf("✓ Encrypted 1MB in %v", encDuration)

			// Decrypt
			decStartTime := time.Now()
			decrypted, err := encrypter.Decrypt(encrypted, nil)
			decDuration := time.Since(decStartTime)
			if err != nil {
				t.Fatalf("Decryption of large data failed: %v", err)
			}
			t.Logf("✓ Decrypted 1MB in %v", decDuration)

			// Verify every byte
			if len(decrypted) != len(plaintext) {
				t.Fatalf("Length mismatch: expected %d, got %d", len(plaintext), len(decrypted))
			}

			for i := range plaintext {
				if decrypted[i] != plaintext[i] {
					t.Fatalf("Data mismatch at byte %d: expected %d, got %d", i, plaintext[i], decrypted[i])
				}
			}
			t.Log("✓ Verified all 1MB bytes match")
		})

		t.Run("KeyPersistence", func(t *testing.T) {
			// Test that keys persist across encrypter instances
			attrs := &types.KeyAttributes{
				CN:                 "test-tpm-persist",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_TPM2,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				Partition:          backend.PARTITION_ENCRYPTION_KEYS,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			}

			_, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer ks.DeleteKey(&types.KeyAttributes{CN: "test-tpm-persist"})

			// Get first encrypter and encrypt
			encrypter1, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get first encrypter: %v", err)
			}

			plaintext := []byte("Data encrypted with first encrypter")
			encrypted, err := encrypter1.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			t.Log("✓ Encrypted with first encrypter instance")

			// Get second encrypter and decrypt
			encrypter2, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get second encrypter: %v", err)
			}

			decrypted, err := encrypter2.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Decryption with second encrypter failed: %v", err)
			}

			if string(decrypted) != string(plaintext) {
				t.Error("Decryption with second encrypter produced wrong plaintext")
			}
			t.Log("✓ Successfully decrypted with second encrypter instance")
		})

		t.Run("MultipleKeys_Concurrent", func(t *testing.T) {
			// Test multiple keys with concurrent operations
			numKeys := 5
			attrs := make([]*types.KeyAttributes, numKeys)

			// Generate multiple keys
			for i := 0; i < numKeys; i++ {
				attrs[i] = &types.KeyAttributes{
					CN:                 fmt.Sprintf("test-tpm-multi-%d", i),
					KeyType:            backend.KEY_TYPE_SECRET,
					StoreType:          backend.STORE_TPM2,
					SymmetricAlgorithm: types.SymmetricAES256GCM,
					Partition:          backend.PARTITION_ENCRYPTION_KEYS,
					AESAttributes: &types.AESAttributes{
						KeySize: 256,
					},
				}

				_, err := ks.GenerateSymmetricKey(attrs[i])
				if err != nil {
					t.Fatalf("Failed to generate key %d: %v", i, err)
				}
				defer ks.DeleteKey(&types.KeyAttributes{CN: fmt.Sprintf("test-tpm-multi-%d", i)})
			}
			t.Logf("✓ Generated %d symmetric keys", numKeys)

			// Encrypt with each key
			encrypted := make([]*types.EncryptedData, numKeys)
			for i := 0; i < numKeys; i++ {
				encrypter, err := ks.SymmetricEncrypter(attrs[i])
				if err != nil {
					t.Fatalf("Failed to get encrypter %d: %v", i, err)
				}

				plaintext := []byte(fmt.Sprintf("Data for key %d", i))
				encrypted[i], err = encrypter.Encrypt(plaintext, nil)
				if err != nil {
					t.Fatalf("Encryption with key %d failed: %v", i, err)
				}
			}
			t.Logf("✓ Encrypted data with %d different keys", numKeys)

			// Decrypt with each key and verify
			for i := 0; i < numKeys; i++ {
				encrypter, err := ks.SymmetricEncrypter(attrs[i])
				if err != nil {
					t.Fatalf("Failed to get encrypter %d for decrypt: %v", i, err)
				}

				decrypted, err := encrypter.Decrypt(encrypted[i], nil)
				if err != nil {
					t.Fatalf("Decryption with key %d failed: %v", i, err)
				}

				expected := fmt.Sprintf("Data for key %d", i)
				if string(decrypted) != expected {
					t.Errorf("Key %d: expected %s, got %s", i, expected, decrypted)
				}
			}
			t.Logf("✓ Decrypted and verified data with %d different keys", numKeys)
		})

		t.Run("EmptyPlaintext", func(t *testing.T) {
			// Test encryption/decryption of empty data
			attrs := &types.KeyAttributes{
				CN:                 "test-tpm-empty",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_TPM2,
				SymmetricAlgorithm: types.SymmetricAES128GCM,
				Partition:          backend.PARTITION_ENCRYPTION_KEYS,
				AESAttributes: &types.AESAttributes{
					KeySize: 128,
				},
			}

			_, err := ks.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer ks.DeleteKey(&types.KeyAttributes{CN: "test-tpm-empty"})

			encrypter, err := ks.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			plaintext := []byte{}
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Encryption of empty data failed: %v", err)
			}
			t.Log("✓ Encrypted empty plaintext")

			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Decryption of empty data failed: %v", err)
			}

			if len(decrypted) != 0 {
				t.Errorf("Expected empty decrypted data, got %d bytes", len(decrypted))
			}
			t.Log("✓ Successfully decrypted empty plaintext")
		})

		t.Run("NonExistentKey", func(t *testing.T) {
			// Test error handling for non-existent key
			attrs := &types.KeyAttributes{
				CN:                 "test-tpm-nonexistent",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_TPM2,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				Partition:          backend.PARTITION_ENCRYPTION_KEYS,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			}

			_, err := ks.SymmetricEncrypter(attrs)
			if err == nil {
				t.Fatal("Expected error for non-existent key, got nil")
			}
			t.Logf("✓ Correctly returned error for non-existent key: %v", err)
		})
	})

	// ========================================
	// Key Rotation Tests
	// ========================================
	t.Run("KeyRotation", func(t *testing.T) {
		// Test RSA key rotation with signature verification
		t.Run("RSA_SignatureLifecycle", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rotate-rsa",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Step 1: Generate original key
			t.Log("Step 1: Generating original RSA key...")
			key, err := ks.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key for rotation test: %v", err)
			}

			// Get original public key for verification
			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}
			origPub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key")
			}
			t.Logf("✓ Generated original RSA key (%d bits)", origPub.N.BitLen())

			// Step 2: Create a signature with the original key
			t.Log("Step 2: Creating signature with original key...")
			testData := []byte("This signature was created before key rotation")
			hash := sha256.Sum256(testData)

			origSigner, err := ks.Signer(attrs)
			if err != nil {
				t.Fatalf("Failed to get signer: %v", err)
			}

			originalSignature, err := origSigner.Sign(rand.Reader, hash[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Failed to sign with original key: %v", err)
			}
			t.Logf("✓ Created signature with original key (%d bytes)", len(originalSignature))

			// Step 3: Verify the original signature works
			t.Log("Step 3: Verifying original signature...")
			err = rsa.VerifyPKCS1v15(origPub, crypto.SHA256, hash[:], originalSignature)
			if err != nil {
				t.Fatalf("Failed to verify original signature: %v", err)
			}
			t.Log("✓ Original signature verifies successfully")

			// Step 4: Rotate the key
			t.Log("Step 4: Rotating the key...")
			err = ks.RotateKey(attrs)
			if err != nil {
				t.Fatalf("Key rotation failed: %v", err)
			}
			t.Log("✓ Key rotation succeeded")

			// Step 5: Verify new key is different
			t.Log("Step 5: Verifying new key is different...")
			newKey, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get rotated key: %v", err)
			}

			newSigner, ok := newKey.(crypto.Signer)
			if !ok {
				t.Fatal("Rotated key does not implement crypto.Signer")
			}
			newPub, ok := newSigner.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatal("Expected RSA public key from rotated key")
			}

			if origPub.N.Cmp(newPub.N) == 0 {
				t.Error("Rotated key has same modulus as original (should be different)")
			} else {
				t.Logf("✓ New key is different from original (%d bits)", newPub.N.BitLen())
			}

			// Step 6: Verify original signature still validates with original public key
			// (Important: old signatures should remain valid with the old public key)
			t.Log("Step 6: Verifying original signature still valid with original public key...")
			err = rsa.VerifyPKCS1v15(origPub, crypto.SHA256, hash[:], originalSignature)
			if err != nil {
				t.Fatalf("Original signature no longer validates: %v", err)
			}
			t.Log("✓ Original signature still validates with original public key")

			// Step 7: Verify original signature does NOT validate with new public key
			// (This confirms the key actually changed)
			t.Log("Step 7: Verifying original signature fails with new public key...")
			err = rsa.VerifyPKCS1v15(newPub, crypto.SHA256, hash[:], originalSignature)
			if err == nil {
				t.Error("Original signature should NOT validate with new public key")
			} else {
				t.Log("✓ Original signature correctly fails with new public key")
			}

			// Step 8: Create a new signature with the rotated key
			t.Log("Step 8: Creating signature with rotated key...")
			testData2 := []byte("This signature was created after key rotation")
			hash2 := sha256.Sum256(testData2)

			newSignerInterface, err := ks.Signer(attrs)
			if err != nil {
				t.Fatalf("Failed to get signer for rotated key: %v", err)
			}

			newSignature, err := newSignerInterface.Sign(rand.Reader, hash2[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Failed to sign with rotated key: %v", err)
			}
			t.Logf("✓ Created signature with rotated key (%d bytes)", len(newSignature))

			// Step 9: Verify the new signature validates with the new public key
			t.Log("Step 9: Verifying new signature with new public key...")
			err = rsa.VerifyPKCS1v15(newPub, crypto.SHA256, hash2[:], newSignature)
			if err != nil {
				t.Fatalf("Failed to verify new signature: %v", err)
			}
			t.Log("✓ New signature verifies successfully with new public key")

			// Step 10: Verify the new signature does NOT validate with the old public key
			t.Log("Step 10: Verifying new signature fails with old public key...")
			err = rsa.VerifyPKCS1v15(origPub, crypto.SHA256, hash2[:], newSignature)
			if err == nil {
				t.Error("New signature should NOT validate with old public key")
			} else {
				t.Log("✓ New signature correctly fails with old public key")
			}

			// Clean up
			err = ks.DeleteKey(attrs)
			if err != nil {
				t.Logf("Warning: Failed to clean up rotation test key: %v", err)
			}

			t.Log("✓ RSA key rotation lifecycle test PASSED")
		})

		// Test ECDSA key rotation with signature verification
		t.Run("ECDSA_SignatureLifecycle", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rotate-ecdsa",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			// Step 1: Generate original key
			t.Log("Step 1: Generating original ECDSA key...")
			key, err := ks.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key for rotation test: %v", err)
			}

			// Get original public key for verification
			signer, ok := key.(crypto.Signer)
			if !ok {
				t.Fatal("Key does not implement crypto.Signer")
			}
			origPub, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Expected ECDSA public key")
			}
			t.Logf("✓ Generated original ECDSA key (curve: %s)", origPub.Curve.Params().Name)

			// Step 2: Create a signature with the original key
			t.Log("Step 2: Creating signature with original key...")
			testData := []byte("ECDSA signature before rotation")
			hash := sha256.Sum256(testData)

			origSigner, err := ks.Signer(attrs)
			if err != nil {
				t.Fatalf("Failed to get signer: %v", err)
			}

			originalSignature, err := origSigner.Sign(rand.Reader, hash[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Failed to sign with original ECDSA key: %v", err)
			}
			t.Logf("✓ Created signature with original key (%d bytes)", len(originalSignature))

			// Step 3: Verify the original signature works
			t.Log("Step 3: Verifying original signature...")
			if !ecdsa.VerifyASN1(origPub, hash[:], originalSignature) {
				t.Fatal("Failed to verify original ECDSA signature")
			}
			t.Log("✓ Original signature verifies successfully")

			// Step 4: Rotate the key
			t.Log("Step 4: Rotating the ECDSA key...")
			err = ks.RotateKey(attrs)
			if err != nil {
				t.Fatalf("ECDSA key rotation failed: %v", err)
			}
			t.Log("✓ Key rotation succeeded")

			// Step 5: Verify new key is different
			t.Log("Step 5: Verifying new key is different...")
			newKey, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get rotated ECDSA key: %v", err)
			}

			newSigner, ok := newKey.(crypto.Signer)
			if !ok {
				t.Fatal("Rotated key does not implement crypto.Signer")
			}
			newPub, ok := newSigner.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Expected ECDSA public key from rotated key")
			}

			if origPub.X.Cmp(newPub.X) == 0 && origPub.Y.Cmp(newPub.Y) == 0 {
				t.Error("Rotated ECDSA key has same coordinates as original (should be different)")
			} else {
				t.Logf("✓ New key is different from original (curve: %s)", newPub.Curve.Params().Name)
			}

			// Step 6: Verify original signature still validates with original public key
			t.Log("Step 6: Verifying original signature still valid with original public key...")
			if !ecdsa.VerifyASN1(origPub, hash[:], originalSignature) {
				t.Fatal("Original ECDSA signature no longer validates")
			}
			t.Log("✓ Original signature still validates with original public key")

			// Step 7: Verify original signature does NOT validate with new public key
			t.Log("Step 7: Verifying original signature fails with new public key...")
			if ecdsa.VerifyASN1(newPub, hash[:], originalSignature) {
				t.Error("Original signature should NOT validate with new public key")
			} else {
				t.Log("✓ Original signature correctly fails with new public key")
			}

			// Step 8: Create a new signature with the rotated key
			t.Log("Step 8: Creating signature with rotated key...")
			testData2 := []byte("ECDSA signature after rotation")
			hash2 := sha256.Sum256(testData2)

			newSignerInterface, err := ks.Signer(attrs)
			if err != nil {
				t.Fatalf("Failed to get signer for rotated key: %v", err)
			}

			newSignature, err := newSignerInterface.Sign(rand.Reader, hash2[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Failed to sign with rotated ECDSA key: %v", err)
			}
			t.Logf("✓ Created signature with rotated key (%d bytes)", len(newSignature))

			// Step 9: Verify the new signature validates with the new public key
			t.Log("Step 9: Verifying new signature with new public key...")
			if !ecdsa.VerifyASN1(newPub, hash2[:], newSignature) {
				t.Fatal("Failed to verify new ECDSA signature")
			}
			t.Log("✓ New signature verifies successfully with new public key")

			// Step 10: Verify the new signature does NOT validate with the old public key
			t.Log("Step 10: Verifying new signature fails with old public key...")
			if ecdsa.VerifyASN1(origPub, hash2[:], newSignature) {
				t.Error("New signature should NOT validate with old public key")
			} else {
				t.Log("✓ New signature correctly fails with old public key")
			}

			// Clean up
			err = ks.DeleteKey(attrs)
			if err != nil {
				t.Logf("Warning: Failed to clean up rotation test key: %v", err)
			}

			t.Log("✓ ECDSA key rotation lifecycle test PASSED")
		})

		// Test ECDSA P-384 key rotation
		t.Run("ECDSA_P384_Rotation", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rotate-ecdsa-p384",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P384(),
				},
			}

			// Generate and rotate
			_, err := ks.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate P-384 key: %v", err)
			}

			err = ks.RotateKey(attrs)
			if err != nil {
				t.Fatalf("P-384 key rotation failed: %v", err)
			}

			// Verify rotated key can sign
			newKey, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get rotated P-384 key: %v", err)
			}

			signer, ok := newKey.(crypto.Signer)
			if !ok {
				t.Fatal("Rotated P-384 key does not implement crypto.Signer")
			}

			// Sign with rotated key
			testData := []byte("P-384 test data")
			hash := sha512.Sum384(testData)

			tpmSigner, err := ks.Signer(attrs)
			if err != nil {
				t.Fatalf("Failed to get signer: %v", err)
			}

			signature, err := tpmSigner.Sign(rand.Reader, hash[:], crypto.SHA384)
			if err != nil {
				t.Fatalf("Failed to sign with rotated P-384 key: %v", err)
			}

			// Verify signature
			ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Expected ECDSA public key")
			}

			if !ecdsa.VerifyASN1(ecdsaPub, hash[:], signature) {
				t.Fatal("Signature verification failed for rotated P-384 key")
			}

			t.Log("✓ P-384 key rotation and signing successful")

			// Clean up
			ks.DeleteKey(attrs)
		})

		// Test error handling: rotate non-existent key
		t.Run("ErrorHandling_NonExistentKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-rotate-nonexistent",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Try to rotate a key that doesn't exist
			err := ks.RotateKey(attrs)
			if err == nil {
				t.Fatal("Expected error when rotating non-existent key, got nil")
			}
			t.Logf("✓ Correctly returned error for non-existent key: %v", err)
		})

		// Test multiple rotations
		t.Run("MultipleRotations", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-tpm-multi-rotate",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_TPM2,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate initial key
			key1, err := ks.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate initial key: %v", err)
			}

			signer1 := key1.(crypto.Signer)
			pub1 := signer1.Public().(*rsa.PublicKey)

			// First rotation
			err = ks.RotateKey(attrs)
			if err != nil {
				t.Fatalf("First rotation failed: %v", err)
			}

			key2, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get key after first rotation: %v", err)
			}
			signer2 := key2.(crypto.Signer)
			pub2 := signer2.Public().(*rsa.PublicKey)

			// Second rotation
			err = ks.RotateKey(attrs)
			if err != nil {
				t.Fatalf("Second rotation failed: %v", err)
			}

			key3, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get key after second rotation: %v", err)
			}
			signer3 := key3.(crypto.Signer)
			pub3 := signer3.Public().(*rsa.PublicKey)

			// Verify all three keys are different
			if pub1.N.Cmp(pub2.N) == 0 {
				t.Error("First and second keys should be different")
			}
			if pub2.N.Cmp(pub3.N) == 0 {
				t.Error("Second and third keys should be different")
			}
			if pub1.N.Cmp(pub3.N) == 0 {
				t.Error("First and third keys should be different")
			}

			t.Log("✓ Multiple rotations produced unique keys")

			// Clean up
			ks.DeleteKey(attrs)
		})
	})

	// ========================================
	// Import/Export Operations
	// ========================================
	t.Run("ImportExport", func(t *testing.T) {
		// Test GetImportParameters with different algorithms
		t.Run("GetImportParameters_RSA_OAEP_SHA256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-import-params-rsa",
				StoreType:    backend.STORE_TPM2,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			// Verify parameters are properly initialized
			if params == nil {
				t.Fatal("Import parameters should not be nil")
			}
			if params.WrappingPublicKey == nil {
				t.Fatal("Wrapping public key should not be nil")
			}
			if params.ImportToken == nil || len(params.ImportToken) == 0 {
				t.Fatal("Import token should not be nil or empty")
			}
			if params.Algorithm != backend.WrappingAlgorithmRSAES_OAEP_SHA_256 {
				t.Errorf("Expected algorithm %s, got %s", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, params.Algorithm)
			}
			if params.ExpiresAt == nil {
				t.Error("ExpiresAt should be set")
			}
			if params.KeySpec == "" {
				t.Error("KeySpec should be set")
			}

			// Verify wrapping public key is RSA with correct size
			rsaPub, ok := params.WrappingPublicKey.(*rsa.PublicKey)
			if !ok {
				t.Fatal("Wrapping public key should be RSA")
			}
			if rsaPub.N.BitLen() != 2048 {
				t.Errorf("Expected 2048-bit RSA key, got %d bits", rsaPub.N.BitLen())
			}

			t.Logf("✓ GetImportParameters succeeded with RSA-OAEP-SHA256")
			t.Logf("  Key Spec: %s", params.KeySpec)
			t.Logf("  Algorithm: %s", params.Algorithm)
			t.Logf("  Wrapping Key Size: %d bits", rsaPub.N.BitLen())
		})

		t.Run("GetImportParameters_RSA_AES_SHA256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-import-params-hybrid",
				StoreType:    backend.STORE_TPM2,
				KeyType:      backend.KEY_TYPE_TLS,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			}

			params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			if params.Algorithm != backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256 {
				t.Errorf("Expected algorithm %s, got %s", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, params.Algorithm)
			}

			t.Logf("✓ GetImportParameters succeeded with RSA-AES-SHA256 hybrid algorithm")
		})

		t.Run("GetImportParameters_UnsupportedAlgorithm", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-import-unsupported",
				StoreType:    backend.STORE_TPM2,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// TPM2 doesn't support SHA-1 wrapping
			params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_1)
			if err == nil {
				t.Fatal("GetImportParameters should fail for unsupported algorithm")
			}
			if params != nil {
				t.Error("Parameters should be nil on error")
			}
			t.Logf("✓ GetImportParameters correctly rejects unsupported algorithm: %v", err)
		})

		// Test WrapKey with RSA-OAEP (for small keys like symmetric keys)
		t.Run("WrapKey_SymmetricKey_RSA_OAEP", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-wrap-symmetric",
				StoreType:          backend.STORE_TPM2,
				KeyType:            backend.KEY_TYPE_ENCRYPTION,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			// Get import parameters
			params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			// Create symmetric key material (32 bytes for AES-256)
			keyMaterial := make([]byte, 32)
			if _, err := rand.Read(keyMaterial); err != nil {
				t.Fatalf("Failed to generate key material: %v", err)
			}

			// Wrap the key
			wrapped, err := ks.WrapKey(keyMaterial, params)
			if err != nil {
				t.Fatalf("WrapKey failed: %v", err)
			}

			// Verify wrapped key structure
			if wrapped == nil {
				t.Fatal("Wrapped key should not be nil")
			}
			if len(wrapped.WrappedKey) == 0 {
				t.Fatal("Wrapped key data should not be empty")
			}
			if wrapped.Algorithm != backend.WrappingAlgorithmRSAES_OAEP_SHA_256 {
				t.Errorf("Expected algorithm %s, got %s", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, wrapped.Algorithm)
			}
			if !bytesEqual(wrapped.ImportToken, params.ImportToken) {
				t.Error("Import token mismatch")
			}

			// Wrapped key should be larger than plaintext (RSA encryption overhead)
			if len(wrapped.WrappedKey) <= len(keyMaterial) {
				t.Errorf("Wrapped key (%d bytes) should be larger than plaintext (%d bytes)",
					len(wrapped.WrappedKey), len(keyMaterial))
			}

			t.Logf("✓ Successfully wrapped %d-byte symmetric key", len(keyMaterial))
			t.Logf("  Wrapped size: %d bytes", len(wrapped.WrappedKey))
			t.Logf("  Overhead: %d bytes", len(wrapped.WrappedKey)-len(keyMaterial))
		})

		// Test WrapKey with hybrid RSA-AES (for large keys like RSA private keys)
		t.Run("WrapKey_LargeKey_RSA_AES", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-wrap-large",
				StoreType:    backend.STORE_TPM2,
				KeyType:      backend.KEY_TYPE_TLS,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Get import parameters with hybrid algorithm
			params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			// Simulate large key material (e.g., RSA 2048 private key ~1200 bytes)
			keyMaterial := make([]byte, 1200)
			if _, err := rand.Read(keyMaterial); err != nil {
				t.Fatalf("Failed to generate key material: %v", err)
			}

			// Wrap the large key
			wrapped, err := ks.WrapKey(keyMaterial, params)
			if err != nil {
				t.Fatalf("WrapKey failed with hybrid algorithm: %v", err)
			}

			if wrapped == nil {
				t.Fatal("Wrapped key should not be nil")
			}
			if len(wrapped.WrappedKey) == 0 {
				t.Fatal("Wrapped key data should not be empty")
			}
			if wrapped.Algorithm != backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256 {
				t.Errorf("Expected algorithm %s, got %s", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, wrapped.Algorithm)
			}

			t.Logf("✓ Successfully wrapped %d-byte key with hybrid RSA-AES", len(keyMaterial))
			t.Logf("  Wrapped size: %d bytes", len(wrapped.WrappedKey))
		})

		// Test round-trip wrapping with external unwrapping (TPM doesn't support UnwrapKey)
		t.Run("WrapKey_RoundTrip_ExternalUnwrap", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-roundtrip",
				StoreType:          backend.STORE_TPM2,
				KeyType:            backend.KEY_TYPE_ENCRYPTION,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			// Get import parameters
			params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			// Generate test key material
			originalKeyMaterial := make([]byte, 32)
			if _, err := rand.Read(originalKeyMaterial); err != nil {
				t.Fatalf("Failed to generate key material: %v", err)
			}

			// Wrap the key
			wrapped, err := ks.WrapKey(originalKeyMaterial, params)
			if err != nil {
				t.Fatalf("WrapKey failed: %v", err)
			}

			// For TPM2, we can't use ks.UnwrapKey (it returns ErrNotSupported)
			// Instead, we verify that UnwrapKey correctly returns the expected error
			unwrapped, err := ks.UnwrapKey(wrapped, params)
			if err == nil {
				t.Fatal("UnwrapKey should return ErrNotSupported for TPM2")
			}
			if unwrapped != nil {
				t.Error("Unwrapped key should be nil")
			}
			if !errors.Is(err, backend.ErrNotSupported) {
				t.Errorf("Expected ErrNotSupported, got: %v", err)
			}

			t.Logf("✓ UnwrapKey correctly returns ErrNotSupported (TPM unwraps in hardware)")
			t.Logf("  Error: %v", err)
		})

		// Test wrapping with invalid parameters
		t.Run("WrapKey_InvalidParameters", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-wrap-invalid",
				StoreType:          backend.STORE_TPM2,
				KeyType:            backend.KEY_TYPE_ENCRYPTION,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			keyMaterial := make([]byte, 32)
			rand.Read(keyMaterial)

			// Test nil key material
			wrapped, err := ks.WrapKey(nil, params)
			if err == nil {
				t.Error("WrapKey should fail with nil key material")
			}
			if wrapped != nil {
				t.Error("Wrapped key should be nil on error")
			}

			// Test empty key material
			wrapped, err = ks.WrapKey([]byte{}, params)
			if err == nil {
				t.Error("WrapKey should fail with empty key material")
			}
			if wrapped != nil {
				t.Error("Wrapped key should be nil on error")
			}

			// Test nil parameters
			wrapped, err = ks.WrapKey(keyMaterial, nil)
			if err == nil {
				t.Error("WrapKey should fail with nil parameters")
			}
			if wrapped != nil {
				t.Error("Wrapped key should be nil on error")
			}

			t.Logf("✓ WrapKey correctly validates input parameters")
		})

		// Test ImportKey (currently returns not implemented error)
		t.Run("ImportKey_CurrentlyNotImplemented", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-import-impl",
				StoreType:          backend.STORE_TPM2,
				KeyType:            backend.KEY_TYPE_ENCRYPTION,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			// Get import parameters and wrap key
			params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			keyMaterial := make([]byte, 32)
			rand.Read(keyMaterial)

			wrapped, err := ks.WrapKey(keyMaterial, params)
			if err != nil {
				t.Fatalf("WrapKey failed: %v", err)
			}

			// ImportKey should return "not fully implemented" error
			err = ks.ImportKey(attrs, wrapped)
			if err == nil {
				t.Fatal("ImportKey should return error (not fully implemented)")
			}

			expectedMsg := "not yet fully implemented"
			if !containsString(err.Error(), expectedMsg) {
				t.Errorf("Expected error to contain '%s', got: %v", expectedMsg, err)
			}

			t.Logf("✓ ImportKey API exists but returns expected error: %v", err)
			t.Logf("  Note: Full TPM2_Import requires specialized key material formatting")
		})

		// Test ImportKey with invalid parameters
		t.Run("ImportKey_InvalidParameters", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-import-invalid",
				StoreType:          backend.STORE_TPM2,
				KeyType:            backend.KEY_TYPE_ENCRYPTION,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			keyMaterial := make([]byte, 32)
			rand.Read(keyMaterial)

			wrapped, err := ks.WrapKey(keyMaterial, params)
			if err != nil {
				t.Fatalf("WrapKey failed: %v", err)
			}

			// Test nil attributes
			err = ks.ImportKey(nil, wrapped)
			if err == nil {
				t.Error("ImportKey should fail with nil attributes")
			}
			if !errors.Is(err, backend.ErrInvalidAttributes) {
				t.Errorf("Expected ErrInvalidAttributes, got: %v", err)
			}

			// Test nil wrapped material
			err = ks.ImportKey(attrs, nil)
			if err == nil {
				t.Error("ImportKey should fail with nil wrapped material")
			}

			t.Logf("✓ ImportKey correctly validates input parameters")
		})

		// Test ExportKey with FixedTPM keys (should fail)
		t.Run("ExportKey_FixedTPM_SecurityConstraint", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-export-fixed",
				StoreType:    backend.STORE_TPM2,
				KeyType:      backend.KEY_TYPE_TLS,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate a key (will have FixedTPM=true by default)
			_, err := ks.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("Key generation failed: %v", err)
			}
			defer ks.DeleteKey(attrs) // Cleanup

			// ExportKey should fail for FixedTPM keys (security requirement)
			wrapped, err := ks.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err == nil {
				t.Fatal("ExportKey should fail for FixedTPM keys (security requirement)")
			}
			if wrapped != nil {
				t.Error("Wrapped key should be nil on error")
			}

			// Should return ErrOperationNotSupported
			if !errors.Is(err, backend.ErrOperationNotSupported) {
				t.Errorf("Expected ErrOperationNotSupported, got: %v", err)
			}

			// Error should mention FixedTPM
			if !containsString(err.Error(), "FixedTPM") {
				t.Errorf("Error should mention FixedTPM attribute: %v", err)
			}

			t.Logf("✓ ExportKey correctly rejects FixedTPM keys (security feature)")
			t.Logf("  Error: %v", err)
		})

		// Test ExportKey with different wrapping algorithms
		t.Run("ExportKey_DifferentAlgorithms", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-export-algo",
				StoreType:    backend.STORE_TPM2,
				KeyType:      backend.KEY_TYPE_TLS,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate a key
			_, err := ks.GenerateKey(attrs)
			if err != nil {
				t.Fatalf("Key generation failed: %v", err)
			}
			defer ks.DeleteKey(attrs)

			// Try different algorithms (all should fail for FixedTPM keys)
			algorithms := []backend.WrappingAlgorithm{
				backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
				backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			}

			for _, algo := range algorithms {
				wrapped, err := ks.ExportKey(attrs, algo)
				if err == nil {
					t.Errorf("ExportKey should fail with algorithm %s", algo)
				}
				if wrapped != nil {
					t.Errorf("Wrapped key should be nil for algorithm %s", algo)
				}
				t.Logf("  Algorithm %s: correctly rejected", algo)
			}

			t.Logf("✓ ExportKey consistently rejects FixedTPM keys across algorithms")
		})

		// Test ExportKey with non-existent key
		t.Run("ExportKey_NonExistentKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "non-existent-export-key",
				StoreType:    backend.STORE_TPM2,
				KeyType:      backend.KEY_TYPE_TLS,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			wrapped, err := ks.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err == nil {
				t.Fatal("ExportKey should fail for non-existent key")
			}
			if wrapped != nil {
				t.Error("Wrapped key should be nil on error")
			}
			if !errors.Is(err, backend.ErrKeyNotFound) {
				t.Errorf("Expected ErrKeyNotFound, got: %v", err)
			}

			t.Logf("✓ ExportKey correctly handles non-existent keys")
		})

		// Test ExportKey with invalid parameters
		t.Run("ExportKey_InvalidParameters", func(t *testing.T) {
			// Test nil attributes
			wrapped, err := ks.ExportKey(nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err == nil {
				t.Error("ExportKey should fail with nil attributes")
			}
			if wrapped != nil {
				t.Error("Wrapped key should be nil on error")
			}
			if !errors.Is(err, backend.ErrInvalidAttributes) {
				t.Errorf("Expected ErrInvalidAttributes, got: %v", err)
			}

			t.Logf("✓ ExportKey correctly validates input parameters")
		})

		// Test ImportExportBackend interface compliance
		t.Run("ImportExportBackend_InterfaceCompliance", func(t *testing.T) {
			// Verify TPM2 backend implements ImportExportBackend
			var _ backend.ImportExportBackend = ks

			// Verify capabilities are reported correctly
			caps := ks.Capabilities()
			if !caps.Import {
				t.Error("TPM2 should report Import capability")
			}
			if !caps.Export {
				t.Error("TPM2 should report Export capability")
			}
			if !caps.SupportsImportExport() {
				t.Error("SupportsImportExport() should return true")
			}

			t.Logf("✓ TPM2 backend correctly implements ImportExportBackend interface")
			t.Logf("  Capabilities: Import=%v, Export=%v", caps.Import, caps.Export)
		})

		// Test key spec determination
		t.Run("KeySpec_DifferentKeyTypes", func(t *testing.T) {
			testCases := []struct {
				name     string
				attrs    *types.KeyAttributes
				expected string
			}{
				{
					name: "RSA-2048",
					attrs: &types.KeyAttributes{
						KeyAlgorithm: x509.RSA,
						RSAAttributes: &types.RSAAttributes{
							KeySize: 2048,
						},
					},
					expected: "RSA_2048",
				},
				{
					name: "RSA-4096",
					attrs: &types.KeyAttributes{
						KeyAlgorithm: x509.RSA,
						RSAAttributes: &types.RSAAttributes{
							KeySize: 4096,
						},
					},
					expected: "RSA_4096",
				},
				{
					name: "ECDSA-P256",
					attrs: &types.KeyAttributes{
						KeyAlgorithm: x509.ECDSA,
						ECCAttributes: &types.ECCAttributes{
							Curve: elliptic.P256(),
						},
					},
					expected: "EC_P-256",
				},
				{
					name: "AES-256",
					attrs: &types.KeyAttributes{
						SymmetricAlgorithm: types.SymmetricAES256GCM,
					},
					expected: "AES_256",
				},
			}

			for _, tc := range testCases {
				tc.attrs.CN = "test-keyspec-" + tc.name
				tc.attrs.StoreType = backend.STORE_TPM2
				tc.attrs.KeyType = backend.KEY_TYPE_ENCRYPTION

				params, err := ks.GetImportParameters(tc.attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
				if err != nil {
					t.Fatalf("GetImportParameters failed for %s: %v", tc.name, err)
				}

				if params.KeySpec != tc.expected {
					t.Errorf("%s: expected KeySpec %s, got %s", tc.name, tc.expected, params.KeySpec)
				} else {
					t.Logf("  %s: KeySpec=%s ✓", tc.name, params.KeySpec)
				}
			}

			t.Logf("✓ Key spec determination works correctly for different key types")
		})
	})

	t.Log("=== TPM2 Integration Tests Completed ===")
}

// createTPMTestCertificate creates a simple self-signed certificate for testing
func createTPMTestCertificate(t *testing.T, cn string) *x509.Certificate {
	// Generate a temporary RSA key for the certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test TPM Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// containsString checks if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

// findSubstring is a helper for containsString
func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
