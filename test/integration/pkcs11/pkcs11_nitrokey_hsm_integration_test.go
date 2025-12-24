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

//go:build integration && nitrokey && pkcs11
// +build integration,nitrokey,pkcs11

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
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNitrokeyHSM tests the Nitrokey HSM integration with the PKCS#11 backend
// This test requires a physical Nitrokey HSM device to be connected
//
// To run this test:
//
//	go test -v -tags="integration && nitrokey && pkcs11" ./test/integration/pkcs11 -run TestNitrokeyHSM
//
// Prerequisites:
//  1. Nitrokey HSM device connected
//  2. OpenSC installed (opensc-pkcs11.so)
//  3. Device initialized with PIN: 648219
//  4. Library path: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
func TestNitrokeyHSM(t *testing.T) {
	// Check if OpenSC library exists
	libPath := "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		t.Fatal("Nitrokey HSM tests require OpenSC PKCS#11 library")
	}

	// Create storage backends
	keyStorage := storage.New()
	certStorageBackend := storage.New()

	// Create PKCS11 backend configuration for Nitrokey HSM
	// The Nitrokey HSM uses the "SmartCard-HSM" token label by default
	// We initialized it with label "go-keychain-test (UserPIN)"
	config := &pkcs11.Config{
		Library:     libPath,
		TokenLabel:  "go-keychain-test (UserPIN)",
		PIN:         "648219",
		KeyStorage:  keyStorage,
		CertStorage: certStorageBackend,
	}

	// Create backend
	backend, err := pkcs11.NewBackend(config)
	require.NoError(t, err, "Failed to create PKCS#11 backend for Nitrokey HSM")
	defer backend.Close()

	// Initialize backend
	// Nitrokey HSM is already initialized, so we use the default SO PIN: 3537363231383830
	// This SO PIN is only needed for initialization, not for regular operations
	err = backend.Initialize("3537363231383830", "648219")
	if err != nil && err != pkcs11.ErrAlreadyInitialized {
		t.Fatalf("Failed to initialize Nitrokey HSM backend: %v", err)
	}

	t.Log("✓ Nitrokey HSM backend initialized successfully")

	// Run test suites
	t.Run("GenerateAndSign_RSA2048_PKCS1v15", func(t *testing.T) {
		testNitrokeyRSA_PKCS1v15(t, backend, 2048)
	})

	t.Run("GenerateAndSign_RSA2048_PSS", func(t *testing.T) {
		testNitrokeyRSA_PSS(t, backend, 2048)
	})

	t.Run("GenerateAndSign_RSA3072_PKCS1v15", func(t *testing.T) {
		testNitrokeyRSA_PKCS1v15(t, backend, 3072)
	})

	t.Run("GenerateAndSign_RSA3072_PSS", func(t *testing.T) {
		testNitrokeyRSA_PSS(t, backend, 3072)
	})

	t.Run("GenerateAndSign_RSA4096_PKCS1v15", func(t *testing.T) {
		testNitrokeyRSA_PKCS1v15(t, backend, 4096)
	})

	t.Run("GenerateAndSign_RSA4096_PSS", func(t *testing.T) {
		testNitrokeyRSA_PSS(t, backend, 4096)
	})

	t.Run("GenerateAndSign_ECDSA_P256", func(t *testing.T) {
		testNitrokeyECDSA(t, backend, elliptic.P256())
	})

	t.Run("GenerateAndSign_ECDSA_P384", func(t *testing.T) {
		testNitrokeyECDSA(t, backend, elliptic.P384())
	})

	t.Run("GenerateAndSign_ECDSA_P521", func(t *testing.T) {
		testNitrokeyECDSA(t, backend, elliptic.P521())
	})

	t.Run("GenerateRandom_32bytes", func(t *testing.T) {
		testNitrokeyRandom(t, backend, 32)
	})

	t.Run("GenerateRandom_64bytes", func(t *testing.T) {
		testNitrokeyRandom(t, backend, 64)
	})

	t.Run("GenerateRandom_256bytes", func(t *testing.T) {
		testNitrokeyRandom(t, backend, 256)
	})

	// RSA Encryption/Decryption Tests
	t.Run("RSAEncryptDecrypt", func(t *testing.T) {
		testNitrokeyRSAEncryptDecrypt(t, backend)
	})

	t.Run("CertificateStorage_Hardware", func(t *testing.T) {
		testNitrokeyCertificateStorageHardware(t, backend)
	})
}

func testNitrokeyRSA_PKCS1v15(t *testing.T, backend *pkcs11.Backend, keySize int) {
	// Clean up any existing key first
	attrs := &types.KeyAttributes{
		CN:           "nitrokey-rsa-test",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: keySize,
		},
	}

	// Try to delete existing key (ignore error if it doesn't exist)
	_ = backend.DeleteKey(attrs)

	// Generate RSA key
	t.Logf("Generating RSA %d key on Nitrokey HSM...", keySize)
	key, err := backend.GenerateRSA(attrs)
	require.NoError(t, err, "Failed to generate RSA key")
	require.NotNil(t, key, "Generated key is nil")

	// Verify it's an RSA key
	rsaPubKey, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok, "Generated key is not an RSA public key")
	assert.Equal(t, keySize, rsaPubKey.N.BitLen(), "Key size mismatch")

	// Test signing
	message := []byte("test message for nitrokey hsm signing")
	digest := sha256.Sum256(message)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok, "Key does not implement crypto.Signer")

	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err, "Failed to sign message")
	require.NotEmpty(t, signature, "Signature is empty")

	// Verify signature
	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest[:], signature)
	require.NoError(t, err, "Signature verification failed")

	t.Logf("✓ RSA %d key generation, signing (PKCS#1 v1.5), and verification successful", keySize)

	// Clean up
	err = backend.DeleteKey(attrs)
	require.NoError(t, err, "Failed to delete key")
}

func testNitrokeyRSA_PSS(t *testing.T, backend *pkcs11.Backend, keySize int) {
	// Clean up any existing key first
	attrs := &types.KeyAttributes{
		CN:           "nitrokey-rsa-pss-test",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: keySize,
		},
	}

	// Try to delete existing key (ignore error if it doesn't exist)
	_ = backend.DeleteKey(attrs)

	// Generate RSA key
	t.Logf("Generating RSA %d key on Nitrokey HSM for PSS testing...", keySize)
	key, err := backend.GenerateRSA(attrs)
	require.NoError(t, err, "Failed to generate RSA key")
	require.NotNil(t, key, "Generated key is nil")

	// Verify it's an RSA key
	rsaPubKey, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok, "Generated key is not an RSA public key")
	assert.Equal(t, keySize, rsaPubKey.N.BitLen(), "Key size mismatch")

	// Test signing with RSA-PSS
	message := []byte("test message for nitrokey hsm RSA-PSS signing")
	h := sha256.New()
	h.Write(message)
	digest := h.Sum(nil)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok, "Key does not implement crypto.Signer")

	// Sign with PSS options
	// Note: crypto11 doesn't support PSSSaltLengthAuto, use PSSSaltLengthEqualsHash
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}

	signature, err := signer.Sign(rand.Reader, digest, pssOpts)
	require.NoError(t, err, "Failed to sign message with PSS")
	require.NotEmpty(t, signature, "Signature is empty")

	// Verify PSS signature
	err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, digest, signature, pssOpts)
	require.NoError(t, err, "PSS signature verification failed")

	t.Logf("✓ RSA %d key generation, signing (PSS), and verification successful", keySize)

	// Clean up
	err = backend.DeleteKey(attrs)
	require.NoError(t, err, "Failed to delete key")
}

func testNitrokeyECDSA(t *testing.T, backend *pkcs11.Backend, curve elliptic.Curve) {
	curveName := "P256"
	switch curve {
	case elliptic.P384():
		curveName = "P384"
	case elliptic.P521():
		curveName = "P521"
	}

	// Clean up any existing key first
	attrs := &types.KeyAttributes{
		CN:           "nitrokey-ecdsa-test",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: curve,
		},
	}

	// Try to delete existing key (ignore error if it doesn't exist)
	_ = backend.DeleteKey(attrs)

	// Generate ECDSA key
	t.Logf("Generating ECDSA %s key on Nitrokey HSM...", curveName)
	key, err := backend.GenerateECDSA(attrs)
	require.NoError(t, err, "Failed to generate ECDSA key")
	require.NotNil(t, key, "Generated key is nil")

	// Verify it's an ECDSA key
	ecdsaPubKey, ok := key.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "Generated key is not an ECDSA public key")
	assert.Equal(t, curve, ecdsaPubKey.Curve, "Curve mismatch")

	// Test signing
	message := []byte("test message for nitrokey hsm ecdsa signing")
	digest := sha256.Sum256(message)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok, "Key does not implement crypto.Signer")

	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err, "Failed to sign message")
	require.NotEmpty(t, signature, "Signature is empty")

	// Verify signature
	verified := ecdsa.VerifyASN1(ecdsaPubKey, digest[:], signature)
	require.True(t, verified, "ECDSA signature verification failed")

	t.Logf("✓ ECDSA %s key generation, signing, and verification successful", curveName)

	// Clean up
	err = backend.DeleteKey(attrs)
	require.NoError(t, err, "Failed to delete key")
}

func testNitrokeyRandom(t *testing.T, backend *pkcs11.Backend, length int) {
	random, err := backend.GenerateRandom(length)
	require.NoError(t, err, "Failed to generate random bytes")
	assert.Len(t, random, length, "Random bytes length mismatch")

	// Check that bytes are not all zeros
	allZeros := true
	for _, b := range random {
		if b != 0 {
			allZeros = false
			break
		}
	}
	assert.False(t, allZeros, "Random bytes should not be all zeros")

	// Generate again and ensure different results
	random2, err := backend.GenerateRandom(length)
	require.NoError(t, err, "Failed to generate second random bytes")
	assert.NotEqual(t, random, random2, "Consecutive random generations should produce different results")

	t.Logf("✓ Generated %d random bytes from Nitrokey HSM hardware RNG", length)
}

func testNitrokeyCertificateStorageHardware(t *testing.T, backend *pkcs11.Backend) {
	// Trigger p11ctx initialization by calling GenerateRandom
	// (p11ctx is lazily initialized on first use)
	_, err := backend.GenerateRandom(1)
	require.NoError(t, err, "Failed to initialize p11ctx")

	// Create HARDWARE-backed certificate storage on the Nitrokey HSM
	certConfig := &pkcs11.CertStorageConfig{
		Mode:                  hardware.CertStorageModeHardware,
		EnableHardwareStorage: true, // Enable HSM hardware certificate storage
		MaxCertificates:       100,  // Limit to prevent token exhaustion
	}

	certStorageBackend, err := backend.CreateCertificateStorage(certConfig)
	require.NoError(t, err, "Failed to create hardware certificate storage")
	defer certStorageBackend.Close()
	certStorage := storage.NewCertAdapter(certStorageBackend)

	t.Log("✓ Created hardware-backed certificate storage on Nitrokey HSM (stores certs ON the HSM)")

	t.Run("SaveAndGetCert", func(t *testing.T) {
		// Generate a key to create a certificate with
		attrs := &types.KeyAttributes{
			CN:           "nitrokey-cert-test",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing key
		_ = backend.DeleteKey(attrs)

		// Generate key
		key, err := backend.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to generate RSA key")
		defer backend.DeleteKey(attrs)

		// Create self-signed certificate
		cert := createNitrokeyTestCertificate(t, key, "Nitrokey HSM Test Cert")

		// Save certificate
		certID := "nitrokey-test-cert-1"
		err = certStorage.SaveCert(certID, cert)
		require.NoError(t, err, "Failed to save certificate")

		// Retrieve certificate
		retrievedCert, err := certStorage.GetCert(certID)
		require.NoError(t, err, "Failed to retrieve certificate")
		require.NotNil(t, retrievedCert, "Retrieved certificate is nil")

		// Verify certificate matches
		assert.Equal(t, cert.Subject.CommonName, retrievedCert.Subject.CommonName)
		assert.Equal(t, cert.SerialNumber, retrievedCert.SerialNumber)
		assert.Equal(t, cert.Raw, retrievedCert.Raw)

		t.Log("✓ Certificate saved and retrieved successfully")

		// Clean up
		err = certStorage.DeleteCert(certID)
		require.NoError(t, err, "Failed to delete certificate")
	})

	t.Run("CertExists", func(t *testing.T) {
		// Generate a key to create a certificate with
		attrs := &types.KeyAttributes{
			CN:           "nitrokey-cert-exists-test",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing key
		_ = backend.DeleteKey(attrs)

		// Generate key
		key, err := backend.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to generate RSA key")
		defer backend.DeleteKey(attrs)

		// Create certificate
		cert := createNitrokeyTestCertificate(t, key, "Nitrokey Exists Test")

		certID := "nitrokey-exists-test"

		// Should not exist initially
		exists, err := certStorage.CertExists(certID)
		require.NoError(t, err, "Failed to check certificate existence")
		assert.False(t, exists, "Certificate should not exist initially")

		// Save certificate
		err = certStorage.SaveCert(certID, cert)
		require.NoError(t, err, "Failed to save certificate")

		// Should exist now
		exists, err = certStorage.CertExists(certID)
		require.NoError(t, err, "Failed to check certificate existence")
		assert.True(t, exists, "Certificate should exist after saving")

		t.Log("✓ Certificate existence check successful")

		// Clean up
		err = certStorage.DeleteCert(certID)
		require.NoError(t, err, "Failed to delete certificate")

		// Should not exist after deletion
		exists, err = certStorage.CertExists(certID)
		require.NoError(t, err, "Failed to check certificate existence")
		assert.False(t, exists, "Certificate should not exist after deletion")
	})

	t.Run("DeleteCert", func(t *testing.T) {
		// Generate a key to create a certificate with
		attrs := &types.KeyAttributes{
			CN:           "nitrokey-cert-delete-test",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing key
		_ = backend.DeleteKey(attrs)

		// Generate key
		key, err := backend.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to generate RSA key")
		defer backend.DeleteKey(attrs)

		// Create certificate
		cert := createNitrokeyTestCertificate(t, key, "Nitrokey Delete Test")

		certID := "nitrokey-delete-test"

		// Save certificate
		err = certStorage.SaveCert(certID, cert)
		require.NoError(t, err, "Failed to save certificate")

		// Verify it exists
		exists, err := certStorage.CertExists(certID)
		require.NoError(t, err, "Failed to check certificate existence")
		assert.True(t, exists, "Certificate should exist after saving")

		// Delete certificate
		err = certStorage.DeleteCert(certID)
		require.NoError(t, err, "Failed to delete certificate")

		// Verify it's gone
		exists, err = certStorage.CertExists(certID)
		require.NoError(t, err, "Failed to check certificate existence")
		assert.False(t, exists, "Certificate should not exist after deletion")

		// Try to retrieve it (should fail)
		_, err = certStorage.GetCert(certID)
		assert.Error(t, err, "Getting deleted certificate should return error")

		t.Log("✓ Certificate deletion successful")
	})

	t.Run("OverwriteCert", func(t *testing.T) {
		// Generate keys to create certificates with
		attrs1 := &types.KeyAttributes{
			CN:           "nitrokey-cert-overwrite-test-1",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		attrs2 := &types.KeyAttributes{
			CN:           "nitrokey-cert-overwrite-test-2",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing keys
		_ = backend.DeleteKey(attrs1)
		_ = backend.DeleteKey(attrs2)

		// Generate keys
		key1, err := backend.GenerateRSA(attrs1)
		require.NoError(t, err, "Failed to generate first RSA key")
		defer backend.DeleteKey(attrs1)

		key2, err := backend.GenerateRSA(attrs2)
		require.NoError(t, err, "Failed to generate second RSA key")
		defer backend.DeleteKey(attrs2)

		// Create two different certificates
		cert1 := createNitrokeyTestCertificate(t, key1, "Nitrokey Cert 1")
		cert2 := createNitrokeyTestCertificate(t, key2, "Nitrokey Cert 2")

		certID := "nitrokey-overwrite-test"

		// Save first certificate
		err = certStorage.SaveCert(certID, cert1)
		require.NoError(t, err, "Failed to save first certificate")

		// Save second certificate with same ID (overwrite)
		err = certStorage.SaveCert(certID, cert2)
		require.NoError(t, err, "Failed to overwrite certificate")

		// Retrieve certificate
		retrievedCert, err := certStorage.GetCert(certID)
		require.NoError(t, err, "Failed to retrieve certificate")

		// Verify it's the second certificate
		assert.Equal(t, cert2.Subject.CommonName, retrievedCert.Subject.CommonName)
		assert.Equal(t, "Nitrokey Cert 2", retrievedCert.Subject.CommonName)

		t.Log("✓ Certificate overwrite successful")

		// Clean up
		err = certStorage.DeleteCert(certID)
		require.NoError(t, err, "Failed to delete certificate")
	})

	t.Run("ListCerts", func(t *testing.T) {
		// Generate a key to create certificates with
		attrs := &types.KeyAttributes{
			CN:           "nitrokey-cert-list-test",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing key
		_ = backend.DeleteKey(attrs)

		// Generate key
		key, err := backend.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to generate RSA key")
		defer backend.DeleteKey(attrs)

		// Create and save multiple certificates
		certIDs := []string{
			"nitrokey-list-cert-1",
			"nitrokey-list-cert-2",
			"nitrokey-list-cert-3",
		}

		for i, certID := range certIDs {
			cert := createNitrokeyTestCertificate(t, key, "Nitrokey List Cert "+string(rune('A'+i)))
			err = certStorage.SaveCert(certID, cert)
			require.NoError(t, err, "Failed to save certificate %s", certID)
		}

		// List certificates
		certList, err := certStorage.ListCerts()
		require.NoError(t, err, "Failed to list certificates")

		// Verify our certificates are in the list
		for _, certID := range certIDs {
			found := false
			for _, listedID := range certList {
				if listedID == certID {
					found = true
					break
				}
			}
			assert.True(t, found, "Certificate %s should be in list", certID)
		}

		t.Logf("✓ Listed %d certificates, found all test certificates", len(certList))

		// Clean up
		for _, certID := range certIDs {
			err = certStorage.DeleteCert(certID)
			require.NoError(t, err, "Failed to delete certificate %s", certID)
		}
	})

	t.Run("CertificateChains", func(t *testing.T) {
		// Generate keys to create certificates with
		attrs1 := &types.KeyAttributes{
			CN:           "nitrokey-chain-root",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		attrs2 := &types.KeyAttributes{
			CN:           "nitrokey-chain-intermediate",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		attrs3 := &types.KeyAttributes{
			CN:           "nitrokey-chain-leaf",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing keys
		_ = backend.DeleteKey(attrs1)
		_ = backend.DeleteKey(attrs2)
		_ = backend.DeleteKey(attrs3)

		// Generate keys
		key1, err := backend.GenerateRSA(attrs1)
		require.NoError(t, err, "Failed to generate root key")
		defer backend.DeleteKey(attrs1)

		key2, err := backend.GenerateRSA(attrs2)
		require.NoError(t, err, "Failed to generate intermediate key")
		defer backend.DeleteKey(attrs2)

		key3, err := backend.GenerateRSA(attrs3)
		require.NoError(t, err, "Failed to generate leaf key")
		defer backend.DeleteKey(attrs3)

		// Create certificate chain
		rootCert := createNitrokeyTestCertificate(t, key1, "Nitrokey Root CA")
		intermediateCert := createNitrokeyTestCertificate(t, key2, "Nitrokey Intermediate CA")
		leafCert := createNitrokeyTestCertificate(t, key3, "Nitrokey Leaf Cert")

		chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}
		chainID := "nitrokey-test-chain"

		// Try to save certificate chain
		err = certStorage.SaveCertChain(chainID, chain)
		if err != nil {
			t.Logf("⚠ Certificate chain storage not supported: %v, skipping chain tests", err)
			return
		}

		// Retrieve certificate chain
		retrievedChain, err := certStorage.GetCertChain(chainID)
		require.NoError(t, err, "Failed to retrieve certificate chain")
		require.Len(t, retrievedChain, 3, "Certificate chain should have 3 certificates")

		// Verify certificates in chain
		assert.Equal(t, leafCert.Subject.CommonName, retrievedChain[0].Subject.CommonName)
		assert.Equal(t, intermediateCert.Subject.CommonName, retrievedChain[1].Subject.CommonName)
		assert.Equal(t, rootCert.Subject.CommonName, retrievedChain[2].Subject.CommonName)

		t.Log("✓ Certificate chain saved and retrieved successfully")

		// Clean up
		err = certStorage.DeleteCert(chainID)
		require.NoError(t, err, "Failed to delete certificate chain")
	})
}

// testNitrokeyRSAEncryptDecrypt tests RSA encryption and decryption operations
func testNitrokeyRSAEncryptDecrypt(t *testing.T, backend *pkcs11.Backend) {
	t.Run("RSA-2048_PKCS1v15_EncryptDecrypt", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "nitrokey-rsa-2048-encrypt",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing key
		_ = backend.DeleteKey(attrs)

		t.Log("Generating RSA 2048 key on Nitrokey HSM for encryption...")
		key, err := backend.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to generate RSA key")
		defer backend.DeleteKey(attrs)

		// Get the public key for encryption
		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "Key must implement crypto.Signer")

		rsaPub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key must be RSA")

		// Encrypt a message with PKCS#1 v1.5
		plaintext := []byte("Secret message for Nitrokey HSM encryption test with PKCS#1 v1.5 padding")
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext)
		require.NoError(t, err, "Failed to encrypt with PKCS#1 v1.5")
		t.Logf("✓ Encrypted %d bytes with RSA-2048 PKCS#1 v1.5 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

		// Get Decrypter interface
		decrypter, err := backend.Decrypter(attrs)
		require.NoError(t, err, "Failed to get Decrypter")

		// Decrypt using Nitrokey HSM
		decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
		require.NoError(t, err, "Failed to decrypt with Nitrokey HSM")

		// Verify decrypted matches original
		assert.Equal(t, plaintext, decrypted, "Decrypted plaintext must match original")
		t.Logf("✓ Decrypted %d bytes successfully, plaintext matches", len(decrypted))
	})

	t.Run("RSA-2048_OAEP_SHA256_EncryptDecrypt", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "nitrokey-rsa-2048-oaep",
			KeyAlgorithm: x509.RSA,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing key
		_ = backend.DeleteKey(attrs)

		t.Log("Generating RSA 2048 key on Nitrokey HSM for OAEP encryption...")
		key, err := backend.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to generate RSA key")
		defer backend.DeleteKey(attrs)

		// Get the public key for encryption
		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "Key must implement crypto.Signer")

		rsaPub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key must be RSA")

		// Encrypt with RSA-OAEP SHA256
		plaintext := []byte("Secret message for Nitrokey HSM with RSA-OAEP SHA-256 padding")
		label := []byte("")
		ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, plaintext, label)
		require.NoError(t, err, "Failed to encrypt with OAEP SHA256")
		t.Logf("✓ Encrypted %d bytes with RSA-OAEP SHA256 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

		// Get Decrypter interface
		decrypter, err := backend.Decrypter(attrs)
		require.NoError(t, err, "Failed to get Decrypter")

		// Decrypt using Nitrokey HSM with OAEP options
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
			CN:           "nitrokey-rsa-3072-oaep",
			KeyAlgorithm: x509.RSA,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 3072,
			},
		}

		// Clean up any existing key
		_ = backend.DeleteKey(attrs)

		t.Log("Generating RSA 3072 key on Nitrokey HSM for OAEP encryption...")
		key, err := backend.GenerateRSA(attrs)
		require.NoError(t, err, "Failed to generate RSA key")
		defer backend.DeleteKey(attrs)

		// Get the public key for encryption
		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "Key must implement crypto.Signer")

		rsaPub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key must be RSA")

		// Encrypt with RSA-OAEP SHA256
		plaintext := []byte("Secret message for Nitrokey HSM RSA-3072 with OAEP padding")
		label := []byte("")
		ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, plaintext, label)
		require.NoError(t, err, "Failed to encrypt with OAEP SHA256")
		t.Logf("✓ Encrypted %d bytes with RSA-3072-OAEP SHA256 (ciphertext: %d bytes)", len(plaintext), len(ciphertext))

		// Get Decrypter interface
		decrypter, err := backend.Decrypter(attrs)
		require.NoError(t, err, "Failed to get Decrypter")

		// Decrypt using Nitrokey HSM with OAEP options
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

func createNitrokeyTestCertificate(t *testing.T, key crypto.Signer, cn string) *x509.Certificate {
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000))
	require.NoError(t, err, "Failed to generate serial number")

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Nitrokey Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err, "Failed to create certificate")

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err, "Failed to parse certificate")

	return cert
}
