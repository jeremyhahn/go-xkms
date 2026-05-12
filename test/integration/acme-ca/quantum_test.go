// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration && quantum

package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/jeremyhahn/go-objstore/pkg/local"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Quantum-Safe Integration Tests - ML-DSA Certificate Authority
// =============================================================================

// TestQuantumIntegration_MLDSA_CAKeyGeneration tests ML-DSA CA key generation with real backend
func TestQuantumIntegration_MLDSA_CAKeyGeneration(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm xkmssdk.QuantumAlgorithm
		pubKeyLen int
	}{
		{
			name:      "ML-DSA-44 CA Key",
			algorithm: xkmssdk.QuantumAlgorithmMLDSA44,
			pubKeyLen: 1312,
		},
		{
			name:      "ML-DSA-65 CA Key",
			algorithm: xkmssdk.QuantumAlgorithmMLDSA65,
			pubKeyLen: 1952,
		},
		{
			name:      "ML-DSA-87 CA Key",
			algorithm: xkmssdk.QuantumAlgorithmMLDSA87,
			pubKeyLen: 2592,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyStore, cleanup := setupQuantumKeyStore(t)
			defer cleanup()

			attrs := &xkmssdk.KeyAttributes{
				CN:        "test-quantum-ca-" + string(tc.algorithm),
				KeyType:   xkmssdk.KeyTypeCA,
				StoreType: xkmssdk.StoreQuantum,
				QuantumAttributes: &xkmssdk.QuantumAttributes{
					Algorithm: tc.algorithm,
				},
			}

			// Generate quantum key using real backend
			backend := keyStore.Backend()
			require.NotNil(t, backend, "Backend should not be nil")

			privateKey, err := backend.GenerateKey(attrs)
			require.NoError(t, err)
			require.NotNil(t, privateKey)

			// Verify it's a real ML-DSA key
			mldsaKey, ok := privateKey.(*xkmssdk.MLDSAPrivateKey)
			require.True(t, ok, "Should be real MLDSAPrivateKey")

			// Verify key properties
			assert.Equal(t, string(tc.algorithm), mldsaKey.Algorithm)
			assert.NotNil(t, mldsaKey.PublicKey)
			assert.GreaterOrEqual(t, len(mldsaKey.PublicKey.Key), tc.pubKeyLen)

			// Test signing
			message := []byte("test message for quantum CA signing")
			signature, err := mldsaKey.Sign(nil, message, nil)
			require.NoError(t, err)
			require.NotEmpty(t, signature)

			// Test verification
			valid, err := mldsaKey.Verify(message, signature)
			require.NoError(t, err)
			assert.True(t, valid, "Signature should be valid")

			// Cleanup
			mldsaKey.Clean()
		})
	}
}

// TestQuantumIntegration_MLKEM_KeyEncapsulation tests ML-KEM key encapsulation with real backend
func TestQuantumIntegration_MLKEM_KeyEncapsulation(t *testing.T) {
	testCases := []struct {
		name         string
		algorithm    xkmssdk.QuantumAlgorithm
		pubKeyLen    int
		ciphertxtLen int
	}{
		{
			name:         "ML-KEM-512 Key",
			algorithm:    xkmssdk.QuantumAlgorithmMLKEM512,
			pubKeyLen:    800,
			ciphertxtLen: 768,
		},
		{
			name:         "ML-KEM-768 Key",
			algorithm:    xkmssdk.QuantumAlgorithmMLKEM768,
			pubKeyLen:    1184,
			ciphertxtLen: 1088,
		},
		{
			name:         "ML-KEM-1024 Key",
			algorithm:    xkmssdk.QuantumAlgorithmMLKEM1024,
			pubKeyLen:    1568,
			ciphertxtLen: 1568,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyStore, cleanup := setupQuantumKeyStore(t)
			defer cleanup()

			attrs := &xkmssdk.KeyAttributes{
				CN:        "test-kem-" + string(tc.algorithm),
				KeyType:   xkmssdk.KeyTypeEncryption,
				StoreType: xkmssdk.StoreQuantum,
				QuantumAttributes: &xkmssdk.QuantumAttributes{
					Algorithm: tc.algorithm,
				},
			}

			// Generate quantum key using real backend
			backend := keyStore.Backend()
			require.NotNil(t, backend, "Backend should not be nil")

			privateKey, err := backend.GenerateKey(attrs)
			require.NoError(t, err)
			require.NotNil(t, privateKey)

			// Verify it's a real ML-KEM key
			mlkemKey, ok := privateKey.(*xkmssdk.MLKEMPrivateKey)
			require.True(t, ok, "Should be real MLKEMPrivateKey")

			// Verify key properties
			assert.Equal(t, string(tc.algorithm), mlkemKey.Algorithm)
			assert.NotNil(t, mlkemKey.PublicKey)

			// Test encapsulation
			ciphertext, sharedSecret, err := mlkemKey.Encapsulate(mlkemKey.PublicKey.Key)
			require.NoError(t, err)
			assert.Equal(t, tc.ciphertxtLen, len(ciphertext))
			assert.Equal(t, 32, len(sharedSecret))

			// Test decapsulation
			recoveredSecret, err := mlkemKey.Decapsulate(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, sharedSecret, recoveredSecret)

			// Cleanup
			mlkemKey.Clean()
		})
	}
}

// TestQuantumIntegration_HybridCertificateChain tests a hybrid CA with both quantum and classical keys
func TestQuantumIntegration_HybridCertificateChain(t *testing.T) {
	caInstance, cleanup := setupHybridQuantumCA(t)
	defer cleanup()

	t.Run("Issue Certificate from Hybrid CA", func(t *testing.T) {
		// Generate client RSA key
		clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Create CSR
		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "quantum-client.example.com",
				Organization: []string{"Quantum Test Org"},
			},
		}

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, clientKey)
		require.NoError(t, err)

		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		})

		// Sign CSR with hybrid CA
		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "quantum-client.example.com",
				Organization: "Quantum Test Org",
				Country:      "US",
			},
			Valid: 365,
		}

		cert, err := caInstance.SignCSR(csrPEM, request)
		require.NoError(t, err)
		require.NotNil(t, cert)

		// Verify certificate
		assert.Equal(t, "quantum-client.example.com", cert.Subject.CommonName)
		assert.True(t, cert.NotAfter.After(time.Now()))
	})

	t.Run("Verify Certificate Chain", func(t *testing.T) {
		request := &ca.CertificateRequest{
			Subject: ca.Subject{
				CommonName:   "chain-test.example.com",
				Organization: "Quantum Test Org",
			},
			Valid: 365,
		}

		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		chains, err := caInstance.Verify(cert, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, chains, "Should have valid certificate chain")
	})
}

// TestQuantumIntegration_SignerInterface tests that ML-DSA keys implement crypto.Signer
func TestQuantumIntegration_SignerInterface(t *testing.T) {
	keyStore, cleanup := setupQuantumKeyStore(t)
	defer cleanup()

	attrs := &xkmssdk.KeyAttributes{
		CN:        "test-signer-key",
		KeyType:   xkmssdk.KeyTypeSigning,
		StoreType: xkmssdk.StoreQuantum,
		QuantumAttributes: &xkmssdk.QuantumAttributes{
			Algorithm: xkmssdk.QuantumAlgorithmMLDSA65,
		},
	}

	backend := keyStore.Backend()
	privateKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Verify it implements crypto.Signer
	signer, ok := privateKey.(crypto.Signer)
	require.True(t, ok, "ML-DSA key should implement crypto.Signer")

	// Test Public() method
	pubKey := signer.Public()
	require.NotNil(t, pubKey)

	// Test Sign() method
	message := []byte("test message for crypto.Signer interface")
	signature, err := signer.Sign(nil, message, nil)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// Cleanup
	mldsaKey := privateKey.(*xkmssdk.MLDSAPrivateKey)
	mldsaKey.Clean()
}

// TestQuantumIntegration_KeyPersistence tests quantum key storage and retrieval
func TestQuantumIntegration_KeyPersistence(t *testing.T) {
	keyStore, cleanup := setupQuantumKeyStore(t)
	defer cleanup()

	attrs := &xkmssdk.KeyAttributes{
		CN:        "persistent-quantum-key",
		KeyType:   xkmssdk.KeyTypeCA,
		StoreType: xkmssdk.StoreQuantum,
		QuantumAttributes: &xkmssdk.QuantumAttributes{
			Algorithm: xkmssdk.QuantumAlgorithmMLDSA65,
		},
	}

	backend := keyStore.Backend()

	t.Run("Generate and Store Key", func(t *testing.T) {
		privateKey, err := backend.GenerateKey(attrs)
		require.NoError(t, err)
		require.NotNil(t, privateKey)
	})

	t.Run("Retrieve Stored Key", func(t *testing.T) {
		retrievedKey, err := backend.GetKey(attrs)
		require.NoError(t, err)
		require.NotNil(t, retrievedKey)

		// Verify it's the same type
		mldsaKey, ok := retrievedKey.(*xkmssdk.MLDSAPrivateKey)
		require.True(t, ok)
		assert.Equal(t, "ML-DSA-65", mldsaKey.Algorithm)
	})

	t.Run("List Keys", func(t *testing.T) {
		keys, err := backend.ListKeys()
		require.NoError(t, err)
		require.NotEmpty(t, keys)

		// Find our key
		found := false
		for _, k := range keys {
			if k.CN == "persistent-quantum-key" {
				found = true
				break
			}
		}
		assert.True(t, found, "Should find our persistent key")
	})

	t.Run("Delete Key", func(t *testing.T) {
		err := backend.DeleteKey(attrs)
		require.NoError(t, err)

		// Verify deletion
		_, err = backend.GetKey(attrs)
		assert.Error(t, err, "Key should be deleted")
	})
}

// TestQuantumIntegration_KeyRotation tests quantum key rotation
func TestQuantumIntegration_KeyRotation(t *testing.T) {
	keyStore, cleanup := setupQuantumKeyStore(t)
	defer cleanup()

	attrs := &xkmssdk.KeyAttributes{
		CN:        "rotatable-quantum-key",
		KeyType:   xkmssdk.KeyTypeSigning,
		StoreType: xkmssdk.StoreQuantum,
		QuantumAttributes: &xkmssdk.QuantumAttributes{
			Algorithm: xkmssdk.QuantumAlgorithmMLDSA44,
		},
	}

	backend := keyStore.Backend()

	// Generate initial key
	initialKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	initialMLDSA := initialKey.(*xkmssdk.MLDSAPrivateKey)
	initialPubKey := make([]byte, len(initialMLDSA.PublicKey.Key))
	copy(initialPubKey, initialMLDSA.PublicKey.Key)

	// Rotate key
	err = backend.RotateKey(attrs)
	require.NoError(t, err)

	// Get rotated key
	rotatedKey, err := backend.GetKey(attrs)
	require.NoError(t, err)

	rotatedMLDSA := rotatedKey.(*xkmssdk.MLDSAPrivateKey)

	// Verify public key changed
	assert.NotEqual(t, initialPubKey, rotatedMLDSA.PublicKey.Key,
		"Public key should change after rotation")

	// Verify rotated key works
	message := []byte("test after rotation")
	signature, err := rotatedMLDSA.Sign(nil, message, nil)
	require.NoError(t, err)

	valid, err := rotatedMLDSA.Verify(message, signature)
	require.NoError(t, err)
	assert.True(t, valid)

	// Cleanup
	rotatedMLDSA.Clean()
}

// TestQuantumIntegration_ConcurrentOperations tests thread safety
func TestQuantumIntegration_ConcurrentOperations(t *testing.T) {
	keyStore, cleanup := setupQuantumKeyStore(t)
	defer cleanup()

	backend := keyStore.Backend()
	numGoroutines := 10
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			attrs := &xkmssdk.KeyAttributes{
				CN:        "concurrent-key-" + string(rune('a'+idx)),
				KeyType:   xkmssdk.KeyTypeSigning,
				StoreType: xkmssdk.StoreQuantum,
				QuantumAttributes: &xkmssdk.QuantumAttributes{
					Algorithm: xkmssdk.QuantumAlgorithmMLDSA44,
				},
			}

			// Generate key
			key, err := backend.GenerateKey(attrs)
			if err != nil {
				errChan <- err
				return
			}

			// Sign message
			mldsaKey := key.(*xkmssdk.MLDSAPrivateKey)
			message := []byte("concurrent message " + string(rune('a'+idx)))
			_, err = mldsaKey.Sign(nil, message, nil)
			if err != nil {
				mldsaKey.Clean()
				errChan <- err
				return
			}

			mldsaKey.Clean()
			errChan <- nil
		}(i)
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-errChan
		assert.NoError(t, err, "Concurrent operation should not fail")
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// setupQuantumKeyStore creates a quantum backend with in-memory storage
func setupQuantumKeyStore(t *testing.T) (xkmssdk.ServiceBackend, func()) {
	t.Helper()

	xkmssdk.ServiceReset()

	// Create in-memory storage
	keyStorage, err := xkmssdk.NewMemoryStorageBackend()
	require.NoError(t, err)

	// Create quantum backend
	quantumBackend, err := xkmssdk.NewQuantumBackend(keyStorage)
	require.NoError(t, err)

	// Create certstore for xkms
	certStorageBackend, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	certAdapter := xkmssdk.NewStorageCertAdapter(certStorageBackend)
	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	require.NoError(t, err)

	// Create xkms wrapper
	ks, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     quantumBackend,
		CertStorage: certStorageBackend,
	})
	require.NoError(t, err)

	// Initialize xkms service service
	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			"quantum": ks,
		},
		DefaultBackend: "quantum",
	})
	require.NoError(t, err)

	cleanup := func() {
		quantumBackend.Close()
		certStore.Close()
		xkmssdk.ServiceReset()
	}

	return ks, cleanup
}

// setupHybridQuantumCA creates a CA with both quantum and classical capabilities
func setupHybridQuantumCA(t *testing.T) (*ca.CA, func()) {
	t.Helper()

	xkmssdk.ServiceReset()

	// Create storages
	keyStorage, err := xkmssdk.NewMemoryStorageBackend()
	require.NoError(t, err)

	certStorageBackend, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)

	// Create quantum backend
	quantumBackend, err := xkmssdk.NewQuantumBackend(keyStorage)
	require.NoError(t, err)

	// Create certstore
	certAdapter := xkmssdk.NewStorageCertAdapter(certStorageBackend)
	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	require.NoError(t, err)

	// Create xkms wrapper
	ks, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     quantumBackend,
		CertStorage: certStorageBackend,
	})
	require.NoError(t, err)

	// Initialize xkms service service
	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			"quantum": ks,
		},
		DefaultBackend: "quantum",
	})
	require.NoError(t, err)

	// Create blob storage
	blobStore := local.New()
	err = blobStore.Configure(map[string]string{"path": t.TempDir()})
	require.NoError(t, err)

	// Create hybrid CA config
	// Note: Until Go's x509 package supports ML-DSA, we use ECDSA
	// for certificate signing but can still use quantum for key storage
	config := ca.Config{
		Identity: []ca.Identity{
			{
				Subject: ca.Subject{
					CommonName:   "Quantum-Hybrid Root CA",
					Organization: "Quantum Test Org",
					Country:      "US",
				},
				Valid:        10,
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     "P256",
				KeystoreType: "quantum",
				IsRoot:       true,
			},
			{
				Subject: ca.Subject{
					CommonName:   "Quantum-Hybrid Intermediate CA",
					Organization: "Quantum Test Org",
					Country:      "US",
				},
				Valid:        5,
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     "P256",
				KeystoreType: "quantum",
				ParentCA:     "Quantum-Hybrid Root CA",
			},
		},
		SelectedCA:                1,
		DefaultValidityPeriod:     365,
		DefaultKeyAlgorithm:       x509.ECDSA,
		DefaultSignatureAlgorithm: x509.ECDSAWithSHA256,
		DefaultHash:               crypto.SHA256,
		LazyInitialization:        false,
	}

	caInstance, err := ca.New(config, certStore, blobStore)
	require.NoError(t, err)

	cleanup := func() {
		quantumBackend.Close()
		certStore.Close()
		xkmssdk.ServiceReset()
	}

	return caInstance, cleanup
}
