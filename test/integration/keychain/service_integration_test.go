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

package keychain

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupServiceIntegration initializes the service with multiple backends for testing
func setupServiceIntegration(t *testing.T) {
	t.Helper()
	keychain.Reset()

	// Create first software backend
	software1KeyStorage := storage.New()
	software1CertStorage := storage.New()
	software1BackendConfig := &software.Config{
		KeyStorage: software1KeyStorage,
	}
	software1Backend, err := software.NewBackend(software1BackendConfig)
	require.NoError(t, err)

	software1KS, err := keychain.New(&keychain.Config{
		Backend:     software1Backend,
		CertStorage: software1CertStorage,
	})
	require.NoError(t, err)

	// Create second software backend (to test multi-backend routing)
	software2KeyStorage := storage.New()
	software2CertStorage := storage.New()
	software2BackendConfig := &software.Config{
		KeyStorage: software2KeyStorage,
	}
	software2Backend, err := software.NewBackend(software2BackendConfig)
	require.NoError(t, err)

	software2KS, err := keychain.New(&keychain.Config{
		Backend:     software2Backend,
		CertStorage: software2CertStorage,
	})
	require.NoError(t, err)

	// Initialize service with multiple backends
	err = keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"backend1": software1KS,
			"backend2": software2KS,
		},
		DefaultBackend: "backend1",
	})
	require.NoError(t, err)
}

// TestServiceIntegration_BackendManagement tests backend management operations
func TestServiceIntegration_BackendManagement(t *testing.T) {
	setupServiceIntegration(t)
	defer keychain.Reset()

	t.Run("Backends", func(t *testing.T) {
		backends := keychain.Backends()
		assert.Len(t, backends, 2)
		assert.Contains(t, backends, "backend1")
		assert.Contains(t, backends, "backend2")
	})

	t.Run("Backend", func(t *testing.T) {
		ks, err := keychain.Backend("backend1")
		assert.NoError(t, err)
		assert.NotNil(t, ks)

		ks, err = keychain.Backend("backend2")
		assert.NoError(t, err)
		assert.NotNil(t, ks)
	})

	t.Run("Backend_NotFound", func(t *testing.T) {
		_, err := keychain.Backend("nonexistent")
		assert.Error(t, err)
		assert.ErrorIs(t, err, keychain.ErrBackendNotFound)
	})

	t.Run("DefaultBackend", func(t *testing.T) {
		ks, err := keychain.DefaultBackend()
		assert.NoError(t, err)
		assert.NotNil(t, ks)
	})
}

// TestServiceIntegration_KeyGeneration tests key generation through the service
func TestServiceIntegration_KeyGeneration(t *testing.T) {
	setupServiceIntegration(t)
	defer keychain.Reset()

	t.Run("GenerateRSA", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rsa-service",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			Hash: crypto.SHA256,
		}

		key, err := keychain.GenerateKey(attrs)
		assert.NoError(t, err)
		assert.NotNil(t, key)

		// Verify we can use it as a signer
		if signer, ok := key.(crypto.Signer); ok {
			assert.NotNil(t, signer.Public())
		}
	})

	t.Run("GenerateECDSA", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa-service",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
			Hash: crypto.SHA256,
		}

		key, err := keychain.GenerateKey(attrs)
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("GenerateEd25519", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-ed25519-service",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.Ed25519,
		}

		key, err := keychain.GenerateKey(attrs)
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})
}

// TestServiceIntegration_KeyRetrieval tests key retrieval through the service
func TestServiceIntegration_KeyRetrieval(t *testing.T) {
	setupServiceIntegration(t)
	defer keychain.Reset()

	t.Run("Key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-retrieve-service",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			Hash: crypto.SHA256,
		}

		// Generate key first
		_, err := keychain.GenerateKey(attrs)
		require.NoError(t, err)

		// Retrieve it
		key, err := keychain.Key(attrs)
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})
}

// TestServiceIntegration_CertificateOperations tests certificate operations
func TestServiceIntegration_CertificateOperations(t *testing.T) {
	setupServiceIntegration(t)
	defer keychain.Reset()

	// Helper to create a test certificate
	createTestCert := func(t *testing.T, cn string, key crypto.Signer) *x509.Certificate {
		t.Helper()

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: cn,
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certDER)
		require.NoError(t, err)

		return cert
	}

	t.Run("SaveAndRetrieveCertificate", func(t *testing.T) {
		// Generate key first
		attrs := &types.KeyAttributes{
			CN:           "test-cert-service",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			Hash: crypto.SHA256,
		}

		key, err := keychain.GenerateKey(attrs)
		require.NoError(t, err)

		// Create certificate
		cert := createTestCert(t, "test-cert-service", key.(crypto.Signer))

		// Save certificate
		err = keychain.SaveCertificate("test-cert-service", cert)
		assert.NoError(t, err)

		// Retrieve certificate
		retrievedCert, err := keychain.Certificate("test-cert-service")
		assert.NoError(t, err)
		assert.NotNil(t, retrievedCert)
		assert.Equal(t, cert.Subject.CommonName, retrievedCert.Subject.CommonName)
	})

	t.Run("DeleteCertificate", func(t *testing.T) {
		// Generate key and certificate
		attrs := &types.KeyAttributes{
			CN:           "test-delete-cert",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			Hash: crypto.SHA256,
		}

		key, err := keychain.GenerateKey(attrs)
		require.NoError(t, err)

		cert := createTestCert(t, "test-delete-cert", key.(crypto.Signer))

		err = keychain.SaveCertificate("test-delete-cert", cert)
		require.NoError(t, err)

		// Delete certificate
		err = keychain.DeleteCertificate("test-delete-cert")
		assert.NoError(t, err)

		// Verify it's deleted
		_, err = keychain.Certificate("test-delete-cert")
		assert.Error(t, err)
	})

	t.Run("ListCertificates", func(t *testing.T) {
		// Generate keys and certificates in both backends
		backend1, err := keychain.Backend("backend1")
		require.NoError(t, err)

		backend2, err := keychain.Backend("backend2")
		require.NoError(t, err)

		// Create cert in backend1
		attrs1 := &types.KeyAttributes{
			CN:           "test-list-cert-1",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			Hash: crypto.SHA256,
		}
		key1, err := backend1.GenerateRSA(attrs1)
		require.NoError(t, err)
		cert1 := createTestCert(t, "test-list-cert-1", key1.(crypto.Signer))
		err = backend1.SaveCert("test-list-cert-1", cert1)
		require.NoError(t, err)

		// Create cert in backend2
		attrs2 := &types.KeyAttributes{
			CN:           "test-list-cert-2",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			Hash: crypto.SHA256,
		}
		key2, err := backend2.GenerateRSA(attrs2)
		require.NoError(t, err)
		cert2 := createTestCert(t, "test-list-cert-2", key2.(crypto.Signer))
		err = backend2.SaveCert("test-list-cert-2", cert2)
		require.NoError(t, err)

		// List all certificates
		certs, err := keychain.ListCertificates()
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(certs), 2, "Should have at least 2 certificates")

		// List from specific backend
		certsBackend1, err := keychain.ListCertificates("backend1")
		assert.NoError(t, err)
		assert.NotEmpty(t, certsBackend1)
	})
}

// TestServiceIntegration_ListKeys tests listing keys across backends
func TestServiceIntegration_ListKeys(t *testing.T) {
	setupServiceIntegration(t)
	defer keychain.Reset()

	// Generate keys in both backends
	backend1, err := keychain.Backend("backend1")
	require.NoError(t, err)

	backend2, err := keychain.Backend("backend2")
	require.NoError(t, err)

	// Create key in backend1
	attrs1 := &types.KeyAttributes{
		CN:           "test-list-key-1",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}
	_, err = backend1.GenerateRSA(attrs1)
	require.NoError(t, err)

	// Create key in backend2
	attrs2 := &types.KeyAttributes{
		CN:           "test-list-key-2",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}
	_, err = backend2.GenerateRSA(attrs2)
	require.NoError(t, err)

	t.Run("ListKeys_AllBackends", func(t *testing.T) {
		keys, err := keychain.ListKeys()
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(keys), 2, "Should have at least 2 keys")
	})

	t.Run("ListKeys_SpecificBackend", func(t *testing.T) {
		keys, err := keychain.ListKeys("backend1")
		assert.NoError(t, err)
		assert.NotEmpty(t, keys)
	})
}

// TestServiceIntegration_Close tests closing the service
func TestServiceIntegration_Close(t *testing.T) {
	setupServiceIntegration(t)

	err := keychain.Close()
	assert.NoError(t, err)

	// Service should still be initialized after Close()
	assert.True(t, keychain.IsInitialized())

	// Reset to fully clear
	keychain.Reset()
	assert.False(t, keychain.IsInitialized())
}
