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

package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitialize_WithNilConfig(t *testing.T) {
	keychain.Reset()

	// Should auto-detect and initialize with defaults
	err := Initialize(nil)
	assert.NoError(t, err)
	assert.True(t, keychain.IsInitialized())

	backends := keychain.Backends()
	assert.NotEmpty(t, backends)

	keychain.Reset()
}

func TestInitialize_WithPKCS8Backend(t *testing.T) {
	keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "pkcs8",
		Backends: []BackendConfig{
			{
				Name:    "pkcs8",
				Type:    "pkcs8",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/keys",
				},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)
	assert.True(t, keychain.IsInitialized())

	// Verify backend is available
	ks, err := keychain.Backend("pkcs8")
	assert.NoError(t, err)
	assert.NotNil(t, ks)

	keychain.Reset()
}

func TestInitialize_WithSoftwareBackend(t *testing.T) {
	keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "software",
		Backends: []BackendConfig{
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/keys",
				},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)

	ks, err := keychain.Backend("software")
	assert.NoError(t, err)
	assert.NotNil(t, ks)

	keychain.Reset()
}

func TestInitialize_WithSymmetricBackend(t *testing.T) {
	keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "symmetric",
		Backends: []BackendConfig{
			{
				Name:    "symmetric",
				Type:    "symmetric",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir":  tempDir + "/keys",
					"password": "test-password-123",
				},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)

	ks, err := keychain.Backend("symmetric")
	assert.NoError(t, err)
	assert.NotNil(t, ks)

	keychain.Reset()
}

func TestInitialize_WithMultipleBackends(t *testing.T) {
	keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "pkcs8",
		Backends: []BackendConfig{
			{
				Name:    "pkcs8",
				Type:    "pkcs8",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/pkcs8",
				},
			},
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/software",
				},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)

	backends := keychain.Backends()
	assert.Len(t, backends, 2)
	assert.Contains(t, backends, "pkcs8")
	assert.Contains(t, backends, "software")

	// Verify default backend
	defaultKS, err := keychain.DefaultBackend()
	assert.NoError(t, err)
	assert.NotNil(t, defaultKS)

	keychain.Reset()
}

func TestInitialize_DisabledBackend(t *testing.T) {
	keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "pkcs8",
		Backends: []BackendConfig{
			{
				Name:    "pkcs8",
				Type:    "pkcs8",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/pkcs8",
				},
			},
			{
				Name:    "software",
				Type:    "software",
				Enabled: false, // Disabled
				Config: map[string]interface{}{
					"key_dir": tempDir + "/software",
				},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)

	backends := keychain.Backends()
	assert.Len(t, backends, 1)
	assert.Contains(t, backends, "pkcs8")
	assert.NotContains(t, backends, "software")

	keychain.Reset()
}

func TestInitialize_NoBackendsEnabled(t *testing.T) {
	keychain.Reset()

	config := &BackendFactoryConfig{
		DefaultBackend: "pkcs8",
		Backends: []BackendConfig{
			{
				Name:    "pkcs8",
				Type:    "pkcs8",
				Enabled: false,
			},
		},
	}

	err := Initialize(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no backends available")

	keychain.Reset()
}

func TestInitialize_InvalidBackendType(t *testing.T) {
	keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "invalid",
		Backends: []BackendConfig{
			{
				Name:    "invalid",
				Type:    "nonexistent-type",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/keys",
				},
			},
		},
	}

	err := Initialize(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no backends available")

	keychain.Reset()
}

func TestInitialize_DefaultToFirstAvailable(t *testing.T) {
	keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "nonexistent", // Invalid default
		Backends: []BackendConfig{
			{
				Name:    "pkcs8",
				Type:    "pkcs8",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/keys",
				},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)

	// Should fall back to first available backend
	defaultKS, err := keychain.DefaultBackend()
	assert.NoError(t, err)
	assert.NotNil(t, defaultKS)

	keychain.Reset()
}

func TestCreateKeyStorage_FileBackend(t *testing.T) {
	tempDir := t.TempDir()

	storage, err := createKeyStorage(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, storage)

	// Verify directory was created
	_, err = os.Stat(tempDir)
	assert.NoError(t, err)
}

func TestCreateKeyStorage_MemoryBackend(t *testing.T) {
	storage, err := createKeyStorage("memory")
	assert.NoError(t, err)
	assert.NotNil(t, storage)

	storage2, err := createKeyStorage("")
	assert.NoError(t, err)
	assert.NotNil(t, storage2)
}

func TestCreateCertStorage_FileBackend(t *testing.T) {
	tempDir := t.TempDir()

	storage, err := createCertStorage(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, storage)

	// Verify directory was created
	_, err = os.Stat(tempDir)
	assert.NoError(t, err)
}

func TestCreateCertStorage_MemoryBackend(t *testing.T) {
	storage, err := createCertStorage("memory")
	assert.NoError(t, err)
	assert.NotNil(t, storage)

	storage2, err := createCertStorage("")
	assert.NoError(t, err)
	assert.NotNil(t, storage2)
}

func TestCreatePKCS8Backend_Success(t *testing.T) {
	tempDir := t.TempDir()

	config := BackendConfig{
		Name: "pkcs8",
		Type: "pkcs8",
		Config: map[string]interface{}{
			"key_dir": tempDir,
		},
	}

	backend, err := createPKCS8Backend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
}

func TestCreatePKCS8Backend_DefaultKeyDir(t *testing.T) {
	config := BackendConfig{
		Name:   "pkcs8",
		Type:   "pkcs8",
		Config: map[string]interface{}{},
	}

	backend, err := createPKCS8Backend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
}

func TestCreateSoftwareBackend_Success(t *testing.T) {
	tempDir := t.TempDir()

	config := BackendConfig{
		Name: "software",
		Type: "software",
		Config: map[string]interface{}{
			"key_dir": tempDir,
		},
	}

	backend, err := createSoftwareBackend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
}

func TestCreateSymmetricBackend_Success(t *testing.T) {
	tempDir := t.TempDir()

	config := BackendConfig{
		Name: "symmetric",
		Type: "symmetric",
		Config: map[string]interface{}{
			"key_dir": tempDir,
		},
	}

	backend, err := createSymmetricBackend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
}

func TestGetDefaultBackendConfigs(t *testing.T) {
	configs := getDefaultBackendConfigs()
	assert.NotEmpty(t, configs)

	// Should have at least PKCS8, Software, and Symmetric backends
	types := make(map[string]bool)
	for _, config := range configs {
		types[config.Type] = true
	}

	assert.True(t, types["pkcs8"])
	assert.True(t, types["software"])
	assert.True(t, types["symmetric"])
}

func TestBackendFactory_Integration(t *testing.T) {
	keychain.Reset()

	tempDir := t.TempDir()

	// Initialize with multiple backends
	config := &BackendFactoryConfig{
		DefaultBackend: "pkcs8",
		Backends: []BackendConfig{
			{
				Name:    "pkcs8",
				Type:    "pkcs8",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/pkcs8",
				},
			},
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/software",
				},
			},
		},
	}

	err := Initialize(config)
	require.NoError(t, err)

	// Test creating keys in different backends
	pkcs8KS, err := keychain.Backend("pkcs8")
	require.NoError(t, err)

	softwareKS, err := keychain.Backend("software")
	require.NoError(t, err)

	// Generate keys
	attrs1 := &types.KeyAttributes{
		CN:        "pkcs8-key",
		StoreType: types.StoreSoftware,
		KeyType:   types.KeyTypeTLS,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	_, err = pkcs8KS.GenerateRSA(attrs1)
	assert.NoError(t, err)

	attrs2 := &types.KeyAttributes{
		CN:        "software-key",
		StoreType: types.StoreSoftware, // Software backend also uses PKCS8 store type
		KeyType:   types.KeyTypeTLS,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	_, err = softwareKS.GenerateRSA(attrs2)
	assert.NoError(t, err)

	// Verify keys were created
	key1, err := pkcs8KS.GetKey(attrs1)
	assert.NoError(t, err)
	assert.NotNil(t, key1)

	key2, err := softwareKS.GetKey(attrs2)
	assert.NoError(t, err)
	assert.NotNil(t, key2)

	// List all keys
	allKeys, err := keychain.ListKeys()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(allKeys), 2, "should have at least 2 keys")

	// Clean up
	err = keychain.Close()
	assert.NoError(t, err)

	keychain.Reset()
}

func TestBackendFactory_SharedCertStorage(t *testing.T) {
	keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "pkcs8",
		Backends: []BackendConfig{
			{
				Name:    "pkcs8",
				Type:    "pkcs8",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/pkcs8",
				},
			},
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/software",
				},
			},
		},
	}

	err := Initialize(config)
	require.NoError(t, err)

	// Both backends should share the same cert storage
	pkcs8KS, _ := keychain.Backend("pkcs8")
	softwareKS, _ := keychain.Backend("software")

	// Save cert via one backend
	cert := createTestCert(t)
	err = pkcs8KS.SaveCert("test-cert", cert)
	require.NoError(t, err)

	// Retrieve via another backend (shared storage)
	retrievedCert, err := softwareKS.GetCert("test-cert")
	assert.NoError(t, err)
	assert.Equal(t, cert.Subject.CommonName, retrievedCert.Subject.CommonName)

	keychain.Reset()
}

// Helper for creating test certificates
func createTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Generate a test key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
