// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
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

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitialize_WithNilConfig(t *testing.T) {
	xkms.Reset()

	// Should auto-detect and initialize with defaults
	err := Initialize(nil)
	assert.NoError(t, err)
	assert.True(t, xkms.IsInitialized())

	backends := xkms.Backends()
	assert.NotEmpty(t, backends)

	xkms.Reset()
}

func TestInitialize_WithPKCS8Backend(t *testing.T) {
	xkms.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "software",
		Backends: []BackendConfig{
			{
				Name:    "pkcs8",
				Type:    "pkcs8",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/keys",
				},
			},
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config:  map[string]interface{}{"key_dir": tempDir + "/software"},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)
	assert.True(t, xkms.IsInitialized())

	// Verify key provider is available
	ks, err := xkms.GetKeyProvider("pkcs8")
	assert.NoError(t, err)
	assert.NotNil(t, ks)

	xkms.Reset()
}

func TestInitialize_WithSoftwareBackend(t *testing.T) {
	xkms.Reset()

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

	ks, err := xkms.GetBackend("software")
	assert.NoError(t, err)
	assert.NotNil(t, ks)

	xkms.Reset()
}

func TestInitialize_WithSymmetricBackend(t *testing.T) {
	xkms.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "software",
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
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config:  map[string]interface{}{"key_dir": tempDir + "/software"},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)

	ks, err := xkms.GetKeyProvider("symmetric")
	assert.NoError(t, err)
	assert.NotNil(t, ks)

	xkms.Reset()
}

func TestInitialize_WithMultipleBackends(t *testing.T) {
	xkms.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "software",
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

	// pkcs8 is a key provider, software is a full-service backend
	backends := xkms.Backends()
	assert.Len(t, backends, 1)
	assert.Contains(t, backends, "software")

	keyProviders := xkms.KeyProviders()
	assert.Contains(t, keyProviders, "pkcs8")

	// Verify default backend
	defaultKS, err := xkms.DefaultBackend()
	assert.NoError(t, err)
	assert.NotNil(t, defaultKS)

	xkms.Reset()
}

func TestInitialize_DisabledBackend(t *testing.T) {
	xkms.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "software",
		Backends: []BackendConfig{
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tempDir + "/software",
				},
			},
			{
				Name:    "software-disabled",
				Type:    "software",
				Enabled: false, // Disabled
				Config: map[string]interface{}{
					"key_dir": tempDir + "/software-disabled",
				},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)

	backends := xkms.Backends()
	assert.Len(t, backends, 1)
	assert.Contains(t, backends, "software")
	assert.NotContains(t, backends, "software-disabled")

	xkms.Reset()
}

func TestInitialize_NoBackendsEnabled(t *testing.T) {
	xkms.Reset()

	config := &BackendFactoryConfig{
		DefaultBackend: "software",
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

	xkms.Reset()
}

func TestInitialize_InvalidBackendType(t *testing.T) {
	xkms.Reset()

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

	xkms.Reset()
}

func TestInitialize_DefaultToFirstAvailable(t *testing.T) {
	xkms.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "nonexistent", // Invalid default
		Backends: []BackendConfig{
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

	// Should fall back to first available backend
	defaultKS, err := xkms.DefaultBackend()
	assert.NoError(t, err)
	assert.NotNil(t, defaultKS)

	xkms.Reset()
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
	xkms.Reset()

	tempDir := t.TempDir()

	// Initialize with multiple backends
	config := &BackendFactoryConfig{
		DefaultBackend: "software",
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
	pkcs8KS, err := xkms.GetKeyProvider("pkcs8")
	require.NoError(t, err)

	softwareKS, err := xkms.GetBackend("software")
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

	// List keys from full-service backends (key providers are not included
	// in ListKeys since they are partial implementations)
	allKeys, err := xkms.ListKeys()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(allKeys), 1, "should have at least 1 key from full-service backend")

	// Clean up
	err = xkms.Close()
	assert.NoError(t, err)

	xkms.Reset()
}

func TestBackendFactory_SharedCertStorage(t *testing.T) {
	xkms.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "software",
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

	// pkcs8 is a key provider, software is a full-service backend
	pkcs8KS, err := xkms.GetKeyProvider("pkcs8")
	require.NoError(t, err)
	softwareKS, err := xkms.GetBackend("software")
	require.NoError(t, err)

	// Save cert via key provider
	cert := createTestCert(t)
	err = pkcs8KS.SaveCert("test-cert", cert)
	require.NoError(t, err)

	// Retrieve via full-service backend (shared storage)
	retrievedCert, err := softwareKS.GetCert("test-cert")
	assert.NoError(t, err)
	assert.Equal(t, cert.Subject.CommonName, retrievedCert.Subject.CommonName)

	xkms.Reset()
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
