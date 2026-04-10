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

package xkms

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAutoInitialize_NilConfig(t *testing.T) {
	t.Cleanup(func() { Reset() })

	err := AutoInitialize(nil)
	require.NoError(t, err)

	assert.True(t, IsInitialized())

	// Software backend should be available (always compiled in)
	backends := Backends()
	assert.NotEmpty(t, backends)

	found := false
	for _, name := range backends {
		if name == string(BackendSoftware) {
			found = true
			break
		}
	}
	assert.True(t, found, "software backend should be initialized")
}

func TestAutoInitialize_DefaultConfig(t *testing.T) {
	t.Cleanup(func() { Reset() })

	err := AutoInitialize(&AutoConfig{})
	require.NoError(t, err)

	assert.True(t, IsInitialized())

	// Default backend should be software
	b, err := DefaultBackend()
	require.NoError(t, err)
	assert.NotNil(t, b)
}

func TestAutoInitialize_CustomDefaultBackend(t *testing.T) {
	t.Cleanup(func() { Reset() })

	err := AutoInitialize(&AutoConfig{
		DefaultBackend: string(BackendSoftware),
	})
	require.NoError(t, err)

	assert.True(t, IsInitialized())

	// Should be able to get software backend (full-service)
	b, err := GetBackend(string(BackendSoftware))
	require.NoError(t, err)
	assert.NotNil(t, b)

	// pkcs8 is a key provider, not a full-service backend
	kp, err := GetKeyProvider(string(BackendPKCS8))
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestAutoInitialize_InvalidDefaultBackendFallback(t *testing.T) {
	t.Cleanup(func() { Reset() })

	// Request a backend that does not exist (not compiled in without build tag)
	err := AutoInitialize(&AutoConfig{
		DefaultBackend: "nonexistent-backend",
	})
	require.NoError(t, err)

	assert.True(t, IsInitialized())

	// Should have fallen back to an available backend
	b, err := DefaultBackend()
	require.NoError(t, err)
	assert.NotNil(t, b)
}

func TestAutoInitialize_AlreadyInitialized(t *testing.T) {
	t.Cleanup(func() { Reset() })

	// First initialization should succeed
	err := AutoInitialize(nil)
	require.NoError(t, err)
	assert.True(t, IsInitialized())

	// Second call should still succeed because Initialize uses sync.Once
	// (it's a no-op, not an error)
	err = AutoInitialize(nil)
	// sync.Once means the second call returns nil (does nothing)
	assert.NoError(t, err)
}

func TestAutoInitialize_WithBackendConfigs(t *testing.T) {
	t.Cleanup(func() { Reset() })

	err := AutoInitialize(&AutoConfig{
		BackendConfigs: map[BackendType]map[string]interface{}{
			BackendSoftware: {
				"key_dir": "memory",
			},
		},
	})
	require.NoError(t, err)

	assert.True(t, IsInitialized())

	b, err := GetBackend(string(BackendSoftware))
	require.NoError(t, err)
	assert.NotNil(t, b)
}

func TestAutoInitialize_WithDataDir(t *testing.T) {
	t.Cleanup(func() { Reset() })

	tmpDir := t.TempDir()

	err := AutoInitialize(&AutoConfig{
		DataDir:        tmpDir,
		DefaultBackend: string(BackendSoftware),
	})
	require.NoError(t, err)

	assert.True(t, IsInitialized())

	b, err := GetBackend(string(BackendSoftware))
	require.NoError(t, err)
	assert.NotNil(t, b)
}

func TestAutoInitialize_MultipleBackendsInitialized(t *testing.T) {
	t.Cleanup(func() { Reset() })

	err := AutoInitialize(nil)
	require.NoError(t, err)

	backends := Backends()
	// At minimum, software should be in full-service backends
	// (tpm2 may fail on hosts without TPM hardware)
	assert.GreaterOrEqual(t, len(backends), 1,
		"at least software should initialize as full-service backend")

	// pkcs8 and symmetric should be key providers
	keyProviders := KeyProviders()
	assert.GreaterOrEqual(t, len(keyProviders), 2,
		"at least pkcs8 and symmetric should initialize as key providers")
}

func TestAutoInitialize_BackendConfigOverrides(t *testing.T) {
	t.Cleanup(func() { Reset() })

	// Override symmetric and pkcs8 key providers with memory storage
	err := AutoInitialize(&AutoConfig{
		BackendConfigs: map[BackendType]map[string]interface{}{
			BackendSymmetric: {
				"key_dir": "memory",
			},
			BackendPKCS8: {
				"key_dir": "memory",
			},
		},
	})
	require.NoError(t, err)

	assert.True(t, IsInitialized())

	// symmetric and pkcs8 are key providers, not full-service backends
	for _, name := range []string{string(BackendSymmetric), string(BackendPKCS8)} {
		kp, kpErr := GetKeyProvider(name)
		require.NoError(t, kpErr, "key provider %s should be available", name)
		assert.NotNil(t, kp)
	}
}

func TestAutoConfig_DefaultValues(t *testing.T) {
	config := &AutoConfig{}

	assert.Equal(t, "", config.DataDir)
	assert.Equal(t, "", config.DefaultBackend)
	assert.Nil(t, config.BackendConfigs)
}

func TestResolveDefaultBackend_PrefersSoftware(t *testing.T) {
	backends := map[string]Backend{
		string(BackendSoftware):  newMockKeyStore(string(BackendSoftware)),
		string(BackendPKCS8):     newMockKeyStore(string(BackendPKCS8)),
		string(BackendSymmetric): newMockKeyStore(string(BackendSymmetric)),
	}

	result := resolveDefaultBackend("", backends)
	assert.Equal(t, string(BackendSoftware), result)
}

func TestResolveDefaultBackend_FallsBackWhenRequestedMissing(t *testing.T) {
	backends := map[string]Backend{
		string(BackendPKCS8):     newMockKeyStore(string(BackendPKCS8)),
		string(BackendSymmetric): newMockKeyStore(string(BackendSymmetric)),
	}

	result := resolveDefaultBackend("nonexistent", backends)
	// Should fall back to first sorted: pkcs8 < symmetric
	assert.Equal(t, string(BackendPKCS8), result)
}

func TestResolveDefaultBackend_UsesRequestedWhenAvailable(t *testing.T) {
	backends := map[string]Backend{
		string(BackendSoftware): newMockKeyStore(string(BackendSoftware)),
		string(BackendPKCS8):    newMockKeyStore(string(BackendPKCS8)),
	}

	result := resolveDefaultBackend(string(BackendPKCS8), backends)
	assert.Equal(t, string(BackendPKCS8), result)
}

func TestResolveBackendConfig_EmptyDefaults(t *testing.T) {
	config := &AutoConfig{}
	result := resolveBackendConfig(config, BackendSoftware)
	assert.Empty(t, result)
}

func TestResolveBackendConfig_WithDataDir(t *testing.T) {
	config := &AutoConfig{
		DataDir: "/tmp/xkms",
	}
	result := resolveBackendConfig(config, BackendSoftware)
	assert.Equal(t, "/tmp/xkms/software", result["key_dir"])
}

func TestResolveBackendConfig_UserOverrideTakesPrecedence(t *testing.T) {
	config := &AutoConfig{
		DataDir: "/tmp/xkms",
		BackendConfigs: map[BackendType]map[string]interface{}{
			BackendSoftware: {
				"key_dir": "/custom/path",
			},
		},
	}
	result := resolveBackendConfig(config, BackendSoftware)
	assert.Equal(t, "/custom/path", result["key_dir"])
}

func TestResolveBackendConfig_MergesUserConfigKeys(t *testing.T) {
	config := &AutoConfig{
		BackendConfigs: map[BackendType]map[string]interface{}{
			BackendSoftware: {
				"custom_key": "custom_value",
			},
		},
	}
	result := resolveBackendConfig(config, BackendSoftware)
	assert.Equal(t, "custom_value", result["custom_key"])
}

func TestCreateCertStorage_InMemory(t *testing.T) {
	cs, err := createCertStorage("")
	require.NoError(t, err)
	assert.NotNil(t, cs)
}

func TestCreateCertStorage_FileBased(t *testing.T) {
	tmpDir := t.TempDir()
	cs, err := createCertStorage(tmpDir)
	require.NoError(t, err)
	assert.NotNil(t, cs)
}

func TestErrNoBackendsAvailable(t *testing.T) {
	assert.True(t, errors.Is(ErrNoBackendsAvailable, ErrNoBackendsAvailable))
	assert.Contains(t, ErrNoBackendsAvailable.Error(), "no backends available")
}

func TestErrNoFactoriesRegistered(t *testing.T) {
	assert.True(t, errors.Is(ErrNoFactoriesRegistered, ErrNoFactoriesRegistered))
	assert.Contains(t, ErrNoFactoriesRegistered.Error(), "no backend factories registered")
}
