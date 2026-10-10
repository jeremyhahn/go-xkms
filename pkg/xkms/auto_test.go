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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// TestAutoInitialize_NoDataDirNeverWritesTPM2KeysInCWD is the regression test
// for #926: AutoInitialize with no Datastore (and no BackendConfigs override)
// never sets "key_storage" for the tpm2 backend, so the tpm2 backend factory
// must fail closed (tpm2.ErrKeyDirRequired) rather than defaulting to a
// tpm2-keys directory resolved relative to the process's working directory.
// AutoInitialize tolerates the failure -- tpm2 is skipped with a warning,
// exactly like a host with no TPM hardware -- and software still comes up.
func TestAutoInitialize_NoDataDirNeverWritesTPM2KeysInCWD(t *testing.T) {
	t.Cleanup(func() { Reset() })

	wd, err := os.Getwd()
	require.NoError(t, err)
	strayDir := filepath.Join(wd, "tpm2-keys")
	_, statErr := os.Stat(strayDir)
	require.True(t, os.IsNotExist(statErr), "precondition: no stray tpm2-keys dir in the working directory")

	require.NoError(t, AutoInitialize(nil))
	assert.True(t, IsInitialized())

	_, statErr = os.Stat(strayDir)
	assert.True(t, os.IsNotExist(statErr), "AutoInitialize must never create tpm2-keys under the working directory")
}

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
				"key_storage": storage.New(),
			},
		},
	})
	require.NoError(t, err)

	assert.True(t, IsInitialized())

	b, err := GetBackend(string(BackendSoftware))
	require.NoError(t, err)
	assert.NotNil(t, b)
}

// TestAutoInitialize_WithDatastore proves a caller-supplied Datastore handle
// (e.g. pkg/compose.FactoryBackend over the datastore, or -- as here -- any storage.Backend, standing in
// for one) is what every backend's key storage is created from: not a
// resolved directory this package opens itself.
func TestAutoInitialize_WithDatastore(t *testing.T) {
	t.Cleanup(func() { Reset() })

	tmpDir := t.TempDir()
	ds, err := file.New(tmpDir)
	require.NoError(t, err)

	err = AutoInitialize(&AutoConfig{
		Datastore:      ds,
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
				"key_storage": storage.New(),
			},
			BackendPKCS8: {
				"key_storage": storage.New(),
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

	assert.Nil(t, config.Datastore)
	assert.Equal(t, "", config.DefaultBackend)
	assert.Nil(t, config.BackendConfigs)
}

// TestAutoInitialize_UnregisteredBackendConfigFailsClosed proves a
// BackendConfigs entry for a backend no build option registers (avr has no
// factory) fails AutoInitialize instead of being skipped, and leaves the
// service uninitialized.
func TestAutoInitialize_UnregisteredBackendConfigFailsClosed(t *testing.T) {
	t.Cleanup(func() { Reset() })

	err := AutoInitialize(&AutoConfig{
		BackendConfigs: map[BackendType]map[string]interface{}{
			BackendSoftware: {},
			BackendAVR:      {},
		},
	})
	require.ErrorIs(t, err, ErrFeatureNotCompiled)

	var featureErr *FeatureNotCompiledError
	require.True(t, errors.As(err, &featureErr))
	assert.Equal(t, string(BackendAVR), featureErr.Feature)
	assert.Empty(t, featureErr.Toggle)
	assert.False(t, IsInitialized())
}

// TestAutoInitialize_UnknownBackendConfigFailsClosed proves a misspelled
// BackendConfigs key is reported, not silently ignored.
func TestAutoInitialize_UnknownBackendConfigFailsClosed(t *testing.T) {
	t.Cleanup(func() { Reset() })

	err := AutoInitialize(&AutoConfig{
		BackendConfigs: map[BackendType]map[string]interface{}{
			BackendType("softwre"): {},
		},
	})
	require.ErrorIs(t, err, ErrFeatureNotCompiled)
	assert.False(t, IsInitialized())
}

// TestAutoInitialize_UnregisteredDefaultBackendFailsClosed proves a
// DefaultBackend naming a known backend that is not compiled in fails
// closed rather than falling back to software.
func TestAutoInitialize_UnregisteredDefaultBackendFailsClosed(t *testing.T) {
	t.Cleanup(func() { Reset() })

	err := AutoInitialize(&AutoConfig{DefaultBackend: string(BackendAVR)})
	require.ErrorIs(t, err, ErrFeatureNotCompiled)
	assert.False(t, IsInitialized())
}

func TestRequireBackend(t *testing.T) {
	factory, err := RequireBackend(BackendSoftware)
	require.NoError(t, err)
	assert.NotNil(t, factory)

	factory, err = RequireBackend(BackendType("nonexistent-backend"))
	require.ErrorIs(t, err, ErrFeatureNotCompiled)
	assert.Nil(t, factory)
	assert.Equal(t, `xkms: backend "nonexistent-backend" is not compiled into this binary`, err.Error())
}

func TestFeatureNotCompiledError_NamesToggle(t *testing.T) {
	err := &FeatureNotCompiledError{Feature: "vault", Toggle: "WITH_VAULT", Tag: "vault"}

	assert.Equal(t,
		`xkms: backend "vault" is not compiled into this binary; build with WITH_VAULT=1 (build tag "vault")`,
		err.Error())
	assert.ErrorIs(t, err, ErrFeatureNotCompiled)
}

func TestBackendStorageError(t *testing.T) {
	err := &BackendStorageError{Backend: "tpm2", Err: storage.ErrEmptyPrefix}

	assert.ErrorIs(t, err, ErrBackendStorageUnresolved)
	assert.ErrorIs(t, err, storage.ErrEmptyPrefix)
	assert.Contains(t, err.Error(), `backend "tpm2"`)
}

func TestResolveDefaultBackend_PrefersSoftware(t *testing.T) {
	backends := map[string]Backend{
		string(BackendSoftware):  newMockKeyStore(string(BackendSoftware)),
		string(BackendPKCS8):     newMockKeyStore(string(BackendPKCS8)),
		string(BackendSymmetric): newMockKeyStore(string(BackendSymmetric)),
	}

	result := ResolveDefaultBackend("", backends)
	assert.Equal(t, string(BackendSoftware), result)
}

func TestResolveDefaultBackend_FallsBackWhenRequestedMissing(t *testing.T) {
	backends := map[string]Backend{
		string(BackendPKCS8):     newMockKeyStore(string(BackendPKCS8)),
		string(BackendSymmetric): newMockKeyStore(string(BackendSymmetric)),
	}

	result := ResolveDefaultBackend("nonexistent", backends)
	// Should fall back to first sorted: pkcs8 < symmetric
	assert.Equal(t, string(BackendPKCS8), result)
}

// TestResolveDefaultBackend_PrefersSoftwareWhenRequestedMissing covers the
// step between "requested" and the sorted name: a configured default that is
// not loaded falls to the software backend, not to whichever loaded backend
// happens to sort first. Without it a typo, or a backend left out of the
// build, would promote an alphabetically earlier cloud KMS to hold every key
// generated without an explicit backend.
func TestResolveDefaultBackend_PrefersSoftwareWhenRequestedMissing(t *testing.T) {
	backends := map[string]Backend{
		"awskms":                newMockKeyStore("awskms"),
		"azurekv":               newMockKeyStore("azurekv"),
		string(BackendSoftware): newMockKeyStore(string(BackendSoftware)),
	}

	assert.Equal(t, string(BackendSoftware), ResolveDefaultBackend("not-loaded", backends))
}

func TestResolveDefaultBackend_UsesRequestedWhenAvailable(t *testing.T) {
	backends := map[string]Backend{
		string(BackendSoftware): newMockKeyStore(string(BackendSoftware)),
		string(BackendPKCS8):    newMockKeyStore(string(BackendPKCS8)),
	}

	result := ResolveDefaultBackend(string(BackendPKCS8), backends)
	assert.Equal(t, string(BackendPKCS8), result)
}

// TestResolveDefaultBackend_EmptyBackends covers the out-of-contract input:
// there is no backend to name, so the rule returns the empty string rather
// than indexing an empty sorted slice. Callers reject this case first with
// their own typed error.
func TestResolveDefaultBackend_EmptyBackends(t *testing.T) {
	assert.Equal(t, "", ResolveDefaultBackend("", map[string]Backend{}))
	assert.Equal(t, "", ResolveDefaultBackend(string(BackendSoftware), nil))
}

func TestResolveBackendConfig_EmptyDefaults(t *testing.T) {
	config := &AutoConfig{}
	result, err := resolveBackendConfig(config, BackendSoftware)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestResolveBackendConfig_WithDatastore(t *testing.T) {
	config := &AutoConfig{
		Datastore: storage.New(),
	}
	result, err := resolveBackendConfig(config, BackendSoftware)
	require.NoError(t, err)
	ks, ok := result["key_storage"].(storage.Backend)
	require.True(t, ok, "key_storage must be a storage.Backend, got %T", result["key_storage"])
	assert.NotNil(t, ks)
}

func TestResolveBackendConfig_UserOverrideTakesPrecedence(t *testing.T) {
	custom := storage.New()
	config := &AutoConfig{
		Datastore: storage.New(),
		BackendConfigs: map[BackendType]map[string]interface{}{
			BackendSoftware: {
				"key_storage": custom,
			},
		},
	}
	result, err := resolveBackendConfig(config, BackendSoftware)
	require.NoError(t, err)
	assert.Same(t, custom, result["key_storage"])
}

func TestResolveBackendConfig_MergesUserConfigKeys(t *testing.T) {
	config := &AutoConfig{
		BackendConfigs: map[BackendType]map[string]interface{}{
			BackendSoftware: {
				"custom_key": "custom_value",
			},
		},
	}
	result, err := resolveBackendConfig(config, BackendSoftware)
	require.NoError(t, err)
	assert.Equal(t, "custom_value", result["custom_key"])
}

func TestCreateCertStorage_InMemory(t *testing.T) {
	cs, err := createCertStorage(nil)
	require.NoError(t, err)
	assert.NotNil(t, cs)
}

func TestCreateCertStorage_PrefixedOverDatastore(t *testing.T) {
	cs, err := createCertStorage(storage.New())
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
