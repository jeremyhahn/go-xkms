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

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterBackendFactory_RegisterAndRetrieve(t *testing.T) {
	// Register a test factory
	testBackend := BackendType("test-factory-register")
	called := false
	testFactory := func(config map[string]interface{}) (types.KeyProvider, error) {
		called = true
		return nil, errors.New("test factory")
	}

	RegisterBackendFactory(testBackend, testFactory)

	factory, ok := GetBackendFactory(testBackend)
	assert.True(t, ok)
	assert.NotNil(t, factory)

	// Call the factory to verify it's the right one
	_, err := factory(nil)
	assert.True(t, called)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "test factory")
}

func TestGetBackendFactory_NotRegistered(t *testing.T) {
	factory, ok := GetBackendFactory(BackendType("nonexistent-factory"))
	assert.False(t, ok)
	assert.Nil(t, factory)
}

func TestGetBackendFactory_EmptyName(t *testing.T) {
	factory, ok := GetBackendFactory(BackendType(""))
	assert.False(t, ok)
	assert.Nil(t, factory)
}

func TestGetBackendFactory_Software(t *testing.T) {
	// Software factory should always be registered via init()
	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok, "software factory should be registered")
	require.NotNil(t, factory)

	// Create a backend using the factory with in-memory storage
	kp, err := factory(map[string]interface{}{
		"key_dir": "memory",
	})
	require.NoError(t, err)
	assert.NotNil(t, kp)

	// Verify the returned KeyProvider has expected type
	assert.Equal(t, types.BackendTypeSoftware, kp.Type())
}

func TestGetBackendFactory_PKCS8(t *testing.T) {
	factory, ok := GetBackendFactory(BackendPKCS8)
	require.True(t, ok, "pkcs8 factory should be registered")
	require.NotNil(t, factory)

	kp, err := factory(map[string]interface{}{
		"key_dir": "memory",
	})
	require.NoError(t, err)
	assert.NotNil(t, kp)
	assert.Equal(t, types.BackendTypeSoftware, kp.Type())
}

func TestGetBackendFactory_Symmetric(t *testing.T) {
	factory, ok := GetBackendFactory(BackendSymmetric)
	require.True(t, ok, "symmetric factory should be registered")
	require.NotNil(t, factory)

	kp, err := factory(map[string]interface{}{
		"key_dir": "memory",
	})
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestGetBackendFactory_TPM2(t *testing.T) {
	// TPM2 factory should be registered (always compiled in)
	factory, ok := GetBackendFactory(BackendTPM2)
	require.True(t, ok, "tpm2 factory should be registered")
	require.NotNil(t, factory)

	// Creating the backend will fail without TPM hardware, which is expected
	_, err := factory(map[string]interface{}{})
	// This may or may not error depending on whether TPM hardware is available.
	// On most CI/dev machines, it will error. We just verify the factory exists.
	_ = err
}

func TestGetBackendFactory_SoftwareDefaultsToMemory(t *testing.T) {
	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)

	// Empty config should default to in-memory storage
	kp, err := factory(map[string]interface{}{})
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestGetBackendFactory_SoftwareWithFilePath(t *testing.T) {
	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)

	tmpDir := t.TempDir()
	kp, err := factory(map[string]interface{}{
		"key_dir": tmpDir,
	})
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestRegisterBackendFactory_Overwrite(t *testing.T) {
	testBackend := BackendType("test-factory-overwrite")

	// Register first factory
	firstCalled := false
	RegisterBackendFactory(testBackend, func(config map[string]interface{}) (types.KeyProvider, error) {
		firstCalled = true
		return nil, errors.New("first")
	})

	// Register second factory (overwrites first)
	secondCalled := false
	RegisterBackendFactory(testBackend, func(config map[string]interface{}) (types.KeyProvider, error) {
		secondCalled = true
		return nil, errors.New("second")
	})

	factory, ok := GetBackendFactory(testBackend)
	require.True(t, ok)

	_, err := factory(nil)
	assert.False(t, firstCalled, "first factory should not be called")
	assert.True(t, secondCalled, "second factory should be called")
	assert.Contains(t, err.Error(), "second")
}

func TestRegisterBackendFactory_MultipleBackends(t *testing.T) {
	// Register factories for multiple test backends
	backends := []BackendType{
		BackendType("test-multi-a"),
		BackendType("test-multi-b"),
		BackendType("test-multi-c"),
	}

	for _, bt := range backends {
		captured := bt
		RegisterBackendFactory(captured, func(config map[string]interface{}) (types.KeyProvider, error) {
			return nil, errors.New(string(captured))
		})
	}

	// Verify all factories are retrievable
	for _, bt := range backends {
		factory, ok := GetBackendFactory(bt)
		require.True(t, ok, "factory should be registered for %s", bt)

		_, err := factory(nil)
		assert.Contains(t, err.Error(), string(bt))
	}
}

func BenchmarkGetBackendFactory(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = GetBackendFactory(BackendSoftware)
	}
}

func BenchmarkRegisterBackendFactory(b *testing.B) {
	b.ReportAllocs()
	testFactory := func(config map[string]interface{}) (types.KeyProvider, error) {
		return nil, nil
	}
	for i := 0; i < b.N; i++ {
		RegisterBackendFactory(BackendType("bench-factory"), testFactory)
	}
}
