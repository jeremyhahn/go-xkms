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

package seal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRegistry creates an initialised BarrierRegistry backed by in-memory
// storage and a software sealing strategy. The system barrier is initialised
// and unsealed so that tenant operations work immediately.
func newTestRegistry(t *testing.T) *BarrierRegistry {
	t.Helper()

	store := NewMemoryBackend()
	strategy := NewSoftwareStrategy()

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root",
	}, strategy)
	require.NoError(t, err)

	creds := Credentials{Secret: "test-pass"}
	initAndUnsealBarrier(t, barrier, creds)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	return registry
}

// newTestRegistryWithTenant registers a tenant that is initialised and unsealed.
func newTestRegistryWithTenant(t *testing.T, tenantID string) *BarrierRegistry {
	t.Helper()

	registry := newTestRegistry(t)
	_, err := registry.RegisterTenant(tenantID)
	require.NoError(t, err, "RegisterTenant(%q)", tenantID)

	ctx := context.Background()
	creds := Credentials{Secret: "tenant-pass"}
	err = registry.InitializeTenant(ctx, tenantID, creds)
	require.NoError(t, err)

	err = registry.UnsealTenant(ctx, tenantID, creds)
	if err != nil && !isAlreadyUnsealed(err) {
		t.Fatalf("UnsealTenant(%q): %v", tenantID, err)
	}

	return registry
}

// ============================================================
// NewTenantPlatformStoreFactory – constructor
// ============================================================

func TestNewTenantPlatformStoreFactory_ValidInputs(t *testing.T) {
	registry := newTestRegistry(t)
	factory := NewTenantPlatformStoreFactory(registry, nil)

	require.NotNil(t, factory)
	assert.NotNil(t, factory.logger) // nil logger → slog.Default()
	assert.Same(t, registry, factory.registry)
}

func TestNewTenantPlatformStoreFactory_NilLoggerUsesDefault(t *testing.T) {
	registry := newTestRegistry(t)
	factory := NewTenantPlatformStoreFactory(registry, nil)
	assert.NotNil(t, factory.logger)
}

func TestNewTenantPlatformStoreFactory_ExplicitLogger(t *testing.T) {
	registry := newTestRegistry(t)
	logger := testLogger()
	factory := NewTenantPlatformStoreFactory(registry, logger)
	assert.Same(t, logger, factory.logger)
}

// ============================================================
// ForTenant – first call creates store
// ============================================================

func TestTenantPlatformStoreFactory_ForTenant_CreatesOnFirstCall(t *testing.T) {
	registry := newTestRegistryWithTenant(t, "tenant-1")
	factory := NewTenantPlatformStoreFactory(registry, testLogger())

	store, err := factory.ForTenant("tenant-1")
	require.NoError(t, err)
	assert.NotNil(t, store)
}

// TestTenantPlatformStoreFactory_ForTenant_ReturnsCachedStore verifies that a
// second call to ForTenant returns the exact same *SealedPlatformStore pointer
// (i.e. the cache hit path is exercised).
func TestTenantPlatformStoreFactory_ForTenant_ReturnsCachedStore(t *testing.T) {
	registry := newTestRegistryWithTenant(t, "tenant-cache")
	factory := NewTenantPlatformStoreFactory(registry, testLogger())

	first, err := factory.ForTenant("tenant-cache")
	require.NoError(t, err)

	second, err := factory.ForTenant("tenant-cache")
	require.NoError(t, err)

	assert.Same(t, first, second, "expected the same *SealedPlatformStore on second call")
}

// ============================================================
// RemoveTenant – evicts from cache
// ============================================================

func TestTenantPlatformStoreFactory_RemoveTenant_EvictsCache(t *testing.T) {
	registry := newTestRegistryWithTenant(t, "evict-me")
	factory := NewTenantPlatformStoreFactory(registry, testLogger())

	first, err := factory.ForTenant("evict-me")
	require.NoError(t, err)

	factory.RemoveTenant("evict-me")

	// After eviction a new store should be created on the next ForTenant call.
	// The tenant is still registered in the registry, so this will succeed.
	second, err := factory.ForTenant("evict-me")
	require.NoError(t, err)

	assert.NotSame(t, first, second, "expected a fresh store after RemoveTenant")
}

func TestTenantPlatformStoreFactory_RemoveTenant_UnknownIsNoop(t *testing.T) {
	registry := newTestRegistry(t)
	factory := NewTenantPlatformStoreFactory(registry, testLogger())

	// Must not panic.
	assert.NotPanics(t, func() {
		factory.RemoveTenant("does-not-exist")
	})
}

// ============================================================
// ForTenant – unregistered tenant returns error
// ============================================================

func TestTenantPlatformStoreFactory_ForTenant_UnregisteredTenant(t *testing.T) {
	registry := newTestRegistry(t)
	factory := NewTenantPlatformStoreFactory(registry, testLogger())

	// "ghost" tenant was never registered in the registry.
	store, err := factory.ForTenant("ghost")
	require.Error(t, err)
	assert.Nil(t, store)
}

// ============================================================
// NewTenantPlatformStore – direct constructor
// ============================================================

func TestNewTenantPlatformStore_Success(t *testing.T) {
	registry := newTestRegistryWithTenant(t, "direct-tenant")

	store, err := NewTenantPlatformStore(registry, "direct-tenant", testLogger())
	require.NoError(t, err)
	require.NotNil(t, store)
}

func TestNewTenantPlatformStore_UnknownTenant(t *testing.T) {
	registry := newTestRegistry(t)

	store, err := NewTenantPlatformStore(registry, "unknown", testLogger())
	require.Error(t, err)
	assert.Nil(t, store)
}

// ============================================================
// Functional – store returned by ForTenant can Put/Get secrets
// ============================================================

func TestTenantPlatformStoreFactory_StoredSecret_Roundtrip(t *testing.T) {
	registry := newTestRegistryWithTenant(t, "roundtrip-tenant")
	factory := NewTenantPlatformStoreFactory(registry, testLogger())

	store, err := factory.ForTenant("roundtrip-tenant")
	require.NoError(t, err)

	ctx := context.Background()
	err = store.Put(ctx, "my-secret", []byte("s3cr3t"))
	require.NoError(t, err)

	got, err := store.Get(ctx, "my-secret")
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cr3t"), got)
}

// ============================================================
// Concurrent ForTenant – LoadOrStore prevents duplicates
// ============================================================

func TestTenantPlatformStoreFactory_ForTenant_Concurrent(t *testing.T) {
	registry := newTestRegistryWithTenant(t, "concurrent-tenant")
	factory := NewTenantPlatformStoreFactory(registry, testLogger())

	const goroutines = 20
	stores := make(chan *SealedPlatformStore, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			s, err := factory.ForTenant("concurrent-tenant")
			if err != nil {
				stores <- nil
				return
			}
			stores <- s
		}()
	}

	var first *SealedPlatformStore
	for i := 0; i < goroutines; i++ {
		s := <-stores
		require.NotNil(t, s, "ForTenant must not return nil")
		if first == nil {
			first = s
		} else {
			assert.Same(t, first, s, "all goroutines must receive the same store")
		}
	}
}
