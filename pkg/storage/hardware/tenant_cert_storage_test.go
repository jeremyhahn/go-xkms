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

package hardware

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// Helpers shared by tenant cert storage tests
// ============================================================

func testSealLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// newHardwareTestRegistry returns an initialised BarrierRegistry ready for use.
func newHardwareTestRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()

	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	barrier, err := seal.NewBarrier(testSealLogger(), store, seal.BarrierConfig{
		RootKeyPath: "test/root",
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)

	ctx := context.Background()
	creds := seal.Credentials{Secret: "test-pass"}
	err = barrier.Initialize(ctx, creds)
	require.NoError(t, err)

	err = barrier.Unseal(ctx, creds)
	if err != nil && !isAlreadyUnsealed(err) {
		t.Fatalf("unseal barrier: %v", err)
	}

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)

	return registry
}

// isAlreadyUnsealed returns true when err signals that the barrier is already open.
func isAlreadyUnsealed(err error) bool {
	return err != nil && (err == seal.ErrAlreadyUnsealed || err == seal.ErrTenantAlreadyUnsealed)
}

// newHardwareTestRegistryWithTenant registers, initialises, and unseals a tenant.
func newHardwareTestRegistryWithTenant(t *testing.T, tenantID string) *seal.BarrierRegistry {
	t.Helper()

	registry := newHardwareTestRegistry(t)

	_, err := registry.RegisterTenant(tenantID)
	require.NoError(t, err)

	ctx := context.Background()
	creds := seal.Credentials{Secret: "tenant-pass"}
	err = registry.InitializeTenant(ctx, tenantID, creds)
	require.NoError(t, err)

	err = registry.UnsealTenant(ctx, tenantID, creds)
	if err != nil && !isAlreadyUnsealed(err) {
		t.Fatalf("UnsealTenant(%q): %v", tenantID, err)
	}

	return registry
}

// ============================================================
// NewTenantCertStorageFactory – constructor
// ============================================================

func TestNewTenantCertStorageFactory_ValidRegistry(t *testing.T) {
	registry := newHardwareTestRegistry(t)
	factory := NewTenantCertStorageFactory(registry)
	require.NotNil(t, factory)
	assert.Same(t, registry, factory.registry)
}

// ============================================================
// ForTenant – first call creates storage
// ============================================================

func TestTenantCertStorageFactory_ForTenant_CreatesOnFirstCall(t *testing.T) {
	registry := newHardwareTestRegistryWithTenant(t, "tenant-1")
	factory := NewTenantCertStorageFactory(registry)

	cs, err := factory.ForTenant("tenant-1")
	require.NoError(t, err)
	assert.NotNil(t, cs)
}

// TestTenantCertStorageFactory_ForTenant_ReturnsCached verifies that a second
// call to ForTenant returns the exact same HardwareCertStorage value
// (the LoadOrStore cache path).
func TestTenantCertStorageFactory_ForTenant_ReturnsCached(t *testing.T) {
	registry := newHardwareTestRegistryWithTenant(t, "cache-tenant")
	factory := NewTenantCertStorageFactory(registry)

	first, err := factory.ForTenant("cache-tenant")
	require.NoError(t, err)

	second, err := factory.ForTenant("cache-tenant")
	require.NoError(t, err)

	// Both must point to the identical underlying value.
	assert.Equal(t, first, second, "expected the same HardwareCertStorage on second call")
}

// ============================================================
// RemoveTenant – evicts from cache
// ============================================================

func TestTenantCertStorageFactory_RemoveTenant_EvictsCache(t *testing.T) {
	registry := newHardwareTestRegistryWithTenant(t, "evict-tenant")
	factory := NewTenantCertStorageFactory(registry)

	_, err := factory.ForTenant("evict-tenant")
	require.NoError(t, err)

	factory.RemoveTenant("evict-tenant")

	// After eviction a new store should be created.
	second, err := factory.ForTenant("evict-tenant")
	require.NoError(t, err)
	require.NotNil(t, second)
}

func TestTenantCertStorageFactory_RemoveTenant_UnknownIsNoop(t *testing.T) {
	registry := newHardwareTestRegistry(t)
	factory := NewTenantCertStorageFactory(registry)

	assert.NotPanics(t, func() {
		factory.RemoveTenant("ghost")
	})
}

// ============================================================
// ForTenant – unregistered tenant returns error
// ============================================================

func TestTenantCertStorageFactory_ForTenant_UnregisteredTenant(t *testing.T) {
	registry := newHardwareTestRegistry(t)
	factory := NewTenantCertStorageFactory(registry)

	cs, err := factory.ForTenant("not-registered")
	require.Error(t, err)
	assert.Nil(t, cs)
}

// ============================================================
// NewTenantCertStorage – direct constructor
// ============================================================

func TestNewTenantCertStorage_Success(t *testing.T) {
	registry := newHardwareTestRegistryWithTenant(t, "direct-tenant")

	cs, err := NewTenantCertStorage(registry, "direct-tenant")
	require.NoError(t, err)
	assert.NotNil(t, cs)
}

func TestNewTenantCertStorage_UnknownTenant(t *testing.T) {
	registry := newHardwareTestRegistry(t)

	cs, err := NewTenantCertStorage(registry, "unknown-tenant")
	require.Error(t, err)
	assert.Nil(t, cs)
}

// ============================================================
// Functional – SaveCert / GetCert roundtrip via tenant storage
// ============================================================

func TestTenantCertStorage_Roundtrip(t *testing.T) {
	registry := newHardwareTestRegistryWithTenant(t, "roundtrip-tenant")
	factory := NewTenantCertStorageFactory(registry)

	cs, err := factory.ForTenant("roundtrip-tenant")
	require.NoError(t, err)

	cert := generateTestCertForAdapter(t, "roundtrip.example.com")

	err = cs.SaveCert("leaf", cert)
	require.NoError(t, err)

	got, err := cs.GetCert("leaf")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, cert.SerialNumber, got.SerialNumber)
}

// ============================================================
// CertExists via tenant-scoped storage
// ============================================================

func TestTenantCertStorage_CertExists(t *testing.T) {
	registry := newHardwareTestRegistryWithTenant(t, "exists-tenant")
	factory := NewTenantCertStorageFactory(registry)

	cs, err := factory.ForTenant("exists-tenant")
	require.NoError(t, err)

	cert := generateTestCertForAdapter(t, "exists.example.com")
	err = cs.SaveCert("check", cert)
	require.NoError(t, err)

	exists, err := cs.CertExists("check")
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = cs.CertExists("not-there")
	require.NoError(t, err)
	assert.False(t, exists)
}

// ============================================================
// Concurrent ForTenant – LoadOrStore prevents duplicates
// ============================================================

func TestTenantCertStorageFactory_ForTenant_Concurrent(t *testing.T) {
	registry := newHardwareTestRegistryWithTenant(t, "concurrent-tenant")
	factory := NewTenantCertStorageFactory(registry)

	const goroutines = 20
	type result struct {
		cs  HardwareCertStorage
		err error
	}
	results := make(chan result, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			cs, err := factory.ForTenant("concurrent-tenant")
			results <- result{cs, err}
		}()
	}

	var first HardwareCertStorage
	for i := 0; i < goroutines; i++ {
		r := <-results
		require.NoError(t, r.err)
		require.NotNil(t, r.cs)
		if first == nil {
			first = r.cs
		} else {
			assert.Equal(t, first, r.cs, "all goroutines must receive the same storage")
		}
	}
}
