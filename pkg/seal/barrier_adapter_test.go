// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package seal

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBarrier_Success(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, strategy)
	require.NoError(t, err)
	require.NotNil(t, barrier)
}

func TestNewBarrier_NoStrategies(t *testing.T) {
	store := newMemoryBackend()

	_, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	})
	assert.Error(t, err)
}

func TestNewBarrier_WithAuditLogger(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()
	recorder := &recordingAuditLogger{}

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
		AuditLogger: recorder,
	}, strategy)
	require.NoError(t, err)
	require.NotNil(t, barrier)
}

func TestNewTenantBarrier_Success(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()

	tb, err := NewTenantBarrier("tenant-1", testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, strategy)
	require.NoError(t, err)
	require.NotNil(t, tb)
}

func TestNewTenantBarrier_NoStrategies(t *testing.T) {
	store := newMemoryBackend()

	_, err := NewTenantBarrier("tenant-1", testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	})
	assert.Error(t, err)
}

func TestNewBarrierRegistry_Success(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, strategy)
	require.NoError(t, err)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)
	require.NotNil(t, registry)
	assert.Same(t, barrier, registry.SystemBarrier())
}

// TestNewBarrierRegistry_NilSystemBarrier verifies a registry is never built
// without a system barrier.
func TestNewBarrierRegistry_NilSystemBarrier(t *testing.T) {
	registry, err := NewBarrierRegistry(nil)
	require.ErrorIs(t, err, ErrNilSystemBarrier)
	assert.Nil(t, registry)
}

// isAlreadyUnsealed returns true if err is any "already unsealed" error.
func isAlreadyUnsealed(err error) bool {
	return errors.Is(err, ErrAlreadyUnsealed) || errors.Is(err, ErrTenantAlreadyUnsealed)
}

// initAndUnsealBarrier initializes and unseals a barrier. After Initialize,
// the barrier may already be unsealed, so we tolerate that.
func initAndUnsealBarrier(t *testing.T, barrier *Barrier, creds Credentials) {
	t.Helper()
	ctx := context.Background()
	err := barrier.Initialize(ctx, creds)
	require.NoError(t, err)
	err = barrier.Unseal(ctx, creds)
	if err != nil && !isAlreadyUnsealed(err) {
		t.Fatalf("failed to unseal barrier: %v", err)
	}
}

func TestBarrierRegistry_TenantLifecycle(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, strategy)
	require.NoError(t, err)

	creds, err := CredentialsFor(t.Context(), []byte("test-password"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()
	initAndUnsealBarrier(t, barrier, creds)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	// Register a default tenant.
	tb, err := registry.RegisterTenantDefault("tenant-1")
	require.NoError(t, err)
	require.NotNil(t, tb)

	// Verify ListTenants.
	tenants := registry.ListTenants()
	assert.Contains(t, tenants, "tenant-1")

	// GetTenant.
	tb2, err := registry.GetTenant("tenant-1")
	require.NoError(t, err)
	assert.NotNil(t, tb2)

	// Tenant alias.
	tb3, err := registry.Tenant("tenant-1")
	require.NoError(t, err)
	assert.NotNil(t, tb3)

	// Initialize tenant.
	ctx := context.Background()
	err = registry.InitializeTenant(ctx, "tenant-1", creds)
	require.NoError(t, err)

	// Unseal tenant -- may already be unsealed after init.
	err = registry.UnsealTenant(ctx, "tenant-1", creds)
	if err != nil && !isAlreadyUnsealed(err) {
		t.Fatalf("unexpected unseal error: %v", err)
	}

	// TenantStatus.
	status, err := registry.TenantStatus("tenant-1")
	require.NoError(t, err)
	assert.NotNil(t, status)

	// Seal tenant.
	err = registry.SealTenant("tenant-1")
	require.NoError(t, err)

	// RemoveTenant.
	err = registry.RemoveTenant("tenant-1")
	require.NoError(t, err)

	// GetTenant should fail now.
	_, err = registry.GetTenant("tenant-1")
	assert.Error(t, err)
}

// TestBarrierRegistry_RegisterTenantOverXKMSStorage verifies go-qrdb's
// registry accepts a tenant barrier over an xkms storage backend once it is
// guarded for go-qrdb's StorageBackend contract.
func TestBarrierRegistry_RegisterTenantOverXKMSStorage(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, strategy)
	require.NoError(t, err)

	creds, err := CredentialsFor(t.Context(), []byte("test-password"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()
	initAndUnsealBarrier(t, barrier, creds)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	tb, err := registry.RegisterTenant(t.Context(), "tenant-custom", guardStorage(newMemoryBackend()), qrdbsdk.BarrierConfig{
		RootKeyPath: "custom/root-key",
	}, NewSoftwareStrategy())
	require.NoError(t, err)
	require.NotNil(t, tb)
}

func TestNewShamirStrategy_Success(t *testing.T) {
	strategy, err := NewShamirStrategy(2, 3)
	require.NoError(t, err)
	require.NotNil(t, strategy)
}

func TestNewShamirStrategy_InvalidThreshold(t *testing.T) {
	_, err := NewShamirStrategy(0, 3)
	assert.Error(t, err)
}
