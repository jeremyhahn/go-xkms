// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package seal

import (
	"context"
	"errors"
	"testing"

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

// TestWrapBarrierRegistry_AdoptsInnerAndSystem covers the adoption path an
// embedded qrdb node's seal integration uses: wrapping an already-constructed
// go-qrdb BarrierRegistry (and its system barrier) rather than building a new
// one, so SystemBarrier and Inner both report exactly what was handed in.
func TestWrapBarrierRegistry_AdoptsInnerAndSystem(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, strategy)
	require.NoError(t, err)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	wrapped := WrapBarrierRegistry(registry.Inner(), barrier)
	require.NotNil(t, wrapped)
	assert.Same(t, barrier, wrapped.SystemBarrier())
	assert.Same(t, registry.Inner(), wrapped.Inner())
}

// TestBarrierRegistry_Attach covers Attach's delegation to the underlying
// go-qrdb registry, used to wire the volume-pool subsystem on after the
// system barrier (and therefore the registry) already exists.
func TestBarrierRegistry_Attach(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, strategy)
	require.NoError(t, err)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	assert.NotPanics(t, func() { registry.Attach() })
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

	creds, err := CredentialsFor([]byte("test-password"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()
	initAndUnsealBarrier(t, barrier, creds)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	// Register a default tenant.
	tb, err := registry.RegisterTenant("tenant-1")
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

func TestBarrierRegistry_RegisterTenantWithConfig(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, strategy)
	require.NoError(t, err)

	creds, err := CredentialsFor([]byte("test-password"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()
	initAndUnsealBarrier(t, barrier, creds)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	tenantStore := newMemoryBackend()
	tb, err := registry.RegisterTenantWithConfig("tenant-custom", tenantStore, BarrierConfig{
		RootKeyPath: "custom/root-key",
	}, NewSoftwareStrategy())
	require.NoError(t, err)
	require.NotNil(t, tb)
}

func TestBarrierRegistry_UnregisterTenant(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, strategy)
	require.NoError(t, err)

	creds, err := CredentialsFor([]byte("test-password"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()
	initAndUnsealBarrier(t, barrier, creds)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	_, err = registry.RegisterTenant("tenant-rm")
	require.NoError(t, err)

	err = registry.UnregisterTenant("tenant-rm")
	require.NoError(t, err)

	_, err = registry.GetTenant("tenant-rm")
	assert.Error(t, err)
}

func TestBarrierRegistry_SealAll(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, strategy)
	require.NoError(t, err)

	creds, err := CredentialsFor([]byte("test-password"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()
	initAndUnsealBarrier(t, barrier, creds)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	err = registry.SealAll()
	require.NoError(t, err)
}

func TestBarrierRegistry_Close(t *testing.T) {
	store := newMemoryBackend()
	strategy := NewSoftwareStrategy()

	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, strategy)
	require.NoError(t, err)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	err = registry.Close()
	require.NoError(t, err)
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
