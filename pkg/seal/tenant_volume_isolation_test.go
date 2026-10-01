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
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// permissiveEntitlements allows every isolation mode + system-managed
// auto-unseal, mirroring xkms's operator default (xkmsDefaultEntitlements).
func permissiveEntitlements() *qrdbsdk.Entitlements {
	return &qrdbsdk.Entitlements{
		AllowedIsolationModes:     []string{"prefix", "barrier", "volume", "raft"},
		AllowDedicatedRaft:        true,
		AllowVolumeStorage:        true,
		AllowSystemManagedBarrier: true,
		AllowDedicatedWAL:         true,
	}
}

// newVolumeTestStack builds an unsealed software system barrier, a volume pool
// rooted under a temp dir, a pool-attached barrier registry, and the composed
// TenantService. It is the in-process analogue of the server's
// initializeBarrierRegistry wiring.
func newVolumeTestStack(t *testing.T, ents *qrdbsdk.Entitlements) (*BarrierRegistry, TenantService, *VolumePoolSubsystem) {
	t.Helper()
	ctx := context.Background()
	dataDir := t.TempDir()

	// The engine-backed memory store: go-qrdb's TenantService commits a new
	// tenant with a fenced create, which the store must decide atomically.
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	barrier, err := NewBarrier(testLogger(), base, BarrierConfig{
		RootKeyPath: "core/seal",
	}, NewSoftwareStrategy())
	require.NoError(t, err)
	creds, err := CredentialsFor([]byte("system-pass"))
	require.NoError(t, err)
	t.Cleanup(func() { creds.Secret.Destroy() })
	require.NoError(t, barrier.Initialize(ctx, creds))
	if barrier.IsSealed() {
		require.NoError(t, barrier.Unseal(ctx, creds))
	}

	pool, err := BuildVolumePoolSubsystem(dataDir, []qrdbsdk.DaemonVolumePoolConfig{{
		Name:  "default",
		Paths: []string{filepath.Join(dataDir, "tenant-volumes")},
	}}, testLogger(), false)
	require.NoError(t, err)
	require.NotNil(t, pool, "volume pool must be configured")
	t.Cleanup(func() { _ = pool.Close() })

	registry, err := NewBarrierRegistry(barrier,
		WithVolumePool(pool.Manager, pool.StateStore, pool.DefaultPoolName),
		WithPerTenantRegistry(pool.PerTenantRegistry),
	)
	require.NoError(t, err)

	svc, err := NewHardwareTenantService(barrier, registry, testLogger(), nil,
		qrdbsdk.WithTenantDefaultEntitlements(ents))
	require.NoError(t, err)

	return registry, svc, pool
}

// TestVolumeTenant_AutoUnseal_CreateAndUse exercises the full
// dedicated-volume-isolation path with system-managed auto-unseal: the pool
// allocates a per-tenant DataRoot, the barrier is initialized and unsealed
// credential-free under the system barrier, and the tenant's namespace is
// usable for at-rest encrypted storage.
func TestVolumeTenant_AutoUnseal_CreateAndUse(t *testing.T) {
	ctx := context.Background()
	registry, svc, _ := newVolumeTestStack(t, permissiveEntitlements())

	info, err := svc.CreateTenant(ctx, "vol-1", "Volume Tenant",
		qrdbsdk.TenantIsolationVolume, qrdbsdk.WithBarrierAutoUnseal(true))
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.TenantIsolationVolume, info.IsolationType)
	assert.NotEmpty(t, info.DataRoot, "volume tenant must be allocated a DataRoot from the pool")
	assert.True(t, info.BarrierAutoUnseal)

	tb, err := registry.Tenant("vol-1")
	require.NoError(t, err)
	require.False(t, tb.IsSealed(), "system-managed auto-unseal tenant barrier must come up unsealed")

	require.NoError(t, tb.Put(ctx, "secret-key", []byte("secret-value")))
	got, err := tb.Get(ctx, "secret-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("secret-value"), got)
}

// TestVolumeTenant_RestoreAfterRestart simulates a process restart: phase-1
// resources are fully closed (releasing the per-tenant Pebble locks), then a
// fresh barrier registry over the same persisted system store + pool directory
// must restore the auto-unseal volume tenant credential-free with its data
// intact. This exercises BarrierRegistry.RestoreVolumeTenants — the boot path
// the server runs in initializeBarrierRegistry.
func TestVolumeTenant_RestoreAfterRestart(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	// The system store is a file store: the simulated restart closes it with
	// the phase-1 stack and reopens it from disk.
	storeDir := filepath.Join(dataDir, "system-store")
	base, err := storage.OpenEngine(storage.EngineConfig{Kind: storage.EngineFile, Path: storeDir})
	require.NoError(t, err)
	creds, err := CredentialsFor([]byte("system-pass"))
	require.NoError(t, err)
	t.Cleanup(func() { creds.Secret.Destroy() })
	pools := []qrdbsdk.DaemonVolumePoolConfig{{
		Name:  "default",
		Paths: []string{filepath.Join(dataDir, "tenant-volumes")},
	}}
	cfg := BarrierConfig{RootKeyPath: "core/seal"}

	// --- Phase 1: create the volume tenant and write data. ---
	barrier1, err := NewBarrier(testLogger(), base, cfg, NewSoftwareStrategy())
	require.NoError(t, err)
	require.NoError(t, barrier1.Initialize(ctx, creds))
	if barrier1.IsSealed() {
		require.NoError(t, barrier1.Unseal(ctx, creds))
	}
	pool1, err := BuildVolumePoolSubsystem(dataDir, pools, testLogger(), false)
	require.NoError(t, err)
	reg1, err := NewBarrierRegistry(barrier1,
		WithVolumePool(pool1.Manager, pool1.StateStore, pool1.DefaultPoolName),
		WithPerTenantRegistry(pool1.PerTenantRegistry))
	require.NoError(t, err)
	svc1, err := NewHardwareTenantService(barrier1, reg1, testLogger(), nil,
		qrdbsdk.WithTenantDefaultEntitlements(permissiveEntitlements()))
	require.NoError(t, err)

	_, err = svc1.CreateTenant(ctx, "vol-1", "Volume Tenant",
		qrdbsdk.TenantIsolationVolume, qrdbsdk.WithBarrierAutoUnseal(true))
	require.NoError(t, err)
	tb1, err := reg1.Tenant("vol-1")
	require.NoError(t, err)
	require.NoError(t, tb1.Put(ctx, "k", []byte("v")))

	// --- Simulated restart: release all phase-1 handles. ---
	require.NoError(t, reg1.Close())
	require.NoError(t, pool1.PerTenantRegistry.CloseAll(ctx))
	require.NoError(t, pool1.Close())

	// --- Phase 2: fresh stack over the same store + pool dir; restore. ---
	base2, err := storage.OpenEngine(storage.EngineConfig{Kind: storage.EngineFile, Path: storeDir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = base2.Close() })
	barrier2, err := NewBarrier(testLogger(), base2, cfg, NewSoftwareStrategy())
	require.NoError(t, err)
	require.NoError(t, barrier2.Unseal(ctx, creds))
	pool2, err := BuildVolumePoolSubsystem(dataDir, pools, testLogger(), false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool2.Close() })
	reg2, err := NewBarrierRegistry(barrier2,
		WithVolumePool(pool2.Manager, pool2.StateStore, pool2.DefaultPoolName),
		WithPerTenantRegistry(pool2.PerTenantRegistry))
	require.NoError(t, err)

	require.NoError(t, reg2.RestoreVolumeTenants(ctx))

	tb2, err := reg2.Tenant("vol-1")
	require.NoError(t, err, "volume tenant must be restored after restart")
	require.False(t, tb2.IsSealed(), "restored auto-unseal tenant barrier must be unsealed credential-free")
	got, err := tb2.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got, "tenant data must survive the restart")
}

// TestVolumeTenant_EntitlementDenied verifies the entitlement plane: with the
// conservative default entitlements (no volume storage), a volume-isolation
// tenant create is rejected before any pool allocation.
func TestVolumeTenant_EntitlementDenied(t *testing.T) {
	ctx := context.Background()
	_, svc, _ := newVolumeTestStack(t, qrdbsdk.DefaultEntitlements())

	_, err := svc.CreateTenant(ctx, "vol-denied", "Denied",
		qrdbsdk.TenantIsolationVolume, qrdbsdk.WithBarrierAutoUnseal(true))
	assert.Error(t, err, "volume isolation must be denied without the AllowVolumeStorage entitlement")
}

// TestBarrierTenant_SelfManaged_SealedUntilInit verifies the two-phase model
// for a self-managed barrier-isolated tenant: CreateTenant registers the pooled
// barrier SEALED, and it stays sealed until an explicit init.
func TestBarrierTenant_SelfManaged_SealedUntilInit(t *testing.T) {
	ctx := context.Background()
	registry, svc, _ := newVolumeTestStack(t, permissiveEntitlements())

	info, err := svc.CreateTenant(ctx, "bar-1", "Barrier Tenant", qrdbsdk.TenantIsolationBarrier)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.TenantIsolationBarrier, info.IsolationType)
	assert.False(t, info.BarrierAutoUnseal)

	tb, err := registry.Tenant("bar-1")
	require.NoError(t, err)
	assert.True(t, tb.IsSealed(), "self-managed barrier tenant must remain sealed until Phase 2 init")
}

// TestHardwareTenantService_StoreWithoutFencedCreateRefuses proves a tenant
// metadata store that cannot decide a fenced create atomically refuses the
// create rather than checking the tombstone and then writing.
func TestHardwareTenantService_StoreWithoutFencedCreateRefuses(t *testing.T) {
	ctx := context.Background()
	barrier, err := NewBarrier(testLogger(), newMemoryBackend(), BarrierConfig{RootKeyPath: "core/seal"}, NewSoftwareStrategy())
	require.NoError(t, err)
	creds, err := CredentialsFor([]byte("system-pass"))
	require.NoError(t, err)
	t.Cleanup(func() { creds.Secret.Destroy() })
	require.NoError(t, barrier.Initialize(ctx, creds))
	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)
	svc, err := NewHardwareTenantService(barrier, registry, testLogger(), nil,
		qrdbsdk.WithTenantDefaultEntitlements(permissiveEntitlements()))
	require.NoError(t, err)

	_, err = svc.CreateTenant(ctx, "t-1", "Tenant", qrdbsdk.TenantIsolationPrefix)
	assert.ErrorIs(t, err, storage.ErrFencedCreateUnsupported)
	_, err = svc.GetTenant(ctx, "t-1")
	assert.Error(t, err, "nothing was created")
}
