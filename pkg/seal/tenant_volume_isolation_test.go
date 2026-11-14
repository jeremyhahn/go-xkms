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

	"github.com/jeremyhahn/go-xkms/pkg/storage"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// permissiveEntitlements allows every isolation mode + system-managed
// auto-unseal, mirroring the node's tenant default (pkg/embeddednode's
// tenantDefaultEntitlements).
func permissiveEntitlements() *qrdbsdk.Entitlements {
	return &qrdbsdk.Entitlements{
		AllowedIsolationModes:     []string{"prefix", "barrier", "volume", "raft"},
		AllowDedicatedRaft:        true,
		AllowVolumeStorage:        true,
		AllowSystemManagedBarrier: true,
		AllowDedicatedWAL:         true,
	}
}

// newTenantTestStack builds an unsealed software system barrier, a barrier
// registry over it, and the composed TenantService.
func newTenantTestStack(t *testing.T, ents *qrdbsdk.Entitlements) (*BarrierRegistry, TenantService) {
	t.Helper()
	ctx := t.Context()

	// The engine-backed memory store: go-qrdb's TenantService commits a new
	// tenant with a fenced create, which the store must decide atomically.
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	barrier, err := NewBarrier(testLogger(), base, BarrierConfig{
		RootKeyPath: "core/seal",
	}, NewSoftwareStrategy())
	require.NoError(t, err)
	creds, err := CredentialsFor(ctx, []byte("system-pass"))
	require.NoError(t, err)
	t.Cleanup(func() { creds.Secret.Destroy() })
	require.NoError(t, barrier.Initialize(ctx, creds))
	if barrier.IsSealed() {
		require.NoError(t, barrier.Unseal(ctx, creds))
	}

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	svc, err := NewHardwareTenantService(barrier, registry, testLogger(), nil,
		qrdbsdk.WithTenantDefaultEntitlements(ents))
	require.NoError(t, err)

	return registry, svc
}

// TestVolumeTenant_EntitlementDenied verifies the entitlement plane: with the
// conservative default entitlements (no volume storage), a volume-isolation
// tenant create is rejected before any pool allocation.
func TestVolumeTenant_EntitlementDenied(t *testing.T) {
	ctx := context.Background()
	_, svc := newTenantTestStack(t, qrdbsdk.DefaultEntitlements())

	_, err := svc.CreateTenant(ctx, "vol-denied", "Denied",
		qrdbsdk.TenantIsolationVolume, qrdbsdk.WithBarrierAutoUnseal(true))
	assert.Error(t, err, "volume isolation must be denied without the AllowVolumeStorage entitlement")
}

// TestBarrierTenant_RefusedWithoutVolumePool verifies a registry over xkms's
// own barrier refuses a barrier-isolated tenant rather than hosting it in the
// shared store: go-qrdb places every dedicated barrier on a per-tenant volume,
// and only the qrdb node composes the volume pool that provides one.
func TestBarrierTenant_RefusedWithoutVolumePool(t *testing.T) {
	ctx := context.Background()
	registry, svc := newTenantTestStack(t, permissiveEntitlements())

	_, err := svc.CreateTenant(ctx, "bar-1", "Barrier Tenant", qrdbsdk.TenantIsolationBarrier)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "per-tenant pebble registry not configured")

	_, err = registry.Tenant("bar-1")
	assert.Error(t, err, "a refused create must not leave a tenant barrier registered")
}

// TestHardwareTenantService_StoreWithoutFencedCreateRefuses proves a tenant
// metadata store that cannot decide a fenced create atomically refuses the
// create rather than checking the tombstone and then writing.
func TestHardwareTenantService_StoreWithoutFencedCreateRefuses(t *testing.T) {
	ctx := context.Background()
	barrier, err := NewBarrier(testLogger(), newMemoryBackend(), BarrierConfig{RootKeyPath: "core/seal"}, NewSoftwareStrategy())
	require.NoError(t, err)
	creds, err := CredentialsFor(t.Context(), []byte("system-pass"))
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

// TestHardwareTenantService_UpdatesTenantThroughGuardedSwap pins that go-qrdb's
// TenantService, which commits every tenant record update with a guarded
// swap, can update a tenant over the composed xkms store: the system barrier
// forwards the swap to the engine-backed memory store, which decides it.
func TestHardwareTenantService_UpdatesTenantThroughGuardedSwap(t *testing.T) {
	ctx := t.Context()
	_, svc := newTenantTestStack(t, permissiveEntitlements())
	_, err := svc.CreateTenant(ctx, "t-1", "Tenant", qrdbsdk.TenantIsolationPrefix)
	require.NoError(t, err)

	narrowed := permissiveEntitlements()
	narrowed.AllowDedicatedRaft = false
	info, err := svc.UpdateEntitlements(ctx, "t-1", narrowed)
	require.NoError(t, err)
	assert.False(t, info.Entitlements.AllowDedicatedRaft)

	got, err := svc.GetTenant(ctx, "t-1")
	require.NoError(t, err)
	assert.False(t, got.Entitlements.AllowDedicatedRaft, "the update was committed")
}
