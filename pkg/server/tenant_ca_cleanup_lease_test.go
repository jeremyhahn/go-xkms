package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// leaseHookClaims runs hook once, just before the first swap that takes a
// cleanup lease: between a late pass's tombstone read and its deletes.
type leaseHookClaims struct {
	storage.Backend
	hook func()
	once sync.Once
}

func (c *leaseHookClaims) CompareAndSwap(ctx context.Context, key string, expected, value []byte) (bool, []byte, error) {
	if tenantLoginCAClaimCleanupOwner(value) != "" {
		c.once.Do(c.hook)
	}
	return c.Backend.(storage.CompareAndSwapper).CompareAndSwap(ctx, key, expected, value)
}

func (c *leaseHookClaims) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	return c.Backend.(storage.CompareAndDeleter).CompareAndDelete(ctx, key, expected)
}

// A pass that read its tenant as removed and paused before its cleanup must
// not delete the key and certificates of the tenant created again with the
// same ID meanwhile: the remove, revive and reprovision all land between the
// tombstone read and the cleanup.
func TestTenantCAKeyFactory_LateCleanupSparesRevivedTenant(t *testing.T) {
	ctx := context.Background()
	baseA, baseB := sharedTenantCABackends(t)
	shared := storage.New()
	b := newTenantCAKeyFactory()
	require.NoError(t, b.Bind(baseB, shared))
	var removeErr, reviveErr, reprovisionErr error
	nodeA := &pausingProvenanceBackend{Backend: baseA}
	nodeA.pause = func() { removeErr = b.RemoveTenant(ctx, "tenant-a") }
	claimsA := &leaseHookClaims{Backend: shared}
	claimsA.hook = func() {
		reviveErr = b.ReviveTenant(ctx, "tenant-a")
		reprovisionErr = b.EnsureTenant(ctx, "tenant-a")
	}
	a := newTenantCAKeyFactory()
	require.NoError(t, a.Bind(nodeA, claimsA))

	require.ErrorIs(t, a.EnsureTenant(ctx, "tenant-a"), errTenantLoginCARemoved)
	require.NoError(t, removeErr)
	require.NoError(t, reviveErr)
	require.NoError(t, reprovisionErr)

	attrs, err := tenantLoginCAKeyAttrs(ctx, baseB, "tenant-a")
	require.NoError(t, err, "the late cleanup deleted the revived tenant's key")
	scoped := xkms.NewTenantScopedBackend(baseB, "tenant-a")
	signer, err := scoped.Signer(ctx, attrs)
	require.NoError(t, err)
	require.True(t, tenantLoginCAKeyProvisioned(ctx, scoped, signer.Public()), "the revived tenant's provenance must survive")
	require.True(t, tenantLoginCACertValid(ctx, scoped, signer.Public()), "the revived tenant's certificate must survive")
	require.NoError(t, b.EnsureTenant(ctx, "tenant-a"))
}

// A revive waits out a live cleanup lease, and takes over the lease of a
// cleanup that stopped.
func TestTenantCAKeyFactory_ReviveRefusesLiveCleanupLease(t *testing.T) {
	ctx := context.Background()
	f, _ := newTenantCAKeyTestFactory(t)
	require.NoError(t, f.EnsureTenant(ctx, "tenant-a"))
	require.NoError(t, f.RemoveTenant(ctx, "tenant-a"))
	claims, err := f.claimStorage()
	require.NoError(t, err)
	owner, err := newTenantLoginCAClaimOwner()
	require.NoError(t, err)
	key := tenantLoginCAClaimKey("tenant-a")
	lease := []byte(tenantLoginCAClaimCleanupPrefix + owner)
	require.NoError(t, claims.Put(ctx, key, lease))

	tenantLoginCALiveOwners.Store(owner, struct{}{})
	err = f.ReviveTenant(ctx, "tenant-a")
	tenantLoginCALiveOwners.Delete(owner)
	require.ErrorIs(t, err, errTenantLoginCAClaimHeld)
	held, err := claims.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, lease, held, "a refused revive must leave the lease")
	removed, err := f.tenantLoginCARemoved(ctx, "tenant-a")
	require.NoError(t, err)
	assert.True(t, removed, "a tenant under a cleanup lease stays removed")
	assert.ErrorIs(t, f.EnsureTenant(ctx, "tenant-a"), errTenantLoginCARemoved, "no pass provisions under a cleanup lease")

	// The holder returned without putting the tombstone back.
	require.NoError(t, f.ReviveTenant(ctx, "tenant-a"))
	_, err = claims.Get(ctx, key)
	require.ErrorIs(t, err, storage.ErrNotFound)
	require.NoError(t, f.EnsureTenant(ctx, "tenant-a"))
}

// A tenant go-qrdb deleted natively never reaches RemoveTenant: the boot pass
// and the next native onboarding reclaim its login CA material, and spare
// the tenants the node still lists.
func TestServer_TenantCAKeys_NativeDeletionReclaimed(t *testing.T) {
	ctx := context.Background()
	_, base := newTenantCAKeyTestFactory(t)
	f := newTenantCAKeyFactory()
	native := &fakeTenantService{tenants: []string{"tenant-a", "tenant-b", "tenant-c"}}
	s := &Server{
		config:       &config.Config{},
		tenantCAKeys: f,
		backends:     map[string]xkms.Backend{"software": base},
	}
	s.adoptTenantService(native)
	useTenantCAClaimStorage(s)
	require.NoError(t, s.provisionTenantCAKeys(ctx))

	// Deleted by go-qrdb directly: no teardown hook runs.
	require.NoError(t, native.DeleteTenant(ctx, "tenant-b"))
	_, err := tenantLoginCAKeyAttrs(ctx, base, "tenant-b")
	require.NoError(t, err, "precondition: native deletion leaves the key")

	// The boot pass reclaims it.
	require.NoError(t, s.provisionTenantCAKeys(ctx))
	assertNoTenantLoginCA(t, base, "tenant-b")
	for _, id := range []string{"tenant-a", "tenant-c", qrdbsdk.SystemTenantID} {
		_, err := tenantLoginCAKeyAttrs(ctx, base, id)
		assert.NoError(t, err, "a listed tenant lost its login CA key: %s", id)
	}

	// The next native onboarding reclaims a tenant deleted since.
	require.NoError(t, native.DeleteTenant(ctx, "tenant-c"))
	native.tenants = append(native.tenants, "tenant-d")
	_, err = f.ProviderForTenant("tenant-d")
	require.NoError(t, err)
	assertNoTenantLoginCA(t, base, "tenant-c")

	// The ID can be created again and provisioned afresh.
	native.tenants = append(native.tenants, "tenant-b")
	_, err = f.ProviderForTenant("tenant-b")
	require.NoError(t, err, "a reclaimed tenant ID must stay usable")
}

// Only a complete listing proves a tenant gone: a failed listing reclaims
// nothing.
func TestTenantCAKeyFactory_ReclaimNeedsCompleteListing(t *testing.T) {
	ctx := context.Background()
	f, base := newTenantCAKeyTestFactory(t)
	svc := &fakeTenantService{tenants: []string{"tenant-a"}}
	f.TrackTenants(svc)
	require.NoError(t, f.EnsureTenant(ctx, "tenant-a"))
	svc.listErr = errors.New("listing unavailable")
	require.Error(t, f.ReclaimWithdrawnTenants(ctx))
	_, err := tenantLoginCAKeyAttrs(ctx, base, "tenant-a")
	require.NoError(t, err, "a failed listing must not reclaim a tenant")
}
