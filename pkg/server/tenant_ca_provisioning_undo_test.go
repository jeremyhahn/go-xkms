package server

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	tenantpkg "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/require"
)

// cancellingTenantCAKeys fails its first EnsureTenant after cancelling the
// request context, the way a client that gives up mid-create does; later
// calls succeed.
type cancellingTenantCAKeys struct {
	cancel context.CancelFunc
	calls  int
}

func (k *cancellingTenantCAKeys) EnsureTenant(ctx context.Context, _ string) error {
	k.calls++
	if k.calls == 1 {
		k.cancel()
		return errors.Join(errors.New("login CA key provisioning failed"), ctx.Err())
	}
	return nil
}

func (k *cancellingTenantCAKeys) RemoveTenant(context.Context, string) error { return nil }

func (k *cancellingTenantCAKeys) ReviveTenant(context.Context, string) error { return nil }

// newRealTenantService builds go-qrdb's own tenant service over an
// initialized in-memory system barrier.
func newRealTenantService(t *testing.T) seal.TenantService {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	barrier, err := seal.NewBarrier(logger, storage.NewMemory(), seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)
	creds := seal.MustCredentials(t.Context(), []byte("test-password"))
	defer creds.Secret.Destroy()
	require.NoError(t, barrier.Initialize(context.Background(), creds))
	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	// Tenant undo active, with this node the whole serving roster, as on a
	// node whose cluster has the feature on.
	const nodeID = "node-1"
	svc, err := seal.NewHardwareTenantService(barrier, registry, logger, nil,
		tenantpkg.WithNodeID(nodeID),
		tenantpkg.WithTenantUndoGate(func() error { return nil }),
		tenantpkg.WithUndoCleanupRoster(func(context.Context) ([]string, error) { return []string{nodeID}, nil }),
	)
	require.NoError(t, err)
	return svc
}

// A create whose login CA provisioning fails after the request context is
// cancelled still leaves no tenant behind, and the same tenant ID can be
// created again: the rollback neither depends on the request context nor
// retires the ID.
func TestProvisioningTenantService_CancelledCreateRollsBackForRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	keys := &cancellingTenantCAKeys{cancel: cancel}
	p := newProvisioningTenantService(newRealTenantService(t), keys)

	_, err := p.CreateTenant(ctx, "tenant-a", "Tenant A", "")
	var provErr *TenantProvisionError
	require.ErrorAs(t, err, &provErr)

	_, err = p.GetTenant(context.Background(), "tenant-a")
	require.Error(t, err, "the failed create must leave no tenant behind")

	// The ID is undone, not retired: a retry is told to come back once the
	// serving nodes have acknowledged the cleanup (this in-memory node has no
	// volume pool, so its acknowledgement never lands here), never that the ID
	// can no longer be used.
	_, err = p.CreateTenant(context.Background(), "tenant-a", "Tenant A", "")
	var pending *qrdbsdk.TenantUndoPendingError
	require.ErrorAs(t, err, &pending, "a retry with the same tenant ID must stay possible, got: %v", err)
	require.Equal(t, "tenant-a", pending.TenantID)
}

// pausingTenantCAKeys fails every EnsureTenant and runs onRemove inside
// RemoveTenant, where a rollback is paused in its CA cleanup.
type pausingTenantCAKeys struct {
	onRemove  func(id string)
	removeErr error
	removed   []string
}

func (k *pausingTenantCAKeys) EnsureTenant(context.Context, string) error {
	return errors.New("login CA certificate save failed")
}

func (k *pausingTenantCAKeys) RemoveTenant(_ context.Context, id string) error {
	if k.onRemove != nil {
		k.onRemove(id)
	}
	k.removed = append(k.removed, id)
	return k.removeErr
}

func (k *pausingTenantCAKeys) ReviveTenant(context.Context, string) error { return nil }

// A rollback keeps the tenant ID fenced until its CA cleanup has finished:
// a create retrying the same ID while the old rollback is still removing the
// CA key is refused, so it cannot adopt the key the rollback then tombstones.
func TestProvisioningTenantService_UndoFencesIDUntilCACleanup(t *testing.T) {
	svc := newRealTenantService(t)
	keys := &pausingTenantCAKeys{}
	var retryErr error
	keys.onRemove = func(id string) {
		_, retryErr = svc.CreateTenant(context.Background(), id, "Tenant A retry", "")
	}
	p := newProvisioningTenantService(svc, keys)

	_, err := p.CreateTenant(context.Background(), "tenant-a", "Tenant A", "")
	var provErr *TenantProvisionError
	require.ErrorAs(t, err, &provErr)
	require.Equal(t, []string{"tenant-a"}, keys.removed)
	require.Error(t, retryErr, "a create retrying the ID during the CA cleanup must be refused")
	var pending *qrdbsdk.TenantUndoPendingError
	require.False(t, errors.As(retryErr, &pending), "the ID must still be held by the tenant, not undone: %v", retryErr)

	_, err = p.GetTenant(context.Background(), "tenant-a")
	require.Error(t, err, "the rollback must undo the tenant once its CA is gone")
}

// A rollback whose CA cleanup fails leaves the tenant in place, still
// fencing the ID, rather than releasing it over leftover CA material.
func TestProvisioningTenantService_UndoKeepsTenantWhenCACleanupFails(t *testing.T) {
	keys := &pausingTenantCAKeys{removeErr: errors.New("login CA key delete failed")}
	p := newProvisioningTenantService(newRealTenantService(t), keys)

	_, err := p.CreateTenant(context.Background(), "tenant-a", "Tenant A", "")
	var provErr *TenantProvisionError
	require.ErrorAs(t, err, &provErr)
	require.ErrorIs(t, err, keys.removeErr)

	_, err = p.GetTenant(context.Background(), "tenant-a")
	require.NoError(t, err, "the tenant must keep fencing the ID until DeleteTenant finishes the cleanup")
}
