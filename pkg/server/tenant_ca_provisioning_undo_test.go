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
