package server

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"

	tenantpkg "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
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

// failingEnsureTenantCAKeys runs the real factory's EnsureTenant and then
// reports a failure, as a provisioning pass that stopped after its key.
type failingEnsureTenantCAKeys struct{ *tenantCAKeyFactory }

func (k failingEnsureTenantCAKeys) EnsureTenant(ctx context.Context, tenantID string) error {
	return errors.Join(k.tenantCAKeyFactory.EnsureTenant(ctx, tenantID), errors.New("provisioning interrupted"))
}

// A wrapped create whose provisioning fails is undone: the plain tombstone
// stays and the ID is free. go-qrdb's native onboarding (POST /v1/tenants)
// may then create the same ID through the unwrapped service and ask for its
// login CA: the tenant is new, so it must get one.
func TestProvisioningTenantService_NativeOnboardingAfterUndoneCreateGetsLoginCA(t *testing.T) {
	ctx := context.Background()
	_, base := newTenantCAKeyTestFactory(t)
	f := newTenantCAKeyFactory()
	native := &fakeTenantService{}
	s := &Server{
		config:       &config.Config{},
		tenantCAKeys: f,
		backends:     map[string]xkms.Backend{"software": base},
	}
	s.adoptTenantService(native)
	useTenantCAClaimStorage(s)
	require.NoError(t, s.provisionTenantCAKeys(ctx))

	p := newProvisioningTenantService(native, failingEnsureTenantCAKeys{f})
	_, err := p.CreateTenant(ctx, "tenant-u", "U", "")
	var provErr *TenantProvisionError
	require.ErrorAs(t, err, &provErr)
	_, err = native.GetTenant(ctx, "tenant-u")
	require.Error(t, err, "the failed create must be undone")

	_, err = native.CreateTenant(ctx, "tenant-u", "U", qrdbsdk.TenantIsolationType(""))
	require.NoError(t, err)

	prov, err := f.ProviderForTenant("tenant-u")
	require.NoError(t, err, "a natively onboarded tenant whose ID was undone must get its login CA")
	signer, err := prov.Signer(ctx)
	require.NoError(t, err)
	cert, err := prov.Certificate(ctx)
	require.NoError(t, err)
	require.True(t, signer.Public().(*ecdsa.PublicKey).Equal(cert.PublicKey), "the login CA cert must be over the signer's key")
}

// failingDeleteKeyBackend fails DeleteKey while fail is set, as a key
// backend that is down or denies the delete.
type failingDeleteKeyBackend struct {
	xkms.Backend
	fail atomic.Bool
}

func (b *failingDeleteKeyBackend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if b.fail.Load() {
		return errors.New("key backend unavailable")
	}
	return b.Backend.DeleteKey(ctx, attrs)
}

// A wrapped create whose rollback fails in its login CA cleanup leaves the
// tenant listed beside its CA tombstone. A restart after the key backend
// recovers resumes that rollback instead of failing the boot pass, and a
// tenant natively re-created under an ID whose undo had finished gets its
// login CA at boot.
func TestProvisionTenantCAKeys_RestartAfterFailedRollbackResumesUndo(t *testing.T) {
	ctx := context.Background()
	_, inner := newTenantCAKeyTestFactory(t)
	base := &failingDeleteKeyBackend{Backend: inner}
	f := newTenantCAKeyFactory()
	native := &fakeTenantService{}
	s := &Server{
		config:       &config.Config{},
		tenantCAKeys: f,
		backends:     map[string]xkms.Backend{"software": base},
	}
	s.adoptTenantService(native)
	useTenantCAClaimStorage(s)
	require.NoError(t, s.provisionTenantCAKeys(ctx))

	p := newProvisioningTenantService(native, failingEnsureTenantCAKeys{f})

	// A finished undo, then a native re-create of the same ID that never
	// asks for its provider before the restart.
	_, err := p.CreateTenant(ctx, "tenant-n", "N", "")
	var provErr *TenantProvisionError
	require.ErrorAs(t, err, &provErr)
	_, err = native.CreateTenant(ctx, "tenant-n", "N", qrdbsdk.TenantIsolationType(""))
	require.NoError(t, err)

	// A rollback whose CA cleanup fails keeps the tenant.
	base.fail.Store(true)
	_, err = p.CreateTenant(ctx, "tenant-r", "R", "")
	require.ErrorAs(t, err, &provErr)
	_, err = native.GetTenant(ctx, "tenant-r")
	require.NoError(t, err, "a rollback whose CA cleanup failed keeps the tenant")

	// The backend recovers; the node restarts.
	base.fail.Store(false)
	require.NoError(t, provisionTenantCAKeysWith(ctx, native, f), "boot must resume the rollback, not fail on its tombstone")

	_, err = native.GetTenant(ctx, "tenant-r")
	require.Error(t, err, "boot must finish the pending rollback")
	_, err = tenantLoginCAKeyAttrs(ctx, base, "tenant-r")
	require.ErrorIs(t, err, errTenantLoginCAKeyNotFound, "the rolled-back tenant must keep no CA key")

	prov, err := f.ProviderForTenant("tenant-n")
	require.NoError(t, err, "a natively re-created tenant must get its login CA at boot")
	signer, err := prov.Signer(ctx)
	require.NoError(t, err)
	cert, err := prov.Certificate(ctx)
	require.NoError(t, err)
	require.True(t, signer.Public().(*ecdsa.PublicKey).Equal(cert.PublicKey), "the login CA cert must be over the signer's key")
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
