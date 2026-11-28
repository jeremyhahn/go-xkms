package server

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

// clearFailingTenantCAKeys fails every login CA provision and, while armed,
// every removal of a create rollback record.
type clearFailingTenantCAKeys struct {
	*tenantCAKeyFactory
	failClear bool
}

func (k *clearFailingTenantCAKeys) EnsureTenant(context.Context, string) error {
	return errors.New("login CA provisioning failed")
}

func (k *clearFailingTenantCAKeys) ClearCreateUndo(ctx context.Context, tenantID string) error {
	if k.failClear {
		return errors.New("claim storage unavailable")
	}
	return k.tenantCAKeyFactory.ClearCreateUndo(ctx, tenantID)
}

// TestProvisionTenantCAKeys_StaleUndoRecordSparesReusedTenantID covers a
// rollback that finished but whose record could not be removed: a tenant
// later created natively under the same ID is a new instance, so neither
// ProviderForTenant nor the boot pass may treat it as rollback-pending,
// while a genuine pending rollback still resumes at boot.
func TestProvisionTenantCAKeys_StaleUndoRecordSparesReusedTenantID(t *testing.T) {
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

	keys := &clearFailingTenantCAKeys{tenantCAKeyFactory: f}
	p := newProvisioningTenantService(native, keys)
	var provErr *TenantProvisionError

	// The undo of each create succeeds; removing its record fails.
	keys.failClear = true
	for _, id := range []string{"tenant-u", "tenant-v"} {
		_, err := p.CreateTenant(ctx, id, "U", "")
		require.ErrorAs(t, err, &provErr)
		_, err = native.GetTenant(ctx, id)
		require.Error(t, err, "the undo of %s must have finished", id)
		pending, err := f.CreateUndoPending(ctx, id)
		require.NoError(t, err)
		require.True(t, pending, "the record of %s must survive the failed removal", id)
	}
	keys.failClear = false

	// go-qrdb reuses both IDs for new tenants created natively.
	_, err := native.CreateTenant(ctx, "tenant-u", "U2", qrdbsdk.TenantIsolationType(""))
	require.NoError(t, err)
	_, err = native.CreateTenant(ctx, "tenant-v", "V2", qrdbsdk.TenantIsolationType(""))
	require.NoError(t, err)

	// Native onboarding of tenant-v asks for its login CA before a restart.
	_, err = f.ProviderForTenant("tenant-v")
	require.NoError(t, err, "a reused tenant ID must not be refused as rollback-pending")

	// A genuine pending rollback of another tenant: its CA cleanup fails.
	base.fail.Store(true)
	_, err = newProvisioningTenantService(native, failingEnsureTenantCAKeys{f}).CreateTenant(ctx, "tenant-r", "R", "")
	require.ErrorAs(t, err, &provErr)
	_, err = native.GetTenant(ctx, "tenant-r")
	require.NoError(t, err)
	base.fail.Store(false)

	// The node restarts.
	require.NoError(t, provisionTenantCAKeysWith(ctx, native, f))

	for _, id := range []string{"tenant-u", "tenant-v"} {
		_, err = native.GetTenant(ctx, id)
		require.NoError(t, err, "boot must not undo the reused tenant %s", id)
		prov, err := f.ProviderForTenant(id)
		require.NoError(t, err, "the reused tenant %s must get its login CA", id)
		signer, err := prov.Signer(ctx)
		require.NoError(t, err)
		cert, err := prov.Certificate(ctx)
		require.NoError(t, err)
		require.True(t, signer.Public().(*ecdsa.PublicKey).Equal(cert.PublicKey))
		pending, err := f.CreateUndoPending(ctx, id)
		require.NoError(t, err)
		require.False(t, pending, "the stale record of %s must be cleared", id)
	}

	_, err = native.GetTenant(ctx, "tenant-r")
	require.Error(t, err, "boot must still finish the genuine pending rollback")
	_, err = tenantLoginCAKeyAttrs(ctx, base, "tenant-r")
	require.ErrorIs(t, err, errTenantLoginCAKeyNotFound)
}
