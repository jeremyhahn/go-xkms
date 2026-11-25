package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

// retainingKeyBackend behaves like Cloud KMS: DeleteKey destroys the key's
// version but the key resource stays listed, has no usable version, and its
// name cannot be created again; RotateKey gives it a fresh version.
type retainingKeyBackend struct {
	xkms.Backend
	mu        sync.Mutex
	destroyed map[string]bool
}

var errRetainedNoUsableVersion = errors.New("crypto key has no enabled version")

func (b *retainingKeyBackend) isDestroyed(cn string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.destroyed[cn]
}

func (b *retainingKeyBackend) DeleteKey(_ context.Context, attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed == nil {
		b.destroyed = map[string]bool{}
	}
	b.destroyed[attrs.CN] = true
	return nil
}

func (b *retainingKeyBackend) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if b.isDestroyed(attrs.CN) {
		return nil, backend.ErrKeyAlreadyExists
	}
	return b.Backend.GenerateECDSA(ctx, attrs)
}

func (b *retainingKeyBackend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, err := b.Backend.RotateKey(ctx, attrs)
	if err == nil {
		b.mu.Lock()
		delete(b.destroyed, attrs.CN)
		b.mu.Unlock()
	}
	return key, err
}

func (b *retainingKeyBackend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if b.isDestroyed(attrs.CN) {
		return nil, errRetainedNoUsableVersion
	}
	return b.Backend.GetKey(ctx, attrs)
}

func (b *retainingKeyBackend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	if b.isDestroyed(attrs.CN) {
		return nil, errRetainedNoUsableVersion
	}
	return b.Backend.Signer(ctx, attrs)
}

// failAfterKeyTenantCAKeys provisions the login CA key, then reports the
// provision failed, so the create rolls back over a key that exists.
type failAfterKeyTenantCAKeys struct {
	*tenantCAKeyFactory
}

func (k failAfterKeyTenantCAKeys) EnsureTenant(ctx context.Context, tenantID string) error {
	if err := k.tenantCAKeyFactory.EnsureTenant(ctx, tenantID); err != nil {
		return err
	}
	return errors.New("provisioning failed after the key")
}

func newRetainingKeyServer(t *testing.T) (*retainingKeyBackend, *tenantCAKeyFactory, *fakeTenantService) {
	t.Helper()
	_, inner := newTenantCAKeyTestFactory(t)
	base := &retainingKeyBackend{Backend: inner}
	f := newTenantCAKeyFactory()
	native := &fakeTenantService{}
	s := &Server{
		config:       &config.Config{},
		tenantCAKeys: f,
		backends:     map[string]xkms.Backend{"software": base},
	}
	s.adoptTenantService(native)
	useTenantCAClaimStorage(s)
	require.NoError(t, s.provisionTenantCAKeys(context.Background()))
	return base, f, native
}

func requireUsableLoginCA(t *testing.T, f *tenantCAKeyFactory, tenantID string) {
	t.Helper()
	ctx := context.Background()
	prov, err := f.ProviderForTenant(tenantID)
	require.NoError(t, err)
	signer, err := prov.Signer(ctx)
	require.NoError(t, err, "the login CA of %s must have a usable key", tenantID)
	cert, err := prov.Certificate(ctx)
	require.NoError(t, err)
	require.True(t, signer.Public().(*ecdsa.PublicKey).Equal(cert.PublicKey))
}

// TestTenantLoginCA_RetryAfterRollbackWithRetainedKey retries a tenant ID
// whose rolled-back login CA key the backend keeps listed as destroyed.
func TestTenantLoginCA_RetryAfterRollbackWithRetainedKey(t *testing.T) {
	ctx := context.Background()
	_, f, native := newRetainingKeyServer(t)

	var provErr *TenantProvisionError
	_, err := newProvisioningTenantService(native, failAfterKeyTenantCAKeys{f}).CreateTenant(ctx, "tenant-g", "G", "")
	require.ErrorAs(t, err, &provErr)
	_, err = native.GetTenant(ctx, "tenant-g")
	require.Error(t, err, "the failed create must be rolled back")

	_, err = newProvisioningTenantService(native, f).CreateTenant(ctx, "tenant-g", "G", "")
	require.NoError(t, err, "a retry of the tenant ID must provision a fresh key")
	requireUsableLoginCA(t, f, "tenant-g")

	// A restart keeps the retried tenant's login CA usable.
	require.NoError(t, provisionTenantCAKeysWith(ctx, native, f))
	requireUsableLoginCA(t, f, "tenant-g")
}

// TestTenantLoginCA_ReclaimWithRetainedKeyDoesNotBlockBoot restarts after a
// native delete whose login CA key the backend keeps listed as destroyed.
func TestTenantLoginCA_ReclaimWithRetainedKeyDoesNotBlockBoot(t *testing.T) {
	ctx := context.Background()
	_, f, native := newRetainingKeyServer(t)

	_, err := newProvisioningTenantService(native, f).CreateTenant(ctx, "tenant-w", "W", "")
	require.NoError(t, err)
	requireUsableLoginCA(t, f, "tenant-w")
	require.NoError(t, native.DeleteTenant(ctx, "tenant-w"))

	// The first boot reclaims the key; the backend keeps it listed.
	require.NoError(t, provisionTenantCAKeysWith(ctx, native, f))
	// Later boots must not fail on the destroyed key.
	require.NoError(t, provisionTenantCAKeysWith(ctx, native, f))
	require.NoError(t, f.ReclaimWithdrawnTenants(ctx))

	// The ID can be used again.
	_, err = newProvisioningTenantService(native, f).CreateTenant(ctx, "tenant-w", "W2", "")
	require.NoError(t, err)
	requireUsableLoginCA(t, f, "tenant-w")
}

// outageKeyBackend fails every Signer call while down is set.
type outageKeyBackend struct {
	*retainingKeyBackend
	mu   sync.Mutex
	down bool
}

var errSignerOutage = errors.New("key service unavailable")

func (b *outageKeyBackend) setDown(down bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.down = down
}

func (b *outageKeyBackend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.Lock()
	down := b.down
	b.mu.Unlock()
	if down {
		return nil, errSignerOutage
	}
	return b.retainingKeyBackend.Signer(ctx, attrs)
}

// TestTenantLoginCA_SignerOutageKeepsLiveKey fails the Signer of a live
// tenant's login CA key and checks the key and its claim are kept.
func TestTenantLoginCA_SignerOutageKeepsLiveKey(t *testing.T) {
	ctx := context.Background()
	_, inner := newTenantCAKeyTestFactory(t)
	base := &outageKeyBackend{retainingKeyBackend: &retainingKeyBackend{Backend: inner}}
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

	_, err := newProvisioningTenantService(native, f).CreateTenant(ctx, "tenant-s", "S", "")
	require.NoError(t, err)
	requireUsableLoginCA(t, f, "tenant-s")
	prov, err := f.ProviderForTenant("tenant-s")
	require.NoError(t, err)
	before, err := prov.Certificate(ctx)
	require.NoError(t, err)
	claims := f.boundClaims()
	claimBefore, err := claims.Get(ctx, tenantLoginCAClaimKey("tenant-s"))
	require.NoError(t, err)

	base.setDown(true)
	require.ErrorIs(t, f.EnsureTenant(ctx, "tenant-s"), errSignerOutage)
	_ = provisionTenantCAKeysWith(ctx, native, f)
	require.NoError(t, f.ReclaimWithdrawnTenants(ctx))
	base.setDown(false)

	retired, err := tenantLoginCAKeyRetired(ctx, claims, "tenant-s")
	require.NoError(t, err)
	require.False(t, retired, "a Signer error must not retire a live key")
	claimAfter, err := claims.Get(ctx, tenantLoginCAClaimKey("tenant-s"))
	require.NoError(t, err)
	require.Equal(t, claimBefore, claimAfter, "a Signer error must leave the claim untouched")
	requireUsableLoginCA(t, f, "tenant-s")
	after, err := prov.Certificate(ctx)
	require.NoError(t, err)
	require.True(t, before.PublicKey.(*ecdsa.PublicKey).Equal(after.PublicKey), "the live key must be kept")
}
