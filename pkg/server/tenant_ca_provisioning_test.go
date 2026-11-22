package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTenantService is a qrdb tenant service that keeps tenants in a map and
// records deletes; only the calls the provisioning paths make are implemented.
type fakeTenantService struct {
	qrdbsdk.ServiceTenantServicer
	tenants   []string
	deleted   []string
	createErr error
	listErr   error
	deleteErr error
}

func (f *fakeTenantService) CreateTenant(_ context.Context, id, name string, _ qrdbsdk.TenantIsolationType, _ ...qrdbsdk.CreateTenantOption) (*qrdbsdk.ServiceTenantInfo, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.tenants = append(f.tenants, id)
	return &qrdbsdk.ServiceTenantInfo{ID: id, Name: name}, nil
}

func (f *fakeTenantService) ListTenants(context.Context) ([]qrdbsdk.ServiceTenantInfo, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]qrdbsdk.ServiceTenantInfo, 0, len(f.tenants))
	for _, id := range f.tenants {
		out = append(out, qrdbsdk.ServiceTenantInfo{ID: id})
	}
	return out, nil
}

func (f *fakeTenantService) DeleteTenant(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	kept := f.tenants[:0]
	for _, known := range f.tenants {
		if known != id {
			kept = append(kept, known)
		}
	}
	f.tenants = kept
	return nil
}

// UndoCreateTenant removes the tenant as DeleteTenant does and records it in
// deleted, so a test sees the rollback of a failed create.
func (f *fakeTenantService) UndoCreateTenant(ctx context.Context, id string) error {
	return f.DeleteTenant(ctx, id)
}

// fakeTenantCAKeys counts EnsureTenant calls per tenant and provisions a
// tenant at most once, as tenantCAKeyFactory.EnsureTenant does.
type fakeTenantCAKeys struct {
	calls       map[string]int
	provisioned map[string]int
	failFor     string
	err         error
}

func newFakeTenantCAKeys() *fakeTenantCAKeys {
	return &fakeTenantCAKeys{calls: map[string]int{}, provisioned: map[string]int{}}
}

func (k *fakeTenantCAKeys) EnsureTenant(_ context.Context, id string) error {
	k.calls[id]++
	if id == k.failFor {
		return k.err
	}
	if k.provisioned[id] == 0 {
		k.provisioned[id] = 1
	}
	return nil
}

func (k *fakeTenantCAKeys) ReviveTenant(context.Context, string) error { return nil }

func (k *fakeTenantCAKeys) RemoveTenant(_ context.Context, id string) error {
	delete(k.provisioned, id)
	return nil
}

func TestProvisioningTenantService_CreateProvisionsKey(t *testing.T) {
	svc := &fakeTenantService{}
	keys := newFakeTenantCAKeys()
	wrapped := newProvisioningTenantService(svc, keys)

	info, err := wrapped.CreateTenant(context.Background(), "tenant-a", "A", "")
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", info.ID)
	assert.Equal(t, 1, keys.provisioned["tenant-a"])
	assert.Empty(t, svc.deleted)
}

func TestProvisioningTenantService_CreateErrorPassesThrough(t *testing.T) {
	createErr := errors.New("create refused")
	svc := &fakeTenantService{createErr: createErr}
	keys := newFakeTenantCAKeys()

	_, err := newProvisioningTenantService(svc, keys).CreateTenant(context.Background(), "tenant-a", "A", "")
	require.ErrorIs(t, err, createErr)
	assert.Empty(t, keys.calls)
	assert.Empty(t, svc.deleted)
}

func TestProvisioningTenantService_EnsureFailureDeletesTenant(t *testing.T) {
	ensureErr := errors.New("backend unavailable")
	deleteErr := errors.New("delete failed")
	svc := &fakeTenantService{deleteErr: deleteErr}
	keys := newFakeTenantCAKeys()
	keys.failFor, keys.err = "tenant-a", ensureErr

	info, err := newProvisioningTenantService(svc, keys).CreateTenant(context.Background(), "tenant-a", "A", "")
	assert.Nil(t, info)
	var perr *TenantProvisionError
	require.ErrorAs(t, err, &perr)
	assert.Equal(t, "tenant-a", perr.TenantID)
	assert.ErrorIs(t, err, ensureErr)
	assert.ErrorIs(t, err, deleteErr)
	assert.Equal(t, []string{"tenant-a"}, svc.deleted)
}

func TestProvisionTenantCAKeys_EveryTenantOnceAndIdempotent(t *testing.T) {
	svc := &fakeTenantService{tenants: []string{"tenant-a", "tenant-b"}}
	keys := newFakeTenantCAKeys()
	ctx := context.Background()

	require.NoError(t, provisionTenantCAKeysWith(ctx, svc, keys))
	for _, id := range []string{"tenant-a", "tenant-b", qrdbsdk.SystemTenantID} {
		assert.Equal(t, 1, keys.calls[id], id)
		assert.Equal(t, 1, keys.provisioned[id], id)
	}

	require.NoError(t, provisionTenantCAKeysWith(ctx, svc, keys))
	for _, id := range []string{"tenant-a", "tenant-b", qrdbsdk.SystemTenantID} {
		assert.Equal(t, 2, keys.calls[id], id)
		assert.Equal(t, 1, keys.provisioned[id], id)
	}
}

func TestProvisionTenantCAKeys_SystemTenantListedOnce(t *testing.T) {
	svc := &fakeTenantService{tenants: []string{qrdbsdk.SystemTenantID, "tenant-a"}}
	keys := newFakeTenantCAKeys()

	require.NoError(t, provisionTenantCAKeysWith(context.Background(), svc, keys))
	assert.Equal(t, 1, keys.calls[qrdbsdk.SystemTenantID])
	assert.Equal(t, 1, keys.calls["tenant-a"])
}

func TestProvisionTenantCAKeys_EnsureErrorIsTyped(t *testing.T) {
	ensureErr := errors.New("backend unavailable")
	svc := &fakeTenantService{tenants: []string{"tenant-a", "tenant-b"}}
	keys := newFakeTenantCAKeys()
	keys.failFor, keys.err = "tenant-b", ensureErr

	err := provisionTenantCAKeysWith(context.Background(), svc, keys)
	var perr *TenantProvisionError
	require.ErrorAs(t, err, &perr)
	assert.Equal(t, "tenant-b", perr.TenantID)
	assert.ErrorIs(t, err, ensureErr)
}

func TestProvisionTenantCAKeys_ListErrorIsTyped(t *testing.T) {
	listErr := errors.New("list failed")
	svc := &fakeTenantService{listErr: listErr}

	err := provisionTenantCAKeysWith(context.Background(), svc, newFakeTenantCAKeys())
	var perr *TenantProvisionError
	require.ErrorAs(t, err, &perr)
	assert.Empty(t, perr.TenantID)
	assert.ErrorIs(t, err, listErr)
}

func TestServer_AdoptTenantService_NoWrapWithoutFactory(t *testing.T) {
	svc := &fakeTenantService{}
	s := &Server{}

	s.adoptTenantService(svc)
	assert.Same(t, svc, s.tenantService)
	useTenantCAClaimStorage(s)
	require.NoError(t, s.provisionTenantCAKeys(context.Background()))
}

func TestServer_AdoptTenantService_WrapsWithFactory(t *testing.T) {
	svc := &fakeTenantService{}
	s := &Server{tenantCAKeys: newTenantCAKeyFactory()}

	s.adoptTenantService(svc)
	wrapped, ok := s.tenantService.(*provisioningTenantService)
	require.True(t, ok)
	assert.Same(t, svc, wrapped.ServiceTenantServicer)
}

func TestServer_AdoptTenantService_Nil(t *testing.T) {
	s := &Server{tenantCAKeys: newTenantCAKeyFactory()}
	s.adoptTenantService(nil)
	assert.Nil(t, s.tenantService)
}

// The factory reads the server's backends only after the boot pass binds it:
// before that the node's background trust refresh would race New writing
// s.backends.
func TestServer_ProvisionTenantCAKeys_BindsFactoryAfterBackends(t *testing.T) {
	_, base := newTenantCAKeyTestFactory(t)
	f := newTenantCAKeyFactory()
	s := &Server{
		config:        &config.Config{},
		tenantCAKeys:  f,
		tenantService: &fakeTenantService{tenants: []string{"tenant-a"}},
		backends:      map[string]xkms.Backend{"software": base},
	}
	_, err := f.ProviderForTenant("tenant-a")
	require.Error(t, err, "factory resolved a backend before the boot pass")

	useTenantCAClaimStorage(s)
	require.NoError(t, s.provisionTenantCAKeys(context.Background()))
	_, err = f.ProviderForTenant("tenant-a")
	require.NoError(t, err)
	_, err = f.ProviderForTenant(qrdbsdk.SystemTenantID)
	require.NoError(t, err)
}

// Request handlers take the server's write lock; a login CA lookup made
// meanwhile must still resolve the bound backend, not read as unbound.
func TestServer_TenantCAKeys_ResolveDuringServerLockContention(t *testing.T) {
	_, base := newTenantCAKeyTestFactory(t)
	f := newTenantCAKeyFactory()
	s := &Server{
		config:        &config.Config{},
		tenantCAKeys:  f,
		tenantService: &fakeTenantService{tenants: []string{"tenant-a"}},
		backends:      map[string]xkms.Backend{"software": base},
	}
	useTenantCAClaimStorage(s)
	require.NoError(t, s.provisionTenantCAKeys(context.Background()))

	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := f.ProviderForTenant("tenant-a")
	require.NoError(t, err, "a held server lock must not unbind the login CA factory")
	ids, err := f.TenantIDs(context.Background())
	require.NoError(t, err)
	assert.Contains(t, ids, "tenant-a")
}

func (f *fakeTenantService) GetTenant(_ context.Context, id string) (*qrdbsdk.ServiceTenantInfo, error) {
	for _, known := range f.tenants {
		if known == id {
			return &qrdbsdk.ServiceTenantInfo{ID: id}, nil
		}
	}
	return nil, qrdbsdk.ErrTenantMissing
}

// go-qrdb's native onboarding (POST /v1/tenants) creates the tenant through
// the node's own tenant service, not the wrapped one, then asks the factory
// for the new tenant's login CA to sign the admin CSR. The key must be there.
func TestServer_TenantCAKeys_NativeOnboardingGetsKey(t *testing.T) {
	ctx := context.Background()
	_, base := newTenantCAKeyTestFactory(t)
	f := newTenantCAKeyFactory()
	native := &fakeTenantService{tenants: []string{"tenant-a"}}
	s := &Server{
		config:       &config.Config{},
		tenantCAKeys: f,
		backends:     map[string]xkms.Backend{"software": base},
	}
	s.adoptTenantService(native)
	useTenantCAClaimStorage(s)
	require.NoError(t, s.provisionTenantCAKeys(ctx))

	// The onboarding path: the unwrapped service creates the tenant.
	_, err := native.CreateTenant(ctx, "tenant-b", "B", qrdbsdk.TenantIsolationType(""))
	require.NoError(t, err)

	p, err := f.ProviderForTenant("tenant-b")
	require.NoError(t, err, "a tenant onboarded natively must get its login CA key")
	signer, err := p.Signer(ctx)
	require.NoError(t, err)
	cert, err := p.Certificate(ctx)
	require.NoError(t, err)
	assert.True(t, signer.Public().(*ecdsa.PublicKey).Equal(cert.PublicKey))

	// A tenant go-qrdb does not know is still refused, and gets no key.
	_, err = f.ProviderForTenant("ghost")
	require.Error(t, err)
	ids, err := f.TenantIDs(ctx)
	require.NoError(t, err)
	assert.NotContains(t, ids, "ghost")
}

// loginCATrust is the node's tenant login CA trust as go-qrdb builds it from
// the factory: the certificate of every tenant TenantIDs lists, read through
// ProviderForTenant. A certificate outside it is not a tenant issuer.
func loginCATrust(t *testing.T, f *tenantCAKeyFactory) []*x509.Certificate {
	t.Helper()
	ctx := context.Background()
	ids, err := f.TenantIDs(ctx)
	require.NoError(t, err)
	var pool []*x509.Certificate
	for _, id := range ids {
		p, err := f.ProviderForTenant(id)
		require.NoError(t, err, id)
		cert, err := p.Certificate(ctx)
		require.NoError(t, err, id)
		pool = append(pool, cert)
	}
	return pool
}

func isTenantIssuer(pool []*x509.Certificate, cert *x509.Certificate) bool {
	for _, c := range pool {
		if c.Equal(cert) {
			return true
		}
	}
	return false
}

// A deleted tenant's login CA leaves the node's trust at once, whether the
// tenant was deleted through the node's wrapped tenant service or through
// go-qrdb's own one, and the wrapped teardown removes its key and certificate.
func TestServer_TenantCAKeys_DeletedTenantWithdrawn(t *testing.T) {
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
	_, caA := tenantLoginCA(t, f, "tenant-a")
	_, caB := tenantLoginCA(t, f, "tenant-b")
	_, caC := tenantLoginCA(t, f, "tenant-c")

	// Deleted through the node's tenant service.
	require.NoError(t, s.tenantService.DeleteTenant(ctx, "tenant-a"))
	// Deleted by go-qrdb directly: no teardown hook runs.
	require.NoError(t, native.DeleteTenant(ctx, "tenant-b"))

	ids, err := f.TenantIDs(ctx)
	require.NoError(t, err)
	assert.NotContains(t, ids, "tenant-a")
	assert.NotContains(t, ids, "tenant-b")
	assert.Contains(t, ids, "tenant-c")
	assert.Contains(t, ids, qrdbsdk.SystemTenantID)

	for _, id := range []string{"tenant-a", "tenant-b"} {
		_, err := f.ProviderForTenant(id)
		assert.Error(t, err, "a deleted tenant keeps a login CA provider: %s", id)
	}

	pool := loginCATrust(t, f)
	assert.False(t, isTenantIssuer(pool, caA), "deleted tenant-a is still a tenant issuer")
	assert.False(t, isTenantIssuer(pool, caB), "deleted tenant-b is still a tenant issuer")
	assert.True(t, isTenantIssuer(pool, caC))

	// The wrapped teardown removed tenant-a's key and certificate.
	_, err = tenantLoginCAKeyAttrs(ctx, base, "tenant-a")
	assert.Error(t, err, "tenant-a's login CA key outlived the tenant")
	exists, err := xkms.NewTenantScopedBackend(base, "tenant-a").CertExists(ctx, tenantLoginCAKeyCN)
	require.NoError(t, err)
	assert.False(t, exists, "tenant-a's login CA certificate outlived the tenant")
}

// useTenantCAClaimStorage gives a test server the shared storage the tenant
// login CA factory takes its provisioning claims in.
func useTenantCAClaimStorage(s *Server) {
	claims := storage.New()
	s.qrdbStorage.Store(&claims)
}
