package server

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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
	return f.deleteErr
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
