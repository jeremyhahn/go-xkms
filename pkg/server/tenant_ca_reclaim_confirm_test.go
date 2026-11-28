package server

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// omittingTenantService lists every tenant except omit (as go-qrdb v0.51
// ListTenants does for metadata it cannot decode) and answers GetTenant for
// omit with getErr, or with the tenant when getErr is nil.
type omittingTenantService struct {
	*fakeTenantService
	omit   string
	getErr error
	active bool
}

func (o *omittingTenantService) ListTenants(ctx context.Context) ([]qrdbsdk.ServiceTenantInfo, error) {
	infos, err := o.fakeTenantService.ListTenants(ctx)
	if err != nil || !o.active {
		return infos, err
	}
	out := infos[:0:0]
	for _, info := range infos {
		if info.ID != o.omit {
			out = append(out, info)
		}
	}
	return out, nil
}

func (o *omittingTenantService) GetTenant(ctx context.Context, id string) (*qrdbsdk.ServiceTenantInfo, error) {
	if o.active && id == o.omit && o.getErr != nil {
		return nil, o.getErr
	}
	return o.fakeTenantService.GetTenant(ctx, id)
}

func assertTenantLoginCAPresent(t *testing.T, base xkms.Backend, tenantID string) {
	t.Helper()
	ctx := context.Background()
	_, err := tenantLoginCAKeyAttrs(ctx, base, tenantID)
	require.NoError(t, err, "a registered tenant lost its login CA key")
	exists, err := xkms.NewTenantScopedBackend(base, tenantID).CertExists(ctx, tenantLoginCAKeyCN)
	require.NoError(t, err)
	assert.True(t, exists, "a registered tenant lost its login CA certificate")
}

func TestTenantCAKeyFactory_ReclaimConfirmsWithGetTenant(t *testing.T) {
	cases := map[string]struct {
		getErr  error
		reclaim bool
	}{
		"GetTenant still finds it":    {getErr: nil, reclaim: false},
		"GetTenant decode error":      {getErr: errors.New("tenant metadata: decode: unexpected EOF"), reclaim: false},
		"GetTenant typed not found":   {getErr: qrdbsdk.ErrTenantMissing, reclaim: true},
		"GetTenant wrapped not found": {getErr: errors.Join(errors.New("lookup"), qrdbsdk.ErrTenantMissing), reclaim: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f, base := newTenantCAKeyTestFactory(t)
			svc := &omittingTenantService{
				fakeTenantService: &fakeTenantService{tenants: []string{"tenant-a", "tenant-x"}},
				omit:              "tenant-x",
				getErr:            tc.getErr,
			}
			f.TrackTenants(svc)
			require.NoError(t, f.EnsureTenant(ctx, "tenant-a"))
			require.NoError(t, f.EnsureTenant(ctx, "tenant-x"))

			svc.active = true
			_ = f.ReclaimWithdrawnTenants(ctx)
			assertTenantLoginCAPresent(t, base, "tenant-a")
			if tc.reclaim {
				assertNoTenantLoginCA(t, base, "tenant-x")
				return
			}
			assertTenantLoginCAPresent(t, base, "tenant-x")
		})
	}
}
