package auth

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ctxIdentityRBAC records the identity the decision context carries.
type ctxIdentityRBAC struct {
	fakeRBACClient
	seen *Identity
}

func (r *ctxIdentityRBAC) Authorize(ctx context.Context, _ *qrdbtransport.Identity, _, _ string) error {
	r.seen = GetIdentity(ctx)
	return nil
}

func TestAuthorize_BindsTheSuppliedIdentity(t *testing.T) {
	rec := &ctxIdentityRBAC{}
	a := NewAuthorizer(rec)
	supplied := &Identity{Subject: "alice", Roles: []string{"viewer"}}
	admin := &Identity{Subject: "root", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"admin"}}

	for name, ctx := range map[string]context.Context{
		"absent":      context.Background(),
		"conflicting": WithIdentity(context.Background(), admin),
	} {
		t.Run(name, func(t *testing.T) {
			rec.seen = nil
			require.NoError(t, a.Authorize(ctx, supplied, "users", "invite"))
			require.NotNil(t, rec.seen)
			assert.Equal(t, "alice", rec.seen.Subject)
			assert.Equal(t, qrdbsdk.SystemTenantID, rec.seen.TenantID)
			assert.Equal(t, []string{"viewer"}, rec.seen.Roles)
		})
	}
	assert.Empty(t, supplied.TenantID, "the supplied identity is not mutated")
}
