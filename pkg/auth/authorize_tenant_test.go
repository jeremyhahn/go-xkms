package auth

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// targetRecorder stands in for the host's AuthMiddleware: it records the
// tenant and permission it is asked about and the identity ctx carries.
type targetRecorder struct {
	err      error
	tenant   string
	perm     qrdbsdk.Permission
	identity *Identity
}

func (r *targetRecorder) AuthorizeTenantTarget(ctx context.Context, tenantID string, perm qrdbsdk.Permission) error {
	r.tenant, r.perm, r.identity = tenantID, perm, GetIdentity(ctx)
	return r.err
}

// TestAuthorizeTenant_ForeignTenantRefusedWithoutTarget: without a
// target-aware decider a foreign tenant is refused before RBAC is asked,
// even for a system-tenant caller RBAC would allow.
func TestAuthorizeTenant_ForeignTenantRefusedWithoutTarget(t *testing.T) {
	rbac := &fakeRBACClient{}
	system := &Identity{Subject: "admin", TenantID: qrdbsdk.SystemTenantID}
	for name, a := range map[string]*Authorizer{
		"rbac": NewAuthorizer(rbac),
		"node": NewNodeAuthorizer(rbac, &scopeDecider{}),
	} {
		t.Run(name, func(t *testing.T) {
			err := a.AuthorizeTenant(WithIdentity(context.Background(), system), system, "tenant-b", "users", "invite")
			var denied *qrdbsdk.PermissionDeniedError
			require.True(t, errors.As(err, &denied), "want PermissionDeniedError, got %v", err)
			assert.Equal(t, "users", denied.Resource)
			assert.Equal(t, "invite", denied.Action)
		})
	}
}

// TestAuthorizeTenant_OwnTenantDecidedAsAuthorize: the caller's own tenant,
// named or left empty, is decided as Authorize decides it.
func TestAuthorizeTenant_OwnTenantDecidedAsAuthorize(t *testing.T) {
	rbacErr := errors.New("rbac refuses")
	a := NewAuthorizer(&fakeRBACClient{err: rbacErr})
	id := &Identity{Subject: "op", TenantID: "tenant-a"}
	ctx := WithIdentity(context.Background(), id)
	assert.ErrorIs(t, a.AuthorizeTenant(ctx, id, "tenant-a", "users", "invite"), rbacErr)
	assert.ErrorIs(t, a.AuthorizeTenant(ctx, id, "", "users", "invite"), rbacErr)

	ok := NewAuthorizer(&fakeRBACClient{})
	assert.NoError(t, ok.AuthorizeTenant(ctx, id, "tenant-a", "users", "invite"))
}

// TestHostAuthorizer_DecidesThroughTarget: a host authorizer asks the
// host's target-aware decider with the requested tenant (AuthorizeTenant)
// or the caller's own (Authorize), on the caller's full identity, and never
// the SDK RBAC projection.
func TestHostAuthorizer_DecidesThroughTarget(t *testing.T) {
	rec := &targetRecorder{}
	a := NewHostAuthorizer(&fakeRBACClient{err: errors.New("projection refuses")}, rec)
	delegated := &Identity{
		Subject:          "svc",
		TenantID:         qrdbsdk.SystemTenantID,
		ScopePermissions: []string{string(qrdbsdk.PermissionUsersInvite)},
	}
	ctx := WithIdentity(context.Background(), delegated)

	require.NoError(t, a.AuthorizeTenant(ctx, delegated, "tenant-b", "users", "invite"))
	assert.Equal(t, "tenant-b", rec.tenant)
	assert.Equal(t, qrdbsdk.PermissionUsersInvite, rec.perm)
	assert.Equal(t, delegated.ScopePermissions, rec.identity.ScopePermissions)

	require.NoError(t, a.Authorize(ctx, delegated, "users", "invite"))
	assert.Equal(t, qrdbsdk.SystemTenantID, rec.tenant)

	rec.err = &qrdbsdk.PermissionDeniedError{Resource: "users", Action: "invite"}
	var denied *qrdbsdk.PermissionDeniedError
	assert.True(t, errors.As(a.AuthorizeTenant(ctx, delegated, "tenant-b", "users", "invite"), &denied))
}

// TestAuthorizeTenant_DisabledAllows: a nil rbac (authorization disabled)
// admits any tenant, as Authorize does.
func TestAuthorizeTenant_DisabledAllows(t *testing.T) {
	id := &Identity{Subject: "op", TenantID: "tenant-a"}
	ctx := WithIdentity(context.Background(), id)
	assert.NoError(t, NewAuthorizer(nil).AuthorizeTenant(ctx, id, "tenant-b", "users", "invite"))
	assert.NoError(t, NewHostAuthorizer(nil, &targetRecorder{err: errors.New("x")}).AuthorizeTenant(ctx, id, "tenant-b", "users", "invite"))
	var nilAuthz *Authorizer
	assert.NoError(t, nilAuthz.AuthorizeTenant(ctx, id, "tenant-b", "users", "invite"))
}
