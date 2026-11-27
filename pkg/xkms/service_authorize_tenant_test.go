package xkms

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// targetRecorder stands in for the host's TenantTargetAuthorizer.
type targetRecorder struct {
	err      error
	tenant   string
	perm     qrdbsdk.Permission
	identity *auth.Identity
}

func (r *targetRecorder) AuthorizeTenantTarget(ctx context.Context, tenantID string, perm qrdbsdk.Permission) error {
	r.tenant, r.perm, r.identity = tenantID, perm, auth.GetIdentity(ctx)
	return r.err
}

func TestAuthorizeTenant_ForeignTenantRefusedWithoutTarget(t *testing.T) {
	svc := &XKMSService{}
	svc.SetAuthorizer(auth.NewAuthorizer(&recordingRBAC{grant: "users:invite"}))
	system := &auth.Identity{Subject: "admin", TenantID: qrdbsdk.SystemTenantID}

	err := svc.authorizeTenant(auth.WithIdentity(context.Background(), system), system, "tenant-b", "users", "invite")
	var denied *qrdbsdk.PermissionDeniedError
	require.True(t, errors.As(err, &denied), "want PermissionDeniedError, got %v", err)
	assert.Equal(t, "users", denied.Resource)
	assert.Equal(t, "invite", denied.Action)
}

func TestAuthorizeTenant_OwnTenantDecidedAsAuthorize(t *testing.T) {
	rbac := &recordingRBAC{}
	svc := &XKMSService{}
	svc.SetAuthorizer(auth.NewAuthorizer(rbac))
	svc.SetTenantTargetAuthorizer(&targetRecorder{err: errors.New("target is not asked")})
	id := &auth.Identity{Subject: "op", TenantID: "tenant-a"}
	ctx := auth.WithIdentity(context.Background(), id)

	require.Error(t, svc.authorizeTenant(ctx, id, "tenant-a", "users", "invite"))
	require.Error(t, svc.authorizeTenant(ctx, id, "", "users", "invite"))
	rbac.grant = "users:invite"
	require.NoError(t, svc.authorizeTenant(ctx, id, "tenant-a", "users", "invite"))
	assert.Equal(t, "op", rbac.identity.Subject)
}

func TestAuthorizeTenant_ForeignTenantDecidedByTargetOnTheSuppliedIdentity(t *testing.T) {
	rec := &targetRecorder{}
	svc := &XKMSService{}
	svc.SetAuthorizer(auth.NewAuthorizer(&recordingRBAC{}))
	svc.SetTenantTargetAuthorizer(rec)
	supplied := &auth.Identity{
		Subject:          "svc",
		ScopePermissions: []string{string(qrdbsdk.PermissionUsersInvite)},
	}
	admin := &auth.Identity{Subject: "root", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"admin"}}

	for name, ctx := range map[string]context.Context{
		"absent":      context.Background(),
		"conflicting": auth.WithIdentity(context.Background(), admin),
	} {
		t.Run(name, func(t *testing.T) {
			rec.identity, rec.err = nil, nil
			require.NoError(t, svc.authorizeTenant(ctx, supplied, "tenant-b", "users", "invite"))
			assert.Equal(t, "tenant-b", rec.tenant)
			assert.Equal(t, qrdbsdk.PermissionUsersInvite, rec.perm)
			require.NotNil(t, rec.identity)
			assert.Equal(t, "svc", rec.identity.Subject)
			assert.Equal(t, qrdbsdk.SystemTenantID, rec.identity.TenantID)
			assert.Equal(t, supplied.ScopePermissions, rec.identity.ScopePermissions)

			rec.err = &qrdbsdk.PermissionDeniedError{Resource: "users", Action: "invite"}
			var denied *qrdbsdk.PermissionDeniedError
			assert.True(t, errors.As(svc.authorizeTenant(ctx, supplied, "tenant-b", "users", "invite"), &denied))
		})
	}
	assert.Empty(t, supplied.TenantID, "the supplied identity is not mutated")
}

func TestAuthorizeTenant_DisabledAllowsAndNilIdentityRefused(t *testing.T) {
	id := &auth.Identity{Subject: "op", TenantID: "tenant-a"}
	ctx := auth.WithIdentity(context.Background(), id)
	target := &targetRecorder{err: errors.New("x")}

	off := &XKMSService{}
	off.SetAuthorizer(auth.NewAuthorizer(nil))
	off.SetTenantTargetAuthorizer(target)
	assert.NoError(t, off.authorizeTenant(ctx, id, "tenant-b", "users", "invite"))

	unset := &XKMSService{}
	assert.NoError(t, unset.authorizeTenant(ctx, id, "tenant-b", "users", "invite"))

	on := &XKMSService{}
	on.SetAuthorizer(auth.NewAuthorizer(&recordingRBAC{}))
	on.SetTenantTargetAuthorizer(target)
	assert.ErrorIs(t, on.authorizeTenant(ctx, nil, "tenant-b", "users", "invite"), auth.ErrUnauthenticated)
}
