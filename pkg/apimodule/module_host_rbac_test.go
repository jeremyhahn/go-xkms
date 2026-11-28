package apimodule

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// hostTargetRecorder stands in for the host's AuthMiddleware.
type hostTargetRecorder struct {
	err      error
	tenant   string
	perm     qrdbsdk.Permission
	identity *auth.Identity
}

func (r *hostTargetRecorder) AuthorizeTenantTarget(ctx context.Context, tenantID string, perm qrdbsdk.Permission) error {
	r.tenant, r.perm, r.identity = tenantID, perm, auth.GetIdentity(ctx)
	return r.err
}

func TestHostRBAC_DecidesThroughTargetOnTheSuppliedIdentity(t *testing.T) {
	rec := &hostTargetRecorder{}
	a := auth.NewAuthorizer(hostRBAC{RBACClient: nodeScopeRBAC{}, target: rec})
	supplied := &auth.Identity{
		Subject:          "svc",
		ScopePermissions: []string{string(qrdbsdk.PermissionUsersInvite)},
	}
	admin := &auth.Identity{Subject: "root", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"admin"}}

	require.NoError(t, a.Authorize(auth.WithIdentity(context.Background(), admin), supplied, "users", "invite"))
	assert.Equal(t, qrdbsdk.SystemTenantID, rec.tenant)
	assert.Equal(t, qrdbsdk.PermissionUsersInvite, rec.perm)
	require.NotNil(t, rec.identity)
	assert.Equal(t, "svc", rec.identity.Subject)
	assert.Equal(t, supplied.ScopePermissions, rec.identity.ScopePermissions)

	rec.err = &qrdbsdk.PermissionDeniedError{Resource: "users", Action: "invite"}
	var denied *qrdbsdk.PermissionDeniedError
	assert.True(t, errors.As(a.Authorize(context.Background(), supplied, "users", "invite"), &denied))
}
