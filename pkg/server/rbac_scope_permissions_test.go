package server

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestServer_RBACHonoursScopePermissions is SPEC row authz-device-onboarding
// on xkmsd: the authorizer the transports and XKMSService share decides on
// the caller's full go-qrdb identity, so a delegated caller granted
// users:create and users:invite through ScopePermissions (a token's scp
// claim, a service principal) is allowed the invitation, as go-qrdb's own
// node authorizer allows it. The SDK RBAC client's identity projection drops
// ScopePermissions and refused it.
func TestServer_RBACHonoursScopePermissions(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Auth.EnableRBAC = true
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, server.Shutdown()) }()
	require.True(t, server.rbacAuthorizer.Enabled(), "RBAC is enabled")

	delegated := &auth.Identity{
		Subject:  "qrdb-service:onboarder",
		TenantID: qrdbsdk.SystemTenantID,
		ScopePermissions: []string{
			string(qrdbsdk.PermissionUsersCreate),
			string(qrdbsdk.PermissionUsersInvite),
		},
	}
	ctx := context.Background()
	for _, perm := range []qrdbsdk.Permission{qrdbsdk.PermissionUsersCreate, qrdbsdk.PermissionUsersInvite} {
		require.NoError(t, server.rbacAuthorizer.Authorize(ctx, delegated,
			qrdbsdk.PermissionResource(perm), qrdbsdk.PermissionAction(perm)),
			"%s is granted through ScopePermissions", perm)
	}
	// The grant is the scope set, not a blanket allow.
	require.Error(t, server.rbacAuthorizer.Authorize(ctx, delegated,
		qrdbsdk.PermissionResource(qrdbsdk.PermissionUsersDelete),
		qrdbsdk.PermissionAction(qrdbsdk.PermissionUsersDelete)))
}
