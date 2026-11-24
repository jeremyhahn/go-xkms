package apimodule

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestModule_HostMount_InviteNeedsUsersInvite is SPEC row
// authz-device-onboarding on the self-built ServiceModule path: a host that
// mounts the module without pkg/server enforces RBAC through go-qrdb, so a
// caller holding users:create but not users:invite must not be handed an
// invitation. The module wires the host's qrdb RBAC into the resolved
// service; without it the service authorizer is nil and allows the mint.
func TestModule_HostMount_InviteNeedsUsersInvite(t *testing.T) {
	client := newHostNodeClient(t)
	ctx := context.Background()
	_, err := client.Roles().CreateRole(ctx, &qrdbtransport.CreateRoleRequest{
		ID:          "creator",
		Name:        "creator",
		TenantID:    qrdbsdk.SystemTenantID,
		Permissions: []string{string(qrdbsdk.PermissionUsersCreate)},
	})
	require.NoError(t, err)

	h := mountLikeHost(t, client)
	// The embedding host composes the service it resolves with its own
	// qrdb user plane, as pkg/server does; nothing here sets an authorizer.
	h.svc.SetUserClients(client.Users(), client.Roles())
	h.module.hostStores(h.svc)

	creator := &auth.Identity{Subject: "creator", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"creator"}}
	cctx := auth.WithIdentity(ctx, creator)
	require.NoError(t, h.svc.AuthorizeCaller(cctx,
		qrdbsdk.PermissionResource(qrdbsdk.PermissionUsersCreate),
		qrdbsdk.PermissionAction(qrdbsdk.PermissionUsersCreate)),
		"the role grants users:create")

	_, err = h.svc.CreateUser(cctx, &transport.CreateUserRequest{
		Username: "invitee",
		Email:    "invitee@example.com",
		TenantID: qrdbsdk.SystemTenantID,
	})
	var denied *qrdbsdk.PermissionDeniedError
	require.True(t, errors.As(err, &denied), "want PermissionDeniedError, got %v", err)
}

// TestModule_HostMount_AuthDisabledAllowsInvite is the other half of the
// self-built posture: the host owns the service it resolves, and a host
// that runs with authorization disabled sets a disabled authorizer on it
// (auth.NewAuthorizer(nil)), as pkg/server's is when RBAC is off. The
// module keeps the host's choice, so every decision made below the
// transport gate stays allowed; the qrdb client's RBAC plane still
// evaluates roles and would refuse an invitation the host allows.
func TestModule_HostMount_AuthDisabledAllowsInvite(t *testing.T) {
	client := newHostNodeClient(t)
	ctx := context.Background()
	_, err := client.Roles().CreateRole(ctx, &qrdbtransport.CreateRoleRequest{
		ID:          "creator",
		Name:        "creator",
		TenantID:    qrdbsdk.SystemTenantID,
		Permissions: []string{string(qrdbsdk.PermissionUsersCreate)},
	})
	require.NoError(t, err)

	h := mountLikeHost(t, client)
	h.svc.SetAuthorizer(auth.NewAuthorizer(nil))
	h.svc.SetUserClients(client.Users(), client.Roles())
	h.module.hostStores(h.svc)

	creator := &auth.Identity{Subject: "creator", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"creator"}}
	_, err = h.svc.CreateUser(auth.WithIdentity(ctx, creator), &transport.CreateUserRequest{
		Username: "invitee",
		Email:    "invitee@example.com",
		TenantID: qrdbsdk.SystemTenantID,
	})
	require.NoError(t, err, "an auth-disabled host allows the invitation")
}

// nodeScopeAuthorizer stands in for the host node's Authorizer(): it
// grants what the identity carries in ScopePermissions.
type nodeScopeAuthorizer struct{}

func (nodeScopeAuthorizer) Authorize(_ context.Context, identity *auth.Identity, resource, action string) error {
	for _, p := range identity.ScopePermissions {
		if p == resource+":"+action {
			return nil
		}
	}
	return &qrdbsdk.PermissionDeniedError{}
}

// TestModule_HostMount_DelegatedInviteUsesNodeAuthorizer: a delegated caller
// granted users:invite only through ScopePermissions gets its invitation
// when the host sets its node's authorizer on the service it owns
// (auth.NewNodeAuthorizer), which decides on the original identity; the
// module keeps it rather than replacing it with the SDK RBAC client, which
// drops ScopePermissions.
func TestModule_HostMount_DelegatedInviteUsesNodeAuthorizer(t *testing.T) {
	client := newHostNodeClient(t)
	h := mountLikeHost(t, client)
	h.svc.SetAuthorizer(auth.NewNodeAuthorizer(client.RBAC(), nodeScopeAuthorizer{}))
	h.svc.SetUserClients(client.Users(), client.Roles())
	h.module.hostStores(h.svc)

	delegated := &auth.Identity{
		Subject:          "qrdb-service:onboarder",
		TenantID:         qrdbsdk.SystemTenantID,
		ScopePermissions: []string{string(qrdbsdk.PermissionUsersInvite)},
	}
	_, err := h.svc.CreateUser(auth.WithIdentity(context.Background(), delegated), &transport.CreateUserRequest{
		Username: "invitee",
		Email:    "invitee@example.com",
		TenantID: qrdbsdk.SystemTenantID,
	})
	require.NoError(t, err, "the delegated users:invite grant is honoured")
}

// hostTargetAuthorizer stands in for the host's AuthMiddleware handed over
// through SetTenantTargetAuthorizer: it decides on the full identity ctx
// carries (ScopePermissions) and, as users:invite's ScopeSelfStrict does,
// only within the caller's own tenant.
type hostTargetAuthorizer struct{}

func (hostTargetAuthorizer) AuthorizeTenantTarget(ctx context.Context, tenantID string, perm qrdbsdk.Permission) error {
	id := auth.GetIdentity(ctx)
	if id != nil && id.TenantID == tenantID {
		for _, p := range id.ScopePermissions {
			if p == string(perm) {
				return nil
			}
		}
	}
	return &qrdbsdk.PermissionDeniedError{Resource: "users", Action: "invite"}
}

// TestModule_HostMount_DefaultAuthorizerKeepsDelegatedGrants: with no
// authorizer set by the host, the self-built service decides on the host's
// target-aware authorizer, so a delegated grant (ScopePermissions) the SDK
// RBAC projection drops is honoured, and a foreign target tenant is refused
// with nothing created.
func TestModule_HostMount_DefaultAuthorizerKeepsDelegatedGrants(t *testing.T) {
	client := newHostNodeClient(t)
	h := mountLikeHost(t, client)
	h.module.SetTenantTargetAuthorizer(hostTargetAuthorizer{})
	h.svc.SetUserClients(client.Users(), client.Roles())
	h.module.hostStores(h.svc)
	require.NotNil(t, h.svc.Authorizer(), "the host wires a default authorizer")

	delegated := &auth.Identity{
		Subject:          "qrdb-service:onboarder",
		TenantID:         qrdbsdk.SystemTenantID,
		ScopePermissions: []string{string(qrdbsdk.PermissionUsersInvite)},
	}
	ctx := auth.WithIdentity(context.Background(), delegated)
	_, err := h.svc.CreateUser(ctx, &transport.CreateUserRequest{
		Username: "invitee",
		Email:    "invitee@example.com",
		TenantID: qrdbsdk.SystemTenantID,
	})
	require.NoError(t, err, "the delegated users:invite grant is honoured on the default path")

	_, err = h.svc.CreateUser(ctx, &transport.CreateUserRequest{
		Username: "foreign",
		Email:    "foreign@example.com",
		TenantID: "tenant-b",
	})
	var denied *qrdbsdk.PermissionDeniedError
	require.True(t, errors.As(err, &denied), "want PermissionDeniedError, got %v", err)
	_, err = client.Users().GetUserByUsername(ctx, "tenant-b", "foreign")
	require.Error(t, err, "a refused invite leaves no account behind")
}
