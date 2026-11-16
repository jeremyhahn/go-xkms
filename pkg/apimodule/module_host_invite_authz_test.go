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
// self-built posture: a host that runs with authorization disabled tells
// the module so, and the service then keeps allowing every decision made
// below the transport gate, as pkg/server's nil authorizer does. The qrdb
// client's RBAC plane still evaluates roles, so wiring it regardless of the
// host's posture would refuse an invitation the host allows.
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

	h := mountLikeHost(t, client, WithAuthorization(false))
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
