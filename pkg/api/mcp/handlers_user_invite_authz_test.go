package mcp

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// mcpInviteDenyRBAC grants everything but users:invite: a caller that
// passes the users:create transport gate and lacks the invite grant.
type mcpInviteDenyRBAC struct{}

func (mcpInviteDenyRBAC) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	if resource+":"+action == string(qrdbsdk.PermissionUsersInvite) {
		return &qrdbsdk.PermissionDeniedError{}
	}
	return nil
}

func (mcpInviteDenyRBAC) ListPermissions(context.Context, *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

func (mcpInviteDenyRBAC) ListOwnPermissions(context.Context) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

// TestHandleCreateUser_InviteDeniedIsForbidden is SPEC row
// authz-device-onboarding on MCP: the service's users:invite refusal is the
// caller's missing grant, so it answers ErrCodeForbidden as the method gate
// does, not ErrCodeInternalError.
func TestHandleCreateUser_InviteDeniedIsForbidden(t *testing.T) {
	server := newUserTestServer(t, &mcpMockUserClient{})
	server.xkmsService.SetAuthorizer(auth.NewAuthorizer(mcpInviteDenyRBAC{}))
	t.Cleanup(func() { server.xkmsService.SetAuthorizer(nil) })

	ctx := auth.WithIdentity(context.Background(),
		&auth.Identity{Subject: "creator", TenantID: qrdbsdk.SystemTenantID})
	req := rpcRequest("user.create", &transport.CreateUserRequest{Username: "invitee", Email: "invitee@example.com"})
	_, err := server.handleCreateUser(ctx, req)

	var opErr *KeyOpError
	require.True(t, errors.As(err, &opErr), "want a KeyOpError, got %v", err)
	assert.Equal(t, ErrCodeForbidden, opErr.Code)
}
