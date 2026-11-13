package xkms

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

// grantSetRBAC is an RBAC client granting exactly the permissions in grants
// and refusing everything else with go-qrdb's own denial type, as the RBAC
// authorizer does.
type grantSetRBAC struct {
	grants map[string]bool
}

func (r *grantSetRBAC) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	if r.grants[resource+":"+action] {
		return nil
	}
	return &qrdbsdk.PermissionDeniedError{}
}

func (r *grantSetRBAC) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

func (r *grantSetRBAC) ListOwnPermissions(ctx context.Context) ([]qrdbtransport.PermissionInfo, error) {
	return r.ListPermissions(ctx, nil)
}

// inviteAuthzService is a user service whose authorizer grants perms, with
// a user client counting the accounts it creates.
func inviteAuthzService(t *testing.T, perms ...string) (*XKMSService, *int, context.Context) {
	t.Helper()
	svc, users, _ := setupServiceWithUserClients(t)
	grants := map[string]bool{}
	for _, p := range perms {
		grants[p] = true
	}
	if perms != nil {
		svc.SetAuthorizer(auth.NewAuthorizer(&grantSetRBAC{grants: grants}))
	} else {
		svc.SetAuthorizer(nil)
	}
	t.Cleanup(func() { svc.SetAuthorizer(nil) })
	created := 0
	users.createUser = func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		created++
		lifecycle := qrdbsdk.LifecycleActive
		if req.Pending {
			lifecycle = qrdbsdk.LifecyclePending
		}
		return &qrdbtransport.User{ID: 42, Username: req.Username, Email: req.Email, TenantID: "tenant-1", Lifecycle: string(lifecycle)}, nil
	}
	users.deleteUser = func(_ context.Context, _ uint64) error {
		created--
		return nil
	}
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "operator", TenantID: "tenant-1"})
	return svc, &created, ctx
}

var (
	permUsersCreate = string(qrdbsdk.PermissionUsersCreate)
	permUsersInvite = string(qrdbsdk.PermissionUsersInvite)
)

// TestCreateUser_InviteRequiresUsersInvite proves users:create alone does not
// mint an invitation: the refusal is go-qrdb's denial and no account is left.
func TestCreateUser_InviteRequiresUsersInvite(t *testing.T) {
	svc, created, ctx := inviteAuthzService(t, permUsersCreate)

	resp, err := svc.CreateUser(ctx, &transport.CreateUserRequest{Username: "erin", Email: "erin@example.com"})
	require.Error(t, err)
	assert.Nil(t, resp)
	var denied *qrdbsdk.PermissionDeniedError
	assert.True(t, errors.As(err, &denied), "want a PermissionDeniedError, got %v", err)
	assert.Equal(t, 0, *created, "no user may be left behind")
}

// TestCreateUser_InviteGrantedMintsInvite proves a caller holding users:create
// and users:invite gets the invitation.
func TestCreateUser_InviteGrantedMintsInvite(t *testing.T) {
	svc, created, ctx := inviteAuthzService(t, permUsersCreate, permUsersInvite)

	resp, err := svc.CreateUser(ctx, &transport.CreateUserRequest{Username: "erin", Email: "erin@example.com"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Invite)
	assert.Equal(t, 1, *created)
}

// TestCreateUser_WithoutEmailLoginKeyNeedsNoInvite proves the bootstrap path,
// which mints no invitation, needs only users:create.
func TestCreateUser_WithoutEmailLoginKeyNeedsNoInvite(t *testing.T) {
	svc, created, ctx := inviteAuthzService(t, permUsersCreate)

	resp, err := svc.CreateUser(ctx, &transport.CreateUserRequest{Username: "bootstrap", WithoutEmailLoginKey: true})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Invite)
	assert.Equal(t, 1, *created)
}

// TestCreateUser_NoAuthorizerStillInvites proves RBAC disabled (no
// authorizer) keeps the invitation path unchanged.
func TestCreateUser_NoAuthorizerStillInvites(t *testing.T) {
	svc, created, ctx := inviteAuthzService(t)

	resp, err := svc.CreateUser(ctx, &transport.CreateUserRequest{Username: "erin", Email: "erin@example.com"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Invite)
	assert.Equal(t, 1, *created)
}
