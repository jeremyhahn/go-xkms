// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package xkms

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/invitetest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// ============================================================================
// Mock UserClient / RoleClient
//
// These mocks implement the qrdb transport UserClient and RoleClient
// interfaces so the xkms user servicer can be exercised entirely in-memory.
// Only the methods the servicer actually calls carry behavior; the rest
// return zero values to satisfy the interface contract.
// ============================================================================

type mockUserClient struct {
	createUser        func(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error)
	getUser           func(ctx context.Context, id uint64) (*qrdbtransport.User, error)
	getUserByUsername func(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error)
	getUserByEmail    func(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error)
	listUsers         func(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error)
	deleteUser        func(ctx context.Context, id uint64) error
	enableUser        func(ctx context.Context, id uint64) error
	disableUser       func(ctx context.Context, id uint64) error
	addCertBinding    func(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error)
	updateUser        func(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error)
}

var _ qrdbtransport.UserClient = (*mockUserClient)(nil)

func (m *mockUserClient) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	return m.createUser(ctx, req)
}

func (m *mockUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	if m.getUser != nil {
		return m.getUser(ctx, id)
	}
	return nil, errors.New("not used")
}

func (m *mockUserClient) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	return m.getUserByUsername(ctx, tenantID, username)
}

func (m *mockUserClient) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	if m.getUserByEmail != nil {
		return m.getUserByEmail(ctx, tenantID, email)
	}
	return nil, &qrdbtransport.UserNotFoundError{Lookup: qrdbtransport.UserLookupKey(tenantID, email)}
}

func (m *mockUserClient) GetUserByCertThumbprint(ctx context.Context, thumbprint string) (*qrdbtransport.User, error) {
	return nil, errors.New("not used")
}

func (m *mockUserClient) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	return m.addCertBinding(ctx, userID, thumbprint, notAfterUnix)
}

func (m *mockUserClient) RemoveCertBinding(ctx context.Context, userID uint64, thumbprint string) (*qrdbtransport.User, error) {
	return nil, errors.New("not used")
}

func (m *mockUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	if m.updateUser != nil {
		return m.updateUser(ctx, req)
	}
	return nil, errors.New("not used")
}

func (m *mockUserClient) DeleteUser(ctx context.Context, id uint64) error {
	return m.deleteUser(ctx, id)
}

func (m *mockUserClient) ListUsers(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
	return m.listUsers(ctx, req)
}

func (m *mockUserClient) EnableUser(ctx context.Context, id uint64) error {
	return m.enableUser(ctx, id)
}

func (m *mockUserClient) DisableUser(ctx context.Context, id uint64) error {
	return m.disableUser(ctx, id)
}

type mockRoleClient struct {
	getRole       func(ctx context.Context, id string) (*qrdbtransport.Role, error)
	getRoleByName func(ctx context.Context, req *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error)
}

var _ qrdbtransport.RoleClient = (*mockRoleClient)(nil)

func (m *mockRoleClient) CreateRole(ctx context.Context, req *qrdbtransport.CreateRoleRequest) (*qrdbtransport.Role, error) {
	return nil, errors.New("not used")
}

func (m *mockRoleClient) GetRole(ctx context.Context, id string) (*qrdbtransport.Role, error) {
	return m.getRole(ctx, id)
}
func (m *mockRoleClient) GetRoleByName(ctx context.Context, req *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
	return m.getRoleByName(ctx, req)
}
func (m *mockRoleClient) ResolvePermissions(ctx context.Context, req *qrdbtransport.ResolvePermissionsRequest) (*qrdbtransport.ResolvePermissionsResponse, error) {
	return nil, nil
}

func (m *mockRoleClient) UpdateRole(ctx context.Context, req *qrdbtransport.UpdateRoleRequest) (*qrdbtransport.Role, error) {
	return nil, errors.New("not used")
}

func (m *mockRoleClient) DeleteRole(ctx context.Context, id string) error {
	return errors.New("not used")
}

func (m *mockRoleClient) ListRoles(ctx context.Context, req *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
	return nil, errors.New("not used")
}

func (m *mockRoleClient) AssignRole(ctx context.Context, userID uint64, roleID string) error {
	return errors.New("not used")
}

func (m *mockRoleClient) UnassignRole(ctx context.Context, userID uint64, roleID string) error {
	return errors.New("not used")
}

func (m *mockRoleClient) ListPermissions(ctx context.Context) (*qrdbtransport.ListPermissionsResponse, error) {
	return nil, errors.New("not used")
}

// ReconcileBuiltInRoles is not exercised by the servicer under test: nothing in
// pkg/xkms reconciles built-in roles, so this mock reports the verb as unused
// exactly as its other unexercised methods do. The convergence itself is
// go-qrdb's, served by its transports.
func (m *mockRoleClient) ReconcileBuiltInRoles(ctx context.Context, req *qrdbtransport.ReconcileRolesRequest) (*qrdbtransport.ReconcileRolesResponse, error) {
	return nil, errors.New("not used")
}

// singleStoreResolver resolves every tenant to the same backing KVStore —
// enough for a unit test's invite store, which does not exercise the
// per-tenant routing or barrier isolation qrdb's own tests already cover.
type singleStoreResolver struct{ store qrdbsdk.KVStore }

func (r singleStoreResolver) Resolve(context.Context, string) (qrdbsdk.KVStore, error) {
	return r.store, nil
}

// setupServiceWithUserClients wires mock user/role clients, plus a real
// (in-memory) invite store, into a fresh service and returns the service
// plus the mocks so individual tests can program per-call behavior.
//
// The invite store is qrdb's own canonical implementation over
// qrdbsdk.NewMemoryKVStore, not a mock: CreateUser's invite-minting behavior
// (go-xkms#1294 part B) is exercised against the real single-use/atomic-write
// semantics, which is the property that matters and a hand-rolled fake could
// get subtly wrong.
func setupServiceWithUserClients(t *testing.T) (*XKMSService, *mockUserClient, *mockRoleClient) {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	users := &mockUserClient{}
	roles := &mockRoleClient{}
	svc.SetUserClients(users, roles)

	inviteStore, err := invitetest.New(singleStoreResolver{store: qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	svc.SetInviteStore(inviteStore)

	return svc, users, roles
}

// ============================================================================
// userToTransport
// ============================================================================

func TestUserToTransport_ResolvesEveryRoleName(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	names := map[string]string{"role-1": "admin", "role-2": "custom-ops"}
	roles.getRole = func(_ context.Context, id string) (*qrdbtransport.Role, error) {
		return &qrdbtransport.Role{ID: id, Name: names[id]}, nil
	}

	info, err := svc.userToTransport(context.Background(), &qrdbtransport.User{
		Username:  "alice",
		Lifecycle: string(qrdbsdk.LifecycleActive),
		RoleIDs:   []string{"role-1", "role-2"},
	})
	require.NoError(t, err)

	assert.Equal(t, "alice", info.Username)
	assert.Equal(t, []string{"admin", "custom-ops"}, info.Roles)
	assert.True(t, info.Enabled)
}

func TestUserToTransport_NoRoles(t *testing.T) {
	svc, _, _ := setupServiceWithUserClients(t)

	info, err := svc.userToTransport(context.Background(), &qrdbtransport.User{
		Username:  "bob",
		Lifecycle: string(qrdbsdk.LifecycleDisabled),
	})
	require.NoError(t, err)

	assert.Equal(t, "bob", info.Username)
	assert.Empty(t, info.Roles)
	assert.False(t, info.Enabled)
}

func TestUserToTransport_RoleLookupErrorFails(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	storeErr := errors.New("role store offline")
	roles.getRole = func(_ context.Context, _ string) (*qrdbtransport.Role, error) {
		return nil, storeErr
	}

	_, err := svc.userToTransport(context.Background(), &qrdbtransport.User{
		Username: "carol",
		RoleIDs:  []string{"missing"},
	})

	// A role the store cannot resolve is an error, never a silently
	// shortened role list.
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "resolve role", opErr.Operation)
	assert.ErrorIs(t, err, storeErr)
}

// ============================================================================
// roleNameToID
// ============================================================================

func TestRoleNameToID_EmptyNameResolvesEmptyID(t *testing.T) {
	svc, _, _ := setupServiceWithUserClients(t)

	id, err := svc.roleNameToID(context.Background(), "", "")
	require.NoError(t, err)
	assert.Empty(t, id)
}

func TestRoleNameToID_BuiltInRoleIsSystemRoleID(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	roles.getRoleByName = func(_ context.Context, _ *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
		t.Fatal("a built-in role must not be looked up")
		return nil, nil
	}

	id, err := svc.roleNameToID(context.Background(), "acme", qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.SystemRoleID("acme", qrdbsdk.RoleNameAdmin), id)
}

func TestRoleNameToID_BuiltInRoleUsesContextTenant(t *testing.T) {
	svc, _, _ := setupServiceWithUserClients(t)

	ctx := qrdbsdk.ContextWithTenant(context.Background(), "acme")
	id, err := svc.roleNameToID(ctx, "", qrdbsdk.RoleNameOperator)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.SystemRoleID("acme", qrdbsdk.RoleNameOperator), id)
}

func TestRoleNameToID_CustomRoleByName(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	roles.getRoleByName = func(_ context.Context, req *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
		assert.Equal(t, "acme", req.TenantID)
		assert.Equal(t, "custom-ops", req.Name)
		return &qrdbtransport.Role{ID: "id-custom", Name: req.Name}, nil
	}

	id, err := svc.roleNameToID(context.Background(), "acme", "custom-ops")
	require.NoError(t, err)
	assert.Equal(t, "id-custom", id)
}

func TestRoleNameToID_UnknownRole(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	roles.getRoleByName = func(_ context.Context, req *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
		return nil, &qrdbsdk.RoleNotFoundError{}
	}

	id, err := svc.roleNameToID(context.Background(), "", "ghost")
	require.Error(t, err)
	assert.Empty(t, id)

	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	var unknown *ErrUnknownRole
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, "ghost", unknown.Role)
}

func TestRoleNameToID_LookupError(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	roles.getRoleByName = func(_ context.Context, _ *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
		return nil, errors.New("role backend down")
	}

	_, err := svc.roleNameToID(context.Background(), "", "custom-ops")
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "resolve role", opErr.Operation)
	var unknown *ErrUnknownRole
	assert.False(t, errors.As(err, &unknown), "a store failure is not an unknown role")
}

// ============================================================================
// CreateUser
// ============================================================================

func TestCreateUser_Success(t *testing.T) {
	svc, users, roles := setupServiceWithUserClients(t)

	adminID := qrdbsdk.SystemRoleID("", qrdbsdk.RoleNameAdmin)
	roles.getRole = func(_ context.Context, id string) (*qrdbtransport.Role, error) {
		return &qrdbtransport.Role{ID: id, Name: qrdbsdk.RoleNameAdmin}, nil
	}
	users.createUser = func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		assert.Equal(t, "dave", req.Username)
		assert.Equal(t, []string{adminID}, req.RoleIDs)
		// Echo what a real store persists — dropping Name here would hide a
		// projection bug in exactly the way this one hid.
		return &qrdbtransport.User{
			Username: "dave", Email: req.Email, Name: req.Name,
			Lifecycle: string(qrdbsdk.LifecycleActive), RoleIDs: []string{adminID},
		}, nil
	}

	resp, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username:    "dave",
		Email:       "dave@example.com",
		DisplayName: "Dave Doe",
		Role:        qrdbsdk.RoleNameAdmin,
	})
	require.NoError(t, err)
	assert.Equal(t, "dave", resp.User.Username)
	assert.Equal(t, []string{qrdbsdk.RoleNameAdmin}, resp.User.Roles)
	assert.Equal(t, "Dave Doe", resp.User.DisplayName)
}

func TestCreateUser_ProjectionErrorRollsBack(t *testing.T) {
	svc, users, roles := setupServiceWithUserClients(t)

	roles.getRole = func(_ context.Context, _ string) (*qrdbtransport.Role, error) {
		return nil, errors.New("role store offline")
	}
	users.createUser = func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 42, Username: req.Username, RoleIDs: req.RoleIDs}, nil
	}
	var deleted uint64
	users.deleteUser = func(_ context.Context, id uint64) error {
		deleted = id
		return nil
	}

	_, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username: "erin",
		Email:    "erin@example.com",
		Role:     qrdbsdk.RoleNameOperator,
	})

	// A user the caller cannot be shown is removed rather than left behind.
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, uint64(42), deleted)
}

func TestCreateUser_NoRoleAssigned(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.createUser = func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		assert.Nil(t, req.RoleIDs)
		return &qrdbtransport.User{Username: "noroles"}, nil
	}

	resp, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "noroles", Email: "noroles@example.com"})
	require.NoError(t, err)
	assert.Equal(t, "noroles", resp.User.Username)
	assert.Empty(t, resp.User.Roles)
}

func TestCreateUser_RoleResolutionError(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	roles.getRoleByName = func(_ context.Context, _ *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
		return nil, &qrdbsdk.RoleNotFoundError{}
	}

	_, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "x", Email: "x@example.com", Role: "nope"})
	var unknown *ErrUnknownRole
	require.ErrorAs(t, err, &unknown)
}

func TestCreateUser_CreateError(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.createUser = func(_ context.Context, _ *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		return nil, errors.New("duplicate username")
	}

	_, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "dupe", Email: "dupe@example.com"})
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "create user", opErr.Operation)
}

func TestCreateUser_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "x"})
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// TestCreateUser_MintsInviteForEmailAccount is go-xkms#1294 part B: an
// account created with an email login key is created PENDING and mints a
// single-use activation invitation in the same call, returned exactly once.
func TestCreateUser_MintsInviteForEmailAccount(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.createUser = func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		assert.True(t, req.Pending, "an email-login-key account must be created pending")
		return &qrdbtransport.User{
			ID: 7, Username: "erin", Email: req.Email, Name: req.Name,
			Lifecycle: string(qrdbsdk.LifecyclePending),
		}, nil
	}

	resp, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username: "erin", Email: "erin@example.com",
	})
	require.NoError(t, err)
	assert.False(t, resp.User.Enabled, "a pending account is not yet enabled")
	require.NotNil(t, resp.Invite)
	assert.NotEmpty(t, resp.Invite.Token)
	assert.WithinDuration(t, time.Now().Add(qrdbsdk.DefaultInviteTTL), resp.Invite.ExpiresAt, time.Minute)
}

// TestCreateUser_WithoutEmailLoginKeyMintsNoInvite pins the one exception:
// a certificate-only/bootstrap identity has no email an invitation could be
// sent to, so it is created active with no invitation, exactly as before
// go-xkms#1294 part B.
func TestCreateUser_WithoutEmailLoginKeyMintsNoInvite(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.createUser = func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		assert.False(t, req.Pending)
		return &qrdbtransport.User{ID: 8, Username: "bootstrap", Lifecycle: string(qrdbsdk.LifecycleActive)}, nil
	}

	resp, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username: "bootstrap", WithoutEmailLoginKey: true,
	})
	require.NoError(t, err)
	assert.True(t, resp.User.Enabled)
	assert.Nil(t, resp.Invite)
}

// TestCreateUser_InviteStoreNotConfigured fails closed BEFORE creating
// anything: an invited account this build cannot mint an invitation for is
// a pending account nothing can ever activate.
func TestCreateUser_InviteStoreNotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	users := &mockUserClient{
		createUser: func(context.Context, *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
			t.Fatal("CreateUser must not reach the store when no invite store is configured")
			return nil, nil
		},
	}
	svc.SetUserClients(users, &mockRoleClient{})

	_, err = svc.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username: "x", Email: "x@example.com",
	})
	require.ErrorIs(t, err, ErrNotConfigured)
}

// TestCreateUser_RollsBackOnInviteMintFailure proves the create is atomic: a
// user this build minted no invitation for is rolled back rather than left
// pending with nothing that can ever activate it.
func TestCreateUser_RollsBackOnInviteMintFailure(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	// The service's invite store is real (setupServiceWithUserClients wires
	// it); force a mint failure the way an exhausted tenant store would, by
	// replacing it with one whose backing KVStore is nil.
	brokenStore, err := invitetest.New(singleStoreResolver{store: nil})
	require.NoError(t, err)
	svc.SetInviteStore(brokenStore)

	deleted := false
	users.createUser = func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 9, Username: "frank", Email: req.Email, Lifecycle: string(qrdbsdk.LifecyclePending)}, nil
	}
	users.deleteUser = func(_ context.Context, id uint64) error {
		assert.Equal(t, uint64(9), id)
		deleted = true
		return nil
	}

	_, err = svc.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username: "frank", Email: "frank@example.com",
	})
	require.Error(t, err)
	assert.True(t, deleted, "the pending account must be rolled back when no invitation could be minted")
}

// ============================================================================
// ListUsers
// ============================================================================

func TestListUsers_Success(t *testing.T) {
	svc, users, roles := setupServiceWithUserClients(t)

	roles.getRole = func(_ context.Context, id string) (*qrdbtransport.Role, error) {
		return &qrdbtransport.Role{ID: id, Name: "viewer"}, nil
	}
	users.listUsers = func(_ context.Context, _ *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
		return &qrdbtransport.ListUsersResponse{Users: []*qrdbtransport.User{
			{Username: "u1", RoleIDs: []string{"r1"}, Lifecycle: string(qrdbsdk.LifecycleActive)},
			{Username: "u2"},
		}}, nil
	}

	resp, err := svc.ListUsers(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Users, 2)
	assert.Equal(t, "u1", resp.Users[0].Username)
	assert.Equal(t, []string{"viewer"}, resp.Users[0].Roles)
	assert.Equal(t, "u2", resp.Users[1].Username)
	assert.Empty(t, resp.Users[1].Roles)
}

func TestListUsers_Error(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.listUsers = func(_ context.Context, _ *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
		return nil, errors.New("list failed")
	}

	_, err := svc.ListUsers(context.Background())
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "list users", opErr.Operation)
}

func TestListUsers_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ListUsers(context.Background())
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// ============================================================================
// GetUser
// ============================================================================

func TestGetUser_Success(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
		assert.Equal(t, "alice", username)
		return &qrdbtransport.User{Username: "alice", Lifecycle: string(qrdbsdk.LifecycleActive)}, nil
	}

	resp, err := svc.GetUser(context.Background(), "alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", resp.User.Username)
	assert.True(t, resp.User.Enabled)
}

func TestGetUser_Error(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return nil, errors.New("not found")
	}

	_, err := svc.GetUser(context.Background(), "ghost")
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "get user", opErr.Operation)
}

func TestGetUser_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// ============================================================================
// DeleteUser
// ============================================================================

func TestDeleteUser_Success(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 1, Username: "alice"}, nil
	}
	var deleted uint64
	users.deleteUser = func(_ context.Context, id uint64) error {
		deleted = id
		return nil
	}

	require.NoError(t, svc.DeleteUser(context.Background(), "alice"))
	assert.Equal(t, uint64(1), deleted)
}

func TestDeleteUser_LookupError(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return nil, errors.New("missing")
	}

	err := svc.DeleteUser(context.Background(), "ghost")
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "get user for deletion", opErr.Operation)
}

func TestDeleteUser_DeleteError(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 1}, nil
	}
	users.deleteUser = func(_ context.Context, _ uint64) error {
		return errors.New("delete blocked")
	}

	err := svc.DeleteUser(context.Background(), "alice")
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "delete user", opErr.Operation)
}

func TestDeleteUser_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	assert.ErrorIs(t, svc.DeleteUser(context.Background(), "alice"), ErrNotConfigured)
}

// ============================================================================
// EnableUser / DisableUser
// ============================================================================

func TestEnableUser_Success(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 9}, nil
	}
	var enabled uint64
	users.enableUser = func(_ context.Context, id uint64) error {
		enabled = id
		return nil
	}

	require.NoError(t, svc.EnableUser(context.Background(), "alice"))
	assert.Equal(t, uint64(9), enabled)
}

func TestEnableUser_LookupError(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return nil, errors.New("missing")
	}

	err := svc.EnableUser(context.Background(), "x")
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "get user", opErr.Operation)
}

func TestEnableUser_EnableError(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 9}, nil
	}
	users.enableUser = func(_ context.Context, _ uint64) error {
		return errors.New("enable failed")
	}

	err := svc.EnableUser(context.Background(), "x")
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "enable user", opErr.Operation)
}

func TestEnableUser_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	assert.ErrorIs(t, svc.EnableUser(context.Background(), "x"), ErrNotConfigured)
}

func TestDisableUser_Success(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 7}, nil
	}
	var disabled uint64
	users.disableUser = func(_ context.Context, id uint64) error {
		disabled = id
		return nil
	}

	require.NoError(t, svc.DisableUser(context.Background(), "alice"))
	assert.Equal(t, uint64(7), disabled)
}

func TestDisableUser_LookupError(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return nil, errors.New("missing")
	}

	err := svc.DisableUser(context.Background(), "x")
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "get user", opErr.Operation)
}

func TestDisableUser_DisableError(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 7}, nil
	}
	users.disableUser = func(_ context.Context, _ uint64) error {
		return errors.New("disable failed")
	}

	err := svc.DisableUser(context.Background(), "x")
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "disable user", opErr.Operation)
}

func TestDisableUser_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	assert.ErrorIs(t, svc.DisableUser(context.Background(), "x"), ErrNotConfigured)
}

// ============================================================================
// BindUserCert
// ============================================================================

func TestBindUserCert_Success(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 5}, nil
	}
	var gotUserID uint64
	var gotThumb string
	var gotExpiry int64
	users.addCertBinding = func(_ context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
		gotUserID, gotThumb, gotExpiry = userID, thumbprint, notAfterUnix
		return &qrdbtransport.User{ID: userID}, nil
	}

	require.NoError(t, svc.BindUserCert(context.Background(), "alice", "thumb-abc", 1234))
	assert.Equal(t, uint64(5), gotUserID)
	assert.Equal(t, "thumb-abc", gotThumb)
	assert.Equal(t, int64(1234), gotExpiry)
}

func TestBindUserCert_LookupError(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return nil, errors.New("missing")
	}

	err := svc.BindUserCert(context.Background(), "x", "t", 0)
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "get user", opErr.Operation)
}

func TestBindUserCert_BindError(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 3}, nil
	}
	users.addCertBinding = func(_ context.Context, _ uint64, _ string, _ int64) (*qrdbtransport.User, error) {
		return nil, errors.New("bind failed")
	}

	err := svc.BindUserCert(context.Background(), "x", "t", 0)
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "bind cert", opErr.Operation)
}

func TestBindUserCert_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	assert.ErrorIs(t, svc.BindUserCert(context.Background(), "x", "t", 0), ErrNotConfigured)
}

// ============================================================================
// ListUserCredentials
// ============================================================================

func TestListUserCredentials_Success(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 3}, nil
	}

	resp, err := svc.ListUserCredentials(context.Background(), "alice")
	require.NoError(t, err)
	assert.Empty(t, resp.Credentials)
}

func TestListUserCredentials_LookupError(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return nil, errors.New("missing")
	}

	_, err := svc.ListUserCredentials(context.Background(), "x")
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "get user", opErr.Operation)
}

func TestListUserCredentials_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	_, err = svc.ListUserCredentials(context.Background(), "x")
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// A user provisioned without the canonical login key must be REFUSED, not
// created.
//
// This path sent Username only, so every provisioned user landed with an empty
// email index while WebAuthn enrollment resolves by email — the account existed
// and could be enrolled by nobody (Codex, go-xkms #190). Against a current qrdb
// node the create is refused outright, so the old behaviour was not merely
// incomplete, it was broken.
func TestCreateUser_EmailIsRequired(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	called := false
	users.createUser = func(_ context.Context, _ *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		called = true
		return &qrdbtransport.User{Username: "nokey"}, nil
	}

	_, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "nokey"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmailRequired)
	assert.False(t, called, "the store must not be reached; the request is refused before any write")
}

// The canonical key and the display name must REACH the store.
//
// DisplayName was previously set on the response only and never persisted, so
// it was echoed back to the caller and lost; Email was never sent at all.
// Asserting on the response would pass in both worlds, so this asserts on what
// the store actually received.
func TestCreateUser_EmailAndNameReachTheStore(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)

	var got *qrdbtransport.CreateUserRequest
	users.createUser = func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		got = req
		return &qrdbtransport.User{
			Username: req.Username, Email: req.Email, Name: req.Name, Lifecycle: string(qrdbsdk.LifecycleActive),
		}, nil
	}

	_, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username:    "erin",
		Email:       "Erin@Example.com",
		DisplayName: "Erin Example",
	})
	require.NoError(t, err)
	require.NotNil(t, got)
	// Normalized, not raw: the service canonicalises before both validating and
	// sending, so the address checked is the address stored. Asserting the raw
	// form here would now be asserting a bug.
	assert.Equal(t, "erin@example.com", got.Email, "the canonical login key must be sent to the store")
	assert.Equal(t, "Erin Example", got.Name, "the display name must be persisted, not just echoed")
	assert.False(t, got.WithoutEmailLoginKey, "a user with an email must not declare that it has none")
}

// A stored user's canonical key and display name must come back on READ.
//
// Create masked this: it assigned the request's DisplayName onto the response
// after projection, so the create call looked correct while userToTransport
// never read Name at all — and UserInfo had no Email field whatsoever. Every
// later GetUser and ListUsers returned a user with no login key and no display
// name (Codex, go-xkms #190).
func TestUserReads_ProjectEmailAndDisplayName(t *testing.T) {
	stored := &qrdbtransport.User{
		ID: 7, Username: "frank", Email: "frank@example.com", Name: "Frank Example", Lifecycle: string(qrdbsdk.LifecycleActive),
	}

	t.Run("GetUser", func(t *testing.T) {
		svc, users, _ := setupServiceWithUserClients(t)
		users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
			return stored, nil
		}
		resp, err := svc.GetUser(context.Background(), "frank")
		require.NoError(t, err)
		assert.Equal(t, "frank@example.com", resp.User.Email, "the canonical login key must be readable")
		assert.Equal(t, "Frank Example", resp.User.DisplayName, "the persisted display name must be readable")
	})

	t.Run("ListUsers", func(t *testing.T) {
		svc, users, _ := setupServiceWithUserClients(t)
		users.listUsers = func(_ context.Context, _ *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
			return &qrdbtransport.ListUsersResponse{Users: []*qrdbtransport.User{stored}}, nil
		}
		resp, err := svc.ListUsers(context.Background())
		require.NoError(t, err)
		require.Len(t, resp.Users, 1)
		assert.Equal(t, "frank@example.com", resp.Users[0].Email)
		assert.Equal(t, "Frank Example", resp.Users[0].DisplayName)
	})
}

// A whitespace-only login key must be refused HERE, as client input.
//
// The guard compared the raw value against "", so "   " passed it, reached
// qrdb, was trimmed to empty there and refused — surfacing as a generic backend
// failure that the transports map to 500/Internal. Malformed client input
// reported as a server fault is the exact path this guard exists to close
// (Codex, go-xkms #190).
func TestCreateUser_WhitespaceOnlyEmailIsClientInput(t *testing.T) {
	for _, blank := range []string{" ", "   ", "\t", "\n  \t "} {
		t.Run(fmt.Sprintf("%q", blank), func(t *testing.T) {
			svc, users, _ := setupServiceWithUserClients(t)
			called := false
			users.createUser = func(_ context.Context, _ *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
				called = true
				return &qrdbtransport.User{Username: "x"}, nil
			}

			_, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{
				Username: "x", Email: blank,
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrEmailRequired)
			assert.False(t, called, "the store must not be reached for input the client can fix")
		})
	}
}

// The normalized value is what gets STORED, so the address validated is the
// address persisted. Without this, a user could be created with a surrounding-
// whitespace or mixed-case key whose index entry qrdb normalizes differently
// from the value echoed back to the caller.
func TestCreateUser_SendsTheNormalizedEmail(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)
	var got *qrdbtransport.CreateUserRequest
	users.createUser = func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		got = req
		return &qrdbtransport.User{Username: req.Username, Email: req.Email}, nil
	}

	_, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username: "grace", Email: "  Grace@Example.COM  ",
	})
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "grace@example.com", got.Email,
		"the store must receive the canonical form, not the raw input")
}

// ============================================================================
// revokeUserSessions (go-xkms#1297): DisableUser and DeleteUser must end
// every refresh-token session the affected account holds, so a session
// started before the lifecycle change cannot keep refreshing.
// ============================================================================

// spyRefreshStore is a token.RefreshStore whose only exercised method is
// RevokeBySubject, recording every subject it is called with. The other
// methods are never reached by revokeUserSessions; a real store's
// behavior for them is already covered in pkg/auth/token.
type spyRefreshStore struct {
	revoked []string
	// failOn optionally fails RevokeBySubject for one subject, so a test can
	// prove a revoke failure does not roll back the lifecycle change that
	// already succeeded.
	failOn string
}

var _ token.RefreshStore = (*spyRefreshStore)(nil)

func (s *spyRefreshStore) Save(context.Context, *token.Record) error { return nil }

func (s *spyRefreshStore) Get(context.Context, string, string) (*token.Record, error) {
	return nil, nil
}

func (s *spyRefreshStore) MarkRotated(context.Context, string, string) error { return nil }

func (s *spyRefreshStore) RevokeFamily(context.Context, string) error { return nil }

func (s *spyRefreshStore) RevokeBySubject(_ context.Context, subject string) error {
	s.revoked = append(s.revoked, subject)
	if s.failOn != "" && subject == s.failOn {
		return errors.New("revoke store unavailable")
	}
	return nil
}

// newTestTokenIssuerWithStore builds a token issuer over a fresh software
// ECDSA P-256 key and the given refresh store.
func newTestTokenIssuerWithStore(t *testing.T, store token.RefreshStore) *token.Issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer, err := token.NewIssuer(&token.Config{
		Signer: key,
		KeyAttributes: &types.KeyAttributes{
			KeyAlgorithm:       x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			Hash:               stdcrypto.SHA256,
		},
		RefreshStore: store,
	})
	require.NoError(t, err)
	return issuer
}

func TestDisableUser_RevokesSessionsForUsernameAndWebAuthnHandle(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)
	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 42, Username: "alice"}, nil
	}
	users.disableUser = func(_ context.Context, _ uint64) error { return nil }

	store := &spyRefreshStore{}
	svc.SetTokenIssuer(newTestTokenIssuerWithStore(t, store))

	require.NoError(t, svc.DisableUser(context.Background(), "alice"))

	wantHandle := base64.RawURLEncoding.EncodeToString(webauthn.HandleFromUserID(42))
	assert.ElementsMatch(t, []string{"alice", wantHandle}, store.revoked,
		"disable must revoke both subject encodings a login can mint a refresh token under")
}

func TestDeleteUser_RevokesSessionsForUsernameAndWebAuthnHandle(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)
	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 7, Username: "bob"}, nil
	}
	users.deleteUser = func(_ context.Context, _ uint64) error { return nil }

	store := &spyRefreshStore{}
	svc.SetTokenIssuer(newTestTokenIssuerWithStore(t, store))

	require.NoError(t, svc.DeleteUser(context.Background(), "bob"))

	wantHandle := base64.RawURLEncoding.EncodeToString(webauthn.HandleFromUserID(7))
	assert.ElementsMatch(t, []string{"bob", wantHandle}, store.revoked)
}

// TestDisableUser_NoTokenIssuerConfiguredStillSucceeds proves a deployment
// with no session-token plane wired (SetTokenIssuer never called) still
// disables the account; the refresh-time re-check is the enforcement point
// there instead.
func TestDisableUser_NoTokenIssuerConfiguredStillSucceeds(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)
	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 1, Username: "alice"}, nil
	}
	users.disableUser = func(_ context.Context, _ uint64) error { return nil }

	require.NoError(t, svc.DisableUser(context.Background(), "alice"))
}

// TestDisableUser_RevokeFailureDoesNotFailTheOperation proves a
// session-revocation failure is best-effort: the qrdb lifecycle change
// already succeeded and must not be rolled back or reported as a failure
// because the (defense-in-depth) session sweep could not reach the store.
func TestDisableUser_RevokeFailureDoesNotFailTheOperation(t *testing.T) {
	svc, users, _ := setupServiceWithUserClients(t)
	users.getUserByUsername = func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
		return &qrdbtransport.User{ID: 1, Username: "mallory"}, nil
	}
	users.disableUser = func(_ context.Context, _ uint64) error { return nil }

	store := &spyRefreshStore{failOn: "mallory"}
	svc.SetTokenIssuer(newTestTokenIssuerWithStore(t, store))

	require.NoError(t, svc.DisableUser(context.Background(), "mallory"))
	assert.Contains(t, store.revoked, "mallory")
}
