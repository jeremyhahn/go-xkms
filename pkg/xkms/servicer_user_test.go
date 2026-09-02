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
	"errors"
	"fmt"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
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
	getUserByUsername func(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error)
	getUserByEmail    func(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error)
	listUsers         func(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error)
	deleteUser        func(ctx context.Context, id uint64) error
	enableUser        func(ctx context.Context, id uint64) error
	disableUser       func(ctx context.Context, id uint64) error
	addCertBinding    func(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error)
}

var _ qrdbtransport.UserClient = (*mockUserClient)(nil)

func (m *mockUserClient) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	return m.createUser(ctx, req)
}

func (m *mockUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	return nil, errors.New("not used")
}

func (m *mockUserClient) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	return m.getUserByUsername(ctx, tenantID, username)
}

func (m *mockUserClient) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	if m.getUserByEmail != nil {
		return m.getUserByEmail(ctx, tenantID, email)
	}
	return nil, &qrdbtransport.UserNotFoundError{ID: email}
}

func (m *mockUserClient) GetUserByCertThumbprint(ctx context.Context, thumbprint string) (*qrdbtransport.User, error) {
	return nil, errors.New("not used")
}

func (m *mockUserClient) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	return m.addCertBinding(ctx, userID, thumbprint, notAfterUnix)
}

func (m *mockUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
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
	getRole   func(ctx context.Context, id string) (*qrdbtransport.Role, error)
	listRoles func(ctx context.Context, req *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error)
}

var _ qrdbtransport.RoleClient = (*mockRoleClient)(nil)

func (m *mockRoleClient) CreateRole(ctx context.Context, req *qrdbtransport.CreateRoleRequest) (*qrdbtransport.Role, error) {
	return nil, errors.New("not used")
}

func (m *mockRoleClient) GetRole(ctx context.Context, id string) (*qrdbtransport.Role, error) {
	return m.getRole(ctx, id)
}
func (m *mockRoleClient) GetRoleByName(ctx context.Context, req *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
	return nil, nil
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
	return m.listRoles(ctx, req)
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

// setupServiceWithUserClients wires mock user/role clients into a fresh
// service and returns the service plus the mocks so individual tests can
// program per-call behavior.
func setupServiceWithUserClients(t *testing.T) (*XKMSService, *mockUserClient, *mockRoleClient) {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	users := &mockUserClient{}
	roles := &mockRoleClient{}
	svc.SetUserClients(users, roles)
	return svc, users, roles
}

// ============================================================================
// userToTransport
// ============================================================================

func TestUserToTransport_ResolvesFirstRoleName(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	roles.getRole = func(_ context.Context, id string) (*qrdbtransport.Role, error) {
		assert.Equal(t, "role-1", id)
		return &qrdbtransport.Role{ID: "role-1", Name: "admin"}, nil
	}

	info := svc.userToTransport(context.Background(), &qrdbtransport.User{
		Username: "alice",
		Enabled:  true,
		RoleIDs:  []string{"role-1", "role-2"},
	})

	assert.Equal(t, "alice", info.Username)
	assert.Equal(t, "admin", info.Role)
	assert.True(t, info.Enabled)
}

func TestUserToTransport_NoRoles(t *testing.T) {
	svc, _, _ := setupServiceWithUserClients(t)

	info := svc.userToTransport(context.Background(), &qrdbtransport.User{
		Username: "bob",
		Enabled:  false,
	})

	assert.Equal(t, "bob", info.Username)
	assert.Empty(t, info.Role)
	assert.False(t, info.Enabled)
}

func TestUserToTransport_RoleLookupErrorLeavesRoleEmpty(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	roles.getRole = func(_ context.Context, _ string) (*qrdbtransport.Role, error) {
		return nil, errors.New("role store offline")
	}

	info := svc.userToTransport(context.Background(), &qrdbtransport.User{
		Username: "carol",
		RoleIDs:  []string{"missing"},
	})

	// A lookup error must not propagate; the role name simply stays empty.
	assert.Equal(t, "carol", info.Username)
	assert.Empty(t, info.Role)
}

// ============================================================================
// roleNameToID
// ============================================================================

func TestRoleNameToID_EmptyNameResolvesEmptyID(t *testing.T) {
	svc, _, _ := setupServiceWithUserClients(t)

	id, err := svc.roleNameToID(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, id)
}

func TestRoleNameToID_Match(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	roles.listRoles = func(_ context.Context, _ *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
		return &qrdbtransport.ListRolesResponse{Roles: []*qrdbtransport.Role{
			{ID: "id-operator", Name: "operator"},
			{ID: "id-admin", Name: "admin"},
		}}, nil
	}

	id, err := svc.roleNameToID(context.Background(), "admin")
	require.NoError(t, err)
	assert.Equal(t, "id-admin", id)
}

func TestRoleNameToID_UnknownRole(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	roles.listRoles = func(_ context.Context, _ *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
		return &qrdbtransport.ListRolesResponse{Roles: []*qrdbtransport.Role{
			{ID: "id-operator", Name: "operator"},
		}}, nil
	}

	id, err := svc.roleNameToID(context.Background(), "ghost")
	require.Error(t, err)
	assert.Empty(t, id)

	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	var unknown *ErrUnknownRole
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, "ghost", unknown.Role)
}

func TestRoleNameToID_ListError(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	roles.listRoles = func(_ context.Context, _ *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
		return nil, errors.New("role list backend down")
	}

	_, err := svc.roleNameToID(context.Background(), "admin")
	var opErr *ErrUserOperation
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "resolve role", opErr.Operation)
}

// ============================================================================
// CreateUser
// ============================================================================

func TestCreateUser_Success(t *testing.T) {
	svc, users, roles := setupServiceWithUserClients(t)

	roles.listRoles = func(_ context.Context, _ *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
		return &qrdbtransport.ListRolesResponse{Roles: []*qrdbtransport.Role{
			{ID: "id-admin", Name: "admin"},
		}}, nil
	}
	roles.getRole = func(_ context.Context, id string) (*qrdbtransport.Role, error) {
		return &qrdbtransport.Role{ID: id, Name: "admin"}, nil
	}
	users.createUser = func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
		assert.Equal(t, "dave", req.Username)
		assert.Equal(t, []string{"id-admin"}, req.RoleIDs)
		// Echo what a real store persists — dropping Name here would hide a
		// projection bug in exactly the way this one hid.
		return &qrdbtransport.User{
			Username: "dave", Email: req.Email, Name: req.Name,
			Enabled: true, RoleIDs: []string{"id-admin"},
		}, nil
	}

	resp, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username:    "dave",
		Email:       "dave@example.com",
		DisplayName: "Dave Doe",
		Role:        "admin",
	})
	require.NoError(t, err)
	assert.Equal(t, "dave", resp.User.Username)
	assert.Equal(t, "admin", resp.User.Role)
	assert.Equal(t, "Dave Doe", resp.User.DisplayName)
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
	assert.Empty(t, resp.User.Role)
}

func TestCreateUser_RoleResolutionError(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	roles.listRoles = func(_ context.Context, _ *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
		return &qrdbtransport.ListRolesResponse{}, nil
	}

	_, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "x", Email: "x@example.com", Role: "nope"})
	require.Error(t, err)
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
			{Username: "u1", RoleIDs: []string{"r1"}, Enabled: true},
			{Username: "u2"},
		}}, nil
	}

	resp, err := svc.ListUsers(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Users, 2)
	assert.Equal(t, "u1", resp.Users[0].Username)
	assert.Equal(t, "viewer", resp.Users[0].Role)
	assert.Equal(t, "u2", resp.Users[1].Username)
	assert.Empty(t, resp.Users[1].Role)
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
		return &qrdbtransport.User{Username: "alice", Enabled: true}, nil
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
			Username: req.Username, Email: req.Email, Name: req.Name, Enabled: true,
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
		ID: 7, Username: "frank", Email: "frank@example.com", Name: "Frank Example", Enabled: true,
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
