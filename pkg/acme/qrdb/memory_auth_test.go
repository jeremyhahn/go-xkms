//go:build codec_json

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

package qrdb

import (
	"context"
	"testing"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// memoryRoleClient tests
// ==========================================================================

func TestMemoryRoleClient_CreateRole_Success(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	role, err := c.CreateRole(ctx, &db.CreateRoleRequest{
		Name:        "admin",
		TenantID:    "tenant-1",
		Permissions: []string{"read", "write"},
	})
	require.NoError(t, err)
	require.NotNil(t, role)
	assert.Equal(t, "role-1", role.ID)
	assert.Equal(t, "admin", role.Name)
	assert.Equal(t, "tenant-1", role.TenantID)
	assert.Equal(t, []string{"read", "write"}, role.Permissions)
	assert.NotEmpty(t, role.CreatedAt)
	assert.NotEmpty(t, role.UpdatedAt)
}

func TestMemoryRoleClient_CreateRole_SequentialIDs(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	r1, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "role-a"})
	require.NoError(t, err)
	assert.Equal(t, "role-1", r1.ID)

	r2, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "role-b"})
	require.NoError(t, err)
	assert.Equal(t, "role-2", r2.ID)
}

func TestMemoryRoleClient_GetRole_Success(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	created, err := c.CreateRole(ctx, &db.CreateRoleRequest{
		Name:     "viewer",
		TenantID: "tenant-1",
	})
	require.NoError(t, err)

	got, err := c.GetRole(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, "viewer", got.Name)
}

func TestMemoryRoleClient_UpdateRole_PartialUpdate_NameOnly(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	created, err := c.CreateRole(ctx, &db.CreateRoleRequest{
		Name:        "editor",
		Permissions: []string{"read"},
	})
	require.NoError(t, err)

	updated, err := c.UpdateRole(ctx, &db.UpdateRoleRequest{
		ID:   created.ID,
		Name: "renamed",
	})
	require.NoError(t, err)
	assert.Equal(t, "renamed", updated.Name)
	assert.Equal(t, []string{"read"}, updated.Permissions)
}

func TestMemoryRoleClient_UpdateRole_PartialUpdate_PermissionsOnly(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	created, err := c.CreateRole(ctx, &db.CreateRoleRequest{
		Name:        "editor",
		Permissions: []string{"read"},
	})
	require.NoError(t, err)

	updated, err := c.UpdateRole(ctx, &db.UpdateRoleRequest{
		ID:          created.ID,
		Permissions: []string{"read", "write"},
	})
	require.NoError(t, err)
	assert.Equal(t, "editor", updated.Name)
	assert.Equal(t, []string{"read", "write"}, updated.Permissions)
}

func TestMemoryRoleClient_ListRoles_Empty(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	resp, err := c.ListRoles(ctx, &db.ListRolesRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.Roles)
	assert.Equal(t, 0, resp.Total)
}

func TestMemoryRoleClient_ListRoles_All(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	_, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "admin", TenantID: "t1"})
	require.NoError(t, err)
	_, err = c.CreateRole(ctx, &db.CreateRoleRequest{Name: "viewer", TenantID: "t2"})
	require.NoError(t, err)

	resp, err := c.ListRoles(ctx, &db.ListRolesRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.Roles, 2)
	assert.Equal(t, 2, resp.Total)
}

func TestMemoryRoleClient_ListRoles_FilterByTenant(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	_, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "admin", TenantID: "t1"})
	require.NoError(t, err)
	_, err = c.CreateRole(ctx, &db.CreateRoleRequest{Name: "viewer", TenantID: "t2"})
	require.NoError(t, err)
	_, err = c.CreateRole(ctx, &db.CreateRoleRequest{Name: "editor", TenantID: "t1"})
	require.NoError(t, err)

	resp, err := c.ListRoles(ctx, &db.ListRolesRequest{TenantID: "t1"})
	require.NoError(t, err)
	assert.Len(t, resp.Roles, 2)
	assert.Equal(t, 2, resp.Total)
}

func TestMemoryRoleClient_AssignRole_Success(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	err := c.AssignRole(ctx, uint64(1), "role-1")
	assert.NoError(t, err)
}

func TestMemoryRoleClient_UnassignRole_Success(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	err := c.UnassignRole(ctx, uint64(1), "role-1")
	assert.NoError(t, err)
}

func TestMemoryRoleClient_ListPermissions_Success(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	resp, err := c.ListPermissions(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// ==========================================================================
// memoryUserClient tests
// ==========================================================================

func TestMemoryUserClient_CreateUser_Success(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &db.CreateUserRequest{
		Username: "alice",
		TenantID: "tenant-1",
		RoleIDs:  []string{"role-1", "role-2"},
	})
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, uint64(1), user.ID)
	assert.Equal(t, "alice", user.Username)
	assert.Equal(t, "tenant-1", user.TenantID)
	assert.Equal(t, []string{"role-1", "role-2"}, user.RoleIDs)
	assert.True(t, user.Enabled)
	assert.NotEmpty(t, user.CreatedAt)
	assert.NotEmpty(t, user.UpdatedAt)
}

func TestMemoryUserClient_CreateUser_SequentialIDs(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	u1, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "alice"})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), u1.ID)

	u2, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "bob"})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), u2.ID)
}

func TestMemoryUserClient_GetUser_Success(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	created, err := c.CreateUser(ctx, &db.CreateUserRequest{
		Username: "alice",
		TenantID: "tenant-1",
	})
	require.NoError(t, err)

	got, err := c.GetUser(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, "alice", got.Username)
}

func TestMemoryUserClient_UpdateUser_PartialUpdate_UsernameOnly(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	created, err := c.CreateUser(ctx, &db.CreateUserRequest{
		Username: "alice",
		RoleIDs:  []string{"role-1"},
	})
	require.NoError(t, err)

	updated, err := c.UpdateUser(ctx, &db.UpdateUserRequest{
		ID:       created.ID,
		Username: "alice-renamed",
	})
	require.NoError(t, err)
	assert.Equal(t, "alice-renamed", updated.Username)
	assert.Equal(t, []string{"role-1"}, updated.RoleIDs)
}

func TestMemoryUserClient_UpdateUser_PartialUpdate_RolesOnly(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	created, err := c.CreateUser(ctx, &db.CreateUserRequest{
		Username: "alice",
		RoleIDs:  []string{"role-1"},
	})
	require.NoError(t, err)

	updated, err := c.UpdateUser(ctx, &db.UpdateUserRequest{
		ID:      created.ID,
		RoleIDs: []string{"role-2", "role-3"},
	})
	require.NoError(t, err)
	assert.Equal(t, "alice", updated.Username)
	assert.Equal(t, []string{"role-2", "role-3"}, updated.RoleIDs)
}

func TestMemoryUserClient_ListUsers_Empty(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	resp, err := c.ListUsers(ctx, &db.ListUsersRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.Users)
	assert.Equal(t, 0, resp.Total)
}

func TestMemoryUserClient_ListUsers_All(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	_, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "alice", TenantID: "t1"})
	require.NoError(t, err)
	_, err = c.CreateUser(ctx, &db.CreateUserRequest{Username: "bob", TenantID: "t2"})
	require.NoError(t, err)

	resp, err := c.ListUsers(ctx, &db.ListUsersRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.Users, 2)
	assert.Equal(t, 2, resp.Total)
}

func TestMemoryUserClient_ListUsers_FilterByTenant(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	_, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "alice", TenantID: "t1"})
	require.NoError(t, err)
	_, err = c.CreateUser(ctx, &db.CreateUserRequest{Username: "bob", TenantID: "t2"})
	require.NoError(t, err)
	_, err = c.CreateUser(ctx, &db.CreateUserRequest{Username: "charlie", TenantID: "t1"})
	require.NoError(t, err)

	resp, err := c.ListUsers(ctx, &db.ListUsersRequest{TenantID: "t1"})
	require.NoError(t, err)
	assert.Len(t, resp.Users, 2)
	assert.Equal(t, 2, resp.Total)
}

func TestMemoryUserClient_EnableUser_Success(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	created, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "alice"})
	require.NoError(t, err)

	// Disable first, then enable
	err = c.DisableUser(ctx, created.ID)
	require.NoError(t, err)

	got, err := c.GetUser(ctx, created.ID)
	require.NoError(t, err)
	assert.False(t, got.Enabled)

	err = c.EnableUser(ctx, created.ID)
	require.NoError(t, err)

	got, err = c.GetUser(ctx, created.ID)
	require.NoError(t, err)
	assert.True(t, got.Enabled)
}

func TestMemoryUserClient_DisableUser_Success(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	created, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "alice"})
	require.NoError(t, err)
	assert.True(t, created.Enabled)

	err = c.DisableUser(ctx, created.ID)
	require.NoError(t, err)

	got, err := c.GetUser(ctx, created.ID)
	require.NoError(t, err)
	assert.False(t, got.Enabled)
}
