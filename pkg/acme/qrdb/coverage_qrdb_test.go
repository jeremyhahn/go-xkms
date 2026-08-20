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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// IsServiceInit
// ==========================================================================

func TestIsServiceInit_True(t *testing.T) {
	err := NewError(ErrorCodeServiceInit, "failed to start embedded server")
	assert.True(t, IsServiceInit(err))
}

func TestIsServiceInit_False_OtherCode(t *testing.T) {
	err := NewError(ErrorCodeInternal, "some other error")
	assert.False(t, IsServiceInit(err))
}

func TestIsServiceInit_False_NilError(t *testing.T) {
	assert.False(t, IsServiceInit(nil))
}

func TestIsServiceInit_False_NonTypedError(t *testing.T) {
	assert.False(t, IsServiceInit(errRoleNotFound))
}

// ==========================================================================
// kvStoreAdapter — index methods always return errors for remote transports
// ==========================================================================

func TestKVStoreAdapter_RegisterEntityIndexes_ReturnsError(t *testing.T) {
	adapter := NewKVStoreAdapter(NewMemoryKVClient())
	err := adapter.RegisterEntityIndexes("account", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "account")
	assert.Contains(t, err.Error(), "remote transport does not support")
	// The wording is incidental; THIS is the contract. go-qrdb's DAO reads the
	// refusal as a capability negotiation and only plans full scans when it
	// matches the sentinel, so an error that merely reads correctly but does
	// not match makes every DAO on this path fail to construct.
	assert.ErrorIs(t, err, qrdbsdk.ErrKVIndexUnsupported)
}

func TestKVStoreAdapter_QueryIndex_ReturnsError(t *testing.T) {
	adapter := NewKVStoreAdapter(NewMemoryKVClient())
	ctx := context.Background()
	result, err := adapter.QueryIndex(ctx, "by_email", []byte("user@example.com"))
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "by_email")
}

func TestKVStoreAdapter_ScanIndex_ReturnsError(t *testing.T) {
	adapter := NewKVStoreAdapter(NewMemoryKVClient())
	ctx := context.Background()
	result, err := adapter.ScanIndex(ctx, "by_name", []byte("a"), []byte("z"))
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "by_name")
}

func TestKVStoreAdapter_QueryCompoundIndex_ReturnsError(t *testing.T) {
	adapter := NewKVStoreAdapter(NewMemoryKVClient())
	ctx := context.Background()
	result, err := adapter.QueryCompoundIndex(ctx, "tenant_email", [][]byte{[]byte("t1"), []byte("user@example.com")})
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "tenant_email")
}

func TestKVStoreAdapter_ScanCompoundIndex_ReturnsError(t *testing.T) {
	adapter := NewKVStoreAdapter(NewMemoryKVClient())
	ctx := context.Background()
	result, err := adapter.ScanCompoundIndex(ctx, "compound_idx", [][]byte{[]byte("t1")}, []byte("a"), []byte("z"))
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "compound_idx")
}

// Compile-time check that kvStoreAdapter satisfies qrdbsdk.KVStore.
var _ qrdbsdk.KVStore = (*kvStoreAdapter)(nil)

// ==========================================================================
// memoryRoleClient — full CRUD + list + permission operations
// ==========================================================================

func TestMemoryRoleClient_CreateAndGetRole(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	tests := []struct {
		name     string
		req      *db.CreateRoleRequest
		wantName string
		wantTID  string
	}{
		{
			name:     "admin role",
			req:      &db.CreateRoleRequest{Name: "admin", TenantID: "t1", Permissions: []string{"read", "write"}},
			wantName: "admin",
			wantTID:  "t1",
		},
		{
			name:     "viewer role",
			req:      &db.CreateRoleRequest{Name: "viewer", TenantID: "t2", Permissions: []string{"read"}},
			wantName: "viewer",
			wantTID:  "t2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role, err := c.CreateRole(ctx, tt.req)
			require.NoError(t, err)
			require.NotNil(t, role)
			assert.Equal(t, tt.wantName, role.Name)
			assert.Equal(t, tt.wantTID, role.TenantID)
			assert.NotEmpty(t, role.ID)
			assert.NotEmpty(t, role.CreatedAt)

			// GetRole by ID.
			got, err := c.GetRole(ctx, role.ID)
			require.NoError(t, err)
			assert.Equal(t, role.ID, got.ID)
			assert.Equal(t, tt.wantName, got.Name)
		})
	}
}

func TestMemoryRoleClient_GetRole_NotFound(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	_, err := c.GetRole(ctx, "nonexistent-role")
	require.Error(t, err)
	assert.Equal(t, errRoleNotFound, err)
}

func TestMemoryRoleClient_UpdateRole_Success(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	role, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "old-name", TenantID: "t1"})
	require.NoError(t, err)

	updated, err := c.UpdateRole(ctx, &db.UpdateRoleRequest{
		ID:          role.ID,
		Name:        "new-name",
		Permissions: []string{"read", "write", "admin"},
	})
	require.NoError(t, err)
	assert.Equal(t, "new-name", updated.Name)
	assert.Equal(t, []string{"read", "write", "admin"}, updated.Permissions)
}

func TestMemoryRoleClient_UpdateRole_NotFound(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	_, err := c.UpdateRole(ctx, &db.UpdateRoleRequest{ID: "ghost-id", Name: "x"})
	require.Error(t, err)
	assert.Equal(t, errRoleNotFound, err)
}

func TestMemoryRoleClient_DeleteRole_Success(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	role, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "to-delete"})
	require.NoError(t, err)

	err = c.DeleteRole(ctx, role.ID)
	require.NoError(t, err)

	_, err = c.GetRole(ctx, role.ID)
	require.Error(t, err)
}

func TestMemoryRoleClient_DeleteRole_NotFound(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	err := c.DeleteRole(ctx, "no-such-id")
	require.Error(t, err)
	assert.Equal(t, errRoleNotFound, err)
}

func TestMemoryRoleClient_ListRoles(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	_, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "r1", TenantID: "tenant-a"})
	require.NoError(t, err)
	_, err = c.CreateRole(ctx, &db.CreateRoleRequest{Name: "r2", TenantID: "tenant-b"})
	require.NoError(t, err)
	_, err = c.CreateRole(ctx, &db.CreateRoleRequest{Name: "r3", TenantID: "tenant-a"})
	require.NoError(t, err)

	t.Run("list all tenants", func(t *testing.T) {
		resp, err := c.ListRoles(ctx, &db.ListRolesRequest{TenantID: ""})
		require.NoError(t, err)
		assert.Equal(t, 3, resp.Total)
	})

	t.Run("filter by tenant-a", func(t *testing.T) {
		resp, err := c.ListRoles(ctx, &db.ListRolesRequest{TenantID: "tenant-a"})
		require.NoError(t, err)
		assert.Equal(t, 2, resp.Total)
	})

	t.Run("filter by tenant-b", func(t *testing.T) {
		resp, err := c.ListRoles(ctx, &db.ListRolesRequest{TenantID: "tenant-b"})
		require.NoError(t, err)
		assert.Equal(t, 1, resp.Total)
	})
}

func TestMemoryRoleClient_AssignAndUnassignRole(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	// These are no-ops in the in-memory client; verify they return no error.
	err := c.AssignRole(ctx, 1, "role-1")
	require.NoError(t, err)

	err = c.UnassignRole(ctx, 1, "role-1")
	require.NoError(t, err)
}

func TestMemoryRoleClient_ListPermissions(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	resp, err := c.ListPermissions(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// ==========================================================================
// memoryRoleClient — GetRoleByName and ResolvePermissions
// ==========================================================================

func TestMemoryRoleClient_GetRoleByName_Success(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	role, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "editor", TenantID: "t1"})
	require.NoError(t, err)

	got, err := c.GetRoleByName(ctx, &db.GetRoleByNameRequest{Name: "editor", TenantID: "t1"})
	require.NoError(t, err)
	assert.Equal(t, role.ID, got.ID)
}

func TestMemoryRoleClient_GetRoleByName_TenantMismatch(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	_, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "editor", TenantID: "t1"})
	require.NoError(t, err)

	_, err = c.GetRoleByName(ctx, &db.GetRoleByNameRequest{Name: "editor", TenantID: "other-tenant"})
	require.Error(t, err)
	assert.Equal(t, errRoleNotFound, err)
}

func TestMemoryRoleClient_GetRoleByName_NilRequest(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	_, err := c.GetRoleByName(ctx, nil)
	require.Error(t, err)
	assert.Equal(t, errRoleNotFound, err)
}

func TestMemoryRoleClient_GetRoleByName_NoTenantFilter(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	role, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "superadmin", TenantID: "t1"})
	require.NoError(t, err)

	// No tenant filter — matches the first role with that name.
	got, err := c.GetRoleByName(ctx, &db.GetRoleByNameRequest{Name: "superadmin"})
	require.NoError(t, err)
	assert.Equal(t, role.ID, got.ID)
}

func TestMemoryRoleClient_ResolvePermissions_MultipleRoles(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	r1, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "r1", Permissions: []string{"read", "write"}})
	require.NoError(t, err)
	r2, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "r2", Permissions: []string{"write", "admin"}})
	require.NoError(t, err)

	resp, err := c.ResolvePermissions(ctx, &db.ResolvePermissionsRequest{RoleIDs: []string{r1.ID, r2.ID}})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admin", "read", "write"}, resp.Permissions)
}

func TestMemoryRoleClient_ResolvePermissions_NilRequest(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	resp, err := c.ResolvePermissions(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, resp.Permissions)
}

func TestMemoryRoleClient_ResolvePermissions_UnknownRoleSkipped(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	r1, err := c.CreateRole(ctx, &db.CreateRoleRequest{Name: "r1", Permissions: []string{"read"}})
	require.NoError(t, err)

	resp, err := c.ResolvePermissions(ctx, &db.ResolvePermissionsRequest{
		RoleIDs: []string{r1.ID, "ghost-role-id"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"read"}, resp.Permissions)
}

func TestMemoryRoleClient_ResolvePermissions_EmptyRoleIDs(t *testing.T) {
	c := newMemoryRoleClient()
	ctx := context.Background()

	resp, err := c.ResolvePermissions(ctx, &db.ResolvePermissionsRequest{RoleIDs: []string{}})
	require.NoError(t, err)
	assert.Empty(t, resp.Permissions)
}

// ==========================================================================
// memoryUserClient — full CRUD + list + cert binding
// ==========================================================================

func TestMemoryUserClient_CreateAndGetUser(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	tests := []struct {
		name     string
		req      *db.CreateUserRequest
		wantUser string
		wantTID  string
	}{
		{
			name:     "alice",
			req:      &db.CreateUserRequest{Username: "alice", TenantID: "t1"},
			wantUser: "alice",
			wantTID:  "t1",
		},
		{
			name:     "bob",
			req:      &db.CreateUserRequest{Username: "bob", TenantID: "t2"},
			wantUser: "bob",
			wantTID:  "t2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := c.CreateUser(ctx, tt.req)
			require.NoError(t, err)
			require.NotNil(t, user)
			assert.Equal(t, tt.wantUser, user.Username)
			assert.Equal(t, tt.wantTID, user.TenantID)
			assert.True(t, user.Enabled)
			assert.NotEmpty(t, user.CreatedAt)

			got, err := c.GetUser(ctx, user.ID)
			require.NoError(t, err)
			assert.Equal(t, user.ID, got.ID)
		})
	}
}

func TestMemoryUserClient_GetUser_NotFound(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	_, err := c.GetUser(ctx, 99999)
	require.Error(t, err)
	assert.Equal(t, errUserNotFound, err)
}

func TestMemoryUserClient_GetUserByUsername_Success(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "charlie", TenantID: "t1"})
	require.NoError(t, err)

	got, err := c.GetUserByUsername(ctx, "t1", "charlie")
	require.NoError(t, err)
	assert.Equal(t, user.ID, got.ID)
}

func TestMemoryUserClient_GetUserByUsername_NotFound(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	_, err := c.GetUserByUsername(ctx, "t1", "nobody")
	require.Error(t, err)
	assert.Equal(t, errUserNotFound, err)
}

func TestMemoryUserClient_GetUserByUsername_TenantMismatch(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	_, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "dave", TenantID: "t1"})
	require.NoError(t, err)

	_, err = c.GetUserByUsername(ctx, "t2", "dave")
	require.Error(t, err)
	assert.Equal(t, errUserNotFound, err)
}

func TestMemoryUserClient_GetUserByCertThumbprint_AlwaysNotFound(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	_, err := c.GetUserByCertThumbprint(ctx, "sha256:abcdef")
	require.Error(t, err)
	assert.Equal(t, errUserNotFound, err)
}

func TestMemoryUserClient_UpdateUser_Success(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "eve"})
	require.NoError(t, err)

	updated, err := c.UpdateUser(ctx, &db.UpdateUserRequest{
		ID:       user.ID,
		Username: "eve-updated",
		RoleIDs:  []string{"role-1"},
	})
	require.NoError(t, err)
	assert.Equal(t, "eve-updated", updated.Username)
	assert.Equal(t, []string{"role-1"}, updated.RoleIDs)
}

func TestMemoryUserClient_UpdateUser_NotFound(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	_, err := c.UpdateUser(ctx, &db.UpdateUserRequest{ID: 99999, Username: "ghost"})
	require.Error(t, err)
	assert.Equal(t, errUserNotFound, err)
}

func TestMemoryUserClient_DeleteUser_Success(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "frank"})
	require.NoError(t, err)

	err = c.DeleteUser(ctx, user.ID)
	require.NoError(t, err)

	_, err = c.GetUser(ctx, user.ID)
	require.Error(t, err)
}

func TestMemoryUserClient_DeleteUser_NotFound(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	err := c.DeleteUser(ctx, 99999)
	require.Error(t, err)
	assert.Equal(t, errUserNotFound, err)
}

func TestMemoryUserClient_ListUsers(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	_, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "u1", TenantID: "ta"})
	require.NoError(t, err)
	_, err = c.CreateUser(ctx, &db.CreateUserRequest{Username: "u2", TenantID: "tb"})
	require.NoError(t, err)
	_, err = c.CreateUser(ctx, &db.CreateUserRequest{Username: "u3", TenantID: "ta"})
	require.NoError(t, err)

	t.Run("list all", func(t *testing.T) {
		resp, err := c.ListUsers(ctx, &db.ListUsersRequest{TenantID: ""})
		require.NoError(t, err)
		assert.Equal(t, 3, resp.Total)
	})

	t.Run("filter tenant-ta", func(t *testing.T) {
		resp, err := c.ListUsers(ctx, &db.ListUsersRequest{TenantID: "ta"})
		require.NoError(t, err)
		assert.Equal(t, 2, resp.Total)
	})
}

func TestMemoryUserClient_EnableUser(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "grace"})
	require.NoError(t, err)

	// Disable then re-enable.
	err = c.DisableUser(ctx, user.ID)
	require.NoError(t, err)

	got, err := c.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.False(t, got.Enabled)

	err = c.EnableUser(ctx, user.ID)
	require.NoError(t, err)

	got, err = c.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, got.Enabled)
}

func TestMemoryUserClient_EnableUser_NotFound(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	err := c.EnableUser(ctx, 99999)
	require.Error(t, err)
	assert.Equal(t, errUserNotFound, err)
}

func TestMemoryUserClient_DisableUser_NotFound(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	err := c.DisableUser(ctx, 99999)
	require.Error(t, err)
	assert.Equal(t, errUserNotFound, err)
}

func TestMemoryUserClient_AddCertBinding_Success(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &db.CreateUserRequest{Username: "henry"})
	require.NoError(t, err)

	bound, err := c.AddCertBinding(ctx, user.ID, "sha256:deadbeef", 9999999999)
	require.NoError(t, err)
	assert.Equal(t, user.ID, bound.ID)
}

func TestMemoryUserClient_AddCertBinding_NotFound(t *testing.T) {
	c := newMemoryUserClient()
	ctx := context.Background()

	_, err := c.AddCertBinding(ctx, 99999, "sha256:dead", 0)
	require.Error(t, err)
	assert.Equal(t, errUserNotFound, err)
}

// ==========================================================================
// testService accessors — Watch, Lease, Batch, Transaction, Index,
//   Certs, Barrier, Ceremony, Credentials (all return nil from testService)
// ==========================================================================

func TestTestService_NilAccessors(t *testing.T) {
	svc := NewTestService()

	t.Run("Watch returns nil", func(t *testing.T) {
		assert.Nil(t, svc.Watch())
	})

	t.Run("Lease returns nil", func(t *testing.T) {
		assert.Nil(t, svc.Lease())
	})

	t.Run("Batch returns nil", func(t *testing.T) {
		assert.Nil(t, svc.Batch())
	})

	t.Run("Transaction returns nil", func(t *testing.T) {
		assert.Nil(t, svc.Transaction())
	})

	t.Run("Index returns nil", func(t *testing.T) {
		assert.Nil(t, svc.Index())
	})

	t.Run("Certs returns nil", func(t *testing.T) {
		assert.Nil(t, svc.Certs())
	})

	t.Run("Barrier returns nil", func(t *testing.T) {
		assert.Nil(t, svc.Barrier())
	})

	t.Run("Ceremony returns nil", func(t *testing.T) {
		assert.Nil(t, svc.Ceremony())
	})

	t.Run("Credentials returns nil", func(t *testing.T) {
		assert.Nil(t, svc.Credentials())
	})
}

func TestTestService_NonNilAccessors(t *testing.T) {
	svc := NewTestService()

	t.Run("KV is not nil", func(t *testing.T) {
		assert.NotNil(t, svc.KV())
	})

	t.Run("Admin is not nil", func(t *testing.T) {
		assert.NotNil(t, svc.Admin())
	})

	t.Run("Users is not nil", func(t *testing.T) {
		assert.NotNil(t, svc.Users())
	})

	t.Run("Roles is not nil", func(t *testing.T) {
		assert.NotNil(t, svc.Roles())
	})

	t.Run("Config is not nil", func(t *testing.T) {
		assert.NotNil(t, svc.Config())
	})
}

func TestTestService_HealthAndClose(t *testing.T) {
	svc := NewTestService()
	ctx := context.Background()

	assert.True(t, svc.Healthy(ctx))
	require.NoError(t, svc.Close())
	assert.False(t, svc.Healthy(ctx))
}

// ==========================================================================
// testAdminClient — GetShardState and GetTopology
// ==========================================================================

func TestTestAdminClient_GetShardState(t *testing.T) {
	svc := NewTestService()
	ctx := context.Background()

	resp, err := svc.Admin().GetShardState(ctx, 1)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, uint64(1), resp.ShardID)
	assert.True(t, resp.HasLeader)
}

func TestTestAdminClient_GetTopology(t *testing.T) {
	svc := NewTestService()
	ctx := context.Background()

	resp, err := svc.Admin().GetTopology(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.NodeID)
}
