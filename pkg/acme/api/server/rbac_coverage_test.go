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

//go:build !integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"net/http"
	"net/http/httptest"
	"testing"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	adminv1 "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- gRPC Role Handler Tests ---

func TestGRPC_CreateTenantRole_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		role: &db.Role{
			ID:          "role-1",
			Name:        "admin",
			TenantID:    "tenant-1",
			Permissions: []string{"read", "write"},
			System:      false,
			CreatedAt:   "2025-01-01T00:00:00Z",
			UpdatedAt:   "2025-01-01T00:00:00Z",
		},
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	resp, err := grpcSrv.CreateTenantRole(context.Background(), &adminv1.CreateTenantRoleRequest{
		TenantId:    "tenant-1",
		Name:        "admin",
		Permissions: []string{"read", "write"},
	})

	require.NoError(t, err)
	assert.Equal(t, "role-1", resp.Id)
	assert.Equal(t, "admin", resp.Name)
	assert.Equal(t, "tenant-1", resp.TenantId)
	assert.Equal(t, []string{"read", "write"}, resp.Permissions)
	assert.False(t, resp.System)
}

func TestGRPC_CreateTenantRole_ServiceNotAvailable(t *testing.T) {
	srv := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.CreateTenantRole(context.Background(), &adminv1.CreateTenantRoleRequest{
		TenantId: "tenant-1",
		Name:     "admin",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestGRPC_CreateTenantRole_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		createRoleErr: errors.New("creation failed"),
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.CreateTenantRole(context.Background(), &adminv1.CreateTenantRoleRequest{
		TenantId: "tenant-1",
		Name:     "admin",
	})

	assert.Error(t, err)
}

func TestGRPC_GetTenantRole_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		role: &db.Role{
			ID:          "role-1",
			Name:        "viewer",
			TenantID:    "tenant-1",
			Permissions: []string{"read"},
			System:      true,
			CreatedAt:   "2025-01-01T00:00:00Z",
		},
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	resp, err := grpcSrv.GetTenantRole(context.Background(), &adminv1.GetTenantRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-1",
	})

	require.NoError(t, err)
	assert.Equal(t, "role-1", resp.Id)
	assert.Equal(t, "viewer", resp.Name)
	assert.True(t, resp.System)
}

func TestGRPC_GetTenantRole_ServiceNotAvailable(t *testing.T) {
	srv := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.GetTenantRole(context.Background(), &adminv1.GetTenantRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-1",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestGRPC_GetTenantRole_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		getRoleErr: errors.New("not found"),
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.GetTenantRole(context.Background(), &adminv1.GetTenantRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "missing",
	})

	assert.Error(t, err)
}

func TestGRPC_UpdateTenantRole_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		role: &db.Role{
			ID:          "role-1",
			Name:        "updated-role",
			TenantID:    "tenant-1",
			Permissions: []string{"read", "write", "delete"},
			UpdatedAt:   "2025-06-01T00:00:00Z",
		},
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	resp, err := grpcSrv.UpdateTenantRole(context.Background(), &adminv1.UpdateTenantRoleRequest{
		TenantId:    "tenant-1",
		RoleId:      "role-1",
		Name:        "updated-role",
		Permissions: []string{"read", "write", "delete"},
	})

	require.NoError(t, err)
	assert.Equal(t, "updated-role", resp.Name)
	assert.Len(t, resp.Permissions, 3)
}

func TestGRPC_UpdateTenantRole_ServiceNotAvailable(t *testing.T) {
	srv := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.UpdateTenantRole(context.Background(), &adminv1.UpdateTenantRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-1",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestGRPC_UpdateTenantRole_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		updateRoleErr: errors.New("update failed"),
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.UpdateTenantRole(context.Background(), &adminv1.UpdateTenantRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-1",
	})

	assert.Error(t, err)
}

func TestGRPC_DeleteTenantRole_Success(t *testing.T) {
	mockTenant := &mockTenantService{}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	resp, err := grpcSrv.DeleteTenantRole(context.Background(), &adminv1.DeleteTenantRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-1",
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGRPC_DeleteTenantRole_ServiceNotAvailable(t *testing.T) {
	srv := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.DeleteTenantRole(context.Background(), &adminv1.DeleteTenantRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-1",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestGRPC_DeleteTenantRole_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		deleteRoleErr: errors.New("delete failed"),
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.DeleteTenantRole(context.Background(), &adminv1.DeleteTenantRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-1",
	})

	assert.Error(t, err)
}

func TestGRPC_ListTenantRoles_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		roles: &db.ListRolesResponse{
			Roles: []*db.Role{
				{ID: "role-1", Name: "admin", TenantID: "tenant-1", Permissions: []string{"all"}},
				{ID: "role-2", Name: "viewer", TenantID: "tenant-1", Permissions: []string{"read"}},
			},
			Total:   2,
			HasMore: false,
		},
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	resp, err := grpcSrv.ListTenantRoles(context.Background(), &adminv1.ListTenantRolesRequest{
		TenantId: "tenant-1",
		Page:     1,
		PageSize: 20,
	})

	require.NoError(t, err)
	assert.Len(t, resp.Roles, 2)
	assert.Equal(t, int32(2), resp.Total)
	assert.False(t, resp.HasMore)
	assert.Equal(t, "admin", resp.Roles[0].Name)
	assert.Equal(t, "viewer", resp.Roles[1].Name)
}

func TestGRPC_ListTenantRoles_ServiceNotAvailable(t *testing.T) {
	srv := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.ListTenantRoles(context.Background(), &adminv1.ListTenantRolesRequest{
		TenantId: "tenant-1",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestGRPC_ListTenantRoles_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		listRolesErr: errors.New("list failed"),
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.ListTenantRoles(context.Background(), &adminv1.ListTenantRolesRequest{
		TenantId: "tenant-1",
	})

	assert.Error(t, err)
}

// --- gRPC User Handler Tests ---

func TestGRPC_CreateTenantUser_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		user: &db.User{
			ID:        1,
			Username:  "alice",
			TenantID:  "tenant-1",
			RoleIDs:   []string{"role-1", "role-2"},
			Lifecycle: string(qrdbsdk.LifecycleActive),
			System:    false,
			CreatedAt: "2025-01-01T00:00:00Z",
			UpdatedAt: "2025-01-01T00:00:00Z",
		},
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	resp, err := grpcSrv.CreateTenantUser(context.Background(), &adminv1.CreateTenantUserRequest{
		TenantId: "tenant-1",
		Username: "alice",
		RoleIds:  []string{"role-1", "role-2"},
	})

	require.NoError(t, err)
	assert.Equal(t, "1", resp.Id)
	assert.Equal(t, "alice", resp.Username)
	assert.Equal(t, "tenant-1", resp.TenantId)
	assert.Equal(t, []string{"role-1", "role-2"}, resp.RoleIds)
	assert.True(t, resp.Enabled)
	assert.False(t, resp.System)
}

func TestGRPC_CreateTenantUser_ServiceNotAvailable(t *testing.T) {
	srv := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.CreateTenantUser(context.Background(), &adminv1.CreateTenantUserRequest{
		TenantId: "tenant-1",
		Username: "alice",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestGRPC_CreateTenantUser_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		createUserErr: errors.New("creation failed"),
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.CreateTenantUser(context.Background(), &adminv1.CreateTenantUserRequest{
		TenantId: "tenant-1",
		Username: "alice",
	})

	assert.Error(t, err)
}

func TestGRPC_GetTenantUser_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		user: &db.User{
			ID:        1,
			Username:  "alice",
			TenantID:  "tenant-1",
			RoleIDs:   []string{"role-1"},
			Lifecycle: string(qrdbsdk.LifecycleActive),
			System:    true,
		},
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	resp, err := grpcSrv.GetTenantUser(context.Background(), &adminv1.GetTenantUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-1",
	})

	require.NoError(t, err)
	assert.Equal(t, "1", resp.Id)
	assert.Equal(t, "alice", resp.Username)
	assert.True(t, resp.System)
}

func TestGRPC_GetTenantUser_ServiceNotAvailable(t *testing.T) {
	srv := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.GetTenantUser(context.Background(), &adminv1.GetTenantUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-1",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestGRPC_GetTenantUser_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		getUserErr: errors.New("not found"),
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.GetTenantUser(context.Background(), &adminv1.GetTenantUserRequest{
		TenantId: "tenant-1",
		UserId:   "missing",
	})

	assert.Error(t, err)
}

func TestGRPC_UpdateTenantUser_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		user: &db.User{
			ID:        1,
			Username:  "alice-updated",
			TenantID:  "tenant-1",
			RoleIDs:   []string{"role-1", "role-3"},
			Lifecycle: string(qrdbsdk.LifecycleActive),
			UpdatedAt: "2025-06-01T00:00:00Z",
		},
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	resp, err := grpcSrv.UpdateTenantUser(context.Background(), &adminv1.UpdateTenantUserRequest{
		TenantId: "tenant-1",
		UserId:   "1",
		Username: "alice-updated",
		RoleIds:  []string{"role-1", "role-3"},
	})

	require.NoError(t, err)
	assert.Equal(t, "alice-updated", resp.Username)
	assert.Len(t, resp.RoleIds, 2)
}

func TestGRPC_UpdateTenantUser_ServiceNotAvailable(t *testing.T) {
	srv := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.UpdateTenantUser(context.Background(), &adminv1.UpdateTenantUserRequest{
		TenantId: "tenant-1",
		UserId:   "1",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestGRPC_UpdateTenantUser_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		updateUserErr: errors.New("update failed"),
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.UpdateTenantUser(context.Background(), &adminv1.UpdateTenantUserRequest{
		TenantId: "tenant-1",
		UserId:   "1",
	})

	assert.Error(t, err)
}

func TestGRPC_DeleteTenantUser_Success(t *testing.T) {
	mockTenant := &mockTenantService{}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	resp, err := grpcSrv.DeleteTenantUser(context.Background(), &adminv1.DeleteTenantUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-1",
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGRPC_DeleteTenantUser_ServiceNotAvailable(t *testing.T) {
	srv := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.DeleteTenantUser(context.Background(), &adminv1.DeleteTenantUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-1",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestGRPC_DeleteTenantUser_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		deleteUserErr: errors.New("delete failed"),
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.DeleteTenantUser(context.Background(), &adminv1.DeleteTenantUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-1",
	})

	assert.Error(t, err)
}

func TestGRPC_ListTenantUsers_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		users: &db.ListUsersResponse{
			Users: []*db.User{
				{ID: 1, Username: "alice", TenantID: "tenant-1", Lifecycle: string(qrdbsdk.LifecycleActive)},
				{ID: 2, Username: "bob", TenantID: "tenant-1", Lifecycle: string(qrdbsdk.LifecycleDisabled)},
			},
			Total:   2,
			HasMore: true,
		},
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	resp, err := grpcSrv.ListTenantUsers(context.Background(), &adminv1.ListTenantUsersRequest{
		TenantId: "tenant-1",
		Page:     1,
		PageSize: 2,
	})

	require.NoError(t, err)
	assert.Len(t, resp.Users, 2)
	assert.Equal(t, int32(2), resp.Total)
	assert.True(t, resp.HasMore)
	assert.Equal(t, "alice", resp.Users[0].Username)
	assert.True(t, resp.Users[0].Enabled)
	assert.Equal(t, "bob", resp.Users[1].Username)
	assert.False(t, resp.Users[1].Enabled)
}

func TestGRPC_ListTenantUsers_ServiceNotAvailable(t *testing.T) {
	srv := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.ListTenantUsers(context.Background(), &adminv1.ListTenantUsersRequest{
		TenantId: "tenant-1",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestGRPC_ListTenantUsers_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		listUsersErr: errors.New("list failed"),
	}
	srv := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcSrv := srv.(*adminServiceServer)

	_, err := grpcSrv.ListTenantUsers(context.Background(), &adminv1.ListTenantUsersRequest{
		TenantId: "tenant-1",
	})

	assert.Error(t, err)
}

// --- Conversion Function Tests ---

func TestConvertDBRoleToProto_Success(t *testing.T) {
	role := &db.Role{
		ID:          "role-1",
		Name:        "admin",
		TenantID:    "tenant-1",
		Permissions: []string{"read", "write"},
		System:      true,
		CreatedAt:   "2025-01-01T00:00:00Z",
		UpdatedAt:   "2025-06-01T00:00:00Z",
	}

	result := convertDBRoleToProto(role)

	require.NotNil(t, result)
	assert.Equal(t, "role-1", result.Id)
	assert.Equal(t, "admin", result.Name)
	assert.Equal(t, "tenant-1", result.TenantId)
	assert.Equal(t, []string{"read", "write"}, result.Permissions)
	assert.True(t, result.System)
	assert.Equal(t, "2025-01-01T00:00:00Z", result.CreatedAt)
	assert.Equal(t, "2025-06-01T00:00:00Z", result.UpdatedAt)
}

func TestConvertDBRoleToProto_Nil(t *testing.T) {
	result := convertDBRoleToProto(nil)
	assert.Nil(t, result)
}

func TestConvertDBUserToProto_Success(t *testing.T) {
	user := &db.User{
		ID:        1,
		Username:  "alice",
		TenantID:  "tenant-1",
		RoleIDs:   []string{"role-1", "role-2"},
		Lifecycle: string(qrdbsdk.LifecycleActive),
		System:    false,
		CreatedAt: "2025-01-01T00:00:00Z",
		UpdatedAt: "2025-06-01T00:00:00Z",
	}

	result := convertDBUserToProto(user)

	require.NotNil(t, result)
	assert.Equal(t, "1", result.Id)
	assert.Equal(t, "alice", result.Username)
	assert.Equal(t, "tenant-1", result.TenantId)
	assert.Equal(t, []string{"role-1", "role-2"}, result.RoleIds)
	assert.True(t, result.Enabled)
	assert.False(t, result.System)
	assert.Equal(t, "2025-01-01T00:00:00Z", result.CreatedAt)
	assert.Equal(t, "2025-06-01T00:00:00Z", result.UpdatedAt)
}

func TestConvertDBUserToProto_Nil(t *testing.T) {
	result := convertDBUserToProto(nil)
	assert.Nil(t, result)
}

// --- MCP Role Handler Tests ---

func TestMCP_CreateRole_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		role: &db.Role{
			ID:          "role-1",
			Name:        "editor",
			TenantID:    "tenant-1",
			Permissions: []string{"read", "write"},
		},
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"role": map[string]interface{}{
			"name":        "editor",
			"permissions": []string{"read", "write"},
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createRole",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Result)
}

func TestMCP_CreateRole_InvalidParams(t *testing.T) {
	mockTenant := &mockTenantService{}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createRole",
		Params:  json.RawMessage(`[1,2,3]`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_CreateRole_ServiceError(t *testing.T) {
	mockTenant := &mockTenantService{
		createRoleErr: errors.New("creation failed"),
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"role": map[string]interface{}{
			"name": "editor",
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createRole",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_GetRole_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		role: &db.Role{
			ID:       "role-1",
			Name:     "admin",
			TenantID: "tenant-1",
		},
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenantId": "tenant-1",
		"roleId":   "role-1",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getRole",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
}

func TestMCP_GetRole_InvalidParams(t *testing.T) {
	srv := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getRole",
		Params:  json.RawMessage(`"invalid"`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_GetRole_ServiceError(t *testing.T) {
	mockTenant := &mockTenantService{
		getRoleErr: errors.New("not found"),
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenantId": "tenant-1",
		"roleId":   "missing",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getRole",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_UpdateRole_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		role: &db.Role{
			ID:          "role-1",
			Name:        "updated-role",
			TenantID:    "tenant-1",
			Permissions: []string{"read", "write", "delete"},
		},
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"role": map[string]interface{}{
			"id":          "role-1",
			"name":        "updated-role",
			"permissions": []string{"read", "write", "delete"},
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.updateRole",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
}

func TestMCP_UpdateRole_InvalidParams(t *testing.T) {
	srv := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.updateRole",
		Params:  json.RawMessage(`123`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_UpdateRole_ServiceError(t *testing.T) {
	mockTenant := &mockTenantService{
		updateRoleErr: errors.New("update failed"),
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"role": map[string]interface{}{
			"id":   "role-1",
			"name": "updated",
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.updateRole",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_DeleteRole_Success(t *testing.T) {
	mockTenant := &mockTenantService{}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenantId": "tenant-1",
		"roleId":   "role-1",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteRole",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
}

func TestMCP_DeleteRole_InvalidParams(t *testing.T) {
	srv := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteRole",
		Params:  json.RawMessage(`true`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_DeleteRole_ServiceError(t *testing.T) {
	mockTenant := &mockTenantService{
		deleteRoleErr: errors.New("delete failed"),
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenantId": "tenant-1",
		"roleId":   "role-1",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteRole",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_ListRoles_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		roles: &db.ListRolesResponse{
			Roles: []*db.Role{
				{ID: "role-1", Name: "admin"},
			},
			Total:   1,
			HasMore: false,
		},
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"request": map[string]interface{}{
			"page":     1,
			"pageSize": 20,
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listRoles",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
}

func TestMCP_ListRoles_InvalidParams(t *testing.T) {
	srv := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listRoles",
		Params:  json.RawMessage(`false`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_ListRoles_ServiceError(t *testing.T) {
	mockTenant := &mockTenantService{
		listRolesErr: errors.New("list failed"),
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"request": map[string]interface{}{
			"page":     1,
			"pageSize": 20,
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listRoles",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

// --- MCP User Handler Tests ---

func TestMCP_CreateUser_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		user: &db.User{
			ID:        1,
			Username:  "alice",
			TenantID:  "tenant-1",
			RoleIDs:   []string{"role-1"},
			Lifecycle: string(qrdbsdk.LifecycleActive),
		},
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"user": map[string]interface{}{
			"username": "alice",
			"roleIDs":  []string{"role-1"},
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createUser",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
}

func TestMCP_CreateUser_InvalidParams(t *testing.T) {
	srv := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createUser",
		Params:  json.RawMessage(`[1,2,3]`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_CreateUser_ServiceError(t *testing.T) {
	mockTenant := &mockTenantService{
		createUserErr: errors.New("creation failed"),
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"user": map[string]interface{}{
			"username": "alice",
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createUser",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_GetUser_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		user: &db.User{
			ID:       1,
			Username: "alice",
			TenantID: "tenant-1",
		},
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenantId": "tenant-1",
		"userId":   "user-1",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getUser",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
}

func TestMCP_GetUser_InvalidParams(t *testing.T) {
	srv := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getUser",
		Params:  json.RawMessage(`"invalid"`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_GetUser_ServiceError(t *testing.T) {
	mockTenant := &mockTenantService{
		getUserErr: errors.New("not found"),
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenantId": "tenant-1",
		"userId":   "missing",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getUser",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_UpdateUser_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		user: &db.User{
			ID:       1,
			Username: "alice-updated",
			TenantID: "tenant-1",
			RoleIDs:  []string{"role-1", "role-3"},
		},
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"user": map[string]interface{}{
			"id":       "1",
			"username": "alice-updated",
			"roleIDs":  []string{"role-1", "role-3"},
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.updateUser",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
}

func TestMCP_UpdateUser_InvalidParams(t *testing.T) {
	srv := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.updateUser",
		Params:  json.RawMessage(`123`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_UpdateUser_ServiceError(t *testing.T) {
	mockTenant := &mockTenantService{
		updateUserErr: errors.New("update failed"),
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"user": map[string]interface{}{
			"id":       "1",
			"username": "updated",
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.updateUser",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_DeleteUser_Success(t *testing.T) {
	mockTenant := &mockTenantService{}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenantId": "tenant-1",
		"userId":   "user-1",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteUser",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
}

func TestMCP_DeleteUser_InvalidParams(t *testing.T) {
	srv := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteUser",
		Params:  json.RawMessage(`true`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_DeleteUser_ServiceError(t *testing.T) {
	mockTenant := &mockTenantService{
		deleteUserErr: errors.New("delete failed"),
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenantId": "tenant-1",
		"userId":   "user-1",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteUser",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_ListUsers_Success(t *testing.T) {
	mockTenant := &mockTenantService{
		users: &db.ListUsersResponse{
			Users: []*db.User{
				{ID: 1, Username: "alice"},
			},
			Total:   1,
			HasMore: false,
		},
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"request": map[string]interface{}{
			"page":     1,
			"pageSize": 20,
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listUsers",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
}

func TestMCP_ListUsers_InvalidParams(t *testing.T) {
	srv := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listUsers",
		Params:  json.RawMessage(`false`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}

func TestMCP_ListUsers_ServiceError(t *testing.T) {
	mockTenant := &mockTenantService{
		listUsersErr: errors.New("list failed"),
	}
	srv := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "tenant-1",
		"request": map[string]interface{}{
			"page":     1,
			"pageSize": 20,
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listUsers",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	srv.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Error)
}
