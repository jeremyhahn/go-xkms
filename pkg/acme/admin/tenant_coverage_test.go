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

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
)

// ==========================================================================
// Tenant role/user handler coverage (0% functions)
// ==========================================================================

// newAuthedTenantRequest creates a tenant handler request with super-admin context.
func newAuthedTenantRequest(method, path string, body []byte) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	return addUserToRequest(req, createPlatformAdminUser())
}

func TestTenantHandlers_CreateTenantRole_Success(t *testing.T) {
	svc := &mockTenantService{
		createTenantRoleFunc: func(_ context.Context, _ string, _ *db.CreateRoleRequest) (*db.Role, error) {
			return &db.Role{ID: "role-1", Name: "admin"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())

	body, _ := json.Marshal(db.CreateRoleRequest{Name: "admin"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/roles", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantRole(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestTenantHandlers_CreateTenantRole_EmptyTenantID(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	body, _ := json.Marshal(db.CreateRoleRequest{Name: "admin"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants//roles", body)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	w := httptest.NewRecorder()
	h.CreateTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_CreateTenantRole_BadJSON(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/roles", []byte("bad"))
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_CreateTenantRole_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		createTenantRoleFunc: func(_ context.Context, _ string, _ *db.CreateRoleRequest) (*db.Role, error) {
			return nil, errors.New("create failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.CreateRoleRequest{Name: "admin"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/roles", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantRole(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_GetTenantRole_Success(t *testing.T) {
	svc := &mockTenantService{
		getTenantRoleFunc: func(_ context.Context, _ string, _ string) (*db.Role, error) {
			return &db.Role{ID: "role-1", Name: "admin"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/roles/role-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.GetTenantRole(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_GetTenantRole_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants//roles/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "roleID": ""})
	w := httptest.NewRecorder()
	h.GetTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_GetTenantRole_NotFound(t *testing.T) {
	svc := &mockTenantService{
		getTenantRoleFunc: func(_ context.Context, _ string, _ string) (*db.Role, error) {
			return nil, errors.New("not found")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/roles/role-x", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-x"})
	w := httptest.NewRecorder()
	h.GetTenantRole(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTenantHandlers_UpdateTenantRole_Success(t *testing.T) {
	svc := &mockTenantService{
		updateTenantRoleFunc: func(_ context.Context, _ string, _ *db.UpdateRoleRequest) (*db.Role, error) {
			return &db.Role{ID: "role-1", Name: "updated"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.UpdateRoleRequest{Name: "updated"})
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/roles/role-1", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.UpdateTenantRole(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_UpdateTenantRole_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants//roles/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "roleID": ""})
	w := httptest.NewRecorder()
	h.UpdateTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_UpdateTenantRole_BadJSON(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/roles/role-1", []byte("bad"))
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.UpdateTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_UpdateTenantRole_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		updateTenantRoleFunc: func(_ context.Context, _ string, _ *db.UpdateRoleRequest) (*db.Role, error) {
			return nil, errors.New("update failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.UpdateRoleRequest{Name: "x"})
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/roles/role-1", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.UpdateTenantRole(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_DeleteTenantRole_Success(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants/t1/roles/role-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.DeleteTenantRole(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_DeleteTenantRole_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants//roles/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "roleID": ""})
	w := httptest.NewRecorder()
	h.DeleteTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_DeleteTenantRole_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		deleteTenantRoleFunc: func(_ context.Context, _ string, _ string) error {
			return errors.New("delete failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants/t1/roles/role-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.DeleteTenantRole(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_ListTenantRoles_Success(t *testing.T) {
	svc := &mockTenantService{
		listTenantRolesFunc: func(_ context.Context, _ string, _ *db.ListRolesRequest) (*db.ListRolesResponse, error) {
			return &db.ListRolesResponse{Roles: []*db.Role{{ID: "r1", Name: "admin"}}}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/roles?page=1&page_size=20", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantRoles(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_ListTenantRoles_EmptyTenantID(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants//roles", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	w := httptest.NewRecorder()
	h.ListTenantRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_ListTenantRoles_NilRoles(t *testing.T) {
	svc := &mockTenantService{
		listTenantRolesFunc: func(_ context.Context, _ string, _ *db.ListRolesRequest) (*db.ListRolesResponse, error) {
			return &db.ListRolesResponse{Roles: nil}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/roles", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantRoles(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_ListTenantRoles_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		listTenantRolesFunc: func(_ context.Context, _ string, _ *db.ListRolesRequest) (*db.ListRolesResponse, error) {
			return nil, errors.New("list failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/roles", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantRoles(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_DeleteTenantUser_Success(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants/t1/users/u1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "u1"})
	w := httptest.NewRecorder()
	h.DeleteTenantUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_DeleteTenantUser_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants//users/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "userID": ""})
	w := httptest.NewRecorder()
	h.DeleteTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_DeleteTenantUser_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		deleteTenantUserFunc: func(_ context.Context, _ string, _ string) error {
			return errors.New("delete failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants/t1/users/u1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "u1"})
	w := httptest.NewRecorder()
	h.DeleteTenantUser(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_ListTenantUsers_Success(t *testing.T) {
	svc := &mockTenantService{
		listTenantUsersFunc: func(_ context.Context, _ string, _ *db.ListUsersRequest) (*db.ListUsersResponse, error) {
			return &db.ListUsersResponse{Users: []*db.User{{ID: 1, Username: "alice"}}}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/users?page=2&page_size=5", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_ListTenantUsers_EmptyTenantID(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants//users", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	w := httptest.NewRecorder()
	h.ListTenantUsers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_ListTenantUsers_NilUsers(t *testing.T) {
	svc := &mockTenantService{
		listTenantUsersFunc: func(_ context.Context, _ string, _ *db.ListUsersRequest) (*db.ListUsersResponse, error) {
			return &db.ListUsersResponse{Users: nil}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/users", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_ListTenantUsers_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		listTenantUsersFunc: func(_ context.Context, _ string, _ *db.ListUsersRequest) (*db.ListUsersResponse, error) {
			return nil, errors.New("list failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/users", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantUsers(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_CreateTenantUser_Success(t *testing.T) {
	svc := &mockTenantService{
		createTenantUserFunc: func(_ context.Context, _ string, _ *db.CreateUserRequest) (*db.User, error) {
			return &db.User{ID: 1, Username: "alice"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.CreateUserRequest{Username: "alice"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/users", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantUser(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestTenantHandlers_CreateTenantUser_EmptyTenantID(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	body, _ := json.Marshal(db.CreateUserRequest{Username: "alice"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants//users", body)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	w := httptest.NewRecorder()
	h.CreateTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_CreateTenantUser_BadJSON(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/users", []byte("bad"))
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_CreateTenantUser_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		createTenantUserFunc: func(_ context.Context, _ string, _ *db.CreateUserRequest) (*db.User, error) {
			return nil, errors.New("create failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.CreateUserRequest{Username: "alice"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/users", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantUser(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_GetTenantUser_Success(t *testing.T) {
	svc := &mockTenantService{
		getTenantUserFunc: func(_ context.Context, _ string, _ string) (*db.User, error) {
			return &db.User{ID: 1, Username: "alice"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/users/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "1"})
	w := httptest.NewRecorder()
	h.GetTenantUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_GetTenantUser_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants//users/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "userID": ""})
	w := httptest.NewRecorder()
	h.GetTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_GetTenantUser_NotFound(t *testing.T) {
	svc := &mockTenantService{
		getTenantUserFunc: func(_ context.Context, _ string, _ string) (*db.User, error) {
			return nil, errors.New("not found")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/users/99", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "99"})
	w := httptest.NewRecorder()
	h.GetTenantUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTenantHandlers_UpdateTenantUser_Success(t *testing.T) {
	svc := &mockTenantService{
		updateTenantUserFunc: func(_ context.Context, _ string, _ *db.UpdateUserRequest) (*db.User, error) {
			return &db.User{ID: 1, Username: "updated"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.UpdateUserRequest{Username: "updated"})
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/users/1", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "1"})
	w := httptest.NewRecorder()
	h.UpdateTenantUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_UpdateTenantUser_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants//users/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "userID": ""})
	w := httptest.NewRecorder()
	h.UpdateTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_UpdateTenantUser_BadJSON(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/users/1", []byte("bad"))
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "1"})
	w := httptest.NewRecorder()
	h.UpdateTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_UpdateTenantUser_InvalidUserID(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	body, _ := json.Marshal(db.UpdateUserRequest{Username: "x"})
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/users/not-a-number", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "not-a-number"})
	w := httptest.NewRecorder()
	h.UpdateTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_UpdateTenantUser_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		updateTenantUserFunc: func(_ context.Context, _ string, _ *db.UpdateUserRequest) (*db.User, error) {
			return nil, errors.New("update failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.UpdateUserRequest{Username: "x"})
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/users/1", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "1"})
	w := httptest.NewRecorder()
	h.UpdateTenantUser(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
