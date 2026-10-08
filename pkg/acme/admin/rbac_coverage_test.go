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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/mux"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Tenant Handlers - Role RBAC Tests
// ============================================================================

func TestCreateTenantRole_Success(t *testing.T) {
	service := &mockTenantService{
		createTenantRoleFunc: func(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error) {
			return &db.Role{
				ID:       "role-1",
				TenantID: tenantID,
				Name:     req.Name,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"name": "editor", "description": "Can edit resources"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/roles", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.CreateTenantRole(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestCreateTenantRole_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/roles", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.CreateTenantRole(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateTenantRole_EmptyTenantID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"name": "editor"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants//roles", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.CreateTenantRole(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateTenantRole_ServiceError(t *testing.T) {
	service := &mockTenantService{
		createTenantRoleFunc: func(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"name": "editor"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/roles", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.CreateTenantRole(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetTenantRole_Success(t *testing.T) {
	service := &mockTenantService{
		getTenantRoleFunc: func(ctx context.Context, tenantID string, roleID string) (*db.Role, error) {
			return &db.Role{
				ID:       roleID,
				TenantID: tenantID,
				Name:     "editor",
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/roles/role-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "roleID": "role-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.GetTenantRole(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetTenantRole_NotFound(t *testing.T) {
	service := &mockTenantService{
		getTenantRoleFunc: func(ctx context.Context, tenantID string, roleID string) (*db.Role, error) {
			return nil, ErrRoleNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/roles/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "roleID": "nonexistent"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.GetTenantRole(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetTenantRole_EmptyTenantOrRoleID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	// Empty tenant ID
	req := httptest.NewRequest("GET", "/api/v1/tenants//roles/role-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "roleID": "role-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()
	handlers.GetTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Empty role ID
	req = httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/roles/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "roleID": ""})
	req = authenticated(req)
	w = httptest.NewRecorder()
	handlers.GetTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateTenantRole_Success(t *testing.T) {
	service := &mockTenantService{
		updateTenantRoleFunc: func(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error) {
			return &db.Role{
				ID:       req.ID,
				TenantID: tenantID,
				Name:     "updated-editor",
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"name": "updated-editor"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/roles/role-1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "roleID": "role-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.UpdateTenantRole(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateTenantRole_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/roles/role-1", bytes.NewBufferString("bad json"))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "roleID": "role-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.UpdateTenantRole(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateTenantRole_EmptyTenantOrRoleID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"name": "updated"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants//roles/role-1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "", "roleID": "role-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()
	handlers.UpdateTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateTenantRole_ServiceError(t *testing.T) {
	service := &mockTenantService{
		updateTenantRoleFunc: func(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error) {
			return nil, errors.New("update failed")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"name": "updated"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/roles/role-1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "roleID": "role-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.UpdateTenantRole(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteTenantRole_Success(t *testing.T) {
	service := &mockTenantService{
		deleteTenantRoleFunc: func(ctx context.Context, tenantID string, roleID string) error {
			return nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1/roles/role-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "roleID": "role-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.DeleteTenantRole(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteTenantRole_EmptyTenantOrRoleID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants//roles/role-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "roleID": "role-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()
	handlers.DeleteTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteTenantRole_ServiceError(t *testing.T) {
	service := &mockTenantService{
		deleteTenantRoleFunc: func(ctx context.Context, tenantID string, roleID string) error {
			return errors.New("delete failed")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1/roles/role-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "roleID": "role-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.DeleteTenantRole(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListTenantRoles_Success(t *testing.T) {
	service := &mockTenantService{
		listTenantRolesFunc: func(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
			return &db.ListRolesResponse{
				Roles: []*db.Role{
					{ID: "role-1", TenantID: tenantID, Name: "editor"},
					{ID: "role-2", TenantID: tenantID, Name: "viewer"},
				},
				Total: 2,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/roles?page=1&page_size=20", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.ListTenantRoles(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListTenantRoles_EmptyTenantID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants//roles", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.ListTenantRoles(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListTenantRoles_ServiceError(t *testing.T) {
	service := &mockTenantService{
		listTenantRolesFunc: func(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
			return nil, errors.New("list failed")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/roles", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.ListTenantRoles(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// Tenant Handlers - User RBAC Tests
// ============================================================================

func TestCreateTenantUser_Success(t *testing.T) {
	service := &mockTenantService{
		createTenantUserFunc: func(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error) {
			return &db.User{
				ID:       uint64(1),
				TenantID: tenantID,
				Username: req.Username,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"username": "newuser", "email": "newuser@example.com"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/users", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.CreateTenantUser(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestCreateTenantUser_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/users", bytes.NewBufferString("not json"))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.CreateTenantUser(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateTenantUser_EmptyTenantID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"username": "newuser"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants//users", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.CreateTenantUser(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateTenantUser_ServiceError(t *testing.T) {
	service := &mockTenantService{
		createTenantUserFunc: func(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"username": "newuser"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/users", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.CreateTenantUser(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetTenantUser_Success(t *testing.T) {
	service := &mockTenantService{
		getTenantUserFunc: func(ctx context.Context, tenantID string, userID string) (*db.User, error) {
			return &db.User{
				ID:       uint64(1),
				TenantID: tenantID,
				Username: "testuser",
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/users/user-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "userID": "1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.GetTenantUser(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetTenantUser_NotFound(t *testing.T) {
	service := &mockTenantService{
		getTenantUserFunc: func(ctx context.Context, tenantID string, userID string) (*db.User, error) {
			return nil, ErrUserNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/users/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "userID": "999"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.GetTenantUser(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetTenantUser_EmptyTenantOrUserID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants//users/user-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "userID": "1"})
	req = authenticated(req)
	w := httptest.NewRecorder()
	handlers.GetTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	req = httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/users/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "userID": ""})
	req = authenticated(req)
	w = httptest.NewRecorder()
	handlers.GetTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateTenantUser_Success(t *testing.T) {
	service := &mockTenantService{
		updateTenantUserFunc: func(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error) {
			return &db.User{
				ID:       req.ID,
				TenantID: tenantID,
				Username: "updated-user",
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"username": "updated-user"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/users/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "userID": "1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.UpdateTenantUser(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateTenantUser_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/users/user-1", bytes.NewBufferString("bad"))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "userID": "1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.UpdateTenantUser(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateTenantUser_EmptyTenantOrUserID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"username": "updated"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants//users/user-1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "", "userID": "1"})
	req = authenticated(req)
	w := httptest.NewRecorder()
	handlers.UpdateTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateTenantUser_ServiceError(t *testing.T) {
	service := &mockTenantService{
		updateTenantUserFunc: func(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error) {
			return nil, errors.New("update failed")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"username": "updated"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/users/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "userID": "1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.UpdateTenantUser(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteTenantUser_Success(t *testing.T) {
	service := &mockTenantService{
		deleteTenantUserFunc: func(ctx context.Context, tenantID string, userID string) error {
			return nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1/users/user-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "userID": "1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.DeleteTenantUser(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteTenantUser_EmptyTenantOrUserID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants//users/user-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "userID": "1"})
	req = authenticated(req)
	w := httptest.NewRecorder()
	handlers.DeleteTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteTenantUser_ServiceError(t *testing.T) {
	service := &mockTenantService{
		deleteTenantUserFunc: func(ctx context.Context, tenantID string, userID string) error {
			return errors.New("delete failed")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1/users/user-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "userID": "1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.DeleteTenantUser(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListTenantUsers_Success(t *testing.T) {
	service := &mockTenantService{
		listTenantUsersFunc: func(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
			return &db.ListUsersResponse{
				Users: []*db.User{
					{ID: uint64(1), TenantID: tenantID, Username: "alice"},
					{ID: uint64(2), TenantID: tenantID, Username: "bob"},
				},
				Total: 2,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/users?page=1&page_size=20", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.ListTenantUsers(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListTenantUsers_EmptyTenantID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants//users", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.ListTenantUsers(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListTenantUsers_ServiceError(t *testing.T) {
	service := &mockTenantService{
		listTenantUsersFunc: func(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
			return nil, errors.New("list failed")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/users", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.ListTenantUsers(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// parsePagination Tests
// ============================================================================

func TestParsePagination_Defaults(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	page, pageSize := parsePagination(req)
	assert.Equal(t, 1, page)
	assert.Equal(t, 20, pageSize)
}

func TestParsePagination_CustomValues(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/test?page=3&page_size=50", nil)
	page, pageSize := parsePagination(req)
	assert.Equal(t, 3, page)
	assert.Equal(t, 50, pageSize)
}

func TestParsePagination_InvalidValues(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/test?page=abc&page_size=xyz", nil)
	page, pageSize := parsePagination(req)
	assert.Equal(t, 1, page)
	assert.Equal(t, 20, pageSize)
}

func TestParsePagination_NegativeValues(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/test?page=-1&page_size=-5", nil)
	page, pageSize := parsePagination(req)
	assert.Equal(t, 1, page)
	assert.Equal(t, 20, pageSize)
}

func TestParsePagination_ZeroValues(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/test?page=0&page_size=0", nil)
	page, pageSize := parsePagination(req)
	assert.Equal(t, 1, page)
	assert.Equal(t, 20, pageSize)
}

// ============================================================================
// Tenant Service - Role RBAC Tests
// ============================================================================

func TestTenantService_CreateTenantRole_EmptyTenantID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.CreateTenantRole(context.Background(), "", &db.CreateRoleRequest{Name: "editor"})
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestTenantService_CreateTenantRole_NilQRDB(t *testing.T) {
	logger := slog.Default()
	service := mustTenantAwareAdminService(t, nil, nil, nil, logger, "1.0.0")

	_, err := service.CreateTenantRole(context.Background(), "tenant-1", &db.CreateRoleRequest{Name: "editor"})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantService_CreateTenantRole_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	role, err := service.CreateTenantRole(context.Background(), "tenant-1", &db.CreateRoleRequest{
		Name:     "editor",
		TenantID: "tenant-1",
	})
	require.NoError(t, err)
	assert.NotNil(t, role)
}

func TestTenantService_GetTenantRole_EmptyTenantID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.GetTenantRole(context.Background(), "", "role-1")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestTenantService_GetTenantRole_NilQRDB(t *testing.T) {
	logger := slog.Default()
	service := mustTenantAwareAdminService(t, nil, nil, nil, logger, "1.0.0")

	_, err := service.GetTenantRole(context.Background(), "tenant-1", "role-1")
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantService_UpdateTenantRole_EmptyTenantID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.UpdateTenantRole(context.Background(), "", &db.UpdateRoleRequest{ID: "role-1"})
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestTenantService_UpdateTenantRole_NilQRDB(t *testing.T) {
	logger := slog.Default()
	service := mustTenantAwareAdminService(t, nil, nil, nil, logger, "1.0.0")

	_, err := service.UpdateTenantRole(context.Background(), "tenant-1", &db.UpdateRoleRequest{ID: "role-1"})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantService_DeleteTenantRole_EmptyTenantID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	err := service.DeleteTenantRole(context.Background(), "", "role-1")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestTenantService_DeleteTenantRole_NilQRDB(t *testing.T) {
	logger := slog.Default()
	service := mustTenantAwareAdminService(t, nil, nil, nil, logger, "1.0.0")

	err := service.DeleteTenantRole(context.Background(), "tenant-1", "role-1")
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantService_ListTenantRoles_EmptyTenantID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.ListTenantRoles(context.Background(), "", &db.ListRolesRequest{})
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestTenantService_ListTenantRoles_NilQRDB(t *testing.T) {
	logger := slog.Default()
	service := mustTenantAwareAdminService(t, nil, nil, nil, logger, "1.0.0")

	_, err := service.ListTenantRoles(context.Background(), "tenant-1", &db.ListRolesRequest{})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

// ============================================================================
// Tenant Service - User RBAC Tests
// ============================================================================

func TestTenantService_CreateTenantUser_EmptyTenantID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.CreateTenantUser(context.Background(), "", &db.CreateUserRequest{Username: "user1"})
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestTenantService_CreateTenantUser_NilQRDB(t *testing.T) {
	logger := slog.Default()
	service := mustTenantAwareAdminService(t, nil, nil, nil, logger, "1.0.0")

	_, err := service.CreateTenantUser(context.Background(), "tenant-1", &db.CreateUserRequest{Username: "user1"})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantService_CreateTenantUser_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	user, err := service.CreateTenantUser(context.Background(), "tenant-1", &db.CreateUserRequest{
		Username: "testuser",
		TenantID: "tenant-1",
		Email:    "testuser@example.com",
	})
	require.NoError(t, err)
	assert.NotNil(t, user)
}

func TestTenantService_GetTenantUser_EmptyTenantID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.GetTenantUser(context.Background(), "", "user-1")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestTenantService_GetTenantUser_NilQRDB(t *testing.T) {
	logger := slog.Default()
	service := mustTenantAwareAdminService(t, nil, nil, nil, logger, "1.0.0")

	_, err := service.GetTenantUser(context.Background(), "tenant-1", "user-1")
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantService_UpdateTenantUser_EmptyTenantID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.UpdateTenantUser(context.Background(), "", &db.UpdateUserRequest{ID: uint64(1)})
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestTenantService_UpdateTenantUser_NilQRDB(t *testing.T) {
	logger := slog.Default()
	service := mustTenantAwareAdminService(t, nil, nil, nil, logger, "1.0.0")

	_, err := service.UpdateTenantUser(context.Background(), "tenant-1", &db.UpdateUserRequest{ID: uint64(1)})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantService_DeleteTenantUser_EmptyTenantID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	err := service.DeleteTenantUser(context.Background(), "", "user-1")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestTenantService_DeleteTenantUser_NilQRDB(t *testing.T) {
	logger := slog.Default()
	service := mustTenantAwareAdminService(t, nil, nil, nil, logger, "1.0.0")

	err := service.DeleteTenantUser(context.Background(), "tenant-1", "user-1")
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantService_ListTenantUsers_EmptyTenantID(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	_, err := service.ListTenantUsers(context.Background(), "", &db.ListUsersRequest{})
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestTenantService_ListTenantUsers_NilQRDB(t *testing.T) {
	logger := slog.Default()
	service := mustTenantAwareAdminService(t, nil, nil, nil, logger, "1.0.0")

	_, err := service.ListTenantUsers(context.Background(), "tenant-1", &db.ListUsersRequest{})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

// ============================================================================
// service.go - Additional coverage for sub-90% methods
// ============================================================================

func TestAdminService_GetCertificate_InvalidPEM(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Save a certificate with invalid PEM to exercise the "continue" branch in GetCertificate
	badCert := &entities.ACMECertificate{
		NumericID: 99,
		Serial:    "99",
		PEM:       "not-valid-pem",
		Status:    "valid",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
		CertURL:   "https://example.com/cert/bad",
	}
	require.NoError(t, certDAO.Save(ctx, badCert))

	// This should return not found since the PEM can't be parsed
	_, err = service.GetCertificate(ctx, "some-serial-that-wont-match")
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

func TestAdminService_RevokeCertificate_InvalidPEMCertSkipped(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Save a certificate with invalid PEM
	badCert := &entities.ACMECertificate{
		NumericID: 99,
		Serial:    "99",
		PEM:       "invalid-pem-data",
		Status:    "valid",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
	require.NoError(t, certDAO.Save(ctx, badCert))

	// This should skip the bad cert and return not found
	err = service.RevokeCertificate(ctx, "some-serial", "testing")
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

func TestAdminService_ListAccounts_Pagination_StartExceedsTotal(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{
		ID:        1,
		Status:    "valid",
		Contact:   []string{"mailto:test@example.com"},
		CreatedAt: time.Now(),
	}
	require.NoError(t, accountDAO.Save(ctx, account))

	// Request page 100 when there's only 1 account - exercises the start >= total branch
	req := ListAccountsRequest{Page: 100, PerPage: 10}
	accounts, pagination, err := service.ListAccounts(ctx, req)

	require.NoError(t, err)
	assert.Len(t, accounts, 0)
	assert.Equal(t, 1, pagination.Total)
	assert.Equal(t, 100, pagination.Page)
}

func TestAdminService_DisableAccount_AlreadyDeactivated(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{
		ID:        1,
		Status:    "deactivated",
		Contact:   []string{"mailto:test@example.com"},
		CreatedAt: time.Now(),
	}
	require.NoError(t, accountDAO.Save(ctx, account))

	// Disabling an already deactivated account should still succeed
	err = service.DisableAccount(ctx, 1)
	require.NoError(t, err)
}

func TestAdminService_ListOrders_Pagination_StartExceedsTotal(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{ID: 1, Status: "valid", CreatedAt: time.Now()}
	require.NoError(t, accountDAO.Save(ctx, account))

	orderDAO, err := service.storageFactory.OrderDAO(1)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		ID:          1,
		AccountID:   1,
		Status:      "pending",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "example.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	require.NoError(t, orderDAO.Save(ctx, order))

	// Request page 100 to exercise start >= total branch
	req := ListOrdersRequest{Page: 100, PerPage: 10}
	orders, pagination, err := service.ListOrders(ctx, req)

	require.NoError(t, err)
	assert.Len(t, orders, 0)
	assert.Equal(t, 1, pagination.Total)
}

func TestAdminService_ListOrders_DefaultPagination(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Test with invalid pagination (should default)
	req := ListOrdersRequest{Page: 0, PerPage: 0}
	_, pagination, err := service.ListOrders(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, 1, pagination.Page)
	assert.Equal(t, 20, pagination.PerPage)
}

func TestAdminService_ListOrders_MaxPerPage(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := ListOrdersRequest{Page: 1, PerPage: 500}
	_, pagination, err := service.ListOrders(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, 100, pagination.PerPage)
}

func TestAdminService_GetStats_WithRevokedAndExpiredCerts(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Valid cert that hasn't expired
	validCert := createTestACMECertificate(t, 1, "valid.example.com", "valid")
	require.NoError(t, certDAO.Save(ctx, validCert))

	// Revoked cert
	revokedCert := createTestACMECertificate(t, 2, "revoked.example.com", "revoked")
	require.NoError(t, certDAO.Save(ctx, revokedCert))

	// Expired cert (status still "valid" but past ExpiresAt)
	expiredCert := createTestACMECertificate(t, 3, "expired.example.com", "valid")
	expiredCert.ExpiresAt = time.Now().Add(-24 * time.Hour)
	require.NoError(t, certDAO.Save(ctx, expiredCert))

	// Create an account with deactivated status
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	activeAccount := &entities.ACMEAccount{ID: 1, Status: "valid", CreatedAt: time.Now()}
	deactivatedAccount := &entities.ACMEAccount{ID: 2, Status: "deactivated", CreatedAt: time.Now()}
	require.NoError(t, accountDAO.Save(ctx, activeAccount))
	require.NoError(t, accountDAO.Save(ctx, deactivatedAccount))

	// Create orders with various statuses
	orderDAO1, err := service.storageFactory.OrderDAO(1)
	require.NoError(t, err)

	pendingOrder := &entities.ACMEOrder{
		ID: 1, AccountID: 1, Status: "pending",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "a.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	processingOrder := &entities.ACMEOrder{
		ID: 2, AccountID: 1, Status: "processing",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "b.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	validOrder := &entities.ACMEOrder{
		ID: 3, AccountID: 1, Status: "valid",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "c.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	require.NoError(t, orderDAO1.Save(ctx, pendingOrder))
	require.NoError(t, orderDAO1.Save(ctx, processingOrder))
	require.NoError(t, orderDAO1.Save(ctx, validOrder))

	stats, err := service.GetStats(ctx)
	require.NoError(t, err)

	assert.Equal(t, 3, stats.TotalCertificates)
	assert.Equal(t, 1, stats.ValidCertificates)
	assert.Equal(t, 1, stats.RevokedCertificates)
	assert.Equal(t, 1, stats.ExpiredCertificates)
	assert.Equal(t, 2, stats.TotalAccounts)
	assert.Equal(t, 1, stats.ActiveAccounts)
	assert.GreaterOrEqual(t, stats.TotalOrders, 3)
	assert.GreaterOrEqual(t, stats.PendingOrders, 2)
	assert.GreaterOrEqual(t, stats.CompletedOrders, 1)
}

func TestAdminService_ConvertToCertificateInfo_InvalidPEM(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	cert := &entities.ACMECertificate{
		NumericID: 1,
		Serial:    "1",
		PEM:       "not-valid-pem",
		Status:    "valid",
	}

	_, err := service.convertToCertificateInfo(cert)
	assert.Error(t, err)
}

func TestAdminService_ListCertificates_WithConvertError(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Save a certificate with invalid PEM to exercise the "continue" in convertToCertificateInfo error path
	badCert := &entities.ACMECertificate{
		NumericID: 1,
		Serial:    "1",
		PEM:       "bad-pem-data",
		Status:    "valid",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
	require.NoError(t, certDAO.Save(ctx, badCert))

	// Also save a valid cert
	goodCert := createTestACMECertificate(t, 2, "good.example.com", "valid")
	require.NoError(t, certDAO.Save(ctx, goodCert))

	req := ListCertificatesRequest{Page: 1, PerPage: 10}
	certs, pagination, err := service.ListCertificates(ctx, req)

	require.NoError(t, err)
	// Bad cert should be skipped, only good cert returned
	assert.Len(t, certs, 1)
	assert.Equal(t, 2, pagination.Total) // Total includes bad cert in count
}

func TestAdminService_ListCertificates_SubjectFilter_InvalidPEM(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Save a cert with invalid PEM - when Subject filter is set, parsePEMCertificate
	// fails and the cert should still be included (the filter skips on parse error)
	badCert := &entities.ACMECertificate{
		NumericID: 1,
		Serial:    "1",
		PEM:       "bad-pem",
		Status:    "valid",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
	require.NoError(t, certDAO.Save(ctx, badCert))

	req := ListCertificatesRequest{Page: 1, PerPage: 10, Subject: "test.example.com"}
	certs, _, err := service.ListCertificates(ctx, req)
	require.NoError(t, err)
	// With subject filter and bad PEM: if err == nil is false, so it doesn't skip
	// but then convertToCertificateInfo will fail -> cert skipped in result
	assert.Len(t, certs, 0)
}

func TestAdminService_ListAccounts_DefaultAndMaxPagination(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Default pagination
	req := ListAccountsRequest{Page: 0, PerPage: 0}
	_, pagination, err := service.ListAccounts(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 1, pagination.Page)
	assert.Equal(t, 20, pagination.PerPage)

	// Max pagination
	req = ListAccountsRequest{Page: 1, PerPage: 500}
	_, pagination, err = service.ListAccounts(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 100, pagination.PerPage)
}

// ============================================================================
// storeKeyAndCert - RSA and Ed25519 key type branches
// ============================================================================

func TestCoverageBoost_StoreKeyAndCert_RSAKey(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := makeTestCert(t, "RSA CA")

	err = service.storeKeyAndCert(context.Background(), "tenant-rsa", "root", key, cert)
	require.NoError(t, err)
}

func TestCoverageBoost_StoreKeyAndCert_Ed25519Key(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	_, privKey, err := generateEd25519Key()
	require.NoError(t, err)
	cert := makeTestCert(t, "Ed25519 CA")

	err = service.storeKeyAndCert(context.Background(), "tenant-ed25519", "root", privKey, cert)
	require.NoError(t, err)
}

// generateEd25519Key generates an Ed25519 key pair for testing.
func generateEd25519Key() (x509.PublicKeyAlgorithm, interface{}, error) {
	logger := slog.Default()
	service, err := NewTenantAwareAdminService(nil, nil, nil, logger, "1.0.0")
	if err != nil {
		return x509.Ed25519, nil, err
	}
	priv, _, err := service.generateKeyPair(x509.Ed25519)
	return x509.Ed25519, priv, err
}

// ============================================================================
// Handlers - writeJSON without pagination
// ============================================================================

func TestWriteJSON_DirectData(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}

	writeJSON(w, http.StatusOK, data)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "value", resp["key"])
}

// ============================================================================
// Additional service.go coverage - ListCertificates pagination edge case
// ============================================================================

func TestAdminService_ListCertificates_StartExceedsTotal(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	cert := createTestACMECertificate(t, 1, "test.example.com", "valid")
	require.NoError(t, certDAO.Save(ctx, cert))

	// Request page 100 when there's only 1 cert
	req := ListCertificatesRequest{Page: 100, PerPage: 10}
	certs, pagination, err := service.ListCertificates(ctx, req)

	require.NoError(t, err)
	assert.Len(t, certs, 0)
	assert.Equal(t, 1, pagination.Total)
	assert.Equal(t, 100, pagination.Page)
}

// ============================================================================
// GetTenantSigningCA - global CA fallback
// ============================================================================

func TestCoverageBoost_GetTenantSigningCA_WithGlobalCA(t *testing.T) {
	// Create test infra with a real CA
	testCA, _, cleanup := createTestInfrastructure(t)
	defer cleanup()

	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, testCA, nil, qrdbSvc, logger, "1.0.0")

	// No tenant-specific CA exists, should fall back to global CA
	signer, cert, err := service.GetTenantSigningCA(context.Background(), "nonexistent-tenant")
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.NotNil(t, cert)
}

// ============================================================================
// ListTenantRoles/Users with custom pagination values
// ============================================================================

func TestListTenantRoles_WithCustomPagination(t *testing.T) {
	var capturedReq *db.ListRolesRequest
	service := &mockTenantService{
		listTenantRolesFunc: func(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
			capturedReq = req
			return &db.ListRolesResponse{Roles: []*db.Role{}, Total: 0}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/roles?page=3&page_size=50", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.ListTenantRoles(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 3, capturedReq.Page)
	assert.Equal(t, 50, capturedReq.PageSize)
	assert.Equal(t, "tenant-1", capturedReq.TenantID)
}

func TestListTenantUsers_WithCustomPagination(t *testing.T) {
	var capturedReq *db.ListUsersRequest
	service := &mockTenantService{
		listTenantUsersFunc: func(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
			capturedReq = req
			return &db.ListUsersResponse{Users: []*db.User{}, Total: 0}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/users?page=2&page_size=25", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = authenticated(req)
	w := httptest.NewRecorder()

	handlers.ListTenantUsers(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 2, capturedReq.Page)
	assert.Equal(t, 25, capturedReq.PageSize)
	assert.Equal(t, "tenant-1", capturedReq.TenantID)
}

// ============================================================================
// Tenant Service - RBAC with real qrdb (success paths via service calls)
// ============================================================================

func TestTenantService_ListTenantRoles_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	resp, err := service.ListTenantRoles(context.Background(), "tenant-1", &db.ListRolesRequest{
		TenantID: "tenant-1",
		Page:     1,
		PageSize: 20,
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestTenantService_ListTenantUsers_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	resp, err := service.ListTenantUsers(context.Background(), "tenant-1", &db.ListUsersRequest{
		TenantID: "tenant-1",
		Page:     1,
		PageSize: 20,
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestTenantService_GetTenantRole_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	// Create a role first, then get it
	role, err := service.CreateTenantRole(context.Background(), "tenant-1", &db.CreateRoleRequest{
		Name:     "testrole",
		TenantID: "tenant-1",
	})
	require.NoError(t, err)
	require.NotNil(t, role)

	retrieved, err := service.GetTenantRole(context.Background(), "tenant-1", role.ID)
	require.NoError(t, err)
	assert.Equal(t, role.ID, retrieved.ID)
}

func TestTenantService_UpdateTenantRole_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	role, err := service.CreateTenantRole(context.Background(), "tenant-1", &db.CreateRoleRequest{
		Name:     "old-name",
		TenantID: "tenant-1",
	})
	require.NoError(t, err)

	updated, err := service.UpdateTenantRole(context.Background(), "tenant-1", &db.UpdateRoleRequest{
		ID:   role.ID,
		Name: "new-name",
	})
	require.NoError(t, err)
	assert.Equal(t, "new-name", updated.Name)
}

func TestTenantService_DeleteTenantRole_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	role, err := service.CreateTenantRole(context.Background(), "tenant-1", &db.CreateRoleRequest{
		Name:     "to-delete",
		TenantID: "tenant-1",
	})
	require.NoError(t, err)

	err = service.DeleteTenantRole(context.Background(), "tenant-1", role.ID)
	require.NoError(t, err)
}

func TestTenantService_GetTenantUser_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	user, err := service.CreateTenantUser(context.Background(), "tenant-1", &db.CreateUserRequest{
		Username: "getme",
		TenantID: "tenant-1",
		Email:    "getme@example.com",
	})
	require.NoError(t, err)

	retrieved, err := service.GetTenantUser(context.Background(), "tenant-1", strconv.FormatUint(user.ID, 10))
	require.NoError(t, err)
	assert.Equal(t, user.ID, retrieved.ID)
}

func TestTenantService_UpdateTenantUser_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	user, err := service.CreateTenantUser(context.Background(), "tenant-1", &db.CreateUserRequest{
		Username: "old-user",
		TenantID: "tenant-1",
		Email:    "old-user@example.com",
	})
	require.NoError(t, err)

	updated, err := service.UpdateTenantUser(context.Background(), "tenant-1", &db.UpdateUserRequest{
		ID:       user.ID,
		Username: "new-user",
	})
	require.NoError(t, err)
	assert.Equal(t, "new-user", updated.Username)
}

func TestTenantService_DeleteTenantUser_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	user, err := service.CreateTenantUser(context.Background(), "tenant-1", &db.CreateUserRequest{
		Username: "deleteme",
		TenantID: "tenant-1",
		Email:    "deleteme@example.com",
	})
	require.NoError(t, err)

	err = service.DeleteTenantUser(context.Background(), "tenant-1", strconv.FormatUint(user.ID, 10))
	require.NoError(t, err)
}

// ============================================================================
// storeKeyAndCert additional coverage - ECDSA key branch
// ============================================================================

func TestCoverageBoost_StoreKeyAndCert_ECDSAKey(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	cert := makeTestCert(t, "ECDSA CA P384")

	err = service.storeKeyAndCert(context.Background(), "tenant-ec", "intermediate", key, cert)
	require.NoError(t, err)
}

// ============================================================================
// storeKeyAndCert with real CA infrastructure (keystore branch)
// ============================================================================

func TestCoverageBoost_StoreKeyAndCert_WithRealCA_RSA(t *testing.T) {
	testCA, _, cleanup := createTestInfrastructure(t)
	defer cleanup()

	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, testCA, nil, qrdbSvc, logger, "1.0.0")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := makeTestCert(t, "Tenant Root RSA CA")

	err = service.storeKeyAndCert(context.Background(), "tenant-real-rsa", "root", key, cert)
	require.NoError(t, err)
}

func TestCoverageBoost_StoreKeyAndCert_WithRealCA_ECDSA(t *testing.T) {
	testCA, _, cleanup := createTestInfrastructure(t)
	defer cleanup()

	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, testCA, nil, qrdbSvc, logger, "1.0.0")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := makeTestCert(t, "Tenant Root ECDSA CA")

	err = service.storeKeyAndCert(context.Background(), "tenant-real-ecdsa", "root", key, cert)
	require.NoError(t, err)
}

func TestCoverageBoost_StoreKeyAndCert_WithRealCA_Ed25519(t *testing.T) {
	testCA, _, cleanup := createTestInfrastructure(t)
	defer cleanup()

	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, testCA, nil, qrdbSvc, logger, "1.0.0")

	_, privKey, err := generateEd25519Key()
	require.NoError(t, err)
	cert := makeTestCert(t, "Tenant Root Ed25519 CA")

	err = service.storeKeyAndCert(context.Background(), "tenant-real-ed", "root", privKey, cert)
	require.NoError(t, err)
}

// ============================================================================
// service.go - ListOrders with specific account ID returning empty orders
// ============================================================================

func TestAdminService_ListOrders_SpecificAccountWithStatus(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{ID: 1, Status: "valid", CreatedAt: time.Now()}
	require.NoError(t, accountDAO.Save(ctx, account))

	orderDAO, err := service.storageFactory.OrderDAO(1)
	require.NoError(t, err)

	order1 := &entities.ACMEOrder{
		ID: 1, AccountID: 1, Status: "pending",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "a.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	order2 := &entities.ACMEOrder{
		ID: 2, AccountID: 1, Status: "valid",
		Identifiers: []entities.ACMEIdentifier{{Type: "dns", Value: "b.com"}},
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	require.NoError(t, orderDAO.Save(ctx, order1))
	require.NoError(t, orderDAO.Save(ctx, order2))

	// List orders for specific account with status filter
	req := ListOrdersRequest{Page: 1, PerPage: 10, AccountID: 1, Status: "pending"}
	orders, pagination, err := service.ListOrders(ctx, req)

	require.NoError(t, err)
	assert.Len(t, orders, 1)
	assert.Equal(t, 1, pagination.Total)
	assert.Equal(t, "pending", orders[0].Status)
}

// ============================================================================
// service.go - ListCertificates with ExpiresDays filter
// ============================================================================

func TestAdminService_ListCertificates_ExpiresDaysFilter(t *testing.T) {
	ctx := context.Background()
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	certDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Cert expiring in 10 days
	soonCert := createTestACMECertificate(t, 1, "soon.example.com", "valid")
	soonCert.ExpiresAt = time.Now().Add(10 * 24 * time.Hour)
	require.NoError(t, certDAO.Save(ctx, soonCert))

	// Cert expiring in 60 days
	laterCert := createTestACMECertificate(t, 2, "later.example.com", "valid")
	laterCert.ExpiresAt = time.Now().Add(60 * 24 * time.Hour)
	require.NoError(t, certDAO.Save(ctx, laterCert))

	// Only get certs expiring within 30 days
	req := ListCertificatesRequest{Page: 1, PerPage: 10, ExpiresDays: 30}
	certs, _, err := service.ListCertificates(ctx, req)

	require.NoError(t, err)
	assert.Len(t, certs, 1)
}
