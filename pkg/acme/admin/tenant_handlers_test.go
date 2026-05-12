//go:build codec_json

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
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
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// mockTenantService is a mock implementation of TenantService for testing
type mockTenantService struct {
	createTenantFunc                     func(ctx context.Context, req CreateTenantRequest) (*TenantInfo, error)
	getTenantFunc                        func(ctx context.Context, tenantID string) (*TenantInfo, error)
	updateTenantFunc                     func(ctx context.Context, tenantID string, req UpdateTenantRequest) (*TenantInfo, error)
	updateTenantStatusFunc               func(ctx context.Context, tenantID string, status string) error
	deleteTenantFunc                     func(ctx context.Context, tenantID string) error
	listTenantsFunc                      func(ctx context.Context, req ListTenantsRequest) ([]*TenantInfo, *Pagination, error)
	createTenantRootCAFunc               func(ctx context.Context, tenantID string, req CreateTenantRootCARequest) (*TenantRootCAInfo, error)
	createTenantIntermediateCAFunc       func(ctx context.Context, tenantID string, req CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error)
	getTenantIntermediateCAFunc          func(ctx context.Context, tenantID string, caID string) (*TenantIntCAInfo, error)
	listTenantIntermediateCAsFunc        func(ctx context.Context, tenantID string) ([]*TenantIntCAInfo, error)
	updateTenantIntermediateCAStatusFunc func(ctx context.Context, tenantID string, caID string, status string) error
	setTenantDefaultIntermediateCAFunc   func(ctx context.Context, tenantID string, caID string) error
	getTenantCAStatusFunc                func(ctx context.Context, tenantID string) (*TenantCAStatusInfo, error)
	createTenantEABFunc                  func(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error)
	getTenantEABFunc                     func(ctx context.Context, tenantID string, kid string) (*EABInfo, error)
	deleteTenantEABFunc                  func(ctx context.Context, tenantID string, kid string) error
	listTenantEABsFunc                   func(ctx context.Context, tenantID string, req ListEABRequest) ([]*EABInfo, *Pagination, error)
	createTenantRoleFunc                 func(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error)
	getTenantRoleFunc                    func(ctx context.Context, tenantID string, roleID string) (*db.Role, error)
	updateTenantRoleFunc                 func(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error)
	deleteTenantRoleFunc                 func(ctx context.Context, tenantID string, roleID string) error
	listTenantRolesFunc                  func(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error)
	createTenantUserFunc                 func(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error)
	getTenantUserFunc                    func(ctx context.Context, tenantID string, userID string) (*db.User, error)
	updateTenantUserFunc                 func(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error)
	deleteTenantUserFunc                 func(ctx context.Context, tenantID string, userID string) error
	listTenantUsersFunc                  func(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error)
}

func (m *mockTenantService) CreateTenant(ctx context.Context, req CreateTenantRequest) (*TenantInfo, error) {
	if m.createTenantFunc != nil {
		return m.createTenantFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockTenantService) GetTenant(ctx context.Context, tenantID string) (*TenantInfo, error) {
	if m.getTenantFunc != nil {
		return m.getTenantFunc(ctx, tenantID)
	}
	return nil, nil
}

func (m *mockTenantService) UpdateTenant(ctx context.Context, tenantID string, req UpdateTenantRequest) (*TenantInfo, error) {
	if m.updateTenantFunc != nil {
		return m.updateTenantFunc(ctx, tenantID, req)
	}
	return nil, nil
}

func (m *mockTenantService) UpdateTenantStatus(ctx context.Context, tenantID string, status string) error {
	if m.updateTenantStatusFunc != nil {
		return m.updateTenantStatusFunc(ctx, tenantID, status)
	}
	return nil
}

func (m *mockTenantService) DeleteTenant(ctx context.Context, tenantID string) error {
	if m.deleteTenantFunc != nil {
		return m.deleteTenantFunc(ctx, tenantID)
	}
	return nil
}

func (m *mockTenantService) ListTenants(ctx context.Context, req ListTenantsRequest) ([]*TenantInfo, *Pagination, error) {
	if m.listTenantsFunc != nil {
		return m.listTenantsFunc(ctx, req)
	}
	return nil, nil, nil
}

func (m *mockTenantService) CreateTenantRootCA(ctx context.Context, tenantID string, req CreateTenantRootCARequest) (*TenantRootCAInfo, error) {
	if m.createTenantRootCAFunc != nil {
		return m.createTenantRootCAFunc(ctx, tenantID, req)
	}
	return nil, nil
}

func (m *mockTenantService) CreateTenantIntermediateCA(ctx context.Context, tenantID string, req CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error) {
	if m.createTenantIntermediateCAFunc != nil {
		return m.createTenantIntermediateCAFunc(ctx, tenantID, req)
	}
	return nil, nil
}

func (m *mockTenantService) GetTenantIntermediateCA(ctx context.Context, tenantID string, caID string) (*TenantIntCAInfo, error) {
	if m.getTenantIntermediateCAFunc != nil {
		return m.getTenantIntermediateCAFunc(ctx, tenantID, caID)
	}
	return nil, nil
}

func (m *mockTenantService) ListTenantIntermediateCAs(ctx context.Context, tenantID string) ([]*TenantIntCAInfo, error) {
	if m.listTenantIntermediateCAsFunc != nil {
		return m.listTenantIntermediateCAsFunc(ctx, tenantID)
	}
	return nil, nil
}

func (m *mockTenantService) UpdateTenantIntermediateCAStatus(ctx context.Context, tenantID string, caID string, status string) error {
	if m.updateTenantIntermediateCAStatusFunc != nil {
		return m.updateTenantIntermediateCAStatusFunc(ctx, tenantID, caID, status)
	}
	return nil
}

func (m *mockTenantService) SetTenantDefaultIntermediateCA(ctx context.Context, tenantID string, caID string) error {
	if m.setTenantDefaultIntermediateCAFunc != nil {
		return m.setTenantDefaultIntermediateCAFunc(ctx, tenantID, caID)
	}
	return nil
}

func (m *mockTenantService) GetTenantCAStatus(ctx context.Context, tenantID string) (*TenantCAStatusInfo, error) {
	if m.getTenantCAStatusFunc != nil {
		return m.getTenantCAStatusFunc(ctx, tenantID)
	}
	return nil, nil
}

func (m *mockTenantService) CreateTenantEAB(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error) {
	if m.createTenantEABFunc != nil {
		return m.createTenantEABFunc(ctx, tenantID, req)
	}
	return nil, nil
}

func (m *mockTenantService) GetTenantEAB(ctx context.Context, tenantID string, kid string) (*EABInfo, error) {
	if m.getTenantEABFunc != nil {
		return m.getTenantEABFunc(ctx, tenantID, kid)
	}
	return nil, nil
}

func (m *mockTenantService) DeleteTenantEAB(ctx context.Context, tenantID string, kid string) error {
	if m.deleteTenantEABFunc != nil {
		return m.deleteTenantEABFunc(ctx, tenantID, kid)
	}
	return nil
}

func (m *mockTenantService) ListTenantEABs(ctx context.Context, tenantID string, req ListEABRequest) ([]*EABInfo, *Pagination, error) {
	if m.listTenantEABsFunc != nil {
		return m.listTenantEABsFunc(ctx, tenantID, req)
	}
	return nil, nil, nil
}

func (m *mockTenantService) CreateTenantRole(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error) {
	if m.createTenantRoleFunc != nil {
		return m.createTenantRoleFunc(ctx, tenantID, req)
	}
	return nil, nil
}

func (m *mockTenantService) GetTenantRole(ctx context.Context, tenantID string, roleID string) (*db.Role, error) {
	if m.getTenantRoleFunc != nil {
		return m.getTenantRoleFunc(ctx, tenantID, roleID)
	}
	return nil, nil
}

func (m *mockTenantService) UpdateTenantRole(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error) {
	if m.updateTenantRoleFunc != nil {
		return m.updateTenantRoleFunc(ctx, tenantID, req)
	}
	return nil, nil
}

func (m *mockTenantService) DeleteTenantRole(ctx context.Context, tenantID string, roleID string) error {
	if m.deleteTenantRoleFunc != nil {
		return m.deleteTenantRoleFunc(ctx, tenantID, roleID)
	}
	return nil
}

func (m *mockTenantService) ListTenantRoles(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
	if m.listTenantRolesFunc != nil {
		return m.listTenantRolesFunc(ctx, tenantID, req)
	}
	return nil, nil
}

func (m *mockTenantService) CreateTenantUser(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error) {
	if m.createTenantUserFunc != nil {
		return m.createTenantUserFunc(ctx, tenantID, req)
	}
	return nil, nil
}

func (m *mockTenantService) GetTenantUser(ctx context.Context, tenantID string, userID string) (*db.User, error) {
	if m.getTenantUserFunc != nil {
		return m.getTenantUserFunc(ctx, tenantID, userID)
	}
	return nil, nil
}

func (m *mockTenantService) UpdateTenantUser(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error) {
	if m.updateTenantUserFunc != nil {
		return m.updateTenantUserFunc(ctx, tenantID, req)
	}
	return nil, nil
}

func (m *mockTenantService) DeleteTenantUser(ctx context.Context, tenantID string, userID string) error {
	if m.deleteTenantUserFunc != nil {
		return m.deleteTenantUserFunc(ctx, tenantID, userID)
	}
	return nil
}

func (m *mockTenantService) ListTenantUsers(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
	if m.listTenantUsersFunc != nil {
		return m.listTenantUsersFunc(ctx, tenantID, req)
	}
	return nil, nil
}

func TestNewTenantHandlers(t *testing.T) {
	service := &mockTenantService{}
	logger := slog.Default()

	handlers := NewTenantHandlers(service, logger)

	if handlers == nil {
		t.Fatal("expected non-nil handlers")
	}
	if handlers.service != service {
		t.Error("service not set correctly")
	}
	if handlers.logger != logger {
		t.Error("logger not set correctly")
	}
}

func TestCreateTenant_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		createTenantFunc: func(ctx context.Context, req CreateTenantRequest) (*TenantInfo, error) {
			return &TenantInfo{
				ID:        req.ID,
				Name:      req.Name,
				Status:    "active",
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"id": "tenant-1", "name": "Test Tenant"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CreateTenant(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp TenantInfo
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ID == "" {
		t.Error("expected tenant ID in response")
	}

}

func TestCreateTenant_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("POST", "/api/v1/tenants", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()

	handlers.CreateTenant(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateTenant_AutoGenerateID(t *testing.T) {
	var capturedReq CreateTenantRequest
	mockService := &mockTenantService{
		createTenantFunc: func(ctx context.Context, req CreateTenantRequest) (*TenantInfo, error) {
			capturedReq = req
			return &TenantInfo{
				ID:        req.ID, // This should be auto-generated by the handler
				Name:      req.Name,
				Status:    "active",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}, nil
		},
	}
	handlers := NewTenantHandlers(mockService, slog.Default())

	// When ID is not provided, the handler auto-generates one
	body := `{"name": "Test Tenant"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	handlers.CreateTenant(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	// Verify the handler auto-generated an ID before calling the service
	if capturedReq.ID == "" {
		t.Error("expected handler to auto-generate ID before calling service")
	}

	// Auto-generated IDs should start with "tenant-"
	if !strings.HasPrefix(capturedReq.ID, "tenant-") {
		t.Errorf("expected auto-generated ID to start with 'tenant-', got %s", capturedReq.ID)
	}
}

func TestCreateTenant_MissingName(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"id": "tenant-1"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	handlers.CreateTenant(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateTenant_AlreadyExists(t *testing.T) {
	service := &mockTenantService{
		createTenantFunc: func(ctx context.Context, req CreateTenantRequest) (*TenantInfo, error) {
			return nil, ErrTenantAlreadyExists
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"id": "tenant-1", "name": "Test Tenant"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	handlers.CreateTenant(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d", http.StatusConflict, w.Code)
	}
}

func TestGetTenant_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		getTenantFunc: func(ctx context.Context, tenantID string) (*TenantInfo, error) {
			return &TenantInfo{
				ID:        tenantID,
				Name:      "Test Tenant",
				Status:    "active",
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenant(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestGetTenant_NotFound(t *testing.T) {
	service := &mockTenantService{
		getTenantFunc: func(ctx context.Context, tenantID string) (*TenantInfo, error) {
			return nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	req = addUserToRequest(req, createSuperAdminUser())
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.GetTenant(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestUpdateTenant_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		updateTenantFunc: func(ctx context.Context, tenantID string, req UpdateTenantRequest) (*TenantInfo, error) {
			return &TenantInfo{
				ID:        tenantID,
				Name:      req.Name,
				Status:    "active",
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"name": "Updated Tenant"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenant(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestUpdateTenant_NotFound(t *testing.T) {
	service := &mockTenantService{
		updateTenantFunc: func(ctx context.Context, tenantID string, req UpdateTenantRequest) (*TenantInfo, error) {
			return nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"name": "Updated Tenant"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/nonexistent", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	req = addUserToRequest(req, createSuperAdminUser())
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.UpdateTenant(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestUpdateTenant_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `invalid json`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenant(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestUpdateTenant_InternalError(t *testing.T) {
	service := &mockTenantService{
		updateTenantFunc: func(ctx context.Context, tenantID string, req UpdateTenantRequest) (*TenantInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"name": "Updated Tenant"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenant(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestUpdateTenantStatus_Success(t *testing.T) {
	service := &mockTenantService{
		updateTenantStatusFunc: func(ctx context.Context, tenantID string, status string) error {
			return nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"status": "suspended"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestUpdateTenantStatus_InvalidStatus(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"status": "invalid"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantStatus(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestUpdateTenantStatus_MissingStatus(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantStatus(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestUpdateTenantStatus_NotFound(t *testing.T) {
	service := &mockTenantService{
		updateTenantStatusFunc: func(ctx context.Context, tenantID string, status string) error {
			return ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"status": "suspended"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/nonexistent/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	req = addUserToRequest(req, createSuperAdminUser())
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.UpdateTenantStatus(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestUpdateTenantStatus_InternalError(t *testing.T) {
	service := &mockTenantService{
		updateTenantStatusFunc: func(ctx context.Context, tenantID string, status string) error {
			return errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"status": "suspended"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantStatus(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestUpdateTenantStatus_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `invalid json`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantStatus(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDeleteTenant_Success(t *testing.T) {
	service := &mockTenantService{
		deleteTenantFunc: func(ctx context.Context, tenantID string) error {
			return nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.DeleteTenant(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDeleteTenant_NotFound(t *testing.T) {
	service := &mockTenantService{
		deleteTenantFunc: func(ctx context.Context, tenantID string) error {
			return ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	req = addUserToRequest(req, createSuperAdminUser())
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.DeleteTenant(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestGetTenant_InternalError(t *testing.T) {
	service := &mockTenantService{
		getTenantFunc: func(ctx context.Context, tenantID string) (*TenantInfo, error) {
			return nil, errors.New("database connection failed")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenant(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestDeleteTenant_InternalError(t *testing.T) {
	service := &mockTenantService{
		deleteTenantFunc: func(ctx context.Context, tenantID string) error {
			return errors.New("database connection failed")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.DeleteTenant(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestListTenants_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		listTenantsFunc: func(ctx context.Context, req ListTenantsRequest) ([]*TenantInfo, *Pagination, error) {
			return []*TenantInfo{
				{ID: "tenant-1", Name: "Tenant 1", Status: "active", CreatedAt: now, UpdatedAt: now},
				{ID: "tenant-2", Name: "Tenant 2", Status: "active", CreatedAt: now, UpdatedAt: now},
			}, &Pagination{Page: 1, PerPage: 20, Total: 2}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	w := httptest.NewRecorder()

	handlers.ListTenants(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp ListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Total < 0 {
		t.Error("expected valid total in response")
	}

}

func TestListTenants_InternalError(t *testing.T) {
	service := &mockTenantService{
		listTenantsFunc: func(ctx context.Context, req ListTenantsRequest) ([]*TenantInfo, *Pagination, error) {
			return nil, nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	w := httptest.NewRecorder()

	handlers.ListTenants(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestListTenants_WithFilters(t *testing.T) {
	var capturedReq ListTenantsRequest
	service := &mockTenantService{
		listTenantsFunc: func(ctx context.Context, req ListTenantsRequest) ([]*TenantInfo, *Pagination, error) {
			capturedReq = req
			return []*TenantInfo{}, &Pagination{Page: 2, PerPage: 10, Total: 0}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants?page=2&per_page=10&status=active", nil)
	w := httptest.NewRecorder()

	handlers.ListTenants(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	if capturedReq.Page != 2 {
		t.Errorf("expected page 2, got %d", capturedReq.Page)
	}
	if capturedReq.PerPage != 10 {
		t.Errorf("expected per_page 10, got %d", capturedReq.PerPage)
	}
	if capturedReq.Status != "active" {
		t.Errorf("expected status 'active', got '%s'", capturedReq.Status)
	}
}

func TestCreateTenantRootCA_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		createTenantRootCAFunc: func(ctx context.Context, tenantID string, req CreateTenantRootCARequest) (*TenantRootCAInfo, error) {
			return &TenantRootCAInfo{
				CommonName:   req.CommonName,
				KeyAlgorithm: req.KeyAlgorithm,
				NotBefore:    now,
				NotAfter:     now.AddDate(req.ValidityYears, 0, 0),
				Status:       "active",
				CreatedAt:    now,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"common_name": "Tenant Root CA", "key_algorithm": "EC-P384", "validity_years": 10}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/root-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantRootCA(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}
}

func TestCreateTenantRootCA_MissingCommonName(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"key_algorithm": "EC-P384", "validity_years": 10}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/root-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantRootCA(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateTenantRootCA_InvalidValidity(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"common_name": "Tenant Root CA", "key_algorithm": "EC-P384", "validity_years": 0}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/root-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantRootCA(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateTenantIntermediateCA_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		createTenantIntermediateCAFunc: func(ctx context.Context, tenantID string, req CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error) {
			return &TenantIntCAInfo{
				CommonName:   req.CommonName,
				ParentType:   req.ParentType,
				KeyAlgorithm: req.KeyAlgorithm,
				NotBefore:    now,
				NotAfter:     now.AddDate(req.ValidityYears, 0, 0),
				Status:       "active",
				CreatedAt:    now,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"common_name": "Tenant Int CA", "parent_type": "global", "key_algorithm": "EC-P384", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}
}

func TestCreateTenantIntermediateCA_InvalidParentType(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"common_name": "Tenant Int CA", "parent_type": "invalid", "key_algorithm": "EC-P384", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateTenantIntermediateCA_DefaultParentType(t *testing.T) {
	now := time.Now()
	var capturedReq CreateTenantIntermediateCARequest
	service := &mockTenantService{
		createTenantIntermediateCAFunc: func(ctx context.Context, tenantID string, req CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error) {
			capturedReq = req
			return &TenantIntCAInfo{
				CommonName:   req.CommonName,
				ParentType:   req.ParentType,
				KeyAlgorithm: req.KeyAlgorithm,
				NotBefore:    now,
				NotAfter:     now.AddDate(req.ValidityYears, 0, 0),
				Status:       "active",
				CreatedAt:    now,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	// Don't specify parent_type - should default to "global"
	body := `{"common_name": "Tenant Int CA", "key_algorithm": "EC-P384", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}
	if capturedReq.ParentType != "global" {
		t.Errorf("expected parent_type to default to 'global', got %s", capturedReq.ParentType)
	}
}

func TestGetTenantCAStatus_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		getTenantCAStatusFunc: func(ctx context.Context, tenantID string) (*TenantCAStatusInfo, error) {
			return &TenantCAStatusInfo{
				TenantID:                tenantID,
				CanIssueCerts:           true,
				ActiveCACount:           1,
				DefaultIntermediateCAID: "ca-1",
				IntermediateCAs: []*TenantIntCAInfo{
					{
						ID:           "ca-1",
						CommonName:   "Tenant Int CA",
						ParentType:   "global",
						Purpose:      "general",
						KeyAlgorithm: "EC-P384",
						NotBefore:    now,
						NotAfter:     now.AddDate(5, 0, 0),
						Status:       "active",
						CreatedAt:    now,
					},
				},
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/ca-status", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantCAStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestListTenantIntermediateCAs_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		listTenantIntermediateCAsFunc: func(ctx context.Context, tenantID string) ([]*TenantIntCAInfo, error) {
			return []*TenantIntCAInfo{
				{ID: "ca-1", CommonName: "CA 1", Status: "active", Purpose: "general", CreatedAt: now},
				{ID: "ca-2", CommonName: "CA 2", Status: "active", Purpose: "server-auth", CreatedAt: now},
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.ListTenantIntermediateCAs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestGetTenantIntermediateCA_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		getTenantIntermediateCAFunc: func(ctx context.Context, tenantID string, caID string) (*TenantIntCAInfo, error) {
			return &TenantIntCAInfo{
				ID:           caID,
				CommonName:   "Test CA",
				Status:       "active",
				Purpose:      "general",
				KeyAlgorithm: "EC-P384",
				CreatedAt:    now,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantIntermediateCA(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestGetTenantIntermediateCA_NotFound(t *testing.T) {
	service := &mockTenantService{
		getTenantIntermediateCAFunc: func(ctx context.Context, tenantID string, caID string) (*TenantIntCAInfo, error) {
			return nil, ErrTenantCANotConfigured
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "nonexistent"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantIntermediateCA(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestUpdateTenantIntermediateCAStatus_Success(t *testing.T) {
	service := &mockTenantService{
		updateTenantIntermediateCAStatusFunc: func(ctx context.Context, tenantID string, caID string, status string) error {
			return nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"status": "pending-rotation"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestUpdateTenantIntermediateCAStatus_InvalidStatus(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"status": "invalid"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestSetTenantDefaultIntermediateCA_Success(t *testing.T) {
	service := &mockTenantService{
		setTenantDefaultIntermediateCAFunc: func(ctx context.Context, tenantID string, caID string) error {
			return nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"intermediate_ca_id": "ca-2"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestSetTenantDefaultIntermediateCA_MissingCAID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestSetTenantDefaultIntermediateCA_CANotFound(t *testing.T) {
	service := &mockTenantService{
		setTenantDefaultIntermediateCAFunc: func(ctx context.Context, tenantID string, caID string) error {
			return ErrTenantCANotConfigured
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"intermediate_ca_id": "nonexistent"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestCreateTenantEAB_Success(t *testing.T) {
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	service := &mockTenantService{
		createTenantEABFunc: func(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error) {
			return &CreateEABResponse{
				ID:        "eab-123",
				MACKey:    "dGVzdC1tYWMta2V5LWJhc2U2NA",
				Algorithm: "HS256",
				ExpiresAt: &expiresAt,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"purpose": "endorse-01", "expires_in_days": 30}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}
}

func TestCreateTenantEAB_InvalidPurpose(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"purpose": "invalid-purpose"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateTenantEAB_DefaultPurpose(t *testing.T) {
	var capturedReq CreateEABRequest
	service := &mockTenantService{
		createTenantEABFunc: func(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error) {
			capturedReq = req
			return &CreateEABResponse{
				ID:        "eab-123",
				MACKey:    "dGVzdC1tYWMta2V5LWJhc2U2NA",
				Algorithm: "HS256",
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	// Don't specify purpose - should default to "account-binding"
	body := `{}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}
	if capturedReq.Purpose != "account-binding" {
		t.Errorf("expected purpose to default to 'account-binding', got %s", capturedReq.Purpose)
	}
}

func TestGetTenantEAB_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		getTenantEABFunc: func(ctx context.Context, tenantID string, kid string) (*EABInfo, error) {
			return &EABInfo{
				ID:        kid,
				TenantID:  tenantID,
				Status:    "active",
				Purpose:   "account-binding",
				CreatedAt: now,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/eab/eab-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "kid": "eab-123"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantEAB(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestGetTenantEAB_NotFound(t *testing.T) {
	service := &mockTenantService{
		getTenantEABFunc: func(ctx context.Context, tenantID string, kid string) (*EABInfo, error) {
			return nil, ErrEABNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/eab/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "kid": "nonexistent"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantEAB(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDeleteTenantEAB_Success(t *testing.T) {
	service := &mockTenantService{
		deleteTenantEABFunc: func(ctx context.Context, tenantID string, kid string) error {
			return nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1/eab/eab-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "kid": "eab-123"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.DeleteTenantEAB(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestListTenantEABs_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		listTenantEABsFunc: func(ctx context.Context, tenantID string, req ListEABRequest) ([]*EABInfo, *Pagination, error) {
			return []*EABInfo{
				{ID: "eab-1", TenantID: tenantID, Status: "active", Purpose: "account-binding", CreatedAt: now},
				{ID: "eab-2", TenantID: tenantID, Status: "active", Purpose: "endorse-01", CreatedAt: now},
			}, &Pagination{Page: 1, PerPage: 20, Total: 2}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/eab", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.ListTenantEABs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestListTenantEABs_WithFilters(t *testing.T) {
	var capturedReq ListEABRequest
	service := &mockTenantService{
		listTenantEABsFunc: func(ctx context.Context, tenantID string, req ListEABRequest) ([]*EABInfo, *Pagination, error) {
			capturedReq = req
			return []*EABInfo{}, &Pagination{Page: 2, PerPage: 10, Total: 0}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/eab?page=2&per_page=10&status=active&purpose=endorse-01", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.ListTenantEABs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	if capturedReq.Page != 2 {
		t.Errorf("expected page 2, got %d", capturedReq.Page)
	}
	if capturedReq.PerPage != 10 {
		t.Errorf("expected per_page 10, got %d", capturedReq.PerPage)
	}
	if capturedReq.Status != "active" {
		t.Errorf("expected status 'active', got %s", capturedReq.Status)
	}
	if capturedReq.Purpose != "endorse-01" {
		t.Errorf("expected purpose 'endorse-01', got %s", capturedReq.Purpose)
	}
}

func TestTenantHandlers_RegisterRoutes(t *testing.T) {
	service := &mockTenantService{}
	handlers := NewTenantHandlers(service, slog.Default())

	router := mux.NewRouter()
	authMiddleware := newTestAuthMiddleware(RoleSuperAdmin)

	handlers.RegisterRoutes(router, authMiddleware)

	// Verify routes were registered by checking the router can match them
	testCases := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/tenants"},
		{"POST", "/api/v1/tenants"},
		{"GET", "/api/v1/tenants/test-tenant"},
		{"PUT", "/api/v1/tenants/test-tenant"},
		{"DELETE", "/api/v1/tenants/test-tenant"},
		{"PUT", "/api/v1/tenants/test-tenant/status"},
		{"POST", "/api/v1/tenants/test-tenant/root-ca"},
		{"GET", "/api/v1/tenants/test-tenant/intermediate-cas"},
		{"POST", "/api/v1/tenants/test-tenant/intermediate-cas"},
		{"GET", "/api/v1/tenants/test-tenant/intermediate-cas/ca-1"},
		{"PUT", "/api/v1/tenants/test-tenant/intermediate-cas/ca-1/status"},
		{"PUT", "/api/v1/tenants/test-tenant/default-intermediate-ca"},
		{"GET", "/api/v1/tenants/test-tenant/ca-status"},
		{"GET", "/api/v1/tenants/test-tenant/eab"},
		{"POST", "/api/v1/tenants/test-tenant/eab"},
		{"GET", "/api/v1/tenants/test-tenant/eab/eab-123"},
		{"DELETE", "/api/v1/tenants/test-tenant/eab/eab-123"},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		var match mux.RouteMatch
		if !router.Match(req, &match) {
			t.Errorf("expected route to match: %s %s", tc.method, tc.path)
		}
	}
}

// Additional coverage tests for tenant handlers

func TestCreateTenantIntermediateCA_MissingCommonName(t *testing.T) {
	service := &mockTenantService{}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"keyAlgorithm": "RSA-2048", "validityYears": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateTenantIntermediateCA_MissingKeyAlgorithm(t *testing.T) {
	service := &mockTenantService{}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"commonName": "Test CA", "validityYears": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateTenantIntermediateCA_InvalidParentType_Coverage(t *testing.T) {
	service := &mockTenantService{}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"commonName": "Test CA", "keyAlgorithm": "RSA-2048", "validityYears": 5, "parentType": "invalid"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateTenantIntermediateCA_InvalidValidity_Coverage(t *testing.T) {
	service := &mockTenantService{}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"commonName": "Test CA", "keyAlgorithm": "RSA-2048", "validityYears": 0}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateTenantIntermediateCA_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		createTenantIntermediateCAFunc: func(ctx context.Context, tenantID string, req CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error) {
			return nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"common_name": "Test CA", "key_algorithm": "RSA-2048", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestCreateTenantIntermediateCA_InternalError(t *testing.T) {
	service := &mockTenantService{
		createTenantIntermediateCAFunc: func(ctx context.Context, tenantID string, req CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"common_name": "Test CA", "key_algorithm": "RSA-2048", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestGetTenantIntermediateCA_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		getTenantIntermediateCAFunc: func(ctx context.Context, tenantID, caID string) (*TenantIntCAInfo, error) {
			return nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantIntermediateCA(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestGetTenantIntermediateCA_CANotFound(t *testing.T) {
	service := &mockTenantService{
		getTenantIntermediateCAFunc: func(ctx context.Context, tenantID, caID string) (*TenantIntCAInfo, error) {
			return nil, ErrTenantCANotConfigured
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantIntermediateCA(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestGetTenantIntermediateCA_InternalError(t *testing.T) {
	service := &mockTenantService{
		getTenantIntermediateCAFunc: func(ctx context.Context, tenantID, caID string) (*TenantIntCAInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantIntermediateCA(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestGetTenantCAStatus_InternalError(t *testing.T) {
	service := &mockTenantService{
		getTenantCAStatusFunc: func(ctx context.Context, tenantID string) (*TenantCAStatusInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/ca-status", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantCAStatus(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestListTenantIntermediateCAs_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		listTenantIntermediateCAsFunc: func(ctx context.Context, tenantID string) ([]*TenantIntCAInfo, error) {
			return nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.ListTenantIntermediateCAs(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestListTenantIntermediateCAs_InternalError(t *testing.T) {
	service := &mockTenantService{
		listTenantIntermediateCAsFunc: func(ctx context.Context, tenantID string) ([]*TenantIntCAInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.ListTenantIntermediateCAs(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestUpdateTenantIntermediateCAStatus_Coverage_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		updateTenantIntermediateCAStatusFunc: func(ctx context.Context, tenantID, caID, status string) error {
			return ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"status": "active"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestUpdateTenantIntermediateCAStatus_Coverage_CANotFound(t *testing.T) {
	service := &mockTenantService{
		updateTenantIntermediateCAStatusFunc: func(ctx context.Context, tenantID, caID, status string) error {
			return ErrTenantCANotConfigured
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"status": "active"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestSetTenantDefaultIntermediateCA_Coverage_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		setTenantDefaultIntermediateCAFunc: func(ctx context.Context, tenantID, caID string) error {
			return ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"intermediate_ca_id": "ca-1"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestSetTenantDefaultIntermediateCA_CANotFound_Coverage(t *testing.T) {
	service := &mockTenantService{
		setTenantDefaultIntermediateCAFunc: func(ctx context.Context, tenantID, caID string) error {
			return ErrTenantCANotConfigured
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"intermediate_ca_id": "ca-1"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestCreateTenantEAB_TenantNotFound_Coverage(t *testing.T) {
	service := &mockTenantService{
		createTenantEABFunc: func(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error) {
			return nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"purpose": "account-binding"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestCreateTenantEAB_InternalError(t *testing.T) {
	service := &mockTenantService{
		createTenantEABFunc: func(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"purpose": "account-binding"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestNewTenantHandlers_WithService(t *testing.T) {
	service := &mockTenantService{}
	handlers := NewTenantHandlers(service, slog.Default())

	if handlers == nil {
		t.Fatal("expected non-nil handlers")
	}
	if handlers.service == nil {
		t.Error("expected non-nil service")
	}
}
