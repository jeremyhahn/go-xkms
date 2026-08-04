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
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

// Test EAB unauthorized and forbidden paths

func TestGetTenantEABHandler_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/eab/kid-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "kid": "kid-123"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.GetTenantEAB(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetTenantEABHandler_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/other-tenant/eab/kid-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant", "kid": "kid-123"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.GetTenantEAB(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGetTenantEABHandler_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		getTenantEABFunc: func(ctx context.Context, tenantID, kid string) (*EABInfo, error) {
			return nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/nonexistent/eab/kid-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent", "kid": "kid-123"})
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.GetTenantEAB(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetTenantEABHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		getTenantEABFunc: func(ctx context.Context, tenantID, kid string) (*EABInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/eab/kid-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "kid": "kid-123"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantEAB(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteTenantEABHandler_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1/eab/kid-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "kid": "kid-123"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.DeleteTenantEAB(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteTenantEABHandler_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/other-tenant/eab/kid-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant", "kid": "kid-123"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.DeleteTenantEAB(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDeleteTenantEABHandler_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		deleteTenantEABFunc: func(ctx context.Context, tenantID, kid string) error {
			return ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/nonexistent/eab/kid-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent", "kid": "kid-123"})
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.DeleteTenantEAB(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteTenantEABHandler_EABNotFound(t *testing.T) {
	service := &mockTenantService{
		deleteTenantEABFunc: func(ctx context.Context, tenantID, kid string) error {
			return ErrEABNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1/eab/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "kid": "nonexistent"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.DeleteTenantEAB(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteTenantEABHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		deleteTenantEABFunc: func(ctx context.Context, tenantID, kid string) error {
			return errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1/eab/kid-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "kid": "kid-123"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.DeleteTenantEAB(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListTenantEABsHandler_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/eab", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.ListTenantEABs(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListTenantEABsHandler_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/other-tenant/eab", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.ListTenantEABs(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestListTenantEABsHandler_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		listTenantEABsFunc: func(ctx context.Context, tenantID string, req ListEABRequest) ([]*EABInfo, *Pagination, error) {
			return nil, nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/nonexistent/eab", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.ListTenantEABs(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListTenantEABsHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		listTenantEABsFunc: func(ctx context.Context, tenantID string, req ListEABRequest) ([]*EABInfo, *Pagination, error) {
			return nil, nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/eab", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.ListTenantEABs(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListTenantEABsHandler_WithFilters(t *testing.T) {
	var capturedReq ListEABRequest
	service := &mockTenantService{
		listTenantEABsFunc: func(ctx context.Context, tenantID string, req ListEABRequest) ([]*EABInfo, *Pagination, error) {
			capturedReq = req
			return []*EABInfo{}, &Pagination{Page: 1, PerPage: 10, Total: 0}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/eab?page=2&per_page=10&status=active&purpose=endorse-01", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.ListTenantEABs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 2, capturedReq.Page)
	assert.Equal(t, 10, capturedReq.PerPage)
	assert.Equal(t, "active", capturedReq.Status)
	assert.Equal(t, "endorse-01", capturedReq.Purpose)
}

// Test Root CA creation paths

func TestCreateTenantRootCAHandler_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/root-ca", bytes.NewBufferString("{}"))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.CreateTenantRootCA(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateTenantRootCAHandler_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("POST", "/api/v1/tenants/other-tenant/root-ca", bytes.NewBufferString("{}"))
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.CreateTenantRootCA(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCreateTenantRootCAHandler_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/root-ca", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantRootCA(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateTenantRootCAHandler_MissingCommonName(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"key_algorithm": "RSA-2048"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/root-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantRootCA(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateTenantRootCAHandler_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		createTenantRootCAFunc: func(ctx context.Context, tenantID string, req CreateTenantRootCARequest) (*TenantRootCAInfo, error) {
			return nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"common_name": "Test Root CA", "key_algorithm": "RSA-2048", "validity_years": 10}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/nonexistent/root-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.CreateTenantRootCA(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCreateTenantRootCAHandler_AlreadyExists(t *testing.T) {
	service := &mockTenantService{
		createTenantRootCAFunc: func(ctx context.Context, tenantID string, req CreateTenantRootCARequest) (*TenantRootCAInfo, error) {
			return nil, ErrTenantRootCAExists
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"common_name": "Test Root CA", "key_algorithm": "RSA-2048", "validity_years": 10}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/root-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantRootCA(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestCreateTenantRootCAHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		createTenantRootCAFunc: func(ctx context.Context, tenantID string, req CreateTenantRootCARequest) (*TenantRootCAInfo, error) {
			return nil, errors.New("internal error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"common_name": "Test Root CA", "key_algorithm": "RSA-2048", "validity_years": 10}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/root-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantRootCA(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateTenantRootCAHandler_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		createTenantRootCAFunc: func(ctx context.Context, tenantID string, req CreateTenantRootCARequest) (*TenantRootCAInfo, error) {
			return &TenantRootCAInfo{
				CommonName:   req.CommonName,
				KeyAlgorithm: req.KeyAlgorithm,
				Status:       "active",
				NotBefore:    now,
				NotAfter:     now.AddDate(10, 0, 0),
				CreatedAt:    now,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"common_name": "Test Root CA", "key_algorithm": "RSA-2048", "validity_years": 10}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/root-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantRootCA(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

// Test CA status paths

func TestGetTenantCAStatusHandler_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/ca-status", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.GetTenantCAStatus(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetTenantCAStatusHandler_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/other-tenant/ca-status", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.GetTenantCAStatus(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGetTenantCAStatusHandler_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		getTenantCAStatusFunc: func(ctx context.Context, tenantID string) (*TenantCAStatusInfo, error) {
			return nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/nonexistent/ca-status", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.GetTenantCAStatus(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetTenantCAStatusHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		getTenantCAStatusFunc: func(ctx context.Context, tenantID string) (*TenantCAStatusInfo, error) {
			return nil, errors.New("internal error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/ca-status", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantCAStatus(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetTenantCAStatusHandler_Success(t *testing.T) {
	service := &mockTenantService{
		getTenantCAStatusFunc: func(ctx context.Context, tenantID string) (*TenantCAStatusInfo, error) {
			return &TenantCAStatusInfo{
				TenantID:      tenantID,
				ActiveCACount: 2,
				CanIssueCerts: true,
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/ca-status", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.GetTenantCAStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// Test intermediate CA status update paths

func TestUpdateTenantIntermediateCAStatusHandler_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"status": "active"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUpdateTenantIntermediateCAStatusHandler_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"status": "active"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/other-tenant/intermediate-cas/ca-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestUpdateTenantIntermediateCAStatusHandler_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1/status", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateTenantIntermediateCAStatusHandler_MissingStatus(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateTenantIntermediateCAStatusHandler_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		updateTenantIntermediateCAStatusFunc: func(ctx context.Context, tenantID, caID, status string) error {
			return ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"status": "active"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/nonexistent/intermediate-cas/ca-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent", "caid": "ca-1"})
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateTenantIntermediateCAStatusHandler_CANotFound(t *testing.T) {
	service := &mockTenantService{
		updateTenantIntermediateCAStatusFunc: func(ctx context.Context, tenantID, caID, status string) error {
			return ErrTenantCANotConfigured
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"status": "active"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/intermediate-cas/nonexistent/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "nonexistent"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateTenantIntermediateCAStatusHandler_Success(t *testing.T) {
	service := &mockTenantService{
		updateTenantIntermediateCAStatusFunc: func(ctx context.Context, tenantID, caID, status string) error {
			return nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"status": "active"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateTenantIntermediateCAStatusHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		updateTenantIntermediateCAStatusFunc: func(ctx context.Context, tenantID, caID, status string) error {
			return errors.New("internal error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"status": "active"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1/status", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.UpdateTenantIntermediateCAStatus(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// Test set default intermediate CA paths

func TestSetTenantDefaultIntermediateCAHandler_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"intermediate_ca_id": "ca-1"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSetTenantDefaultIntermediateCAHandler_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"intermediate_ca_id": "ca-1"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/other-tenant/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestSetTenantDefaultIntermediateCAHandler_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/default-intermediate-ca", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetTenantDefaultIntermediateCAHandler_MissingCAID(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetTenantDefaultIntermediateCAHandler_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		setTenantDefaultIntermediateCAFunc: func(ctx context.Context, tenantID, caID string) error {
			return ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"intermediate_ca_id": "ca-1"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/nonexistent/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSetTenantDefaultIntermediateCAHandler_CANotFound(t *testing.T) {
	service := &mockTenantService{
		setTenantDefaultIntermediateCAFunc: func(ctx context.Context, tenantID, caID string) error {
			return ErrTenantCANotConfigured
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"intermediate_ca_id": "nonexistent"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSetTenantDefaultIntermediateCAHandler_Success(t *testing.T) {
	service := &mockTenantService{
		setTenantDefaultIntermediateCAFunc: func(ctx context.Context, tenantID, caID string) error {
			return nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"intermediate_ca_id": "ca-1"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetTenantDefaultIntermediateCAHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		setTenantDefaultIntermediateCAFunc: func(ctx context.Context, tenantID, caID string) error {
			return errors.New("internal error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"intermediate_ca_id": "ca-1"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1/default-intermediate-ca", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.SetTenantDefaultIntermediateCA(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// Additional tests for CreateTenantIntermediateCA handler to improve coverage

func TestCreateTenantIntermediateCAHandler_MissingKeyAlgorithm(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"common_name": "Test Int CA", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateTenantIntermediateCAHandler_InvalidParentType(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"common_name": "Test Int CA", "key_algorithm": "RSA-2048", "parent_type": "invalid", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateTenantIntermediateCAHandler_InvalidValidity(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"common_name": "Test Int CA", "key_algorithm": "RSA-2048", "parent_type": "tenant", "validity_years": 0}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Additional tests for ListTenantIntermediateCAs handler

func TestListTenantIntermediateCAsHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		listTenantIntermediateCAsFunc: func(ctx context.Context, tenantID string) ([]*TenantIntCAInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.ListTenantIntermediateCAs(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// Additional tests for GetTenantIntermediateCA handler

func TestGetTenantIntermediateCAHandler_InternalError(t *testing.T) {
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

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// Additional tests for CreateTenantEAB handler

func TestCreateTenantEABHandler_InvalidPurpose(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"purpose": "invalid-purpose"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateTenantEABHandler_Endorse01WithoutDeviceInfo(t *testing.T) {
	service := &mockTenantService{
		createTenantEABFunc: func(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error) {
			return &CreateEABResponse{
				ID:        "test-kid",
				MACKey:    "test-mac-key",
				Algorithm: "HS256",
			}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"purpose": "endorse-01"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestCreateTenantEABHandler_InvalidEABPurposeError(t *testing.T) {
	service := &mockTenantService{
		createTenantEABFunc: func(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error) {
			return nil, ErrInvalidEABPurpose
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"purpose": "account-binding"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Additional CreateTenantIntermediateCA handler tests

func TestCreateTenantIntermediateCAHandler_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		createTenantIntermediateCAFunc: func(ctx context.Context, tenantID string, req CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error) {
			return nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"common_name": "Test Int CA", "key_algorithm": "RSA-2048", "parent_type": "tenant", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCreateTenantIntermediateCAHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		createTenantIntermediateCAFunc: func(ctx context.Context, tenantID string, req CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error) {
			return nil, errors.New("internal error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"common_name": "Test Int CA", "key_algorithm": "RSA-2048", "parent_type": "tenant", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// Additional ListTenantIntermediateCAs handler tests

func TestListTenantIntermediateCAsHandler_TenantNotFound(t *testing.T) {
	service := &mockTenantService{
		listTenantIntermediateCAsFunc: func(ctx context.Context, tenantID string) ([]*TenantIntCAInfo, error) {
			return nil, ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.ListTenantIntermediateCAs(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// Additional GetTenantIntermediateCA handler tests

func TestGetTenantIntermediateCAHandler_TenantNotFound(t *testing.T) {
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

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetTenantIntermediateCAHandler_CANotFound(t *testing.T) {
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

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// Additional CreateTenantEAB handler tests

func TestCreateTenantEABHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		createTenantEABFunc: func(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error) {
			return nil, errors.New("internal error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"purpose": "account-binding"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// Additional ListTenantIntermediateCAs handler tests

func TestListTenantIntermediateCAsHandler_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.ListTenantIntermediateCAs(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListTenantIntermediateCAsHandler_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/other-tenant/intermediate-cas", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.ListTenantIntermediateCAs(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// Additional CreateTenantIntermediateCA handler tests

func TestCreateTenantIntermediateCAHandler_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"common_name": "Test Int CA", "key_algorithm": "RSA-2048", "parent_type": "tenant", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateTenantIntermediateCAHandler_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"common_name": "Test Int CA", "key_algorithm": "RSA-2048", "parent_type": "tenant", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/other-tenant/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCreateTenantIntermediateCAHandler_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{invalid json`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateTenantIntermediateCAHandler_MissingCommonName(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"key_algorithm": "RSA-2048", "parent_type": "tenant", "validity_years": 5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/intermediate-cas", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantIntermediateCA(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Additional GetTenantIntermediateCA handler tests

func TestGetTenantIntermediateCAHandler_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1/intermediate-cas/ca-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1", "caid": "ca-1"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.GetTenantIntermediateCA(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetTenantIntermediateCAHandler_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/other-tenant/intermediate-cas/ca-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant", "caid": "ca-1"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.GetTenantIntermediateCA(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// Additional CreateTenantEAB handler tests

func TestCreateTenantEABHandler_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"purpose": "account-binding"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateTenantEABHandler_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"purpose": "account-binding"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/other-tenant/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCreateTenantEABHandler_InvalidJSON(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{invalid json`
	req := httptest.NewRequest("POST", "/api/v1/tenants/tenant-1/eab", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createAdminUser("tenant-1"))
	w := httptest.NewRecorder()

	handlers.CreateTenantEAB(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
