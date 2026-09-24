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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

// mockService implements Service interface for testing
type mockService struct {
	listCertificatesFunc         func(ctx context.Context, req ListCertificatesRequest) ([]*CertificateInfo, *Pagination, error)
	getCertificateFunc           func(ctx context.Context, serial string) (*CertificateInfo, error)
	revokeCertificateFunc        func(ctx context.Context, serial, reason string) error
	listExpiringCertificatesFunc func(ctx context.Context, days, page, perPage int) ([]*CertificateInfo, *Pagination, error)
	listAccountsFunc             func(ctx context.Context, req ListAccountsRequest) ([]*AccountInfo, *Pagination, error)
	getAccountFunc               func(ctx context.Context, id uint64) (*AccountInfo, error)
	disableAccountFunc           func(ctx context.Context, id uint64) error
	listOrdersFunc               func(ctx context.Context, req ListOrdersRequest) ([]*OrderInfo, *Pagination, error)
	getOrderFunc                 func(ctx context.Context, orderID, accountID uint64) (*OrderInfo, error)
	getStatusFunc                func(ctx context.Context) (*CAStatus, error)
	getStatsFunc                 func(ctx context.Context) (*CAStats, error)
}

func (m *mockService) ListCertificates(ctx context.Context, req ListCertificatesRequest) ([]*CertificateInfo, *Pagination, error) {
	if m.listCertificatesFunc != nil {
		return m.listCertificatesFunc(ctx, req)
	}
	return nil, nil, nil
}

func (m *mockService) GetCertificate(ctx context.Context, serial string) (*CertificateInfo, error) {
	if m.getCertificateFunc != nil {
		return m.getCertificateFunc(ctx, serial)
	}
	return nil, nil
}

func (m *mockService) RevokeCertificate(ctx context.Context, serial, reason string) error {
	if m.revokeCertificateFunc != nil {
		return m.revokeCertificateFunc(ctx, serial, reason)
	}
	return nil
}

func (m *mockService) ListExpiringCertificates(ctx context.Context, days, page, perPage int) ([]*CertificateInfo, *Pagination, error) {
	if m.listExpiringCertificatesFunc != nil {
		return m.listExpiringCertificatesFunc(ctx, days, page, perPage)
	}
	return nil, nil, nil
}

func (m *mockService) ListAccounts(ctx context.Context, req ListAccountsRequest) ([]*AccountInfo, *Pagination, error) {
	if m.listAccountsFunc != nil {
		return m.listAccountsFunc(ctx, req)
	}
	return nil, nil, nil
}

func (m *mockService) GetAccount(ctx context.Context, id uint64) (*AccountInfo, error) {
	if m.getAccountFunc != nil {
		return m.getAccountFunc(ctx, id)
	}
	return nil, nil
}

func (m *mockService) DisableAccount(ctx context.Context, id uint64) error {
	if m.disableAccountFunc != nil {
		return m.disableAccountFunc(ctx, id)
	}
	return nil
}

func (m *mockService) ListOrders(ctx context.Context, req ListOrdersRequest) ([]*OrderInfo, *Pagination, error) {
	if m.listOrdersFunc != nil {
		return m.listOrdersFunc(ctx, req)
	}
	return nil, nil, nil
}

func (m *mockService) GetOrder(ctx context.Context, orderID, accountID uint64) (*OrderInfo, error) {
	if m.getOrderFunc != nil {
		return m.getOrderFunc(ctx, orderID, accountID)
	}
	return nil, nil
}

func (m *mockService) GetStatus(ctx context.Context) (*CAStatus, error) {
	if m.getStatusFunc != nil {
		return m.getStatusFunc(ctx)
	}
	return nil, nil
}

func (m *mockService) GetStats(ctx context.Context) (*CAStats, error) {
	if m.getStatsFunc != nil {
		return m.getStatsFunc(ctx)
	}
	return nil, nil
}

func TestNewHandlers(t *testing.T) {
	service := &mockService{}
	logger := slog.Default()

	handlers := NewHandlers(service, logger)

	assert.NotNil(t, handlers)
	assert.Equal(t, service, handlers.service)
	assert.Equal(t, logger, handlers.logger)
}

func TestRegisterRoutes(t *testing.T) {
	handlers := NewHandlers(&mockService{}, slog.Default())
	router := mux.NewRouter()

	// Register routes without auth middleware
	handlers.RegisterRoutes(router, nil, newPermissiveGate())

	// Verify routes are registered
	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/admin/certificates"},
		{"GET", "/admin/certificates/expiring"},
		{"GET", "/admin/certificates/12345"},
		{"POST", "/admin/certificates/12345/revoke"},
		{"GET", "/admin/accounts"},
		{"GET", "/admin/accounts/1"},
		{"DELETE", "/admin/accounts/1"},
		{"GET", "/admin/orders"},
		{"GET", "/admin/orders/1"},
		{"GET", "/admin/status"},
		{"GET", "/admin/stats"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.True(t, matched, "Route %s %s should be registered", tt.method, tt.path)
		})
	}
}

func TestRegisterRoutes_WithAuth(t *testing.T) {
	handlers := NewHandlers(&mockService{}, slog.Default())
	router := mux.NewRouter()

	// Register with mTLS auth middleware. The development-mode bypass that
	// granted super-admin with a wildcard permission set to every request was
	// deleted along with the parallel role model.
	authMiddleware := NewMTLSAuthMiddleware(nil)
	handlers.RegisterRoutes(router, authMiddleware, newPermissiveGate())

	req := httptest.NewRequest("GET", "/admin/status", nil)
	var match mux.RouteMatch
	matched := router.Match(req, &match)
	assert.True(t, matched)
}

func TestListCertificates_Success(t *testing.T) {
	service := &mockService{
		listCertificatesFunc: func(ctx context.Context, req ListCertificatesRequest) ([]*CertificateInfo, *Pagination, error) {
			return []*CertificateInfo{
				{ID: 1, SerialNumber: "1234"},
			}, &Pagination{Page: 1, PerPage: 20, Total: 1}, nil
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/certificates?page=1&per_page=20&status=valid&subject=test", nil)
	w := httptest.NewRecorder()

	handlers.ListCertificates(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListCertificates_Error(t *testing.T) {
	service := &mockService{
		listCertificatesFunc: func(ctx context.Context, req ListCertificatesRequest) ([]*CertificateInfo, *Pagination, error) {
			return nil, nil, errors.New("database error")
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/certificates", nil)
	w := httptest.NewRecorder()

	handlers.ListCertificates(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetCertificate_Success(t *testing.T) {
	service := &mockService{
		getCertificateFunc: func(ctx context.Context, serial string) (*CertificateInfo, error) {
			return &CertificateInfo{ID: 1, SerialNumber: serial}, nil
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/certificates/1234", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": "1234"})
	w := httptest.NewRecorder()

	handlers.GetCertificate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetCertificate_NotFound(t *testing.T) {
	service := &mockService{
		getCertificateFunc: func(ctx context.Context, serial string) (*CertificateInfo, error) {
			return nil, ErrCertificateNotFound
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/certificates/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": "nonexistent"})
	w := httptest.NewRecorder()

	handlers.GetCertificate(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetCertificate_NotFound_Wrapped is go-xkms#894's regression case: the
// handler compares the service error with errors.Is, so a service that
// wraps ErrCertificateNotFound with call-site context (fmt.Errorf's %w)
// must still map to 404, not fall through to the 500 branch a bare ==
// comparison would take.
func TestGetCertificate_NotFound_Wrapped(t *testing.T) {
	service := &mockService{
		getCertificateFunc: func(ctx context.Context, serial string) (*CertificateInfo, error) {
			return nil, fmt.Errorf("lookup serial %s: %w", serial, ErrCertificateNotFound)
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/certificates/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": "nonexistent"})
	w := httptest.NewRecorder()

	handlers.GetCertificate(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetCertificate_Error(t *testing.T) {
	service := &mockService{
		getCertificateFunc: func(ctx context.Context, serial string) (*CertificateInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/certificates/1234", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": "1234"})
	w := httptest.NewRecorder()

	handlers.GetCertificate(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRevokeCertificate_Success(t *testing.T) {
	service := &mockService{
		revokeCertificateFunc: func(ctx context.Context, serial, reason string) error {
			return nil
		},
	}
	handlers := NewHandlers(service, slog.Default())

	body := `{"reason": "key compromise"}`
	req := httptest.NewRequest("POST", "/admin/certificates/1234/revoke", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"serial": "1234"})
	w := httptest.NewRecorder()

	handlers.RevokeCertificate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRevokeCertificate_InvalidJSON(t *testing.T) {
	handlers := NewHandlers(&mockService{}, slog.Default())

	req := httptest.NewRequest("POST", "/admin/certificates/1234/revoke", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"serial": "1234"})
	w := httptest.NewRecorder()

	handlers.RevokeCertificate(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeCertificate_NotFound(t *testing.T) {
	service := &mockService{
		revokeCertificateFunc: func(ctx context.Context, serial, reason string) error {
			return ErrCertificateNotFound
		},
	}
	handlers := NewHandlers(service, slog.Default())

	body := `{"reason": "key compromise"}`
	req := httptest.NewRequest("POST", "/admin/certificates/nonexistent/revoke", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"serial": "nonexistent"})
	w := httptest.NewRecorder()

	handlers.RevokeCertificate(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRevokeCertificate_Error(t *testing.T) {
	service := &mockService{
		revokeCertificateFunc: func(ctx context.Context, serial, reason string) error {
			return errors.New("revocation failed")
		},
	}
	handlers := NewHandlers(service, slog.Default())

	body := `{"reason": "key compromise"}`
	req := httptest.NewRequest("POST", "/admin/certificates/1234/revoke", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"serial": "1234"})
	w := httptest.NewRecorder()

	handlers.RevokeCertificate(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListExpiringCertificates_Success(t *testing.T) {
	service := &mockService{
		listExpiringCertificatesFunc: func(ctx context.Context, days, page, perPage int) ([]*CertificateInfo, *Pagination, error) {
			return []*CertificateInfo{
				{ID: 1, SerialNumber: "1234"},
			}, &Pagination{Page: 1, PerPage: 20, Total: 1}, nil
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/certificates/expiring?days=30&page=1&per_page=20", nil)
	w := httptest.NewRecorder()

	handlers.ListExpiringCertificates(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListExpiringCertificates_Error(t *testing.T) {
	service := &mockService{
		listExpiringCertificatesFunc: func(ctx context.Context, days, page, perPage int) ([]*CertificateInfo, *Pagination, error) {
			return nil, nil, errors.New("database error")
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/certificates/expiring", nil)
	w := httptest.NewRecorder()

	handlers.ListExpiringCertificates(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListAccounts_Success(t *testing.T) {
	service := &mockService{
		listAccountsFunc: func(ctx context.Context, req ListAccountsRequest) ([]*AccountInfo, *Pagination, error) {
			return []*AccountInfo{
				{ID: 1, Status: "valid"},
			}, &Pagination{Page: 1, PerPage: 20, Total: 1}, nil
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/accounts?page=1&per_page=20&status=valid", nil)
	w := httptest.NewRecorder()

	handlers.ListAccounts(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListAccounts_Error(t *testing.T) {
	service := &mockService{
		listAccountsFunc: func(ctx context.Context, req ListAccountsRequest) ([]*AccountInfo, *Pagination, error) {
			return nil, nil, errors.New("database error")
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/accounts", nil)
	w := httptest.NewRecorder()

	handlers.ListAccounts(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetAccount_Success(t *testing.T) {
	service := &mockService{
		getAccountFunc: func(ctx context.Context, id uint64) (*AccountInfo, error) {
			return &AccountInfo{ID: FlexUint64(id), Status: "valid"}, nil
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/accounts/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handlers.GetAccount(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAccount_InvalidID(t *testing.T) {
	handlers := NewHandlers(&mockService{}, slog.Default())

	req := httptest.NewRequest("GET", "/admin/accounts/invalid", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "invalid"})
	w := httptest.NewRecorder()

	handlers.GetAccount(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAccount_NotFound(t *testing.T) {
	service := &mockService{
		getAccountFunc: func(ctx context.Context, id uint64) (*AccountInfo, error) {
			return nil, ErrAccountNotFound
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/accounts/999", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "999"})
	w := httptest.NewRecorder()

	handlers.GetAccount(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetAccount_Error(t *testing.T) {
	service := &mockService{
		getAccountFunc: func(ctx context.Context, id uint64) (*AccountInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/accounts/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handlers.GetAccount(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDisableAccount_Success(t *testing.T) {
	service := &mockService{
		disableAccountFunc: func(ctx context.Context, id uint64) error {
			return nil
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/admin/accounts/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handlers.DisableAccount(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDisableAccount_InvalidID(t *testing.T) {
	handlers := NewHandlers(&mockService{}, slog.Default())

	req := httptest.NewRequest("DELETE", "/admin/accounts/invalid", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "invalid"})
	w := httptest.NewRecorder()

	handlers.DisableAccount(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDisableAccount_NotFound(t *testing.T) {
	service := &mockService{
		disableAccountFunc: func(ctx context.Context, id uint64) error {
			return ErrAccountNotFound
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/admin/accounts/999", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "999"})
	w := httptest.NewRecorder()

	handlers.DisableAccount(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDisableAccount_Error(t *testing.T) {
	service := &mockService{
		disableAccountFunc: func(ctx context.Context, id uint64) error {
			return errors.New("database error")
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/admin/accounts/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handlers.DisableAccount(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListOrders_Success(t *testing.T) {
	service := &mockService{
		listOrdersFunc: func(ctx context.Context, req ListOrdersRequest) ([]*OrderInfo, *Pagination, error) {
			return []*OrderInfo{
				{ID: 1, AccountID: 1, Status: "valid"},
			}, &Pagination{Page: 1, PerPage: 20, Total: 1}, nil
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/orders?page=1&per_page=20&status=valid&account_id=1", nil)
	w := httptest.NewRecorder()

	handlers.ListOrders(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListOrders_Error(t *testing.T) {
	service := &mockService{
		listOrdersFunc: func(ctx context.Context, req ListOrdersRequest) ([]*OrderInfo, *Pagination, error) {
			return nil, nil, errors.New("database error")
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/orders", nil)
	w := httptest.NewRecorder()

	handlers.ListOrders(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetOrder_Success(t *testing.T) {
	service := &mockService{
		getOrderFunc: func(ctx context.Context, orderID, accountID uint64) (*OrderInfo, error) {
			return &OrderInfo{ID: orderID, AccountID: accountID, Status: "valid"}, nil
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/orders/1?account_id=1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handlers.GetOrder(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetOrder_InvalidOrderID(t *testing.T) {
	handlers := NewHandlers(&mockService{}, slog.Default())

	req := httptest.NewRequest("GET", "/admin/orders/invalid?account_id=1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "invalid"})
	w := httptest.NewRecorder()

	handlers.GetOrder(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetOrder_MissingAccountID(t *testing.T) {
	handlers := NewHandlers(&mockService{}, slog.Default())

	req := httptest.NewRequest("GET", "/admin/orders/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handlers.GetOrder(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetOrder_InvalidAccountID(t *testing.T) {
	handlers := NewHandlers(&mockService{}, slog.Default())

	req := httptest.NewRequest("GET", "/admin/orders/1?account_id=invalid", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handlers.GetOrder(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetOrder_NotFound(t *testing.T) {
	service := &mockService{
		getOrderFunc: func(ctx context.Context, orderID, accountID uint64) (*OrderInfo, error) {
			return nil, ErrOrderNotFound
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/orders/999?account_id=1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "999"})
	w := httptest.NewRecorder()

	handlers.GetOrder(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetOrder_Error(t *testing.T) {
	service := &mockService{
		getOrderFunc: func(ctx context.Context, orderID, accountID uint64) (*OrderInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/orders/1?account_id=1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handlers.GetOrder(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetStatus_Success(t *testing.T) {
	service := &mockService{
		getStatusFunc: func(ctx context.Context) (*CAStatus, error) {
			return &CAStatus{Identity: "Test CA", Initialized: true}, nil
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/status", nil)
	w := httptest.NewRecorder()

	handlers.GetStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetStatus_Error(t *testing.T) {
	service := &mockService{
		getStatusFunc: func(ctx context.Context) (*CAStatus, error) {
			return nil, errors.New("status error")
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/status", nil)
	w := httptest.NewRecorder()

	handlers.GetStatus(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetStats_Success(t *testing.T) {
	service := &mockService{
		getStatsFunc: func(ctx context.Context) (*CAStats, error) {
			return &CAStats{TotalCertificates: 100, ValidCertificates: 80}, nil
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/stats", nil)
	w := httptest.NewRecorder()

	handlers.GetStats(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetStats_Error(t *testing.T) {
	service := &mockService{
		getStatsFunc: func(ctx context.Context) (*CAStats, error) {
			return nil, errors.New("stats error")
		},
	}
	handlers := NewHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/admin/stats", nil)
	w := httptest.NewRecorder()

	handlers.GetStats(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestParseInt_DefaultValues(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		defaultValue int
		expected     int
	}{
		{"empty string returns default", "", 10, 10},
		{"valid number", "5", 10, 5},
		{"invalid number returns default", "invalid", 10, 10},
		{"negative number", "-5", 10, -5},
		{"zero", "0", 10, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseInt(tt.input, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}

	writeJSON(w, http.StatusOK, data)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var decoded map[string]string
	err := json.NewDecoder(w.Body).Decode(&decoded)
	assert.NoError(t, err)
	assert.Equal(t, "value", decoded["key"])
}

func TestWriteJSON_WithListResponse(t *testing.T) {
	w := httptest.NewRecorder()
	data := ListResponse{
		Items:   []string{"a", "b"},
		Total:   2,
		Page:    1,
		PerPage: 20,
	}

	writeJSON(w, http.StatusOK, data)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var decoded ListResponse
	err := json.NewDecoder(w.Body).Decode(&decoded)
	assert.NoError(t, err)
	assert.Equal(t, 2, decoded.Total)
	assert.Equal(t, 1, decoded.Page)
	assert.Equal(t, 20, decoded.PerPage)
}

func TestWriteProblem(t *testing.T) {
	w := httptest.NewRecorder()

	writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid input")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/problem+json", w.Header().Get("Content-Type"))

	var problem ProblemDetail
	err := json.NewDecoder(w.Body).Decode(&problem)
	assert.NoError(t, err)
	assert.Equal(t, "urn:trusted-ca:error:bad-request", problem.Type)
	assert.Equal(t, "Bad Request", problem.Title)
	assert.Equal(t, "Invalid input", problem.Detail)
	assert.Equal(t, http.StatusBadRequest, problem.Status)
}

// failingResponseWriter is an http.ResponseWriter whose Write always fails,
// simulating a client that disconnects mid-response so json.Encoder.Encode
// cannot finish writing the body.
type failingResponseWriter struct {
	header http.Header
}

func (w *failingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("simulated write failure")
}

func (w *failingResponseWriter) WriteHeader(int) {}

// TestWriteJSON_LogsEncodeFailure verifies that a failure to write the
// response body — which can no longer be reported to the client because
// headers are already sent — is logged rather than silently dropped.
func TestWriteJSON_LogsEncodeFailure(t *testing.T) {
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	defer slog.SetDefault(prev)

	writeJSON(&failingResponseWriter{}, http.StatusOK, map[string]string{"key": "value"})

	assert.Contains(t, logBuf.String(), "failed to write JSON response")
}

// TestWriteProblem_LogsEncodeFailure is TestWriteJSON_LogsEncodeFailure for
// the RFC 7807 problem-detail encoder.
func TestWriteProblem_LogsEncodeFailure(t *testing.T) {
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	defer slog.SetDefault(prev)

	writeProblem(&failingResponseWriter{}, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid input")

	assert.Contains(t, logBuf.String(), "failed to write problem detail response")
}
