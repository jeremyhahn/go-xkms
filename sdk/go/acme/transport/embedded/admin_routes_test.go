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

package embedded

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// mockAdminService implements AdminServicer for testing.
type mockAdminService struct {
	lastPath   string
	lastMethod string
	response   interface{}
	statusCode int
}

func newMockAdminService() *mockAdminService {
	return &mockAdminService{
		statusCode: http.StatusOK,
		response:   map[string]string{"status": "ok"},
	}
}

func (m *mockAdminService) writeAdminResponse(w http.ResponseWriter, r *http.Request) {
	m.lastPath = r.URL.Path
	m.lastMethod = r.Method
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(m.statusCode)
	if m.response != nil {
		json.NewEncoder(w).Encode(m.response)
	}
}

func (m *mockAdminService) StatusHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) StatsHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) ListCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) GetCertificateHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) RevokeCertificateHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) ListAccountsHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) GetAccountHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) DisableAccountHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) CreateTenantHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) ListTenantsHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) GetTenantHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) UpdateTenantHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) DeleteTenantHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) UpdateTenantStatusHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) CreateEABHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) ListEABHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) GetEABHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) DeleteEABHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) CreateRoleHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) ListRolesHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) GetRoleHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) UpdateRoleHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) DeleteRoleHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) ListOrdersHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) GetOrderHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) CreateRootCAHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) CAStatusHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) CreateIntermediateCAHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) ListIntermediateCAsHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) GetIntermediateCAHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}
func (m *mockAdminService) UpdateIntermediateCAStatusHandler(w http.ResponseWriter, r *http.Request) {
	m.writeAdminResponse(w, r)
}

// TestAdminRoutes_AllRegistered verifies admin routes are registered when admin service is provided.
func TestAdminRoutes_AllRegistered(t *testing.T) {
	t.Parallel()

	restSvc := newMockRestService()
	adminSvc := newMockAdminService()

	cfg := &transport.Config{}
	tr, err := NewTransport(cfg, WithService(restSvc), WithAdminService(adminSvc))
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	embeddedTransport := tr.(*Transport)

	adminRoutes := []routeKey{
		{service: "admin.status", method: "status"},
		{service: "admin.status", method: "stats"},
		{service: "admin.certificate", method: "list"},
		{service: "admin.certificate", method: "get"},
		{service: "admin.certificate", method: "revoke"},
		{service: "admin.account", method: "list"},
		{service: "admin.account", method: "get"},
		{service: "admin.account", method: "disable"},
		{service: "admin.tenant", method: "create"},
		{service: "admin.tenant", method: "list"},
		{service: "admin.tenant", method: "get"},
		{service: "admin.tenant", method: "update"},
		{service: "admin.tenant", method: "delete"},
		{service: "admin.tenant", method: "updateStatus"},
		{service: "admin.eab", method: "create"},
		{service: "admin.eab", method: "list"},
		{service: "admin.eab", method: "get"},
		{service: "admin.eab", method: "delete"},
		{service: "admin.role", method: "create"},
		{service: "admin.role", method: "list"},
		{service: "admin.role", method: "get"},
		{service: "admin.role", method: "update"},
		{service: "admin.role", method: "delete"},
		{service: "admin.user", method: "create"},
		{service: "admin.user", method: "list"},
		{service: "admin.user", method: "get"},
		{service: "admin.user", method: "update"},
		{service: "admin.user", method: "delete"},
		{service: "admin.order", method: "list"},
		{service: "admin.order", method: "get"},
		{service: "admin.tenant.ca", method: "createRootCA"},
		{service: "admin.tenant.ca", method: "status"},
		{service: "admin.tenant.ca", method: "createIntermediateCA"},
		{service: "admin.tenant.ca", method: "listIntermediateCAs"},
		{service: "admin.tenant.ca", method: "getIntermediateCA"},
		{service: "admin.tenant.ca", method: "updateIntermediateCAStatus"},
	}

	for _, key := range adminRoutes {
		if _, ok := embeddedTransport.handlers[key]; !ok {
			t.Errorf("missing admin route: %s/%s", key.service, key.method)
		}
	}
}

// TestAdminRoutes_RequestInvokesHandler verifies that admin requests invoke the correct handler.
func TestAdminRoutes_RequestInvokesHandler(t *testing.T) {
	t.Parallel()

	restSvc := newMockRestService()
	adminSvc := newMockAdminService()

	cfg := &transport.Config{}
	tr, err := NewTransport(cfg, WithService(restSvc), WithAdminService(adminSvc))
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()

	resp, err := tr.Request(ctx, "admin.status", "status", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestAdminRoutes_WithoutAdminService verifies that admin routes are not registered when no admin service is provided.
func TestAdminRoutes_WithoutAdminService(t *testing.T) {
	t.Parallel()

	restSvc := newMockRestService()

	cfg := &transport.Config{}
	tr, err := NewTransport(cfg, WithService(restSvc))
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()

	_, err = tr.Request(ctx, "admin.status", "status", nil)
	if err == nil {
		t.Fatal("expected error for admin route without admin service")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected not found error, got: %v", err)
	}
}

// TestAdminRoutes_WithAdminService_NilValue verifies error handling for nil admin service.
func TestAdminRoutes_WithAdminService_NilValue(t *testing.T) {
	t.Parallel()

	cfg := &transport.Config{}
	_, err := NewTransport(cfg, WithService(newMockRestService()), WithAdminService(nil))
	if err == nil {
		t.Fatal("expected error for nil admin service")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}

// TestAdminRoutes_AdminOnlyTransport verifies that a transport can be created with only admin service.
func TestAdminRoutes_AdminOnlyTransport(t *testing.T) {
	t.Parallel()

	adminSvc := newMockAdminService()

	cfg := &transport.Config{}
	tr, err := NewTransport(cfg, WithAdminService(adminSvc))
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()

	resp, err := tr.Request(ctx, "admin.status", "status", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestAdminRoutes_ACMEStillWorks verifies that ACME routes still work alongside admin routes.
func TestAdminRoutes_ACMEStillWorks(t *testing.T) {
	t.Parallel()

	restSvc := newMockRestService()
	restSvc.directoryResponse = map[string]string{
		"newNonce":   "https://localhost/acme/new-nonce",
		"newAccount": "https://localhost/acme/new-acct",
		"newOrder":   "https://localhost/acme/new-order",
		"revokeCert": "https://localhost/acme/revoke-cert",
		"keyChange":  "https://localhost/acme/key-change",
	}
	adminSvc := newMockAdminService()

	cfg := &transport.Config{}
	tr, err := NewTransport(cfg, WithService(restSvc), WithAdminService(adminSvc))
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()

	resp, err := tr.Request(ctx, "directory", "get", nil)
	if err != nil {
		t.Fatalf("Request(directory/get) error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response for directory/get")
	}
}

// TestIsAdminService verifies the isAdminService helper function.
func TestIsAdminService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		service string
		want    bool
	}{
		{"admin.tenant", true},
		{"admin.status", true},
		{"admin.tenant.ca", true},
		{"directory", false},
		{"account", false},
		{"certificate", false},
		{"admin", false},
	}

	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			if got := isAdminService(tt.service); got != tt.want {
				t.Errorf("isAdminService(%q) = %v, want %v", tt.service, got, tt.want)
			}
		})
	}
}

// TestNewAdminFactory verifies the admin factory creates transports correctly.
func TestNewAdminFactory(t *testing.T) {
	t.Parallel()

	restSvc := newMockRestService()
	adminSvc := newMockAdminService()

	factory := NewAdminFactory(restSvc, adminSvc)

	cfg := &transport.Config{}
	tr, err := factory.Create(cfg)
	if err != nil {
		t.Fatalf("Factory.Create() error = %v", err)
	}
	defer tr.Close()

	if !tr.Healthy() {
		t.Error("transport should be healthy after creation")
	}
}
