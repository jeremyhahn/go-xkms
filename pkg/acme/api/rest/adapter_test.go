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

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
)

// TestNewAdapter tests the NewAdapter constructor with various configurations.
func TestNewAdapter(t *testing.T) {
	tests := []struct {
		name      string
		config    *api.AdapterConfig
		wantError bool
		errMsg    string
	}{
		{
			name: "valid config with base URL",
			config: &api.AdapterConfig{
				BaseURL:   "http://localhost:8443",
				AuthToken: "test-token",
			},
			wantError: false,
		},
		{
			name: "empty base URL returns error",
			config: &api.AdapterConfig{
				BaseURL:   "",
				AuthToken: "test-token",
			},
			wantError: true,
			errMsg:    "base URL is required",
		},
		{
			name: "valid config with empty TLS config",
			config: &api.AdapterConfig{
				BaseURL:   "https://localhost:8443",
				TLSConfig: &api.TLSConfig{},
			},
			wantError: false,
		},
		{
			name: "invalid client certificate paths",
			config: &api.AdapterConfig{
				BaseURL: "https://localhost:8443",
				TLSConfig: &api.TLSConfig{
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
			wantError: true,
			errMsg:    "failed to load client certificate",
		},
		{
			name: "invalid CA certificate path",
			config: &api.AdapterConfig{
				BaseURL: "https://localhost:8443",
				TLSConfig: &api.TLSConfig{
					CAFile: "/nonexistent/ca.pem",
				},
			},
			wantError: true,
			errMsg:    "failed to read CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, err := NewAdapter(tt.config)

			if tt.wantError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if adapter == nil {
				t.Fatal("expected adapter, got nil")
			}

			if adapter.baseURL != tt.config.BaseURL {
				t.Errorf("expected baseURL %q, got %q", tt.config.BaseURL, adapter.baseURL)
			}

			if adapter.authToken != tt.config.AuthToken {
				t.Errorf("expected authToken %q, got %q", tt.config.AuthToken, adapter.authToken)
			}
		})
	}
}

// TestNewAdapterWithValidTLSCerts tests NewAdapter with valid TLS certificate files.
func TestNewAdapterWithValidTLSCerts(t *testing.T) {
	tempDir := t.TempDir()

	// Create test CA certificate
	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpGgSJHKMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7k1+zEAq3r8XYzjQwFJDV
KNyKPiLPLHfzZNMl8qe4w5dKqWzL8IqPqjm4lVnUqMmVVqBqkNnGpKNqQpQGEZxN
AgMBAAGjUDBOMB0GA1UdDgQWBBQfH3bNDwOGPJVN2h3TKJZzAJVwDjAfBgNVHSME
GDAWgBQfH3bNDwOGPJVN2h3TKJZzAJVwDjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3
DQEBCwUAA0EA
-----END CERTIFICATE-----`
	if err := os.WriteFile(caCertPath, []byte(caCertPEM), 0600); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}

	config := &api.AdapterConfig{
		BaseURL: "https://localhost:8443",
		TLSConfig: &api.TLSConfig{
			CAFile: caCertPath,
		},
	}

	adapter, err := NewAdapter(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if adapter == nil {
		t.Fatal("expected adapter, got nil")
	}
}

// TestProtocol verifies the Protocol method returns api.ProtocolREST.
func TestProtocol(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	protocol := adapter.Protocol()
	if protocol != api.ProtocolREST {
		t.Errorf("expected protocol %q, got %q", api.ProtocolREST, protocol)
	}
}

// TestClose verifies the Close method works correctly.
func TestClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = adapter.Close()
	if err != nil {
		t.Errorf("expected nil error from Close, got %v", err)
	}
}

// TestCreateTenant tests the CreateTenant method.
func TestCreateTenant(t *testing.T) {
	tests := []struct {
		name       string
		request    *admin.CreateTenantRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name: "successful creation",
			request: &admin.CreateTenantRequest{
				ID:   "tenant-1",
				Name: "Test Tenant",
			},
			statusCode: http.StatusCreated,
			response: &admin.TenantInfo{
				ID:        "tenant-1",
				Name:      "Test Tenant",
				Status:    "active",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			wantError: false,
		},
		{
			name: "bad request error",
			request: &admin.CreateTenantRequest{
				ID: "",
			},
			statusCode: http.StatusBadRequest,
			response:   `{"error": "invalid tenant ID"}`,
			wantError:  true,
			errContain: "400",
		},
		{
			name: "conflict error",
			request: &admin.CreateTenantRequest{
				ID:   "existing-tenant",
				Name: "Existing",
			},
			statusCode: http.StatusConflict,
			response:   `{"error": "tenant already exists"}`,
			wantError:  true,
			errContain: "409",
		},
		{
			name: "internal server error",
			request: &admin.CreateTenantRequest{
				ID:   "tenant-1",
				Name: "Test",
			},
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST method, got %s", r.Method)
				}
				if r.URL.Path != "/api/v1/tenants" {
					t.Errorf("expected path /api/v1/tenants, got %s", r.URL.Path)
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
				}
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Errorf("expected Authorization Bearer test-token, got %s", r.Header.Get("Authorization"))
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					_, _ = w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{
				BaseURL:   server.URL,
				AuthToken: "test-token",
			})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			tenant, err := adapter.CreateTenant(context.Background(), tt.request)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tenant.ID != tt.request.ID {
				t.Errorf("expected tenant ID %q, got %q", tt.request.ID, tenant.ID)
			}
		})
	}
}

// TestGetTenant tests the GetTenant method.
func TestGetTenant(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:       "successful get",
			tenantID:   "tenant-1",
			statusCode: http.StatusOK,
			response: &admin.TenantInfo{
				ID:     "tenant-1",
				Name:   "Test Tenant",
				Status: "active",
			},
			wantError: false,
		},
		{
			name:       "not found error",
			tenantID:   "nonexistent",
			statusCode: http.StatusNotFound,
			response:   `{"error": "tenant not found"}`,
			wantError:  true,
			errContain: "404",
		},
		{
			name:       "internal server error",
			tenantID:   "tenant-1",
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					_, _ = w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			tenant, err := adapter.GetTenant(context.Background(), tt.tenantID)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tenant.ID != tt.tenantID {
				t.Errorf("expected tenant ID %q, got %q", tt.tenantID, tenant.ID)
			}
		})
	}
}

// TestUpdateTenant tests the UpdateTenant method.
func TestUpdateTenant(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		request    *admin.UpdateTenantRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:     "successful update",
			tenantID: "tenant-1",
			request: &admin.UpdateTenantRequest{
				Name: "Updated Tenant",
			},
			statusCode: http.StatusOK,
			response: &admin.TenantInfo{
				ID:     "tenant-1",
				Name:   "Updated Tenant",
				Status: "active",
			},
			wantError: false,
		},
		{
			name:     "not found error",
			tenantID: "nonexistent",
			request: &admin.UpdateTenantRequest{
				Name: "Updated",
			},
			statusCode: http.StatusNotFound,
			response:   `{"error": "tenant not found"}`,
			wantError:  true,
			errContain: "404",
		},
		{
			name:     "bad request error",
			tenantID: "tenant-1",
			request: &admin.UpdateTenantRequest{
				Name: "",
			},
			statusCode: http.StatusBadRequest,
			response:   `{"error": "invalid request"}`,
			wantError:  true,
			errContain: "400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut {
					t.Errorf("expected PUT method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					_, _ = w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			tenant, err := adapter.UpdateTenant(context.Background(), tt.tenantID, tt.request)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tenant.Name != tt.request.Name {
				t.Errorf("expected tenant name %q, got %q", tt.request.Name, tenant.Name)
			}
		})
	}
}

// TestDeleteTenant tests the DeleteTenant method.
func TestDeleteTenant(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		statusCode int
		response   string
		wantError  bool
		errContain string
	}{
		{
			name:       "successful delete",
			tenantID:   "tenant-1",
			statusCode: http.StatusNoContent,
			response:   "",
			wantError:  false,
		},
		{
			name:       "not found error",
			tenantID:   "nonexistent",
			statusCode: http.StatusNotFound,
			response:   `{"error": "tenant not found"}`,
			wantError:  true,
			errContain: "404",
		},
		{
			name:       "forbidden error",
			tenantID:   "protected-tenant",
			statusCode: http.StatusForbidden,
			response:   `{"error": "cannot delete protected tenant"}`,
			wantError:  true,
			errContain: "403",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected DELETE method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			err = adapter.DeleteTenant(context.Background(), tt.tenantID)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestListTenants tests the ListTenants method.
func TestListTenants(t *testing.T) {
	tests := []struct {
		name       string
		request    *admin.ListTenantsRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
		wantCount  int
	}{
		{
			name: "successful list",
			request: &admin.ListTenantsRequest{
				Page:    1,
				PerPage: 10,
			},
			statusCode: http.StatusOK,
			response: map[string]interface{}{
				"items": []*admin.TenantInfo{
					{ID: "tenant-1", Name: "Tenant 1"},
					{ID: "tenant-2", Name: "Tenant 2"},
				},
				"total":    2,
				"page":     1,
				"per_page": 10,
			},
			wantError: false,
			wantCount: 2,
		},
		{
			name: "empty list",
			request: &admin.ListTenantsRequest{
				Page:    1,
				PerPage: 10,
			},
			statusCode: http.StatusOK,
			response: map[string]interface{}{
				"items":    []*admin.TenantInfo{},
				"total":    0,
				"page":     1,
				"per_page": 10,
			},
			wantError: false,
			wantCount: 0,
		},
		{
			name: "internal server error",
			request: &admin.ListTenantsRequest{
				Page:    1,
				PerPage: 10,
			},
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}
				if !strings.HasPrefix(r.URL.Path, "/api/v1/tenants") {
					t.Errorf("expected path to start with /api/v1/tenants, got %s", r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			tenants, pagination, err := adapter.ListTenants(context.Background(), tt.request)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(tenants) != tt.wantCount {
				t.Errorf("expected %d tenants, got %d", tt.wantCount, len(tenants))
			}

			if pagination == nil {
				t.Error("expected pagination, got nil")
			}
		})
	}
}

// TestCreateEAB tests the CreateEAB method.
func TestCreateEAB(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		request    *admin.CreateEABRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:     "successful creation",
			tenantID: "tenant-1",
			request: &admin.CreateEABRequest{
				Purpose: "account-binding",
			},
			statusCode: http.StatusCreated,
			response: &admin.CreateEABResponse{
				ID:        "eab-123",
				MACKey:    "base64url-encoded-key",
				Algorithm: "HS256",
			},
			wantError: false,
		},
		{
			name:     "bad request",
			tenantID: "tenant-1",
			request: &admin.CreateEABRequest{
				Purpose: "invalid-purpose",
			},
			statusCode: http.StatusBadRequest,
			response:   `{"error": "invalid purpose"}`,
			wantError:  true,
			errContain: "400",
		},
		{
			name:     "tenant not found",
			tenantID: "nonexistent",
			request: &admin.CreateEABRequest{
				Purpose: "account-binding",
			},
			statusCode: http.StatusNotFound,
			response:   `{"error": "tenant not found"}`,
			wantError:  true,
			errContain: "404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID + "/eab"
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			eab, err := adapter.CreateEAB(context.Background(), tt.tenantID, tt.request)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if eab.ID == "" {
				t.Error("expected non-empty EAB ID")
			}
		})
	}
}

// TestGetEAB tests the GetEAB method.
func TestGetEAB(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		kid        string
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:       "successful get",
			tenantID:   "tenant-1",
			kid:        "eab-123",
			statusCode: http.StatusOK,
			response: &admin.EABInfo{
				ID:       "eab-123",
				TenantID: "tenant-1",
				Status:   "valid",
				Purpose:  "account-binding",
			},
			wantError: false,
		},
		{
			name:       "not found",
			tenantID:   "tenant-1",
			kid:        "nonexistent",
			statusCode: http.StatusNotFound,
			response:   `{"error": "EAB not found"}`,
			wantError:  true,
			errContain: "404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID + "/eab/" + tt.kid
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			eab, err := adapter.GetEAB(context.Background(), tt.tenantID, tt.kid)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if eab.ID != tt.kid {
				t.Errorf("expected EAB ID %q, got %q", tt.kid, eab.ID)
			}
		})
	}
}

// TestDeleteEAB tests the DeleteEAB method.
func TestDeleteEAB(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		kid        string
		statusCode int
		response   string
		wantError  bool
		errContain string
	}{
		{
			name:       "successful delete",
			tenantID:   "tenant-1",
			kid:        "eab-123",
			statusCode: http.StatusNoContent,
			response:   "",
			wantError:  false,
		},
		{
			name:       "not found",
			tenantID:   "tenant-1",
			kid:        "nonexistent",
			statusCode: http.StatusNotFound,
			response:   `{"error": "EAB not found"}`,
			wantError:  true,
			errContain: "404",
		},
		{
			name:       "already used",
			tenantID:   "tenant-1",
			kid:        "used-eab",
			statusCode: http.StatusConflict,
			response:   `{"error": "EAB already used"}`,
			wantError:  true,
			errContain: "409",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected DELETE method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID + "/eab/" + tt.kid
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			err = adapter.DeleteEAB(context.Background(), tt.tenantID, tt.kid)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestListEABs tests the ListEABs method.
func TestListEABs(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		request    *admin.ListEABRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
		wantCount  int
	}{
		{
			name:     "successful list",
			tenantID: "tenant-1",
			request: &admin.ListEABRequest{
				Page:    1,
				PerPage: 10,
			},
			statusCode: http.StatusOK,
			response: map[string]interface{}{
				"items": []*admin.EABInfo{
					{ID: "eab-1", Status: "valid"},
					{ID: "eab-2", Status: "used"},
				},
				"total":    2,
				"page":     1,
				"per_page": 10,
			},
			wantError: false,
			wantCount: 2,
		},
		{
			name:     "internal server error",
			tenantID: "tenant-1",
			request: &admin.ListEABRequest{
				Page:    1,
				PerPage: 10,
			},
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			eabs, pagination, err := adapter.ListEABs(context.Background(), tt.tenantID, tt.request)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(eabs) != tt.wantCount {
				t.Errorf("expected %d EABs, got %d", tt.wantCount, len(eabs))
			}

			if pagination == nil {
				t.Error("expected pagination, got nil")
			}
		})
	}
}

// TestCreateTenantRole tests the CreateTenantRole method.
func TestCreateTenantRole(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		req        *db.CreateRoleRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:     "successful creation",
			tenantID: "tenant-1",
			req: &db.CreateRoleRequest{
				Name:        "admin",
				Permissions: []string{"read", "write"},
			},
			statusCode: http.StatusCreated,
			response: &db.Role{
				ID:          "role-1",
				Name:        "admin",
				TenantID:    "tenant-1",
				Permissions: []string{"read", "write"},
			},
			wantError: false,
		},
		{
			name:     "bad request",
			tenantID: "tenant-1",
			req: &db.CreateRoleRequest{
				Name: "",
			},
			statusCode: http.StatusBadRequest,
			response:   `{"error": "invalid role name"}`,
			wantError:  true,
			errContain: "400",
		},
		{
			name:     "conflict",
			tenantID: "tenant-1",
			req: &db.CreateRoleRequest{
				Name: "existing-role",
			},
			statusCode: http.StatusConflict,
			response:   `{"error": "role already exists"}`,
			wantError:  true,
			errContain: "409",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID + "/roles"
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			role, err := adapter.CreateTenantRole(context.Background(), tt.tenantID, tt.req)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if role.Name != tt.req.Name {
				t.Errorf("expected role name %q, got %q", tt.req.Name, role.Name)
			}
		})
	}
}

// TestGetTenantRole tests the GetTenantRole method.
func TestGetTenantRole(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		roleID     string
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:       "successful get",
			tenantID:   "tenant-1",
			roleID:     "role-1",
			statusCode: http.StatusOK,
			response: &db.Role{
				ID:   "role-1",
				Name: "admin",
			},
			wantError: false,
		},
		{
			name:       "not found",
			tenantID:   "tenant-1",
			roleID:     "nonexistent",
			statusCode: http.StatusNotFound,
			response:   `{"error": "role not found"}`,
			wantError:  true,
			errContain: "404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID + "/roles/" + tt.roleID
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			role, err := adapter.GetTenantRole(context.Background(), tt.tenantID, tt.roleID)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if role.ID != tt.roleID {
				t.Errorf("expected role ID %q, got %q", tt.roleID, role.ID)
			}
		})
	}
}

// TestUpdateTenantRole tests the UpdateTenantRole method.
func TestUpdateTenantRole(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		req        *db.UpdateRoleRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:     "successful update",
			tenantID: "tenant-1",
			req: &db.UpdateRoleRequest{
				ID:          "role-1",
				Name:        "updated-admin",
				Permissions: []string{"read", "write", "delete"},
			},
			statusCode: http.StatusOK,
			response: &db.Role{
				ID:          "role-1",
				Name:        "updated-admin",
				Permissions: []string{"read", "write", "delete"},
			},
			wantError: false,
		},
		{
			name:     "not found",
			tenantID: "tenant-1",
			req: &db.UpdateRoleRequest{
				ID:   "nonexistent",
				Name: "updated",
			},
			statusCode: http.StatusNotFound,
			response:   `{"error": "role not found"}`,
			wantError:  true,
			errContain: "404",
		},
		{
			name:     "system role immutable",
			tenantID: "tenant-1",
			req: &db.UpdateRoleRequest{
				ID:   "system-role",
				Name: "updated",
			},
			statusCode: http.StatusForbidden,
			response:   `{"error": "system role is immutable"}`,
			wantError:  true,
			errContain: "403",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut {
					t.Errorf("expected PUT method, got %s", r.Method)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			role, err := adapter.UpdateTenantRole(context.Background(), tt.tenantID, tt.req)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if role.Name != tt.req.Name {
				t.Errorf("expected name %q, got %q", tt.req.Name, role.Name)
			}
		})
	}
}

// TestDeleteTenantRole tests the DeleteTenantRole method.
func TestDeleteTenantRole(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		roleID     string
		statusCode int
		response   string
		wantError  bool
		errContain string
	}{
		{
			name:       "successful delete",
			tenantID:   "tenant-1",
			roleID:     "role-1",
			statusCode: http.StatusNoContent,
			response:   "",
			wantError:  false,
		},
		{
			name:       "not found",
			tenantID:   "tenant-1",
			roleID:     "nonexistent",
			statusCode: http.StatusNotFound,
			response:   `{"error": "role not found"}`,
			wantError:  true,
			errContain: "404",
		},
		{
			name:       "system role immutable",
			tenantID:   "tenant-1",
			roleID:     "system-role",
			statusCode: http.StatusForbidden,
			response:   `{"error": "system role is immutable"}`,
			wantError:  true,
			errContain: "403",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected DELETE method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID + "/roles/" + tt.roleID
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			err = adapter.DeleteTenantRole(context.Background(), tt.tenantID, tt.roleID)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestListTenantRoles tests the ListTenantRoles method.
func TestListTenantRoles(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		req        *db.ListRolesRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
		wantCount  int
	}{
		{
			name:       "successful list",
			tenantID:   "tenant-1",
			req:        &db.ListRolesRequest{Page: 1, PageSize: 10},
			statusCode: http.StatusOK,
			response: &db.ListRolesResponse{
				Roles: []*db.Role{
					{ID: "role-1", Name: "admin"},
					{ID: "role-2", Name: "viewer"},
				},
				Total:   2,
				HasMore: false,
			},
			wantError: false,
			wantCount: 2,
		},
		{
			name:       "empty list",
			tenantID:   "tenant-1",
			req:        &db.ListRolesRequest{Page: 1, PageSize: 10},
			statusCode: http.StatusOK,
			response: &db.ListRolesResponse{
				Roles:   []*db.Role{},
				Total:   0,
				HasMore: false,
			},
			wantError: false,
			wantCount: 0,
		},
		{
			name:       "internal server error",
			tenantID:   "tenant-1",
			req:        &db.ListRolesRequest{Page: 1, PageSize: 10},
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			result, err := adapter.ListTenantRoles(context.Background(), tt.tenantID, tt.req)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(result.Roles) != tt.wantCount {
				t.Errorf("expected %d roles, got %d", tt.wantCount, len(result.Roles))
			}
		})
	}
}

// TestCreateTenantUser tests the CreateTenantUser method.
func TestCreateTenantUser(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		req        *db.CreateUserRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:     "successful creation",
			tenantID: "tenant-1",
			req: &db.CreateUserRequest{
				Username: "testuser",
				RoleIDs:  []string{"role-1"},
			},
			statusCode: http.StatusCreated,
			response: &db.User{
				ID:       1,
				Username: "testuser",
				TenantID: "tenant-1",
				RoleIDs:  []string{"role-1"},
				Enabled:  true,
			},
			wantError: false,
		},
		{
			name:     "bad request",
			tenantID: "tenant-1",
			req: &db.CreateUserRequest{
				Username: "",
			},
			statusCode: http.StatusBadRequest,
			response:   `{"error": "invalid username"}`,
			wantError:  true,
			errContain: "400",
		},
		{
			name:     "conflict",
			tenantID: "tenant-1",
			req: &db.CreateUserRequest{
				Username: "existing-user",
			},
			statusCode: http.StatusConflict,
			response:   `{"error": "user already exists"}`,
			wantError:  true,
			errContain: "409",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID + "/users"
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			user, err := adapter.CreateTenantUser(context.Background(), tt.tenantID, tt.req)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if user.Username != tt.req.Username {
				t.Errorf("expected username %q, got %q", tt.req.Username, user.Username)
			}
		})
	}
}

// TestGetTenantUser tests the GetTenantUser method.
func TestGetTenantUser(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		userID     string
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:       "successful get",
			tenantID:   "tenant-1",
			userID:     "user-1",
			statusCode: http.StatusOK,
			response: &db.User{
				ID:       1,
				Username: "testuser",
			},
			wantError: false,
		},
		{
			name:       "not found",
			tenantID:   "tenant-1",
			userID:     "nonexistent",
			statusCode: http.StatusNotFound,
			response:   `{"error": "user not found"}`,
			wantError:  true,
			errContain: "404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID + "/users/" + tt.userID
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			user, err := adapter.GetTenantUser(context.Background(), tt.tenantID, tt.userID)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if user.Username == "" {
				t.Errorf("expected a decoded user for %q, got empty username", tt.userID)
			}
		})
	}
}

// TestUpdateTenantUser tests the UpdateTenantUser method.
func TestUpdateTenantUser(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		req        *db.UpdateUserRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:     "successful update",
			tenantID: "tenant-1",
			req: &db.UpdateUserRequest{
				ID:       1,
				Username: "updated-user",
				RoleIDs:  []string{"role-1", "role-2"},
			},
			statusCode: http.StatusOK,
			response: &db.User{
				ID:       1,
				Username: "updated-user",
				RoleIDs:  []string{"role-1", "role-2"},
			},
			wantError: false,
		},
		{
			name:     "not found",
			tenantID: "tenant-1",
			req: &db.UpdateUserRequest{
				ID:       999,
				Username: "updated",
			},
			statusCode: http.StatusNotFound,
			response:   `{"error": "user not found"}`,
			wantError:  true,
			errContain: "404",
		},
		{
			name:     "system user immutable",
			tenantID: "tenant-1",
			req: &db.UpdateUserRequest{
				ID:       100,
				Username: "updated",
			},
			statusCode: http.StatusForbidden,
			response:   `{"error": "system user is immutable"}`,
			wantError:  true,
			errContain: "403",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut {
					t.Errorf("expected PUT method, got %s", r.Method)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			user, err := adapter.UpdateTenantUser(context.Background(), tt.tenantID, tt.req)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if user.Username != tt.req.Username {
				t.Errorf("expected username %q, got %q", tt.req.Username, user.Username)
			}
		})
	}
}

// TestDeleteTenantUser tests the DeleteTenantUser method.
func TestDeleteTenantUser(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		userID     string
		statusCode int
		response   string
		wantError  bool
		errContain string
	}{
		{
			name:       "successful delete",
			tenantID:   "tenant-1",
			userID:     "user-1",
			statusCode: http.StatusNoContent,
			response:   "",
			wantError:  false,
		},
		{
			name:       "not found",
			tenantID:   "tenant-1",
			userID:     "nonexistent",
			statusCode: http.StatusNotFound,
			response:   `{"error": "user not found"}`,
			wantError:  true,
			errContain: "404",
		},
		{
			name:       "system user immutable",
			tenantID:   "tenant-1",
			userID:     "system-user",
			statusCode: http.StatusForbidden,
			response:   `{"error": "system user is immutable"}`,
			wantError:  true,
			errContain: "403",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected DELETE method, got %s", r.Method)
				}
				expectedPath := "/api/v1/tenants/" + tt.tenantID + "/users/" + tt.userID
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			err = adapter.DeleteTenantUser(context.Background(), tt.tenantID, tt.userID)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestListTenantUsers tests the ListTenantUsers method.
func TestListTenantUsers(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		req        *db.ListUsersRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
		wantCount  int
	}{
		{
			name:       "successful list",
			tenantID:   "tenant-1",
			req:        &db.ListUsersRequest{Page: 1, PageSize: 10},
			statusCode: http.StatusOK,
			response: &db.ListUsersResponse{
				Users: []*db.User{
					{ID: 1, Username: "alice"},
					{ID: 2, Username: "bob"},
				},
				Total:   2,
				HasMore: false,
			},
			wantError: false,
			wantCount: 2,
		},
		{
			name:       "empty list",
			tenantID:   "tenant-1",
			req:        &db.ListUsersRequest{Page: 1, PageSize: 10},
			statusCode: http.StatusOK,
			response: &db.ListUsersResponse{
				Users:   []*db.User{},
				Total:   0,
				HasMore: false,
			},
			wantError: false,
			wantCount: 0,
		},
		{
			name:       "internal server error",
			tenantID:   "tenant-1",
			req:        &db.ListUsersRequest{Page: 1, PageSize: 10},
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			result, err := adapter.ListTenantUsers(context.Background(), tt.tenantID, tt.req)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(result.Users) != tt.wantCount {
				t.Errorf("expected %d users, got %d", tt.wantCount, len(result.Users))
			}
		})
	}
}

// TestListCertificates tests the ListCertificates method.
func TestListCertificates(t *testing.T) {
	tests := []struct {
		name       string
		request    *admin.ListCertificatesRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
		wantCount  int
	}{
		{
			name: "successful list",
			request: &admin.ListCertificatesRequest{
				Page:    1,
				PerPage: 10,
			},
			statusCode: http.StatusOK,
			response: map[string]interface{}{
				"items": []*admin.CertificateInfo{
					{ID: 1, SerialNumber: "abc123", Subject: "CN=test1"},
					{ID: 2, SerialNumber: "def456", Subject: "CN=test2"},
				},
				"total":    2,
				"page":     1,
				"per_page": 10,
			},
			wantError: false,
			wantCount: 2,
		},
		{
			name: "internal server error",
			request: &admin.ListCertificatesRequest{
				Page:    1,
				PerPage: 10,
			},
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}
				if !strings.HasPrefix(r.URL.Path, "/admin/certificates") {
					t.Errorf("expected path to start with /admin/certificates, got %s", r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			certs, pagination, err := adapter.ListCertificates(context.Background(), tt.request)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(certs) != tt.wantCount {
				t.Errorf("expected %d certificates, got %d", tt.wantCount, len(certs))
			}

			if pagination == nil {
				t.Error("expected pagination, got nil")
			}
		})
	}
}

// TestGetCertificate tests the GetCertificate method.
func TestGetCertificate(t *testing.T) {
	tests := []struct {
		name       string
		serial     string
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:       "successful get",
			serial:     "abc123",
			statusCode: http.StatusOK,
			response: &admin.CertificateInfo{
				ID:           1,
				SerialNumber: "abc123",
				Subject:      "CN=test",
				Status:       "valid",
			},
			wantError: false,
		},
		{
			name:       "not found",
			serial:     "nonexistent",
			statusCode: http.StatusNotFound,
			response:   `{"error": "certificate not found"}`,
			wantError:  true,
			errContain: "404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}
				expectedPath := "/admin/certificates/" + tt.serial
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			cert, err := adapter.GetCertificate(context.Background(), tt.serial)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cert.SerialNumber != tt.serial {
				t.Errorf("expected serial %q, got %q", tt.serial, cert.SerialNumber)
			}
		})
	}
}

// TestRevokeCertificate tests the RevokeCertificate method.
func TestRevokeCertificate(t *testing.T) {
	tests := []struct {
		name       string
		serial     string
		reason     string
		statusCode int
		response   string
		wantError  bool
		errContain string
	}{
		{
			name:       "successful revoke",
			serial:     "abc123",
			reason:     "keyCompromise",
			statusCode: http.StatusOK,
			response:   "",
			wantError:  false,
		},
		{
			name:       "not found",
			serial:     "nonexistent",
			reason:     "keyCompromise",
			statusCode: http.StatusNotFound,
			response:   `{"error": "certificate not found"}`,
			wantError:  true,
			errContain: "404",
		},
		{
			name:       "already revoked",
			serial:     "revoked-cert",
			reason:     "keyCompromise",
			statusCode: http.StatusConflict,
			response:   `{"error": "certificate already revoked"}`,
			wantError:  true,
			errContain: "409",
		},
		{
			name:       "invalid reason",
			serial:     "abc123",
			reason:     "invalid-reason",
			statusCode: http.StatusBadRequest,
			response:   `{"error": "invalid revocation reason"}`,
			wantError:  true,
			errContain: "400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST method, got %s", r.Method)
				}
				expectedPath := "/admin/certificates/" + tt.serial + "/revoke"
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				// Verify request body contains reason
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
					if body["reason"] != tt.reason {
						t.Errorf("expected reason %q, got %q", tt.reason, body["reason"])
					}
				}

				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			err = adapter.RevokeCertificate(context.Background(), tt.serial, tt.reason)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestListAccounts tests the ListAccounts method.
func TestListAccounts(t *testing.T) {
	tests := []struct {
		name       string
		request    *admin.ListAccountsRequest
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
		wantCount  int
	}{
		{
			name: "successful list",
			request: &admin.ListAccountsRequest{
				Page:    1,
				PerPage: 10,
			},
			statusCode: http.StatusOK,
			response: map[string]interface{}{
				"items": []*admin.AccountInfo{
					{ID: 1, Status: "valid", Contact: []string{"mailto:test@example.com"}},
					{ID: 2, Status: "deactivated", Contact: []string{"mailto:test2@example.com"}},
				},
				"total":    2,
				"page":     1,
				"per_page": 10,
			},
			wantError: false,
			wantCount: 2,
		},
		{
			name: "successful list with status filter",
			request: &admin.ListAccountsRequest{
				Page:    1,
				PerPage: 10,
				Status:  "valid",
			},
			statusCode: http.StatusOK,
			response: map[string]interface{}{
				"items": []*admin.AccountInfo{
					{ID: 1, Status: "valid", Contact: []string{"mailto:test@example.com"}},
				},
				"total":    1,
				"page":     1,
				"per_page": 10,
			},
			wantError: false,
			wantCount: 1,
		},
		{
			name: "empty list",
			request: &admin.ListAccountsRequest{
				Page:    1,
				PerPage: 10,
			},
			statusCode: http.StatusOK,
			response: map[string]interface{}{
				"items":    []*admin.AccountInfo{},
				"total":    0,
				"page":     1,
				"per_page": 10,
			},
			wantError: false,
			wantCount: 0,
		},
		{
			name: "internal server error",
			request: &admin.ListAccountsRequest{
				Page:    1,
				PerPage: 10,
			},
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
		{
			name: "unauthorized error",
			request: &admin.ListAccountsRequest{
				Page:    1,
				PerPage: 10,
			},
			statusCode: http.StatusUnauthorized,
			response:   `{"error": "unauthorized"}`,
			wantError:  true,
			errContain: "401",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}
				if !strings.HasPrefix(r.URL.Path, "/admin/accounts") {
					t.Errorf("expected path to start with /admin/accounts, got %s", r.URL.Path)
				}

				// Verify query parameters
				query := r.URL.Query()
				if tt.request.Status != "" && query.Get("status") != tt.request.Status {
					t.Errorf("expected status query param %q, got %q", tt.request.Status, query.Get("status"))
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			accounts, pagination, err := adapter.ListAccounts(context.Background(), tt.request)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(accounts) != tt.wantCount {
				t.Errorf("expected %d accounts, got %d", tt.wantCount, len(accounts))
			}

			if pagination == nil {
				t.Error("expected pagination, got nil")
			}
		})
	}
}

// TestListAccountsDoRequestError tests ListAccounts when doRequest fails.
func TestListAccountsDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _, err = adapter.ListAccounts(ctx, &admin.ListAccountsRequest{Page: 1, PerPage: 10})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestGetAccount tests the GetAccount method.
func TestGetAccount(t *testing.T) {
	tests := []struct {
		name       string
		accountID  uint64
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:       "successful get",
			accountID:  123,
			statusCode: http.StatusOK,
			response: &admin.AccountInfo{
				ID:                   123,
				Status:               "valid",
				Contact:              []string{"mailto:test@example.com"},
				TermsOfServiceAgreed: true,
				OrderCount:           5,
			},
			wantError: false,
		},
		{
			name:       "not found",
			accountID:  999,
			statusCode: http.StatusNotFound,
			response:   `{"error": "account not found"}`,
			wantError:  true,
			errContain: "404",
		},
		{
			name:       "internal server error",
			accountID:  123,
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
		{
			name:       "unauthorized error",
			accountID:  123,
			statusCode: http.StatusUnauthorized,
			response:   `{"error": "unauthorized"}`,
			wantError:  true,
			errContain: "401",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}
				expectedPath := "/admin/accounts/123"
				if tt.accountID == 999 {
					expectedPath = "/admin/accounts/999"
				}
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			account, err := adapter.GetAccount(context.Background(), tt.accountID)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if uint64(account.ID) != tt.accountID {
				t.Errorf("expected account ID %d, got %d", tt.accountID, account.ID)
			}
		})
	}
}

// TestGetAccountDoRequestError tests GetAccount when doRequest fails.
func TestGetAccountDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.GetAccount(ctx, 123)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDisableAccount tests the DisableAccount method.
func TestDisableAccount(t *testing.T) {
	tests := []struct {
		name       string
		accountID  uint64
		statusCode int
		response   string
		wantError  bool
		errContain string
	}{
		{
			name:       "successful disable",
			accountID:  123,
			statusCode: http.StatusOK,
			response:   "",
			wantError:  false,
		},
		{
			name:       "not found",
			accountID:  999,
			statusCode: http.StatusNotFound,
			response:   `{"error": "account not found"}`,
			wantError:  true,
			errContain: "404",
		},
		{
			name:       "already disabled",
			accountID:  456,
			statusCode: http.StatusConflict,
			response:   `{"error": "account already disabled"}`,
			wantError:  true,
			errContain: "409",
		},
		{
			name:       "internal server error",
			accountID:  123,
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
		{
			name:       "unauthorized error",
			accountID:  123,
			statusCode: http.StatusUnauthorized,
			response:   `{"error": "unauthorized"}`,
			wantError:  true,
			errContain: "401",
		},
		{
			name:       "forbidden error",
			accountID:  123,
			statusCode: http.StatusForbidden,
			response:   `{"error": "forbidden"}`,
			wantError:  true,
			errContain: "403",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST method, got %s", r.Method)
				}

				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			err = adapter.DisableAccount(context.Background(), tt.accountID)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestDisableAccountDoRequestError tests DisableAccount when doRequest fails.
func TestDisableAccountDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = adapter.DisableAccount(ctx, 123)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestGetStatus tests the GetStatus method.
func TestGetStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:       "successful get",
			statusCode: http.StatusOK,
			response: &admin.CAStatus{
				Identity:      "test-ca",
				Initialized:   true,
				Version:       "1.0.0",
				KeyAlgorithm:  "ECDSA-P256",
				SignatureAlgo: "SHA256WithECDSA",
				RootCA:        "CN=Test Root CA",
			},
			wantError: false,
		},
		{
			name:       "internal server error",
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
		{
			name:       "service unavailable",
			statusCode: http.StatusServiceUnavailable,
			response:   `{"error": "service unavailable"}`,
			wantError:  true,
			errContain: "503",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}
				if r.URL.Path != "/admin/status" {
					t.Errorf("expected path /admin/status, got %s", r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			status, err := adapter.GetStatus(context.Background())

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if status.Identity == "" {
				t.Error("expected non-empty identity")
			}
		})
	}
}

// TestGetStats tests the GetStats method.
func TestGetStats(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   interface{}
		wantError  bool
		errContain string
	}{
		{
			name:       "successful get",
			statusCode: http.StatusOK,
			response: &admin.CAStats{
				TotalCertificates:   100,
				ValidCertificates:   90,
				RevokedCertificates: 5,
				ExpiredCertificates: 5,
				TotalAccounts:       50,
				ActiveAccounts:      45,
				TotalOrders:         200,
				PendingOrders:       10,
				CompletedOrders:     190,
			},
			wantError: false,
		},
		{
			name:       "internal server error",
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "internal error"}`,
			wantError:  true,
			errContain: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET method, got %s", r.Method)
				}
				if r.URL.Path != "/admin/stats" {
					t.Errorf("expected path /admin/stats, got %s", r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				switch v := tt.response.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			stats, err := adapter.GetStats(context.Background())

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if stats.TotalCertificates == 0 && stats.TotalAccounts == 0 {
				t.Error("expected non-zero stats")
			}
		})
	}
}

// TestDoRequestMarshalError tests that doRequest handles marshal errors correctly.
func TestDoRequestMarshalError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not have been made")
	}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	// Create a value that cannot be marshaled to JSON
	badValue := make(chan int)

	_, err = adapter.doRequest(context.Background(), http.MethodPost, "/test", badValue)
	if err == nil {
		t.Error("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to marshal") {
		t.Errorf("expected marshal error, got %q", err.Error())
	}
}

// TestDoRequestContextCancellation tests that doRequest respects context cancellation.
func TestDoRequestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = adapter.doRequest(ctx, http.MethodGet, "/test", nil)
	if err == nil {
		t.Error("expected error due to context cancellation")
	}
}

// TestDoRequestWithoutAuthToken tests that requests work without auth token.
func TestDoRequestWithoutAuthToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("expected no Authorization header")
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(&admin.CAStatus{Identity: "test"})
	}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{
		BaseURL: server.URL,
		// No auth token
	})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	status, err := adapter.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.Identity != "test" {
		t.Errorf("expected identity 'test', got %q", status.Identity)
	}
}

// TestDecodeResponseInvalidJSON tests decodeResponse with invalid JSON.
func TestDecodeResponseInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json{"))
	}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	_, err = adapter.GetStatus(context.Background())
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// TestInterfaceCompliance verifies that Adapter implements AdminAdapter.
func TestInterfaceCompliance(t *testing.T) {
	var _ api.AdminAdapter = (*Adapter)(nil)
}

// TestAdapterHeadersSet verifies that Content-Type and Accept headers are set correctly.
func TestAdapterHeadersSet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept application/json, got %s", r.Header.Get("Accept"))
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(&admin.CAStatus{Identity: "test"})
	}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	_, err = adapter.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDoRequestWithNilBody verifies requests work with nil body.
func TestDoRequestWithNilBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(&admin.CAStatus{Identity: "test"})
	}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	resp, err := adapter.doRequest(context.Background(), http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

// TestCreateTenantDoRequestError tests CreateTenant when doRequest fails.
func TestCreateTenantDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.CreateTenant(ctx, &admin.CreateTenantRequest{ID: "test"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestGetTenantDoRequestError tests GetTenant when doRequest fails.
func TestGetTenantDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.GetTenant(ctx, "test")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestUpdateTenantDoRequestError tests UpdateTenant when doRequest fails.
func TestUpdateTenantDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.UpdateTenant(ctx, "test", &admin.UpdateTenantRequest{Name: "updated"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDeleteTenantDoRequestError tests DeleteTenant when doRequest fails.
func TestDeleteTenantDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = adapter.DeleteTenant(ctx, "test")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestListTenantsDoRequestError tests ListTenants when doRequest fails.
func TestListTenantsDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _, err = adapter.ListTenants(ctx, &admin.ListTenantsRequest{Page: 1, PerPage: 10})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestCreateEABDoRequestError tests CreateEAB when doRequest fails.
func TestCreateEABDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.CreateEAB(ctx, "tenant-1", &admin.CreateEABRequest{Purpose: "account-binding"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestGetEABDoRequestError tests GetEAB when doRequest fails.
func TestGetEABDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.GetEAB(ctx, "tenant-1", "eab-123")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDeleteEABDoRequestError tests DeleteEAB when doRequest fails.
func TestDeleteEABDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = adapter.DeleteEAB(ctx, "tenant-1", "eab-123")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestListEABsDoRequestError tests ListEABs when doRequest fails.
func TestListEABsDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _, err = adapter.ListEABs(ctx, "tenant-1", &admin.ListEABRequest{Page: 1, PerPage: 10})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestCreateTenantRoleDoRequestError tests CreateTenantRole when doRequest fails.
func TestCreateTenantRoleDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.CreateTenantRole(ctx, "tenant-1", &db.CreateRoleRequest{Name: "test"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestGetTenantRoleDoRequestError tests GetTenantRole when doRequest fails.
func TestGetTenantRoleDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.GetTenantRole(ctx, "tenant-1", "role-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestUpdateTenantRoleDoRequestError tests UpdateTenantRole when doRequest fails.
func TestUpdateTenantRoleDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.UpdateTenantRole(ctx, "tenant-1", &db.UpdateRoleRequest{ID: "role-1", Name: "test"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDeleteTenantRoleDoRequestError tests DeleteTenantRole when doRequest fails.
func TestDeleteTenantRoleDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = adapter.DeleteTenantRole(ctx, "tenant-1", "role-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestListTenantRolesDoRequestError tests ListTenantRoles when doRequest fails.
func TestListTenantRolesDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.ListTenantRoles(ctx, "tenant-1", &db.ListRolesRequest{Page: 1, PageSize: 10})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestCreateTenantUserDoRequestError tests CreateTenantUser when doRequest fails.
func TestCreateTenantUserDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.CreateTenantUser(ctx, "tenant-1", &db.CreateUserRequest{Username: "test"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestGetTenantUserDoRequestError tests GetTenantUser when doRequest fails.
func TestGetTenantUserDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.GetTenantUser(ctx, "tenant-1", "user-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestUpdateTenantUserDoRequestError tests UpdateTenantUser when doRequest fails.
func TestUpdateTenantUserDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.UpdateTenantUser(ctx, "tenant-1", &db.UpdateUserRequest{ID: 1, Username: "test"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDeleteTenantUserDoRequestError tests DeleteTenantUser when doRequest fails.
func TestDeleteTenantUserDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = adapter.DeleteTenantUser(ctx, "tenant-1", "user-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestListTenantUsersDoRequestError tests ListTenantUsers when doRequest fails.
func TestListTenantUsersDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.ListTenantUsers(ctx, "tenant-1", &db.ListUsersRequest{Page: 1, PageSize: 10})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestListCertificatesDoRequestError tests ListCertificates when doRequest fails.
func TestListCertificatesDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _, err = adapter.ListCertificates(ctx, &admin.ListCertificatesRequest{Page: 1, PerPage: 10})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestGetCertificateDoRequestError tests GetCertificate when doRequest fails.
func TestGetCertificateDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.GetCertificate(ctx, "abc123")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestRevokeCertificateDoRequestError tests RevokeCertificate when doRequest fails.
func TestRevokeCertificateDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = adapter.RevokeCertificate(ctx, "abc123", "keyCompromise")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestGetStatusDoRequestError tests GetStatus when doRequest fails.
func TestGetStatusDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.GetStatus(ctx)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestGetStatsDoRequestError tests GetStats when doRequest fails.
func TestGetStatsDoRequestError(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://invalid-host-that-does-not-exist.local:12345"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = adapter.GetStats(ctx)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestDecodeResponseWithNilTarget tests decodeResponse with nil target.
func TestDecodeResponseWithNilTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	err = adapter.DeleteTenant(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDecodeListResponseErrorPaths tests decodeListResponse error paths.
func TestDecodeListResponseErrorPaths(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		statusCode int
		wantError  bool
		errContain string
	}{
		{
			name:       "RFC 7807 error response",
			response:   `{"type":"urn:trusted-ca:error:not-found","title":"Not Found","detail":"tenant not found","status":404}`,
			statusCode: http.StatusNotFound,
			wantError:  true,
			errContain: "tenant not found",
		},
		{
			name:       "generic HTTP error",
			response:   `{"error": "internal error"}`,
			statusCode: http.StatusInternalServerError,
			wantError:  true,
			errContain: "500",
		},
		{
			name:       "invalid json in paginated response",
			response:   `invalid json{`,
			statusCode: http.StatusOK,
			wantError:  true,
			errContain: "failed to decode paginated response",
		},
		{
			name:       "invalid items field type",
			response:   `{"items": "not an array", "total": 1, "page": 1, "per_page": 10}`,
			statusCode: http.StatusOK,
			wantError:  true,
			errContain: "failed to decode items",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatalf("unexpected error creating adapter: %v", err)
			}

			// Use ListTenants which calls decodeListResponse
			_, _, err = adapter.ListTenants(context.Background(), &admin.ListTenantsRequest{Page: 1, PerPage: 10})

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error containing %q, got %q", tt.errContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestDecodeResponseDirectAPIResponse tests decodeResponse with direct API response format.
func TestDecodeResponseDirectAPIResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Return data directly without envelope wrapper
		response := &admin.CAStatus{
			Identity:    "test-ca",
			Initialized: true,
			Version:     "1.0.0",
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	status, err := adapter.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.Identity != "test-ca" {
		t.Errorf("expected identity 'test-ca', got %q", status.Identity)
	}
}

// TestDecodeResponseDirectFormat tests decodeResponse with direct response format.
func TestDecodeResponseDirectFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Return a direct (non-wrapped) response
		response := &admin.CAStatus{
			Identity:    "direct-ca",
			Initialized: true,
			Version:     "2.0.0",
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	status, err := adapter.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.Identity != "direct-ca" {
		t.Errorf("expected identity 'direct-ca', got %q", status.Identity)
	}
}

// TestDecodeListResponseWithPagination tests decodeListResponse with paginated response.
func TestDecodeListResponseWithPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"items": []*admin.TenantInfo{
				{ID: "tenant-1", Name: "Tenant 1"},
			},
			"total":    1,
			"page":     1,
			"per_page": 10,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	tenants, pagination, err := adapter.ListTenants(context.Background(), &admin.ListTenantsRequest{Page: 1, PerPage: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tenants) != 1 {
		t.Errorf("expected 1 tenant, got %d", len(tenants))
	}

	if pagination == nil {
		t.Fatal("expected non-nil pagination")
	}
	if pagination.Total != 1 {
		t.Errorf("expected total 1, got %d", pagination.Total)
	}
}

// TestDecodeListResponseEmptyItems tests decodeListResponse with empty items.
func TestDecodeListResponseEmptyItems(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"items":    []*admin.TenantInfo{},
			"total":    0,
			"page":     1,
			"per_page": 10,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	tenants, pagination, err := adapter.ListTenants(context.Background(), &admin.ListTenantsRequest{Page: 1, PerPage: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tenants) != 0 {
		t.Errorf("expected 0 tenants, got %d", len(tenants))
	}

	if pagination == nil {
		t.Fatal("expected non-nil pagination")
	}
	if pagination.Total != 0 {
		t.Errorf("expected total 0, got %d", pagination.Total)
	}
}

// TestDoRequestInvalidURL tests doRequest with an invalid URL that causes request creation to fail.
func TestDoRequestInvalidURL(t *testing.T) {
	// Create adapter with a valid-looking but problematic base URL
	adapter, err := NewAdapter(&api.AdapterConfig{BaseURL: "http://localhost:8080"})
	if err != nil {
		t.Fatalf("unexpected error creating adapter: %v", err)
	}

	// Use a URL path with control characters that will cause NewRequestWithContext to fail
	_, err = adapter.doRequest(context.Background(), http.MethodGet, string([]byte{0x7f}), nil)
	if err == nil {
		t.Error("expected error for invalid URL, got nil")
	}

	if !strings.Contains(err.Error(), "failed to create request") {
		t.Errorf("expected 'failed to create request' error, got %q", err.Error())
	}
}
