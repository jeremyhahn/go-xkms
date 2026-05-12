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

package mcp

import (
	"context"
	"encoding/json"
	"io"
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

// mockMCPHandler creates a test handler that responds to JSON-RPC requests.
type mockMCPHandler struct {
	t              *testing.T
	responses      map[string]interface{}
	errors         map[string]*JSONRPCError
	statusCode     int
	expectAuth     string
	validateParams func(method string, params json.RawMessage) error
}

func newMockMCPHandler(t *testing.T) *mockMCPHandler {
	return &mockMCPHandler{
		t:          t,
		responses:  make(map[string]interface{}),
		errors:     make(map[string]*JSONRPCError),
		statusCode: http.StatusOK,
	}
}

func (h *mockMCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Verify content type
	if r.Header.Get("Content-Type") != "application/json" {
		h.t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
	}

	// Verify accept header
	if r.Header.Get("Accept") != "application/json" {
		h.t.Errorf("Expected Accept application/json, got %s", r.Header.Get("Accept"))
	}

	// Verify auth token if expected
	if h.expectAuth != "" {
		authHeader := r.Header.Get("Authorization")
		expected := "Bearer " + h.expectAuth
		if authHeader != expected {
			h.t.Errorf("Expected Authorization '%s', got '%s'", expected, authHeader)
		}
	}

	// Verify path
	if r.URL.Path != "/mcp" {
		h.t.Errorf("Expected path /mcp, got %s", r.URL.Path)
	}

	// Read and parse request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.t.Fatalf("Failed to read request body: %v", err)
	}
	defer r.Body.Close()

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.t.Fatalf("Failed to parse JSON-RPC request: %v", err)
	}

	// Validate JSON-RPC version
	if req.JSONRPC != "2.0" {
		h.t.Errorf("Expected JSON-RPC version 2.0, got %s", req.JSONRPC)
	}

	// Validate params if handler provided
	if h.validateParams != nil {
		paramsBytes, _ := json.Marshal(req.Params)
		if err := h.validateParams(req.Method, paramsBytes); err != nil {
			h.t.Errorf("Params validation failed: %v", err)
		}
	}

	// Return configured status code
	if h.statusCode != http.StatusOK {
		w.WriteHeader(h.statusCode)
		w.Write([]byte("error response"))
		return
	}

	// Build response
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	// Check for configured error
	if err, ok := h.errors[req.Method]; ok {
		resp.Error = err
	} else if result, ok := h.responses[req.Method]; ok {
		resultBytes, _ := json.Marshal(result)
		resp.Result = resultBytes
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func TestNewAdapter(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		config := &api.AdapterConfig{
			MCPAddr:   "localhost:9445",
			AuthToken: "test-token",
		}
		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		if adapter == nil {
			t.Fatal("NewAdapter() returned nil")
		}
		if adapter.baseURL != "http://localhost:9445" {
			t.Errorf("Expected baseURL http://localhost:9445, got %s", adapter.baseURL)
		}
		if adapter.authToken != "test-token" {
			t.Errorf("Expected authToken test-token, got %s", adapter.authToken)
		}
	})

	t.Run("empty MCP address error", func(t *testing.T) {
		config := &api.AdapterConfig{
			MCPAddr: "",
		}
		_, err := NewAdapter(config)
		if err == nil {
			t.Error("Expected error for empty MCP address")
		}
		if !strings.Contains(err.Error(), "MCP address is required") {
			t.Errorf("Expected 'MCP address is required' error, got: %v", err)
		}
	})

	t.Run("with empty TLS config", func(t *testing.T) {
		config := &api.AdapterConfig{
			MCPAddr:   "localhost:9445",
			TLSConfig: &api.TLSConfig{},
		}
		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() with TLS failed: %v", err)
		}
		defer adapter.Close()
	})

	t.Run("with valid CA certificate", func(t *testing.T) {
		// Create a temporary CA certificate file
		tmpDir := t.TempDir()
		caFile := filepath.Join(tmpDir, "ca.pem")
		// Write a minimal PEM-encoded certificate (not valid for signing, just for loading)
		caPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKZdQCXJYnhPMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RDQTAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RDQTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96FCFxjPqFhLwg0IUUL
h6T6hJ2FH7m7fT7C9m3NQJ/dWYZwSBFl7mDVfBJM8GwxpQQX4CnPBZ9lrQhxQMXn
AgMBAAGjUzBRMB0GA1UdDgQWBBR1fLmMUMQsIXuSCJ7xyQzTxQGEYDAfBgNVHSME
GDAWgBR1fLmMUMQsIXuSCJ7xyQzTxQGEYDAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAE8PhfR2wJlEP8m7cJ8OMJrHw5GrOFw5YBW9YKQfnpEUqClzM
t9rjKnWm9k9M8NEgZ8gPgP9mD3mBkZ9OA6qzZA==
-----END CERTIFICATE-----`
		if err := os.WriteFile(caFile, []byte(caPEM), 0600); err != nil {
			t.Fatalf("Failed to write CA file: %v", err)
		}

		config := &api.AdapterConfig{
			MCPAddr: "localhost:9445",
			TLSConfig: &api.TLSConfig{
				CAFile: caFile,
			},
		}
		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() with CA certificate failed: %v", err)
		}
		defer adapter.Close()
	})

	t.Run("without auth token", func(t *testing.T) {
		config := &api.AdapterConfig{
			MCPAddr: "localhost:9445",
		}
		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()
		if adapter.authToken != "" {
			t.Errorf("Expected empty authToken, got '%s'", adapter.authToken)
		}
	})

	t.Run("nil TLS config", func(t *testing.T) {
		config := &api.AdapterConfig{
			MCPAddr:   "localhost:9445",
			TLSConfig: nil,
		}
		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()
	})
}

func TestAdapterProtocol(t *testing.T) {
	handler := newMockMCPHandler(t)
	server := httptest.NewServer(handler)
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "http://")
	adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
	if err != nil {
		t.Fatalf("NewAdapter() failed: %v", err)
	}
	defer adapter.Close()

	if adapter.Protocol() != api.ProtocolMCP {
		t.Errorf("Expected ProtocolMCP, got %v", adapter.Protocol())
	}
}

func TestAdapterClose(t *testing.T) {
	handler := newMockMCPHandler(t)
	server := httptest.NewServer(handler)
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "http://")
	adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
	if err != nil {
		t.Fatalf("NewAdapter() failed: %v", err)
	}

	err = adapter.Close()
	if err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

func TestAdapterInterfaceCompliance(t *testing.T) {
	var _ api.AdminAdapter = (*Adapter)(nil)
}

func TestAdapterJSONRPCCall(t *testing.T) {
	t.Run("successful call with auth token", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.expectAuth = "my-secret-token"
		handler.responses["test.method"] = map[string]string{"result": "success"}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{
			MCPAddr:   addr,
			AuthToken: "my-secret-token",
		})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		var result map[string]string
		err = adapter.call(ctx, "test.method", nil, &result)
		if err != nil {
			t.Fatalf("call() failed: %v", err)
		}
		if result["result"] != "success" {
			t.Errorf("Expected result 'success', got %v", result)
		}
	})

	t.Run("successful call without auth token", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["test.method"] = map[string]string{"result": "success"}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{
			MCPAddr: addr,
		})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		var result map[string]string
		err = adapter.call(ctx, "test.method", nil, &result)
		if err != nil {
			t.Fatalf("call() failed: %v", err)
		}
	})

	t.Run("call with HTTP error status", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.statusCode = http.StatusInternalServerError
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		var result interface{}
		err = adapter.call(ctx, "test.method", nil, &result)
		if err == nil {
			t.Error("Expected error for HTTP error status")
		}
		if !strings.Contains(err.Error(), "request failed with status 500") {
			t.Errorf("Expected status 500 error, got: %v", err)
		}
	})

	t.Run("call with JSON-RPC error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["test.method"] = &JSONRPCError{
			Code:    -32600,
			Message: "Invalid Request",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		var result interface{}
		err = adapter.call(ctx, "test.method", nil, &result)
		if err == nil {
			t.Error("Expected error for JSON-RPC error")
		}
		if !strings.Contains(err.Error(), "RPC error -32600: Invalid Request") {
			t.Errorf("Expected RPC error, got: %v", err)
		}
	})

	t.Run("call with context timeout", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
		})
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		var result interface{}
		err = adapter.call(ctx, "test.method", nil, &result)
		if err == nil {
			t.Error("Expected error for context timeout")
		}
	})

	t.Run("call with invalid response JSON", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not valid json"))
		})
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		var result interface{}
		err = adapter.call(ctx, "test.method", nil, &result)
		if err == nil {
			t.Error("Expected error for invalid response JSON")
		}
		if !strings.Contains(err.Error(), "failed to decode response") {
			t.Errorf("Expected decode error, got: %v", err)
		}
	})

	t.Run("call with nil result parameter", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["test.method"] = map[string]string{"ignored": "value"}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		err = adapter.call(ctx, "test.method", nil, nil)
		if err != nil {
			t.Errorf("call() with nil result should succeed: %v", err)
		}
	})

	t.Run("call with invalid result unmarshal", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		// Return a response that cannot be unmarshaled into an int
		handler.responses["test.method"] = map[string]string{"key": "value"}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		var result int // wrong type for the response
		err = adapter.call(ctx, "test.method", nil, &result)
		if err == nil {
			t.Error("Expected error for invalid result unmarshal")
		}
		if !strings.Contains(err.Error(), "failed to unmarshal result") {
			t.Errorf("Expected unmarshal error, got: %v", err)
		}
	})

	t.Run("request ID increments", func(t *testing.T) {
		var requestIDs []int64
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var req JSONRPCRequest
			json.Unmarshal(body, &req)
			requestIDs = append(requestIDs, req.ID)
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
			json.NewEncoder(w).Encode(resp)
		})
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		adapter.call(ctx, "method1", nil, nil)
		adapter.call(ctx, "method2", nil, nil)
		adapter.call(ctx, "method3", nil, nil)

		if len(requestIDs) != 3 {
			t.Fatalf("Expected 3 requests, got %d", len(requestIDs))
		}
		if requestIDs[0] != 1 || requestIDs[1] != 2 || requestIDs[2] != 3 {
			t.Errorf("Expected IDs [1,2,3], got %v", requestIDs)
		}
	})
}

func TestAdapterTenantOperations(t *testing.T) {
	t.Run("CreateTenant success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.createTenant"] = admin.TenantInfo{
			ID:     "tenant-1",
			Name:   "Test Tenant",
			Status: "active",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.CreateTenantRequest{
			ID:   "tenant-1",
			Name: "Test Tenant",
		}
		tenant, err := adapter.CreateTenant(ctx, req)
		if err != nil {
			t.Fatalf("CreateTenant() failed: %v", err)
		}
		if tenant.ID != "tenant-1" {
			t.Errorf("Expected tenant ID 'tenant-1', got '%s'", tenant.ID)
		}
		if tenant.Name != "Test Tenant" {
			t.Errorf("Expected tenant name 'Test Tenant', got '%s'", tenant.Name)
		}
	})

	t.Run("CreateTenant error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.createTenant"] = &JSONRPCError{
			Code:    -32000,
			Message: "tenant already exists",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.CreateTenantRequest{ID: "tenant-1", Name: "Test"}
		_, err = adapter.CreateTenant(ctx, req)
		if err == nil {
			t.Error("Expected error for CreateTenant")
		}
	})

	t.Run("GetTenant success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.getTenant"] = admin.TenantInfo{
			ID:     "tenant-1",
			Name:   "Test Tenant",
			Status: "active",
		}
		handler.validateParams = func(method string, params json.RawMessage) error {
			if method == "admin.getTenant" {
				var p map[string]string
				json.Unmarshal(params, &p)
				if p["tenantId"] != "tenant-1" {
					t.Errorf("Expected tenant_id 'tenant-1', got '%s'", p["tenantId"])
				}
			}
			return nil
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		tenant, err := adapter.GetTenant(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("GetTenant() failed: %v", err)
		}
		if tenant.ID != "tenant-1" {
			t.Errorf("Expected tenant ID 'tenant-1', got '%s'", tenant.ID)
		}
	})

	t.Run("GetTenant not found", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.getTenant"] = &JSONRPCError{
			Code:    -32001,
			Message: "tenant not found",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		_, err = adapter.GetTenant(ctx, "nonexistent")
		if err == nil {
			t.Error("Expected error for nonexistent tenant")
		}
	})

	t.Run("UpdateTenant success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.updateTenant"] = admin.TenantInfo{
			ID:     "tenant-1",
			Name:   "Updated Tenant",
			Status: "active",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.UpdateTenantRequest{Name: "Updated Tenant"}
		tenant, err := adapter.UpdateTenant(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("UpdateTenant() failed: %v", err)
		}
		if tenant.Name != "Updated Tenant" {
			t.Errorf("Expected tenant name 'Updated Tenant', got '%s'", tenant.Name)
		}
	})

	t.Run("UpdateTenant error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.updateTenant"] = &JSONRPCError{
			Code:    -32001,
			Message: "tenant not found",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.UpdateTenantRequest{Name: "Updated"}
		_, err = adapter.UpdateTenant(ctx, "nonexistent", req)
		if err == nil {
			t.Error("Expected error for UpdateTenant")
		}
	})

	t.Run("DeleteTenant success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.deleteTenant"] = nil
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		err = adapter.DeleteTenant(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("DeleteTenant() failed: %v", err)
		}
	})

	t.Run("DeleteTenant error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.deleteTenant"] = &JSONRPCError{
			Code:    -32001,
			Message: "cannot delete tenant with active resources",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		err = adapter.DeleteTenant(ctx, "tenant-1")
		if err == nil {
			t.Error("Expected error for DeleteTenant")
		}
	})

	t.Run("ListTenants success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.listTenants"] = map[string]interface{}{
			"tenants": []*admin.TenantInfo{
				{ID: "tenant-1", Name: "Tenant 1"},
				{ID: "tenant-2", Name: "Tenant 2"},
			},
			"pagination": &admin.Pagination{
				Page:    1,
				PerPage: 10,
				Total:   2,
			},
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.ListTenantsRequest{Page: 1, PerPage: 10}
		tenants, pagination, err := adapter.ListTenants(ctx, req)
		if err != nil {
			t.Fatalf("ListTenants() failed: %v", err)
		}
		if len(tenants) != 2 {
			t.Errorf("Expected 2 tenants, got %d", len(tenants))
		}
		if pagination == nil {
			t.Error("Expected pagination, got nil")
		}
	})

	t.Run("ListTenants error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.listTenants"] = &JSONRPCError{
			Code:    -32000,
			Message: "database error",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.ListTenantsRequest{Page: 1, PerPage: 10}
		_, _, err = adapter.ListTenants(ctx, req)
		if err == nil {
			t.Error("Expected error for ListTenants")
		}
	})
}

func TestAdapterEABOperations(t *testing.T) {
	t.Run("CreateEAB success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.createEAB"] = admin.CreateEABResponse{
			ID:        "eab-123",
			MACKey:    "base64-encoded-key",
			Algorithm: "HS256",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.CreateEABRequest{
			Purpose:       "account-binding",
			ExpiresInDays: 30,
		}
		eab, err := adapter.CreateEAB(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("CreateEAB() failed: %v", err)
		}
		if eab.ID != "eab-123" {
			t.Errorf("Expected EAB ID 'eab-123', got '%s'", eab.ID)
		}
		if eab.MACKey != "base64-encoded-key" {
			t.Errorf("Expected MACKey 'base64-encoded-key', got '%s'", eab.MACKey)
		}
	})

	t.Run("CreateEAB error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.createEAB"] = &JSONRPCError{
			Code:    -32000,
			Message: "invalid purpose",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.CreateEABRequest{Purpose: "invalid"}
		_, err = adapter.CreateEAB(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for CreateEAB with invalid purpose")
		}
	})

	t.Run("GetEAB success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.getEAB"] = admin.EABInfo{
			ID:       "eab-123",
			TenantID: "tenant-1",
			Status:   "active",
			Purpose:  "account-binding",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		eab, err := adapter.GetEAB(ctx, "tenant-1", "eab-123")
		if err != nil {
			t.Fatalf("GetEAB() failed: %v", err)
		}
		if eab.ID != "eab-123" {
			t.Errorf("Expected EAB ID 'eab-123', got '%s'", eab.ID)
		}
	})

	t.Run("GetEAB not found", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.getEAB"] = &JSONRPCError{
			Code:    -32001,
			Message: "EAB not found",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		_, err = adapter.GetEAB(ctx, "tenant-1", "nonexistent")
		if err == nil {
			t.Error("Expected error for nonexistent EAB")
		}
	})

	t.Run("DeleteEAB success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.deleteEAB"] = nil
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		err = adapter.DeleteEAB(ctx, "tenant-1", "eab-123")
		if err != nil {
			t.Fatalf("DeleteEAB() failed: %v", err)
		}
	})

	t.Run("ListEABs success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.listEABs"] = map[string]interface{}{
			"eabs": []*admin.EABInfo{
				{ID: "eab-1", Purpose: "account-binding"},
				{ID: "eab-2", Purpose: "endorse-01"},
			},
			"pagination": &admin.Pagination{
				Page:    1,
				PerPage: 10,
				Total:   2,
			},
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.ListEABRequest{Page: 1, PerPage: 10}
		eabs, pagination, err := adapter.ListEABs(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("ListEABs() failed: %v", err)
		}
		if len(eabs) != 2 {
			t.Errorf("Expected 2 EABs, got %d", len(eabs))
		}
		if pagination == nil {
			t.Error("Expected pagination, got nil")
		}
	})

	t.Run("ListEABs error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.listEABs"] = &JSONRPCError{
			Code:    -32000,
			Message: "database error",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.ListEABRequest{Page: 1, PerPage: 10}
		_, _, err = adapter.ListEABs(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for ListEABs")
		}
	})
}

func TestAdapterRoleOperations(t *testing.T) {
	t.Run("CreateTenantRole success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.createRole"] = db.Role{
			ID:          "role-1",
			Name:        "admin",
			TenantID:    "tenant-1",
			Permissions: []string{"read", "write"},
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.CreateRoleRequest{
			Name:        "admin",
			Permissions: []string{"read", "write"},
		}
		role, err := adapter.CreateTenantRole(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("CreateTenantRole() failed: %v", err)
		}
		if role.ID != "role-1" {
			t.Errorf("Expected role ID 'role-1', got '%s'", role.ID)
		}
		if role.Name != "admin" {
			t.Errorf("Expected role name 'admin', got '%s'", role.Name)
		}
	})

	t.Run("CreateTenantRole error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.createRole"] = &JSONRPCError{
			Code:    -32000,
			Message: "role already exists",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.CreateRoleRequest{Name: "existing"}
		_, err = adapter.CreateTenantRole(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for existing role")
		}
	})

	t.Run("GetTenantRole success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.getRole"] = db.Role{
			ID:          "role-1",
			Name:        "admin",
			TenantID:    "tenant-1",
			Permissions: []string{"read", "write"},
		}
		handler.validateParams = func(method string, params json.RawMessage) error {
			if method == "admin.getRole" {
				var p map[string]string
				json.Unmarshal(params, &p)
				if p["tenantId"] != "tenant-1" {
					t.Errorf("Expected tenant_id 'tenant-1', got '%s'", p["tenantId"])
				}
				if p["roleId"] != "role-1" {
					t.Errorf("Expected role_id 'role-1', got '%s'", p["roleId"])
				}
			}
			return nil
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		role, err := adapter.GetTenantRole(ctx, "tenant-1", "role-1")
		if err != nil {
			t.Fatalf("GetTenantRole() failed: %v", err)
		}
		if role.ID != "role-1" {
			t.Errorf("Expected role ID 'role-1', got '%s'", role.ID)
		}
		if role.Name != "admin" {
			t.Errorf("Expected role name 'admin', got '%s'", role.Name)
		}
	})

	t.Run("GetTenantRole not found", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.getRole"] = &JSONRPCError{
			Code:    -32001,
			Message: "role not found",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		_, err = adapter.GetTenantRole(ctx, "tenant-1", "nonexistent")
		if err == nil {
			t.Error("Expected error for nonexistent role")
		}
	})

	t.Run("UpdateTenantRole success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.updateRole"] = db.Role{
			ID:          "role-1",
			Name:        "super-admin",
			TenantID:    "tenant-1",
			Permissions: []string{"read", "write", "delete"},
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.UpdateRoleRequest{
			ID:          "role-1",
			Name:        "super-admin",
			Permissions: []string{"read", "write", "delete"},
		}
		role, err := adapter.UpdateTenantRole(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("UpdateTenantRole() failed: %v", err)
		}
		if role.Name != "super-admin" {
			t.Errorf("Expected role name 'super-admin', got '%s'", role.Name)
		}
		if len(role.Permissions) != 3 {
			t.Errorf("Expected 3 permissions, got %d", len(role.Permissions))
		}
	})

	t.Run("UpdateTenantRole error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.updateRole"] = &JSONRPCError{
			Code:    -32001,
			Message: "role not found",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.UpdateRoleRequest{ID: "nonexistent", Name: "updated"}
		_, err = adapter.UpdateTenantRole(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for UpdateTenantRole")
		}
	})

	t.Run("DeleteTenantRole success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.deleteRole"] = nil
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		err = adapter.DeleteTenantRole(ctx, "tenant-1", "role-1")
		if err != nil {
			t.Fatalf("DeleteTenantRole() failed: %v", err)
		}
	})

	t.Run("DeleteTenantRole error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.deleteRole"] = &JSONRPCError{
			Code:    -32000,
			Message: "role is a system role",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		err = adapter.DeleteTenantRole(ctx, "tenant-1", "system-role")
		if err == nil {
			t.Error("Expected error for system role deletion")
		}
	})

	t.Run("ListTenantRoles success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.listRoles"] = db.ListRolesResponse{
			Roles: []*db.Role{
				{ID: "role-1", Name: "admin", TenantID: "tenant-1"},
				{ID: "role-2", Name: "viewer", TenantID: "tenant-1"},
			},
			Total:   2,
			HasMore: false,
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.ListRolesRequest{Page: 1, PageSize: 10}
		resp, err := adapter.ListTenantRoles(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("ListTenantRoles() failed: %v", err)
		}
		if len(resp.Roles) != 2 {
			t.Errorf("Expected 2 roles, got %d", len(resp.Roles))
		}
		if resp.Total != 2 {
			t.Errorf("Expected total 2, got %d", resp.Total)
		}
	})

	t.Run("ListTenantRoles error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.listRoles"] = &JSONRPCError{
			Code:    -32000,
			Message: "database error",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.ListRolesRequest{Page: 1, PageSize: 10}
		_, err = adapter.ListTenantRoles(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for ListTenantRoles")
		}
	})
}

func TestAdapterUserOperations(t *testing.T) {
	t.Run("CreateTenantUser success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.createUser"] = db.User{
			ID:       "user-1",
			Username: "alice",
			TenantID: "tenant-1",
			RoleIDs:  []string{"role-1"},
			Enabled:  true,
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.CreateUserRequest{
			Username: "alice",
			RoleIDs:  []string{"role-1"},
		}
		user, err := adapter.CreateTenantUser(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("CreateTenantUser() failed: %v", err)
		}
		if user.ID != "user-1" {
			t.Errorf("Expected user ID 'user-1', got '%s'", user.ID)
		}
		if user.Username != "alice" {
			t.Errorf("Expected username 'alice', got '%s'", user.Username)
		}
		if !user.Enabled {
			t.Error("Expected user to be enabled")
		}
	})

	t.Run("CreateTenantUser error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.createUser"] = &JSONRPCError{
			Code:    -32000,
			Message: "user already exists",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.CreateUserRequest{Username: "existing"}
		_, err = adapter.CreateTenantUser(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for existing user")
		}
	})

	t.Run("GetTenantUser success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.getUser"] = db.User{
			ID:       "user-1",
			Username: "alice",
			TenantID: "tenant-1",
			Enabled:  true,
		}
		handler.validateParams = func(method string, params json.RawMessage) error {
			if method == "admin.getUser" {
				var p map[string]string
				json.Unmarshal(params, &p)
				if p["tenantId"] != "tenant-1" {
					t.Errorf("Expected tenant_id 'tenant-1', got '%s'", p["tenantId"])
				}
				if p["userId"] != "user-1" {
					t.Errorf("Expected user_id 'user-1', got '%s'", p["userId"])
				}
			}
			return nil
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		user, err := adapter.GetTenantUser(ctx, "tenant-1", "user-1")
		if err != nil {
			t.Fatalf("GetTenantUser() failed: %v", err)
		}
		if user.ID != "user-1" {
			t.Errorf("Expected user ID 'user-1', got '%s'", user.ID)
		}
		if user.Username != "alice" {
			t.Errorf("Expected username 'alice', got '%s'", user.Username)
		}
	})

	t.Run("GetTenantUser not found", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.getUser"] = &JSONRPCError{
			Code:    -32001,
			Message: "user not found",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		_, err = adapter.GetTenantUser(ctx, "tenant-1", "nonexistent")
		if err == nil {
			t.Error("Expected error for nonexistent user")
		}
	})

	t.Run("UpdateTenantUser success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.updateUser"] = db.User{
			ID:       "user-1",
			Username: "alice-updated",
			TenantID: "tenant-1",
			RoleIDs:  []string{"role-1", "role-2"},
			Enabled:  true,
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.UpdateUserRequest{
			ID:       "user-1",
			Username: "alice-updated",
			RoleIDs:  []string{"role-1", "role-2"},
		}
		user, err := adapter.UpdateTenantUser(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("UpdateTenantUser() failed: %v", err)
		}
		if user.Username != "alice-updated" {
			t.Errorf("Expected username 'alice-updated', got '%s'", user.Username)
		}
		if len(user.RoleIDs) != 2 {
			t.Errorf("Expected 2 role IDs, got %d", len(user.RoleIDs))
		}
	})

	t.Run("UpdateTenantUser error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.updateUser"] = &JSONRPCError{
			Code:    -32001,
			Message: "user not found",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.UpdateUserRequest{ID: "nonexistent", Username: "updated"}
		_, err = adapter.UpdateTenantUser(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for UpdateTenantUser")
		}
	})

	t.Run("DeleteTenantUser success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.deleteUser"] = nil
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		err = adapter.DeleteTenantUser(ctx, "tenant-1", "user-1")
		if err != nil {
			t.Fatalf("DeleteTenantUser() failed: %v", err)
		}
	})

	t.Run("DeleteTenantUser error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.deleteUser"] = &JSONRPCError{
			Code:    -32000,
			Message: "cannot delete system user",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		err = adapter.DeleteTenantUser(ctx, "tenant-1", "system-user")
		if err == nil {
			t.Error("Expected error for system user deletion")
		}
	})

	t.Run("ListTenantUsers success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.listUsers"] = db.ListUsersResponse{
			Users: []*db.User{
				{ID: "user-1", Username: "alice", TenantID: "tenant-1"},
				{ID: "user-2", Username: "bob", TenantID: "tenant-1"},
			},
			Total:   2,
			HasMore: false,
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.ListUsersRequest{Page: 1, PageSize: 10}
		resp, err := adapter.ListTenantUsers(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("ListTenantUsers() failed: %v", err)
		}
		if len(resp.Users) != 2 {
			t.Errorf("Expected 2 users, got %d", len(resp.Users))
		}
		if resp.Total != 2 {
			t.Errorf("Expected total 2, got %d", resp.Total)
		}
	})

	t.Run("ListTenantUsers error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.listUsers"] = &JSONRPCError{
			Code:    -32000,
			Message: "database error",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &db.ListUsersRequest{Page: 1, PageSize: 10}
		_, err = adapter.ListTenantUsers(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for ListTenantUsers")
		}
	})
}

func TestAdapterCertificateOperations(t *testing.T) {
	t.Run("ListCertificates success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.listCertificates"] = map[string]interface{}{
			"certificates": []*admin.CertificateInfo{
				{SerialNumber: "123", Subject: "CN=test1"},
				{SerialNumber: "456", Subject: "CN=test2"},
			},
			"pagination": &admin.Pagination{
				Page:    1,
				PerPage: 10,
				Total:   2,
			},
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.ListCertificatesRequest{Page: 1, PerPage: 10}
		certs, pagination, err := adapter.ListCertificates(ctx, req)
		if err != nil {
			t.Fatalf("ListCertificates() failed: %v", err)
		}
		if len(certs) != 2 {
			t.Errorf("Expected 2 certificates, got %d", len(certs))
		}
		if pagination == nil {
			t.Error("Expected pagination, got nil")
		}
	})

	t.Run("ListCertificates error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.listCertificates"] = &JSONRPCError{
			Code:    -32000,
			Message: "database error",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		req := &admin.ListCertificatesRequest{Page: 1, PerPage: 10}
		_, _, err = adapter.ListCertificates(ctx, req)
		if err == nil {
			t.Error("Expected error for ListCertificates")
		}
	})

	t.Run("GetCertificate success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.getCertificate"] = admin.CertificateInfo{
			SerialNumber: "123",
			Subject:      "CN=test",
			Status:       "valid",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		cert, err := adapter.GetCertificate(ctx, "123")
		if err != nil {
			t.Fatalf("GetCertificate() failed: %v", err)
		}
		if cert.SerialNumber != "123" {
			t.Errorf("Expected serial '123', got '%s'", cert.SerialNumber)
		}
	})

	t.Run("GetCertificate not found", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.getCertificate"] = &JSONRPCError{
			Code:    -32001,
			Message: "certificate not found",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		_, err = adapter.GetCertificate(ctx, "nonexistent")
		if err == nil {
			t.Error("Expected error for nonexistent certificate")
		}
	})

	t.Run("RevokeCertificate success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.revokeCertificate"] = nil
		handler.validateParams = func(method string, params json.RawMessage) error {
			if method == "admin.revokeCertificate" {
				var p map[string]string
				json.Unmarshal(params, &p)
				if p["serial"] != "123" {
					t.Errorf("Expected serial '123', got '%s'", p["serial"])
				}
				if p["reason"] != "keyCompromise" {
					t.Errorf("Expected reason 'keyCompromise', got '%s'", p["reason"])
				}
			}
			return nil
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		err = adapter.RevokeCertificate(ctx, "123", "keyCompromise")
		if err != nil {
			t.Fatalf("RevokeCertificate() failed: %v", err)
		}
	})

	t.Run("RevokeCertificate error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.revokeCertificate"] = &JSONRPCError{
			Code:    -32000,
			Message: "certificate already revoked",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		err = adapter.RevokeCertificate(ctx, "123", "keyCompromise")
		if err == nil {
			t.Error("Expected error for already revoked certificate")
		}
	})
}

func TestAdapterStatusOperations(t *testing.T) {
	t.Run("GetStatus success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.getStatus"] = admin.CAStatus{
			Identity:      "Test CA",
			Initialized:   true,
			Version:       "1.0.0",
			KeyAlgorithm:  "ECDSA-P256",
			SignatureAlgo: "SHA256-RSA",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		status, err := adapter.GetStatus(ctx)
		if err != nil {
			t.Fatalf("GetStatus() failed: %v", err)
		}
		if !status.Initialized {
			t.Error("Expected Initialized to be true")
		}
		if status.Version != "1.0.0" {
			t.Errorf("Expected version '1.0.0', got '%s'", status.Version)
		}
	})

	t.Run("GetStatus error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.getStatus"] = &JSONRPCError{
			Code:    -32000,
			Message: "CA not initialized",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		_, err = adapter.GetStatus(ctx)
		if err == nil {
			t.Error("Expected error for GetStatus")
		}
	})

	t.Run("GetStats success", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.responses["admin.getStats"] = admin.CAStats{
			TotalCertificates:   100,
			ValidCertificates:   80,
			RevokedCertificates: 15,
			ExpiredCertificates: 5,
			TotalAccounts:       50,
			ActiveAccounts:      45,
			TotalOrders:         200,
			PendingOrders:       10,
			CompletedOrders:     190,
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		stats, err := adapter.GetStats(ctx)
		if err != nil {
			t.Fatalf("GetStats() failed: %v", err)
		}
		if stats.TotalCertificates != 100 {
			t.Errorf("Expected TotalCertificates 100, got %d", stats.TotalCertificates)
		}
		if stats.ValidCertificates != 80 {
			t.Errorf("Expected ValidCertificates 80, got %d", stats.ValidCertificates)
		}
	})

	t.Run("GetStats error", func(t *testing.T) {
		handler := newMockMCPHandler(t)
		handler.errors["admin.getStats"] = &JSONRPCError{
			Code:    -32000,
			Message: "stats unavailable",
		}
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		_, err = adapter.GetStats(ctx)
		if err == nil {
			t.Error("Expected error for GetStats")
		}
	})
}

func TestAdapterNetworkErrors(t *testing.T) {
	t.Run("connection refused", func(t *testing.T) {
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: "localhost:59999"})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		_, err = adapter.GetStatus(ctx)
		if err == nil {
			t.Error("Expected error for connection refused")
		}
	})

	t.Run("server closed mid-request", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Skip("ResponseWriter does not support hijacking")
			}
			conn, _, _ := hj.Hijack()
			conn.Close()
		})
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := strings.TrimPrefix(server.URL, "http://")
		adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer adapter.Close()

		ctx := context.Background()
		_, err = adapter.GetStatus(ctx)
		if err == nil {
			t.Error("Expected error for closed connection")
		}
	})
}

func TestAdapterConcurrency(t *testing.T) {
	handler := newMockMCPHandler(t)
	handler.responses["admin.getStatus"] = admin.CAStatus{
		Initialized: true,
		Version:     "1.0.0",
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "http://")
	adapter, err := NewAdapter(&api.AdapterConfig{MCPAddr: addr})
	if err != nil {
		t.Fatalf("NewAdapter() failed: %v", err)
	}
	defer adapter.Close()

	// Run concurrent requests
	const numGoroutines = 10
	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			ctx := context.Background()
			_, err := adapter.GetStatus(ctx)
			done <- err
		}()
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		if err := <-done; err != nil {
			t.Errorf("Concurrent GetStatus() failed: %v", err)
		}
	}
}

func TestJSONRPCRequestResponse(t *testing.T) {
	t.Run("JSONRPCRequest marshaling", func(t *testing.T) {
		req := JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "test.method",
			Params:  map[string]string{"key": "value"},
			ID:      1,
		}
		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("Failed to marshal: %v", err)
		}
		var unmarshaled JSONRPCRequest
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if unmarshaled.JSONRPC != "2.0" {
			t.Errorf("Expected JSONRPC '2.0', got '%s'", unmarshaled.JSONRPC)
		}
		if unmarshaled.Method != "test.method" {
			t.Errorf("Expected Method 'test.method', got '%s'", unmarshaled.Method)
		}
	})

	t.Run("JSONRPCRequest without params", func(t *testing.T) {
		req := JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "test.method",
			ID:      1,
		}
		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("Failed to marshal: %v", err)
		}
		// Verify params is omitted
		if strings.Contains(string(data), `"params"`) {
			t.Error("Expected params to be omitted")
		}
	})

	t.Run("JSONRPCResponse marshaling", func(t *testing.T) {
		result, _ := json.Marshal(map[string]string{"status": "ok"})
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			Result:  result,
			ID:      1,
		}
		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Failed to marshal: %v", err)
		}
		var unmarshaled JSONRPCResponse
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if unmarshaled.JSONRPC != "2.0" {
			t.Errorf("Expected JSONRPC '2.0', got '%s'", unmarshaled.JSONRPC)
		}
	})

	t.Run("JSONRPCResponse with error", func(t *testing.T) {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &JSONRPCError{
				Code:    -32600,
				Message: "Invalid Request",
			},
			ID: 1,
		}
		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Failed to marshal: %v", err)
		}
		var unmarshaled JSONRPCResponse
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if unmarshaled.Error == nil {
			t.Error("Expected Error to be non-nil")
		}
		if unmarshaled.Error.Code != -32600 {
			t.Errorf("Expected error code -32600, got %d", unmarshaled.Error.Code)
		}
	})

	t.Run("JSONRPCError marshaling", func(t *testing.T) {
		rpcErr := JSONRPCError{
			Code:    -32600,
			Message: "Invalid Request",
			Data:    "additional info",
		}
		data, err := json.Marshal(rpcErr)
		if err != nil {
			t.Fatalf("Failed to marshal: %v", err)
		}
		var unmarshaled JSONRPCError
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if unmarshaled.Code != -32600 {
			t.Errorf("Expected Code -32600, got %d", unmarshaled.Code)
		}
		if unmarshaled.Message != "Invalid Request" {
			t.Errorf("Expected Message 'Invalid Request', got '%s'", unmarshaled.Message)
		}
	})

	t.Run("JSONRPCError without data", func(t *testing.T) {
		rpcErr := JSONRPCError{
			Code:    -32600,
			Message: "Invalid Request",
		}
		data, err := json.Marshal(rpcErr)
		if err != nil {
			t.Fatalf("Failed to marshal: %v", err)
		}
		// Verify data is omitted
		if strings.Contains(string(data), `"data"`) {
			t.Error("Expected data to be omitted")
		}
	})
}
