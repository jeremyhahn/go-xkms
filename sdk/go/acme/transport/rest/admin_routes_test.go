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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// TestAdminRoutes_AllRegistered verifies that all admin routes are registered in the route map.
func TestAdminRoutes_AllRegistered(t *testing.T) {
	t.Parallel()

	cfg := &transport.Config{
		Address:  "http://localhost:9443",
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	restTransport := tr.(*Transport)

	adminRouteKeys := []string{
		"admin.status/status",
		"admin.status/stats",
		"admin.certificate/list",
		"admin.certificate/get",
		"admin.certificate/revoke",
		"admin.account/list",
		"admin.account/get",
		"admin.account/disable",
		"admin.tenant/create",
		"admin.tenant/list",
		"admin.tenant/get",
		"admin.tenant/update",
		"admin.tenant/delete",
		"admin.tenant/updateStatus",
		"admin.eab/create",
		"admin.eab/list",
		"admin.eab/get",
		"admin.eab/delete",
		"admin.role/create",
		"admin.role/list",
		"admin.role/get",
		"admin.role/update",
		"admin.role/delete",
		"admin.user/create",
		"admin.user/list",
		"admin.user/get",
		"admin.user/update",
		"admin.user/delete",
		"admin.order/list",
		"admin.order/get",
		"admin.tenant.ca/createRootCA",
		"admin.tenant.ca/status",
		"admin.tenant.ca/createIntermediateCA",
		"admin.tenant.ca/listIntermediateCAs",
		"admin.tenant.ca/getIntermediateCA",
		"admin.tenant.ca/updateIntermediateCAStatus",
	}

	for _, key := range adminRouteKeys {
		if _, ok := restTransport.routes[key]; !ok {
			t.Errorf("missing admin route: %s", key)
		}
	}
}

// TestAdminRoutes_HTTPMethods verifies that admin routes use correct HTTP methods.
func TestAdminRoutes_HTTPMethods(t *testing.T) {
	t.Parallel()

	routes := buildAdminRouteMap()

	tests := []struct {
		routeKey   string
		wantMethod HTTPMethod
	}{
		{"admin.status/status", MethodGET},
		{"admin.status/stats", MethodGET},
		{"admin.certificate/list", MethodGET},
		{"admin.certificate/get", MethodGET},
		{"admin.certificate/revoke", MethodPOST},
		{"admin.account/list", MethodGET},
		{"admin.account/get", MethodGET},
		{"admin.account/disable", MethodDELETE},
		{"admin.tenant/create", MethodPOST},
		{"admin.tenant/list", MethodGET},
		{"admin.tenant/get", MethodGET},
		{"admin.tenant/update", MethodPUT},
		{"admin.tenant/delete", MethodDELETE},
		{"admin.eab/create", MethodPOST},
		{"admin.eab/delete", MethodDELETE},
		{"admin.role/update", MethodPUT},
		{"admin.role/delete", MethodDELETE},
		{"admin.user/update", MethodPUT},
		{"admin.user/delete", MethodDELETE},
		{"admin.tenant.ca/createRootCA", MethodPOST},
		{"admin.tenant.ca/status", MethodGET},
		{"admin.tenant.ca/updateIntermediateCAStatus", MethodPUT},
	}

	for _, tt := range tests {
		t.Run(tt.routeKey, func(t *testing.T) {
			route, ok := routes[tt.routeKey]
			if !ok {
				t.Fatalf("route %s not found", tt.routeKey)
			}
			if route.Method != tt.wantMethod {
				t.Errorf("route %s method = %s, want %s", tt.routeKey, route.Method, tt.wantMethod)
			}
		})
	}
}

// TestAdminRoutes_PathBuilders verifies path builders produce correct URLs.
func TestAdminRoutes_PathBuilders(t *testing.T) {
	t.Parallel()

	baseURL := "https://localhost:9443"

	tests := []struct {
		name     string
		routeKey string
		request  interface{}
		wantPath string
	}{
		{
			name:     "status endpoint",
			routeKey: "admin.status/status",
			request:  nil,
			wantPath: baseURL + "/admin/status",
		},
		{
			name:     "stats endpoint",
			routeKey: "admin.status/stats",
			request:  nil,
			wantPath: baseURL + "/admin/stats",
		},
		{
			name:     "certificate list",
			routeKey: "admin.certificate/list",
			request:  nil,
			wantPath: baseURL + "/admin/certificates",
		},
		{
			name:     "certificate get by serial",
			routeKey: "admin.certificate/get",
			request: &struct {
				Serial string `json:"serial"`
			}{Serial: "ABC123"},
			wantPath: baseURL + "/admin/certificates/ABC123",
		},
		{
			name:     "tenant get by ID",
			routeKey: "admin.tenant/get",
			request: &struct {
				TenantID string `json:"tenantId"`
			}{TenantID: "tenant-1"},
			wantPath: baseURL + "/api/v1/tenants/tenant-1",
		},
		{
			name:     "tenant create (static path)",
			routeKey: "admin.tenant/create",
			request:  map[string]string{"name": "Test Tenant"},
			wantPath: baseURL + "/api/v1/tenants",
		},
		{
			name:     "EAB get with two IDs",
			routeKey: "admin.eab/get",
			request: &struct {
				TenantID string `json:"tenantId"`
				KID      string `json:"kid"`
			}{TenantID: "tenant-1", KID: "kid-abc"},
			wantPath: baseURL + "/api/v1/tenants/tenant-1/eab/kid-abc",
		},
		{
			name:     "role get with two IDs",
			routeKey: "admin.role/get",
			request: &struct {
				TenantID string `json:"tenantId"`
				RoleID   string `json:"roleId"`
			}{TenantID: "tenant-1", RoleID: "role-xyz"},
			wantPath: baseURL + "/api/v1/tenants/tenant-1/roles/role-xyz",
		},
		{
			name:     "order list (static)",
			routeKey: "admin.order/list",
			request:  nil,
			wantPath: baseURL + "/admin/orders",
		},
		{
			name:     "order get with numeric ID",
			routeKey: "admin.order/get",
			request: &struct {
				OrderID uint64 `json:"orderId"`
			}{OrderID: 42},
			wantPath: baseURL + "/admin/orders/42",
		},
		{
			name:     "tenant CA create root",
			routeKey: "admin.tenant.ca/createRootCA",
			request: &struct {
				TenantID string `json:"tenantId"`
			}{TenantID: "tenant-2"},
			wantPath: baseURL + "/api/v1/tenants/tenant-2/root-ca",
		},
		{
			name:     "intermediate CA get",
			routeKey: "admin.tenant.ca/getIntermediateCA",
			request: &struct {
				TenantID string `json:"tenantId"`
				CAID     string `json:"caId"`
			}{TenantID: "tenant-2", CAID: "ca-1"},
			wantPath: baseURL + "/api/v1/tenants/tenant-2/intermediate-cas/ca-1",
		},
	}

	routes := buildAdminRouteMap()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, ok := routes[tt.routeKey]
			if !ok {
				t.Fatalf("route %s not found", tt.routeKey)
			}
			got := route.PathBuilder(baseURL, tt.request)
			if got != tt.wantPath {
				t.Errorf("PathBuilder() = %q, want %q", got, tt.wantPath)
			}
		})
	}
}

// TestAdminRoutes_PathBuilder_MissingFields verifies that missing required fields return empty string.
func TestAdminRoutes_PathBuilder_MissingFields(t *testing.T) {
	t.Parallel()

	routes := buildAdminRouteMap()
	baseURL := "https://localhost:9443"

	tests := []struct {
		name     string
		routeKey string
		request  interface{}
	}{
		{
			name:     "tenant get with empty ID",
			routeKey: "admin.tenant/get",
			request: &struct {
				TenantID string `json:"tenantId"`
			}{},
		},
		{
			name:     "certificate get with nil request",
			routeKey: "admin.certificate/get",
			request:  nil,
		},
		{
			name:     "EAB get with missing kid",
			routeKey: "admin.eab/get",
			request: &struct {
				TenantID string `json:"tenantId"`
			}{TenantID: "tenant-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := routes[tt.routeKey]
			got := route.PathBuilder(baseURL, tt.request)
			if got != "" {
				t.Errorf("PathBuilder() = %q, want empty string for missing fields", got)
			}
		})
	}
}

// TestAdminRoutes_RequestIntegration verifies that admin routes can be called through the transport.
func TestAdminRoutes_RequestIntegration(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"path":   r.URL.Path,
			"method": r.Method,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx := context.Background()

	t.Run("admin.status/status returns correct path", func(t *testing.T) {
		resp, err := tr.Request(ctx, "admin.status", "status", nil)
		if err != nil {
			t.Fatalf("Request() error = %v", err)
		}
		restResp := resp.(*Response)
		if !strings.Contains(string(restResp.Body), "/admin/status") {
			t.Errorf("expected path /admin/status in response, got: %s", restResp.Body)
		}
	})

	t.Run("admin.tenant/get uses GET method", func(t *testing.T) {
		req := &struct {
			TenantID string `json:"tenantId"`
		}{TenantID: "test-tenant"}
		resp, err := tr.Request(ctx, "admin.tenant", "get", req)
		if err != nil {
			t.Fatalf("Request() error = %v", err)
		}
		restResp := resp.(*Response)
		if !strings.Contains(string(restResp.Body), "GET") {
			t.Errorf("expected GET method in response, got: %s", restResp.Body)
		}
		if !strings.Contains(string(restResp.Body), "/api/v1/tenants/test-tenant") {
			t.Errorf("expected path /api/v1/tenants/test-tenant in response, got: %s", restResp.Body)
		}
	})

	t.Run("admin.tenant/create uses POST method", func(t *testing.T) {
		req := map[string]string{"name": "New Tenant"}
		resp, err := tr.Request(ctx, "admin.tenant", "create", req)
		if err != nil {
			t.Fatalf("Request() error = %v", err)
		}
		restResp := resp.(*Response)
		if !strings.Contains(string(restResp.Body), "POST") {
			t.Errorf("expected POST method in response, got: %s", restResp.Body)
		}
	})

	t.Run("unknown admin route returns error", func(t *testing.T) {
		_, err := tr.Request(ctx, "admin.nonexistent", "get", nil)
		if err == nil {
			t.Fatal("expected error for unknown admin route")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got: %v", err)
		}
	})
}

// TestExtractField verifies the extractField helper function.
func TestExtractField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		req      interface{}
		field    string
		expected string
	}{
		{
			name: "string field",
			req: &struct {
				TenantID string `json:"tenantId"`
			}{TenantID: "test"},
			field:    "tenantId",
			expected: "test",
		},
		{
			name: "numeric field",
			req: &struct {
				OrderID uint64 `json:"orderId"`
			}{OrderID: 42},
			field:    "orderId",
			expected: "42",
		},
		{
			name: "missing field",
			req: &struct {
				Name string `json:"name"`
			}{Name: "test"},
			field:    "tenantId",
			expected: "",
		},
		{
			name:     "nil request",
			req:      nil,
			field:    "tenantId",
			expected: "",
		},
		{
			name: "empty string field",
			req: &struct {
				TenantID string `json:"tenantId"`
			}{},
			field:    "tenantId",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractField(tt.req, tt.field)
			if got != tt.expected {
				t.Errorf("extractField() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestHasBody verifies the hasBody helper function.
func TestHasBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method HTTPMethod
		want   bool
	}{
		{MethodGET, false},
		{MethodPOST, true},
		{MethodPUT, true},
		{MethodDELETE, false},
		{MethodHEAD, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			if got := hasBody(tt.method); got != tt.want {
				t.Errorf("hasBody(%s) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}
