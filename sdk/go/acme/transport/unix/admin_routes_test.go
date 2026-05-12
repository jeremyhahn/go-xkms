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

package unix

import (
	"net/http"
	"testing"
)

// TestAdminRoutes_AllRegistered verifies that all admin routes are in the endpoint registry.
func TestAdminRoutes_AllRegistered(t *testing.T) {
	t.Parallel()

	adminRoutes := []struct {
		service string
		method  string
	}{
		{"admin.status", "status"},
		{"admin.status", "stats"},
		{"admin.certificate", "list"},
		{"admin.certificate", "get"},
		{"admin.certificate", "revoke"},
		{"admin.account", "list"},
		{"admin.account", "get"},
		{"admin.account", "disable"},
		{"admin.tenant", "create"},
		{"admin.tenant", "list"},
		{"admin.tenant", "get"},
		{"admin.tenant", "update"},
		{"admin.tenant", "delete"},
		{"admin.tenant", "updateStatus"},
		{"admin.eab", "create"},
		{"admin.eab", "list"},
		{"admin.eab", "get"},
		{"admin.eab", "delete"},
		{"admin.role", "create"},
		{"admin.role", "list"},
		{"admin.role", "get"},
		{"admin.role", "update"},
		{"admin.role", "delete"},
		{"admin.user", "create"},
		{"admin.user", "list"},
		{"admin.user", "get"},
		{"admin.user", "update"},
		{"admin.user", "delete"},
		{"admin.order", "list"},
		{"admin.order", "get"},
		{"admin.tenant.ca", "createRootCA"},
		{"admin.tenant.ca", "status"},
		{"admin.tenant.ca", "createIntermediateCA"},
		{"admin.tenant.ca", "listIntermediateCAs"},
		{"admin.tenant.ca", "getIntermediateCA"},
		{"admin.tenant.ca", "updateIntermediateCAStatus"},
	}

	for _, rt := range adminRoutes {
		key := endpointKey(rt.service, rt.method)
		if _, ok := endpointRegistry[key]; !ok {
			t.Errorf("missing admin route: %s/%s", rt.service, rt.method)
		}
	}
}

// TestAdminRoutes_HTTPMethods verifies correct HTTP methods for admin endpoints.
func TestAdminRoutes_HTTPMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		service    string
		method     string
		wantMethod string
	}{
		{"admin.status", "status", http.MethodGet},
		{"admin.status", "stats", http.MethodGet},
		{"admin.certificate", "list", http.MethodGet},
		{"admin.certificate", "revoke", http.MethodPost},
		{"admin.account", "disable", http.MethodDelete},
		{"admin.tenant", "create", http.MethodPost},
		{"admin.tenant", "get", http.MethodGet},
		{"admin.tenant", "update", http.MethodPut},
		{"admin.tenant", "delete", http.MethodDelete},
		{"admin.eab", "create", http.MethodPost},
		{"admin.eab", "delete", http.MethodDelete},
		{"admin.role", "update", http.MethodPut},
		{"admin.user", "update", http.MethodPut},
		{"admin.tenant.ca", "createRootCA", http.MethodPost},
		{"admin.tenant.ca", "status", http.MethodGet},
		{"admin.tenant.ca", "updateIntermediateCAStatus", http.MethodPut},
	}

	for _, tt := range tests {
		t.Run(tt.service+"/"+tt.method, func(t *testing.T) {
			key := endpointKey(tt.service, tt.method)
			endpoint, ok := endpointRegistry[key]
			if !ok {
				t.Fatalf("endpoint %s/%s not found", tt.service, tt.method)
			}
			if endpoint.Method != tt.wantMethod {
				t.Errorf("method = %s, want %s", endpoint.Method, tt.wantMethod)
			}
		})
	}
}

// TestAdminRoutes_Paths verifies admin endpoint paths.
func TestAdminRoutes_Paths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		service  string
		method   string
		wantPath string
	}{
		{"admin.status", "status", "/admin/status"},
		{"admin.status", "stats", "/admin/stats"},
		{"admin.certificate", "list", "/admin/certificates"},
		{"admin.certificate", "get", "/admin/certificates/{serial}"},
		{"admin.tenant", "create", "/api/v1/tenants"},
		{"admin.tenant", "list", "/api/v1/tenants"},
		{"admin.tenant", "get", "/api/v1/tenants/{tenantId}"},
		{"admin.eab", "get", "/api/v1/tenants/{tenantId}/eab/{kid}"},
		{"admin.role", "get", "/api/v1/tenants/{tenantId}/roles/{roleId}"},
		{"admin.user", "get", "/api/v1/tenants/{tenantId}/users/{userId}"},
		{"admin.order", "list", "/admin/orders"},
		{"admin.order", "get", "/admin/orders/{orderId}"},
		{"admin.tenant.ca", "createRootCA", "/api/v1/tenants/{tenantId}/root-ca"},
		{"admin.tenant.ca", "getIntermediateCA", "/api/v1/tenants/{tenantId}/intermediate-cas/{caId}"},
	}

	for _, tt := range tests {
		t.Run(tt.service+"/"+tt.method, func(t *testing.T) {
			key := endpointKey(tt.service, tt.method)
			endpoint, ok := endpointRegistry[key]
			if !ok {
				t.Fatalf("endpoint %s/%s not found", tt.service, tt.method)
			}
			if endpoint.Path != tt.wantPath {
				t.Errorf("path = %q, want %q", endpoint.Path, tt.wantPath)
			}
		})
	}
}

// TestSubstitutePathParams verifies path parameter substitution.
func TestSubstitutePathParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
		req  interface{}
		want string
	}{
		{
			name: "nil request",
			url:  "http://localhost/api/v1/tenants/{tenantId}",
			req:  nil,
			want: "http://localhost/api/v1/tenants/{tenantId}",
		},
		{
			name: "no placeholders",
			url:  "http://localhost/admin/status",
			req: &struct {
				TenantID string `json:"tenantId"`
			}{TenantID: "test"},
			want: "http://localhost/admin/status",
		},
		{
			name: "single string field",
			url:  "http://localhost/api/v1/tenants/{tenantId}",
			req: &struct {
				TenantID string `json:"tenantId"`
			}{TenantID: "t1"},
			want: "http://localhost/api/v1/tenants/t1",
		},
		{
			name: "multiple fields",
			url:  "http://localhost/api/v1/tenants/{tenantId}/eab/{kid}",
			req: &struct {
				TenantID string `json:"tenantId"`
				KID      string `json:"kid"`
			}{TenantID: "t1", KID: "k1"},
			want: "http://localhost/api/v1/tenants/t1/eab/k1",
		},
		{
			name: "numeric field",
			url:  "http://localhost/admin/orders/{orderId}",
			req: &struct {
				OrderID uint64 `json:"orderId"`
			}{OrderID: 42},
			want: "http://localhost/admin/orders/42",
		},
		{
			name: "map request (ACME compat)",
			url:  "http://localhost/acme/order/{id}",
			req:  map[string]interface{}{"id": "order-1"},
			want: "http://localhost/acme/order/order-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := substitutePathParams(tt.url, tt.req)
			if got != tt.want {
				t.Errorf("substitutePathParams() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAdminRoutes_DoNotBreakACME verifies that ACME routes still exist after admin routes init.
func TestAdminRoutes_DoNotBreakACME(t *testing.T) {
	t.Parallel()

	acmeRoutes := []struct {
		service string
		method  string
	}{
		{"directory", "get"},
		{"nonce", "new"},
		{"account", "create"},
		{"order", "create"},
		{"certificate", "revoke"},
		{"health", "check"},
	}

	for _, rt := range acmeRoutes {
		key := endpointKey(rt.service, rt.method)
		if _, ok := endpointRegistry[key]; !ok {
			t.Errorf("ACME route missing after admin init: %s/%s", rt.service, rt.method)
		}
	}
}
