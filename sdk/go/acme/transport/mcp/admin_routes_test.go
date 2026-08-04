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

package mcp

import (
	"testing"
)

// TestAdminMethodMappings verifies that all admin dotted service names are registered.
func TestAdminMethodMappings(t *testing.T) {
	t.Parallel()

	adminServices := []string{
		"admin.tenant",
		"admin.eab",
		"admin.role",
		"admin.user",
		"admin.certificate",
		"admin.account",
		"admin.status",
		"admin.order",
		"admin.tenant.ca",
	}

	for _, svc := range adminServices {
		if _, ok := methodMappings[svc]; !ok {
			t.Errorf("missing method mapping for admin service: %s", svc)
		}
	}
}

// TestAdminMethodNames verifies that admin service/method pairs map to correct
// server-side JSON-RPC method names. The server uses admin.{verb}{Resource} format.
func TestAdminMethodNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		service  string
		method   string
		expected string
	}{
		// Tenant service
		{"admin.tenant", "create", "admin.createTenant"},
		{"admin.tenant", "get", "admin.getTenant"},
		{"admin.tenant", "update", "admin.updateTenant"},
		{"admin.tenant", "delete", "admin.deleteTenant"},
		{"admin.tenant", "list", "admin.listTenants"},
		{"admin.tenant", "updateStatus", "admin.updateTenantStatus"},

		// EAB service
		{"admin.eab", "create", "admin.createEAB"},
		{"admin.eab", "get", "admin.getEAB"},
		{"admin.eab", "delete", "admin.deleteEAB"},
		{"admin.eab", "list", "admin.listEABs"},

		// Role service
		{"admin.role", "create", "admin.createRole"},
		{"admin.role", "get", "admin.getRole"},
		{"admin.role", "update", "admin.updateRole"},
		{"admin.role", "delete", "admin.deleteRole"},
		{"admin.role", "list", "admin.listRoles"},

		// User service
		{"admin.user", "create", "admin.createUser"},
		{"admin.user", "get", "admin.getUser"},
		{"admin.user", "update", "admin.updateUser"},
		{"admin.user", "delete", "admin.deleteUser"},
		{"admin.user", "list", "admin.listUsers"},

		// Certificate service (short-form)
		{"admin.certificate", "list", "admin.listCertificates"},
		{"admin.certificate", "get", "admin.getCertificate"},
		{"admin.certificate", "revoke", "admin.revokeCertificate"},
		// Certificate service (long-form)
		{"admin.certificate", "listCertificates", "admin.listCertificates"},
		{"admin.certificate", "getCertificate", "admin.getCertificate"},
		{"admin.certificate", "revokeCertificate", "admin.revokeCertificate"},

		// Account service (short-form)
		{"admin.account", "list", "admin.listAccounts"},
		{"admin.account", "get", "admin.getAccount"},
		{"admin.account", "disable", "admin.disableAccount"},
		// Account service (long-form)
		{"admin.account", "listAccounts", "admin.listAccounts"},
		{"admin.account", "getAccount", "admin.getAccount"},
		{"admin.account", "disableAccount", "admin.disableAccount"},

		// Status service
		{"admin.status", "status", "admin.getStatus"},
		{"admin.status", "stats", "admin.getStats"},

		// Order service (short-form)
		{"admin.order", "list", "admin.listOrders"},
		{"admin.order", "get", "admin.getOrder"},
		// Order service (long-form)
		{"admin.order", "listOrders", "admin.listOrders"},
		{"admin.order", "getOrder", "admin.getOrder"},

		// Tenant CA service
		{"admin.tenant.ca", "createRootCA", "admin.createRootCA"},
		{"admin.tenant.ca", "status", "admin.getTenantCAStatus"},
		{"admin.tenant.ca", "createIntermediateCA", "admin.createIntermediateCA"},
		{"admin.tenant.ca", "listIntermediateCAs", "admin.listIntermediateCAs"},
		{"admin.tenant.ca", "getIntermediateCA", "admin.getIntermediateCA"},
		{"admin.tenant.ca", "updateIntermediateCAStatus", "admin.updateIntermediateCAStatus"},
	}

	for _, tt := range tests {
		t.Run(tt.service+"/"+tt.method, func(t *testing.T) {
			got := mapMethodName(tt.service, tt.method)
			if got != tt.expected {
				t.Errorf("mapMethodName(%q, %q) = %q, want %q", tt.service, tt.method, got, tt.expected)
			}
		})
	}
}

// TestAdminMethodMappings_FallbackForUnknownMethod verifies that unknown methods
// fall back to admin.{method} format.
func TestAdminMethodMappings_FallbackForUnknownMethod(t *testing.T) {
	t.Parallel()

	got := mapMethodName("admin.tenant", "unknownMethod")
	expected := "admin.unknownMethod"
	if got != expected {
		t.Errorf("mapMethodName(admin.tenant, unknownMethod) = %q, want %q", got, expected)
	}
}

// TestAdminMethodMappings_UnknownServiceFallback verifies that unknown services fall back to service.method.
func TestAdminMethodMappings_UnknownServiceFallback(t *testing.T) {
	t.Parallel()

	got := mapMethodName("admin.unknown", "get")
	expected := "admin.unknown.get"
	if got != expected {
		t.Errorf("mapMethodName(admin.unknown, get) = %q, want %q", got, expected)
	}
}
