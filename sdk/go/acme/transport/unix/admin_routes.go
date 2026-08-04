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

package unix

import "net/http"

// adminEndpointRegistry maps admin service/method pairs to REST endpoints.
// This provides O(1) constant-time lookup for admin route routing.
var adminEndpointRegistry = map[string]EndpointInfo{
	// Status service
	endpointKey("admin.status", "status"): {Path: "/admin/status", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.status", "stats"):  {Path: "/admin/stats", Method: http.MethodGet, RequiresBody: false},

	// Certificate service
	endpointKey("admin.certificate", "list"):   {Path: "/admin/certificates", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.certificate", "get"):    {Path: "/admin/certificates/{serial}", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.certificate", "revoke"): {Path: "/admin/certificates/{serial}/revoke", Method: http.MethodPost, RequiresBody: true},

	// Account service
	endpointKey("admin.account", "list"):    {Path: "/admin/accounts", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.account", "get"):     {Path: "/admin/accounts/{accountId}", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.account", "disable"): {Path: "/admin/accounts/{accountId}", Method: http.MethodDelete, RequiresBody: false},

	// Tenant service
	endpointKey("admin.tenant", "create"):       {Path: "/api/v1/tenants", Method: http.MethodPost, RequiresBody: true},
	endpointKey("admin.tenant", "list"):         {Path: "/api/v1/tenants", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.tenant", "get"):          {Path: "/api/v1/tenants/{tenantId}", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.tenant", "update"):       {Path: "/api/v1/tenants/{tenantId}", Method: http.MethodPut, RequiresBody: true},
	endpointKey("admin.tenant", "delete"):       {Path: "/api/v1/tenants/{tenantId}", Method: http.MethodDelete, RequiresBody: false},
	endpointKey("admin.tenant", "updateStatus"): {Path: "/api/v1/tenants/{tenantId}/status", Method: http.MethodPut, RequiresBody: true},

	// EAB service
	endpointKey("admin.eab", "create"): {Path: "/api/v1/tenants/{tenantId}/eab", Method: http.MethodPost, RequiresBody: true},
	endpointKey("admin.eab", "list"):   {Path: "/api/v1/tenants/{tenantId}/eab", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.eab", "get"):    {Path: "/api/v1/tenants/{tenantId}/eab/{kid}", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.eab", "delete"): {Path: "/api/v1/tenants/{tenantId}/eab/{kid}", Method: http.MethodDelete, RequiresBody: false},

	// Role service
	endpointKey("admin.role", "create"): {Path: "/api/v1/tenants/{tenantId}/roles", Method: http.MethodPost, RequiresBody: true},
	endpointKey("admin.role", "list"):   {Path: "/api/v1/tenants/{tenantId}/roles", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.role", "get"):    {Path: "/api/v1/tenants/{tenantId}/roles/{roleId}", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.role", "update"): {Path: "/api/v1/tenants/{tenantId}/roles/{id}", Method: http.MethodPut, RequiresBody: true},
	endpointKey("admin.role", "delete"): {Path: "/api/v1/tenants/{tenantId}/roles/{roleId}", Method: http.MethodDelete, RequiresBody: false},

	// User service
	endpointKey("admin.user", "create"): {Path: "/api/v1/tenants/{tenantId}/users", Method: http.MethodPost, RequiresBody: true},
	endpointKey("admin.user", "list"):   {Path: "/api/v1/tenants/{tenantId}/users", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.user", "get"):    {Path: "/api/v1/tenants/{tenantId}/users/{userId}", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.user", "update"): {Path: "/api/v1/tenants/{tenantId}/users/{id}", Method: http.MethodPut, RequiresBody: true},
	endpointKey("admin.user", "delete"): {Path: "/api/v1/tenants/{tenantId}/users/{userId}", Method: http.MethodDelete, RequiresBody: false},

	// Order service (admin)
	endpointKey("admin.order", "list"): {Path: "/admin/orders", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.order", "get"):  {Path: "/admin/orders/{orderId}", Method: http.MethodGet, RequiresBody: false},

	// Tenant CA service
	endpointKey("admin.tenant.ca", "createRootCA"):               {Path: "/api/v1/tenants/{tenantId}/root-ca", Method: http.MethodPost, RequiresBody: true},
	endpointKey("admin.tenant.ca", "status"):                     {Path: "/api/v1/tenants/{tenantId}/ca-status", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.tenant.ca", "createIntermediateCA"):       {Path: "/api/v1/tenants/{tenantId}/intermediate-cas", Method: http.MethodPost, RequiresBody: true},
	endpointKey("admin.tenant.ca", "listIntermediateCAs"):        {Path: "/api/v1/tenants/{tenantId}/intermediate-cas", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.tenant.ca", "getIntermediateCA"):          {Path: "/api/v1/tenants/{tenantId}/intermediate-cas/{caId}", Method: http.MethodGet, RequiresBody: false},
	endpointKey("admin.tenant.ca", "updateIntermediateCAStatus"): {Path: "/api/v1/tenants/{tenantId}/intermediate-cas/{caId}", Method: http.MethodPut, RequiresBody: true},
}

func init() {
	// Merge admin routes into the main endpoint registry.
	for k, v := range adminEndpointRegistry {
		endpointRegistry[k] = v
	}
}
