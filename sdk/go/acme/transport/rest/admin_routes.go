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

package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	// MethodPUT is the HTTP PUT method.
	MethodPUT HTTPMethod = http.MethodPut

	// MethodDELETE is the HTTP DELETE method.
	MethodDELETE HTTPMethod = http.MethodDelete
)

// hasBody returns true if the HTTP method typically carries a request body.
func hasBody(m HTTPMethod) bool {
	return m == MethodPOST || m == MethodPUT
}

// extractField extracts a string field from a request by JSON marshaling it to a map.
// This avoids circular dependencies between the transport and admin client packages.
func extractField(req interface{}, field string) string {
	if req == nil {
		return ""
	}
	data, err := json.Marshal(req)
	if err != nil {
		return ""
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return ""
	}
	if v, ok := m[field]; ok {
		switch val := v.(type) {
		case string:
			return val
		case float64:
			return fmt.Sprintf("%d", int64(val))
		}
	}
	return ""
}

// adminPath creates a PathBuilder that constructs a static admin API path.
func adminPath(path string) PathBuilder {
	return func(baseURL string, _ interface{}) string {
		return baseURL + path
	}
}

// adminPathWithQuery creates a PathBuilder for a static path that carries
// the request's params as a query string. It returns "" when the request
// cannot be encoded, which the transport reports as an unbuildable path.
func adminPathWithQuery(path string, params []transport.QueryParam) PathBuilder {
	return func(baseURL string, req interface{}) string {
		query, err := transport.EncodeQuery(req, params)
		if err != nil {
			return ""
		}
		return baseURL + path + query
	}
}

// adminPathWithField creates a PathBuilder that substitutes a single request field
// into a path template. The placeholder in the template uses the format {fieldName}.
func adminPathWithField(pathTemplate, fieldName string) PathBuilder {
	return func(baseURL string, req interface{}) string {
		id := extractField(req, fieldName)
		if id == "" {
			return ""
		}
		path := strings.Replace(pathTemplate, "{"+fieldName+"}", id, 1)
		return baseURL + path
	}
}

// adminPathWithFields creates a PathBuilder that substitutes multiple request fields
// into a path template. Placeholders use the format {fieldName}.
func adminPathWithFields(pathTemplate string, fieldNames ...string) PathBuilder {
	return func(baseURL string, req interface{}) string {
		path := pathTemplate
		for _, field := range fieldNames {
			id := extractField(req, field)
			if id == "" {
				return ""
			}
			path = strings.Replace(path, "{"+field+"}", id, 1)
		}
		return baseURL + path
	}
}

// buildAdminRouteMap creates the map-based dispatch table for admin API endpoints.
func buildAdminRouteMap() map[string]RouteInfo {
	return map[string]RouteInfo{
		// Status service
		"admin.status/status": {
			Method:      MethodGET,
			PathBuilder: adminPath("/admin/status"),
		},
		"admin.status/stats": {
			Method:      MethodGET,
			PathBuilder: adminPath("/admin/stats"),
		},

		// Certificate service
		"admin.certificate/list": {
			Method:      MethodGET,
			PathBuilder: adminPath("/admin/certificates"),
		},
		"admin.certificate/get": {
			Method:      MethodGET,
			PathBuilder: adminPathWithField("/admin/certificates/{serial}", "serial"),
			ExtractID:   true,
		},
		"admin.certificate/revoke": {
			Method:      MethodPOST,
			PathBuilder: adminPathWithField("/admin/certificates/{serial}/revoke", "serial"),
			ExtractID:   true,
		},

		// Account service
		"admin.account/list": {
			Method:      MethodGET,
			PathBuilder: adminPath("/admin/accounts"),
		},
		"admin.account/get": {
			Method:      MethodGET,
			PathBuilder: adminPathWithField("/admin/accounts/{accountId}", "accountId"),
			ExtractID:   true,
		},
		"admin.account/disable": {
			Method:      MethodDELETE,
			PathBuilder: adminPathWithField("/admin/accounts/{accountId}", "accountId"),
			ExtractID:   true,
		},

		// Tenant service
		"admin.tenant/create": {
			Method:      MethodPOST,
			PathBuilder: adminPath("/api/v1/tenants/"),
		},
		"admin.tenant/list": {
			Method:      MethodGET,
			PathBuilder: adminPathWithQuery("/api/v1/tenants/", transport.TenantListQuery),
		},
		"admin.tenant/get": {
			Method:      MethodGET,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}", "tenantId"),
			ExtractID:   true,
		},
		"admin.tenant/update": {
			Method:      MethodPUT,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}", "tenantId"),
			ExtractID:   true,
		},
		"admin.tenant/delete": {
			Method:      MethodDELETE,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}", "tenantId"),
			ExtractID:   true,
		},
		"admin.tenant/updateStatus": {
			Method:      MethodPUT,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}/status", "tenantId"),
			ExtractID:   true,
		},

		// EAB service
		"admin.eab/create": {
			Method:      MethodPOST,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}/eab", "tenantId"),
			ExtractID:   true,
		},
		"admin.eab/list": {
			Method:      MethodGET,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}/eab", "tenantId"),
			ExtractID:   true,
		},
		"admin.eab/get": {
			Method:      MethodGET,
			PathBuilder: adminPathWithFields("/api/v1/tenants/{tenantId}/eab/{kid}", "tenantId", "kid"),
			ExtractID:   true,
		},
		"admin.eab/delete": {
			Method:      MethodDELETE,
			PathBuilder: adminPathWithFields("/api/v1/tenants/{tenantId}/eab/{kid}", "tenantId", "kid"),
			ExtractID:   true,
		},

		// Role service
		"admin.role/create": {
			Method:      MethodPOST,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}/roles", "tenantId"),
			ExtractID:   true,
		},
		"admin.role/list": {
			Method:      MethodGET,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}/roles", "tenantId"),
			ExtractID:   true,
		},
		"admin.role/get": {
			Method:      MethodGET,
			PathBuilder: adminPathWithFields("/api/v1/tenants/{tenantId}/roles/{roleId}", "tenantId", "roleId"),
			ExtractID:   true,
		},
		"admin.role/update": {
			Method:      MethodPUT,
			PathBuilder: adminPathWithFields("/api/v1/tenants/{tenantId}/roles/{id}", "tenantId", "id"),
			ExtractID:   true,
		},
		"admin.role/delete": {
			Method:      MethodDELETE,
			PathBuilder: adminPathWithFields("/api/v1/tenants/{tenantId}/roles/{roleId}", "tenantId", "roleId"),
			ExtractID:   true,
		},

		// User service
		"admin.user/create": {
			Method:      MethodPOST,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}/users", "tenantId"),
			ExtractID:   true,
		},
		"admin.user/list": {
			Method:      MethodGET,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}/users", "tenantId"),
			ExtractID:   true,
		},
		"admin.user/get": {
			Method:      MethodGET,
			PathBuilder: adminPathWithFields("/api/v1/tenants/{tenantId}/users/{userId}", "tenantId", "userId"),
			ExtractID:   true,
		},
		"admin.user/update": {
			Method:      MethodPUT,
			PathBuilder: adminPathWithFields("/api/v1/tenants/{tenantId}/users/{id}", "tenantId", "id"),
			ExtractID:   true,
		},
		"admin.user/delete": {
			Method:      MethodDELETE,
			PathBuilder: adminPathWithFields("/api/v1/tenants/{tenantId}/users/{userId}", "tenantId", "userId"),
			ExtractID:   true,
		},

		// Order service (admin)
		"admin.order/list": {
			Method:      MethodGET,
			PathBuilder: adminPath("/admin/orders"),
		},
		"admin.order/get": {
			Method:      MethodGET,
			PathBuilder: adminPathWithField("/admin/orders/{orderId}", "orderId"),
			ExtractID:   true,
		},

		// Tenant CA service
		"admin.tenant.ca/createRootCA": {
			Method:      MethodPOST,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}/root-ca", "tenantId"),
			ExtractID:   true,
		},
		"admin.tenant.ca/status": {
			Method:      MethodGET,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}/ca-status", "tenantId"),
			ExtractID:   true,
		},
		"admin.tenant.ca/createIntermediateCA": {
			Method:      MethodPOST,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}/intermediate-cas", "tenantId"),
			ExtractID:   true,
		},
		"admin.tenant.ca/listIntermediateCAs": {
			Method:      MethodGET,
			PathBuilder: adminPathWithField("/api/v1/tenants/{tenantId}/intermediate-cas", "tenantId"),
			ExtractID:   true,
		},
		"admin.tenant.ca/getIntermediateCA": {
			Method:      MethodGET,
			PathBuilder: adminPathWithFields("/api/v1/tenants/{tenantId}/intermediate-cas/{caId}", "tenantId", "caId"),
			ExtractID:   true,
		},
		"admin.tenant.ca/updateIntermediateCAStatus": {
			Method:      MethodPUT,
			PathBuilder: adminPathWithFields("/api/v1/tenants/{tenantId}/intermediate-cas/{caId}", "tenantId", "caId"),
			ExtractID:   true,
		},
	}
}
