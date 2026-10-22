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

package quic

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// extractAdminField extracts a string field from a request by JSON marshaling it to a map.
// This avoids circular dependencies between the transport and admin client packages.
func extractAdminField(req interface{}, field string) string {
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

// decodeAdminJSONResponse decodes a generic admin JSON response.
func decodeAdminJSONResponse(body []byte, headers http.Header) (interface{}, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// adminStaticPath creates a routeConfig with a static path for admin endpoints.
func adminStaticPath(method, path string) *routeConfig {
	return &routeConfig{
		httpMethod:  method,
		path:        path,
		bodyEncoder: encodeJSONBody,
		respDecoder: decodeAdminJSONResponse,
	}
}

// adminStaticPathNoBody creates a routeConfig with a static path and no body encoding.
func adminStaticPathNoBody(method, path string) *routeConfig {
	return &routeConfig{
		httpMethod:  method,
		path:        path,
		bodyEncoder: nil,
		respDecoder: decodeAdminJSONResponse,
	}
}

// buildAdminRouteMap creates the admin route dispatch table for QUIC transport.
func buildAdminRouteMap() map[routeKey]*routeConfig {
	return map[routeKey]*routeConfig{
		// Status service
		{service: "admin.status", method: "status"}: adminStaticPathNoBody(http.MethodGet, "/admin/status"),
		{service: "admin.status", method: "stats"}:  adminStaticPathNoBody(http.MethodGet, "/admin/stats"),

		// Certificate service
		{service: "admin.certificate", method: "list"}:   adminStaticPathNoBody(http.MethodGet, "/admin/certificates"),
		{service: "admin.certificate", method: "get"}:    adminDynamicPath(http.MethodGet, "/admin/certificates/{serial}", "serial"),
		{service: "admin.certificate", method: "revoke"}: adminDynamicPath(http.MethodPost, "/admin/certificates/{serial}/revoke", "serial"),

		// Account service
		{service: "admin.account", method: "list"}:    adminStaticPathNoBody(http.MethodGet, "/admin/accounts"),
		{service: "admin.account", method: "get"}:     adminDynamicPath(http.MethodGet, "/admin/accounts/{accountId}", "accountId"),
		{service: "admin.account", method: "disable"}: adminDynamicPath(http.MethodDelete, "/admin/accounts/{accountId}", "accountId"),

		// Tenant service
		{service: "admin.tenant", method: "create"}:       adminStaticPath(http.MethodPost, "/api/v1/tenants/"),
		{service: "admin.tenant", method: "list"}:         adminDynamicFields(http.MethodGet, "/api/v1/tenants/"),
		{service: "admin.tenant", method: "get"}:          adminDynamicPath(http.MethodGet, "/api/v1/tenants/{tenantId}", "tenantId"),
		{service: "admin.tenant", method: "update"}:       adminDynamicPath(http.MethodPut, "/api/v1/tenants/{tenantId}", "tenantId"),
		{service: "admin.tenant", method: "delete"}:       adminDynamicPath(http.MethodDelete, "/api/v1/tenants/{tenantId}", "tenantId"),
		{service: "admin.tenant", method: "updateStatus"}: adminDynamicPath(http.MethodPut, "/api/v1/tenants/{tenantId}/status", "tenantId"),

		// EAB service
		{service: "admin.eab", method: "create"}: adminDynamicPath(http.MethodPost, "/api/v1/tenants/{tenantId}/eab", "tenantId"),
		{service: "admin.eab", method: "list"}:   adminDynamicPath(http.MethodGet, "/api/v1/tenants/{tenantId}/eab", "tenantId"),
		{service: "admin.eab", method: "get"}:    adminDynamicFields(http.MethodGet, "/api/v1/tenants/{tenantId}/eab/{kid}", "tenantId", "kid"),
		{service: "admin.eab", method: "delete"}: adminDynamicFields(http.MethodDelete, "/api/v1/tenants/{tenantId}/eab/{kid}", "tenantId", "kid"),

		// Role service
		{service: "admin.role", method: "create"}: adminDynamicPath(http.MethodPost, "/api/v1/tenants/{tenantId}/roles", "tenantId"),
		{service: "admin.role", method: "list"}:   adminDynamicPath(http.MethodGet, "/api/v1/tenants/{tenantId}/roles", "tenantId"),
		{service: "admin.role", method: "get"}:    adminDynamicFields(http.MethodGet, "/api/v1/tenants/{tenantId}/roles/{roleId}", "tenantId", "roleId"),
		{service: "admin.role", method: "update"}: adminDynamicFields(http.MethodPut, "/api/v1/tenants/{tenantId}/roles/{id}", "tenantId", "id"),
		{service: "admin.role", method: "delete"}: adminDynamicFields(http.MethodDelete, "/api/v1/tenants/{tenantId}/roles/{roleId}", "tenantId", "roleId"),

		// User service
		{service: "admin.user", method: "create"}: adminDynamicPath(http.MethodPost, "/api/v1/tenants/{tenantId}/users", "tenantId"),
		{service: "admin.user", method: "list"}:   adminDynamicPath(http.MethodGet, "/api/v1/tenants/{tenantId}/users", "tenantId"),
		{service: "admin.user", method: "get"}:    adminDynamicFields(http.MethodGet, "/api/v1/tenants/{tenantId}/users/{userId}", "tenantId", "userId"),
		{service: "admin.user", method: "update"}: adminDynamicFields(http.MethodPut, "/api/v1/tenants/{tenantId}/users/{id}", "tenantId", "id"),
		{service: "admin.user", method: "delete"}: adminDynamicFields(http.MethodDelete, "/api/v1/tenants/{tenantId}/users/{userId}", "tenantId", "userId"),

		// Order service (admin)
		{service: "admin.order", method: "list"}: adminStaticPathNoBody(http.MethodGet, "/admin/orders"),
		{service: "admin.order", method: "get"}:  adminDynamicPath(http.MethodGet, "/admin/orders/{orderId}", "orderId"),

		// Tenant CA service
		{service: "admin.tenant.ca", method: "createRootCA"}:               adminDynamicPath(http.MethodPost, "/api/v1/tenants/{tenantId}/root-ca", "tenantId"),
		{service: "admin.tenant.ca", method: "status"}:                     adminDynamicPath(http.MethodGet, "/api/v1/tenants/{tenantId}/ca-status", "tenantId"),
		{service: "admin.tenant.ca", method: "createIntermediateCA"}:       adminDynamicPath(http.MethodPost, "/api/v1/tenants/{tenantId}/intermediate-cas", "tenantId"),
		{service: "admin.tenant.ca", method: "listIntermediateCAs"}:        adminDynamicPath(http.MethodGet, "/api/v1/tenants/{tenantId}/intermediate-cas", "tenantId"),
		{service: "admin.tenant.ca", method: "getIntermediateCA"}:          adminDynamicFields(http.MethodGet, "/api/v1/tenants/{tenantId}/intermediate-cas/{caId}", "tenantId", "caId"),
		{service: "admin.tenant.ca", method: "updateIntermediateCAStatus"}: adminDynamicFields(http.MethodPut, "/api/v1/tenants/{tenantId}/intermediate-cas/{caId}", "tenantId", "caId"),
	}
}

// adminDynamicPath creates a routeConfig where a single field is substituted into the path template.
// The path template is stored in routeConfig.path as empty string since it is resolved dynamically.
func adminDynamicPath(httpMethod, pathTemplate, fieldName string) *routeConfig {
	return &routeConfig{
		httpMethod: httpMethod,
		path:       "", // Resolved dynamically in resolveAdminURL
		bodyEncoder: func(req interface{}) ([]byte, error) {
			if httpMethod == http.MethodPost || httpMethod == http.MethodPut {
				return encodeJSONBody(req)
			}
			return nil, nil
		},
		respDecoder: decodeAdminJSONResponse,
	}
}

// adminDynamicFields creates a routeConfig where multiple fields are substituted into the path template.
func adminDynamicFields(httpMethod, pathTemplate string, fieldNames ...string) *routeConfig {
	return &routeConfig{
		httpMethod: httpMethod,
		path:       "", // Resolved dynamically in resolveAdminURL
		bodyEncoder: func(req interface{}) ([]byte, error) {
			if httpMethod == http.MethodPost || httpMethod == http.MethodPut {
				return encodeJSONBody(req)
			}
			return nil, nil
		},
		respDecoder: decodeAdminJSONResponse,
	}
}

// adminPathTemplates maps route keys to their path templates for dynamic admin URL resolution.
var adminPathTemplates = map[routeKey]adminPathInfo{
	// Certificate
	{service: "admin.certificate", method: "get"}:    {template: "/admin/certificates/{serial}", fields: []string{"serial"}},
	{service: "admin.certificate", method: "revoke"}: {template: "/admin/certificates/{serial}/revoke", fields: []string{"serial"}},

	// Account
	{service: "admin.account", method: "get"}:     {template: "/admin/accounts/{accountId}", fields: []string{"accountId"}},
	{service: "admin.account", method: "disable"}: {template: "/admin/accounts/{accountId}", fields: []string{"accountId"}},

	// Tenant
	{service: "admin.tenant", method: "list"}:         {template: "/api/v1/tenants/", query: transport.TenantListQuery},
	{service: "admin.tenant", method: "get"}:          {template: "/api/v1/tenants/{tenantId}", fields: []string{"tenantId"}},
	{service: "admin.tenant", method: "update"}:       {template: "/api/v1/tenants/{tenantId}", fields: []string{"tenantId"}},
	{service: "admin.tenant", method: "delete"}:       {template: "/api/v1/tenants/{tenantId}", fields: []string{"tenantId"}},
	{service: "admin.tenant", method: "updateStatus"}: {template: "/api/v1/tenants/{tenantId}/status", fields: []string{"tenantId"}},

	// EAB
	{service: "admin.eab", method: "create"}: {template: "/api/v1/tenants/{tenantId}/eab", fields: []string{"tenantId"}},
	{service: "admin.eab", method: "list"}:   {template: "/api/v1/tenants/{tenantId}/eab", fields: []string{"tenantId"}},
	{service: "admin.eab", method: "get"}:    {template: "/api/v1/tenants/{tenantId}/eab/{kid}", fields: []string{"tenantId", "kid"}},
	{service: "admin.eab", method: "delete"}: {template: "/api/v1/tenants/{tenantId}/eab/{kid}", fields: []string{"tenantId", "kid"}},

	// Role
	{service: "admin.role", method: "create"}: {template: "/api/v1/tenants/{tenantId}/roles", fields: []string{"tenantId"}},
	{service: "admin.role", method: "list"}:   {template: "/api/v1/tenants/{tenantId}/roles", fields: []string{"tenantId"}},
	{service: "admin.role", method: "get"}:    {template: "/api/v1/tenants/{tenantId}/roles/{roleId}", fields: []string{"tenantId", "roleId"}},
	{service: "admin.role", method: "update"}: {template: "/api/v1/tenants/{tenantId}/roles/{id}", fields: []string{"tenantId", "id"}},
	{service: "admin.role", method: "delete"}: {template: "/api/v1/tenants/{tenantId}/roles/{roleId}", fields: []string{"tenantId", "roleId"}},

	// User
	{service: "admin.user", method: "create"}: {template: "/api/v1/tenants/{tenantId}/users", fields: []string{"tenantId"}},
	{service: "admin.user", method: "list"}:   {template: "/api/v1/tenants/{tenantId}/users", fields: []string{"tenantId"}},
	{service: "admin.user", method: "get"}:    {template: "/api/v1/tenants/{tenantId}/users/{userId}", fields: []string{"tenantId", "userId"}},
	{service: "admin.user", method: "update"}: {template: "/api/v1/tenants/{tenantId}/users/{id}", fields: []string{"tenantId", "id"}},
	{service: "admin.user", method: "delete"}: {template: "/api/v1/tenants/{tenantId}/users/{userId}", fields: []string{"tenantId", "userId"}},

	// Order
	{service: "admin.order", method: "get"}: {template: "/admin/orders/{orderId}", fields: []string{"orderId"}},

	// Tenant CA
	{service: "admin.tenant.ca", method: "createRootCA"}:               {template: "/api/v1/tenants/{tenantId}/root-ca", fields: []string{"tenantId"}},
	{service: "admin.tenant.ca", method: "status"}:                     {template: "/api/v1/tenants/{tenantId}/ca-status", fields: []string{"tenantId"}},
	{service: "admin.tenant.ca", method: "createIntermediateCA"}:       {template: "/api/v1/tenants/{tenantId}/intermediate-cas", fields: []string{"tenantId"}},
	{service: "admin.tenant.ca", method: "listIntermediateCAs"}:        {template: "/api/v1/tenants/{tenantId}/intermediate-cas", fields: []string{"tenantId"}},
	{service: "admin.tenant.ca", method: "getIntermediateCA"}:          {template: "/api/v1/tenants/{tenantId}/intermediate-cas/{caId}", fields: []string{"tenantId", "caId"}},
	{service: "admin.tenant.ca", method: "updateIntermediateCAStatus"}: {template: "/api/v1/tenants/{tenantId}/intermediate-cas/{caId}", fields: []string{"tenantId", "caId"}},
}

// adminPathInfo holds template, field and query info for dynamic admin URL
// resolution.
type adminPathInfo struct {
	template string
	fields   []string
	query    []transport.QueryParam
}

// resolveAdminURL resolves a dynamic admin URL by substituting fields from the request.
func resolveAdminURL(baseURL string, key routeKey, req interface{}) string {
	info, ok := adminPathTemplates[key]
	if !ok {
		return ""
	}

	path := info.template
	for _, field := range info.fields {
		id := extractAdminField(req, field)
		if id == "" {
			return ""
		}
		path = strings.Replace(path, "{"+field+"}", id, 1)
	}
	query, err := transport.EncodeQuery(req, info.query)
	if err != nil {
		return ""
	}
	return baseURL + path + query
}

// isAdminRoute returns true if the service name is an admin service.
func isAdminRoute(service string) bool {
	return strings.HasPrefix(service, "admin.")
}
