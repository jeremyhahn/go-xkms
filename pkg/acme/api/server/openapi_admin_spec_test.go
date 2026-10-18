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

//go:build !integration

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api/swagger"
)

// mockTenantAwareAdminService composes the existing mockAdminService and
// mockTenantService test doubles (server_test.go), so the resulting type
// satisfies admin.TenantAwareService and buildRouter registers every route
// family a real deployment would: certificates, accounts, orders, status,
// stats, audit and algorithms (admin.Service); tenants, CA hierarchy, EAB,
// roles and users (admin.TenantService). It exists only so TestAdminOpenAPISpec_MatchesRouter
// walks the same route set a real deployment registers; none of its
// promoted methods are ever called.
type mockTenantAwareAdminService struct {
	mockAdminService
	mockTenantService
}

var _ admin.TenantAwareService = (*mockTenantAwareAdminService)(nil)

// pathParamPattern matches a single {name} path-parameter segment.
var pathParamPattern = regexp.MustCompile(`\{[^{}]+\}`)

// normalizeRoutePath collapses every {paramName} segment to a single "{}"
// token, so a router path built with gorilla mux's own parameter names
// (e.g. "/api/v1/tenants/{id}/roles/{roleID}") compares equal to the
// OpenAPI spec's path built with its documentation-oriented parameter names
// (e.g. "/api/v1/tenants/{tenantId}/roles/{roleID}"). The parameter's name
// is not part of the URL the router actually matches, so it is not part of
// "does this route exist" either.
func normalizeRoutePath(path string) string {
	return pathParamPattern.ReplaceAllString(path, "{}")
}

// infrastructureRoutePrefixes lists router paths that are deliberately not
// documented in admin-api.yaml: they are transport plumbing, not Admin API
// business capabilities.
//
//   - /health is an unauthenticated liveness probe, not an admin operation.
//   - /mcp is a single JSON-RPC 2.0 endpoint that dispatches to many methods
//     by request body, not by path or HTTP method; MCPToolPermissions
//     (pkg/acme/api/server/mcp_permissions.go) is that surface's own
//     contract, not something OpenAPI's path/method model can express.
//   - /docs and /openapi/ serve and describe this very spec; documenting
//     them inside the spec they serve is circular, and pkg/acme/api/swagger
//     already has its own request/response tests.
//   - /ui/admin/ is a static SPA asset tree (pkg/acme/gui/webui), not a set
//     of discrete REST resources.
var infrastructureRoutePrefixes = []string{
	"/health",
	"/mcp",
	"/docs",
	"/openapi/",
	"/ui/admin/",
}

func isInfrastructureRoute(path string) bool {
	for _, prefix := range infrastructureRoutePrefixes {
		if path == prefix || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// routerAdminAPIRoutes walks router and returns the set of "METHOD path"
// strings for every leaf route with an HTTP method matcher (excluding the
// infrastructure routes above), with path parameters normalized per
// normalizeRoutePath.
func routerAdminAPIRoutes(t *testing.T, router *mux.Router) map[string]bool {
	t.Helper()
	routes := map[string]bool{}

	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			// Intermediate PathPrefix().Subrouter() wrapper routes carry no
			// method matcher of their own; only their leaf routes do.
			return nil
		}
		pathTemplate, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		if isInfrastructureRoute(pathTemplate) {
			return nil
		}

		normalized := normalizeRoutePath(pathTemplate)
		for _, method := range methods {
			routes[method+" "+normalized] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk admin router: %v", err)
	}
	return routes
}

// specAdminAPIRoutes returns the set of "METHOD path" strings declared in
// doc, with path parameters normalized per normalizeRoutePath.
func specAdminAPIRoutes(doc *openapi3.T) map[string]bool {
	routes := map[string]bool{}
	for path, pathItem := range doc.Paths.Map() {
		normalized := normalizeRoutePath(path)
		for method := range pathItem.Operations() {
			routes[method+" "+normalized] = true
		}
	}
	return routes
}

// buildAdminAPIRouter constructs the same gorilla mux router buildRouter
// assembles for a real deployment: every admin.Service and admin.TenantService
// route family, plus /docs, /openapi, /health, /mcp
// and the admin web UI.
func buildAdminAPIRouter(t *testing.T) *mux.Router {
	t.Helper()
	tenantAware := &mockTenantAwareAdminService{}
	srv, err := NewMultiProtocolServer(
		&ServerConfig{
			RESTAddr:     ":0",
			GRPCAddr:     ":0",
			QUICAddr:     ":0",
			MCPAddr:      ":0",
			GRPCUnixPath: "/tmp/openapi-admin-spec-test.sock",
			Logger:       newTestLogger(),
		},
		tenantAware,
		tenantAware,
		&mockAuthHandler{},
	)
	if err != nil {
		t.Fatalf("failed to build admin API server: %v", err)
	}
	return srv.router
}

// loadAdminAPISpec fetches admin-api.yaml exactly as OpenAPISpecHandler
// serves it at runtime (the embedded pkg/acme/api/swagger/openapi/admin-api.yaml),
// rather than reading a file off disk that could drift from what is
// actually served, and validates it against the OpenAPI 3 schema.
func loadAdminAPISpec(t *testing.T) *openapi3.T {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/openapi/admin-api.yaml", nil)
	rec := httptest.NewRecorder()
	swagger.NewHandler(nil).OpenAPISpecHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("failed to fetch admin-api.yaml: status %d", rec.Code)
	}

	doc, err := openapi3.NewLoader().LoadFromData(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("failed to parse admin-api.yaml: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("admin-api.yaml failed OpenAPI 3 validation: %v", err)
	}
	return doc
}

// TestAdminOpenAPISpec_Valid asserts admin-api.yaml, as served by
// GET /openapi/admin-api.yaml, is a structurally valid OpenAPI 3 document.
func TestAdminOpenAPISpec_Valid(t *testing.T) {
	loadAdminAPISpec(t)
}

// TestAdminOpenAPISpec_MatchesRouter walks the real gorilla mux admin router
// buildRouter assembles and asserts admin-api.yaml declares exactly the same
// set of (method, path) routes: every router route appears in the spec, and
// every spec path/method appears in the router, modulo path-parameter names
// (see normalizeRoutePath) and the infrastructure routes documented on
// infrastructureRoutePrefixes.
func TestAdminOpenAPISpec_MatchesRouter(t *testing.T) {
	doc := loadAdminAPISpec(t)
	specRoutes := specAdminAPIRoutes(doc)
	routerRoutes := routerAdminAPIRoutes(t, buildAdminAPIRouter(t))

	var missingFromSpec, missingFromRouter []string
	for route := range routerRoutes {
		if !specRoutes[route] {
			missingFromSpec = append(missingFromSpec, route)
		}
	}
	for route := range specRoutes {
		if !routerRoutes[route] {
			missingFromRouter = append(missingFromRouter, route)
		}
	}
	sort.Strings(missingFromSpec)
	sort.Strings(missingFromRouter)

	if len(missingFromSpec) > 0 {
		t.Errorf("router routes missing from admin-api.yaml:\n  %s", strings.Join(missingFromSpec, "\n  "))
	}
	if len(missingFromRouter) > 0 {
		t.Errorf("admin-api.yaml routes not registered on the router:\n  %s", strings.Join(missingFromRouter, "\n  "))
	}
	if len(routerRoutes) == 0 {
		t.Fatal("router produced no routes to compare against the spec; the test itself is broken")
	}
}
