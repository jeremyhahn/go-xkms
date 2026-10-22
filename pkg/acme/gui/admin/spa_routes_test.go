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

//go:build gui

package admin

import (
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	acmeadmin "github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
)

// spaClientSource is the admin SPA's API client. Every server call the
// embedded bundle makes goes through it, so it is the frontend's half of the
// route contract.
const spaClientSource = "../../web/packages/admin/src/lib/api/admin-api.ts"

// spaCallPattern matches one apiClient call in spaClientSource and captures
// its method and its path literal, e.g.
// apiClient.get<CertificateInfo>(`/admin/certificates/${serial}`).
var spaCallPattern = regexp.MustCompile("apiClient\\.(get|post|put|delete)(?:<[^(]*>)?\\(\\s*['`]([^'`]+)['`]")

// pathParamPattern matches a path parameter in either notation: a
// TypeScript ${...} interpolation or a gorilla/mux {name} segment.
var pathParamPattern = regexp.MustCompile(`\$\{[^}]+\}|\{[^}]+\}`)

// sdkGaps are the SPA calls the desktop router cannot serve yet. The ACME
// admin API serves both on xkmsd, but the SDK's trustedca.Client has no
// operation for either, and the desktop reaches the CA only through the SDK.
// TestApp_ServesEverySPACall asserts each is still unserved, so an entry
// cannot outlive the gap it records.
var sdkGaps = map[string]bool{
	"GET /admin/audit": true,
	"PUT /api/v1/tenants/{}/default-intermediate-ca": true,
}

// routeKey is "METHOD /path" with every path parameter written as {}, so a
// SPA call, a mounted route and an ACME admin route compare equal whatever
// they name their parameters.
func routeKey(method, path string) string {
	return method + " " + pathParamPattern.ReplaceAllString(path, "{}")
}

// samplePath fills every {} of a routeKey path with a concrete segment.
func samplePath(path string) string {
	return pathParamPattern.ReplaceAllString(path, "x1")
}

// spaCalls returns the routeKey of every call in spaClientSource.
func spaCalls(t *testing.T) map[string]bool {
	t.Helper()
	source, err := os.ReadFile(spaClientSource)
	if err != nil {
		t.Fatalf("reading the SPA API client: %v", err)
	}
	calls := make(map[string]bool)
	for _, match := range spaCallPattern.FindAllStringSubmatch(string(source), -1) {
		method := map[string]string{
			"get":    http.MethodGet,
			"post":   http.MethodPost,
			"put":    http.MethodPut,
			"delete": http.MethodDelete,
		}[match[1]]
		calls[routeKey(method, match[2])] = true
	}
	if len(calls) == 0 {
		t.Fatalf("no apiClient calls found in %s; the pattern no longer matches the client", spaClientSource)
	}
	return calls
}

// mountedRoutes returns the routeKey of every route the mounted router serves.
func mountedRoutes(t *testing.T, router *mux.Router) []string {
	t.Helper()
	var mounted []string
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		methods, err := route.GetMethods()
		if err != nil {
			// A PathPrefix route carrying a subrouter has no methods of its
			// own; only the leaves are API routes.
			return nil
		}
		path, err := route.GetPathTemplate()
		if err != nil {
			return err
		}
		for _, method := range methods {
			mounted = append(mounted, routeKey(method, path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}
	sort.Strings(mounted)
	return mounted
}

func mountedRouter(t *testing.T) *mux.Router {
	t.Helper()
	router, ok := mountedAPI(t, newTestApp()).(*mux.Router)
	if !ok {
		t.Fatal("the admin API handler must be the mux router")
	}
	return router
}

// TestApp_ServesEverySPACall proves every call the embedded SPA makes routes
// through the desktop router, except the recorded SDK gaps.
func TestApp_ServesEverySPACall(t *testing.T) {
	router := mountedRouter(t)
	calls := spaCalls(t)
	for key := range calls {
		t.Run(key, func(t *testing.T) {
			method, path, _ := strings.Cut(key, " ")
			served := routes(t, router, method, samplePath(path))
			switch {
			case sdkGaps[key] && served:
				t.Fatalf("%s is now served; remove it from sdkGaps", key)
			case !sdkGaps[key] && !served:
				t.Fatalf("the SPA calls %s but the desktop router does not serve it", key)
			}
		})
	}
	for key := range sdkGaps {
		if !calls[key] {
			t.Errorf("sdkGaps lists %s, which the SPA no longer calls", key)
		}
	}
}

// TestApp_ServesNothingTheSPACannotReach proves the desktop router exposes
// no route the bundle never calls.
func TestApp_ServesNothingTheSPACannotReach(t *testing.T) {
	calls := spaCalls(t)
	for _, key := range mountedRoutes(t, mountedRouter(t)) {
		if !calls[key] {
			t.Errorf("the desktop router serves %s, which the SPA never calls", key)
		}
	}
}

// TestApp_RoutesAreTheACMEAdminAPIs proves every desktop route is a route
// xkmsd serves the same bundle: the ACME admin API its /admin-ui host
// mounts, or the tenant lifecycle routes whose one owner is the core REST
// table (go-xkms#794). The SPA's one route set then works against both hosts.
func TestApp_RoutesAreTheACMEAdminAPIs(t *testing.T) {
	acme := make(map[string]bool)
	for _, rt := range acmeadmin.Routes() {
		acme[routeKey(rt.Method, rt.Path)] = true
	}
	for _, spec := range rest.Routes() {
		if spec.Auth == rest.RouteAuthTenant {
			acme[routeKey(spec.Method, spec.Pattern)] = true
		}
	}
	for _, key := range mountedRoutes(t, mountedRouter(t)) {
		if !acme[key] {
			t.Errorf("the desktop router serves %s, which the ACME admin API does not", key)
		}
	}
}

// TestApp_UnknownPathIsNotFound proves a path outside the route set,
// including the desktop router's former /api/v1 CA-wide paths, answers 404.
func TestApp_UnknownPathIsNotFound(t *testing.T) {
	router := mountedRouter(t)
	for _, path := range []string{
		"/api/v1/nonexistent",
		"/admin/nonexistent",
		"/api/v1/status",
		"/api/v1/certificates",
	} {
		t.Run(path, func(t *testing.T) {
			if rec := request(t, router, http.MethodGet, path); rec.Code != http.StatusNotFound {
				t.Fatalf("expected 404, got %d", rec.Code)
			}
		})
	}
}
