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

package swagger

import (
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// failingResponseWriter is a ResponseWriter that fails on Write to trigger error paths.
type failingResponseWriter struct {
	header     http.Header
	statusCode int
}

func newFailingResponseWriter() *failingResponseWriter {
	return &failingResponseWriter{
		header: make(http.Header),
	}
}

func (f *failingResponseWriter) Header() http.Header {
	return f.header
}

func (f *failingResponseWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("simulated write failure")
}

func (f *failingResponseWriter) WriteHeader(statusCode int) {
	f.statusCode = statusCode
}

// fakeAuthMiddleware stands in for the production mTLS/JWT admin.AuthHandler.
// It publishes a fixed identity on the request context, mirroring what real
// authentication middleware does after verifying credentials, so
// PermissionGate.Authorize has something to evaluate.
type fakeAuthMiddleware struct {
	identity *auth.Identity
}

func (f fakeAuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.identity != nil {
			r = r.WithContext(auth.WithIdentity(r.Context(), f.identity))
		}
		next.ServeHTTP(w, r)
	})
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// permissiveGate returns a gate whose authorizer has no RBAC client, so
// authorization is disabled (RBAC-disabled => allow-all). Authentication is
// still mandatory: a request with no identity is denied regardless.
func permissiveGate() *admin.PermissionGate {
	return admin.NewPermissionGate(auth.NewAuthorizer(nil), discardLogger())
}

func authenticatedIdentity() *auth.Identity {
	return &auth.Identity{Subject: "test-admin", TenantID: "system"}
}

func TestNewHandler_DefaultConfig(t *testing.T) {
	h := NewHandler(nil)
	if h.basePath != "/docs" {
		t.Errorf("expected basePath /docs, got %s", h.basePath)
	}
	if h.defaultSpec != "acme-api" {
		t.Errorf("expected defaultSpec acme-api, got %s", h.defaultSpec)
	}
	if h.title != "go-xkms API Documentation" {
		t.Errorf("expected default title, got %s", h.title)
	}
}

func TestNewHandler_WithLogger(t *testing.T) {
	logger := slog.Default()
	h := NewHandler(&Config{
		Logger: logger,
	})
	if h.logger != logger {
		t.Error("expected logger to be set")
	}
}

func TestSwaggerUIHandler_ReturnsHTML(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec := httptest.NewRecorder()

	h.SwaggerUIHandler(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected text/html content type, got %s", contentType)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "swagger-ui") {
		t.Error("expected body to contain swagger-ui")
	}
	if !strings.Contains(bodyStr, "/docs/swagger-ui-bundle.js") {
		t.Error("expected body to load the vendored bundle from the docs base path")
	}
	if !strings.Contains(bodyStr, "/docs/swagger-initializer.js") {
		t.Error("expected body to load the externalized initializer script")
	}
	if strings.Contains(bodyStr, "unpkg.com") {
		t.Error("expected body to contain no CDN references")
	}
	if strings.Contains(bodyStr, "SwaggerUIBundle(") {
		t.Error("expected the page-configuration call to live in the externalized initializer, not inline")
	}
}

func TestSwaggerUIHandler_SetsStrictCSP(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec := httptest.NewRecorder()

	h.SwaggerUIHandler(rec, req)

	csp := rec.Result().Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("expected a Content-Security-Policy header")
	}
	for _, want := range []string{
		"default-src 'self'",
		"script-src 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("expected CSP to contain %q, got %q", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-eval") {
		t.Errorf("expected CSP to forbid unsafe-eval, got %q", csp)
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("expected script-src to forbid unsafe-inline, got %q", csp)
	}
}

func TestSwaggerUIHandler_SpecQueryParam(t *testing.T) {
	h := NewHandler(nil)

	tests := []struct {
		name           string
		querySpec      string
		expectedActive string
	}{
		{"default_acme", "", "acme-api"},
		{"admin_api", "admin-api", "admin-api"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url := "/docs"
			if tc.querySpec != "" {
				url += "?spec=" + tc.querySpec
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			rec := httptest.NewRecorder()

			h.SwaggerUIHandler(rec, req)

			body, _ := io.ReadAll(rec.Body)
			bodyStr := string(body)

			// The initializer script URL carries the selected spec as a
			// query parameter; the initializer itself resolves it to the
			// openapi/{spec}.yaml URL.
			if !strings.Contains(bodyStr, "swagger-initializer.js?spec="+tc.expectedActive) {
				t.Errorf("expected body to select spec %s, got %s", tc.expectedActive, bodyStr)
			}
		})
	}
}

func TestSwaggerUIHandler_TemplateError(t *testing.T) {
	for name, h := range map[string]*Handler{
		"no_logger":   NewHandler(nil),
		"with_logger": NewHandler(&Config{Logger: discardLogger()}),
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/docs", nil)
			w := newFailingResponseWriter()

			// A failing writer makes the template execution fail.
			h.SwaggerUIHandler(w, req)

			if w.statusCode != http.StatusInternalServerError {
				t.Errorf("expected status 500, got %d", w.statusCode)
			}
		})
	}
}

func TestInitializerHandler_RendersSelectedSpec(t *testing.T) {
	h := NewHandler(&Config{DefaultSpec: "acme-api"})

	tests := []struct {
		name        string
		querySpec   string
		expectedURL string
	}{
		{"default", "", "/openapi/acme-api.yaml"},
		{"admin", "admin-api", "/openapi/admin-api.yaml"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url := "/docs/swagger-initializer.js"
			if tc.querySpec != "" {
				url += "?spec=" + tc.querySpec
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			rec := httptest.NewRecorder()

			h.InitializerHandler(rec, req)

			resp := rec.Result()
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status 200, got %d", resp.StatusCode)
			}
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "javascript") {
				t.Errorf("expected a javascript content type, got %s", ct)
			}

			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)
			if !strings.Contains(bodyStr, `url: "`+tc.expectedURL+`"`) {
				t.Errorf("expected body to embed spec URL %s, got %s", tc.expectedURL, bodyStr)
			}
			if !strings.Contains(bodyStr, "SwaggerUIBundle({") {
				t.Error("expected body to configure SwaggerUIBundle")
			}
		})
	}
}

func TestInitializerHandler_UnknownSpecNotFound(t *testing.T) {
	for name, h := range map[string]*Handler{
		"no_logger":   NewHandler(&Config{DefaultSpec: "acme-api"}),
		"with_logger": NewHandler(&Config{DefaultSpec: "acme-api", Logger: discardLogger()}),
	} {
		t.Run(name, func(t *testing.T) {
			for _, spec := range []string{"missing", `x";alert(1);//`, "../acme-api"} {
				req := httptest.NewRequest(http.MethodGet, "/docs/swagger-initializer.js?spec="+url.QueryEscape(spec), nil)
				rec := httptest.NewRecorder()

				h.InitializerHandler(rec, req)

				if rec.Code != http.StatusNotFound {
					t.Errorf("spec %q: expected status 404, got %d", spec, rec.Code)
				}
			}
		})
	}
}

func TestSpecURLs_MatchEmbeddedSpecs(t *testing.T) {
	for name, specURL := range specURLs {
		if _, err := fs.ReadFile(openAPISpecs, "openapi/"+name+".yaml"); err != nil {
			t.Errorf("spec %q (%s) is not embedded: %v", name, specURL, err)
		}
	}
}

func TestInitializerHandler_TemplateError(t *testing.T) {
	for name, h := range map[string]*Handler{
		"no_logger":   NewHandler(nil),
		"with_logger": NewHandler(&Config{Logger: discardLogger()}),
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/docs/swagger-initializer.js", nil)
			w := newFailingResponseWriter()

			h.InitializerHandler(w, req)

			if w.statusCode != http.StatusInternalServerError {
				t.Errorf("expected status 500, got %d", w.statusCode)
			}
		})
	}
}

func TestAssetHandler_ServesVendoredCSS(t *testing.T) {
	h := NewHandler(&Config{Logger: discardLogger()})
	req := httptest.NewRequest(http.MethodGet, "/docs/swagger-ui.css", nil)
	rec := httptest.NewRecorder()

	h.AssetHandler(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/css") {
		t.Errorf("expected text/css content type, got %s", ct)
	}
}

func TestAssetHandler_ServesVendoredBundleAndPreset(t *testing.T) {
	h := NewHandler(nil)

	for _, name := range []string{"swagger-ui-bundle.js", "swagger-ui-standalone-preset.js", "favicon-32x32.png"} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/docs/"+name, nil)
			rec := httptest.NewRecorder()

			h.AssetHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status 200 for %s, got %d", name, rec.Code)
			}
			if rec.Body.Len() == 0 {
				t.Errorf("expected non-empty body for %s", name)
			}
		})
	}
}

func TestAssetHandler_UnknownAssetNotFound(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/docs/does-not-exist.js", nil)
	rec := httptest.NewRecorder()

	h.AssetHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

// TestAssetHandler_LicenseFilesNotServed asserts the provenance files vendored
// alongside the UI assets (LICENSE, NOTICE, VERSION) are never reachable over
// HTTP: only the //go:embed'd *.css/*.js/*.png globs are exposed.
func TestAssetHandler_LicenseFilesNotServed(t *testing.T) {
	h := NewHandler(nil)

	for _, name := range []string{"LICENSE", "NOTICE", "VERSION"} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/docs/"+name, nil)
			rec := httptest.NewRecorder()

			h.AssetHandler(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Errorf("expected %s to be unreachable (404), got %d", name, rec.Code)
			}
		})
	}
}

func TestOpenAPISpecHandler_ACMESpec(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/openapi/acme-api.yaml", nil)
	rec := httptest.NewRecorder()

	h.OpenAPISpecHandler(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/yaml" {
		t.Errorf("expected application/yaml, got %s", contentType)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "openapi: 3.0.3") {
		t.Error("expected body to contain openapi version")
	}
	if !strings.Contains(bodyStr, "ACME") {
		t.Error("expected body to contain ACME")
	}
}

func TestOpenAPISpecHandler_NotFound(t *testing.T) {
	for name, h := range map[string]*Handler{
		"no_logger":   NewHandler(nil),
		"with_logger": NewHandler(&Config{Logger: discardLogger()}),
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/openapi/nonexistent.yaml", nil)
			rec := httptest.NewRecorder()

			h.OpenAPISpecHandler(rec, req)

			resp := rec.Result()
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("expected status 404, got %d", resp.StatusCode)
			}
		})
	}
}

// TestOpenAPISpecHandler_NoWildcardCORS asserts the spec endpoint no longer
// sets Access-Control-Allow-Origin: *. The endpoint is gated behind admin
// authentication (see TestRegisterRoutes_RequiresAuthentication); a wildcard
// CORS header on an authenticated admin response is exactly the kind of
// leftover permissiveness that made this endpoint's move from "unserved" to
// "gated" worth auditing for.
func TestOpenAPISpecHandler_NoWildcardCORS(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/openapi/acme-api.yaml", nil)
	rec := httptest.NewRecorder()

	h.OpenAPISpecHandler(rec, req)

	if cors := rec.Result().Header.Get("Access-Control-Allow-Origin"); cors != "" {
		t.Errorf("expected no Access-Control-Allow-Origin header, got %q", cors)
	}
}

func TestRegisterMux(t *testing.T) {
	h := NewHandler(&Config{
		BasePath: "/docs",
	})
	serveMux := http.NewServeMux()
	h.RegisterMux(serveMux)

	t.Run("base_path_trailing_slash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/docs/", nil)
		rec := httptest.NewRecorder()
		serveMux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("vendored_asset", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/docs/swagger-ui.css", nil)
		rec := httptest.NewRecorder()
		serveMux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})
}

func TestRegisterMux_CustomBasePath(t *testing.T) {
	h := NewHandler(&Config{
		BasePath: "/api-docs",
	})
	serveMux := http.NewServeMux()
	h.RegisterMux(serveMux)

	req := httptest.NewRequest(http.MethodGet, "/api-docs", nil)
	rec := httptest.NewRecorder()
	serveMux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "swagger-ui") {
		t.Error("expected response to contain swagger-ui")
	}
}

func TestRegisterMux_IntegrationWithServer(t *testing.T) {
	h := NewHandler(&Config{
		BasePath:    "/docs",
		Title:       "Test API",
		DefaultSpec: "admin-api",
		Logger:      slog.Default(),
	})
	serveMux := http.NewServeMux()
	h.RegisterMux(serveMux)

	server := httptest.NewServer(serveMux)
	defer server.Close()

	t.Run("swagger_ui_via_server", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/docs")
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Should use default spec (admin-api)
		if !strings.Contains(bodyStr, "swagger-initializer.js?spec=admin-api") {
			t.Error("expected default spec to be admin-api")
		}
		if !strings.Contains(bodyStr, "Test API") {
			t.Error("expected custom title")
		}
	})

	t.Run("openapi_spec_via_server", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/openapi/admin-api.yaml")
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "openapi:") {
			t.Error("expected valid OpenAPI spec")
		}
	})

	t.Run("initializer_via_server", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/docs/swagger-initializer.js?spec=acme-api")
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), `url: "/openapi/acme-api.yaml"`) {
			t.Errorf("expected initializer to select acme-api spec, got %s", string(body))
		}
	})
}

// TestRegisterRoutes verifies every docs and openapi route is registered on
// the gorilla mux router and, once authenticated against a permissive gate
// (RBAC disabled), actually reachable.
func TestRegisterRoutes(t *testing.T) {
	h := NewHandler(nil)
	router := mux.NewRouter()
	authMiddleware := fakeAuthMiddleware{identity: authenticatedIdentity()}
	h.RegisterRoutes(router, authMiddleware, permissiveGate())

	tests := []struct {
		name   string
		path   string
		status int
	}{
		{"docs_exact", "/docs", http.StatusOK},
		{"docs_trailing_slash", "/docs/", http.StatusOK},
		{"docs_initializer", "/docs/swagger-initializer.js", http.StatusOK},
		{"docs_asset", "/docs/swagger-ui.css", http.StatusOK},
		{"openapi_admin", "/openapi/admin-api.yaml", http.StatusOK},
		{"openapi_acme", "/openapi/acme-api.yaml", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tc.status {
				t.Errorf("%s: expected status %d, got %d", tc.path, tc.status, rec.Code)
			}
		})
	}
}

// TestRegisterRoutes_RequiresAuthentication asserts /docs and /openapi are
// gated, not public: a request that never reaches the identity-publishing
// auth middleware is denied rather than served, exactly like every other
// route this package registers through admin.PermissionGate.
func TestRegisterRoutes_RequiresAuthentication(t *testing.T) {
	h := NewHandler(nil)
	router := mux.NewRouter()
	// No identity is attached, mirroring an unauthenticated caller.
	h.RegisterRoutes(router, fakeAuthMiddleware{}, permissiveGate())

	for _, path := range []string{"/docs", "/openapi/admin-api.yaml"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected status 401 for unauthenticated %s, got %d", path, rec.Code)
			}
		})
	}
}

// TestRegisterRoutes_NilAuthMiddleware exercises registration with a nil
// admin.AuthHandler (a deployment that authenticates elsewhere in the
// chain). The gate still enforces: no identity means no access.
func TestRegisterRoutes_NilAuthMiddleware(t *testing.T) {
	h := NewHandler(nil)
	router := mux.NewRouter()
	h.RegisterRoutes(router, nil, permissiveGate())

	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

// TestErrAssetLoad_Error confirms the packaging-defect error names both the
// origin package and the underlying detail, so a panic surfaced from
// uiAssetsFS's init identifies itself unambiguously.
func TestErrAssetLoad_Error(t *testing.T) {
	err := &ErrAssetLoad{Detail: "sub dir: no such directory"}

	want := "swagger: failed to load vendored UI assets: sub dir: no such directory"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestInitializerHandler_UnknownSpecNotFound_WithLogger exercises the same
// unknown-spec 404 path as TestInitializerHandler_UnknownSpecNotFound, but
// with a logger attached so the warning branch runs too.
// TestInitializerHandler_TemplateError_WithLogger exercises the template
// rendering failure branch with a logger attached, mirroring
// TestInitializerHandler_TemplateError but confirming the logger.Error call
// does not itself panic or otherwise disrupt the 500 response.
// TestAssetHandler_WithLogger exercises AssetHandler's debug-logging branch,
// which the logger-less tests above never reach.
