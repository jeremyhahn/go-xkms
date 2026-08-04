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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func TestNewHandler_CustomConfig(t *testing.T) {
	h := NewHandler(&Config{
		BasePath:    "/api-docs",
		Title:       "Custom Title",
		DefaultSpec: "admin-api",
	})
	if h.basePath != "/api-docs" {
		t.Errorf("expected basePath /api-docs, got %s", h.basePath)
	}
	if h.defaultSpec != "admin-api" {
		t.Errorf("expected defaultSpec admin-api, got %s", h.defaultSpec)
	}
	if h.title != "Custom Title" {
		t.Errorf("expected Custom Title, got %s", h.title)
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

	// Verify it contains Swagger UI elements
	if !strings.Contains(bodyStr, "swagger-ui") {
		t.Error("expected body to contain swagger-ui")
	}
	if !strings.Contains(bodyStr, "SwaggerUIBundle") {
		t.Error("expected body to contain SwaggerUIBundle")
	}
}

func TestSwaggerUIHandler_SpecQueryParam(t *testing.T) {
	h := NewHandler(nil)

	tests := []struct {
		name           string
		querySpec      string
		expectedSpec   string
		expectedActive string
	}{
		{"default_acme", "", "acme-api", "acme-api"},
		{"explicit_acme", "acme-api", "acme-api", "acme-api"},
		{"admin_api", "admin-api", "admin-api", "admin-api"},
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

			// Check the spec URL is correctly set (template escapes slashes in JS)
			expectedSpec := tc.expectedSpec + ".yaml"
			if !strings.Contains(bodyStr, expectedSpec) {
				t.Errorf("expected body to contain %s", expectedSpec)
			}
		})
	}
}

func TestSwaggerUIHandler_WithLogger(t *testing.T) {
	logger := slog.Default()
	h := NewHandler(&Config{
		Logger: logger,
	})
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec := httptest.NewRecorder()

	h.SwaggerUIHandler(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "swagger-ui") {
		t.Error("expected body to contain swagger-ui")
	}
}

func TestSwaggerUIHandler_TemplateError_NoLogger(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	w := newFailingResponseWriter()

	// This should trigger the error path when the template fails to write
	h.SwaggerUIHandler(w, req)

	// The error handler sets a 500 status code
	if w.statusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.statusCode)
	}
}

func TestSwaggerUIHandler_TemplateError_WithLogger(t *testing.T) {
	logger := slog.Default()
	h := NewHandler(&Config{
		Logger: logger,
	})
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	w := newFailingResponseWriter()

	// This should trigger the error path with logging when the template fails to write
	h.SwaggerUIHandler(w, req)

	// The error handler sets a 500 status code
	if w.statusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.statusCode)
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

	// Verify it's a valid OpenAPI spec
	if !strings.Contains(bodyStr, "openapi: 3.0.3") {
		t.Error("expected body to contain openapi version")
	}
	if !strings.Contains(bodyStr, "ACME") {
		t.Error("expected body to contain ACME")
	}
}

func TestOpenAPISpecHandler_AdminSpec(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/openapi/admin-api.yaml", nil)
	rec := httptest.NewRecorder()

	h.OpenAPISpecHandler(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify it's a valid OpenAPI spec
	if !strings.Contains(bodyStr, "openapi: 3.0.3") {
		t.Error("expected body to contain openapi version")
	}
	if !strings.Contains(bodyStr, "Admin API") {
		t.Error("expected body to contain Admin API")
	}
}

func TestOpenAPISpecHandler_NotFound(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/openapi/nonexistent.yaml", nil)
	rec := httptest.NewRecorder()

	h.OpenAPISpecHandler(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}
}

func TestOpenAPISpecHandler_CORSHeader(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/openapi/acme-api.yaml", nil)
	rec := httptest.NewRecorder()

	h.OpenAPISpecHandler(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	cors := resp.Header.Get("Access-Control-Allow-Origin")
	if cors != "*" {
		t.Errorf("expected CORS header *, got %s", cors)
	}
}

func TestOpenAPISpecHandler_WithLogger(t *testing.T) {
	logger := slog.Default()
	h := NewHandler(&Config{
		Logger: logger,
	})
	req := httptest.NewRequest(http.MethodGet, "/openapi/acme-api.yaml", nil)
	rec := httptest.NewRecorder()

	h.OpenAPISpecHandler(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestOpenAPISpecHandler_NotFound_WithLogger(t *testing.T) {
	logger := slog.Default()
	h := NewHandler(&Config{
		Logger: logger,
	})
	req := httptest.NewRequest(http.MethodGet, "/openapi/nonexistent.yaml", nil)
	rec := httptest.NewRecorder()

	h.OpenAPISpecHandler(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}
}

func TestRegisterMux(t *testing.T) {
	h := NewHandler(&Config{
		BasePath: "/docs",
	})
	mux := http.NewServeMux()
	h.RegisterMux(mux)

	// Test base docs path
	t.Run("base_path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/docs", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		resp := rec.Result()
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(contentType, "text/html") {
			t.Errorf("expected text/html content type, got %s", contentType)
		}
	})

	// Test docs path with trailing slash
	t.Run("base_path_trailing_slash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/docs/", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		resp := rec.Result()
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
	})

	// Test OpenAPI spec endpoint
	t.Run("openapi_spec", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/openapi/acme-api.yaml", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		resp := rec.Result()
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType != "application/yaml" {
			t.Errorf("expected application/yaml, got %s", contentType)
		}
	})
}

func TestRegisterMux_CustomBasePath(t *testing.T) {
	h := NewHandler(&Config{
		BasePath: "/api-docs",
	})
	mux := http.NewServeMux()
	h.RegisterMux(mux)

	// Test custom base path
	req := httptest.NewRequest(http.MethodGet, "/api-docs", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
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
	mux := http.NewServeMux()
	h.RegisterMux(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Test Swagger UI endpoint via HTTP server
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
		if !strings.Contains(bodyStr, "admin-api.yaml") {
			t.Error("expected default spec to be admin-api")
		}
		if !strings.Contains(bodyStr, "Test API") {
			t.Error("expected custom title")
		}
	})

	// Test OpenAPI spec endpoint via HTTP server
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
}
