// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-keychain/pkg/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestService(t *testing.T) *webauthn.Service {
	svc, err := webauthn.NewService(webauthn.ServiceParams{
		Config: &webauthn.Config{
			RPID:          "example.com",
			RPDisplayName: "Example",
			RPOrigins:     []string{"https://example.com"},
		},
		UserStore:       webauthn.NewMemoryUserStore(),
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: webauthn.NewMemoryCredentialStore(),
	})
	require.NoError(t, err)
	return svc
}

func TestMountChi(t *testing.T) {
	svc := newTestService(t)
	h := NewHandler(svc)

	r := chi.NewRouter()
	r.Route("/api/v1/webauthn", func(r chi.Router) {
		MountChi(r, h)
	})

	tests := []struct {
		method string
		path   string
		body   string
		want   int
	}{
		{http.MethodPost, "/api/v1/webauthn/registration/begin", `{"email":"test@example.com"}`, http.StatusOK},
		{http.MethodPost, "/api/v1/webauthn/registration/finish", "{}", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/webauthn/registration/status", "", http.StatusOK},
		{http.MethodPost, "/api/v1/webauthn/login/begin", "{}", http.StatusOK},
		{http.MethodPost, "/api/v1/webauthn/login/finish", "{}", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			var body *strings.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.want, rec.Code)
		})
	}
}

// mockMuxRouter implements MuxRouter for testing
type mockMuxRouter struct {
	routes map[string]mockMuxRoute
}

func newMockMuxRouter() *mockMuxRouter {
	return &mockMuxRouter{routes: make(map[string]mockMuxRoute)}
}

func (m *mockMuxRouter) HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) MuxRoute {
	route := mockMuxRoute{path: path, handler: f}
	m.routes[path] = route
	return &route
}

type mockMuxRoute struct {
	path    string
	methods []string
	handler func(http.ResponseWriter, *http.Request)
}

func (m *mockMuxRoute) Methods(methods ...string) MuxRoute {
	m.methods = methods
	return m
}

func TestMountMux(t *testing.T) {
	svc := newTestService(t)
	h := NewHandler(svc)

	r := newMockMuxRouter()
	MountMux(r, h)

	// Verify all routes are registered
	expectedRoutes := []string{
		"/registration/begin",
		"/registration/finish",
		"/registration/status",
		"/login/begin",
		"/login/finish",
	}

	for _, path := range expectedRoutes {
		route, ok := r.routes[path]
		assert.True(t, ok, "route %s should be registered", path)
		assert.NotNil(t, route.handler, "route %s should have handler", path)
	}
}

func TestMountStdlib(t *testing.T) {
	svc := newTestService(t)
	h := NewHandler(svc)

	mux := http.NewServeMux()
	MountStdlib(mux, "/api/v1/webauthn", h)

	tests := []struct {
		method string
		path   string
		body   string
		want   int
	}{
		{http.MethodPost, "/api/v1/webauthn/registration/begin", `{"email":"test@example.com"}`, http.StatusOK},
		{http.MethodPost, "/api/v1/webauthn/registration/finish", "{}", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/webauthn/registration/status", "", http.StatusOK},
		{http.MethodPost, "/api/v1/webauthn/login/begin", "{}", http.StatusOK},
		{http.MethodPost, "/api/v1/webauthn/login/finish", "{}", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			var body *strings.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, tt.want, rec.Code)
		})
	}
}

func TestHandler_Routes(t *testing.T) {
	svc := newTestService(t)
	h := NewHandler(svc)

	routes := h.Routes()

	assert.Len(t, routes, 5)

	expectedRoutes := map[string]string{
		"/registration/begin":  "POST",
		"/registration/finish": "POST",
		"/registration/status": "GET",
		"/login/begin":         "POST",
		"/login/finish":        "POST",
	}

	for _, route := range routes {
		expectedMethod, ok := expectedRoutes[route.Path]
		assert.True(t, ok, "unexpected route path: %s", route.Path)
		assert.Equal(t, expectedMethod, route.Method)
		assert.NotNil(t, route.Handler)
	}
}

func TestHandler_HandlerFunc(t *testing.T) {
	svc := newTestService(t)
	h := NewHandler(svc)

	handlerFunc := h.HandlerFunc()

	tests := []struct {
		path   string
		method string
		body   string
		want   int
	}{
		{"/registration/begin", http.MethodPost, `{"email":"test@example.com"}`, http.StatusOK},
		{"/registration/finish", http.MethodPost, "{}", http.StatusBadRequest},
		{"/registration/status", http.MethodGet, "", http.StatusOK},
		{"/login/begin", http.MethodPost, "{}", http.StatusOK},
		{"/login/finish", http.MethodPost, "{}", http.StatusBadRequest},
		{"/unknown", http.MethodGet, "", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			var body *strings.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handlerFunc(rec, req)
			assert.Equal(t, tt.want, rec.Code)
		})
	}
}

func TestHandler_HandlerFunc_WithStripPrefix(t *testing.T) {
	svc := newTestService(t)
	h := NewHandler(svc)

	mux := http.NewServeMux()
	mux.Handle("/api/v1/webauthn/", http.StripPrefix("/api/v1/webauthn", h.HandlerFunc()))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin",
		strings.NewReader(`{"email":"test@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
