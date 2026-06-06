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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
)

func TestResponseWriter(t *testing.T) {
	t.Run("Captures status code on WriteHeader", func(t *testing.T) {
		w := httptest.NewRecorder()
		rw := newResponseWriter(w)

		rw.WriteHeader(http.StatusCreated)

		if rw.statusCode != http.StatusCreated {
			t.Errorf("Expected status code %d, got %d", http.StatusCreated, rw.statusCode)
		}

		if !rw.written {
			t.Error("Expected written flag to be true")
		}
	})

	t.Run("Default status code is 200", func(t *testing.T) {
		w := httptest.NewRecorder()
		rw := newResponseWriter(w)

		if rw.statusCode != http.StatusOK {
			t.Errorf("Expected default status code %d, got %d", http.StatusOK, rw.statusCode)
		}
	})

	t.Run("Write calls WriteHeader if not written", func(t *testing.T) {
		w := httptest.NewRecorder()
		rw := newResponseWriter(w)

		data := []byte("test")
		n, err := rw.Write(data)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		if n != len(data) {
			t.Errorf("Expected %d bytes written, got %d", len(data), n)
		}

		if !rw.written {
			t.Error("Expected written flag to be true")
		}

		if rw.statusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, rw.statusCode)
		}
	})

	t.Run("WriteHeader only once", func(t *testing.T) {
		w := httptest.NewRecorder()
		rw := newResponseWriter(w)

		rw.WriteHeader(http.StatusCreated)
		rw.WriteHeader(http.StatusBadRequest) // Should be ignored

		if rw.statusCode != http.StatusCreated {
			t.Errorf("Expected status code %d, got %d", http.StatusCreated, rw.statusCode)
		}
	})
}

func TestCORSMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := CORSMiddleware(handler)

	t.Run("Sets CORS headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Error("Access-Control-Allow-Origin header not set correctly")
		}

		if w.Header().Get("Access-Control-Allow-Methods") == "" {
			t.Error("Access-Control-Allow-Methods header not set")
		}

		if w.Header().Get("Access-Control-Allow-Headers") == "" {
			t.Error("Access-Control-Allow-Headers header not set")
		}

		if w.Header().Get("Access-Control-Max-Age") != "3600" {
			t.Error("Access-Control-Max-Age header not set correctly")
		}
	})

	t.Run("Handles OPTIONS preflight", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/test", nil)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("Calls next handler for non-OPTIONS", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	// A cross-origin browser frontend completes the WebAuthn ceremony by
	// sending X-Session-Id / X-User-Id on /finish and reading them from
	// /begin responses. Those headers must be both allowed and exposed.
	t.Run("Permits and exposes WebAuthn session headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/webauthn/login/finish", nil)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		allow := w.Header().Get("Access-Control-Allow-Headers")
		expose := w.Header().Get("Access-Control-Expose-Headers")
		for _, h := range []string{webauthnhttp.HeaderSessionID, webauthnhttp.HeaderUserID} {
			if !strings.Contains(allow, h) {
				t.Errorf("Access-Control-Allow-Headers missing %q: %q", h, allow)
			}
			if !strings.Contains(expose, h) {
				t.Errorf("Access-Control-Expose-Headers missing %q: %q", h, expose)
			}
		}
	})
}

func TestContentTypeMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := ContentTypeMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	contentType := w.Header().Get("Content-Type")
	expected := "application/json; charset=utf-8"
	if contentType != expected {
		t.Errorf("Expected Content-Type %s, got %s", expected, contentType)
	}
}
