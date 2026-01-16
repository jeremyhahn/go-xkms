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

package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/correlation"
)

func TestCorrelationMiddleware(t *testing.T) {
	// Create a mock server for testing
	mockServer := &Server{}

	t.Run("Uses X-Correlation-ID from request", func(t *testing.T) {
		expectedID := "test-correlation-id"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify the correlation ID is in the context
			actualID := correlation.GetCorrelationID(r.Context())
			if actualID != expectedID {
				t.Errorf("Expected correlation ID %s, got %s", expectedID, actualID)
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := mockServer.CorrelationMiddleware()(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(correlation.CorrelationIDHeader, expectedID)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		// Verify response header
		responseID := w.Header().Get(correlation.CorrelationIDHeader)
		if responseID != expectedID {
			t.Errorf("Expected response correlation ID %s, got %s", expectedID, responseID)
		}
	})

	t.Run("Uses X-Request-ID as fallback", func(t *testing.T) {
		expectedID := "test-request-id"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actualID := correlation.GetCorrelationID(r.Context())
			if actualID != expectedID {
				t.Errorf("Expected correlation ID %s, got %s", expectedID, actualID)
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := mockServer.CorrelationMiddleware()(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(correlation.RequestIDHeader, expectedID)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		responseID := w.Header().Get(correlation.CorrelationIDHeader)
		if responseID != expectedID {
			t.Errorf("Expected response correlation ID %s, got %s", expectedID, responseID)
		}
	})

	t.Run("Generates new correlation ID if none provided", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actualID := correlation.GetCorrelationID(r.Context())
			if actualID == "" {
				t.Error("Expected correlation ID to be generated, got empty string")
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := mockServer.CorrelationMiddleware()(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		responseID := w.Header().Get(correlation.CorrelationIDHeader)
		if responseID == "" {
			t.Error("Expected correlation ID in response header, got empty string")
		}
	})

	t.Run("X-Correlation-ID takes precedence over X-Request-ID", func(t *testing.T) {
		expectedID := "correlation-id"
		requestID := "request-id"

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actualID := correlation.GetCorrelationID(r.Context())
			if actualID != expectedID {
				t.Errorf("Expected correlation ID %s, got %s", expectedID, actualID)
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := mockServer.CorrelationMiddleware()(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(correlation.CorrelationIDHeader, expectedID)
		req.Header.Set(correlation.RequestIDHeader, requestID)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		responseID := w.Header().Get(correlation.CorrelationIDHeader)
		if responseID != expectedID {
			t.Errorf("Expected response correlation ID %s, got %s", expectedID, responseID)
		}
	})
}
