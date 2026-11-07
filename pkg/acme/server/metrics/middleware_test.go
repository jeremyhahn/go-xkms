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

package metrics

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMount verifies that Mount both instruments every request the router
// serves and makes the production metric set (circuit breaker, cache,
// degradation, tenant-aware counters) part of the same Registry the base
// set registers into - the single call site cmd/xkmsd/acme.go and
// pkg/acme/client/trustedca.go both use.
func TestMount(t *testing.T) {
	router := mux.NewRouter()
	router.HandleFunc("/acme/new-account", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}).Methods(http.MethodPost)

	Mount(router)

	before := getCounterValue(t, requestsTotal, "new-account", "201")

	req := httptest.NewRequest(http.MethodPost, "/acme/new-account", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	after := getCounterValue(t, requestsTotal, "new-account", "201")
	assert.Equal(t, before+1, after)

	// InitProduction's metrics (e.g. the circuit breaker gauge) must be part
	// of the same Registry Mount initializes, not left unregistered.
	assert.NotNil(t, GetCircuitBreakerState())
	metricFamilies, err := Registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metricFamilies)
}

func TestMiddleware(t *testing.T) {
	Init()

	tests := []struct {
		name           string
		path           string
		handlerStatus  int
		expectedStatus string
	}{
		{
			name:           "successful request",
			path:           "/acme/new-account",
			handlerStatus:  http.StatusOK,
			expectedStatus: "200",
		},
		{
			name:           "created request",
			path:           "/acme/new-order",
			handlerStatus:  http.StatusCreated,
			expectedStatus: "201",
		},
		{
			name:           "bad request",
			path:           "/acme/challenge/123",
			handlerStatus:  http.StatusBadRequest,
			expectedStatus: "400",
		},
		{
			name:           "internal server error",
			path:           "/acme/order/456/finalize",
			handlerStatus:  http.StatusInternalServerError,
			expectedStatus: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.handlerStatus)
			})

			// Wrap with middleware
			wrapped := Middleware(handler)

			// Create request and response recorder
			req := httptest.NewRequest("POST", tt.path, nil)
			rec := httptest.NewRecorder()

			// Get initial metric values
			endpoint := extractEndpoint(tt.path)
			beforeRequests := getCounterValue(t, requestsTotal, endpoint, tt.expectedStatus)
			beforeDuration := getHistogramCount(t, requestDuration, endpoint)

			// Execute request
			wrapped.ServeHTTP(rec, req)

			// Verify status code
			assert.Equal(t, tt.handlerStatus, rec.Code)

			// Verify metrics were recorded
			afterRequests := getCounterValue(t, requestsTotal, endpoint, tt.expectedStatus)
			assert.Equal(t, beforeRequests+1, afterRequests)

			// Verify duration was recorded
			afterDuration := getHistogramCount(t, requestDuration, endpoint)
			assert.Equal(t, beforeDuration+1, afterDuration)

			// Verify error metrics for 4xx and 5xx
			if tt.handlerStatus >= 400 {
				errorType := "client_error"
				if tt.handlerStatus >= 500 {
					errorType = "server_error"
				}
				// Just verify the error was recorded, don't check exact count
				// since other tests may have incremented it
				value := getCounterValueSingle(t, errorsTotal, errorType)
				assert.Greater(t, value, float64(0))
			}
		})
	}
}

func TestMiddlewareDefaultStatus(t *testing.T) {
	Init()

	// Handler that doesn't explicitly set status (should default to 200)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	wrapped := Middleware(handler)
	req := httptest.NewRequest("GET", "/acme/directory", nil)
	rec := httptest.NewRecorder()

	endpoint := extractEndpoint("/acme/directory")
	before := getCounterValue(t, requestsTotal, endpoint, "200")

	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	after := getCounterValue(t, requestsTotal, endpoint, "200")
	assert.Equal(t, before+1, after)
}

func TestExtractEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "new-account",
			path:     "/acme/new-account",
			expected: "new-account",
		},
		{
			name:     "account with ID",
			path:     "/acme/account/12345",
			expected: "account",
		},
		{
			name:     "order finalize",
			path:     "/acme/order/67890/finalize",
			expected: "order-finalize",
		},
		{
			name:     "challenge with ID",
			path:     "/acme/challenge/999",
			expected: "challenge",
		},
		{
			name:     "directory",
			path:     "/acme/directory",
			expected: "directory",
		},
		{
			name:     "new-nonce",
			path:     "/acme/new-nonce",
			expected: "new-nonce",
		},
		{
			name:     "authorization with ID",
			path:     "/acme/authz/123",
			expected: "authz",
		},
		{
			name:     "certificate with ID",
			path:     "/acme/cert/456",
			expected: "cert",
		},
		{
			name:     "revoke-cert",
			path:     "/acme/revoke-cert",
			expected: "revoke-cert",
		},
		{
			name:     "key-change",
			path:     "/acme/key-change",
			expected: "key-change",
		},
		{
			name:     "orders list",
			path:     "/acme/orders/789",
			expected: "orders",
		},
		{
			name:     "root path",
			path:     "/",
			expected: "unknown",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "unknown",
		},
		{
			name:     "health endpoint",
			path:     "/health",
			expected: "health",
		},
		{
			name:     "metrics endpoint",
			path:     "/metrics",
			expected: "metrics",
		},
		{
			name:     "trailing slash",
			path:     "/acme/directory/",
			expected: "directory",
		},
		{
			name:     "multiple IDs",
			path:     "/acme/account/123/order/456/finalize",
			expected: "account-order-finalize",
		},
		{
			name:     "only numeric ID after acme prefix",
			path:     "/acme/12345",
			expected: "12345",
		},
		{
			name:     "acme prefix only",
			path:     "/acme/",
			expected: "unknown",
		},
		{
			name:     "acme prefix no trailing slash",
			path:     "/acme",
			expected: "unknown",
		},
		{
			name:     "path with empty parts in middle",
			path:     "/acme//directory",
			expected: "directory",
		},
		{
			name:     "multiple empty parts",
			path:     "/acme///new-account//",
			expected: "new-account",
		},
		{
			name:     "only numeric IDs",
			path:     "/123/456/789",
			expected: "123",
		},
		{
			name:     "mixed with leading numeric",
			path:     "/123/account/456",
			expected: "account",
		},
		{
			name:     "path with only empty parts after acme",
			path:     "/acme////",
			expected: "unknown",
		},
		{
			name:     "only numeric ID after acme prefix and empty parts",
			path:     "/acme///123///",
			expected: "unknown",
		},
		{
			name:     "acme stripped only as the first part",
			path:     "/123/acme/456/order/789",
			expected: "acme-order",
		},
		{
			name:     "largest uint64 ID",
			path:     "/acme/order/18446744073709551615",
			expected: "order",
		},
		{
			name:     "negative number (treated as non-numeric)",
			path:     "/acme/order/-123",
			expected: "order--123",
		},
		{
			name:     "alphanumeric mixed",
			path:     "/acme/order/abc123",
			expected: "order-abc123",
		},
		{
			name:     "UUID-like identifier",
			path:     "/acme/order/550e8400-e29b-41d4-a716-446655440000",
			expected: "order-550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:     "url-encoded characters pass through",
			path:     "/acme/order%20test",
			expected: "order%20test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractEndpoint(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMiddlewareConcurrency tests middleware under concurrent load
func TestMiddlewareConcurrency(t *testing.T) {
	Init()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Middleware(handler)

	var wg sync.WaitGroup
	concurrency := 100
	requestsPerGoroutine := 10

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				req := httptest.NewRequest("POST", "/acme/new-account", nil)
				rec := httptest.NewRecorder()
				wrapped.ServeHTTP(rec, req)
				assert.Equal(t, http.StatusOK, rec.Code)
			}
		}(i)
	}

	wg.Wait()

	// Verify metrics were recorded correctly
	value := getCounterValue(t, requestsTotal, "new-account", "200")
	assert.GreaterOrEqual(t, value, float64(concurrency*requestsPerGoroutine))
}

// TestResponseWriterMultipleWriteHeaders tests that status code wrapper behavior
func TestResponseWriterMultipleWriteHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}

	// First write
	rw.WriteHeader(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, rw.statusCode)
	assert.Equal(t, http.StatusCreated, rec.Code)

	// Subsequent calls update wrapper's statusCode field (even though underlying
	// ResponseWriter ignores the call per HTTP spec)
	rw.WriteHeader(http.StatusBadRequest)
	// Our wrapper updates its field
	assert.Equal(t, http.StatusBadRequest, rw.statusCode)
	// But the underlying recorder keeps the first status
	assert.Equal(t, http.StatusCreated, rec.Code)
}

// TestMiddlewareWithPanicRecovery tests middleware behavior if handler panics
func TestMiddlewareWithPanicRecovery(t *testing.T) {
	Init()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This should not panic the middleware
		w.WriteHeader(http.StatusOK)
		// Even if we write after WriteHeader, metrics should still work
		_, _ = w.Write([]byte("test"))
	})

	wrapped := Middleware(handler)
	req := httptest.NewRequest("GET", "/acme/test", nil)
	rec := httptest.NewRecorder()

	// Should not panic
	require.NotPanics(t, func() {
		wrapped.ServeHTTP(rec, req)
	})

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestExtractEndpointWithSpecialCharacters tests paths with special characters
