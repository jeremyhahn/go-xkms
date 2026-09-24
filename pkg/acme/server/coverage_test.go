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

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// BodySizeLimitMiddleware Tests (0% -> 100%)
// =============================================================================

// TestBodySizeLimitMiddleware_LimitsPostBody verifies that POST requests
// with bodies larger than the limit are rejected.
func TestBodySizeLimitMiddleware_LimitsPostBody(t *testing.T) {
	middleware := BodySizeLimitMiddleware(10) // 10 bytes max

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := middleware(handler)

	t.Run("allows small POST body", func(t *testing.T) {
		body := bytes.NewBufferString("small")
		req := httptest.NewRequest(http.MethodPost, "/test", body)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("rejects oversized POST body", func(t *testing.T) {
		body := bytes.NewBufferString("this body is way too large for the limit")
		req := httptest.NewRequest(http.MethodPost, "/test", body)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})

	t.Run("allows GET without body size limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("limits PUT body", func(t *testing.T) {
		body := bytes.NewBufferString("this body is way too large for the limit")
		req := httptest.NewRequest(http.MethodPut, "/test", body)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})

	t.Run("limits PATCH body", func(t *testing.T) {
		body := bytes.NewBufferString("this body is way too large for the limit")
		req := httptest.NewRequest(http.MethodPatch, "/test", body)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})
}

// TestBodySizeLimitMiddleware_DefaultMaxSize verifies that passing 0 or negative
// uses DefaultMaxRequestBodySize.
func TestBodySizeLimitMiddleware_DefaultMaxSize(t *testing.T) {
	middleware := BodySizeLimitMiddleware(0)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := middleware(handler)

	// A body smaller than DefaultMaxRequestBodySize should be allowed
	smallBody := bytes.NewBuffer(make([]byte, 1024))
	req := httptest.NewRequest(http.MethodPost, "/test", smallBody)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestBodySizeLimitMiddleware_NegativeMaxBytes verifies that a negative value
// uses DefaultMaxRequestBodySize.
func TestBodySizeLimitMiddleware_NegativeMaxBytes(t *testing.T) {
	middleware := BodySizeLimitMiddleware(-100)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := middleware(handler)

	smallBody := bytes.NewBuffer(make([]byte, 512))
	req := httptest.NewRequest(http.MethodPost, "/test", smallBody)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// =============================================================================
// extractIPFromRemoteAddr Tests (71.4% -> 100%)
// =============================================================================

// TestExtractIPFromRemoteAddr_IPv6WithoutPort covers the "[::1]" case
// where there is no port separator "]:".
func TestExtractIPFromRemoteAddr_IPv6WithoutPort(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{
			name:       "ipv6 with port",
			remoteAddr: "[::1]:8080",
			expected:   "::1",
		},
		{
			name:       "ipv6 without port",
			remoteAddr: "[::1]",
			expected:   "::1",
		},
		{
			name:       "ipv6 full address with port",
			remoteAddr: "[2001:db8::1]:443",
			expected:   "2001:db8::1",
		},
		{
			name:       "ipv6 full address without port",
			remoteAddr: "[2001:db8::1]",
			expected:   "2001:db8::1",
		},
		{
			name:       "ipv4 with port",
			remoteAddr: "192.168.1.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:       "ipv4 without port",
			remoteAddr: "192.168.1.1",
			expected:   "192.168.1.1",
		},
		{
			name:       "bare hostname",
			remoteAddr: "localhost",
			expected:   "localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractIPFromRemoteAddr(tt.remoteAddr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// getMaxInterval Tests (66.7% -> 100%)
// =============================================================================

// TestTenantRateLimiter_GetMaxInterval_NoIntervalsConfigured verifies that
// getMaxInterval returns the default 1 hour when no rate limits are configured.
func TestTenantRateLimiter_GetMaxInterval_NoIntervalsConfigured(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{},
	}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	maxInterval := trl.getMaxInterval()
	assert.Equal(t, time.Hour, maxInterval)
}

// TestTenantRateLimiter_GetMaxInterval_NilDefaultConfig verifies that
// getMaxInterval returns the default 1 hour when DefaultConfig is nil.
func TestTenantRateLimiter_GetMaxInterval_NilDefaultConfig(t *testing.T) {
	config := &TenantRateLimiterConfig{}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	maxInterval := trl.getMaxInterval()
	assert.Equal(t, time.Hour, maxInterval)
}

// TestTenantRateLimiter_GetMaxInterval_AllRatesConfigured verifies that
// getMaxInterval returns the largest interval from all configured rates.
func TestTenantRateLimiter_GetMaxInterval_AllRatesConfigured(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			NewAccountRate:       &RateLimit{MaxRequests: 10, Interval: time.Hour},
			NewOrderRate:         &RateLimit{MaxRequests: 100, Interval: 3 * time.Hour},
			CertificateRate:      &RateLimit{MaxRequests: 50, Interval: 6 * time.Hour},
			OverallRequestRate:   &RateLimit{MaxRequests: 20, Interval: time.Second},
			FailedValidationRate: &RateLimit{MaxRequests: 5, Interval: 2 * time.Hour},
		},
	}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	maxInterval := trl.getMaxInterval()
	// CertificateRate has the largest interval at 6 hours
	assert.Equal(t, 6*time.Hour, maxInterval)
}

// TestTenantRateLimiter_GetMaxInterval_PartialRatesConfigured verifies that
// getMaxInterval handles partial configuration correctly.
func TestTenantRateLimiter_GetMaxInterval_PartialRatesConfigured(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			NewAccountRate:     &RateLimit{MaxRequests: 10, Interval: 30 * time.Minute},
			OverallRequestRate: &RateLimit{MaxRequests: 20, Interval: time.Second},
		},
	}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	maxInterval := trl.getMaxInterval()
	assert.Equal(t, 30*time.Minute, maxInterval)
}

// =============================================================================
// TenantRateLimiterFromContext Tests (75% -> 100%)
// =============================================================================

// TestTenantRateLimiterFromContext_NonStringValue verifies that
// TenantRateLimiterFromContext returns empty string when the context
// value is not a string type.
func TestTenantRateLimiterFromContext_NonStringValue(t *testing.T) {
	type myKey struct{}
	fn := TenantRateLimiterFromContext(myKey{})

	// Set a non-string value in context
	ctx := context.WithValue(context.Background(), myKey{}, 12345)
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)

	tenantID := fn(req)
	assert.Empty(t, tenantID)
}

// TestTenantRateLimiterFromContext_MissingKey verifies that
// TenantRateLimiterFromContext returns empty string when the key is absent.
func TestTenantRateLimiterFromContext_MissingKey(t *testing.T) {
	type myKey struct{}
	fn := TenantRateLimiterFromContext(myKey{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	tenantID := fn(req)
	assert.Empty(t, tenantID)
}

// =============================================================================
// ClientID Tests (81.2% -> higher)
// =============================================================================

// TestClientID_EmptyBody verifies that ClientID falls back to IP when
// the request body is empty.
func TestClientID_EmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(""))
	req.RemoteAddr = "10.0.0.1:5678"

	clientID := ClientID(req)
	assert.Equal(t, "10.0.0.1", clientID)
}

// TestClientID_BodyReadError verifies that ClientID falls back to IP
// when the body read fails.
func TestClientID_BodyReadError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Body = io.NopCloser(&errorReader{})
	req.RemoteAddr = "10.0.0.2:5678"

	clientID := ClientID(req)
	assert.Equal(t, "10.0.0.2", clientID)
}

// errorReader is a reader that always returns an error.
type errorReader struct{}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

// =============================================================================
// getRateLimit Tests (83.3% -> higher)
// =============================================================================

// TestTenantRateLimiter_GetRateLimit_NilDefaultConfig verifies that getRateLimit
// returns nil when DefaultConfig is nil and the tenant has no specific config.
func TestTenantRateLimiter_GetRateLimit_NilDefaultConfig(t *testing.T) {
	config := &TenantRateLimiterConfig{}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	rateLimit := trl.getRateLimit("unknown-tenant")
	assert.Nil(t, rateLimit)
}

// =============================================================================
// getRateLimitFromDefaultConfig Tests (85.7% -> 100%)
// =============================================================================

// TestTenantRateLimiter_DefaultConfigOperationTypes verifies that
// getRateLimitFromDefaultConfig routes each operation type correctly.
func TestTenantRateLimiter_DefaultConfigOperationTypes(t *testing.T) {
	defaultConfig := &RateLimitConfig{
		NewAccountRate:       &RateLimit{MaxRequests: 10, Interval: time.Hour},
		NewOrderRate:         &RateLimit{MaxRequests: 100, Interval: time.Hour},
		CertificateRate:      &RateLimit{MaxRequests: 50, Interval: time.Hour},
		OverallRequestRate:   &RateLimit{MaxRequests: 20, Interval: time.Second},
		FailedValidationRate: &RateLimit{MaxRequests: 5, Interval: time.Hour},
	}

	tests := []struct {
		opType      string
		expectedMax int
	}{
		{"new-account", 10},
		{"new-order", 100},
		{"certificate", 50},
		{"overall", 20},
		{"failed-validation", 5},
		{"unknown-op", 20}, // falls back to overall
	}

	for _, tt := range tests {
		t.Run(tt.opType, func(t *testing.T) {
			config := &TenantRateLimiterConfig{
				DefaultConfig: defaultConfig,
			}

			trl := NewTenantRateLimiter(config, nil, ClientIP, tt.opType)
			defer trl.Stop()

			rl := trl.getRateLimitFromDefaultConfig()
			require.NotNil(t, rl)
			assert.Equal(t, tt.expectedMax, rl.MaxRequests)
		})
	}
}
