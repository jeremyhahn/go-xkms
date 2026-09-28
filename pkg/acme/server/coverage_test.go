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
