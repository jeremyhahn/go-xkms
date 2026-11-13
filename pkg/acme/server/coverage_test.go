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
