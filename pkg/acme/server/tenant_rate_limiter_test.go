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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewTenantRateLimiter(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		trl := NewTenantRateLimiter(nil, nil, ClientIP, "overall")
		defer trl.Stop()

		require.NotNil(t, trl)
		require.NotNil(t, trl.config)
		require.NotNil(t, trl.config.DefaultConfig)
		require.Equal(t, 5*time.Minute, trl.config.CleanupInterval)
		require.Equal(t, 10000, trl.config.MaxEntriesPerTenant)
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &TenantRateLimiterConfig{
			DefaultConfig:       DefaultRateLimitConfig(),
			CleanupInterval:     time.Minute,
			MaxEntriesPerTenant: 1000,
		}

		trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
		defer trl.Stop()

		require.NotNil(t, trl)
		require.Equal(t, time.Minute, trl.config.CleanupInterval)
		require.Equal(t, 1000, trl.config.MaxEntriesPerTenant)
	})
}

func TestTenantRateLimiter_Allow(t *testing.T) {
	t.Run("allows requests within limit", func(t *testing.T) {
		config := &TenantRateLimiterConfig{
			DefaultConfig: &RateLimitConfig{
				OverallRequestRate: &RateLimit{
					MaxRequests: 5,
					Interval:    time.Minute,
				},
			},
		}

		trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
		defer trl.Stop()

		// All 5 requests should be allowed
		for i := 0; i < 5; i++ {
			allowed := trl.Allow("tenant1", "client1")
			require.True(t, allowed, "request %d should be allowed", i+1)
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		config := &TenantRateLimiterConfig{
			DefaultConfig: &RateLimitConfig{
				OverallRequestRate: &RateLimit{
					MaxRequests: 2,
					Interval:    time.Minute,
				},
			},
		}

		trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
		defer trl.Stop()

		// First 2 requests should be allowed
		require.True(t, trl.Allow("tenant1", "client1"))
		require.True(t, trl.Allow("tenant1", "client1"))

		// 3rd request should be blocked
		require.False(t, trl.Allow("tenant1", "client1"))
	})

	t.Run("isolates tenants", func(t *testing.T) {
		config := &TenantRateLimiterConfig{
			DefaultConfig: &RateLimitConfig{
				OverallRequestRate: &RateLimit{
					MaxRequests: 1,
					Interval:    time.Minute,
				},
			},
		}

		trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
		defer trl.Stop()

		// Tenant 1 uses its limit
		require.True(t, trl.Allow("tenant1", "client1"))
		require.False(t, trl.Allow("tenant1", "client1"))

		// Tenant 2 should still have its own limit
		require.True(t, trl.Allow("tenant2", "client1"))
		require.False(t, trl.Allow("tenant2", "client1"))
	})

	t.Run("isolates clients within tenant", func(t *testing.T) {
		config := &TenantRateLimiterConfig{
			DefaultConfig: &RateLimitConfig{
				OverallRequestRate: &RateLimit{
					MaxRequests: 1,
					Interval:    time.Minute,
				},
			},
		}

		trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
		defer trl.Stop()

		// Client 1 uses its limit
		require.True(t, trl.Allow("tenant1", "client1"))
		require.False(t, trl.Allow("tenant1", "client1"))

		// Client 2 should have its own limit
		require.True(t, trl.Allow("tenant1", "client2"))
		require.False(t, trl.Allow("tenant1", "client2"))
	})

	t.Run("uses tenant-specific config when available", func(t *testing.T) {
		config := &TenantRateLimiterConfig{
			DefaultConfig: &RateLimitConfig{
				OverallRequestRate: &RateLimit{
					MaxRequests: 1,
					Interval:    time.Minute,
				},
			},
			TenantConfigs: map[string]*TenantRateLimitConfig{
				"premium-tenant": {
					TenantID: "premium-tenant",
					OverallRequestRate: &RateLimit{
						MaxRequests: 100,
						Interval:    time.Minute,
					},
				},
			},
		}

		trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
		defer trl.Stop()

		// Default tenant gets 1 request
		require.True(t, trl.Allow("default-tenant", "client1"))
		require.False(t, trl.Allow("default-tenant", "client1"))

		// Premium tenant gets 100 requests
		for i := 0; i < 100; i++ {
			require.True(t, trl.Allow("premium-tenant", "client1"), "request %d should be allowed", i+1)
		}
		require.False(t, trl.Allow("premium-tenant", "client1"))
	})

	t.Run("allows all when no rate limit configured", func(t *testing.T) {
		config := &TenantRateLimiterConfig{
			DefaultConfig: &RateLimitConfig{},
		}

		trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
		defer trl.Stop()

		// Should allow unlimited requests
		for i := 0; i < 100; i++ {
			require.True(t, trl.Allow("tenant1", "client1"))
		}
	})
}

func TestTenantRateLimiter_BurstMultiplier(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			OverallRequestRate: &RateLimit{
				MaxRequests: 2,
				Interval:    time.Minute,
			},
		},
		TenantConfigs: map[string]*TenantRateLimitConfig{
			"burst-tenant": {
				TenantID: "burst-tenant",
				OverallRequestRate: &RateLimit{
					MaxRequests: 2,
					Interval:    time.Minute,
				},
				BurstMultiplier: 2.0, // Allows 4 tokens max
			},
		},
	}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	// Normal tenant can only accumulate up to MaxRequests (2)
	require.True(t, trl.Allow("normal-tenant", "client1"))
	require.True(t, trl.Allow("normal-tenant", "client1"))
	require.False(t, trl.Allow("normal-tenant", "client1"))

	// Burst tenant gets 2 requests initially, but with burst multiplier
	// the max tokens is 4, so after refill it could have more
	require.True(t, trl.Allow("burst-tenant", "client1"))
	require.True(t, trl.Allow("burst-tenant", "client1"))
	require.False(t, trl.Allow("burst-tenant", "client1"))
}

func TestTenantRateLimiter_TokenRefill(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			OverallRequestRate: &RateLimit{
				MaxRequests: 2,
				Interval:    100 * time.Millisecond,
			},
		},
	}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	// Use all tokens
	require.True(t, trl.Allow("tenant1", "client1"))
	require.True(t, trl.Allow("tenant1", "client1"))
	require.False(t, trl.Allow("tenant1", "client1"))

	// Wait for tokens to refill
	time.Sleep(150 * time.Millisecond)

	// Should have tokens again
	require.True(t, trl.Allow("tenant1", "client1"))
}

func TestTenantRateLimiter_MaxEntriesPerTenant(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			OverallRequestRate: &RateLimit{
				MaxRequests: 100,
				Interval:    time.Hour,
			},
		},
		MaxEntriesPerTenant: 3,
	}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	// First 3 clients should work
	require.True(t, trl.Allow("tenant1", "client1"))
	require.True(t, trl.Allow("tenant1", "client2"))
	require.True(t, trl.Allow("tenant1", "client3"))

	// 4th client should be rejected (max entries reached)
	require.False(t, trl.Allow("tenant1", "client4"))

	// Existing clients should still work
	require.True(t, trl.Allow("tenant1", "client1"))
}

func TestTenantRateLimiter_Metrics(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			OverallRequestRate: &RateLimit{
				MaxRequests: 2,
				Interval:    time.Minute,
			},
		},
	}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	// Make requests
	trl.Allow("tenant1", "client1") // Allowed
	trl.Allow("tenant1", "client1") // Allowed
	trl.Allow("tenant1", "client1") // Rate limited

	metrics := trl.GetMetrics("tenant1")
	require.NotNil(t, metrics)
	require.Equal(t, uint64(3), metrics.TotalRequests.Load())
	require.Equal(t, uint64(1), metrics.RateLimitedRequests.Load())
}

func TestTenantRateLimiter_GetAllMetrics(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			OverallRequestRate: &RateLimit{
				MaxRequests: 10,
				Interval:    time.Minute,
			},
		},
	}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	// Make requests for multiple tenants
	trl.Allow("tenant1", "client1")
	trl.Allow("tenant2", "client1")
	trl.Allow("tenant3", "client1")

	allMetrics := trl.GetAllMetrics()
	require.Len(t, allMetrics, 3)
	require.NotNil(t, allMetrics["tenant1"])
	require.NotNil(t, allMetrics["tenant2"])
	require.NotNil(t, allMetrics["tenant3"])
}

func TestTenantRateLimiter_Middleware(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			OverallRequestRate: &RateLimit{
				MaxRequests: 2,
				Interval:    time.Minute,
			},
		},
	}

	tenantKeyFn := TenantRateLimiterFromHeader("X-Tenant-ID")
	trl := NewTenantRateLimiter(config, tenantKeyFn, ClientIP, "overall")
	defer trl.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := trl.Middleware()
	wrappedHandler := middleware(handler)

	// First 2 requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Tenant-ID", "tenant1")
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}

	// 3rd request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", "tenant1")
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestTenantRateLimiter_ConcurrentAccess(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			OverallRequestRate: &RateLimit{
				MaxRequests: 1000,
				Interval:    time.Minute,
			},
		},
	}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	var wg sync.WaitGroup
	numGoroutines := 100
	requestsPerGoroutine := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(tenantNum int) {
			defer wg.Done()
			tenantID := "tenant" + formatInt(tenantNum%10)
			clientID := "client" + formatInt(tenantNum)

			for j := 0; j < requestsPerGoroutine; j++ {
				trl.Allow(tenantID, clientID)
			}
		}(i)
	}

	wg.Wait()

	// Verify metrics are consistent
	allMetrics := trl.GetAllMetrics()
	var total uint64
	for _, m := range allMetrics {
		total += m.TotalRequests.Load()
	}
	require.Equal(t, uint64(numGoroutines*requestsPerGoroutine), total)
}

func TestTenantRateLimiter_OperationTypes(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			NewAccountRate: &RateLimit{
				MaxRequests: 10,
				Interval:    time.Hour,
			},
			NewOrderRate: &RateLimit{
				MaxRequests: 100,
				Interval:    time.Hour,
			},
			CertificateRate: &RateLimit{
				MaxRequests: 50,
				Interval:    time.Hour,
			},
			OverallRequestRate: &RateLimit{
				MaxRequests: 1000,
				Interval:    time.Hour,
			},
			FailedValidationRate: &RateLimit{
				MaxRequests: 5,
				Interval:    time.Hour,
			},
		},
	}

	tests := []struct {
		opType      string
		constructor func(*TenantRateLimiterConfig, TenantKeyFunc) *TenantRateLimiter
		expected    int
	}{
		{"new-account", NewTenantAccountRateLimiter, 10},
		{"new-order", NewTenantOrderRateLimiter, 100},
		{"certificate", NewTenantCertificateRateLimiter, 50},
		{"overall", NewTenantOverallRateLimiter, 1000},
		{"failed-validation", NewTenantFailedValidationRateLimiter, 5},
	}

	for _, tt := range tests {
		t.Run(tt.opType, func(t *testing.T) {
			trl := tt.constructor(config, nil)
			defer trl.Stop()

			// All requests up to limit should be allowed
			for i := 0; i < tt.expected; i++ {
				allowed := trl.Allow("tenant1", "client1")
				require.True(t, allowed, "request %d should be allowed for %s", i+1, tt.opType)
			}

			// Next request should be blocked
			require.False(t, trl.Allow("tenant1", "client1"))
		})
	}
}

func TestTenantKeyFunctions(t *testing.T) {
	t.Run("TenantRateLimiterFromHeader", func(t *testing.T) {
		fn := TenantRateLimiterFromHeader("X-Tenant-ID")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Tenant-ID", "my-tenant")

		tenantID := fn(req)
		require.Equal(t, "my-tenant", tenantID)
	})

	t.Run("TenantRateLimiterFromHeader with missing header", func(t *testing.T) {
		fn := TenantRateLimiterFromHeader("X-Tenant-ID")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		tenantID := fn(req)
		require.Empty(t, tenantID)
	})

	t.Run("TenantRateLimiterFromRequestContext", func(t *testing.T) {
		fn := TenantRateLimiterFromRequestContext()

		ctx := WithTenantID(context.Background(), "context-tenant")
		req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)

		tenantID := fn(req)
		require.Equal(t, "context-tenant", tenantID)
	})

	t.Run("TenantRateLimiterFromRequestContext with missing context", func(t *testing.T) {
		fn := TenantRateLimiterFromRequestContext()

		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		tenantID := fn(req)
		require.Empty(t, tenantID)
	})

	t.Run("TenantRateLimiterFromContext with custom key", func(t *testing.T) {
		type customKey struct{}
		fn := TenantRateLimiterFromContext(customKey{})

		ctx := context.WithValue(context.Background(), customKey{}, "custom-tenant")
		req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)

		tenantID := fn(req)
		require.Equal(t, "custom-tenant", tenantID)
	})
}

func TestTenantIDContext(t *testing.T) {
	t.Run("WithTenantID and TenantIDFromContext", func(t *testing.T) {
		ctx := WithTenantID(context.Background(), "test-tenant")

		tenantID := TenantIDFromContext(ctx)
		require.Equal(t, "test-tenant", tenantID)
	})

	t.Run("TenantIDFromContext with missing value", func(t *testing.T) {
		tenantID := TenantIDFromContext(context.Background())
		require.Empty(t, tenantID)
	})
}

func TestFormatInt(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{123, "123"},
		{-1, "-1"},
		{-123, "-123"},
		{1000000, "1000000"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatInt(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestTenantRateLimiter_Cleanup(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			OverallRequestRate: &RateLimit{
				MaxRequests: 10,
				Interval:    10 * time.Millisecond, // Very short interval for testing
			},
		},
		CleanupInterval: 50 * time.Millisecond,
	}

	trl := NewTenantRateLimiter(config, nil, ClientIP, "overall")
	defer trl.Stop()

	// Create some entries
	trl.Allow("tenant1", "client1")
	trl.Allow("tenant1", "client2")

	// Verify entries exist
	state := trl.getOrCreateState("tenant1")
	state.mu.RLock()
	initialCount := len(state.buckets)
	state.mu.RUnlock()
	require.Equal(t, 2, initialCount)

	// Wait for cleanup cycle and entries to expire
	time.Sleep(200 * time.Millisecond)

	// Entries should be cleaned up
	state.mu.RLock()
	finalCount := len(state.buckets)
	state.mu.RUnlock()
	require.Equal(t, 0, finalCount)
}

func TestTenantRateLimiter_TenantConfigOperationTypes(t *testing.T) {
	config := &TenantRateLimiterConfig{
		TenantConfigs: map[string]*TenantRateLimitConfig{
			"tenant1": {
				TenantID: "tenant1",
				NewAccountRate: &RateLimit{
					MaxRequests: 5,
					Interval:    time.Hour,
				},
				NewOrderRate: &RateLimit{
					MaxRequests: 10,
					Interval:    time.Hour,
				},
				CertificateRate: &RateLimit{
					MaxRequests: 20,
					Interval:    time.Hour,
				},
				OverallRequestRate: &RateLimit{
					MaxRequests: 100,
					Interval:    time.Hour,
				},
				FailedValidationRate: &RateLimit{
					MaxRequests: 3,
					Interval:    time.Hour,
				},
			},
		},
	}

	tests := []struct {
		opType   string
		expected int
	}{
		{"new-account", 5},
		{"new-order", 10},
		{"certificate", 20},
		{"overall", 100},
		{"failed-validation", 3},
		{"unknown-operation", 100}, // Falls back to overall
	}

	for _, tt := range tests {
		t.Run(tt.opType, func(t *testing.T) {
			trl := NewTenantRateLimiter(config, nil, ClientIP, tt.opType)
			defer trl.Stop()

			// All requests up to limit should be allowed
			for i := 0; i < tt.expected; i++ {
				allowed := trl.Allow("tenant1", "client1")
				require.True(t, allowed, "request %d should be allowed for %s", i+1, tt.opType)
			}

			// Next request should be blocked
			require.False(t, trl.Allow("tenant1", "client1"))
		})
	}
}

// TestTenantRateLimiter_RetryAfterSeconds proves that RetryAfterSeconds
// reports the configured interval, in seconds, for a tenant whose rate limit
// resolves (go-xkms#886: ChallengeHandler's failed-validation category calls
// this directly, since it cannot use Middleware).
func TestTenantRateLimiter_RetryAfterSeconds(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			FailedValidationRate: &RateLimit{MaxRequests: 5, Interval: 90 * time.Second},
		},
	}
	trl := NewTenantRateLimiter(config, nil, ClientID, "failed-validation")
	defer trl.Stop()

	require.Equal(t, 90, trl.RetryAfterSeconds("any-tenant"))
}

// TestTenantRateLimiter_RetryAfterSeconds_NoConfig proves the error/edge
// path: a tenant (or operation type) with no resolvable rate limit falls
// back to the documented 60-second default instead of reporting 0 or
// panicking.
func TestTenantRateLimiter_RetryAfterSeconds_NoConfig(t *testing.T) {
	trl := NewTenantRateLimiter(&TenantRateLimiterConfig{}, nil, ClientID, "failed-validation")
	defer trl.Stop()

	require.Equal(t, 60, trl.RetryAfterSeconds("any-tenant"))
}

// TestTenantRateLimiter_SharedQuotaAcrossAccounts proves go-xkms#886's core
// tenant-admission-control property: a per-tenant overall quota, mounted
// with a client-key function that ignores which account or client made the
// request (the same constant every call — the shape cmd/xkmsd's
// tenantSharedClientKey and pkg/acme/client's equivalent use), is consumed
// by every account belonging to that tenant from one shared bucket, not one
// bucket per account. Two different accounts of "tenant-x" (simulated here
// by two requests carrying different KIDs, both resolving to the same
// context tenant the way TenantAuthMiddleware would) exhaust the same
// two-request budget between them.
func TestTenantRateLimiter_SharedQuotaAcrossAccounts(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			OverallRequestRate: &RateLimit{MaxRequests: 2, Interval: time.Minute},
		},
	}
	sharedClientKey := func(*http.Request) string { return "" }
	trl := NewTenantRateLimiter(config, TenantRateLimiterFromRequestContext(), sharedClientKey, "overall")
	defer trl.Stop()

	handler := trl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	requestFromAccount := func(kid string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
		req = req.WithContext(WithTenantID(req.Context(), "tenant-x"))
		req.Header.Set("X-Account-KID", kid) // irrelevant to the shared bucket key; only distinguishes the two accounts for the test
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	// First account's request consumes 1 of the tenant's 2-request budget.
	require.Equal(t, http.StatusOK, requestFromAccount("account-a").Code)
	// A second, different account of the SAME tenant consumes the other.
	require.Equal(t, http.StatusOK, requestFromAccount("account-b").Code)
	// A third request — from either account — finds the tenant's shared
	// budget already exhausted.
	require.Equal(t, http.StatusTooManyRequests, requestFromAccount("account-a").Code)
}

// TestTenantRateLimiter_SharedQuotaAcrossAccounts_DifferentTenantsIsolated
// proves the complementary property: two different tenants never share a
// bucket, even under the same shared-client-key construction — one tenant
// exhausting its quota never throttles another tenant's traffic.
func TestTenantRateLimiter_SharedQuotaAcrossAccounts_DifferentTenantsIsolated(t *testing.T) {
	config := &TenantRateLimiterConfig{
		DefaultConfig: &RateLimitConfig{
			OverallRequestRate: &RateLimit{MaxRequests: 1, Interval: time.Minute},
		},
	}
	sharedClientKey := func(*http.Request) string { return "" }
	trl := NewTenantRateLimiter(config, TenantRateLimiterFromRequestContext(), sharedClientKey, "overall")
	defer trl.Stop()

	handler := trl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	requestFromTenant := func(tenantID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
		req = req.WithContext(WithTenantID(req.Context(), tenantID))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	require.Equal(t, http.StatusOK, requestFromTenant("tenant-x").Code)
	require.Equal(t, http.StatusTooManyRequests, requestFromTenant("tenant-x").Code, "tenant-x's own budget is exhausted")
	require.Equal(t, http.StatusOK, requestFromTenant("tenant-y").Code, "tenant-y is unaffected by tenant-x's exhausted budget")
}
