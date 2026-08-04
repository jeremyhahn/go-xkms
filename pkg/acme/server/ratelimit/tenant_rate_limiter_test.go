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

package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	metrics.Init()
	metrics.InitProduction()
}

func TestDefaultTenantConfig(t *testing.T) {
	config := DefaultTenantConfig("test-tenant")

	assert.Equal(t, "test-tenant", config.TenantID)
	assert.Equal(t, 50.0, config.RequestsPerSecond)
	assert.Equal(t, 100, config.BurstSize)
	assert.Equal(t, 100, config.NewAccountPerHour)
	assert.Equal(t, 1000, config.NewOrderPerHour)
	assert.Equal(t, 500, config.CertificatesPerDay)
	assert.True(t, config.Enabled)
}

func TestTokenBucket(t *testing.T) {
	t.Run("allows requests up to burst", func(t *testing.T) {
		tb := newTokenBucket(10.0, 5) // 10 req/s, burst of 5

		// Should allow 5 requests immediately
		for i := 0; i < 5; i++ {
			assert.True(t, tb.allow(), "request %d should be allowed", i)
		}

		// 6th request should be denied
		assert.False(t, tb.allow())
	})

	t.Run("refills tokens over time", func(t *testing.T) {
		tb := newTokenBucket(100.0, 2) // 100 req/s, burst of 2

		// Drain the bucket
		for i := 0; i < 2; i++ {
			assert.True(t, tb.allow())
		}
		assert.False(t, tb.allow())

		// Wait for refill
		time.Sleep(50 * time.Millisecond)

		// Should have some tokens now
		assert.True(t, tb.allow())
	})

	t.Run("tokens available", func(t *testing.T) {
		tb := newTokenBucket(10.0, 5)

		// Initial tokens
		tokens := tb.tokensAvailable()
		assert.Equal(t, 5.0, tokens)

		// After one request
		tb.allow()
		tokens = tb.tokensAvailable()
		assert.Equal(t, 4.0, tokens)
	})
}

func TestQuotaBucket(t *testing.T) {
	t.Run("allows requests up to limit", func(t *testing.T) {
		qb := newQuotaBucket(5, time.Hour)

		for i := 0; i < 5; i++ {
			assert.True(t, qb.allow(), "request %d should be allowed", i)
		}

		assert.False(t, qb.allow())
	})

	t.Run("resets on new window", func(t *testing.T) {
		// Use a very short window for testing
		qb := newQuotaBucket(2, 10*time.Millisecond)

		// Use up quota
		assert.True(t, qb.allow())
		assert.True(t, qb.allow())
		assert.False(t, qb.allow())

		// Wait for new window
		time.Sleep(20 * time.Millisecond)

		// Should be allowed again
		assert.True(t, qb.allow())
	})

	t.Run("current count", func(t *testing.T) {
		qb := newQuotaBucket(10, time.Hour)

		assert.Equal(t, uint64(0), qb.currentCount())

		qb.allow()
		qb.allow()

		assert.Equal(t, uint64(2), qb.currentCount())
	})
}

func TestTenantLimiter(t *testing.T) {
	config := &TenantConfig{
		TenantID:           "test-tenant",
		RequestsPerSecond:  100.0,
		BurstSize:          10,
		NewAccountPerHour:  5,
		NewOrderPerHour:    10,
		CertificatesPerDay: 3,
		Enabled:            true,
	}

	limiter := newTenantLimiter(config)

	t.Run("allow request", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			assert.True(t, limiter.AllowRequest("test"))
		}
	})

	t.Run("allow new account", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			assert.True(t, limiter.AllowNewAccount())
		}
		assert.False(t, limiter.AllowNewAccount())
	})

	t.Run("allow new order", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			assert.True(t, limiter.AllowNewOrder())
		}
		assert.False(t, limiter.AllowNewOrder())
	})

	t.Run("allow certificate", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			assert.True(t, limiter.AllowCertificate())
		}
		assert.False(t, limiter.AllowCertificate())
	})

	t.Run("disabled limiter allows all", func(t *testing.T) {
		disabledConfig := DefaultTenantConfig("disabled")
		disabledConfig.Enabled = false
		disabledLimiter := newTenantLimiter(disabledConfig)

		for i := 0; i < 1000; i++ {
			assert.True(t, disabledLimiter.AllowRequest("test"))
		}
	})

	t.Run("stats", func(t *testing.T) {
		stats := limiter.Stats()
		assert.Equal(t, "test-tenant", stats.TenantID)
		assert.GreaterOrEqual(t, stats.RequestsTotal, uint64(10))
	})
}

func TestTenantRateLimiter(t *testing.T) {
	ctx := context.Background()

	t.Run("creates limiter for new tenant", func(t *testing.T) {
		trl := NewTenantRateLimiter(nil, nil)

		allowed, err := trl.AllowRequest(ctx, "new-tenant", "test")
		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("reuses limiter for existing tenant", func(t *testing.T) {
		trl := NewTenantRateLimiter(nil, nil)

		limiter1, err := trl.GetLimiter(ctx, "existing-tenant")
		require.NoError(t, err)

		limiter2, err := trl.GetLimiter(ctx, "existing-tenant")
		require.NoError(t, err)

		assert.Same(t, limiter1, limiter2)
	})

	t.Run("with config provider", func(t *testing.T) {
		provider := NewMemoryConfigProvider()
		provider.SetConfig("custom-tenant", &TenantConfig{
			TenantID:          "custom-tenant",
			RequestsPerSecond: 1.0,
			BurstSize:         2,
			Enabled:           true,
		})

		trl := NewTenantRateLimiter(nil, provider)

		// Should allow 2 requests
		allowed, _ := trl.AllowRequest(ctx, "custom-tenant", "test")
		assert.True(t, allowed)
		allowed, _ = trl.AllowRequest(ctx, "custom-tenant", "test")
		assert.True(t, allowed)

		// Third should be denied
		allowed, _ = trl.AllowRequest(ctx, "custom-tenant", "test")
		assert.False(t, allowed)
	})

	t.Run("update config", func(t *testing.T) {
		trl := NewTenantRateLimiter(nil, nil)

		// Get default limiter
		_, _ = trl.AllowRequest(ctx, "update-tenant", "test")

		// Update with stricter config
		trl.UpdateConfig("update-tenant", &TenantConfig{
			TenantID:          "update-tenant",
			RequestsPerSecond: 1.0,
			BurstSize:         1,
			Enabled:           true,
		})

		// Should only allow 1 now
		allowed, _ := trl.AllowRequest(ctx, "update-tenant", "test")
		assert.True(t, allowed)
		allowed, _ = trl.AllowRequest(ctx, "update-tenant", "test")
		assert.False(t, allowed)
	})

	t.Run("remove tenant", func(t *testing.T) {
		trl := NewTenantRateLimiter(nil, nil)

		// Create limiter
		_, _ = trl.GetLimiter(ctx, "remove-tenant")

		// Remove it
		trl.RemoveTenant("remove-tenant")

		// Should create a new one
		limiter, err := trl.GetLimiter(ctx, "remove-tenant")
		require.NoError(t, err)
		assert.NotNil(t, limiter)
	})

	t.Run("stats", func(t *testing.T) {
		trl := NewTenantRateLimiter(nil, nil)

		_, _ = trl.AllowRequest(ctx, "stats-tenant-1", "test")
		_, _ = trl.AllowRequest(ctx, "stats-tenant-2", "test")

		stats := trl.Stats()
		assert.Contains(t, stats, "stats-tenant-1")
		assert.Contains(t, stats, "stats-tenant-2")
	})
}

func TestTenantRateLimiterConcurrency(t *testing.T) {
	trl := NewTenantRateLimiter(nil, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	tenants := 10
	requestsPerTenant := 100

	for i := 0; i < tenants; i++ {
		wg.Add(1)
		go func(tenantID string) {
			defer wg.Done()
			for j := 0; j < requestsPerTenant; j++ {
				_, _ = trl.AllowRequest(ctx, tenantID, "test")
			}
		}(formatTenantID(i))
	}

	wg.Wait()

	stats := trl.Stats()
	assert.Len(t, stats, tenants)
}

func formatTenantID(n int) string {
	return "tenant-" + formatInt(n)
}

func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

func TestMiddleware(t *testing.T) {
	trl := NewTenantRateLimiter(nil, nil)
	trl.UpdateConfig("limited-tenant", &TenantConfig{
		TenantID:          "limited-tenant",
		RequestsPerSecond: 1.0,
		BurstSize:         1,
		Enabled:           true,
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := trl.Middleware(func(r *http.Request) string {
		return r.Header.Get("X-Tenant-ID")
	})

	wrappedHandler := middleware(handler)

	t.Run("allows requests within limit", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/acme/directory", nil)
		req.Header.Set("X-Tenant-ID", "allowed-tenant")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		// First request should succeed
		req1 := httptest.NewRequest("GET", "/acme/directory", nil)
		req1.Header.Set("X-Tenant-ID", "limited-tenant")
		rec1 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec1, req1)
		assert.Equal(t, http.StatusOK, rec1.Code)

		// Second request should be rate limited
		req2 := httptest.NewRequest("GET", "/acme/directory", nil)
		req2.Header.Set("X-Tenant-ID", "limited-tenant")
		rec2 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec2, req2)
		assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
		assert.Equal(t, "60", rec2.Header().Get("Retry-After"))
		assert.Equal(t, "application/problem+json", rec2.Header().Get("Content-Type"))
	})

	t.Run("uses default tenant for missing header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/acme/directory", nil)
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestExtractEndpointFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/acme/directory", "directory"},
		{"/acme/new-account", "new-account"},
		{"/acme/account/123", "account"},
		{"acme/new-order", "new-order"},
		{"/directory", "directory"},
		{"", ""},
		{"/", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := extractEndpointFromPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMemoryConfigProvider(t *testing.T) {
	ctx := context.Background()
	provider := NewMemoryConfigProvider()

	t.Run("returns error for unknown tenant", func(t *testing.T) {
		_, err := provider.GetTenantConfig(ctx, "unknown")
		assert.ErrorIs(t, err, ErrTenantNotFound)
	})

	t.Run("returns config for known tenant", func(t *testing.T) {
		config := &TenantConfig{
			TenantID:          "known-tenant",
			RequestsPerSecond: 100.0,
		}
		provider.SetConfig("known-tenant", config)

		retrieved, err := provider.GetTenantConfig(ctx, "known-tenant")
		require.NoError(t, err)
		assert.Equal(t, config, retrieved)
	})
}

func TestAllowNewAccountAndOrder(t *testing.T) {
	ctx := context.Background()
	trl := NewTenantRateLimiter(nil, nil)

	// Update with limited config
	trl.UpdateConfig("quota-tenant", &TenantConfig{
		TenantID:          "quota-tenant",
		RequestsPerSecond: 100.0,
		BurstSize:         100,
		NewAccountPerHour: 2,
		NewOrderPerHour:   3,
		Enabled:           true,
	})

	t.Run("allow new account", func(t *testing.T) {
		allowed, err := trl.AllowNewAccount(ctx, "quota-tenant")
		require.NoError(t, err)
		assert.True(t, allowed)

		allowed, err = trl.AllowNewAccount(ctx, "quota-tenant")
		require.NoError(t, err)
		assert.True(t, allowed)

		// Third should fail
		allowed, err = trl.AllowNewAccount(ctx, "quota-tenant")
		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("allow new order", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			allowed, err := trl.AllowNewOrder(ctx, "quota-tenant")
			require.NoError(t, err)
			assert.True(t, allowed)
		}

		// Fourth should fail
		allowed, err := trl.AllowNewOrder(ctx, "quota-tenant")
		require.NoError(t, err)
		assert.False(t, allowed)
	})
}

func TestAllowCertificate(t *testing.T) {
	ctx := context.Background()
	trl := NewTenantRateLimiter(nil, nil)

	trl.UpdateConfig("cert-tenant", &TenantConfig{
		TenantID:           "cert-tenant",
		RequestsPerSecond:  100.0,
		BurstSize:          100,
		CertificatesPerDay: 2,
		Enabled:            true,
	})

	allowed, err := trl.AllowCertificate(ctx, "cert-tenant")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = trl.AllowCertificate(ctx, "cert-tenant")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Third should fail
	allowed, err = trl.AllowCertificate(ctx, "cert-tenant")
	require.NoError(t, err)
	assert.False(t, allowed)
}
