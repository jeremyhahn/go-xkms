// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTenantLimiter_DisabledAllowNewAccount verifies that AllowNewAccount
// returns true when rate limiting is disabled for the tenant.
func TestTenantLimiter_DisabledAllowNewAccount(t *testing.T) {
	config := &TenantConfig{
		TenantID:          "disabled-tenant",
		NewAccountPerHour: 1,
		Enabled:           false,
	}
	limiter := newTenantLimiter(config)

	// Should always return true when disabled, even beyond the quota
	for i := 0; i < 10; i++ {
		assert.True(t, limiter.AllowNewAccount(), "request %d should be allowed when disabled", i)
	}
}

// TestTenantLimiter_DisabledAllowNewOrder verifies that AllowNewOrder
// returns true when rate limiting is disabled for the tenant.
func TestTenantLimiter_DisabledAllowNewOrder(t *testing.T) {
	config := &TenantConfig{
		TenantID:        "disabled-tenant",
		NewOrderPerHour: 1,
		Enabled:         false,
	}
	limiter := newTenantLimiter(config)

	for i := 0; i < 10; i++ {
		assert.True(t, limiter.AllowNewOrder(), "request %d should be allowed when disabled", i)
	}
}

// TestTenantLimiter_DisabledAllowCertificate verifies that AllowCertificate
// returns true when rate limiting is disabled for the tenant.
func TestTenantLimiter_DisabledAllowCertificate(t *testing.T) {
	config := &TenantConfig{
		TenantID:           "disabled-tenant",
		CertificatesPerDay: 1,
		Enabled:            false,
	}
	limiter := newTenantLimiter(config)

	for i := 0; i < 10; i++ {
		assert.True(t, limiter.AllowCertificate(), "request %d should be allowed when disabled", i)
	}
}

// TestTenantRateLimiter_AllowNewAccountWithLimits verifies quota enforcement
// via the TenantRateLimiter wrapper for new account creation.
func TestTenantRateLimiter_AllowNewAccountWithLimits(t *testing.T) {
	ctx := context.Background()

	provider := NewMemoryConfigProvider()
	provider.SetConfig("limited", &TenantConfig{
		TenantID:          "limited",
		RequestsPerSecond: 100.0,
		BurstSize:         100,
		NewAccountPerHour: 2,
		Enabled:           true,
	})

	trl := NewTenantRateLimiter(nil, provider)

	// First 2 should succeed
	allowed, err := trl.AllowNewAccount(ctx, "limited")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = trl.AllowNewAccount(ctx, "limited")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Third should be denied
	allowed, err = trl.AllowNewAccount(ctx, "limited")
	require.NoError(t, err)
	assert.False(t, allowed)
}

// TestTenantRateLimiter_AllowNewOrderWithLimits verifies quota enforcement
// via the TenantRateLimiter wrapper for new order creation.
func TestTenantRateLimiter_AllowNewOrderWithLimits(t *testing.T) {
	ctx := context.Background()

	provider := NewMemoryConfigProvider()
	provider.SetConfig("limited", &TenantConfig{
		TenantID:          "limited",
		RequestsPerSecond: 100.0,
		BurstSize:         100,
		NewOrderPerHour:   2,
		Enabled:           true,
	})

	trl := NewTenantRateLimiter(nil, provider)

	allowed, err := trl.AllowNewOrder(ctx, "limited")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = trl.AllowNewOrder(ctx, "limited")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Third should be denied
	allowed, err = trl.AllowNewOrder(ctx, "limited")
	require.NoError(t, err)
	assert.False(t, allowed)
}

// TestTenantRateLimiter_AllowCertificateWithLimits verifies quota enforcement
// via the TenantRateLimiter wrapper for certificate issuance.
func TestTenantRateLimiter_AllowCertificateWithLimits(t *testing.T) {
	ctx := context.Background()

	provider := NewMemoryConfigProvider()
	provider.SetConfig("limited", &TenantConfig{
		TenantID:           "limited",
		RequestsPerSecond:  100.0,
		BurstSize:          100,
		CertificatesPerDay: 2,
		Enabled:            true,
	})

	trl := NewTenantRateLimiter(nil, provider)

	allowed, err := trl.AllowCertificate(ctx, "limited")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = trl.AllowCertificate(ctx, "limited")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Third should be denied
	allowed, err = trl.AllowCertificate(ctx, "limited")
	require.NoError(t, err)
	assert.False(t, allowed)
}

// TestTenantRateLimiter_AllowRequestWithLimits verifies request rate enforcement
// via the TenantRateLimiter wrapper using a tenant-specific config.
func TestTenantRateLimiter_AllowRequestWithLimits(t *testing.T) {
	ctx := context.Background()

	provider := NewMemoryConfigProvider()
	provider.SetConfig("tight", &TenantConfig{
		TenantID:          "tight",
		RequestsPerSecond: 1.0,
		BurstSize:         1,
		Enabled:           true,
	})

	trl := NewTenantRateLimiter(nil, provider)

	// First request allowed
	allowed, err := trl.AllowRequest(ctx, "tight", "directory")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Second should be denied (burst of 1 exhausted)
	allowed, err = trl.AllowRequest(ctx, "tight", "directory")
	require.NoError(t, err)
	assert.False(t, allowed)
}

// TestTenantRateLimiter_MiddlewareEmptyTenantDefaultsToDefault verifies that
// the middleware assigns "default" tenant when the extractor returns empty string.
func TestTenantRateLimiter_MiddlewareEmptyTenantDefaultsToDefault(t *testing.T) {
	trl := NewTenantRateLimiter(nil, nil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Extractor always returns empty string
	middleware := trl.Middleware(func(r *http.Request) string {
		return ""
	})

	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/acme/directory", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify that the "default" tenant was used by checking stats
	stats := trl.Stats()
	_, hasDefault := stats["default"]
	assert.True(t, hasDefault, "should have created a limiter for the 'default' tenant")
}

// TestTenantRateLimiter_MiddlewareRateLimitedResponse verifies that the
// middleware writes an RFC 8555 compliant rate limit error when requests
// exceed the limit for a tenant identified by the extractor.
func TestTenantRateLimiter_MiddlewareRateLimitedResponse(t *testing.T) {
	trl := NewTenantRateLimiter(nil, nil)

	// Configure a tight rate limit
	trl.UpdateConfig("middleware-tenant", &TenantConfig{
		TenantID:          "middleware-tenant",
		RequestsPerSecond: 1.0,
		BurstSize:         1,
		Enabled:           true,
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := trl.Middleware(func(r *http.Request) string {
		return "middleware-tenant"
	})

	wrappedHandler := middleware(handler)

	// First request succeeds
	req1 := httptest.NewRequest("GET", "/acme/new-account", nil)
	rec1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Second request should be rate limited
	req2 := httptest.NewRequest("GET", "/acme/new-account", nil)
	rec2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
	assert.Equal(t, "application/problem+json", rec2.Header().Get("Content-Type"))
	assert.Equal(t, "60", rec2.Header().Get("Retry-After"))
}

// TestTenantRateLimiter_GetLimiterFallsBackToDefault verifies that GetLimiter
// uses default config when the config provider returns an error.
func TestTenantRateLimiter_GetLimiterFallsBackToDefault(t *testing.T) {
	ctx := context.Background()

	// Provider that doesn't have the requested tenant
	provider := NewMemoryConfigProvider()

	trl := NewTenantRateLimiter(nil, provider)

	// Unknown tenant should fall back to default config
	limiter, err := trl.GetLimiter(ctx, "unknown-tenant")
	require.NoError(t, err)
	require.NotNil(t, limiter)

	// Should use default config values
	assert.Equal(t, "unknown-tenant", limiter.config.TenantID)
	assert.Equal(t, 50.0, limiter.config.RequestsPerSecond)
}
