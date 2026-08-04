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

// Package ratelimit provides tenant-aware rate limiting for the ACME server.
// It implements per-tenant token bucket rate limiting with configurable limits.
package ratelimit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
)

// Tenant rate limiting errors.
var (
	// ErrRateLimitExceeded is returned when the rate limit is exceeded.
	ErrRateLimitExceeded = errors.New("ratelimit: rate limit exceeded")

	// ErrTenantNotFound is returned when the tenant is not found.
	ErrTenantNotFound = errors.New("ratelimit: tenant not found")
)

// TenantConfig contains rate limiting configuration for a tenant.
type TenantConfig struct {
	// TenantID is the unique identifier for the tenant.
	TenantID string

	// RequestsPerSecond is the maximum requests per second allowed.
	RequestsPerSecond float64

	// BurstSize is the maximum number of requests allowed in a burst.
	BurstSize int

	// NewAccountPerHour limits new account creation per hour.
	NewAccountPerHour int

	// NewOrderPerHour limits new order creation per hour.
	NewOrderPerHour int

	// CertificatesPerDay limits certificate issuance per day.
	CertificatesPerDay int

	// Enabled indicates whether rate limiting is enabled for this tenant.
	Enabled bool
}

// DefaultTenantConfig returns default rate limiting configuration for a tenant.
func DefaultTenantConfig(tenantID string) *TenantConfig {
	return &TenantConfig{
		TenantID:           tenantID,
		RequestsPerSecond:  50.0,
		BurstSize:          100,
		NewAccountPerHour:  100,
		NewOrderPerHour:    1000,
		CertificatesPerDay: 500,
		Enabled:            true,
	}
}

// tokenBucket implements a lock-free token bucket rate limiter.
type tokenBucket struct {
	tokens        atomic.Int64 // Current tokens * 1000 for precision
	maxTokens     int64        // Maximum tokens * 1000
	refillRate    int64        // Tokens per second * 1000
	lastRefill    atomic.Int64 // Last refill time in nanoseconds
	refillMu      sync.Mutex   // Mutex for refill operations
	requestsTotal atomic.Uint64
	requestsLimit atomic.Uint64
}

// newTokenBucket creates a new token bucket rate limiter.
func newTokenBucket(requestsPerSecond float64, burstSize int) *tokenBucket {
	tb := &tokenBucket{
		maxTokens:  int64(burstSize) * 1000,
		refillRate: int64(requestsPerSecond * 1000),
	}
	// Start with full bucket
	tb.tokens.Store(tb.maxTokens)
	tb.lastRefill.Store(time.Now().UnixNano())
	return tb
}

// allow checks if a request is allowed and consumes a token if so.
func (tb *tokenBucket) allow() bool {
	tb.refillMu.Lock()
	defer tb.refillMu.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now().UnixNano()
	lastRefill := tb.lastRefill.Load()
	elapsed := now - lastRefill

	if elapsed > 0 {
		// Calculate tokens to add
		tokensToAdd := (elapsed * tb.refillRate) / int64(time.Second)
		currentTokens := tb.tokens.Load()
		newTokens := currentTokens + tokensToAdd
		if newTokens > tb.maxTokens {
			newTokens = tb.maxTokens
		}
		tb.tokens.Store(newTokens)
		tb.lastRefill.Store(now)
	}

	// Try to consume a token
	currentTokens := tb.tokens.Load()
	if currentTokens >= 1000 {
		tb.tokens.Add(-1000)
		tb.requestsTotal.Add(1)
		return true
	}

	tb.requestsLimit.Add(1)
	return false
}

// tokens returns the current number of tokens available.
func (tb *tokenBucket) tokensAvailable() float64 {
	return float64(tb.tokens.Load()) / 1000.0
}

// quotaBucket tracks quota usage over a time window.
type quotaBucket struct {
	count    atomic.Uint64
	limit    uint64
	windowNs int64 // Window duration in nanoseconds
	windowNr atomic.Int64
}

// newQuotaBucket creates a new quota bucket.
func newQuotaBucket(limit int, window time.Duration) *quotaBucket {
	return &quotaBucket{
		limit:    uint64(limit),
		windowNs: window.Nanoseconds(),
	}
}

// allow checks if the quota allows another request.
func (qb *quotaBucket) allow() bool {
	now := time.Now().UnixNano()
	currentWindow := now / qb.windowNs

	// Reset count if window has changed
	storedWindow := qb.windowNr.Load()
	if currentWindow != storedWindow {
		// Try to update the window atomically
		if qb.windowNr.CompareAndSwap(storedWindow, currentWindow) {
			qb.count.Store(0)
		}
	}

	// Increment and check
	newCount := qb.count.Add(1)
	return newCount <= qb.limit
}

// count returns the current count in the window.
func (qb *quotaBucket) currentCount() uint64 {
	return qb.count.Load()
}

// TenantLimiter manages rate limiting for a single tenant.
type TenantLimiter struct {
	config        *TenantConfig
	requestBucket *tokenBucket
	accountQuota  *quotaBucket
	orderQuota    *quotaBucket
	certQuota     *quotaBucket
}

// newTenantLimiter creates a new limiter for a tenant.
func newTenantLimiter(config *TenantConfig) *TenantLimiter {
	return &TenantLimiter{
		config:        config,
		requestBucket: newTokenBucket(config.RequestsPerSecond, config.BurstSize),
		accountQuota:  newQuotaBucket(config.NewAccountPerHour, time.Hour),
		orderQuota:    newQuotaBucket(config.NewOrderPerHour, time.Hour),
		certQuota:     newQuotaBucket(config.CertificatesPerDay, 24*time.Hour),
	}
}

// AllowRequest checks if a general request is allowed.
func (tl *TenantLimiter) AllowRequest(endpoint string) bool {
	if !tl.config.Enabled {
		return true
	}

	allowed := tl.requestBucket.allow()
	if !allowed {
		metrics.RecordTenantRateLimitHit(tl.config.TenantID, endpoint)
	}
	metrics.SetTenantRateLimitTokens(tl.config.TenantID, tl.requestBucket.tokensAvailable())
	return allowed
}

// AllowNewAccount checks if a new account creation is allowed.
func (tl *TenantLimiter) AllowNewAccount() bool {
	if !tl.config.Enabled {
		return true
	}
	return tl.accountQuota.allow()
}

// AllowNewOrder checks if a new order creation is allowed.
func (tl *TenantLimiter) AllowNewOrder() bool {
	if !tl.config.Enabled {
		return true
	}
	return tl.orderQuota.allow()
}

// AllowCertificate checks if certificate issuance is allowed.
func (tl *TenantLimiter) AllowCertificate() bool {
	if !tl.config.Enabled {
		return true
	}
	return tl.certQuota.allow()
}

// Stats returns current limiter statistics.
func (tl *TenantLimiter) Stats() TenantLimiterStats {
	return TenantLimiterStats{
		TenantID:            tl.config.TenantID,
		TokensAvailable:     tl.requestBucket.tokensAvailable(),
		AccountsThisHour:    tl.accountQuota.currentCount(),
		OrdersThisHour:      tl.orderQuota.currentCount(),
		CertificatesToday:   tl.certQuota.currentCount(),
		RequestsTotal:       tl.requestBucket.requestsTotal.Load(),
		RequestsRateLimited: tl.requestBucket.requestsLimit.Load(),
	}
}

// TenantLimiterStats contains statistics for a tenant limiter.
type TenantLimiterStats struct {
	TenantID            string  `json:"tenant_id"`
	TokensAvailable     float64 `json:"tokens_available"`
	AccountsThisHour    uint64  `json:"accounts_this_hour"`
	OrdersThisHour      uint64  `json:"orders_this_hour"`
	CertificatesToday   uint64  `json:"certificates_today"`
	RequestsTotal       uint64  `json:"requests_total"`
	RequestsRateLimited uint64  `json:"requests_rate_limited"`
}

// TenantRateLimiter manages rate limiting across multiple tenants.
type TenantRateLimiter struct {
	limiters       sync.Map // map[string]*TenantLimiter
	defaultConfig  *TenantConfig
	configProvider TenantConfigProvider
}

// TenantConfigProvider provides tenant configurations.
type TenantConfigProvider interface {
	GetTenantConfig(ctx context.Context, tenantID string) (*TenantConfig, error)
}

// NewTenantRateLimiter creates a new tenant rate limiter.
func NewTenantRateLimiter(defaultConfig *TenantConfig, provider TenantConfigProvider) *TenantRateLimiter {
	if defaultConfig == nil {
		defaultConfig = DefaultTenantConfig("default")
	}
	return &TenantRateLimiter{
		defaultConfig:  defaultConfig,
		configProvider: provider,
	}
}

// GetLimiter returns the limiter for a tenant, creating one if necessary.
func (trl *TenantRateLimiter) GetLimiter(ctx context.Context, tenantID string) (*TenantLimiter, error) {
	if limiter, ok := trl.limiters.Load(tenantID); ok {
		return limiter.(*TenantLimiter), nil
	}

	// Get tenant config
	var config *TenantConfig
	if trl.configProvider != nil {
		var err error
		config, err = trl.configProvider.GetTenantConfig(ctx, tenantID)
		if err != nil {
			// Use default config if provider fails
			config = DefaultTenantConfig(tenantID)
		}
	} else {
		config = DefaultTenantConfig(tenantID)
	}

	limiter := newTenantLimiter(config)
	actual, _ := trl.limiters.LoadOrStore(tenantID, limiter)
	return actual.(*TenantLimiter), nil
}

// AllowRequest checks if a request is allowed for a tenant.
func (trl *TenantRateLimiter) AllowRequest(ctx context.Context, tenantID, endpoint string) (bool, error) {
	limiter, err := trl.GetLimiter(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return limiter.AllowRequest(endpoint), nil
}

// AllowNewAccount checks if new account creation is allowed for a tenant.
func (trl *TenantRateLimiter) AllowNewAccount(ctx context.Context, tenantID string) (bool, error) {
	limiter, err := trl.GetLimiter(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return limiter.AllowNewAccount(), nil
}

// AllowNewOrder checks if new order creation is allowed for a tenant.
func (trl *TenantRateLimiter) AllowNewOrder(ctx context.Context, tenantID string) (bool, error) {
	limiter, err := trl.GetLimiter(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return limiter.AllowNewOrder(), nil
}

// AllowCertificate checks if certificate issuance is allowed for a tenant.
func (trl *TenantRateLimiter) AllowCertificate(ctx context.Context, tenantID string) (bool, error) {
	limiter, err := trl.GetLimiter(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return limiter.AllowCertificate(), nil
}

// UpdateConfig updates the configuration for a tenant.
func (trl *TenantRateLimiter) UpdateConfig(tenantID string, config *TenantConfig) {
	limiter := newTenantLimiter(config)
	trl.limiters.Store(tenantID, limiter)
}

// RemoveTenant removes a tenant's limiter.
func (trl *TenantRateLimiter) RemoveTenant(tenantID string) {
	trl.limiters.Delete(tenantID)
}

// Stats returns statistics for all tenants.
func (trl *TenantRateLimiter) Stats() map[string]TenantLimiterStats {
	stats := make(map[string]TenantLimiterStats)
	trl.limiters.Range(func(key, value any) bool {
		tenantID := key.(string)
		limiter := value.(*TenantLimiter)
		stats[tenantID] = limiter.Stats()
		return true
	})
	return stats
}

// RateLimitResponse represents an RFC 8555 compliant rate limit error response.
type RateLimitResponse struct {
	Type        string `json:"type"`
	Detail      string `json:"detail"`
	Status      int    `json:"status"`
	RetryAfter  int    `json:"retryAfter,omitempty"`
	SubProblems []struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	} `json:"subproblems,omitempty"`
}

// Middleware returns an HTTP middleware that enforces tenant rate limiting.
func (trl *TenantRateLimiter) Middleware(tenantExtractor func(r *http.Request) string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := tenantExtractor(r)
			if tenantID == "" {
				tenantID = "default"
			}

			endpoint := extractEndpointFromPath(r.URL.Path)
			allowed, err := trl.AllowRequest(r.Context(), tenantID, endpoint)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !allowed {
				writeRateLimitError(w, tenantID)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// writeRateLimitError writes an RFC 8555 compliant rate limit error response.
func writeRateLimitError(w http.ResponseWriter, tenantID string) {
	response := RateLimitResponse{
		Type:       "urn:ietf:params:acme:error:rateLimited",
		Detail:     "Rate limit exceeded for tenant " + tenantID + ". Please retry after the specified time.",
		Status:     http.StatusTooManyRequests,
		RetryAfter: 60, // Default retry after 60 seconds
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusTooManyRequests)

	_ = json.NewEncoder(w).Encode(response)
}

// extractEndpointFromPath extracts the endpoint name from a URL path.
func extractEndpointFromPath(path string) string {
	// Remove leading slash
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	// Find the endpoint after /acme/
	if len(path) > 5 && path[:5] == "acme/" {
		path = path[5:]
	}

	// Return the first path segment
	for i, c := range path {
		if c == '/' {
			return path[:i]
		}
	}
	return path
}

// MemoryConfigProvider provides tenant configurations from memory.
type MemoryConfigProvider struct {
	configs sync.Map // map[string]*TenantConfig
}

// NewMemoryConfigProvider creates a new memory-based config provider.
func NewMemoryConfigProvider() *MemoryConfigProvider {
	return &MemoryConfigProvider{}
}

// SetConfig sets the configuration for a tenant.
func (p *MemoryConfigProvider) SetConfig(tenantID string, config *TenantConfig) {
	p.configs.Store(tenantID, config)
}

// GetTenantConfig returns the configuration for a tenant.
func (p *MemoryConfigProvider) GetTenantConfig(ctx context.Context, tenantID string) (*TenantConfig, error) {
	if config, ok := p.configs.Load(tenantID); ok {
		return config.(*TenantConfig), nil
	}
	return nil, ErrTenantNotFound
}
