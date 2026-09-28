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
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
)

// TenantRateLimitConfig holds per-tenant rate limiting configuration.
type TenantRateLimitConfig struct {
	// TenantID identifies the tenant this configuration applies to.
	TenantID string

	// NewAccountRate limits account creation per IP address for this tenant.
	NewAccountRate *RateLimit

	// NewOrderRate limits order creation per account for this tenant.
	NewOrderRate *RateLimit

	// CertificateRate limits certificate issuance per account for this tenant.
	CertificateRate *RateLimit

	// OverallRequestRate limits all requests per IP for this tenant.
	OverallRequestRate *RateLimit

	// FailedValidationRate limits failed challenge validation attempts for this tenant.
	FailedValidationRate *RateLimit

	// BurstMultiplier allows short bursts above the rate limit.
	// A value of 1.0 means no bursting, 2.0 allows double the normal rate briefly.
	// Default is 1.0 if not set.
	BurstMultiplier float64
}

// TenantRateLimitMetrics tracks rate limiting metrics per tenant.
type TenantRateLimitMetrics struct {
	// TotalRequests is the total number of requests for this tenant.
	TotalRequests atomic.Uint64

	// RateLimitedRequests is the number of requests that were rate limited.
	RateLimitedRequests atomic.Uint64

	// LastRateLimitedAt is the timestamp of the last rate-limited request.
	LastRateLimitedAt atomic.Int64
}

// TenantRateLimiterConfig holds configuration for the tenant-aware rate limiter.
type TenantRateLimiterConfig struct {
	// DefaultConfig is the default rate limit configuration for tenants without custom config.
	DefaultConfig *RateLimitConfig

	// TenantConfigs maps tenant IDs to their specific rate limit configurations.
	TenantConfigs map[string]*TenantRateLimitConfig

	// CleanupInterval is how often to clean up expired rate limit entries.
	// Default is 5 minutes if not set.
	CleanupInterval time.Duration

	// MaxEntriesPerTenant is the maximum number of rate limit entries per tenant.
	// Prevents memory exhaustion from too many unique clients.
	// Default is DefaultMaxEntries if not set.
	MaxEntriesPerTenant int

	// MetricsEnabled enables Prometheus metrics collection.
	MetricsEnabled bool
}

// TenantKeyFunc extracts the tenant ID from an HTTP request.
// Returns empty string if no tenant context is found.
type TenantKeyFunc func(r *http.Request) string

// tenantBucket holds rate limiting state for a single client within a tenant.
type tenantBucket struct {
	tokens      int
	lastRequest time.Time
}

// tenantLimiterState holds the rate limiting state for a single tenant.
type tenantLimiterState struct {
	buckets map[string]*tenantBucket
	mu      sync.RWMutex
}

// TenantRateLimiter implements tenant-aware rate limiting.
// Each tenant has isolated rate limits with configurable per-tenant settings.
// Thread-safe with lock-free metrics collection.
type TenantRateLimiter struct {
	config        *TenantRateLimiterConfig
	states        map[string]*tenantLimiterState
	statesMu      sync.RWMutex
	metrics       map[string]*TenantRateLimitMetrics
	metricsMu     sync.RWMutex
	tenantKeyFn   TenantKeyFunc
	clientKeyFn   func(r *http.Request) string
	operationType string
	stopCleanup   chan struct{}
	cleanupDone   chan struct{}
}

// NewTenantRateLimiter creates a new tenant-aware rate limiter.
//
// Parameters:
//   - config: Rate limiter configuration
//   - tenantKeyFn: Function to extract tenant ID from request
//   - clientKeyFn: Function to extract client ID from request (e.g., ClientIP or ClientID)
//   - operationType: Type of operation being rate limited (for metrics/logging)
//
// Returns:
//   - *TenantRateLimiter: Configured rate limiter instance
func NewTenantRateLimiter(
	config *TenantRateLimiterConfig,
	tenantKeyFn TenantKeyFunc,
	clientKeyFn func(r *http.Request) string,
	operationType string,
) *TenantRateLimiter {
	if config == nil {
		config = &TenantRateLimiterConfig{
			DefaultConfig: DefaultRateLimitConfig(),
		}
	}

	if config.CleanupInterval == 0 {
		config.CleanupInterval = 5 * time.Minute
	}

	if config.MaxEntriesPerTenant == 0 {
		config.MaxEntriesPerTenant = DefaultMaxEntries
	}

	trl := &TenantRateLimiter{
		config:        config,
		states:        make(map[string]*tenantLimiterState),
		metrics:       make(map[string]*TenantRateLimitMetrics),
		tenantKeyFn:   tenantKeyFn,
		clientKeyFn:   clientKeyFn,
		operationType: operationType,
		stopCleanup:   make(chan struct{}),
		cleanupDone:   make(chan struct{}),
	}

	// Start background cleanup
	go trl.cleanupLoop()

	return trl
}

// Stop stops the rate limiter and releases resources.
func (trl *TenantRateLimiter) Stop() {
	close(trl.stopCleanup)
	<-trl.cleanupDone
}

// cleanupLoop periodically removes expired rate limit entries.
func (trl *TenantRateLimiter) cleanupLoop() {
	defer close(trl.cleanupDone)

	ticker := time.NewTicker(trl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-trl.stopCleanup:
			return
		case <-ticker.C:
			trl.cleanup()
		}
	}
}

// cleanup removes expired rate limit entries.
func (trl *TenantRateLimiter) cleanup() {
	trl.statesMu.RLock()
	tenantIDs := make([]string, 0, len(trl.states))
	for tenantID := range trl.states {
		tenantIDs = append(tenantIDs, tenantID)
	}
	trl.statesMu.RUnlock()

	now := time.Now()
	maxAge := trl.getMaxInterval() * 2 // Keep entries for 2x the max interval

	for _, tenantID := range tenantIDs {
		trl.statesMu.RLock()
		state, ok := trl.states[tenantID]
		trl.statesMu.RUnlock()
		if !ok {
			continue
		}

		state.mu.Lock()
		for clientID, bucket := range state.buckets {
			if now.Sub(bucket.lastRequest) > maxAge {
				delete(state.buckets, clientID)
			}
		}
		state.mu.Unlock()
	}
}

// getMaxInterval returns the maximum interval from all rate limits.
// This is used to determine how long to keep rate limit entries before cleanup.
func (trl *TenantRateLimiter) getMaxInterval() time.Duration {
	var maxInterval time.Duration

	if trl.config.DefaultConfig != nil {
		if trl.config.DefaultConfig.NewAccountRate != nil && trl.config.DefaultConfig.NewAccountRate.Interval > maxInterval {
			maxInterval = trl.config.DefaultConfig.NewAccountRate.Interval
		}
		if trl.config.DefaultConfig.NewOrderRate != nil && trl.config.DefaultConfig.NewOrderRate.Interval > maxInterval {
			maxInterval = trl.config.DefaultConfig.NewOrderRate.Interval
		}
		if trl.config.DefaultConfig.CertificateRate != nil && trl.config.DefaultConfig.CertificateRate.Interval > maxInterval {
			maxInterval = trl.config.DefaultConfig.CertificateRate.Interval
		}
		if trl.config.DefaultConfig.OverallRequestRate != nil && trl.config.DefaultConfig.OverallRequestRate.Interval > maxInterval {
			maxInterval = trl.config.DefaultConfig.OverallRequestRate.Interval
		}
		if trl.config.DefaultConfig.FailedValidationRate != nil && trl.config.DefaultConfig.FailedValidationRate.Interval > maxInterval {
			maxInterval = trl.config.DefaultConfig.FailedValidationRate.Interval
		}
	}

	// Default to 1 hour if no intervals are configured
	if maxInterval == 0 {
		maxInterval = time.Hour
	}

	return maxInterval
}

// getRateLimit returns the rate limit for the given tenant and operation type.
func (trl *TenantRateLimiter) getRateLimit(tenantID string) *RateLimit {
	// Check tenant-specific config first
	if trl.config.TenantConfigs != nil {
		if tenantConfig, ok := trl.config.TenantConfigs[tenantID]; ok {
			return trl.getRateLimitFromTenantConfig(tenantConfig)
		}
	}

	// Fall back to default config
	if trl.config.DefaultConfig == nil {
		return nil
	}

	return trl.getRateLimitFromDefaultConfig()
}

// getRateLimitFromTenantConfig returns the rate limit from a tenant config.
func (trl *TenantRateLimiter) getRateLimitFromTenantConfig(config *TenantRateLimitConfig) *RateLimit {
	switch trl.operationType {
	case "new-account":
		return config.NewAccountRate
	case "new-order":
		return config.NewOrderRate
	case "certificate":
		return config.CertificateRate
	case "overall":
		return config.OverallRequestRate
	case "failed-validation":
		return config.FailedValidationRate
	default:
		return config.OverallRequestRate
	}
}

// getRateLimitFromDefaultConfig returns the rate limit from the default config.
func (trl *TenantRateLimiter) getRateLimitFromDefaultConfig() *RateLimit {
	switch trl.operationType {
	case "new-account":
		return trl.config.DefaultConfig.NewAccountRate
	case "new-order":
		return trl.config.DefaultConfig.NewOrderRate
	case "certificate":
		return trl.config.DefaultConfig.CertificateRate
	case "overall":
		return trl.config.DefaultConfig.OverallRequestRate
	case "failed-validation":
		return trl.config.DefaultConfig.FailedValidationRate
	default:
		return trl.config.DefaultConfig.OverallRequestRate
	}
}

// getOrCreateState returns the rate limiter state for the given tenant, creating it if necessary.
func (trl *TenantRateLimiter) getOrCreateState(tenantID string) *tenantLimiterState {
	trl.statesMu.RLock()
	state, ok := trl.states[tenantID]
	trl.statesMu.RUnlock()

	if ok {
		return state
	}

	trl.statesMu.Lock()
	defer trl.statesMu.Unlock()

	// Double-check after acquiring write lock
	if state, ok = trl.states[tenantID]; ok {
		return state
	}

	state = &tenantLimiterState{
		buckets: make(map[string]*tenantBucket),
	}
	trl.states[tenantID] = state
	return state
}

// getOrCreateMetrics returns the metrics for the given tenant, creating them if necessary.
func (trl *TenantRateLimiter) getOrCreateMetrics(tenantID string) *TenantRateLimitMetrics {
	trl.metricsMu.RLock()
	metrics, ok := trl.metrics[tenantID]
	trl.metricsMu.RUnlock()

	if ok {
		return metrics
	}

	trl.metricsMu.Lock()
	defer trl.metricsMu.Unlock()

	// Double-check after acquiring write lock
	if metrics, ok = trl.metrics[tenantID]; ok {
		return metrics
	}

	metrics = &TenantRateLimitMetrics{}
	trl.metrics[tenantID] = metrics
	return metrics
}

// Allow checks if a request should be allowed based on tenant rate limits.
// Returns true if the request is allowed, false if it should be rate limited.
func (trl *TenantRateLimiter) Allow(tenantID, clientID string) bool {
	rateLimit := trl.getRateLimit(tenantID)
	if rateLimit == nil {
		// No rate limit configured - allow all
		return true
	}

	state := trl.getOrCreateState(tenantID)
	metrics := trl.getOrCreateMetrics(tenantID)

	// Increment total requests (lock-free)
	metrics.TotalRequests.Add(1)

	state.mu.Lock()
	defer state.mu.Unlock()

	// Check if we've hit the max entries limit
	if len(state.buckets) >= trl.config.MaxEntriesPerTenant {
		// Under high load, start rejecting new clients to prevent memory exhaustion
		if _, exists := state.buckets[clientID]; !exists {
			metrics.RateLimitedRequests.Add(1)
			metrics.LastRateLimitedAt.Store(time.Now().Unix())
			return false
		}
	}

	now := time.Now()
	bucket, exists := state.buckets[clientID]

	if !exists {
		// First request from this client
		bucket = &tenantBucket{
			tokens:      rateLimit.MaxRequests - 1, // Consume one token
			lastRequest: now,
		}
		state.buckets[clientID] = bucket
		return true
	}

	// Calculate token refill
	elapsed := now.Sub(bucket.lastRequest)
	tokensToAdd := int(elapsed.Seconds() / rateLimit.Interval.Seconds())

	// Apply burst multiplier if configured
	maxTokens := rateLimit.MaxRequests
	if trl.config.TenantConfigs != nil {
		if tenantConfig, ok := trl.config.TenantConfigs[tenantID]; ok && tenantConfig.BurstMultiplier > 1.0 {
			maxTokens = int(float64(rateLimit.MaxRequests) * tenantConfig.BurstMultiplier)
		}
	}

	bucket.tokens = min(maxTokens, bucket.tokens+tokensToAdd)
	bucket.lastRequest = now

	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	// Rate limited
	metrics.RateLimitedRequests.Add(1)
	metrics.LastRateLimitedAt.Store(now.Unix())
	return false
}

// GetMetrics returns the current metrics for a tenant.
func (trl *TenantRateLimiter) GetMetrics(tenantID string) *TenantRateLimitMetrics {
	trl.metricsMu.RLock()
	defer trl.metricsMu.RUnlock()
	return trl.metrics[tenantID]
}

// GetAllMetrics returns metrics for all tenants.
func (trl *TenantRateLimiter) GetAllMetrics() map[string]*TenantRateLimitMetrics {
	trl.metricsMu.RLock()
	defer trl.metricsMu.RUnlock()

	result := make(map[string]*TenantRateLimitMetrics, len(trl.metrics))
	for k, v := range trl.metrics {
		result[k] = v
	}
	return result
}

// Middleware returns an HTTP middleware that applies tenant-aware rate limiting.
func (trl *TenantRateLimiter) Middleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := ""
			if trl.tenantKeyFn != nil {
				tenantID = trl.tenantKeyFn(r)
			}

			clientID := trl.clientKeyFn(r)

			if !trl.Allow(tenantID, clientID) {
				trl.writeRateLimitError(w, tenantID)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RetryAfterSeconds returns the Retry-After value, in seconds, a caller
// should report for tenantID's currently configured rate limit. It exists so
// a call site that cannot use Middleware — because it must enforce the limit
// conditionally rather than on every request, as
// pkg/acme/server/handlers.ChallengeHandler does for the failed-validation
// category — can still build an RFC 8555 compliant response without
// duplicating TenantRateLimiter's rate-limit resolution.
func (trl *TenantRateLimiter) RetryAfterSeconds(tenantID string) int {
	rateLimit := trl.getRateLimit(tenantID)
	if rateLimit == nil {
		return 60 // Default to 60 seconds if no rate limit config
	}
	return int(rateLimit.Interval.Seconds())
}

// writeRateLimitError writes an RFC 8555 compliant rate limit error response.
func (trl *TenantRateLimiter) writeRateLimitError(w http.ResponseWriter, tenantID string) {
	retryAfterSeconds := trl.RetryAfterSeconds(tenantID)

	w.Header().Set("Retry-After", formatRetryAfter(retryAfterSeconds))
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusTooManyRequests)

	detail := formatRateLimitDetail(retryAfterSeconds)
	acmeError := common.RateLimited(detail)

	if err := writeJSONError(w, acmeError); err != nil {
		// Headers and status are already written; there is no way to
		// report this to the client, so it's only logged.
		slog.Error("failed to write rate limit error response", slog.String("error", err.Error()))
	}
}

// formatRetryAfter formats the retry after value as a string.
func formatRetryAfter(seconds int) string {
	return formatInt(seconds)
}

// formatRateLimitDetail formats the rate limit detail message.
func formatRateLimitDetail(seconds int) string {
	return "Rate limit exceeded. Please retry after " + formatInt(seconds) + " seconds."
}

// formatInt formats an integer as a string without using fmt.
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}

	negative := n < 0
	if negative {
		n = -n
	}

	// Max int64 has 19 digits
	var buf [20]byte
	i := len(buf)

	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}

	if negative {
		i--
		buf[i] = '-'
	}

	return string(buf[i:])
}

// TenantRateLimiterFromContext extracts the tenant ID from context.
// This is a helper function for use as a TenantKeyFunc.
func TenantRateLimiterFromContext(key interface{}) TenantKeyFunc {
	return func(r *http.Request) string {
		if tenantID, ok := r.Context().Value(key).(string); ok {
			return tenantID
		}
		return ""
	}
}

// TenantRateLimiterFromHeader extracts the tenant ID from an HTTP header.
// This is a helper function for use as a TenantKeyFunc.
func TenantRateLimiterFromHeader(headerName string) TenantKeyFunc {
	return func(r *http.Request) string {
		return r.Header.Get(headerName)
	}
}

// NewTenantAccountRateLimiter creates a tenant-aware rate limiter for account creation.
func NewTenantAccountRateLimiter(config *TenantRateLimiterConfig, tenantKeyFn TenantKeyFunc) *TenantRateLimiter {
	return NewTenantRateLimiter(config, tenantKeyFn, ClientIP, "new-account")
}

// NewTenantOrderRateLimiter creates a tenant-aware rate limiter for order creation.
func NewTenantOrderRateLimiter(config *TenantRateLimiterConfig, tenantKeyFn TenantKeyFunc) *TenantRateLimiter {
	return NewTenantRateLimiter(config, tenantKeyFn, ClientID, "new-order")
}

// NewTenantCertificateRateLimiter creates a tenant-aware rate limiter for certificate operations.
func NewTenantCertificateRateLimiter(config *TenantRateLimiterConfig, tenantKeyFn TenantKeyFunc) *TenantRateLimiter {
	return NewTenantRateLimiter(config, tenantKeyFn, ClientID, "certificate")
}

// NewTenantOverallRateLimiter creates a tenant-aware rate limiter for all requests.
func NewTenantOverallRateLimiter(config *TenantRateLimiterConfig, tenantKeyFn TenantKeyFunc) *TenantRateLimiter {
	return NewTenantRateLimiter(config, tenantKeyFn, ClientIP, "overall")
}

// NewTenantFailedValidationRateLimiter creates a tenant-aware rate limiter for failed validations.
func NewTenantFailedValidationRateLimiter(config *TenantRateLimiterConfig, tenantKeyFn TenantKeyFunc) *TenantRateLimiter {
	return NewTenantRateLimiter(config, tenantKeyFn, ClientID, "failed-validation")
}

// TenantContextKey is the context key type for tenant ID.
type TenantContextKey struct{}

// WithTenantID returns a new context with the tenant ID set.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantContextKey{}, tenantID)
}

// TenantIDFromContext returns the tenant ID from the context.
func TenantIDFromContext(ctx context.Context) string {
	if tenantID, ok := ctx.Value(TenantContextKey{}).(string); ok {
		return tenantID
	}
	return ""
}

// TenantRateLimiterFromRequestContext extracts tenant ID from request context.
func TenantRateLimiterFromRequestContext() TenantKeyFunc {
	return func(r *http.Request) string {
		return TenantIDFromContext(r.Context())
	}
}
