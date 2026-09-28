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
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
)

// RateLimitConfig contains rate limiting configuration per RFC 8555 Section 6.6.
// Different limits can be configured for different endpoint categories.
type RateLimitConfig struct {
	// NewAccountRate limits account creation per IP address.
	// Example: 10 accounts per hour per IP
	NewAccountRate *RateLimit

	// NewOrderRate limits order creation per account.
	// Example: 300 orders per 3 hours per account
	NewOrderRate *RateLimit

	// CertificateRate limits certificate issuance per account.
	// Example: 50 certificates per 3 hours per account
	CertificateRate *RateLimit

	// OverallRequestRate limits all requests per IP.
	// Example: 20 requests per second per IP
	OverallRequestRate *RateLimit

	// FailedValidationRate limits failed challenge validation attempts per account.
	// Example: 5 failed validations per hour per account
	FailedValidationRate *RateLimit
}

// RateLimit defines a rate limit policy with max requests and time window.
type RateLimit struct {
	// MaxRequests is the maximum number of requests allowed
	MaxRequests int

	// Interval is the time window for the rate limit
	Interval time.Duration
}

// DefaultRateLimitConfig returns a sensible default rate limiting configuration
// that follows common ACME server practices (similar to Let's Encrypt).
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		// 10 new accounts per IP per hour
		NewAccountRate: &RateLimit{
			MaxRequests: 10,
			Interval:    time.Hour,
		},
		// 300 new orders per account per 3 hours
		NewOrderRate: &RateLimit{
			MaxRequests: 300,
			Interval:    3 * time.Hour,
		},
		// 50 certificates per account per 3 hours
		CertificateRate: &RateLimit{
			MaxRequests: 50,
			Interval:    3 * time.Hour,
		},
		// 20 requests per second per IP
		OverallRequestRate: &RateLimit{
			MaxRequests: 20,
			Interval:    time.Second,
		},
		// 5 failed validations per account per hour
		FailedValidationRate: &RateLimit{
			MaxRequests: 5,
			Interval:    time.Hour,
		},
	}
}

// DefaultMaxEntries is the number of client buckets a RateLimiter or a
// TenantRateLimiter tenant tracks before it refuses to admit a new client.
// It bounds the memory a flood of distinct client keys can consume.
const DefaultMaxEntries = 10000

// maxSweepInterval caps how long a RateLimiter goes between sweeps of its
// expired buckets, so a long-interval limiter (new-account: 10 per hour)
// still frees capacity promptly once entries age out.
const maxSweepInterval = time.Minute

// rateBucket is the token-bucket state of one client key.
type rateBucket struct {
	tokens      int
	lastRequest time.Time
}

// RateLimiter implements a token bucket rate limiting policy for ACME requests.
// It tracks request rates per resource key (the client IP, or an account ID
// only once the account's JWS has been verified) and enforces a configurable
// limit to prevent abuse.
//
// Its state is bounded: a bucket idle for its TTL (see ttl) is evicted, and
// once DefaultMaxEntries keys are tracked a new key is refused until one
// expires — the same fail-closed policy as TenantRateLimiter.
type RateLimiter struct {
	MaxRequests int           // Maximum number of requests allowed in the interval
	Interval    time.Duration // Time interval for rate limit window

	// mu guards buckets and lastSweep. It is held only for the bucket
	// arithmetic in Allow, never across a handler or a body read.
	mu         sync.Mutex
	buckets    map[string]*rateBucket
	lastSweep  time.Time
	maxEntries int

	// now is the limiter's clock: time.Now in production. It is a seam so
	// tests can age buckets past their TTL deterministically instead of
	// sleeping for the interval.
	now func() time.Time

	// auditLog records EventRateLimitExceeded when a request is throttled.
	// Nil (the default) disables audit emission entirely; SetAuditLogger
	// wires a real logger without changing NewRateLimiter's signature,
	// which every existing caller (production and test) depends on.
	auditLog audit.AuditLogger
}

// NewRateLimiter creates a new rate limiter with the specified maximum requests and interval.
//
// Parameters:
//   - maxRequests: Maximum number of requests allowed within the interval
//   - interval: Time window for the rate limit (e.g., time.Minute)
//
// Returns:
//   - *RateLimiter: Configured rate limiter instance
func NewRateLimiter(maxRequests int, interval time.Duration) *RateLimiter {
	now := time.Now
	return &RateLimiter{
		MaxRequests: maxRequests,
		Interval:    interval,
		buckets:     make(map[string]*rateBucket),
		lastSweep:   now(),
		maxEntries:  DefaultMaxEntries,
		now:         now,
	}
}

// ttl is how long a bucket may sit idle before it is evicted:
// MaxRequests intervals, the time a fully drained bucket takes to refill.
// An idle bucket that old is indistinguishable from a new one, so eviction
// never grants or withholds a token. A limiter that admits nothing keeps a
// bucket one interval; one with no positive interval never refills, so its
// buckets never expire (only the entry cap bounds it).
func (rl *RateLimiter) ttl() time.Duration {
	if rl.Interval <= 0 {
		return time.Duration(math.MaxInt64)
	}
	if rl.MaxRequests <= 1 {
		return rl.Interval
	}
	if rl.Interval > time.Duration(math.MaxInt64)/time.Duration(rl.MaxRequests) {
		return time.Duration(math.MaxInt64)
	}
	return rl.Interval * time.Duration(rl.MaxRequests)
}

// Len reports how many client buckets the limiter currently tracks.
func (rl *RateLimiter) Len() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

// Allow consumes one token from key's bucket and reports whether the request
// is admitted. A key not yet tracked starts with a full bucket, unless the
// limiter already tracks its maximum number of keys, in which case the new
// key is refused until an existing bucket expires.
//
// The lock is held only for this arithmetic; callers must derive key before
// calling and serve the request after Allow returns.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	rl.sweepExpiredLocked(now)

	bucket, exists := rl.buckets[key]
	if !exists {
		if len(rl.buckets) >= rl.maxEntries {
			return false
		}
		bucket = &rateBucket{tokens: rl.MaxRequests, lastRequest: now}
		rl.buckets[key] = bucket
	} else {
		// Token bucket refill: one token per elapsed interval, capped at
		// MaxRequests.
		if rl.Interval > 0 {
			refill := now.Sub(bucket.lastRequest) / rl.Interval
			if refill > time.Duration(rl.MaxRequests) {
				refill = time.Duration(rl.MaxRequests)
			}
			bucket.tokens = min(rl.MaxRequests, bucket.tokens+int(refill))
		}
		bucket.lastRequest = now
	}

	if bucket.tokens <= 0 {
		return false
	}
	bucket.tokens--
	return true
}

// sweepExpiredLocked evicts every bucket idle for longer than ttl. It runs at
// most once per sweep period (ttl, capped at maxSweepInterval), so its O(n)
// cost is amortized across all requests in that period. rl.mu must be held.
func (rl *RateLimiter) sweepExpiredLocked(now time.Time) {
	ttl := rl.ttl()
	if now.Sub(rl.lastSweep) < min(ttl, maxSweepInterval) {
		return
	}
	rl.lastSweep = now
	for key, bucket := range rl.buckets {
		if now.Sub(bucket.lastRequest) >= ttl {
			delete(rl.buckets, key)
		}
	}
}

// SetAuditLogger wires the audit logger EventRateLimitExceeded is recorded
// to. A nil logger (the default) disables audit emission: the rate limiter
// still enforces the policy, it just does not record a trail entry.
func (rl *RateLimiter) SetAuditLogger(logger audit.AuditLogger) {
	rl.auditLog = logger
}

// NewClientRateLimiterMiddleware builds the overall per-client ACME
// admission-control middleware mounted on the whole "/acme" surface: a
// RateLimiter keyed by ClientIP, wired to auditLog so a throttled request is
// recorded via EventRateLimitExceeded. It is keyed on the client address, not
// the JWS "kid": it runs before the JWS is verified, and an unverified kid is
// attacker-chosen, so keying on it would let one client mint a fresh bucket
// per request. It is the single construction path
// for that blanket limiter — the standalone TrustedCA
// (pkg/acme/client/trustedca.go) and xkmsd's embedded ACME listener
// (cmd/xkmsd/acme.go) both call it instead of hand-rolling their own
// NewRateLimiter + SetAuditLogger + MiddlewareFunc wiring.
func NewClientRateLimiterMiddleware(maxRequests int, interval time.Duration, auditLog audit.AuditLogger) func(http.Handler) http.Handler {
	limiter := NewRateLimiter(maxRequests, interval)
	limiter.SetAuditLogger(auditLog)
	return limiter.MiddlewareFunc(rateLimitClientIPKey)
}

// recordRateLimitExceeded logs EventRateLimitExceeded for resourceKey.
// EventRateLimitExceeded is SeveritySecurity (repeated throttling can signal
// a credential-stuffing or enumeration attempt), so a failed write is
// returned rather than swallowed: the caller must refuse the request rather
// than let it proceed with a degraded trail. A nil auditLog (rate limiting
// used without audit wiring) is not a failure.
func (rl *RateLimiter) recordRateLimitExceeded(r *http.Request, resourceKey string) error {
	if rl.auditLog == nil {
		return nil
	}
	writeErr := rl.auditLog.LogWithContext(
		audit.RequestContext(r.Context(), r),
		audit.EventRateLimitExceeded,
		resourceKey,
		"acme:rate_limit",
		"throttle",
		audit.ResultFailure,
		map[string]interface{}{
			"max_requests": rl.MaxRequests,
			"interval":     rl.Interval.String(),
		},
	)
	return audit.HandleWriteFailure(nil, audit.EventRateLimitExceeded, writeErr)
}

// MiddlewareFunc generates a rate-limiting middleware function using a resource key function.
// The resource key function extracts an identifier from the request (e.g., client IP or JWS KID)
// to track rate limits per client.
//
// This middleware returns proper RFC 8555 compliant error responses when rate limits are exceeded:
// - HTTP 429 Too Many Requests status code
// - Retry-After header with seconds as integer (per RFC 8555 Section 6.6)
// - ACME error response with type "urn:ietf:params:acme:error:rateLimited"
//
// Parameters:
//   - resourceKeyFunc: Function that extracts a unique identifier from the request
//
// Returns:
//   - func(next http.Handler) http.Handler: Middleware function for use with http.Handler chains
func (rl *RateLimiter) MiddlewareFunc(resourceKeyFunc func(r *http.Request) string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The key is derived, and the request served, outside the
			// limiter's lock: only Allow's bucket arithmetic is serialized,
			// so one slow request never delays another.
			resourceKey := resourceKeyFunc(r)
			if rl.Allow(resourceKey) {
				next.ServeHTTP(w, r)
				return
			}

			// Rate limit exceeded - return RFC 8555 compliant error response.
			// The request is refused either way, so a failed audit write
			// cannot change the outcome to "allow" here (there is no more
			// permissive action to withhold); it is surfaced through the
			// default logger since RateLimiter has no logger of its own.
			if auditErr := rl.recordRateLimitExceeded(r, resourceKey); auditErr != nil {
				slog.Default().Error("audit log failed", "error", auditErr)
			}
			rl.writeRateLimitError(w)
		})
	}
}

// writeRateLimitError writes an RFC 8555 compliant rate limit error response.
// Per RFC 8555 Section 6.6, this includes:
// - HTTP 429 Too Many Requests status
// - Retry-After header with seconds as integer
// - ACME error JSON with type "urn:ietf:params:acme:error:rateLimited"
func (rl *RateLimiter) writeRateLimitError(w http.ResponseWriter) {
	retryAfterSeconds := int(rl.Interval.Seconds())

	// Per RFC 8555 Section 6.6: Retry-After header MUST be in seconds (integer)
	// NOT a Go duration string like "1m0s"
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfterSeconds))
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusTooManyRequests)

	// Create RFC 8555 compliant ACME error response
	detail := fmt.Sprintf("Rate limit exceeded. Please retry after %d seconds.", retryAfterSeconds)
	acmeError := common.RateLimited(detail)

	// Write the ACME error response
	if err := writeJSONError(w, acmeError); err != nil {
		// If JSON encoding fails, we've already set headers and status code
		// so just log and return
		return
	}
}

// NewAccountRateLimiter creates a middleware for limiting new account creation per IP address.
// This implements RFC 8555 Section 6.6 rate limiting for account creation endpoints.
//
// Parameters:
//   - config: Rate limit configuration
//
// Returns:
//   - func(next http.Handler) http.Handler: Middleware function
func NewAccountRateLimiter(config *RateLimit) func(next http.Handler) http.Handler {
	if config == nil {
		// No rate limit configured - return pass-through middleware
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	limiter := NewRateLimiter(config.MaxRequests, config.Interval)
	return limiter.MiddlewareFunc(rateLimitClientIPKey)
}

// NewOrderRateLimiter creates a middleware for limiting order creation per account.
// This implements RFC 8555 Section 6.6 rate limiting for new order endpoints.
//
// Parameters:
//   - config: Rate limit configuration
//
// Returns:
//   - func(next http.Handler) http.Handler: Middleware function
func NewOrderRateLimiter(config *RateLimit) func(next http.Handler) http.Handler {
	if config == nil {
		// No rate limit configured - return pass-through middleware
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	limiter := NewRateLimiter(config.MaxRequests, config.Interval)
	return limiter.MiddlewareFunc(rateLimitClientIDKey)
}

// CertificateRateLimiter creates a middleware for limiting certificate operations per account.
// This implements RFC 8555 Section 6.6 rate limiting for certificate endpoints.
//
// Parameters:
//   - config: Rate limit configuration
//
// Returns:
//   - func(next http.Handler) http.Handler: Middleware function
func CertificateRateLimiter(config *RateLimit) func(next http.Handler) http.Handler {
	if config == nil {
		// No rate limit configured - return pass-through middleware
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	limiter := NewRateLimiter(config.MaxRequests, config.Interval)
	return limiter.MiddlewareFunc(rateLimitClientIDKey)
}

// OverallRateLimiter creates a middleware for limiting all requests per IP address.
// This implements RFC 8555 Section 6.6 general rate limiting across all endpoints.
//
// Parameters:
//   - config: Rate limit configuration
//
// Returns:
//   - func(next http.Handler) http.Handler: Middleware function
func OverallRateLimiter(config *RateLimit) func(next http.Handler) http.Handler {
	if config == nil {
		// No rate limit configured - return pass-through middleware
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	limiter := NewRateLimiter(config.MaxRequests, config.Interval)
	return limiter.MiddlewareFunc(rateLimitClientIPKey)
}

// FailedValidationRateLimiter creates a middleware for limiting failed validation attempts per account.
// This implements RFC 8555 Section 6.6 rate limiting to prevent abuse through repeated failed validations.
//
// Parameters:
//   - config: Rate limit configuration
//
// Returns:
//   - func(next http.Handler) http.Handler: Middleware function
func FailedValidationRateLimiter(config *RateLimit) func(next http.Handler) http.Handler {
	if config == nil {
		// No rate limit configured - return pass-through middleware
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	limiter := NewRateLimiter(config.MaxRequests, config.Interval)
	return limiter.MiddlewareFunc(rateLimitClientIDKey)
}

// TrustedProxies is the set of proxies trusted to name the client in the
// X-Forwarded-For / X-Real-IP headers. Nil (the default) trusts none, so
// proxy headers are ignored and only the transport peer address is used.
var TrustedProxies *ratelimit.TrustedProxies

// ClientIP extracts the client's IP address from the request. Proxy headers
// are honoured only from TrustedProxies; the resolution rules are those of
// the shared ratelimit.TrustedProxies.ClientIP, which the REST login limiter
// uses too.
func ClientIP(r *http.Request) string {
	return TrustedProxies.ClientIP(r)
}

// verifiedAccountContextKey is the context key under which
// WithVerifiedAccountID publishes the account a request's JWS was verified
// against. It is unexported so only WithVerifiedAccountID can set it.
type verifiedAccountContextKey struct{}

// WithVerifiedAccountID returns a copy of ctx recording that the request's
// JWS signature was verified against account accountID. Only the code that
// performed that verification may call it (handlers.RestService.
// TenantAuthMiddleware); ClientID trusts it unconditionally.
func WithVerifiedAccountID(ctx context.Context, accountID uint64) context.Context {
	return context.WithValue(ctx, verifiedAccountContextKey{}, accountID)
}

// VerifiedAccountIDFromContext returns the account WithVerifiedAccountID
// recorded on ctx, if any.
func VerifiedAccountIDFromContext(ctx context.Context) (uint64, bool) {
	accountID, ok := ctx.Value(verifiedAccountContextKey{}).(uint64)
	return accountID, ok
}

// ClientID returns the rate-limiting key for a request: the decimal account
// ID when the request's JWS has already been verified (see
// WithVerifiedAccountID), otherwise the client IP (ClientIP). The two cannot
// collide — an IP address always contains "." or ":".
//
// It never reads the request body and never trusts an unverified JWS "kid":
// a kid taken from an unverified header is attacker-chosen, and keying on it
// would let a client mint a fresh bucket per request and bypass the limit.
//
// This is used for account-based rate limiting (new orders, certificates,
// failed validations), whose limiters are mounted after the JWS is verified.
func ClientID(r *http.Request) string {
	if accountID, ok := VerifiedAccountIDFromContext(r.Context()); ok {
		return strconv.FormatUint(accountID, 10)
	}
	return ClientIP(r)
}

// rateLimitClientIPKey resolves ClientIP and folds it through
// ratelimit.RateLimitKey, so every rate limiter keyed on the client's
// transport/forwarded IP address (NewAccountRateLimiter, OverallRateLimiter,
// and the tenant-aware new-account/overall limiters) buckets an IPv6 client
// on its /64 rather than its full address, while an IPv4 client keys on its
// exact address as before.
func rateLimitClientIPKey(r *http.Request) string {
	return ratelimit.RateLimitKey(ClientIP(r))
}

// rateLimitClientIDKey resolves ClientID and folds it through
// ratelimit.RateLimitKey. A JWS KID passes through unchanged — it is never a
// valid IP address — and the IP fallback is masked exactly like
// rateLimitClientIPKey, so every ClientID-keyed limiter (new-order,
// certificate, failed-validation, and the overall per-client admission
// control) gets the same IPv6 /64 protection before an account exists to key
// on.
func rateLimitClientIDKey(r *http.Request) string {
	return ratelimit.RateLimitKey(ClientID(r))
}

// writeJSONError writes an ACME error response in JSON format.
func writeJSONError(w http.ResponseWriter, acmeErr *entities.Error) error {
	return json.NewEncoder(w).Encode(acmeErr)
}
