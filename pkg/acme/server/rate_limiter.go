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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
)

// DefaultMaxRequestBodySize is the default maximum request body size (64KB).
// This prevents DoS attacks via memory exhaustion from large request bodies.
// ACME requests are typically small (JWS payloads), so 64KB is generous.
const DefaultMaxRequestBodySize int64 = 64 * 1024

// MaxRequestBodySize controls the maximum allowed request body size.
// Configure this based on your deployment needs.
var MaxRequestBodySize int64 = DefaultMaxRequestBodySize

// BodySizeLimitMiddleware creates a middleware that limits request body size.
// This prevents DoS attacks by rejecting requests with bodies larger than maxBytes.
// Returns HTTP 413 Payload Too Large if the limit is exceeded.
//
// Parameters:
//   - maxBytes: Maximum allowed body size in bytes. If 0, uses DefaultMaxRequestBodySize.
//
// Returns:
//   - func(next http.Handler) http.Handler: Middleware function
func BodySizeLimitMiddleware(maxBytes int64) func(next http.Handler) http.Handler {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxRequestBodySize
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only limit body size for methods that have a body
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

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

// RateLimiter implements a token bucket rate limiting policy for ACME requests.
// It tracks request rates per resource (typically by client IP or JWS KID) and
// enforces configurable rate limits to prevent abuse.
type RateLimiter struct {
	MaxRequests int                  // Maximum number of requests allowed in the interval
	Interval    time.Duration        // Time interval for rate limit window
	Tokens      map[string]int       // Remaining tokens per resource key
	LastRequest map[string]time.Time // Timestamp of last request per resource key
	mu          sync.Mutex           // Mutex to synchronize access

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
	return &RateLimiter{
		MaxRequests: maxRequests,
		Interval:    interval,
		Tokens:      make(map[string]int),
		LastRequest: make(map[string]time.Time),
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
// RateLimiter keyed by ClientID (the JWS KID once an account exists, the
// client IP before one does), wired to auditLog so a throttled request is
// recorded via EventRateLimitExceeded. It is the single construction path
// for that blanket limiter — the standalone TrustedCA
// (pkg/acme/client/trustedca.go) and xkmsd's embedded ACME listener
// (cmd/xkmsd/acme.go) both call it instead of hand-rolling their own
// NewRateLimiter + SetAuditLogger + MiddlewareFunc wiring.
func NewClientRateLimiterMiddleware(maxRequests int, interval time.Duration, auditLog audit.AuditLogger) func(http.Handler) http.Handler {
	limiter := NewRateLimiter(maxRequests, interval)
	limiter.SetAuditLogger(auditLog)
	return limiter.MiddlewareFunc(ClientID)
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
			rl.mu.Lock()
			defer rl.mu.Unlock()

			resourceKey := resourceKeyFunc(r) // Generate the resource key (IP or KID)

			// Calculate time since the last request for this resource
			now := time.Now()
			elapsed := now.Sub(rl.LastRequest[resourceKey])

			// Add tokens back based on time passed (token bucket refill)
			tokensToAdd := int(elapsed.Seconds() / rl.Interval.Seconds())
			rl.Tokens[resourceKey] = min(rl.MaxRequests, rl.Tokens[resourceKey]+tokensToAdd)

			// Update last request time
			rl.LastRequest[resourceKey] = now

			// Check if we have tokens left
			if rl.Tokens[resourceKey] > 0 {
				rl.Tokens[resourceKey]--
				next.ServeHTTP(w, r) // Serve the request
			} else {
				// Rate limit exceeded - return RFC 8555 compliant error response.
				// The request is refused either way, so a failed audit write
				// cannot change the outcome to "allow" here (there is no more
				// permissive action to withhold); it is surfaced through the
				// default logger since RateLimiter has no logger of its own.
				if auditErr := rl.recordRateLimitExceeded(r, resourceKey); auditErr != nil {
					slog.Default().Error("audit log failed", "error", auditErr)
				}
				rl.writeRateLimitError(w)
			}
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
	return limiter.MiddlewareFunc(ClientIP)
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
	return limiter.MiddlewareFunc(ClientID)
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
	return limiter.MiddlewareFunc(ClientID)
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
	return limiter.MiddlewareFunc(ClientIP)
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
	return limiter.MiddlewareFunc(ClientID)
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

// ClientID generates a rate-limiting client identifier by parsing the JWS KID from the request,
// or falling back to the client's IP address if KID is not available.
//
// This function attempts to extract the KeyID from the JWS protected header to identify
// authenticated ACME clients. If the request doesn't contain a valid JWS or KID,
// it falls back to using the client's IP address (with proxy header support).
//
// This is used for account-based rate limiting (new orders, certificates, failed validations).
//
// Parameters:
//   - r: HTTP request to extract client identifier from
//
// Returns:
//   - string: Client identifier (JWS KID or IP address)
func ClientID(r *http.Request) string {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return ClientIP(r)
	}
	// The body has already been read in full above, and net/http closes the
	// server request body itself once the handler returns, so a close error
	// here is neither actionable nor meaningful (go-xkms#866).
	defer func() { _ = r.Body.Close() }()

	// Restore the body so it can be read again by the handler
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	jwsString := strings.TrimSpace(string(body))
	jws, err := jose.ParseSigned(jwsString, AllowedJOSEAlgorithms)
	if err != nil {
		return ClientIP(r)
	}

	if len(jws.Signatures) == 0 {
		return ClientIP(r)
	}

	protectedHeader := jws.Signatures[0].Header

	if protectedHeader.KeyID == "" {
		return ClientIP(r)
	}
	return protectedHeader.KeyID
}

// writeJSONError writes an ACME error response in JSON format.
func writeJSONError(w http.ResponseWriter, acmeErr *entities.Error) error {
	return json.NewEncoder(w).Encode(acmeErr)
}
