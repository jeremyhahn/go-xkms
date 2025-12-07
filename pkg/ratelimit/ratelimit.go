// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ratelimit

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Limiter implements a token bucket rate limiter with per-client tracking.
// It uses the golang.org/x/time/rate package for efficient, thread-safe rate limiting.
type Limiter struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
	enabled  bool

	// Cleanup settings
	cleanupInterval time.Duration
	maxIdle         time.Duration
	lastSeen        map[string]time.Time
	stopCleanup     chan struct{}
}

// Config holds rate limiter configuration.
type Config struct {
	// Enabled controls whether rate limiting is active.
	Enabled bool

	// RequestsPerMinute sets the sustained rate limit.
	RequestsPerMinute int

	// Burst allows short bursts above the sustained rate.
	// If not set, defaults to RequestsPerMinute.
	Burst int

	// CleanupInterval controls how often to remove idle clients.
	// Defaults to 10 minutes.
	CleanupInterval time.Duration

	// MaxIdle is how long a client can be idle before cleanup.
	// Defaults to 30 minutes.
	MaxIdle time.Duration
}

// New creates a new rate limiter with the given configuration.
func New(config *Config) *Limiter {
	if config == nil {
		config = &Config{Enabled: false}
	}

	burst := config.Burst
	if burst == 0 {
		burst = config.RequestsPerMinute
	}

	cleanupInterval := config.CleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = 10 * time.Minute
	}

	maxIdle := config.MaxIdle
	if maxIdle == 0 {
		maxIdle = 30 * time.Minute
	}

	// Convert requests per minute to requests per second
	ratePerSecond := rate.Limit(float64(config.RequestsPerMinute) / 60.0)

	l := &Limiter{
		limiters:        make(map[string]*rate.Limiter),
		lastSeen:        make(map[string]time.Time),
		rate:            ratePerSecond,
		burst:           burst,
		enabled:         config.Enabled,
		cleanupInterval: cleanupInterval,
		maxIdle:         maxIdle,
		stopCleanup:     make(chan struct{}),
	}

	if config.Enabled {
		go l.cleanupWorker()
	}

	return l
}

// getLimiter returns the rate limiter for a given client identifier.
// Creates a new limiter if one doesn't exist.
func (l *Limiter) getLimiter(clientID string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, exists := l.limiters[clientID]
	if !exists {
		limiter = rate.NewLimiter(l.rate, l.burst)
		l.limiters[clientID] = limiter
	}

	l.lastSeen[clientID] = time.Now()
	return limiter
}

// Allow checks if a request from the given client should be allowed.
// Returns true if the request is within rate limits.
func (l *Limiter) Allow(clientID string) bool {
	if !l.enabled {
		return true
	}

	limiter := l.getLimiter(clientID)
	return limiter.Allow()
}

// Wait blocks until the rate limit allows the request.
// Returns nil on success or an error if the context is cancelled.
func (l *Limiter) Wait(clientID string) error {
	if !l.enabled {
		return nil
	}

	limiter := l.getLimiter(clientID)
	return limiter.Wait(context.TODO())
}

// cleanupWorker periodically removes idle clients from memory.
func (l *Limiter) cleanupWorker() {
	ticker := time.NewTicker(l.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.cleanup()
		case <-l.stopCleanup:
			return
		}
	}
}

// cleanup removes clients that haven't made requests recently.
func (l *Limiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for clientID, lastSeen := range l.lastSeen {
		if now.Sub(lastSeen) > l.maxIdle {
			delete(l.limiters, clientID)
			delete(l.lastSeen, clientID)
		}
	}
}

// Stop stops the cleanup worker.
func (l *Limiter) Stop() {
	close(l.stopCleanup)
}

// Stats returns current rate limiter statistics.
func (l *Limiter) Stats() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return map[string]interface{}{
		"enabled":        l.enabled,
		"active_clients": len(l.limiters),
		"rate_per_min":   float64(l.rate) * 60,
		"burst":          l.burst,
	}
}

// Middleware returns an HTTP middleware that enforces rate limiting.
// It uses the client's IP address as the identifier.
func Middleware(limiter *Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract client IP
			clientIP := getClientIP(r)

			// Check rate limit
			if !limiter.Allow(clientIP) {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP from the request.
// Checks X-Forwarded-For and X-Real-IP headers for proxied requests.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (may contain multiple IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (original client)
		if idx := len(xff); idx > 0 {
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' {
					return xff[:i]
				}
			}
			return xff
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// UnaryServerInterceptor returns a gRPC unary server interceptor that enforces rate limiting.
func UnaryServerInterceptor(limiter *Limiter) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Extract client IP from peer info
		clientIP := getClientIPFromContext(ctx)

		// Check rate limit
		if !limiter.Allow(clientIP) {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor that enforces rate limiting.
func StreamServerInterceptor(limiter *Limiter) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Extract client IP from peer info
		clientIP := getClientIPFromContext(ss.Context())

		// Check rate limit
		if !limiter.Allow(clientIP) {
			return status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(srv, ss)
	}
}

// getClientIPFromContext extracts the client IP from a gRPC context.
func getClientIPFromContext(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "unknown"
	}

	if p.Addr == nil {
		return "unknown"
	}

	// Extract IP from address (may be "ip:port" format)
	addr := p.Addr.String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// If splitting fails, return the whole address
		return addr
	}
	return host
}

// AllowConn checks if a request from the given network connection should be allowed.
// This is useful for TCP-based protocols like MCP.
func (l *Limiter) AllowConn(conn net.Conn) bool {
	if !l.enabled {
		return true
	}

	clientIP := getClientIPFromConn(conn)
	return l.Allow(clientIP)
}

// getClientIPFromConn extracts the client IP from a net.Conn.
func getClientIPFromConn(conn net.Conn) string {
	if conn == nil {
		return "unknown"
	}

	addr := conn.RemoteAddr()
	if addr == nil {
		return "unknown"
	}

	// Extract IP from address (may be "ip:port" format)
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// IsEnabled returns whether rate limiting is enabled.
func (l *Limiter) IsEnabled() bool {
	return l.enabled
}
