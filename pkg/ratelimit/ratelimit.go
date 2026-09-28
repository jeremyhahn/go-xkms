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
	"net"
	"net/http"
	"strconv"
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

	// maxClients caps the number of tracked clients (see Config.MaxClients).
	maxClients int
}

// DefaultMaxClients is the number of distinct clients a Limiter tracks when
// Config.MaxClients is zero.
const DefaultMaxClients = 100_000

// CapacityError reports that a Limiter already tracks its maximum number of
// clients and so refused to start tracking another.
type CapacityError struct {
	// Limit is the configured client cap.
	Limit int
}

// Error describes the exhausted capacity.
func (e *CapacityError) Error() string {
	return "ratelimit: client table is full (" + strconv.Itoa(e.Limit) + " clients)"
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

	// MaxClients caps how many distinct clients are tracked at once, so a
	// flood of new client identities cannot grow memory without bound.
	// While the table is full a request from an untracked client is refused
	// (fail closed) until idle clients are cleaned up; clients already
	// tracked are unaffected. Defaults to DefaultMaxClients.
	MaxClients int
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

	maxClients := config.MaxClients
	if maxClients <= 0 {
		maxClients = DefaultMaxClients
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
		maxClients:      maxClients,
	}

	if config.Enabled {
		go l.cleanupWorker()
	}

	return l
}

// getLimiter returns the rate limiter for a given client identifier,
// creating one if it doesn't exist. It fails with *CapacityError when the
// client is new and the table already holds maxClients entries.
func (l *Limiter) getLimiter(clientID string) (*rate.Limiter, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, exists := l.limiters[clientID]
	if !exists {
		if len(l.limiters) >= l.maxClients {
			return nil, &CapacityError{Limit: l.maxClients}
		}
		limiter = rate.NewLimiter(l.rate, l.burst)
		l.limiters[clientID] = limiter
	}

	l.lastSeen[clientID] = time.Now()
	return limiter, nil
}

// Allow checks if a request from the given client should be allowed.
// Returns true if the request is within rate limits. A new client is refused
// while the client table is full.
func (l *Limiter) Allow(clientID string) bool {
	if !l.enabled {
		return true
	}

	limiter, err := l.getLimiter(clientID)
	if err != nil {
		return false
	}
	return limiter.Allow()
}

// Wait blocks until the rate limit allows the request.
// Returns nil on success, *CapacityError when the client is new and the
// client table is full, or an error if the context is cancelled.
func (l *Limiter) Wait(ctx context.Context, clientID string) error {
	if !l.enabled {
		return nil
	}

	limiter, err := l.getLimiter(clientID)
	if err != nil {
		return err
	}
	return limiter.Wait(ctx)
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
		"max_clients":    l.maxClients,
	}
}

// Middleware returns an HTTP middleware that enforces rate limiting, keyed by
// the client IP address that proxies resolves for each request (see
// TrustedProxies.ClientIP). A nil proxies trusts no forwarding header, so the
// key is the transport peer's IP address without its port.
func Middleware(limiter *Limiter, proxies *TrustedProxies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow(proxies.ClientIP(r)) {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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

	return remoteHost(p.Addr.String())
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

	return remoteHost(addr.String())
}

// IsEnabled returns whether rate limiting is enabled.
func (l *Limiter) IsEnabled() bool {
	return l.enabled
}
