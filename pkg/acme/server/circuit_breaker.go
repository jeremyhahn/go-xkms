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
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitState represents the current state of a circuit breaker.
type CircuitState uint32

const (
	// CircuitStateClosed indicates the circuit is closed and requests flow normally.
	CircuitStateClosed CircuitState = iota

	// CircuitStateOpen indicates the circuit is open and requests are rejected.
	CircuitStateOpen

	// CircuitStateHalfOpen indicates the circuit is testing if the backend has recovered.
	CircuitStateHalfOpen
)

// String returns a human-readable representation of the circuit state.
func (s CircuitState) String() string {
	switch s {
	case CircuitStateClosed:
		return "closed"
	case CircuitStateOpen:
		return "open"
	case CircuitStateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig holds configuration for a circuit breaker.
type CircuitBreakerConfig struct {
	// Name identifies this circuit breaker (for logging/metrics).
	Name string

	// FailureThreshold is the number of consecutive failures before opening the circuit.
	// Default is 5 if not set.
	FailureThreshold uint32

	// SuccessThreshold is the number of consecutive successes in half-open state
	// required to close the circuit. Default is 2 if not set.
	SuccessThreshold uint32

	// Timeout is how long the circuit stays open before transitioning to half-open.
	// Default is 30 seconds if not set.
	Timeout time.Duration

	// MaxHalfOpenRequests is the maximum number of requests allowed in half-open state.
	// Default is 1 if not set.
	MaxHalfOpenRequests uint32

	// OnStateChange is called when the circuit state changes.
	// Can be used for logging or metrics.
	OnStateChange func(name string, from, to CircuitState)
}

// DefaultCircuitBreakerConfig returns sensible default configuration.
func DefaultCircuitBreakerConfig(name string) *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		Name:                name,
		FailureThreshold:    5,
		SuccessThreshold:    2,
		Timeout:             30 * time.Second,
		MaxHalfOpenRequests: 1,
	}
}

// CircuitBreakerMetrics holds metrics for a circuit breaker.
// Uses atomic operations for lock-free access.
type CircuitBreakerMetrics struct {
	// TotalRequests is the total number of requests through this breaker.
	TotalRequests atomic.Uint64

	// SuccessfulRequests is the number of successful requests.
	SuccessfulRequests atomic.Uint64

	// FailedRequests is the number of failed requests.
	FailedRequests atomic.Uint64

	// RejectedRequests is the number of requests rejected due to open circuit.
	RejectedRequests atomic.Uint64

	// StateChanges is the number of state changes.
	StateChanges atomic.Uint64

	// LastStateChange is the timestamp of the last state change.
	LastStateChange atomic.Int64

	// CurrentState holds the current state (for metrics queries).
	CurrentState atomic.Uint32
}

// CircuitBreaker implements the circuit breaker pattern for backend services.
// It prevents cascading failures by failing fast when backends are unhealthy.
// Thread-safe with lock-free state management using atomic operations.
type CircuitBreaker struct {
	config  *CircuitBreakerConfig
	state   atomic.Uint32
	metrics *CircuitBreakerMetrics

	// Failure/success counters
	consecutiveFailures  atomic.Uint32
	consecutiveSuccesses atomic.Uint32

	// Timing
	lastFailureTime    atomic.Int64
	lastStateChange    atomic.Int64
	halfOpenInProgress atomic.Uint32
}

// Typed errors for circuit breaker
var (
	// ErrCircuitOpen is returned when the circuit is open.
	ErrCircuitOpen = errors.New("circuit breaker: circuit is open")

	// ErrCircuitHalfOpenMaxRequests is returned when max half-open requests are exceeded.
	ErrCircuitHalfOpenMaxRequests = errors.New("circuit breaker: max half-open requests exceeded")
)

// NewCircuitBreaker creates a new circuit breaker with the given configuration.
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig("default")
	}

	// Apply defaults
	if config.FailureThreshold == 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold == 0 {
		config.SuccessThreshold = 2
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxHalfOpenRequests == 0 {
		config.MaxHalfOpenRequests = 1
	}

	cb := &CircuitBreaker{
		config:  config,
		metrics: &CircuitBreakerMetrics{},
	}

	cb.state.Store(uint32(CircuitStateClosed))
	cb.metrics.CurrentState.Store(uint32(CircuitStateClosed))
	cb.lastStateChange.Store(time.Now().UnixNano())
	cb.metrics.LastStateChange.Store(time.Now().Unix())

	return cb
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() CircuitState {
	return CircuitState(cb.state.Load())
}

// Name returns the name of this circuit breaker.
func (cb *CircuitBreaker) Name() string {
	return cb.config.Name
}

// Metrics returns the current metrics for this circuit breaker.
func (cb *CircuitBreaker) Metrics() *CircuitBreakerMetrics {
	return cb.metrics
}

// Allow checks if a request should be allowed through the circuit breaker.
// Returns nil if allowed, or an error if the circuit is open.
func (cb *CircuitBreaker) Allow() error {
	cb.metrics.TotalRequests.Add(1)

	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitStateClosed:
		return nil

	case CircuitStateOpen:
		// Check if timeout has elapsed
		lastChange := cb.lastStateChange.Load()
		elapsed := time.Duration(time.Now().UnixNano() - lastChange)

		if elapsed >= cb.config.Timeout {
			// Transition to half-open
			if cb.transitionState(CircuitStateOpen, CircuitStateHalfOpen) {
				// Allow this request as the first half-open probe
				cb.halfOpenInProgress.Store(1)
				return nil
			}
		}

		cb.metrics.RejectedRequests.Add(1)
		return ErrCircuitOpen

	case CircuitStateHalfOpen:
		// Check if we can allow more half-open requests
		current := cb.halfOpenInProgress.Add(1)
		if current > cb.config.MaxHalfOpenRequests {
			cb.halfOpenInProgress.Add(^uint32(0)) // Decrement
			cb.metrics.RejectedRequests.Add(1)
			return ErrCircuitHalfOpenMaxRequests
		}
		return nil
	}

	return nil
}

// Success records a successful request.
// Should be called after a successful operation.
func (cb *CircuitBreaker) Success() {
	cb.metrics.SuccessfulRequests.Add(1)

	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitStateClosed:
		// Reset consecutive failures on success
		cb.consecutiveFailures.Store(0)

	case CircuitStateHalfOpen:
		cb.halfOpenInProgress.Add(^uint32(0)) // Decrement

		// Count consecutive successes in half-open state
		successes := cb.consecutiveSuccesses.Add(1)

		if successes >= cb.config.SuccessThreshold {
			// Backend has recovered, close the circuit
			cb.transitionState(CircuitStateHalfOpen, CircuitStateClosed)
			cb.consecutiveSuccesses.Store(0)
			cb.consecutiveFailures.Store(0)
		}
	}
}

// Failure records a failed request.
// Should be called after a failed operation.
func (cb *CircuitBreaker) Failure() {
	cb.metrics.FailedRequests.Add(1)
	cb.lastFailureTime.Store(time.Now().UnixNano())

	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitStateClosed:
		// Count consecutive failures
		failures := cb.consecutiveFailures.Add(1)

		if failures >= cb.config.FailureThreshold {
			// Too many failures, open the circuit
			cb.transitionState(CircuitStateClosed, CircuitStateOpen)
		}

	case CircuitStateHalfOpen:
		cb.halfOpenInProgress.Add(^uint32(0)) // Decrement

		// Any failure in half-open state opens the circuit again
		cb.transitionState(CircuitStateHalfOpen, CircuitStateOpen)
		cb.consecutiveSuccesses.Store(0)
	}
}

// transitionState attempts to transition from one state to another.
// Returns true if the transition was successful.
func (cb *CircuitBreaker) transitionState(from, to CircuitState) bool {
	if cb.state.CompareAndSwap(uint32(from), uint32(to)) {
		now := time.Now()
		cb.lastStateChange.Store(now.UnixNano())
		cb.metrics.LastStateChange.Store(now.Unix())
		cb.metrics.StateChanges.Add(1)
		cb.metrics.CurrentState.Store(uint32(to))

		if cb.config.OnStateChange != nil {
			cb.config.OnStateChange(cb.config.Name, from, to)
		}

		return true
	}
	return false
}

// Execute runs a function with circuit breaker protection.
// If the circuit is open, returns ErrCircuitOpen without calling the function.
// Records success or failure based on the error returned by the function.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if err := cb.Allow(); err != nil {
		return err
	}

	err := fn()
	if err != nil {
		cb.Failure()
		return err
	}

	cb.Success()
	return nil
}

// ExecuteWithContext runs a function with circuit breaker protection and context.
// Similar to Execute but allows passing a context for cancellation.
func (cb *CircuitBreaker) ExecuteWithContext(ctx context.Context, fn func(context.Context) error) error {
	if err := cb.Allow(); err != nil {
		return err
	}

	// Check context before executing
	select {
	case <-ctx.Done():
		cb.Failure()
		return ctx.Err()
	default:
	}

	err := fn(ctx)
	if err != nil {
		cb.Failure()
		return err
	}

	cb.Success()
	return nil
}

// Reset resets the circuit breaker to closed state.
// This is useful for testing or manual recovery.
func (cb *CircuitBreaker) Reset() {
	oldState := CircuitState(cb.state.Swap(uint32(CircuitStateClosed)))
	cb.consecutiveFailures.Store(0)
	cb.consecutiveSuccesses.Store(0)
	cb.halfOpenInProgress.Store(0)

	now := time.Now()
	cb.lastStateChange.Store(now.UnixNano())
	cb.metrics.LastStateChange.Store(now.Unix())
	cb.metrics.CurrentState.Store(uint32(CircuitStateClosed))

	if oldState != CircuitStateClosed && cb.config.OnStateChange != nil {
		cb.config.OnStateChange(cb.config.Name, oldState, CircuitStateClosed)
	}
}

// ForceOpen forces the circuit breaker to open state.
// This is useful for manual intervention or testing.
func (cb *CircuitBreaker) ForceOpen() {
	oldState := CircuitState(cb.state.Swap(uint32(CircuitStateOpen)))
	cb.consecutiveSuccesses.Store(0)

	now := time.Now()
	cb.lastStateChange.Store(now.UnixNano())
	cb.metrics.LastStateChange.Store(now.Unix())
	cb.metrics.CurrentState.Store(uint32(CircuitStateOpen))

	if oldState != CircuitStateOpen && cb.config.OnStateChange != nil {
		cb.config.OnStateChange(cb.config.Name, oldState, CircuitStateOpen)
	}
}

// CircuitBreakerRegistry manages multiple circuit breakers.
// Thread-safe with RWMutex for concurrent access.
type CircuitBreakerRegistry struct {
	breakers map[string]*CircuitBreaker
	mu       sync.RWMutex
}

// NewCircuitBreakerRegistry creates a new circuit breaker registry.
func NewCircuitBreakerRegistry() *CircuitBreakerRegistry {
	return &CircuitBreakerRegistry{
		breakers: make(map[string]*CircuitBreaker),
	}
}

// Register adds a circuit breaker to the registry.
func (r *CircuitBreakerRegistry) Register(cb *CircuitBreaker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.breakers[cb.Name()] = cb
}

// Get retrieves a circuit breaker by name.
func (r *CircuitBreakerRegistry) Get(name string) *CircuitBreaker {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.breakers[name]
}

// GetOrCreate retrieves a circuit breaker by name, creating it with default config if it doesn't exist.
func (r *CircuitBreakerRegistry) GetOrCreate(name string) *CircuitBreaker {
	// Try read lock first
	r.mu.RLock()
	if cb, ok := r.breakers[name]; ok {
		r.mu.RUnlock()
		return cb
	}
	r.mu.RUnlock()

	// Need to create - acquire write lock
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock
	if cb, ok := r.breakers[name]; ok {
		return cb
	}

	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig(name))
	r.breakers[name] = cb
	return cb
}

// List returns all registered circuit breakers.
func (r *CircuitBreakerRegistry) List() []*CircuitBreaker {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*CircuitBreaker, 0, len(r.breakers))
	for _, cb := range r.breakers {
		result = append(result, cb)
	}
	return result
}

// ResetAll resets all circuit breakers to closed state.
func (r *CircuitBreakerRegistry) ResetAll() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, cb := range r.breakers {
		cb.Reset()
	}
}

// CircuitBreakerMiddleware creates an HTTP middleware that wraps requests with circuit breaker protection.
// If the circuit is open, returns HTTP 503 Service Unavailable.
func CircuitBreakerMiddleware(cb *CircuitBreaker) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := cb.Allow(); err != nil {
				writeCircuitBreakerError(w, cb)
				return
			}

			// Wrap response writer to detect failures
			wrapped := &circuitBreakerResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(wrapped, r)

			// Record success or failure based on status code
			if wrapped.statusCode >= 500 {
				cb.Failure()
			} else {
				cb.Success()
			}
		})
	}
}

// circuitBreakerResponseWriter wraps http.ResponseWriter to capture the status code.
type circuitBreakerResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code.
func (w *circuitBreakerResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// writeCircuitBreakerError writes an HTTP 503 error response when the circuit is open.
func writeCircuitBreakerError(w http.ResponseWriter, cb *CircuitBreaker) {
	// Calculate retry-after based on remaining timeout
	lastChange := cb.lastStateChange.Load()
	elapsed := time.Duration(time.Now().UnixNano() - lastChange)
	remaining := cb.config.Timeout - elapsed

	if remaining < 0 {
		remaining = time.Second
	}

	retryAfterSeconds := int(remaining.Seconds())
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}

	w.Header().Set("Retry-After", formatInt(retryAfterSeconds))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)

	// Simple JSON response
	response := `{"error":"service_unavailable","message":"Service temporarily unavailable. Circuit breaker is open.","retry_after":` + formatInt(retryAfterSeconds) + `}`
	_, _ = w.Write([]byte(response))
}
