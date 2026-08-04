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

// Package circuitbreaker implements the circuit breaker pattern for resilient
// external service calls. It prevents cascading failures by failing fast when
// a service is unhealthy, and gradually tests recovery.
package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
)

// State represents the current state of a circuit breaker.
type State int

const (
	// StateClosed indicates normal operation - requests are allowed through.
	StateClosed State = iota
	// StateHalfOpen indicates the circuit is testing if the service has recovered.
	StateHalfOpen
	// StateOpen indicates the circuit is open - requests fail immediately.
	StateOpen
)

// String returns the string representation of a circuit breaker state.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateHalfOpen:
		return "half-open"
	case StateOpen:
		return "open"
	default:
		return "unknown"
	}
}

// Error types for circuit breaker operations.
var (
	// ErrCircuitOpen is returned when the circuit breaker is open and requests
	// should fail immediately.
	ErrCircuitOpen = errors.New("circuit breaker: circuit is open")

	// ErrTooManyRequests is returned in half-open state when too many requests
	// are already being tested.
	ErrTooManyRequests = errors.New("circuit breaker: too many requests in half-open state")
)

// Config contains configuration for a circuit breaker.
type Config struct {
	// Name identifies this circuit breaker for metrics and logging.
	Name string

	// MaxFailures is the number of consecutive failures before the circuit opens.
	// Default: 5
	MaxFailures uint32

	// ResetTimeout is how long the circuit stays open before transitioning to half-open.
	// Default: 30 seconds
	ResetTimeout time.Duration

	// HalfOpenMaxRequests is the maximum number of requests allowed in half-open state.
	// Default: 1
	HalfOpenMaxRequests uint32

	// SuccessThreshold is the number of consecutive successes needed to close the circuit.
	// Default: 2
	SuccessThreshold uint32

	// Timeout is the maximum time allowed for a single operation.
	// Default: 10 seconds
	Timeout time.Duration

	// OnStateChange is called when the circuit breaker state changes.
	OnStateChange func(name string, from, to State)
}

// DefaultConfig returns a default circuit breaker configuration.
func DefaultConfig(name string) *Config {
	return &Config{
		Name:                name,
		MaxFailures:         5,
		ResetTimeout:        30 * time.Second,
		HalfOpenMaxRequests: 1,
		SuccessThreshold:    2,
		Timeout:             10 * time.Second,
	}
}

// CircuitBreaker implements the circuit breaker pattern.
type CircuitBreaker struct {
	name                string
	maxFailures         uint32
	resetTimeout        time.Duration
	halfOpenMaxRequests uint32
	successThreshold    uint32
	timeout             time.Duration
	onStateChange       func(name string, from, to State)

	// State tracking using atomic operations for lock-free reads
	state            atomic.Int32
	failureCount     atomic.Uint32
	successCount     atomic.Uint32
	halfOpenRequests atomic.Uint32
	lastFailureTime  atomic.Int64

	// Mutex for state transitions (rare operation)
	mu sync.Mutex
}

// New creates a new circuit breaker with the given configuration.
func New(cfg *Config) *CircuitBreaker {
	if cfg == nil {
		cfg = DefaultConfig("default")
	}

	cb := &CircuitBreaker{
		name:                cfg.Name,
		maxFailures:         cfg.MaxFailures,
		resetTimeout:        cfg.ResetTimeout,
		halfOpenMaxRequests: cfg.HalfOpenMaxRequests,
		successThreshold:    cfg.SuccessThreshold,
		timeout:             cfg.Timeout,
		onStateChange:       cfg.OnStateChange,
	}

	// Initialize in closed state
	cb.state.Store(int32(StateClosed))

	return cb
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() State {
	return State(cb.state.Load())
}

// Name returns the name of the circuit breaker.
func (cb *CircuitBreaker) Name() string {
	return cb.name
}

// Counts returns the current failure and success counts.
func (cb *CircuitBreaker) Counts() (failures, successes uint32) {
	return cb.failureCount.Load(), cb.successCount.Load()
}

// Execute executes the given function with circuit breaker protection.
// If the circuit is open, it returns ErrCircuitOpen immediately.
// If the circuit is half-open and too many requests are in flight, it returns ErrTooManyRequests.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	return cb.ExecuteContext(context.Background(), fn)
}

// ExecuteContext executes the given function with circuit breaker protection and context.
func (cb *CircuitBreaker) ExecuteContext(ctx context.Context, fn func() error) error {
	// Check if we should allow the request
	if err := cb.beforeRequest(); err != nil {
		return err
	}

	// Create a timeout context if configured
	if cb.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cb.timeout)
		defer cancel()
	}

	// Execute the function in a goroutine to handle context cancellation
	resultCh := make(chan error, 1)
	go func() {
		resultCh <- fn()
	}()

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-resultCh:
	}

	// Record the result
	cb.afterRequest(err)

	return err
}

// beforeRequest checks if a request should be allowed and updates state accordingly.
func (cb *CircuitBreaker) beforeRequest() error {
	currentState := cb.State()

	switch currentState {
	case StateClosed:
		// Always allow requests in closed state
		return nil

	case StateOpen:
		// Check if we should transition to half-open
		lastFailure := time.Unix(0, cb.lastFailureTime.Load())
		if time.Since(lastFailure) >= cb.resetTimeout {
			cb.transitionTo(StateHalfOpen)
			return cb.beforeRequest() // Re-check in new state
		}
		return ErrCircuitOpen

	case StateHalfOpen:
		// Limit requests in half-open state
		current := cb.halfOpenRequests.Add(1)
		if current > cb.halfOpenMaxRequests {
			cb.halfOpenRequests.Add(^uint32(0)) // Decrement
			return ErrTooManyRequests
		}
		return nil

	default:
		return nil
	}
}

// afterRequest records the result of a request and updates state accordingly.
func (cb *CircuitBreaker) afterRequest(err error) {
	currentState := cb.State()

	if err != nil {
		cb.recordFailure(currentState)
	} else {
		cb.recordSuccess(currentState)
	}
}

// recordFailure records a failed request and potentially opens the circuit.
func (cb *CircuitBreaker) recordFailure(currentState State) {
	metrics.RecordCircuitBreakerFailure(cb.name)
	cb.lastFailureTime.Store(time.Now().UnixNano())

	switch currentState {
	case StateClosed:
		failures := cb.failureCount.Add(1)
		cb.successCount.Store(0)

		if failures >= cb.maxFailures {
			cb.transitionTo(StateOpen)
		}

	case StateHalfOpen:
		cb.halfOpenRequests.Add(^uint32(0)) // Decrement
		cb.transitionTo(StateOpen)
	}
}

// recordSuccess records a successful request and potentially closes the circuit.
func (cb *CircuitBreaker) recordSuccess(currentState State) {
	metrics.RecordCircuitBreakerSuccess(cb.name)

	switch currentState {
	case StateClosed:
		cb.failureCount.Store(0)
		cb.successCount.Add(1)

	case StateHalfOpen:
		cb.halfOpenRequests.Add(^uint32(0)) // Decrement
		successes := cb.successCount.Add(1)

		if successes >= cb.successThreshold {
			cb.transitionTo(StateClosed)
		}
	}
}

// transitionTo transitions the circuit breaker to a new state.
func (cb *CircuitBreaker) transitionTo(newState State) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	currentState := State(cb.state.Load())
	if currentState == newState {
		return
	}

	// Reset counters on state change
	cb.failureCount.Store(0)
	cb.successCount.Store(0)
	cb.halfOpenRequests.Store(0)

	// Update state
	cb.state.Store(int32(newState))

	// Update metrics
	metrics.SetCircuitBreakerState(cb.name, metrics.CircuitBreakerState(newState))

	if newState == StateOpen {
		metrics.RecordCircuitBreakerTrip(cb.name)
	}

	// Call state change callback
	if cb.onStateChange != nil {
		cb.onStateChange(cb.name, currentState, newState)
	}
}

// Reset manually resets the circuit breaker to the closed state.
func (cb *CircuitBreaker) Reset() {
	cb.transitionTo(StateClosed)
}

// Trip manually trips the circuit breaker to the open state.
func (cb *CircuitBreaker) Trip() {
	cb.lastFailureTime.Store(time.Now().UnixNano())
	cb.transitionTo(StateOpen)
}

// Manager manages multiple circuit breakers for different services.
type Manager struct {
	breakers sync.Map // map[string]*CircuitBreaker
}

// NewManager creates a new circuit breaker manager.
func NewManager() *Manager {
	return &Manager{}
}

// Get returns the circuit breaker for the given name, creating it if necessary.
func (m *Manager) Get(name string) *CircuitBreaker {
	if cb, ok := m.breakers.Load(name); ok {
		return cb.(*CircuitBreaker)
	}

	// Create a new circuit breaker with default config
	cb := New(DefaultConfig(name))
	actual, _ := m.breakers.LoadOrStore(name, cb)
	return actual.(*CircuitBreaker)
}

// GetOrCreate returns the circuit breaker for the given name, or creates one with the given config.
func (m *Manager) GetOrCreate(cfg *Config) *CircuitBreaker {
	if cb, ok := m.breakers.Load(cfg.Name); ok {
		return cb.(*CircuitBreaker)
	}

	cb := New(cfg)
	actual, _ := m.breakers.LoadOrStore(cfg.Name, cb)
	return actual.(*CircuitBreaker)
}

// Register registers a circuit breaker with the manager.
func (m *Manager) Register(cb *CircuitBreaker) {
	m.breakers.Store(cb.name, cb)
}

// List returns all registered circuit breakers.
func (m *Manager) List() []*CircuitBreaker {
	var result []*CircuitBreaker
	m.breakers.Range(func(key, value any) bool {
		result = append(result, value.(*CircuitBreaker))
		return true
	})
	return result
}

// ResetAll resets all circuit breakers to the closed state.
func (m *Manager) ResetAll() {
	m.breakers.Range(func(key, value any) bool {
		value.(*CircuitBreaker).Reset()
		return true
	})
}

// Status returns the status of all circuit breakers.
func (m *Manager) Status() map[string]State {
	status := make(map[string]State)
	m.breakers.Range(func(key, value any) bool {
		cb := value.(*CircuitBreaker)
		status[cb.name] = cb.State()
		return true
	})
	return status
}

// DefaultManager is the default circuit breaker manager.
var DefaultManager = NewManager()

// Execute executes the function with the default manager's circuit breaker.
func Execute(name string, fn func() error) error {
	return DefaultManager.Get(name).Execute(fn)
}

// ExecuteContext executes the function with context using the default manager's circuit breaker.
func ExecuteContext(ctx context.Context, name string, fn func() error) error {
	return DefaultManager.Get(name).ExecuteContext(ctx, fn)
}
