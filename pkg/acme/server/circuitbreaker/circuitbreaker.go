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
	//
	// DELIVERY IS UNORDERED. The callback runs after cb.mu is released (it is
	// user code and must not run under the state lock -- see
	// transitionToLocked), so two transitions committed in one order can be
	// delivered in the other: A commits closed->open and is descheduled before
	// its callback; B commits open->closed and delivers first; A then delivers
	// closed->open while State() already reads closed.
	//
	// So each invocation is a true report of one committed transition, and the
	// SEQUENCE of invocations is not a state history. Do not reconstruct the
	// breaker's state from it, and do not assume the last callback's `to`
	// matches State(). Read State() for the current state; use the callback
	// for logging, metrics and alerts, which are the uses it has.
	//
	// Ordering it would mean a queue drained by a dispatcher outside the lock
	// -- machinery this package has no caller to justify: nothing in go-xkms
	// imports pkg/acme/server/circuitbreaker outside its own tests. Owner
	// ruling 2026-08-23 on #98: document the property, do not build the
	// dispatcher. A future importer that needs ordered delivery is the event
	// that changes that, and it should reopen #98 rather than assume order.
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

	// generation increments on every state change. An admission carries the
	// generation it was granted in, so a completion that outlived its
	// generation can be recognised and ignored: its evidence is about a
	// window that has already closed, and its half-open slot belongs to a
	// counter transitionTo has since reset.
	generation atomic.Uint64

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
	// Check if we should allow the request. The admission records what was
	// granted, so afterRequest can settle exactly what this call took rather
	// than guessing from whatever state the breaker is in by then.
	adm, err := cb.beforeRequest()
	if err != nil {
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

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-resultCh:
	}

	// Record the result
	cb.afterRequest(adm, err)

	return err
}

// Admission is what Allow granted a single call. Complete must be called
// exactly once with the call's outcome to settle it.
//
// Allow/Complete exist alongside Execute/ExecuteContext for callers whose
// operation must not be run inside Execute's goroutine: Execute abandons that
// goroutine on context timeout without waiting for it, which is fine for an
// idempotent network call but wrong for an HTTP handler writing directly to
// a ResponseWriter (the goroutine can still be writing after the timed-out
// caller returns and the connection is reused or closed) or for a write
// whose caller must not believe it failed while it is still committing.
// Allow admits the call and returns immediately; the caller performs the
// operation synchronously, under its own context and timeout, and reports
// the outcome with Complete. No goroutine, no breaker-imposed timeout.
type Admission struct {
	adm admission
}

// Allow reports whether a call may proceed under cb's current state,
// admitting it if so. The zero Admission is not valid; only the Admission
// Allow returns may be passed to Complete.
func (cb *CircuitBreaker) Allow() (Admission, error) {
	adm, err := cb.beforeRequest()
	return Admission{adm: adm}, err
}

// Complete settles the call admitted by a. err is the outcome of the call:
// nil for success, non-nil for failure. Complete must be called exactly once
// per Admission.
func (cb *CircuitBreaker) Complete(a Admission, err error) {
	cb.afterRequest(a.adm, err)
}

// admission is what beforeRequest granted a single call. afterRequest settles
// against it rather than re-reading the breaker's state, because the two run
// either side of the caller's function and the state can move in between.
type admission struct {
	// state is the state the call was admitted under. Its result is evidence
	// about that state, not about whichever state the breaker reached while
	// the call was in flight.
	state State

	// generation is the transition generation the call was admitted in.
	// State alone is not enough: the breaker can leave half-open and return
	// to it while a probe is still running, and that later half-open is a
	// different window with its own slots and its own counters.
	generation uint64

	// heldHalfOpenSlot is true when beforeRequest incremented
	// halfOpenRequests for this call, so exactly this call must decrement it
	// -- and only while its generation is still current.
	heldHalfOpenSlot bool
}

// beforeRequest checks if a request should be allowed and updates state
// accordingly, returning what it admitted the call under.
//
// The state and the generation are read TOGETHER, under cb.mu. Reading them
// independently is not merely imprecise, it produces incoherent admissions:
// observe StateClosed, let a Closed->Open->HalfOpen sequence run, then read the
// generation, and the call is tagged {state: closed, generation: half-open}.
// That pair passes the staleness check at completion and is then settled with
// CLOSED semantics inside a half-open window -- so a probe failure increments
// the closed failure counter instead of reopening the circuit, and with
// MaxFailures > 1 the breaker stays half-open after recovery demonstrably
// failed. Fail-open, from two atomic loads that were individually correct.
//
// The lock is the cost of that coherence. It is worth it here: admission is
// not the hot path a circuit breaker exists to protect, and an incoherent
// admission is unrecoverable once granted.
func (cb *CircuitBreaker) beforeRequest() (admission, error) {
	for {
		cb.mu.Lock()

		currentState := State(cb.state.Load())
		gen := cb.generation.Load()

		switch currentState {
		case StateClosed:
			// Always allow requests in closed state
			cb.mu.Unlock()
			return admission{state: StateClosed, generation: gen}, nil

		case StateOpen:
			// Check if we should transition to half-open
			lastFailure := time.Unix(0, cb.lastFailureTime.Load())
			if time.Since(lastFailure) >= cb.resetTimeout {
				notify := cb.transitionToLocked(StateHalfOpen)
				cb.mu.Unlock()
				if notify != nil {
					notify()
				}
				continue // Decide again in the new state
			}
			cb.mu.Unlock()
			return admission{}, ErrCircuitOpen

		case StateHalfOpen:
			// Limit requests in half-open state. Taking the slot happens under
			// the same lock that read the generation, so the slot and the
			// generation it belongs to cannot disagree.
			current := cb.halfOpenRequests.Add(1)
			if current > cb.halfOpenMaxRequests {
				cb.halfOpenRequests.Add(^uint32(0)) // Decrement
				cb.mu.Unlock()
				return admission{}, ErrTooManyRequests
			}
			cb.mu.Unlock()
			return admission{state: StateHalfOpen, generation: gen, heldHalfOpenSlot: true}, nil

		default:
			cb.mu.Unlock()
			return admission{state: currentState, generation: gen}, nil
		}
	}
}

// afterRequest records the result of a request and updates state accordingly.
//
// It settles against the admission rather than re-reading the breaker, because
// the two run either side of the caller's function and the breaker can move in
// between. Two things follow from that, and both used to be wrong.
//
// The half-open slot is released only by a call that took one, and only while
// that slot still exists. It used to be released inside
// recordSuccess/recordFailure keyed on the CURRENT state, so a call admitted
// while closed and finishing after the breaker reached half-open decremented a
// counter it never incremented -- and halfOpenRequests is an atomic.Uint32, so
// at zero it wrapped to 4294967295 and the half-open limit admitted everything
// until the next transition. Generation matters as much as ownership here:
// transitionTo resets the counter, so a probe from an earlier half-open window
// would otherwise release a slot belonging to a later one.
//
// The result is recorded against the state that admitted it, and only if that
// state is still the current generation. Attribution alone is not enough and
// is actively dangerous without the generation check: with two probes in
// flight, one failing and reopening the breaker, the other's late success
// would transition an open breaker straight back to closed on its admitted
// half-open state -- closing the circuit moments after recovery demonstrably
// failed, and skipping resetTimeout entirely. A completion that outlived its
// generation is evidence about a window that has closed, so it updates the
// metrics and changes nothing else.
func (cb *CircuitBreaker) afterRequest(adm admission, err error) {
	// The call happened, so it counts in the metrics whether or not its
	// generation is still current.
	if err != nil {
		metrics.RecordCircuitBreakerFailure(cb.name)
	} else {
		metrics.RecordCircuitBreakerSuccess(cb.name)
	}

	cb.mu.Lock()
	var notify func()
	if adm.generation == cb.generation.Load() {
		if adm.heldHalfOpenSlot {
			cb.halfOpenRequests.Add(^uint32(0)) // Decrement
		}

		if err != nil {
			notify = cb.recordFailureLocked(adm.state)
		} else {
			notify = cb.recordSuccessLocked(adm.state)
		}
	}
	cb.mu.Unlock()

	// Outside the lock: OnStateChange is user code and may call back into the
	// breaker.
	if notify != nil {
		notify()
	}
}

// recordFailureLocked records a failed request and potentially opens the
// circuit. cb.mu must be held.
//
// admittedState is the state the call was admitted under, not the current one.
// The half-open slot is released by afterRequest, which owns the pairing.
func (cb *CircuitBreaker) recordFailureLocked(admittedState State) (notify func()) {
	cb.lastFailureTime.Store(time.Now().UnixNano())

	switch admittedState {
	case StateClosed:
		failures := cb.failureCount.Add(1)
		cb.successCount.Store(0)

		if failures >= cb.maxFailures {
			return cb.transitionToLocked(StateOpen)
		}

	case StateHalfOpen:
		// A probe failed: the dependency has not recovered.
		return cb.transitionToLocked(StateOpen)
	}
	return nil
}

// recordSuccessLocked records a successful request and potentially closes the
// circuit. cb.mu must be held.
//
// admittedState is the state the call was admitted under, not the current one.
func (cb *CircuitBreaker) recordSuccessLocked(admittedState State) (notify func()) {
	switch admittedState {
	case StateClosed:
		cb.failureCount.Store(0)
		cb.successCount.Add(1)

	case StateHalfOpen:
		successes := cb.successCount.Add(1)

		if successes >= cb.successThreshold {
			return cb.transitionToLocked(StateClosed)
		}
	}
	return nil
}

// transitionTo transitions the circuit breaker to a new state.
func (cb *CircuitBreaker) transitionTo(newState State) {
	cb.mu.Lock()
	notify := cb.transitionToLocked(newState)
	cb.mu.Unlock()

	if notify != nil {
		notify()
	}
}

// transitionToLocked is transitionTo with cb.mu already held. It returns the
// state-change notification to run AFTER the lock is released, or nil.
func (cb *CircuitBreaker) transitionToLocked(newState State) (notify func()) {
	currentState := State(cb.state.Load())
	if currentState == newState {
		return nil
	}

	// A new generation begins. Every admission granted in the old one is now
	// stale: its half-open slot no longer exists (the counter is reset just
	// below) and its result is evidence about a window that has closed.
	cb.generation.Add(1)

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

	// The callback is NOT invoked here. It is user code, and it runs while
	// cb.mu is held -- so a callback that calls back into the breaker (Execute,
	// Trip, Reset) blocks on a mutex this transition cannot release until the
	// callback returns. sync.Mutex is not reentrant, so that is a deadlock, not
	// a slow path.
	//
	// It became reachable from Execute when admission started taking cb.mu:
	// before that, a closed-state Execute never touched this lock. Returning
	// the invocation lets every caller run it after unlocking.
	//
	// The cost of returning it is that delivery is UNORDERED under concurrent
	// transitions -- the transition is committed here, the callback runs after
	// the caller unlocks, and nothing sequences those two windows across
	// goroutines. That is the documented contract of Config.OnStateChange,
	// which explains what an observer may and may not conclude from it.
	if cb.onStateChange != nil {
		onStateChange, name := cb.onStateChange, cb.name
		return func() { onStateChange(name, currentState, newState) }
	}
	return nil
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
