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

package client

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/acme"
)

// Challenge solver errors
var (
	ErrNoSolverRegistered     = errors.New("acme-client: no solver registered for challenge type")
	ErrNoChallengeSupported   = errors.New("acme-client: no supported challenge type found in authorization")
	ErrNilAuthorization       = errors.New("acme-client: nil authorization provided")
	ErrNilChallenge           = errors.New("acme-client: nil challenge provided")
	ErrEmptyDomain            = errors.New("acme-client: empty domain provided")
	ErrEmptyKeyAuth           = errors.New("acme-client: empty key authorization provided")
	ErrSolverAlreadyExists    = errors.New("acme-client: solver already registered for this type")
	ErrResolverClosed         = errors.New("acme-client: resolver has been closed")
	ErrInvalidChallengeStatus = errors.New("acme-client: challenge has invalid status")
)

// ChallengeSolver defines the interface for solving ACME challenges.
// Implementations are responsible for presenting proof of domain control
// and cleaning up after challenge completion.
type ChallengeSolver interface {
	// Type returns the challenge type this solver handles (e.g., "http-01", "dns-01").
	Type() string

	// Solve presents the challenge response for the given domain.
	// The keyAuth parameter is the key authorization string (token.thumbprint).
	// This method should present the challenge response and return once ready
	// for validation (e.g., DNS record is propagated).
	Solve(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error

	// Cleanup removes any resources created during Solve.
	// This should be called after challenge verification completes,
	// regardless of success or failure.
	Cleanup(ctx context.Context, domain string, challenge *acme.Challenge) error
}

// ChallengeResolver manages challenge solvers and coordinates challenge resolution.
// It maintains a registry of solvers by challenge type and selects the best
// available solver based on configured preferences.
type ChallengeResolver struct {
	solvers     map[string]ChallengeSolver
	preferences []string
	mu          sync.RWMutex
	closed      atomic.Bool
}

// NewChallengeResolver creates a new ChallengeResolver with default preferences.
// The default preference order is: dns-01, http-01, tls-alpn-01.
// This order prefers dns-01 as it supports wildcard certificates and doesn't
// require exposing any ports.
func NewChallengeResolver() *ChallengeResolver {
	return &ChallengeResolver{
		solvers: make(map[string]ChallengeSolver),
		preferences: []string{
			string(ChallengeTypeDNS01),
			string(ChallengeTypeHTTP01),
			string(ChallengeTypeTLSALPN01),
		},
	}
}

// RegisterSolver adds a solver for a specific challenge type.
// If a solver for the same type is already registered, it will be replaced.
func (r *ChallengeResolver) RegisterSolver(solver ChallengeSolver) error {
	if solver == nil {
		return ErrNilChallenge
	}

	if r.closed.Load() {
		return ErrResolverClosed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.solvers[solver.Type()] = solver
	return nil
}

// RegisterSolverStrict adds a solver for a specific challenge type.
// Returns an error if a solver for the same type is already registered.
func (r *ChallengeResolver) RegisterSolverStrict(solver ChallengeSolver) error {
	if solver == nil {
		return ErrNilChallenge
	}

	if r.closed.Load() {
		return ErrResolverClosed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.solvers[solver.Type()]; exists {
		return ErrSolverAlreadyExists
	}

	r.solvers[solver.Type()] = solver
	return nil
}

// UnregisterSolver removes a solver for a specific challenge type.
// Returns true if a solver was removed, false if no solver was registered.
func (r *ChallengeResolver) UnregisterSolver(challengeType string) bool {
	if r.closed.Load() {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.solvers[challengeType]; exists {
		delete(r.solvers, challengeType)
		return true
	}
	return false
}

// SetPreferences sets the ordered preference for challenge types.
// When multiple challenge types are available, the resolver will select
// the first type in this list that has a registered solver.
func (r *ChallengeResolver) SetPreferences(types ...string) {
	if r.closed.Load() {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.preferences = make([]string, len(types))
	copy(r.preferences, types)
}

// GetPreferences returns the current challenge type preferences.
func (r *ChallengeResolver) GetPreferences() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]string, len(r.preferences))
	copy(result, r.preferences)
	return result
}

// GetSolver returns the solver for a specific challenge type.
// Returns nil and false if no solver is registered for the type.
func (r *ChallengeResolver) GetSolver(challengeType string) (ChallengeSolver, bool) {
	if r.closed.Load() {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	solver, exists := r.solvers[challengeType]
	return solver, exists
}

// HasSolver returns true if a solver is registered for the given challenge type.
func (r *ChallengeResolver) HasSolver(challengeType string) bool {
	_, exists := r.GetSolver(challengeType)
	return exists
}

// ListSolvers returns the types of all registered solvers.
func (r *ChallengeResolver) ListSolvers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.solvers))
	for t := range r.solvers {
		types = append(types, t)
	}
	return types
}

// SolverCount returns the number of registered solvers.
func (r *ChallengeResolver) SolverCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.solvers)
}

// SelectChallenge selects the best challenge from the authorization based on
// registered solvers and preferences. Returns the selected challenge and its
// solver, or an error if no suitable challenge is found.
func (r *ChallengeResolver) SelectChallenge(authz *acme.Authorization) (*acme.Challenge, ChallengeSolver, error) {
	if authz == nil {
		return nil, nil, ErrNilAuthorization
	}

	if r.closed.Load() {
		return nil, nil, ErrResolverClosed
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Build a map of available challenges by type
	challenges := make(map[string]*acme.Challenge)
	for _, c := range authz.Challenges {
		if c != nil && c.Status != acme.StatusInvalid {
			challenges[c.Type] = c
		}
	}

	// Select based on preferences
	for _, preferredType := range r.preferences {
		if challenge, available := challenges[preferredType]; available {
			if solver, registered := r.solvers[preferredType]; registered {
				return challenge, solver, nil
			}
		}
	}

	// Fall back to any registered solver
	for challengeType, challenge := range challenges {
		if solver, registered := r.solvers[challengeType]; registered {
			return challenge, solver, nil
		}
	}

	return nil, nil, ErrNoChallengeSupported
}

// Solve finds and executes the best available solver for the authorization.
// It selects a challenge based on preferences, solves it, and returns the
// selected challenge for further processing (e.g., accepting with ACME server).
func (r *ChallengeResolver) Solve(ctx context.Context, authz *acme.Authorization, keyAuth string) (*acme.Challenge, error) {
	if authz == nil {
		return nil, ErrNilAuthorization
	}

	if keyAuth == "" {
		return nil, ErrEmptyKeyAuth
	}

	if r.closed.Load() {
		return nil, ErrResolverClosed
	}

	// Extract domain from authorization
	domain := authz.Identifier.Value
	if domain == "" {
		return nil, ErrEmptyDomain
	}

	// Select the best challenge and solver
	challenge, solver, err := r.SelectChallenge(authz)
	if err != nil {
		return nil, err
	}

	// Solve the challenge
	if err := solver.Solve(ctx, domain, challenge, keyAuth); err != nil {
		return nil, err
	}

	return challenge, nil
}

// SolveWithCleanup solves the challenge and ensures cleanup is called after
// the provided function completes. This is useful for wrapping the entire
// challenge acceptance workflow.
func (r *ChallengeResolver) SolveWithCleanup(
	ctx context.Context,
	authz *acme.Authorization,
	keyAuth string,
	afterSolve func(ctx context.Context, challenge *acme.Challenge) error,
) error {
	challenge, err := r.Solve(ctx, authz, keyAuth)
	if err != nil {
		return err
	}

	// Get the solver for cleanup
	solver, exists := r.GetSolver(challenge.Type)
	if !exists {
		return ErrNoSolverRegistered
	}

	// Ensure cleanup is called
	domain := authz.Identifier.Value
	defer func() {
		// Use a fresh context for cleanup since the original might be cancelled
		cleanupCtx := context.Background()
		_ = solver.Cleanup(cleanupCtx, domain, challenge)
	}()

	// Execute the after-solve function (typically accepting the challenge)
	if afterSolve != nil {
		return afterSolve(ctx, challenge)
	}

	return nil
}

// Cleanup performs cleanup for a specific challenge.
// This should be called after challenge verification completes.
func (r *ChallengeResolver) Cleanup(ctx context.Context, domain string, challenge *acme.Challenge) error {
	if challenge == nil {
		return ErrNilChallenge
	}

	if domain == "" {
		return ErrEmptyDomain
	}

	solver, exists := r.GetSolver(challenge.Type)
	if !exists {
		return ErrNoSolverRegistered
	}

	return solver.Cleanup(ctx, domain, challenge)
}

// Close marks the resolver as closed and prevents further operations.
// Existing solvers are cleared to allow garbage collection.
func (r *ChallengeResolver) Close() error {
	if r.closed.Swap(true) {
		return nil // Already closed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Clear solvers to allow GC
	r.solvers = make(map[string]ChallengeSolver)
	r.preferences = nil

	return nil
}

// IsClosed returns true if the resolver has been closed.
func (r *ChallengeResolver) IsClosed() bool {
	return r.closed.Load()
}
