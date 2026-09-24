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
	"testing"

	"golang.org/x/crypto/acme"
)

// mockSolver implements ChallengeSolver for testing
type mockSolver struct {
	challengeType string
	solveFunc     func(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error
	cleanupFunc   func(ctx context.Context, domain string, challenge *acme.Challenge) error
	solveCalled   bool
	cleanupCalled bool
	mu            sync.Mutex
}

func newMockSolver(challengeType string) *mockSolver {
	return &mockSolver{
		challengeType: challengeType,
	}
}

func (m *mockSolver) Type() string {
	return m.challengeType
}

func (m *mockSolver) Solve(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error {
	m.mu.Lock()
	m.solveCalled = true
	m.mu.Unlock()

	if m.solveFunc != nil {
		return m.solveFunc(ctx, domain, challenge, keyAuth)
	}
	return nil
}

func (m *mockSolver) Cleanup(ctx context.Context, domain string, challenge *acme.Challenge) error {
	m.mu.Lock()
	m.cleanupCalled = true
	m.mu.Unlock()

	if m.cleanupFunc != nil {
		return m.cleanupFunc(ctx, domain, challenge)
	}
	return nil
}

func (m *mockSolver) wasSolveCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.solveCalled
}

func (m *mockSolver) wasCleanupCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cleanupCalled
}

func TestResolverNewChallengeResolver(t *testing.T) {
	resolver := NewChallengeResolver()

	if resolver == nil {
		t.Fatal("NewChallengeResolver returned nil")
	}

	if resolver.solvers == nil {
		t.Error("solvers map not initialized")
	}

	if len(resolver.preferences) != 3 {
		t.Errorf("expected 3 default preferences, got %d", len(resolver.preferences))
	}

	expectedPrefs := []string{"dns-01", "http-01", "tls-alpn-01"}
	for i, pref := range expectedPrefs {
		if resolver.preferences[i] != pref {
			t.Errorf("preference[%d]: expected %s, got %s", i, pref, resolver.preferences[i])
		}
	}
}

func TestResolverRegisterSolver(t *testing.T) {
	resolver := NewChallengeResolver()

	t.Run("register valid solver", func(t *testing.T) {
		solver := newMockSolver("dns-01")
		err := resolver.RegisterSolver(solver)
		if err != nil {
			t.Fatalf("RegisterSolver failed: %v", err)
		}

		registeredSolver, exists := resolver.GetSolver("dns-01")
		if !exists {
			t.Error("solver not found after registration")
		}
		if registeredSolver != solver {
			t.Error("registered solver does not match")
		}
	})

	t.Run("register nil solver", func(t *testing.T) {
		err := resolver.RegisterSolver(nil)
		if err == nil {
			t.Error("expected error for nil solver")
		}
		if !errors.Is(err, ErrNilChallenge) {
			t.Errorf("expected ErrNilChallenge, got %v", err)
		}
	})

	t.Run("replace existing solver", func(t *testing.T) {
		solver1 := newMockSolver("http-01")
		solver2 := newMockSolver("http-01")

		_ = resolver.RegisterSolver(solver1)
		_ = resolver.RegisterSolver(solver2)

		registeredSolver, _ := resolver.GetSolver("http-01")
		if registeredSolver != solver2 {
			t.Error("solver was not replaced")
		}
	})
}

func TestResolverRegisterSolverStrict(t *testing.T) {
	resolver := NewChallengeResolver()

	t.Run("register first solver", func(t *testing.T) {
		solver := newMockSolver("dns-01")
		err := resolver.RegisterSolverStrict(solver)
		if err != nil {
			t.Fatalf("RegisterSolverStrict failed: %v", err)
		}
	})

	t.Run("reject duplicate solver", func(t *testing.T) {
		solver := newMockSolver("dns-01")
		err := resolver.RegisterSolverStrict(solver)
		if err == nil {
			t.Error("expected error for duplicate solver")
		}
		if !errors.Is(err, ErrSolverAlreadyExists) {
			t.Errorf("expected ErrSolverAlreadyExists, got %v", err)
		}
	})

	t.Run("register nil solver strict", func(t *testing.T) {
		err := resolver.RegisterSolverStrict(nil)
		if err == nil {
			t.Error("expected error for nil solver")
		}
	})
}

func TestResolverUnregisterSolver(t *testing.T) {
	resolver := NewChallengeResolver()
	solver := newMockSolver("dns-01")
	_ = resolver.RegisterSolver(solver)

	t.Run("unregister existing solver", func(t *testing.T) {
		removed := resolver.UnregisterSolver("dns-01")
		if !removed {
			t.Error("expected true when removing existing solver")
		}

		_, exists := resolver.GetSolver("dns-01")
		if exists {
			t.Error("solver still exists after unregistration")
		}
	})

	t.Run("unregister non-existent solver", func(t *testing.T) {
		removed := resolver.UnregisterSolver("non-existent")
		if removed {
			t.Error("expected false when removing non-existent solver")
		}
	})
}

func TestResolverSetPreferences(t *testing.T) {
	resolver := NewChallengeResolver()

	t.Run("set new preferences", func(t *testing.T) {
		resolver.SetPreferences("http-01", "dns-01")

		prefs := resolver.GetPreferences()
		if len(prefs) != 2 {
			t.Fatalf("expected 2 preferences, got %d", len(prefs))
		}
		if prefs[0] != "http-01" || prefs[1] != "dns-01" {
			t.Error("preferences not set correctly")
		}
	})

	t.Run("set empty preferences", func(t *testing.T) {
		resolver.SetPreferences()
		prefs := resolver.GetPreferences()
		if len(prefs) != 0 {
			t.Errorf("expected 0 preferences, got %d", len(prefs))
		}
	})
}

func TestResolverGetPreferences(t *testing.T) {
	resolver := NewChallengeResolver()
	resolver.SetPreferences("a", "b", "c")

	prefs := resolver.GetPreferences()

	// Modify the returned slice
	prefs[0] = "modified"

	// Original should be unchanged
	originalPrefs := resolver.GetPreferences()
	if originalPrefs[0] != "a" {
		t.Error("GetPreferences should return a copy, not the original slice")
	}
}

func TestResolverGetSolver(t *testing.T) {
	resolver := NewChallengeResolver()

	t.Run("get existing solver", func(t *testing.T) {
		solver := newMockSolver("dns-01")
		_ = resolver.RegisterSolver(solver)

		retrieved, exists := resolver.GetSolver("dns-01")
		if !exists {
			t.Error("solver should exist")
		}
		if retrieved != solver {
			t.Error("retrieved solver does not match")
		}
	})

	t.Run("get non-existent solver", func(t *testing.T) {
		_, exists := resolver.GetSolver("non-existent")
		if exists {
			t.Error("solver should not exist")
		}
	})
}

func TestResolverHasSolver(t *testing.T) {
	resolver := NewChallengeResolver()
	solver := newMockSolver("dns-01")
	_ = resolver.RegisterSolver(solver)

	if !resolver.HasSolver("dns-01") {
		t.Error("HasSolver should return true for registered solver")
	}

	if resolver.HasSolver("http-01") {
		t.Error("HasSolver should return false for unregistered solver")
	}
}

func TestResolverListSolvers(t *testing.T) {
	resolver := NewChallengeResolver()

	t.Run("empty resolver", func(t *testing.T) {
		solvers := resolver.ListSolvers()
		if len(solvers) != 0 {
			t.Errorf("expected 0 solvers, got %d", len(solvers))
		}
	})

	t.Run("with registered solvers", func(t *testing.T) {
		_ = resolver.RegisterSolver(newMockSolver("dns-01"))
		_ = resolver.RegisterSolver(newMockSolver("http-01"))

		solvers := resolver.ListSolvers()
		if len(solvers) != 2 {
			t.Errorf("expected 2 solvers, got %d", len(solvers))
		}
	})
}

func TestResolverSolverCount(t *testing.T) {
	resolver := NewChallengeResolver()

	if resolver.SolverCount() != 0 {
		t.Error("expected 0 solvers initially")
	}

	_ = resolver.RegisterSolver(newMockSolver("dns-01"))
	if resolver.SolverCount() != 1 {
		t.Error("expected 1 solver after registration")
	}

	_ = resolver.RegisterSolver(newMockSolver("http-01"))
	if resolver.SolverCount() != 2 {
		t.Error("expected 2 solvers after second registration")
	}
}

func TestResolverSelectChallenge(t *testing.T) {
	t.Run("select preferred challenge", func(t *testing.T) {
		resolver := NewChallengeResolver()
		resolver.SetPreferences("dns-01", "http-01")
		_ = resolver.RegisterSolver(newMockSolver("dns-01"))
		_ = resolver.RegisterSolver(newMockSolver("http-01"))

		authz := &acme.Authorization{
			Challenges: []*acme.Challenge{
				{Type: "http-01", Status: acme.StatusPending},
				{Type: "dns-01", Status: acme.StatusPending},
			},
		}

		challenge, solver, err := resolver.SelectChallenge(authz)
		if err != nil {
			t.Fatalf("SelectChallenge failed: %v", err)
		}
		if challenge.Type != "dns-01" {
			t.Errorf("expected dns-01 (preferred), got %s", challenge.Type)
		}
		if solver.Type() != "dns-01" {
			t.Error("solver type mismatch")
		}
	})

	t.Run("fallback to available challenge", func(t *testing.T) {
		resolver := NewChallengeResolver()
		resolver.SetPreferences("dns-01") // Only prefer dns-01
		_ = resolver.RegisterSolver(newMockSolver("http-01"))

		authz := &acme.Authorization{
			Challenges: []*acme.Challenge{
				{Type: "http-01", Status: acme.StatusPending},
				{Type: "dns-01", Status: acme.StatusPending},
			},
		}

		challenge, _, err := resolver.SelectChallenge(authz)
		if err != nil {
			t.Fatalf("SelectChallenge failed: %v", err)
		}
		if challenge.Type != "http-01" {
			t.Errorf("expected http-01 (fallback), got %s", challenge.Type)
		}
	})

	t.Run("skip invalid challenges", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_ = resolver.RegisterSolver(newMockSolver("dns-01"))
		_ = resolver.RegisterSolver(newMockSolver("http-01"))

		authz := &acme.Authorization{
			Challenges: []*acme.Challenge{
				{Type: "dns-01", Status: acme.StatusInvalid}, // Should be skipped
				{Type: "http-01", Status: acme.StatusPending},
			},
		}

		challenge, _, err := resolver.SelectChallenge(authz)
		if err != nil {
			t.Fatalf("SelectChallenge failed: %v", err)
		}
		if challenge.Type != "http-01" {
			t.Errorf("expected http-01 (dns-01 is invalid), got %s", challenge.Type)
		}
	})

	t.Run("no supported challenge", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_ = resolver.RegisterSolver(newMockSolver("dns-01"))

		authz := &acme.Authorization{
			Challenges: []*acme.Challenge{
				{Type: "http-01", Status: acme.StatusPending},
			},
		}

		_, _, err := resolver.SelectChallenge(authz)
		if err == nil {
			t.Error("expected error for unsupported challenge")
		}
		if !errors.Is(err, ErrNoChallengeSupported) {
			t.Errorf("expected ErrNoChallengeSupported, got %v", err)
		}
	})

	t.Run("nil authorization", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_, _, err := resolver.SelectChallenge(nil)
		if err == nil {
			t.Error("expected error for nil authorization")
		}
		if !errors.Is(err, ErrNilAuthorization) {
			t.Errorf("expected ErrNilAuthorization, got %v", err)
		}
	})

	t.Run("skip nil challenges", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_ = resolver.RegisterSolver(newMockSolver("http-01"))

		authz := &acme.Authorization{
			Challenges: []*acme.Challenge{
				nil, // Should be skipped
				{Type: "http-01", Status: acme.StatusPending},
			},
		}

		challenge, _, err := resolver.SelectChallenge(authz)
		if err != nil {
			t.Fatalf("SelectChallenge failed: %v", err)
		}
		if challenge.Type != "http-01" {
			t.Errorf("expected http-01, got %s", challenge.Type)
		}
	})
}

func TestResolverSolve(t *testing.T) {
	t.Run("successful solve", func(t *testing.T) {
		resolver := NewChallengeResolver()
		mockSolv := newMockSolver("dns-01")
		_ = resolver.RegisterSolver(mockSolv)

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "dns-01", Status: acme.StatusPending, Token: "test-token"},
			},
		}

		ctx := context.Background()
		challenge, err := resolver.Solve(ctx, authz, "keyAuth123")
		if err != nil {
			t.Fatalf("Solve failed: %v", err)
		}
		if challenge == nil {
			t.Fatal("Solve returned nil challenge")
		}
		if !mockSolv.wasSolveCalled() {
			t.Error("Solve method was not called on solver")
		}
	})

	t.Run("solve with solver error", func(t *testing.T) {
		resolver := NewChallengeResolver()
		expectedErr := errors.New("solver error")
		mockSolv := newMockSolver("dns-01")
		mockSolv.solveFunc = func(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error {
			return expectedErr
		}
		_ = resolver.RegisterSolver(mockSolv)

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "dns-01", Status: acme.StatusPending},
			},
		}

		_, err := resolver.Solve(context.Background(), authz, "keyAuth")
		if err == nil {
			t.Error("expected error from solver")
		}
		if !errors.Is(err, expectedErr) {
			t.Errorf("expected solver error, got %v", err)
		}
	})

	t.Run("solve with nil authorization", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_, err := resolver.Solve(context.Background(), nil, "keyAuth")
		if err == nil {
			t.Error("expected error for nil authorization")
		}
		if !errors.Is(err, ErrNilAuthorization) {
			t.Errorf("expected ErrNilAuthorization, got %v", err)
		}
	})

	t.Run("solve with empty keyAuth", func(t *testing.T) {
		resolver := NewChallengeResolver()
		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
		}
		_, err := resolver.Solve(context.Background(), authz, "")
		if err == nil {
			t.Error("expected error for empty keyAuth")
		}
		if !errors.Is(err, ErrEmptyKeyAuth) {
			t.Errorf("expected ErrEmptyKeyAuth, got %v", err)
		}
	})

	t.Run("solve with empty domain", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_ = resolver.RegisterSolver(newMockSolver("dns-01"))

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Type: "dns", Value: ""}, // Empty domain
			Challenges: []*acme.Challenge{
				{Type: "dns-01", Status: acme.StatusPending},
			},
		}

		_, err := resolver.Solve(context.Background(), authz, "keyAuth")
		if err == nil {
			t.Error("expected error for empty domain")
		}
		if !errors.Is(err, ErrEmptyDomain) {
			t.Errorf("expected ErrEmptyDomain, got %v", err)
		}
	})
}

func TestResolverSolveWithCleanup(t *testing.T) {
	t.Run("successful solve with cleanup", func(t *testing.T) {
		resolver := NewChallengeResolver()
		mockSolv := newMockSolver("dns-01")
		_ = resolver.RegisterSolver(mockSolv)

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "dns-01", Status: acme.StatusPending, Token: "test-token"},
			},
		}

		afterSolveCalled := false
		err := resolver.SolveWithCleanup(context.Background(), authz, "keyAuth", func(ctx context.Context, challenge *acme.Challenge) error {
			afterSolveCalled = true
			return nil
		})
		if err != nil {
			t.Fatalf("SolveWithCleanup failed: %v", err)
		}
		if !afterSolveCalled {
			t.Error("afterSolve callback was not called")
		}
		if !mockSolv.wasCleanupCalled() {
			t.Error("Cleanup was not called")
		}
	})

	t.Run("cleanup on afterSolve error", func(t *testing.T) {
		resolver := NewChallengeResolver()
		mockSolv := newMockSolver("dns-01")
		_ = resolver.RegisterSolver(mockSolv)

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "dns-01", Status: acme.StatusPending, Token: "test-token"},
			},
		}

		expectedErr := errors.New("afterSolve error")
		err := resolver.SolveWithCleanup(context.Background(), authz, "keyAuth", func(ctx context.Context, challenge *acme.Challenge) error {
			return expectedErr
		})
		if !errors.Is(err, expectedErr) {
			t.Errorf("expected afterSolve error, got %v", err)
		}
		// Cleanup should still be called
		if !mockSolv.wasCleanupCalled() {
			t.Error("Cleanup should be called even on error")
		}
	})

	t.Run("nil afterSolve function", func(t *testing.T) {
		resolver := NewChallengeResolver()
		mockSolv := newMockSolver("dns-01")
		_ = resolver.RegisterSolver(mockSolv)

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "dns-01", Status: acme.StatusPending, Token: "test-token"},
			},
		}

		err := resolver.SolveWithCleanup(context.Background(), authz, "keyAuth", nil)
		if err != nil {
			t.Fatalf("SolveWithCleanup with nil callback failed: %v", err)
		}
		if !mockSolv.wasCleanupCalled() {
			t.Error("Cleanup should be called")
		}
	})

	t.Run("cleanup failure is joined into the returned error", func(t *testing.T) {
		resolver := NewChallengeResolver()
		mockSolv := newMockSolver("dns-01")
		cleanupErr := errors.New("stale TXT record could not be removed")
		mockSolv.cleanupFunc = func(ctx context.Context, domain string, challenge *acme.Challenge) error {
			return cleanupErr
		}
		_ = resolver.RegisterSolver(mockSolv)

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "dns-01", Status: acme.StatusPending, Token: "test-token"},
			},
		}

		err := resolver.SolveWithCleanup(context.Background(), authz, "keyAuth", func(ctx context.Context, challenge *acme.Challenge) error {
			return nil
		})
		if err == nil {
			t.Fatal("expected an error when cleanup fails")
		}
		if !errors.Is(err, cleanupErr) {
			t.Errorf("expected returned error to wrap cleanup error, got %v", err)
		}
		if !errors.Is(err, ErrChallengeCleanupFailed) {
			t.Errorf("expected returned error to match ErrChallengeCleanupFailed, got %v", err)
		}
	})

	t.Run("cleanup failure is joined with the afterSolve error, not hidden by it", func(t *testing.T) {
		resolver := NewChallengeResolver()
		mockSolv := newMockSolver("dns-01")
		cleanupErr := errors.New("stale TXT record could not be removed")
		mockSolv.cleanupFunc = func(ctx context.Context, domain string, challenge *acme.Challenge) error {
			return cleanupErr
		}
		_ = resolver.RegisterSolver(mockSolv)

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "dns-01", Status: acme.StatusPending, Token: "test-token"},
			},
		}

		afterSolveErr := errors.New("afterSolve error")
		err := resolver.SolveWithCleanup(context.Background(), authz, "keyAuth", func(ctx context.Context, challenge *acme.Challenge) error {
			return afterSolveErr
		})
		if !errors.Is(err, afterSolveErr) {
			t.Errorf("expected returned error to wrap afterSolve error, got %v", err)
		}
		if !errors.Is(err, cleanupErr) {
			t.Errorf("expected returned error to also wrap cleanup error, got %v", err)
		}
	})
}

func TestResolverCleanup(t *testing.T) {
	t.Run("successful cleanup", func(t *testing.T) {
		resolver := NewChallengeResolver()
		mockSolv := newMockSolver("dns-01")
		_ = resolver.RegisterSolver(mockSolv)

		challenge := &acme.Challenge{Type: "dns-01", Token: "test-token"}
		err := resolver.Cleanup(context.Background(), "example.com", challenge)
		if err != nil {
			t.Fatalf("Cleanup failed: %v", err)
		}
		if !mockSolv.wasCleanupCalled() {
			t.Error("Cleanup was not called on solver")
		}
	})

	t.Run("cleanup with nil challenge", func(t *testing.T) {
		resolver := NewChallengeResolver()
		err := resolver.Cleanup(context.Background(), "example.com", nil)
		if err == nil {
			t.Error("expected error for nil challenge")
		}
		if !errors.Is(err, ErrNilChallenge) {
			t.Errorf("expected ErrNilChallenge, got %v", err)
		}
	})

	t.Run("cleanup with empty domain", func(t *testing.T) {
		resolver := NewChallengeResolver()
		challenge := &acme.Challenge{Type: "dns-01"}
		err := resolver.Cleanup(context.Background(), "", challenge)
		if err == nil {
			t.Error("expected error for empty domain")
		}
		if !errors.Is(err, ErrEmptyDomain) {
			t.Errorf("expected ErrEmptyDomain, got %v", err)
		}
	})

	t.Run("cleanup with unregistered solver", func(t *testing.T) {
		resolver := NewChallengeResolver()
		challenge := &acme.Challenge{Type: "dns-01"}
		err := resolver.Cleanup(context.Background(), "example.com", challenge)
		if err == nil {
			t.Error("expected error for unregistered solver")
		}
		if !errors.Is(err, ErrNoSolverRegistered) {
			t.Errorf("expected ErrNoSolverRegistered, got %v", err)
		}
	})
}

func TestResolverClose(t *testing.T) {
	t.Run("close resolver", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_ = resolver.RegisterSolver(newMockSolver("dns-01"))

		err := resolver.Close()
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		if !resolver.IsClosed() {
			t.Error("resolver should be closed")
		}

		// Operations should fail after close
		err = resolver.RegisterSolver(newMockSolver("http-01"))
		if err == nil {
			t.Error("expected error after close")
		}
		if !errors.Is(err, ErrResolverClosed) {
			t.Errorf("expected ErrResolverClosed, got %v", err)
		}
	})

	t.Run("double close", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_ = resolver.Close()
		err := resolver.Close()
		if err != nil {
			t.Error("double close should not return error")
		}
	})

	t.Run("operations fail after close", func(t *testing.T) {
		resolver := NewChallengeResolver()
		_ = resolver.Close()

		// GetSolver
		_, exists := resolver.GetSolver("dns-01")
		if exists {
			t.Error("GetSolver should return false after close")
		}

		// UnregisterSolver
		removed := resolver.UnregisterSolver("dns-01")
		if removed {
			t.Error("UnregisterSolver should return false after close")
		}

		// RegisterSolverStrict
		err := resolver.RegisterSolverStrict(newMockSolver("dns-01"))
		if !errors.Is(err, ErrResolverClosed) {
			t.Error("RegisterSolverStrict should fail after close")
		}

		// SelectChallenge
		_, _, err = resolver.SelectChallenge(&acme.Authorization{})
		if !errors.Is(err, ErrResolverClosed) {
			t.Error("SelectChallenge should fail after close")
		}

		// Solve
		_, err = resolver.Solve(context.Background(), &acme.Authorization{}, "keyAuth")
		if !errors.Is(err, ErrResolverClosed) {
			t.Error("Solve should fail after close")
		}
	})
}

func TestResolverConcurrentAccess(t *testing.T) {
	resolver := NewChallengeResolver()
	var wg sync.WaitGroup

	// Concurrent registrations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			solver := newMockSolver("type-" + string(rune('a'+idx)))
			_ = resolver.RegisterSolver(solver)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = resolver.ListSolvers()
			_ = resolver.SolverCount()
			_ = resolver.GetPreferences()
		}()
	}

	wg.Wait()

	// Verify state is consistent
	if resolver.SolverCount() != 10 {
		t.Errorf("expected 10 solvers, got %d", resolver.SolverCount())
	}
}
