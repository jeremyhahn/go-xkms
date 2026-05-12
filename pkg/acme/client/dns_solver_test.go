// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// mockDNSProvider implements providers.Provider for testing
type mockDNSProvider struct {
	presentFunc  func(ctx context.Context, domain, fqdn, value string) error
	cleanupFunc  func(ctx context.Context, domain, fqdn, value string) error
	mu           sync.Mutex
	presentCalls []presentCall
	cleanupCalls []cleanupCall
}

type presentCall struct {
	domain string
	fqdn   string
	value  string
}

type cleanupCall struct {
	domain string
	fqdn   string
	value  string
}

func newMockDNSProvider() *mockDNSProvider {
	return &mockDNSProvider{
		presentCalls: make([]presentCall, 0),
		cleanupCalls: make([]cleanupCall, 0),
	}
}

func (m *mockDNSProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	m.mu.Lock()
	m.presentCalls = append(m.presentCalls, presentCall{domain: domain, fqdn: fqdn, value: value})
	m.mu.Unlock()

	if m.presentFunc != nil {
		return m.presentFunc(ctx, domain, fqdn, value)
	}
	return nil
}

func (m *mockDNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	m.mu.Lock()
	m.cleanupCalls = append(m.cleanupCalls, cleanupCall{domain: domain, fqdn: fqdn, value: value})
	m.mu.Unlock()

	if m.cleanupFunc != nil {
		return m.cleanupFunc(ctx, domain, fqdn, value)
	}
	return nil
}

func (m *mockDNSProvider) getPresentCalls() []presentCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	calls := make([]presentCall, len(m.presentCalls))
	copy(calls, m.presentCalls)
	return calls
}

func (m *mockDNSProvider) getCleanupCalls() []cleanupCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	calls := make([]cleanupCall, len(m.cleanupCalls))
	copy(calls, m.cleanupCalls)
	return calls
}

func TestDNSSolverNewDNSSolver(t *testing.T) {
	t.Run("create with valid provider", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, err := NewDNSSolver(provider)
		if err != nil {
			t.Fatalf("NewDNSSolver failed: %v", err)
		}
		if solver == nil {
			t.Fatal("NewDNSSolver returned nil")
		}
		if solver.provider != provider {
			t.Error("provider not set correctly")
		}
	})

	t.Run("create with nil provider", func(t *testing.T) {
		solver, err := NewDNSSolver(nil)
		if err == nil {
			t.Error("expected error for nil provider")
		}
		if !errors.Is(err, ErrNilProvider) {
			t.Errorf("expected ErrNilProvider, got %v", err)
		}
		if solver != nil {
			t.Error("solver should be nil on error")
		}
	})

	t.Run("create with options", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, err := NewDNSSolver(provider,
			WithPropagationWait(5*time.Second),
			WithPropagationCheck(60*time.Second, 2*time.Second),
			WithNameservers([]string{"1.1.1.1:53", "1.0.0.1:53"}),
			WithRecordTTL(300),
		)
		if err != nil {
			t.Fatalf("NewDNSSolver failed: %v", err)
		}
		if solver.propagationWait != 5*time.Second {
			t.Errorf("propagationWait: expected 5s, got %v", solver.propagationWait)
		}
		if solver.propagationTimeout != 60*time.Second {
			t.Errorf("propagationTimeout: expected 60s, got %v", solver.propagationTimeout)
		}
		if solver.propagationInterval != 2*time.Second {
			t.Errorf("propagationInterval: expected 2s, got %v", solver.propagationInterval)
		}
		if !solver.checkPropagation {
			t.Error("checkPropagation should be true")
		}
		if len(solver.nameservers) != 2 {
			t.Errorf("expected 2 nameservers, got %d", len(solver.nameservers))
		}
		if solver.recordTTL != 300 {
			t.Errorf("recordTTL: expected 300, got %d", solver.recordTTL)
		}
	})
}

func TestDNSSolverType(t *testing.T) {
	provider := newMockDNSProvider()
	solver, _ := NewDNSSolver(provider)

	if solver.Type() != "dns-01" {
		t.Errorf("expected 'dns-01', got %s", solver.Type())
	}
}

func TestDNSSolverSolve(t *testing.T) {
	t.Run("successful solve", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		challenge := &acme.Challenge{Type: "dns-01", Token: "test-token-123"}
		keyAuth := "test-token-123.thumbprint"

		ctx := context.Background()
		err := solver.Solve(ctx, "example.com", challenge, keyAuth)
		if err != nil {
			t.Fatalf("Solve failed: %v", err)
		}

		// Verify Present was called with correct parameters
		calls := provider.getPresentCalls()
		if len(calls) != 1 {
			t.Fatalf("expected 1 Present call, got %d", len(calls))
		}

		expectedFQDN := "_acme-challenge.example.com."
		if calls[0].fqdn != expectedFQDN {
			t.Errorf("expected FQDN %s, got %s", expectedFQDN, calls[0].fqdn)
		}
		if calls[0].domain != "example.com" {
			t.Errorf("expected domain example.com, got %s", calls[0].domain)
		}

		// Verify the value is correctly computed
		expectedValue := ComputeDNS01ChallengeValue(keyAuth)
		if calls[0].value != expectedValue {
			t.Errorf("expected value %s, got %s", expectedValue, calls[0].value)
		}
	})

	t.Run("solve with domain having trailing dot", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := solver.Solve(context.Background(), "example.com.", challenge, "keyAuth")
		if err != nil {
			t.Fatalf("Solve failed: %v", err)
		}

		calls := provider.getPresentCalls()
		// Should not have double dot
		if calls[0].fqdn != "_acme-challenge.example.com." {
			t.Errorf("FQDN should not have double dot: %s", calls[0].fqdn)
		}
	})

	t.Run("solve with empty domain", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := solver.Solve(context.Background(), "", challenge, "keyAuth")
		if err == nil {
			t.Error("expected error for empty domain")
		}
		if !errors.Is(err, ErrEmptyDomain) {
			t.Errorf("expected ErrEmptyDomain, got %v", err)
		}
	})

	t.Run("solve with nil challenge", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		err := solver.Solve(context.Background(), "example.com", nil, "keyAuth")
		if err == nil {
			t.Error("expected error for nil challenge")
		}
		if !errors.Is(err, ErrNilChallenge) {
			t.Errorf("expected ErrNilChallenge, got %v", err)
		}
	})

	t.Run("solve with empty keyAuth", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := solver.Solve(context.Background(), "example.com", challenge, "")
		if err == nil {
			t.Error("expected error for empty keyAuth")
		}
		if !errors.Is(err, ErrEmptyKeyAuth) {
			t.Errorf("expected ErrEmptyKeyAuth, got %v", err)
		}
	})

	t.Run("solve with provider error", func(t *testing.T) {
		provider := newMockDNSProvider()
		expectedErr := errors.New("provider error")
		provider.presentFunc = func(ctx context.Context, domain, fqdn, value string) error {
			return expectedErr
		}

		solver, _ := NewDNSSolver(provider)
		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}

		err := solver.Solve(context.Background(), "example.com", challenge, "keyAuth")
		if err == nil {
			t.Error("expected error from provider")
		}
		var caErr *caerrors.TrustedCAError
		if !errors.As(err, &caErr) || caErr.Type != caerrors.DNS {
			t.Errorf("expected DNS error, got %v", err)
		}
	})

	t.Run("solve after close", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)
		_ = solver.Close()

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := solver.Solve(context.Background(), "example.com", challenge, "keyAuth")
		if err == nil {
			t.Error("expected error after close")
		}
		if !errors.Is(err, ErrDNSSolverClosed) {
			t.Errorf("expected ErrDNSSolverClosed, got %v", err)
		}
	})

	t.Run("solve with propagation wait", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider, WithPropagationWait(50*time.Millisecond))

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		start := time.Now()
		err := solver.Solve(context.Background(), "example.com", challenge, "keyAuth")
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("Solve failed: %v", err)
		}
		if elapsed < 50*time.Millisecond {
			t.Errorf("expected at least 50ms wait, got %v", elapsed)
		}
	})

	t.Run("solve with context cancellation during wait", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider, WithPropagationWait(5*time.Second))

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		start := time.Now()
		err := solver.Solve(ctx, "example.com", challenge, "keyAuth")
		elapsed := time.Since(start)

		if err == nil {
			t.Error("expected context cancellation error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
		if elapsed > 1*time.Second {
			t.Error("should have cancelled quickly")
		}
	})
}

func TestDNSSolverCleanup(t *testing.T) {
	t.Run("cleanup after solve", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		challenge := &acme.Challenge{Type: "dns-01", Token: "test-token"}
		keyAuth := "test-token.thumbprint"

		// First solve
		_ = solver.Solve(context.Background(), "example.com", challenge, keyAuth)

		// Then cleanup
		err := solver.Cleanup(context.Background(), "example.com", challenge)
		if err != nil {
			t.Fatalf("Cleanup failed: %v", err)
		}

		calls := provider.getCleanupCalls()
		if len(calls) != 1 {
			t.Fatalf("expected 1 CleanUp call, got %d", len(calls))
		}

		expectedFQDN := "_acme-challenge.example.com."
		if calls[0].fqdn != expectedFQDN {
			t.Errorf("expected FQDN %s, got %s", expectedFQDN, calls[0].fqdn)
		}

		expectedValue := ComputeDNS01ChallengeValue(keyAuth)
		if calls[0].value != expectedValue {
			t.Errorf("expected value %s, got %s", expectedValue, calls[0].value)
		}

		// Active record count should be 0
		if solver.ActiveRecordCount() != 0 {
			t.Errorf("expected 0 active records, got %d", solver.ActiveRecordCount())
		}
	})

	t.Run("cleanup without prior solve", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		challenge := &acme.Challenge{Type: "dns-01", Token: "unknown-token"}
		err := solver.Cleanup(context.Background(), "example.com", challenge)
		if err != nil {
			t.Fatalf("Cleanup should succeed even without prior Solve: %v", err)
		}

		calls := provider.getCleanupCalls()
		if len(calls) != 1 {
			t.Fatalf("expected 1 CleanUp call, got %d", len(calls))
		}

		// Should use empty value since record wasn't tracked
		if calls[0].value != "" {
			t.Errorf("expected empty value for unknown record, got %s", calls[0].value)
		}
	})

	t.Run("cleanup with empty domain", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := solver.Cleanup(context.Background(), "", challenge)
		if err == nil {
			t.Error("expected error for empty domain")
		}
		if !errors.Is(err, ErrEmptyDomain) {
			t.Errorf("expected ErrEmptyDomain, got %v", err)
		}
	})

	t.Run("cleanup with nil challenge", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		err := solver.Cleanup(context.Background(), "example.com", nil)
		if err == nil {
			t.Error("expected error for nil challenge")
		}
		if !errors.Is(err, ErrNilChallenge) {
			t.Errorf("expected ErrNilChallenge, got %v", err)
		}
	})

	t.Run("cleanup with provider error", func(t *testing.T) {
		provider := newMockDNSProvider()
		expectedErr := errors.New("cleanup error")
		provider.cleanupFunc = func(ctx context.Context, domain, fqdn, value string) error {
			return expectedErr
		}

		solver, _ := NewDNSSolver(provider)
		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}

		err := solver.Cleanup(context.Background(), "example.com", challenge)
		if err == nil {
			t.Error("expected error from provider")
		}
		var caErr *caerrors.TrustedCAError
		if !errors.As(err, &caErr) || caErr.Type != caerrors.DNS {
			t.Errorf("expected DNS error, got %v", err)
		}
	})

	t.Run("cleanup after close", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)
		_ = solver.Close()

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := solver.Cleanup(context.Background(), "example.com", challenge)
		if err == nil {
			t.Error("expected error after close")
		}
		if !errors.Is(err, ErrDNSSolverClosed) {
			t.Errorf("expected ErrDNSSolverClosed, got %v", err)
		}
	})
}

func TestDNSSolverClose(t *testing.T) {
	provider := newMockDNSProvider()
	solver, _ := NewDNSSolver(provider)

	err := solver.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !solver.IsClosed() {
		t.Error("solver should be closed")
	}
}

func TestDNSSolverActiveRecordCount(t *testing.T) {
	provider := newMockDNSProvider()
	solver, _ := NewDNSSolver(provider)

	if solver.ActiveRecordCount() != 0 {
		t.Error("expected 0 active records initially")
	}

	challenge1 := &acme.Challenge{Type: "dns-01", Token: "token1"}
	challenge2 := &acme.Challenge{Type: "dns-01", Token: "token2"}

	_ = solver.Solve(context.Background(), "example.com", challenge1, "keyAuth1")
	if solver.ActiveRecordCount() != 1 {
		t.Error("expected 1 active record")
	}

	_ = solver.Solve(context.Background(), "example.org", challenge2, "keyAuth2")
	if solver.ActiveRecordCount() != 2 {
		t.Error("expected 2 active records")
	}

	_ = solver.Cleanup(context.Background(), "example.com", challenge1)
	if solver.ActiveRecordCount() != 1 {
		t.Error("expected 1 active record after cleanup")
	}
}

func TestDNSSolverComputeDNS01ChallengeValue(t *testing.T) {
	testCases := []struct {
		name    string
		keyAuth string
	}{
		{"simple keyAuth", "token.thumbprint"},
		{"long keyAuth", "a1b2c3d4e5f6g7h8i9j0.abcdefghijklmnopqrstuvwxyz1234567890"},
		{"special characters", "test-token_123.thumb_print-abc"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ComputeDNS01ChallengeValue(tc.keyAuth)

			// Verify it's valid base64url
			decoded, err := base64.RawURLEncoding.DecodeString(result)
			if err != nil {
				t.Fatalf("result is not valid base64url: %v", err)
			}

			// Verify it's a SHA-256 hash (32 bytes)
			if len(decoded) != sha256.Size {
				t.Errorf("expected SHA-256 size (%d), got %d", sha256.Size, len(decoded))
			}

			// Verify it matches manual computation
			hash := sha256.Sum256([]byte(tc.keyAuth))
			expected := base64.RawURLEncoding.EncodeToString(hash[:])
			if result != expected {
				t.Errorf("expected %s, got %s", expected, result)
			}
		})
	}
}

func TestDNSSolverBuildACMEChallengeFQDN(t *testing.T) {
	testCases := []struct {
		domain   string
		expected string
	}{
		{"example.com", "_acme-challenge.example.com."},
		{"example.com.", "_acme-challenge.example.com."},
		{"sub.example.com", "_acme-challenge.sub.example.com."},
		{"sub.example.com.", "_acme-challenge.sub.example.com."},
	}

	for _, tc := range testCases {
		t.Run(tc.domain, func(t *testing.T) {
			result := buildACMEChallengeFQDN(tc.domain)
			if result != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestDNSSolverBuildRecordKey(t *testing.T) {
	key := buildRecordKey("example.com", "token123")
	if key != "example.com:token123" {
		t.Errorf("unexpected key format: %s", key)
	}
}

func TestDNSSolverInterfaceCompliance(t *testing.T) {
	// Verify DNSSolver implements ChallengeSolver
	var _ ChallengeSolver = (*DNSSolver)(nil)
}

func TestDNSSolverWithOptions(t *testing.T) {
	t.Run("WithPropagationWait", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider, WithPropagationWait(10*time.Second))
		if solver.propagationWait != 10*time.Second {
			t.Errorf("expected 10s, got %v", solver.propagationWait)
		}
	})

	t.Run("WithPropagationCheck", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider, WithPropagationCheck(30*time.Second, 1*time.Second))
		if !solver.checkPropagation {
			t.Error("checkPropagation should be true")
		}
		if solver.propagationTimeout != 30*time.Second {
			t.Errorf("expected timeout 30s, got %v", solver.propagationTimeout)
		}
		if solver.propagationInterval != 1*time.Second {
			t.Errorf("expected interval 1s, got %v", solver.propagationInterval)
		}
	})

	t.Run("WithNameservers", func(t *testing.T) {
		provider := newMockDNSProvider()
		ns := []string{"8.8.8.8:53", "1.1.1.1:53"}
		solver, _ := NewDNSSolver(provider, WithNameservers(ns))
		if len(solver.nameservers) != 2 {
			t.Errorf("expected 2 nameservers, got %d", len(solver.nameservers))
		}
		if solver.nameservers[0] != "8.8.8.8:53" {
			t.Errorf("unexpected nameserver: %s", solver.nameservers[0])
		}
	})

	t.Run("WithRecordTTL", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider, WithRecordTTL(600))
		if solver.recordTTL != 600 {
			t.Errorf("expected TTL 600, got %d", solver.recordTTL)
		}
	})
}

func TestDNSSolverConcurrentAccess(t *testing.T) {
	provider := newMockDNSProvider()
	solver, _ := NewDNSSolver(provider)
	var wg sync.WaitGroup

	// Concurrent solves
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			challenge := &acme.Challenge{
				Type:  "dns-01",
				Token: "token-" + string(rune('a'+idx)),
			}
			_ = solver.Solve(context.Background(), "example.com", challenge, "keyAuth")
		}(i)
	}

	wg.Wait()

	// Verify all records were tracked
	if solver.ActiveRecordCount() != 10 {
		t.Errorf("expected 10 active records, got %d", solver.ActiveRecordCount())
	}

	// Concurrent cleanups
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			challenge := &acme.Challenge{
				Type:  "dns-01",
				Token: "token-" + string(rune('a'+idx)),
			}
			_ = solver.Cleanup(context.Background(), "example.com", challenge)
		}(i)
	}

	wg.Wait()

	if solver.ActiveRecordCount() != 0 {
		t.Errorf("expected 0 active records after cleanup, got %d", solver.ActiveRecordCount())
	}
}

// TestDefaultPreCheckOption tests the DefaultPreCheckOption function
func TestDefaultPreCheckOption(t *testing.T) {
	opt := DefaultPreCheckOption()

	if opt == nil {
		t.Fatal("expected non-nil option")
	}

	if opt.Timeout <= 0 {
		t.Error("expected positive timeout")
	}

	if opt.Interval <= 0 {
		t.Error("expected positive interval")
	}

	if opt.AllowFailure {
		t.Error("expected AllowFailure to be false by default")
	}

	if opt.CheckFunc != nil {
		t.Error("expected nil CheckFunc by default")
	}
}

// TestWrapPreCheck tests the WrapPreCheck function
func TestWrapPreCheck(t *testing.T) {
	t.Run("wrap with nil option uses defaults", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		wrapped := WrapPreCheck(solver, nil)
		if wrapped == nil {
			t.Fatal("expected non-nil wrapped solver")
		}
		if wrapped.solver != solver {
			t.Error("wrapped solver should reference original")
		}
		if wrapped.option.Timeout <= 0 {
			t.Error("expected default timeout")
		}
	})

	t.Run("wrap with custom option", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		opt := &PreCheckOption{
			Timeout:      5 * time.Second,
			Interval:     500 * time.Millisecond,
			AllowFailure: true,
		}

		wrapped := WrapPreCheck(solver, opt)
		if wrapped.option.Timeout != 5*time.Second {
			t.Errorf("expected 5s timeout, got %v", wrapped.option.Timeout)
		}
		if wrapped.option.Interval != 500*time.Millisecond {
			t.Errorf("expected 500ms interval, got %v", wrapped.option.Interval)
		}
		if !wrapped.option.AllowFailure {
			t.Error("expected AllowFailure to be true")
		}
	})

	t.Run("wrap with zero timeout uses default", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		opt := &PreCheckOption{
			Timeout:  0,
			Interval: 0,
		}

		wrapped := WrapPreCheck(solver, opt)
		if wrapped.option.Timeout <= 0 {
			t.Error("expected default timeout when zero provided")
		}
		if wrapped.option.Interval <= 0 {
			t.Error("expected default interval when zero provided")
		}
	})
}

// TestPreCheckDNSSolverType tests the Type method
func TestPreCheckDNSSolverType(t *testing.T) {
	provider := newMockDNSProvider()
	solver, _ := NewDNSSolver(provider)
	wrapped := WrapPreCheck(solver, nil)

	if wrapped.Type() != "dns-01" {
		t.Errorf("expected 'dns-01', got %s", wrapped.Type())
	}
}

// TestPreCheckDNSSolverSolve tests the Solve method
func TestPreCheckDNSSolverSolve(t *testing.T) {
	t.Run("solve without check func", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)
		wrapped := WrapPreCheck(solver, &PreCheckOption{
			CheckFunc: nil,
		})

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := wrapped.Solve(context.Background(), "example.com", challenge, "keyAuth")
		if err != nil {
			t.Fatalf("Solve failed: %v", err)
		}

		calls := provider.getPresentCalls()
		if len(calls) != 1 {
			t.Errorf("expected 1 Present call, got %d", len(calls))
		}
	})

	t.Run("solve with passing check func", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		checkCalled := false
		wrapped := WrapPreCheck(solver, &PreCheckOption{
			Timeout:  100 * time.Millisecond,
			Interval: 10 * time.Millisecond,
			CheckFunc: func(ctx context.Context, fqdn, value string) error {
				checkCalled = true
				return nil // Success immediately
			},
		})

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := wrapped.Solve(context.Background(), "example.com", challenge, "keyAuth")
		if err != nil {
			t.Fatalf("Solve failed: %v", err)
		}

		if !checkCalled {
			t.Error("check function was not called")
		}
	})

	t.Run("solve with failing check func and AllowFailure=false", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		wrapped := WrapPreCheck(solver, &PreCheckOption{
			Timeout:      50 * time.Millisecond,
			Interval:     10 * time.Millisecond,
			AllowFailure: false,
			CheckFunc: func(ctx context.Context, fqdn, value string) error {
				return errors.New("check failed")
			},
		})

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := wrapped.Solve(context.Background(), "example.com", challenge, "keyAuth")
		if err == nil {
			t.Error("expected error when pre-check fails")
		}

		// Cleanup should have been called
		cleanupCalls := provider.getCleanupCalls()
		if len(cleanupCalls) != 1 {
			t.Errorf("expected cleanup to be called on failure, got %d calls", len(cleanupCalls))
		}
	})

	t.Run("solve with failing check func and AllowFailure=true", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		wrapped := WrapPreCheck(solver, &PreCheckOption{
			Timeout:      50 * time.Millisecond,
			Interval:     10 * time.Millisecond,
			AllowFailure: true,
			CheckFunc: func(ctx context.Context, fqdn, value string) error {
				return errors.New("check failed")
			},
		})

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := wrapped.Solve(context.Background(), "example.com", challenge, "keyAuth")
		if err != nil {
			t.Errorf("expected no error when AllowFailure=true, got %v", err)
		}
	})

	t.Run("solve with check func that eventually passes", func(t *testing.T) {
		provider := newMockDNSProvider()
		solver, _ := NewDNSSolver(provider)

		callCount := 0
		wrapped := WrapPreCheck(solver, &PreCheckOption{
			Timeout:  200 * time.Millisecond,
			Interval: 20 * time.Millisecond,
			CheckFunc: func(ctx context.Context, fqdn, value string) error {
				callCount++
				if callCount < 3 {
					return errors.New("not ready yet")
				}
				return nil
			},
		})

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := wrapped.Solve(context.Background(), "example.com", challenge, "keyAuth")
		if err != nil {
			t.Fatalf("Solve failed: %v", err)
		}

		if callCount < 3 {
			t.Errorf("expected at least 3 check calls, got %d", callCount)
		}
	})

	t.Run("solve propagates underlying solver error", func(t *testing.T) {
		provider := newMockDNSProvider()
		provider.presentFunc = func(ctx context.Context, domain, fqdn, value string) error {
			return errors.New("present error")
		}

		solver, _ := NewDNSSolver(provider)
		wrapped := WrapPreCheck(solver, nil)

		challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
		err := wrapped.Solve(context.Background(), "example.com", challenge, "keyAuth")
		if err == nil {
			t.Error("expected error from underlying solver")
		}
	})
}

// TestPreCheckDNSSolverCleanup tests the Cleanup method
func TestPreCheckDNSSolverCleanup(t *testing.T) {
	provider := newMockDNSProvider()
	solver, _ := NewDNSSolver(provider)
	wrapped := WrapPreCheck(solver, nil)

	// First solve
	challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
	_ = wrapped.Solve(context.Background(), "example.com", challenge, "keyAuth")

	// Then cleanup
	err := wrapped.Cleanup(context.Background(), "example.com", challenge)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	calls := provider.getCleanupCalls()
	if len(calls) != 1 {
		t.Errorf("expected 1 cleanup call, got %d", len(calls))
	}
}

// TestPreCheckDNSSolverClose tests the Close method
func TestPreCheckDNSSolverClose(t *testing.T) {
	provider := newMockDNSProvider()
	solver, _ := NewDNSSolver(provider)
	wrapped := WrapPreCheck(solver, nil)

	err := wrapped.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !wrapped.IsClosed() {
		t.Error("expected wrapped solver to be closed")
	}

	if !solver.IsClosed() {
		t.Error("expected underlying solver to be closed")
	}
}

// TestPreCheckDNSSolverIsClosed tests the IsClosed method
func TestPreCheckDNSSolverIsClosed(t *testing.T) {
	provider := newMockDNSProvider()
	solver, _ := NewDNSSolver(provider)
	wrapped := WrapPreCheck(solver, nil)

	if wrapped.IsClosed() {
		t.Error("should not be closed initially")
	}

	_ = wrapped.Close()

	if !wrapped.IsClosed() {
		t.Error("should be closed after Close()")
	}
}

// TestPreCheckDNSSolverActiveRecordCount tests the ActiveRecordCount method
func TestPreCheckDNSSolverActiveRecordCount(t *testing.T) {
	provider := newMockDNSProvider()
	solver, _ := NewDNSSolver(provider)
	wrapped := WrapPreCheck(solver, nil)

	if wrapped.ActiveRecordCount() != 0 {
		t.Error("expected 0 active records initially")
	}

	challenge := &acme.Challenge{Type: "dns-01", Token: "token"}
	_ = wrapped.Solve(context.Background(), "example.com", challenge, "keyAuth")

	if wrapped.ActiveRecordCount() != 1 {
		t.Error("expected 1 active record after solve")
	}
}

// TestCheckDNSFromNameservers tests the CheckDNSFromNameservers pre-check function factory
func TestCheckDNSFromNameservers(t *testing.T) {
	t.Run("creates valid pre-check function", func(t *testing.T) {
		nameservers := []string{"8.8.8.8:53", "1.1.1.1:53"}
		checkFunc := CheckDNSFromNameservers(nameservers)

		if checkFunc == nil {
			t.Fatal("expected non-nil check function")
		}
	})
}

// TestCheckDNSFromPublic tests the CheckDNSFromPublic pre-check function factory
func TestCheckDNSFromPublic(t *testing.T) {
	checkFunc := CheckDNSFromPublic()

	if checkFunc == nil {
		t.Fatal("expected non-nil check function")
	}
}

// TestCheckDNSFromAuthoritative tests the CheckDNSFromAuthoritative pre-check function factory
func TestCheckDNSFromAuthoritative(t *testing.T) {
	checkFunc := CheckDNSFromAuthoritative()

	if checkFunc == nil {
		t.Fatal("expected non-nil check function")
	}
}

// TestPreCheckDNSSolverInterfaceCompliance tests interface compliance
func TestPreCheckDNSSolverInterfaceCompliance(t *testing.T) {
	// Verify PreCheckDNSSolver implements ChallengeSolver
	var _ ChallengeSolver = (*PreCheckDNSSolver)(nil)
}
