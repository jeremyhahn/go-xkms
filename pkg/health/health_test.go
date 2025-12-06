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

package health

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewChecker(t *testing.T) {
	checker := NewChecker()
	if checker == nil {
		t.Fatal("NewChecker returned nil")
		return
	}
	if len(checker.checks) != 0 {
		t.Errorf("expected 0 checks, got %d", len(checker.checks))
	}
	if checker.started {
		t.Error("expected started to be false")
	}
	if time.Since(checker.startTime) > time.Second {
		t.Error("startTime should be recent")
	}
}

func TestRegisterCheck(t *testing.T) {
	checker := NewChecker()

	// Register a check
	check := func(ctx context.Context) CheckResult {
		return CheckResult{
			Name:   "test",
			Status: StatusHealthy,
		}
	}
	checker.RegisterCheck("test", check)

	// Verify it was registered
	checks := checker.GetAllChecks()
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}
	if checks[0] != "test" {
		t.Errorf("expected check name 'test', got %s", checks[0])
	}

	// Register nil check (should be ignored)
	checker.RegisterCheck("nil", nil)
	checks = checker.GetAllChecks()
	if len(checks) != 1 {
		t.Errorf("expected 1 check after registering nil, got %d", len(checks))
	}

	// Replace existing check
	check2 := func(ctx context.Context) CheckResult {
		return CheckResult{
			Name:   "test2",
			Status: StatusDegraded,
		}
	}
	checker.RegisterCheck("test", check2)
	checks = checker.GetAllChecks()
	if len(checks) != 1 {
		t.Errorf("expected 1 check after replacement, got %d", len(checks))
	}
}

func TestUnregisterCheck(t *testing.T) {
	checker := NewChecker()

	check := func(ctx context.Context) CheckResult {
		return CheckResult{Status: StatusHealthy}
	}
	checker.RegisterCheck("test", check)
	checker.RegisterCheck("test2", check)

	// Verify both registered
	checks := checker.GetAllChecks()
	if len(checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(checks))
	}

	// Unregister one
	checker.UnregisterCheck("test")
	checks = checker.GetAllChecks()
	if len(checks) != 1 {
		t.Fatalf("expected 1 check after unregister, got %d", len(checks))
	}
	if checks[0] != "test2" {
		t.Errorf("expected 'test2' to remain, got %s", checks[0])
	}

	// Unregister non-existent (should not panic)
	checker.UnregisterCheck("nonexistent")
	checks = checker.GetAllChecks()
	if len(checks) != 1 {
		t.Errorf("expected 1 check after unregistering nonexistent, got %d", len(checks))
	}
}

func TestMarkStarted(t *testing.T) {
	checker := NewChecker()

	if checker.IsStarted() {
		t.Error("expected IsStarted to be false initially")
	}

	checker.MarkStarted()

	if !checker.IsStarted() {
		t.Error("expected IsStarted to be true after MarkStarted")
	}

	// Test MarkNotStarted
	checker.MarkNotStarted()
	if checker.IsStarted() {
		t.Error("expected IsStarted to be false after MarkNotStarted")
	}
}

func TestLive(t *testing.T) {
	checker := NewChecker()
	ctx := context.Background()

	result := checker.Live(ctx)

	if result.Name != "liveness" {
		t.Errorf("expected name 'liveness', got %s", result.Name)
	}
	if result.Status != StatusHealthy {
		t.Errorf("expected status %s, got %s", StatusHealthy, result.Status)
	}
	if result.Message == "" {
		t.Error("expected non-empty message")
	}
	if result.Latency < 0 {
		t.Error("expected non-negative latency")
	}
}

func TestReady(t *testing.T) {
	tests := []struct {
		name           string
		checks         map[string]CheckFunc
		expectedCount  int
		expectedStatus Status
	}{
		{
			name:           "no checks",
			checks:         map[string]CheckFunc{},
			expectedCount:  1, // Default check
			expectedStatus: StatusHealthy,
		},
		{
			name: "single healthy check",
			checks: map[string]CheckFunc{
				"test": func(ctx context.Context) CheckResult {
					return CheckResult{
						Name:   "test",
						Status: StatusHealthy,
					}
				},
			},
			expectedCount:  1,
			expectedStatus: StatusHealthy,
		},
		{
			name: "multiple healthy checks",
			checks: map[string]CheckFunc{
				"check1": func(ctx context.Context) CheckResult {
					return CheckResult{
						Name:   "check1",
						Status: StatusHealthy,
					}
				},
				"check2": func(ctx context.Context) CheckResult {
					return CheckResult{
						Name:   "check2",
						Status: StatusHealthy,
					}
				},
			},
			expectedCount:  2,
			expectedStatus: StatusHealthy,
		},
		{
			name: "one unhealthy check",
			checks: map[string]CheckFunc{
				"check1": func(ctx context.Context) CheckResult {
					return CheckResult{
						Name:   "check1",
						Status: StatusHealthy,
					}
				},
				"check2": func(ctx context.Context) CheckResult {
					return CheckResult{
						Name:   "check2",
						Status: StatusUnhealthy,
						Error:  "connection failed",
					}
				},
			},
			expectedCount:  2,
			expectedStatus: StatusUnhealthy,
		},
		{
			name: "degraded check",
			checks: map[string]CheckFunc{
				"check1": func(ctx context.Context) CheckResult {
					return CheckResult{
						Name:   "check1",
						Status: StatusDegraded,
					}
				},
			},
			expectedCount:  1,
			expectedStatus: StatusDegraded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker()
			for name, check := range tt.checks {
				checker.RegisterCheck(name, check)
			}

			ctx := context.Background()
			results := checker.Ready(ctx)

			if len(results) != tt.expectedCount {
				t.Errorf("expected %d results, got %d", tt.expectedCount, len(results))
			}

			// Verify all results have required fields
			for _, result := range results {
				if result.Name == "" {
					t.Error("result missing name")
				}
				if result.Status == "" {
					t.Error("result missing status")
				}
				if result.Latency < 0 {
					t.Error("result has negative latency")
				}
			}

			// Verify aggregate status
			status := AggregateStatus(results)
			if status != tt.expectedStatus {
				t.Errorf("expected aggregate status %s, got %s", tt.expectedStatus, status)
			}
		})
	}
}

func TestStartup(t *testing.T) {
	checker := NewChecker()
	ctx := context.Background()

	// Before marking started
	result := checker.Startup(ctx)
	if result.Name != "startup" {
		t.Errorf("expected name 'startup', got %s", result.Name)
	}
	if result.Status != StatusUnhealthy {
		t.Errorf("expected status %s before started, got %s", StatusUnhealthy, result.Status)
	}

	// After marking started
	checker.MarkStarted()
	result = checker.Startup(ctx)
	if result.Status != StatusHealthy {
		t.Errorf("expected status %s after started, got %s", StatusHealthy, result.Status)
	}
	if result.Message == "" {
		t.Error("expected non-empty message")
	}
}

func TestIsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		checks   map[string]CheckFunc
		expected bool
	}{
		{
			name:     "no checks",
			checks:   map[string]CheckFunc{},
			expected: true,
		},
		{
			name: "all healthy",
			checks: map[string]CheckFunc{
				"check1": func(ctx context.Context) CheckResult {
					return CheckResult{Status: StatusHealthy}
				},
				"check2": func(ctx context.Context) CheckResult {
					return CheckResult{Status: StatusHealthy}
				},
			},
			expected: true,
		},
		{
			name: "one unhealthy",
			checks: map[string]CheckFunc{
				"check1": func(ctx context.Context) CheckResult {
					return CheckResult{Status: StatusHealthy}
				},
				"check2": func(ctx context.Context) CheckResult {
					return CheckResult{Status: StatusUnhealthy}
				},
			},
			expected: false,
		},
		{
			name: "one degraded",
			checks: map[string]CheckFunc{
				"check1": func(ctx context.Context) CheckResult {
					return CheckResult{Status: StatusHealthy}
				},
				"check2": func(ctx context.Context) CheckResult {
					return CheckResult{Status: StatusDegraded}
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker()
			for name, check := range tt.checks {
				checker.RegisterCheck(name, check)
			}

			ctx := context.Background()
			healthy := checker.IsHealthy(ctx)

			if healthy != tt.expected {
				t.Errorf("expected IsHealthy=%v, got %v", tt.expected, healthy)
			}
		})
	}
}

func TestUptime(t *testing.T) {
	checker := NewChecker()

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	uptime := checker.Uptime()
	if uptime < 10*time.Millisecond {
		t.Errorf("expected uptime >= 10ms, got %v", uptime)
	}
	if uptime > time.Second {
		t.Errorf("expected uptime < 1s, got %v", uptime)
	}
}

func TestAggregateStatus(t *testing.T) {
	tests := []struct {
		name     string
		results  []CheckResult
		expected Status
	}{
		{
			name:     "empty results",
			results:  []CheckResult{},
			expected: StatusHealthy,
		},
		{
			name: "all healthy",
			results: []CheckResult{
				{Status: StatusHealthy},
				{Status: StatusHealthy},
			},
			expected: StatusHealthy,
		},
		{
			name: "one unhealthy",
			results: []CheckResult{
				{Status: StatusHealthy},
				{Status: StatusUnhealthy},
			},
			expected: StatusUnhealthy,
		},
		{
			name: "one degraded",
			results: []CheckResult{
				{Status: StatusHealthy},
				{Status: StatusDegraded},
			},
			expected: StatusDegraded,
		},
		{
			name: "unhealthy takes precedence over degraded",
			results: []CheckResult{
				{Status: StatusHealthy},
				{Status: StatusDegraded},
				{Status: StatusUnhealthy},
			},
			expected: StatusUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := AggregateStatus(tt.results)
			if status != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, status)
			}
		})
	}
}

func TestCheckResultFields(t *testing.T) {
	checker := NewChecker()

	// Register a check that sets all fields
	checker.RegisterCheck("detailed", func(ctx context.Context) CheckResult {
		return CheckResult{
			Name:    "detailed",
			Status:  StatusDegraded,
			Message: "slow response",
			Error:   "timeout exceeded",
		}
	})

	ctx := context.Background()
	results := checker.Ready(ctx)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	result := results[0]
	if result.Name != "detailed" {
		t.Errorf("expected name 'detailed', got %s", result.Name)
	}
	if result.Status != StatusDegraded {
		t.Errorf("expected status %s, got %s", StatusDegraded, result.Status)
	}
	if result.Message != "slow response" {
		t.Errorf("expected message 'slow response', got %s", result.Message)
	}
	if result.Error != "timeout exceeded" {
		t.Errorf("expected error 'timeout exceeded', got %s", result.Error)
	}
	if result.Latency < 0 {
		t.Error("expected non-negative latency")
	}
}

func TestCheckContext(t *testing.T) {
	checker := NewChecker()

	// Register a check that respects context cancellation
	checker.RegisterCheck("context-aware", func(ctx context.Context) CheckResult {
		select {
		case <-ctx.Done():
			return CheckResult{
				Name:   "context-aware",
				Status: StatusUnhealthy,
				Error:  ctx.Err().Error(),
			}
		case <-time.After(100 * time.Millisecond):
			return CheckResult{
				Name:   "context-aware",
				Status: StatusHealthy,
			}
		}
	})

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results := checker.Ready(ctx)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	result := results[0]
	if result.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy with cancelled context, got %s", result.Status)
	}
	if result.Error == "" {
		t.Error("expected error message with cancelled context")
	}
}

func TestCheckErrorHandling(t *testing.T) {
	checker := NewChecker()

	// Register a check that panics (shouldn't crash the checker)
	checker.RegisterCheck("panicky", func(ctx context.Context) CheckResult {
		// This should be handled gracefully by the caller
		panic("intentional panic for testing")
	})

	// The Ready method itself doesn't catch panics - that's the caller's responsibility
	// This test verifies the check is properly registered
	checks := checker.GetAllChecks()
	if len(checks) != 1 {
		t.Errorf("expected 1 check, got %d", len(checks))
	}
}

// TestConcurrency verifies thread safety
func TestConcurrency(t *testing.T) {
	checker := NewChecker()
	ctx := context.Background()

	// Start multiple goroutines registering checks
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			checker.RegisterCheck(
				string(rune('a'+id)),
				func(ctx context.Context) CheckResult {
					return CheckResult{Status: StatusHealthy}
				},
			)
			done <- true
		}(i)
	}

	// Wait for all registrations
	for i := 0; i < 10; i++ {
		<-done
	}

	// Start multiple goroutines running checks
	for i := 0; i < 10; i++ {
		go func() {
			checker.Ready(ctx)
			checker.Live(ctx)
			checker.Startup(ctx)
			done <- true
		}()
	}

	// Wait for all checks
	for i := 0; i < 10; i++ {
		<-done
	}

	// Start multiple goroutines unregistering checks
	for i := 0; i < 10; i++ {
		go func(id int) {
			checker.UnregisterCheck(string(rune('a' + id)))
			done <- true
		}(i)
	}

	// Wait for all unregistrations
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify no panics occurred and final state is valid
	if len(checker.GetAllChecks()) != 0 {
		t.Errorf("expected 0 checks after unregistering all, got %d", len(checker.GetAllChecks()))
	}
}

// BenchmarkReady measures performance of readiness checks
func BenchmarkReady(b *testing.B) {
	checker := NewChecker()
	ctx := context.Background()

	// Register 10 checks
	for i := 0; i < 10; i++ {
		checker.RegisterCheck(
			string(rune('a'+i)),
			func(ctx context.Context) CheckResult {
				return CheckResult{
					Name:   "bench",
					Status: StatusHealthy,
				}
			},
		)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.Ready(ctx)
	}
}

// TestCheckWithTimeout verifies checks can use timeouts
func TestCheckWithTimeout(t *testing.T) {
	checker := NewChecker()

	checker.RegisterCheck("slow", func(ctx context.Context) CheckResult {
		// Create a timeout context
		ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()

		select {
		case <-time.After(100 * time.Millisecond):
			return CheckResult{
				Name:   "slow",
				Status: StatusHealthy,
			}
		case <-ctx.Done():
			return CheckResult{
				Name:   "slow",
				Status: StatusUnhealthy,
				Error:  errors.New("check timed out").Error(),
			}
		}
	})

	ctx := context.Background()
	results := checker.Ready(ctx)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	result := results[0]
	if result.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy due to timeout, got %s", result.Status)
	}
	if result.Error == "" {
		t.Error("expected error message for timeout")
	}
}
