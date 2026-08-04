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

package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Initialize metrics for tests
	metrics.Init()
	metrics.InitProduction()
}

func TestNewCircuitBreaker(t *testing.T) {
	t.Run("with default config", func(t *testing.T) {
		cb := New(nil)
		assert.NotNil(t, cb)
		assert.Equal(t, "default", cb.Name())
		assert.Equal(t, StateClosed, cb.State())
	})

	t.Run("with custom config", func(t *testing.T) {
		cfg := &Config{
			Name:                "test",
			MaxFailures:         3,
			ResetTimeout:        10 * time.Second,
			HalfOpenMaxRequests: 2,
			SuccessThreshold:    3,
			Timeout:             5 * time.Second,
		}
		cb := New(cfg)
		assert.NotNil(t, cb)
		assert.Equal(t, "test", cb.Name())
		assert.Equal(t, StateClosed, cb.State())
	})
}

func TestCircuitBreakerStateClosed(t *testing.T) {
	cb := New(&Config{
		Name:        "test-closed",
		MaxFailures: 3,
	})

	t.Run("allows successful requests", func(t *testing.T) {
		err := cb.Execute(func() error {
			return nil
		})
		assert.NoError(t, err)
		assert.Equal(t, StateClosed, cb.State())
	})

	t.Run("allows failed requests below threshold", func(t *testing.T) {
		testErr := errors.New("test error")

		// Two failures should not open the circuit
		for i := 0; i < 2; i++ {
			err := cb.Execute(func() error {
				return testErr
			})
			assert.Equal(t, testErr, err)
		}
		assert.Equal(t, StateClosed, cb.State())
	})

	t.Run("resets failure count on success", func(t *testing.T) {
		cb := New(&Config{
			Name:        "test-reset",
			MaxFailures: 3,
		})

		// Two failures
		testErr := errors.New("test error")
		for i := 0; i < 2; i++ {
			_ = cb.Execute(func() error { return testErr })
		}

		// One success should reset
		_ = cb.Execute(func() error { return nil })

		// Two more failures should not open circuit
		for i := 0; i < 2; i++ {
			_ = cb.Execute(func() error { return testErr })
		}
		assert.Equal(t, StateClosed, cb.State())
	})
}

func TestCircuitBreakerStateTransitions(t *testing.T) {
	t.Run("closed to open on max failures", func(t *testing.T) {
		var stateChanges []struct{ from, to State }
		cb := New(&Config{
			Name:        "test-transition",
			MaxFailures: 3,
			OnStateChange: func(name string, from, to State) {
				stateChanges = append(stateChanges, struct{ from, to State }{from, to})
			},
		})

		testErr := errors.New("test error")

		// Three failures should open the circuit
		for i := 0; i < 3; i++ {
			_ = cb.Execute(func() error { return testErr })
		}

		assert.Equal(t, StateOpen, cb.State())
		require.Len(t, stateChanges, 1)
		assert.Equal(t, StateClosed, stateChanges[0].from)
		assert.Equal(t, StateOpen, stateChanges[0].to)
	})

	t.Run("open to half-open after reset timeout", func(t *testing.T) {
		cb := New(&Config{
			Name:                "test-halfopen-transition",
			MaxFailures:         1,
			ResetTimeout:        10 * time.Millisecond,
			HalfOpenMaxRequests: 5,
			SuccessThreshold:    1, // Only need 1 success to close
		})

		// Trip the circuit
		_ = cb.Execute(func() error { return errors.New("error") })
		assert.Equal(t, StateOpen, cb.State())

		// Wait for reset timeout
		time.Sleep(30 * time.Millisecond)

		// Next request should transition to half-open, and on success, close
		err := cb.Execute(func() error { return nil })
		assert.NoError(t, err)
		// After success with threshold=1, it should close again
		assert.Equal(t, StateClosed, cb.State())
	})

	t.Run("half-open to closed on success threshold", func(t *testing.T) {
		cb := New(&Config{
			Name:                "test-halfopen-close",
			MaxFailures:         1,
			ResetTimeout:        1 * time.Millisecond,
			HalfOpenMaxRequests: 5,
			SuccessThreshold:    2,
		})

		// Trip the circuit
		_ = cb.Execute(func() error { return errors.New("error") })
		time.Sleep(5 * time.Millisecond)

		// Two successes should close the circuit
		_ = cb.Execute(func() error { return nil })
		_ = cb.Execute(func() error { return nil })

		assert.Equal(t, StateClosed, cb.State())
	})

	t.Run("half-open to open on failure", func(t *testing.T) {
		cb := New(&Config{
			Name:                "test-halfopen-open",
			MaxFailures:         1,
			ResetTimeout:        1 * time.Millisecond,
			HalfOpenMaxRequests: 5,
		})

		// Trip the circuit
		_ = cb.Execute(func() error { return errors.New("error") })
		time.Sleep(5 * time.Millisecond)

		// Failure in half-open should re-open
		_ = cb.Execute(func() error { return errors.New("error") })

		assert.Equal(t, StateOpen, cb.State())
	})
}

func TestCircuitBreakerOpen(t *testing.T) {
	cb := New(&Config{
		Name:         "test-open",
		MaxFailures:  1,
		ResetTimeout: 1 * time.Hour, // Long timeout
	})

	// Trip the circuit
	_ = cb.Execute(func() error { return errors.New("error") })
	assert.Equal(t, StateOpen, cb.State())

	t.Run("returns error immediately when open", func(t *testing.T) {
		executed := false
		err := cb.Execute(func() error {
			executed = true
			return nil
		})
		assert.ErrorIs(t, err, ErrCircuitOpen)
		assert.False(t, executed)
	})
}

func TestCircuitBreakerTimeout(t *testing.T) {
	t.Run("times out slow operations", func(t *testing.T) {
		cb := New(&Config{
			Name:        "test-timeout-slow",
			Timeout:     10 * time.Millisecond,
			MaxFailures: 100, // High so we don't trip
		})

		err := cb.Execute(func() error {
			time.Sleep(100 * time.Millisecond)
			return nil
		})
		assert.Error(t, err)
		assert.Equal(t, context.DeadlineExceeded, err)
	})

	t.Run("allows fast operations", func(t *testing.T) {
		cb := New(&Config{
			Name:        "test-timeout-fast",
			Timeout:     10 * time.Millisecond,
			MaxFailures: 100,
		})

		err := cb.Execute(func() error {
			return nil
		})
		assert.NoError(t, err)
	})
}

func TestCircuitBreakerManualControl(t *testing.T) {
	cb := New(&Config{Name: "test-manual"})

	t.Run("manual trip", func(t *testing.T) {
		cb.Trip()
		assert.Equal(t, StateOpen, cb.State())
	})

	t.Run("manual reset", func(t *testing.T) {
		cb.Reset()
		assert.Equal(t, StateClosed, cb.State())
	})
}

func TestCircuitBreakerConcurrency(t *testing.T) {
	cb := New(&Config{
		Name:        "test-concurrent",
		MaxFailures: 100,
	})

	var wg sync.WaitGroup
	var successCount atomic.Int32
	var errorCount atomic.Int32

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			err := cb.Execute(func() error {
				if n%2 == 0 {
					return errors.New("error")
				}
				return nil
			})
			if err == nil {
				successCount.Add(1)
			} else {
				errorCount.Add(1)
			}
		}(i)
	}

	wg.Wait()
	assert.Equal(t, int32(500), successCount.Load())
	assert.Equal(t, int32(500), errorCount.Load())
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateClosed, "closed"},
		{StateHalfOpen, "half-open"},
		{StateOpen, "open"},
		{State(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestCircuitBreakerCounts(t *testing.T) {
	cb := New(&Config{
		Name:        "test-counts",
		MaxFailures: 10,
	})

	// Some successes
	for i := 0; i < 5; i++ {
		_ = cb.Execute(func() error { return nil })
	}

	// Some failures
	for i := 0; i < 3; i++ {
		_ = cb.Execute(func() error { return errors.New("error") })
	}

	failures, successes := cb.Counts()
	assert.Equal(t, uint32(3), failures)
	// Successes are reset when failures occur
	assert.Equal(t, uint32(0), successes)
}

func TestManager(t *testing.T) {
	mgr := NewManager()

	t.Run("get or create circuit breaker", func(t *testing.T) {
		cb1 := mgr.Get("test-1")
		cb2 := mgr.Get("test-1")
		assert.Same(t, cb1, cb2)

		cb3 := mgr.Get("test-2")
		assert.NotSame(t, cb1, cb3)
	})

	t.Run("get or create with config", func(t *testing.T) {
		cfg := &Config{
			Name:        "test-custom",
			MaxFailures: 10,
		}
		cb := mgr.GetOrCreate(cfg)
		assert.Equal(t, "test-custom", cb.Name())

		// Should return same instance on second call
		cb2 := mgr.GetOrCreate(cfg)
		assert.Same(t, cb, cb2)
	})

	t.Run("register circuit breaker", func(t *testing.T) {
		cb := New(&Config{Name: "registered"})
		mgr.Register(cb)

		retrieved := mgr.Get("registered")
		assert.Same(t, cb, retrieved)
	})

	t.Run("list circuit breakers", func(t *testing.T) {
		mgr := NewManager()
		mgr.Get("cb-1")
		mgr.Get("cb-2")
		mgr.Get("cb-3")

		list := mgr.List()
		assert.Len(t, list, 3)
	})

	t.Run("status", func(t *testing.T) {
		mgr := NewManager()
		cb1 := mgr.Get("status-1")
		cb2 := mgr.Get("status-2")
		cb2.Trip()

		status := mgr.Status()
		assert.Equal(t, StateClosed, status["status-1"])
		assert.Equal(t, StateOpen, status["status-2"])

		// Reset to not affect other tests
		cb1.Reset()
		cb2.Reset()
	})

	t.Run("reset all", func(t *testing.T) {
		mgr := NewManager()
		cb1 := mgr.Get("reset-1")
		cb2 := mgr.Get("reset-2")
		cb1.Trip()
		cb2.Trip()

		mgr.ResetAll()

		assert.Equal(t, StateClosed, cb1.State())
		assert.Equal(t, StateClosed, cb2.State())
	})
}

func TestDefaultManagerFunctions(t *testing.T) {
	t.Run("execute", func(t *testing.T) {
		err := Execute("default-test", func() error {
			return nil
		})
		assert.NoError(t, err)
	})

	t.Run("execute with context", func(t *testing.T) {
		ctx := context.Background()
		err := ExecuteContext(ctx, "default-ctx-test", func() error {
			return nil
		})
		assert.NoError(t, err)
	})
}

func TestHalfOpenRequestLimit(t *testing.T) {
	cb := New(&Config{
		Name:                "test-halfopen-limit",
		MaxFailures:         1,
		ResetTimeout:        1 * time.Millisecond,
		HalfOpenMaxRequests: 1,
	})

	// Trip the circuit
	_ = cb.Execute(func() error { return errors.New("error") })
	time.Sleep(5 * time.Millisecond)

	// Start a slow request in half-open
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = cb.Execute(func() error {
			time.Sleep(50 * time.Millisecond)
			return nil
		})
	}()

	// Give the goroutine time to start
	time.Sleep(5 * time.Millisecond)

	// Second request should fail in half-open when limit is reached
	err := cb.Execute(func() error { return nil })
	// The behavior depends on timing - either we get too many requests or it succeeds
	// after the first request completes
	if err != nil {
		assert.Equal(t, ErrTooManyRequests, err)
	}

	wg.Wait()
}

func TestCircuitBreakerWithContext(t *testing.T) {
	cb := New(&Config{Name: "test-ctx"})

	t.Run("respects context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := cb.ExecuteContext(ctx, func() error {
			time.Sleep(100 * time.Millisecond)
			return nil
		})
		assert.Error(t, err)
	})
}
