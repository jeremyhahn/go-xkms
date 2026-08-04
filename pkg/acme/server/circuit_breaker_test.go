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
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCircuitState_String(t *testing.T) {
	tests := []struct {
		state    CircuitState
		expected string
	}{
		{CircuitStateClosed, "closed"},
		{CircuitStateOpen, "open"},
		{CircuitStateHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestDefaultCircuitBreakerConfig(t *testing.T) {
	config := DefaultCircuitBreakerConfig("test-breaker")

	require.Equal(t, "test-breaker", config.Name)
	require.Equal(t, uint32(5), config.FailureThreshold)
	require.Equal(t, uint32(2), config.SuccessThreshold)
	require.Equal(t, 30*time.Second, config.Timeout)
	require.Equal(t, uint32(1), config.MaxHalfOpenRequests)
}

func TestNewCircuitBreaker(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		cb := NewCircuitBreaker(nil)

		require.NotNil(t, cb)
		require.Equal(t, "default", cb.Name())
		require.Equal(t, CircuitStateClosed, cb.State())
		require.Equal(t, uint32(5), cb.config.FailureThreshold)
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			Name:                "custom",
			FailureThreshold:    10,
			SuccessThreshold:    3,
			Timeout:             time.Minute,
			MaxHalfOpenRequests: 2,
		}

		cb := NewCircuitBreaker(config)

		require.Equal(t, "custom", cb.Name())
		require.Equal(t, uint32(10), cb.config.FailureThreshold)
		require.Equal(t, uint32(3), cb.config.SuccessThreshold)
		require.Equal(t, time.Minute, cb.config.Timeout)
		require.Equal(t, uint32(2), cb.config.MaxHalfOpenRequests)
	})

	t.Run("applies defaults for zero values", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			Name: "partial",
		}

		cb := NewCircuitBreaker(config)

		require.Equal(t, uint32(5), cb.config.FailureThreshold)
		require.Equal(t, uint32(2), cb.config.SuccessThreshold)
		require.Equal(t, 30*time.Second, cb.config.Timeout)
		require.Equal(t, uint32(1), cb.config.MaxHalfOpenRequests)
	})
}

func TestCircuitBreaker_ClosedState(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:             "test",
		FailureThreshold: 3,
	})

	t.Run("allows requests when closed", func(t *testing.T) {
		err := cb.Allow()
		require.NoError(t, err)
		require.Equal(t, CircuitStateClosed, cb.State())
	})

	t.Run("stays closed on success", func(t *testing.T) {
		cb.Success()
		require.Equal(t, CircuitStateClosed, cb.State())
	})

	t.Run("counts consecutive failures", func(t *testing.T) {
		cb.Failure()
		require.Equal(t, CircuitStateClosed, cb.State())
		require.Equal(t, uint32(1), cb.consecutiveFailures.Load())

		cb.Failure()
		require.Equal(t, CircuitStateClosed, cb.State())
		require.Equal(t, uint32(2), cb.consecutiveFailures.Load())
	})

	t.Run("resets failure count on success", func(t *testing.T) {
		cb.Success()
		require.Equal(t, uint32(0), cb.consecutiveFailures.Load())
	})
}

func TestCircuitBreaker_OpensOnFailureThreshold(t *testing.T) {
	var stateChanges []CircuitState
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:             "test",
		FailureThreshold: 3,
		OnStateChange: func(name string, from, to CircuitState) {
			stateChanges = append(stateChanges, to)
		},
	})

	// Initial state is closed
	require.Equal(t, CircuitStateClosed, cb.State())

	// Record failures
	cb.Failure()
	cb.Failure()
	require.Equal(t, CircuitStateClosed, cb.State())

	// Third failure should open the circuit
	cb.Failure()
	require.Equal(t, CircuitStateOpen, cb.State())
	require.Len(t, stateChanges, 1)
	require.Equal(t, CircuitStateOpen, stateChanges[0])
}

func TestCircuitBreaker_OpenState(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:             "test",
		FailureThreshold: 1,
		Timeout:          100 * time.Millisecond,
	})

	// Open the circuit
	cb.Failure()
	require.Equal(t, CircuitStateOpen, cb.State())

	t.Run("rejects requests when open", func(t *testing.T) {
		err := cb.Allow()
		require.Equal(t, ErrCircuitOpen, err)
	})

	t.Run("tracks rejected requests", func(t *testing.T) {
		metrics := cb.Metrics()
		require.Greater(t, metrics.RejectedRequests.Load(), uint64(0))
	})
}

func TestCircuitBreaker_TransitionsToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:                "test",
		FailureThreshold:    1,
		Timeout:             50 * time.Millisecond,
		MaxHalfOpenRequests: 1,
	})

	// Open the circuit
	cb.Failure()
	require.Equal(t, CircuitStateOpen, cb.State())

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	// Next request should transition to half-open and be allowed
	err := cb.Allow()
	require.NoError(t, err)
	require.Equal(t, CircuitStateHalfOpen, cb.State())
}

func TestCircuitBreaker_HalfOpenState(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:                "test",
		FailureThreshold:    1,
		SuccessThreshold:    2,
		Timeout:             10 * time.Millisecond,
		MaxHalfOpenRequests: 1,
	})

	// Open the circuit
	cb.Failure()
	time.Sleep(20 * time.Millisecond)

	// Transition to half-open
	err := cb.Allow()
	require.NoError(t, err)
	require.Equal(t, CircuitStateHalfOpen, cb.State())

	t.Run("limits requests in half-open", func(t *testing.T) {
		// Second request should be rejected
		err := cb.Allow()
		require.Equal(t, ErrCircuitHalfOpenMaxRequests, err)
	})
}

func TestCircuitBreaker_ClosesOnSuccessThreshold(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:                "test",
		FailureThreshold:    1,
		SuccessThreshold:    2,
		Timeout:             10 * time.Millisecond,
		MaxHalfOpenRequests: 2,
	})

	// Open the circuit
	cb.Failure()
	time.Sleep(20 * time.Millisecond)

	// Transition to half-open
	_ = cb.Allow()
	require.Equal(t, CircuitStateHalfOpen, cb.State())

	// First success
	cb.Success()
	require.Equal(t, CircuitStateHalfOpen, cb.State())

	// Get another request slot
	_ = cb.Allow()

	// Second success should close the circuit
	cb.Success()
	require.Equal(t, CircuitStateClosed, cb.State())
}

func TestCircuitBreaker_ReopensOnHalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:                "test",
		FailureThreshold:    1,
		SuccessThreshold:    2,
		Timeout:             10 * time.Millisecond,
		MaxHalfOpenRequests: 1,
	})

	// Open the circuit
	cb.Failure()
	time.Sleep(20 * time.Millisecond)

	// Transition to half-open
	_ = cb.Allow()
	require.Equal(t, CircuitStateHalfOpen, cb.State())

	// Failure in half-open should reopen
	cb.Failure()
	require.Equal(t, CircuitStateOpen, cb.State())
}

func TestCircuitBreaker_Execute(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:             "test",
		FailureThreshold: 3,
	})

	t.Run("executes function and records success", func(t *testing.T) {
		var called bool
		err := cb.Execute(func() error {
			called = true
			return nil
		})

		require.NoError(t, err)
		require.True(t, called)
		require.Equal(t, uint64(1), cb.Metrics().SuccessfulRequests.Load())
	})

	t.Run("executes function and records failure", func(t *testing.T) {
		testErr := errors.New("test error")
		err := cb.Execute(func() error {
			return testErr
		})

		require.Equal(t, testErr, err)
		require.Equal(t, uint64(1), cb.Metrics().FailedRequests.Load())
	})

	t.Run("returns error when circuit is open", func(t *testing.T) {
		cb.ForceOpen()

		var called bool
		err := cb.Execute(func() error {
			called = true
			return nil
		})

		require.Equal(t, ErrCircuitOpen, err)
		require.False(t, called)
	})
}

func TestCircuitBreaker_ExecuteWithContext(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:             "test",
		FailureThreshold: 3,
	})

	t.Run("executes function with context", func(t *testing.T) {
		ctx := context.Background()
		var receivedCtx context.Context

		err := cb.ExecuteWithContext(ctx, func(c context.Context) error {
			receivedCtx = c
			return nil
		})

		require.NoError(t, err)
		require.NotNil(t, receivedCtx)
	})

	t.Run("fails immediately on canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		var called bool
		err := cb.ExecuteWithContext(ctx, func(c context.Context) error {
			called = true
			return nil
		})

		require.Equal(t, context.Canceled, err)
		require.False(t, called)
	})
}

func TestCircuitBreaker_Reset(t *testing.T) {
	var stateChanges []CircuitState
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:             "test",
		FailureThreshold: 1,
		OnStateChange: func(name string, from, to CircuitState) {
			stateChanges = append(stateChanges, to)
		},
	})

	// Open the circuit
	cb.Failure()
	require.Equal(t, CircuitStateOpen, cb.State())

	// Reset
	cb.Reset()
	require.Equal(t, CircuitStateClosed, cb.State())
	require.Equal(t, uint32(0), cb.consecutiveFailures.Load())
	require.Equal(t, uint32(0), cb.consecutiveSuccesses.Load())
}

func TestCircuitBreaker_ForceOpen(t *testing.T) {
	var stateChanges []CircuitState
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name: "test",
		OnStateChange: func(name string, from, to CircuitState) {
			stateChanges = append(stateChanges, to)
		},
	})

	// Force open from closed
	cb.ForceOpen()
	require.Equal(t, CircuitStateOpen, cb.State())
	require.Len(t, stateChanges, 1)
	require.Equal(t, CircuitStateOpen, stateChanges[0])

	// Force open when already open (should not trigger callback)
	cb.ForceOpen()
	require.Len(t, stateChanges, 1) // Still just one change
}

func TestCircuitBreaker_Metrics(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:             "test",
		FailureThreshold: 10,
	})

	// Make some requests
	for i := 0; i < 5; i++ {
		_ = cb.Allow()
		cb.Success()
	}

	for i := 0; i < 3; i++ {
		_ = cb.Allow()
		cb.Failure()
	}

	metrics := cb.Metrics()
	require.Equal(t, uint64(8), metrics.TotalRequests.Load())
	require.Equal(t, uint64(5), metrics.SuccessfulRequests.Load())
	require.Equal(t, uint64(3), metrics.FailedRequests.Load())
	require.Equal(t, uint32(CircuitStateClosed), metrics.CurrentState.Load())
}

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:             "test",
		FailureThreshold: 1000, // High threshold to avoid opening
	})

	var wg sync.WaitGroup
	numGoroutines := 100
	requestsPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				_ = cb.Allow()
				if j%2 == 0 {
					cb.Success()
				} else {
					cb.Failure()
				}
			}
		}()
	}

	wg.Wait()

	metrics := cb.Metrics()
	total := metrics.SuccessfulRequests.Load() + metrics.FailedRequests.Load()
	require.Equal(t, uint64(numGoroutines*requestsPerGoroutine), total)
}

// Registry tests

func TestNewCircuitBreakerRegistry(t *testing.T) {
	r := NewCircuitBreakerRegistry()
	require.NotNil(t, r)

	breakers := r.List()
	require.Empty(t, breakers)
}

func TestCircuitBreakerRegistry_Register(t *testing.T) {
	r := NewCircuitBreakerRegistry()

	cb := NewCircuitBreaker(&CircuitBreakerConfig{Name: "test"})
	r.Register(cb)

	retrieved := r.Get("test")
	require.Equal(t, cb, retrieved)
}

func TestCircuitBreakerRegistry_Get(t *testing.T) {
	r := NewCircuitBreakerRegistry()

	t.Run("returns nil for non-existent", func(t *testing.T) {
		cb := r.Get("non-existent")
		require.Nil(t, cb)
	})

	t.Run("returns registered breaker", func(t *testing.T) {
		expected := NewCircuitBreaker(&CircuitBreakerConfig{Name: "test"})
		r.Register(expected)

		actual := r.Get("test")
		require.Equal(t, expected, actual)
	})
}

func TestCircuitBreakerRegistry_GetOrCreate(t *testing.T) {
	r := NewCircuitBreakerRegistry()

	t.Run("creates new breaker", func(t *testing.T) {
		cb := r.GetOrCreate("new-breaker")
		require.NotNil(t, cb)
		require.Equal(t, "new-breaker", cb.Name())
	})

	t.Run("returns existing breaker", func(t *testing.T) {
		cb1 := r.GetOrCreate("same-breaker")
		cb2 := r.GetOrCreate("same-breaker")
		require.Equal(t, cb1, cb2)
	})
}

func TestCircuitBreakerRegistry_List(t *testing.T) {
	r := NewCircuitBreakerRegistry()

	r.Register(NewCircuitBreaker(&CircuitBreakerConfig{Name: "a"}))
	r.Register(NewCircuitBreaker(&CircuitBreakerConfig{Name: "b"}))
	r.Register(NewCircuitBreaker(&CircuitBreakerConfig{Name: "c"}))

	list := r.List()
	require.Len(t, list, 3)

	names := make(map[string]bool)
	for _, cb := range list {
		names[cb.Name()] = true
	}
	require.True(t, names["a"])
	require.True(t, names["b"])
	require.True(t, names["c"])
}

func TestCircuitBreakerRegistry_ResetAll(t *testing.T) {
	r := NewCircuitBreakerRegistry()

	cb1 := NewCircuitBreaker(&CircuitBreakerConfig{Name: "a", FailureThreshold: 1})
	cb2 := NewCircuitBreaker(&CircuitBreakerConfig{Name: "b", FailureThreshold: 1})

	r.Register(cb1)
	r.Register(cb2)

	// Open both
	cb1.Failure()
	cb2.Failure()
	require.Equal(t, CircuitStateOpen, cb1.State())
	require.Equal(t, CircuitStateOpen, cb2.State())

	// Reset all
	r.ResetAll()
	require.Equal(t, CircuitStateClosed, cb1.State())
	require.Equal(t, CircuitStateClosed, cb2.State())
}

func TestCircuitBreakerRegistry_ConcurrentAccess(t *testing.T) {
	r := NewCircuitBreakerRegistry()

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent registration
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			name := "breaker-" + formatInt(n)
			cb := NewCircuitBreaker(&CircuitBreakerConfig{Name: name})
			r.Register(cb)
		}(i)
	}

	wg.Wait()

	// Verify all were registered
	list := r.List()
	require.Len(t, list, numGoroutines)
}

// Middleware tests

func TestCircuitBreakerMiddleware(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:             "test",
		FailureThreshold: 2,
		Timeout:          50 * time.Millisecond,
	})

	t.Run("allows requests when closed", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := CircuitBreakerMiddleware(cb)
		wrappedHandler := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("records success for 2xx-4xx responses", func(t *testing.T) {
		cb.Reset()
		initialSuccess := cb.Metrics().SuccessfulRequests.Load()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		})

		middleware := CircuitBreakerMiddleware(cb)
		wrappedHandler := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		require.Greater(t, cb.Metrics().SuccessfulRequests.Load(), initialSuccess)
	})

	t.Run("records failure for 5xx responses", func(t *testing.T) {
		cb.Reset()
		initialFailures := cb.Metrics().FailedRequests.Load()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		middleware := CircuitBreakerMiddleware(cb)
		wrappedHandler := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		require.Greater(t, cb.Metrics().FailedRequests.Load(), initialFailures)
	})

	t.Run("returns 503 when circuit is open", func(t *testing.T) {
		cb.ForceOpen()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := CircuitBreakerMiddleware(cb)
		wrappedHandler := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.NotEmpty(t, w.Header().Get("Retry-After"))
		require.Contains(t, w.Body.String(), "service_unavailable")
	})
}

func TestCircuitBreakerResponseWriter(t *testing.T) {
	t.Run("captures status code", func(t *testing.T) {
		inner := httptest.NewRecorder()
		wrapped := &circuitBreakerResponseWriter{
			ResponseWriter: inner,
			statusCode:     http.StatusOK,
		}

		wrapped.WriteHeader(http.StatusTeapot)

		require.Equal(t, http.StatusTeapot, wrapped.statusCode)
		require.Equal(t, http.StatusTeapot, inner.Code)
	})

	t.Run("defaults to 200", func(t *testing.T) {
		inner := httptest.NewRecorder()
		wrapped := &circuitBreakerResponseWriter{
			ResponseWriter: inner,
			statusCode:     http.StatusOK,
		}

		require.Equal(t, http.StatusOK, wrapped.statusCode)
	})
}

func TestWriteCircuitBreakerError(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:    "test",
		Timeout: 30 * time.Second,
	})

	w := httptest.NewRecorder()
	writeCircuitBreakerError(w, cb)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	retryAfter := w.Header().Get("Retry-After")
	require.NotEmpty(t, retryAfter)

	body := w.Body.String()
	require.Contains(t, body, "service_unavailable")
	require.Contains(t, body, "Circuit breaker is open")
}

func TestCircuitBreaker_StateChangeCallback(t *testing.T) {
	var changes []struct {
		name string
		from CircuitState
		to   CircuitState
	}

	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:             "test",
		FailureThreshold: 1,
		SuccessThreshold: 1,
		Timeout:          10 * time.Millisecond,
		OnStateChange: func(name string, from, to CircuitState) {
			changes = append(changes, struct {
				name string
				from CircuitState
				to   CircuitState
			}{name, from, to})
		},
	})

	// Open the circuit
	cb.Failure()
	require.Len(t, changes, 1)
	require.Equal(t, "test", changes[0].name)
	require.Equal(t, CircuitStateClosed, changes[0].from)
	require.Equal(t, CircuitStateOpen, changes[0].to)

	// Wait and transition to half-open
	time.Sleep(20 * time.Millisecond)
	_ = cb.Allow()
	require.Len(t, changes, 2)
	require.Equal(t, CircuitStateOpen, changes[1].from)
	require.Equal(t, CircuitStateHalfOpen, changes[1].to)

	// Close the circuit
	cb.Success()
	require.Len(t, changes, 3)
	require.Equal(t, CircuitStateHalfOpen, changes[2].from)
	require.Equal(t, CircuitStateClosed, changes[2].to)
}

func TestCircuitBreaker_RaceConditions(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		Name:                "test",
		FailureThreshold:    5,
		SuccessThreshold:    2,
		Timeout:             10 * time.Millisecond,
		MaxHalfOpenRequests: 3,
	})

	var wg sync.WaitGroup
	var successCount, failureCount, rejectedCount atomic.Int64

	// Run concurrent operations
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				err := cb.Allow()
				if err != nil {
					rejectedCount.Add(1)
					continue
				}

				if j%3 == 0 {
					cb.Failure()
					failureCount.Add(1)
				} else {
					cb.Success()
					successCount.Add(1)
				}

				// Occasionally reset
				if j%50 == 0 {
					cb.Reset()
				}
			}
		}()
	}

	wg.Wait()

	// Just verify it completed without panicking
	metrics := cb.Metrics()
	require.NotNil(t, metrics)

	t.Logf("Successes: %d, Failures: %d, Rejected: %d",
		successCount.Load(), failureCount.Load(), rejectedCount.Load())
}
