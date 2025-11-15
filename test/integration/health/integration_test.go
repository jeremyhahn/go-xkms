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

//go:build integration

package health

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/health"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHealthCheckerLivenessIntegration tests liveness probe
func TestHealthCheckerLivenessIntegration(t *testing.T) {
	checker := health.NewChecker()
	ctx := context.Background()

	// Liveness should always succeed if process is running
	result := checker.Live(ctx)
	assert.Equal(t, "liveness", result.Name)
	assert.Equal(t, health.StatusHealthy, result.Status)
	assert.Equal(t, "Service is alive", result.Message)
	assert.Greater(t, result.Latency, time.Duration(0))
}

// TestHealthCheckerReadinessIntegration tests readiness probe
func TestHealthCheckerReadinessIntegration(t *testing.T) {
	checker := health.NewChecker()
	ctx := context.Background()

	t.Run("NoChecksRegistered", func(t *testing.T) {
		results := checker.Ready(ctx)
		require.Len(t, results, 1, "Should have default result")
		assert.Equal(t, "default", results[0].Name)
		assert.Equal(t, health.StatusHealthy, results[0].Status)
		assert.Contains(t, results[0].Message, "No readiness checks")
	})

	t.Run("WithHealthyChecks", func(t *testing.T) {
		checker := health.NewChecker()

		// Register healthy checks
		checker.RegisterCheck("database", func(ctx context.Context) health.CheckResult {
			return health.CheckResult{
				Name:    "database",
				Status:  health.StatusHealthy,
				Message: "Database connection OK",
			}
		})

		checker.RegisterCheck("cache", func(ctx context.Context) health.CheckResult {
			return health.CheckResult{
				Name:    "cache",
				Status:  health.StatusHealthy,
				Message: "Cache connection OK",
			}
		})

		results := checker.Ready(ctx)
		require.Len(t, results, 2, "Should have 2 check results")

		// Verify both checks are healthy
		for _, result := range results {
			assert.Equal(t, health.StatusHealthy, result.Status)
			assert.Greater(t, result.Latency, time.Duration(0))
		}
	})

	t.Run("WithUnhealthyCheck", func(t *testing.T) {
		checker := health.NewChecker()

		// Register one healthy and one unhealthy check
		checker.RegisterCheck("healthy-service", func(ctx context.Context) health.CheckResult {
			return health.CheckResult{
				Name:    "healthy-service",
				Status:  health.StatusHealthy,
				Message: "Service is OK",
			}
		})

		checker.RegisterCheck("unhealthy-service", func(ctx context.Context) health.CheckResult {
			return health.CheckResult{
				Name:    "unhealthy-service",
				Status:  health.StatusUnhealthy,
				Message: "Service connection failed",
				Error:   "connection timeout",
			}
		})

		results := checker.Ready(ctx)
		require.Len(t, results, 2, "Should have 2 check results")

		// Find the unhealthy check
		var foundUnhealthy bool
		for _, result := range results {
			if result.Name == "unhealthy-service" {
				foundUnhealthy = true
				assert.Equal(t, health.StatusUnhealthy, result.Status)
				assert.NotEmpty(t, result.Error)
			}
		}
		assert.True(t, foundUnhealthy, "Should find unhealthy check")
	})

	t.Run("WithDegradedCheck", func(t *testing.T) {
		checker := health.NewChecker()

		checker.RegisterCheck("degraded-service", func(ctx context.Context) health.CheckResult {
			return health.CheckResult{
				Name:    "degraded-service",
				Status:  health.StatusDegraded,
				Message: "Service running with reduced capacity",
			}
		})

		results := checker.Ready(ctx)
		require.Len(t, results, 1, "Should have 1 check result")
		assert.Equal(t, health.StatusDegraded, results[0].Status)
	})
}

// TestHealthCheckerStartupIntegration tests startup probe
func TestHealthCheckerStartupIntegration(t *testing.T) {
	checker := health.NewChecker()
	ctx := context.Background()

	t.Run("NotStarted", func(t *testing.T) {
		result := checker.Startup(ctx)
		assert.Equal(t, "startup", result.Name)
		assert.Equal(t, health.StatusUnhealthy, result.Status)
		assert.Contains(t, result.Message, "not complete")
		assert.False(t, checker.IsStarted())
	})

	t.Run("Started", func(t *testing.T) {
		checker.MarkStarted()
		result := checker.Startup(ctx)
		assert.Equal(t, "startup", result.Name)
		assert.Equal(t, health.StatusHealthy, result.Status)
		assert.Contains(t, result.Message, "fully initialized")
		assert.True(t, checker.IsStarted())

		// Verify uptime is reported
		assert.Contains(t, result.Message, "uptime:")
	})

	t.Run("MarkNotStarted", func(t *testing.T) {
		checker.MarkNotStarted()
		result := checker.Startup(ctx)
		assert.Equal(t, health.StatusUnhealthy, result.Status)
		assert.False(t, checker.IsStarted())
	})
}

// TestHealthCheckerRegisterUnregisterIntegration tests check registration
func TestHealthCheckerRegisterUnregisterIntegration(t *testing.T) {
	checker := health.NewChecker()
	ctx := context.Background()

	// Register a check
	checkCalled := false
	checker.RegisterCheck("test-check", func(ctx context.Context) health.CheckResult {
		checkCalled = true
		return health.CheckResult{
			Name:   "test-check",
			Status: health.StatusHealthy,
		}
	})

	// Verify check is registered
	checks := checker.GetAllChecks()
	assert.Contains(t, checks, "test-check")

	// Run readiness check
	results := checker.Ready(ctx)
	assert.True(t, checkCalled, "Check should have been called")
	require.Len(t, results, 1)

	// Unregister the check
	checker.UnregisterCheck("test-check")
	checks = checker.GetAllChecks()
	assert.NotContains(t, checks, "test-check")

	// Readiness should now return default
	results = checker.Ready(ctx)
	require.Len(t, results, 1)
	assert.Equal(t, "default", results[0].Name)
}

// TestHealthCheckerReplaceCheckIntegration tests replacing an existing check
func TestHealthCheckerReplaceCheckIntegration(t *testing.T) {
	checker := health.NewChecker()
	ctx := context.Background()

	// Register first version of check
	checker.RegisterCheck("service", func(ctx context.Context) health.CheckResult {
		return health.CheckResult{
			Name:    "service",
			Status:  health.StatusHealthy,
			Message: "Version 1",
		}
	})

	// Replace with second version
	checker.RegisterCheck("service", func(ctx context.Context) health.CheckResult {
		return health.CheckResult{
			Name:    "service",
			Status:  health.StatusHealthy,
			Message: "Version 2",
		}
	})

	// Should only have one check
	checks := checker.GetAllChecks()
	assert.Len(t, checks, 1)

	// Should use the replaced version
	results := checker.Ready(ctx)
	require.Len(t, results, 1)
	assert.Equal(t, "Version 2", results[0].Message)
}

// TestHealthCheckerNilCheckIntegration tests registering nil check
func TestHealthCheckerNilCheckIntegration(t *testing.T) {
	checker := health.NewChecker()

	// Register nil check (should be ignored)
	checker.RegisterCheck("nil-check", nil)

	// Should have no checks
	checks := checker.GetAllChecks()
	assert.NotContains(t, checks, "nil-check")
}

// TestHealthCheckerIsHealthyIntegration tests IsHealthy method
func TestHealthCheckerIsHealthyIntegration(t *testing.T) {
	ctx := context.Background()

	t.Run("AllHealthy", func(t *testing.T) {
		checker := health.NewChecker()

		checker.RegisterCheck("service1", func(ctx context.Context) health.CheckResult {
			return health.CheckResult{Status: health.StatusHealthy}
		})
		checker.RegisterCheck("service2", func(ctx context.Context) health.CheckResult {
			return health.CheckResult{Status: health.StatusHealthy}
		})

		assert.True(t, checker.IsHealthy(ctx))
	})

	t.Run("OneUnhealthy", func(t *testing.T) {
		checker := health.NewChecker()

		checker.RegisterCheck("healthy", func(ctx context.Context) health.CheckResult {
			return health.CheckResult{Status: health.StatusHealthy}
		})
		checker.RegisterCheck("unhealthy", func(ctx context.Context) health.CheckResult {
			return health.CheckResult{Status: health.StatusUnhealthy}
		})

		assert.False(t, checker.IsHealthy(ctx))
	})

	t.Run("OneDegraded", func(t *testing.T) {
		checker := health.NewChecker()

		checker.RegisterCheck("healthy", func(ctx context.Context) health.CheckResult {
			return health.CheckResult{Status: health.StatusHealthy}
		})
		checker.RegisterCheck("degraded", func(ctx context.Context) health.CheckResult {
			return health.CheckResult{Status: health.StatusDegraded}
		})

		assert.False(t, checker.IsHealthy(ctx))
	})
}

// TestHealthCheckerUptimeIntegration tests uptime tracking
func TestHealthCheckerUptimeIntegration(t *testing.T) {
	checker := health.NewChecker()

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	uptime := checker.Uptime()
	assert.Greater(t, uptime, 100*time.Millisecond)
	assert.Less(t, uptime, 1*time.Second)
}

// TestHealthCheckerAggregateStatusIntegration tests status aggregation
func TestHealthCheckerAggregateStatusIntegration(t *testing.T) {
	tests := []struct {
		name     string
		results  []health.CheckResult
		expected health.Status
	}{
		{
			name: "AllHealthy",
			results: []health.CheckResult{
				{Status: health.StatusHealthy},
				{Status: health.StatusHealthy},
			},
			expected: health.StatusHealthy,
		},
		{
			name: "OneUnhealthy",
			results: []health.CheckResult{
				{Status: health.StatusHealthy},
				{Status: health.StatusUnhealthy},
			},
			expected: health.StatusUnhealthy,
		},
		{
			name: "OneDegraded",
			results: []health.CheckResult{
				{Status: health.StatusHealthy},
				{Status: health.StatusDegraded},
			},
			expected: health.StatusDegraded,
		},
		{
			name: "UnhealthyAndDegraded",
			results: []health.CheckResult{
				{Status: health.StatusUnhealthy},
				{Status: health.StatusDegraded},
			},
			expected: health.StatusUnhealthy,
		},
		{
			name:     "Empty",
			results:  []health.CheckResult{},
			expected: health.StatusHealthy,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := health.AggregateStatus(tc.results)
			assert.Equal(t, tc.expected, status)
		})
	}
}

// TestHealthCheckerConcurrentIntegration tests concurrent health checks
func TestHealthCheckerConcurrentIntegration(t *testing.T) {
	checker := health.NewChecker()
	ctx := context.Background()

	// Register multiple checks
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("check-%d", i)
		checker.RegisterCheck(name, func(ctx context.Context) health.CheckResult {
			// Simulate some work
			time.Sleep(10 * time.Millisecond)
			return health.CheckResult{
				Name:   name,
				Status: health.StatusHealthy,
			}
		})
	}

	// Run checks concurrently
	var wg sync.WaitGroup
	numConcurrent := 20

	wg.Add(numConcurrent)
	for i := 0; i < numConcurrent; i++ {
		go func() {
			defer wg.Done()
			results := checker.Ready(ctx)
			assert.Greater(t, len(results), 0)
		}()
	}

	wg.Wait()
}

// TestHealthCheckerContextCancellationIntegration tests context cancellation
func TestHealthCheckerContextCancellationIntegration(t *testing.T) {
	checker := health.NewChecker()

	// Register a slow check
	checker.RegisterCheck("slow-check", func(ctx context.Context) health.CheckResult {
		select {
		case <-ctx.Done():
			return health.CheckResult{
				Name:    "slow-check",
				Status:  health.StatusUnhealthy,
				Message: "Check cancelled",
				Error:   ctx.Err().Error(),
			}
		case <-time.After(5 * time.Second):
			return health.CheckResult{
				Name:   "slow-check",
				Status: health.StatusHealthy,
			}
		}
	})

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Run checks with cancelled context
	results := checker.Ready(ctx)
	require.Len(t, results, 1)
}

// TestHealthCheckerHTTPHandlerIntegration tests HTTP handler integration
func TestHealthCheckerHTTPHandlerIntegration(t *testing.T) {
	checker := health.NewChecker()
	checker.MarkStarted()

	// Register some checks
	checker.RegisterCheck("service", func(ctx context.Context) health.CheckResult {
		return health.CheckResult{
			Name:    "service",
			Status:  health.StatusHealthy,
			Message: "Service is healthy",
		}
	})

	t.Run("LivenessEndpoint", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result := checker.Live(r.Context())
			w.Header().Set("Content-Type", "application/json")
			if result.Status == health.StatusHealthy {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			json.NewEncoder(w).Encode(result)
		})

		req := httptest.NewRequest("GET", "/health/live", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result health.CheckResult
		err := json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.Equal(t, health.StatusHealthy, result.Status)
	})

	t.Run("ReadinessEndpoint", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			results := checker.Ready(r.Context())
			w.Header().Set("Content-Type", "application/json")

			status := health.AggregateStatus(results)
			if status == health.StatusHealthy {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			json.NewEncoder(w).Encode(results)
		})

		req := httptest.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var results []health.CheckResult
		err := json.NewDecoder(resp.Body).Decode(&results)
		require.NoError(t, err)
		assert.Greater(t, len(results), 0)
	})

	t.Run("StartupEndpoint", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result := checker.Startup(r.Context())
			w.Header().Set("Content-Type", "application/json")
			if result.Status == health.StatusHealthy {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			json.NewEncoder(w).Encode(result)
		})

		req := httptest.NewRequest("GET", "/health/startup", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result health.CheckResult
		err := json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.Equal(t, health.StatusHealthy, result.Status)
	})
}

// TestHealthCheckerRealWorldScenarioIntegration simulates a real-world scenario
func TestHealthCheckerRealWorldScenarioIntegration(t *testing.T) {
	checker := health.NewChecker()
	ctx := context.Background()

	// Simulate service initialization
	assert.False(t, checker.IsStarted(), "Should not be started initially")

	// Register dependency checks
	checker.RegisterCheck("database", func(ctx context.Context) health.CheckResult {
		// Simulate database connection check
		time.Sleep(10 * time.Millisecond)
		return health.CheckResult{
			Name:    "database",
			Status:  health.StatusHealthy,
			Message: "PostgreSQL connection OK",
		}
	})

	checker.RegisterCheck("cache", func(ctx context.Context) health.CheckResult {
		// Simulate cache connection check
		time.Sleep(5 * time.Millisecond)
		return health.CheckResult{
			Name:    "cache",
			Status:  health.StatusHealthy,
			Message: "Redis connection OK",
		}
	})

	checker.RegisterCheck("storage", func(ctx context.Context) health.CheckResult {
		// Simulate storage check
		time.Sleep(15 * time.Millisecond)
		return health.CheckResult{
			Name:    "storage",
			Status:  health.StatusHealthy,
			Message: "S3 bucket accessible",
		}
	})

	// Startup should fail before initialization complete
	startup := checker.Startup(ctx)
	assert.Equal(t, health.StatusUnhealthy, startup.Status)

	// Mark service as started
	checker.MarkStarted()

	// Startup should now succeed
	startup = checker.Startup(ctx)
	assert.Equal(t, health.StatusHealthy, startup.Status)

	// Liveness should always succeed
	liveness := checker.Live(ctx)
	assert.Equal(t, health.StatusHealthy, liveness.Status)

	// Readiness should check all dependencies
	readiness := checker.Ready(ctx)
	assert.Len(t, readiness, 3)

	// All checks should be healthy
	assert.True(t, checker.IsHealthy(ctx))

	// Simulate a degraded dependency
	checker.RegisterCheck("cache", func(ctx context.Context) health.CheckResult {
		return health.CheckResult{
			Name:    "cache",
			Status:  health.StatusDegraded,
			Message: "Redis connection slow",
		}
	})

	// Readiness should now show degraded state
	readiness = checker.Ready(ctx)
	aggregateStatus := health.AggregateStatus(readiness)
	assert.Equal(t, health.StatusDegraded, aggregateStatus)
	assert.False(t, checker.IsHealthy(ctx))

	// Simulate a failed dependency
	checker.RegisterCheck("database", func(ctx context.Context) health.CheckResult {
		return health.CheckResult{
			Name:    "database",
			Status:  health.StatusUnhealthy,
			Message: "Database connection failed",
			Error:   "connection timeout after 30s",
		}
	})

	// Readiness should now show unhealthy state
	readiness = checker.Ready(ctx)
	aggregateStatus = health.AggregateStatus(readiness)
	assert.Equal(t, health.StatusUnhealthy, aggregateStatus)
	assert.False(t, checker.IsHealthy(ctx))

	// Liveness should still succeed (process is still alive)
	liveness = checker.Live(ctx)
	assert.Equal(t, health.StatusHealthy, liveness.Status)

	// Verify uptime is tracked
	uptime := checker.Uptime()
	assert.Greater(t, uptime, time.Duration(0))
}

// TestHealthCheckerLatencyMeasurementIntegration tests latency measurement
func TestHealthCheckerLatencyMeasurementIntegration(t *testing.T) {
	checker := health.NewChecker()
	ctx := context.Background()

	// Register check with known delay
	expectedDelay := 50 * time.Millisecond
	checker.RegisterCheck("slow-service", func(ctx context.Context) health.CheckResult {
		time.Sleep(expectedDelay)
		return health.CheckResult{
			Name:   "slow-service",
			Status: health.StatusHealthy,
		}
	})

	// Run readiness check
	results := checker.Ready(ctx)
	require.Len(t, results, 1)

	// Verify latency was measured
	result := results[0]
	assert.GreaterOrEqual(t, result.Latency, expectedDelay)
	assert.Less(t, result.Latency, expectedDelay+100*time.Millisecond)
}

// TestHealthCheckerMultipleNameSettingIntegration tests check name handling
func TestHealthCheckerMultipleNameSettingIntegration(t *testing.T) {
	checker := health.NewChecker()
	ctx := context.Background()

	// Register check that doesn't set name
	checker.RegisterCheck("auto-name", func(ctx context.Context) health.CheckResult {
		return health.CheckResult{
			Status:  health.StatusHealthy,
			Message: "Check without explicit name",
		}
	})

	// Run readiness check
	results := checker.Ready(ctx)
	require.Len(t, results, 1)

	// Name should be automatically set
	assert.Equal(t, "auto-name", results[0].Name)
}

// TestHealthCheckerJSONSerializationIntegration tests JSON serialization
func TestHealthCheckerJSONSerializationIntegration(t *testing.T) {
	checker := health.NewChecker()
	ctx := context.Background()

	checker.RegisterCheck("test-service", func(ctx context.Context) health.CheckResult {
		return health.CheckResult{
			Name:    "test-service",
			Status:  health.StatusHealthy,
			Message: "Service is OK",
			Latency: 123 * time.Millisecond,
		}
	})

	results := checker.Ready(ctx)
	require.Len(t, results, 1)

	// Serialize to JSON
	data, err := json.Marshal(results[0])
	require.NoError(t, err)

	// Deserialize
	var decoded health.CheckResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "test-service", decoded.Name)
	assert.Equal(t, health.StatusHealthy, decoded.Status)
	assert.Equal(t, "Service is OK", decoded.Message)
}

// TestHealthCheckerKubernetesPatternIntegration tests Kubernetes probe pattern
func TestHealthCheckerKubernetesPatternIntegration(t *testing.T) {
	checker := health.NewChecker()

	// Setup HTTP server with Kubernetes-style endpoints
	mux := http.NewServeMux()

	// Liveness probe - always succeeds if process is running
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		result := checker.Live(r.Context())
		if result.Status == health.StatusHealthy {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "OK")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})

	// Readiness probe - checks dependencies
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		results := checker.Ready(r.Context())
		status := health.AggregateStatus(results)
		if status == health.StatusHealthy {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "OK")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})

	// Startup probe - checks if initialization is complete
	mux.HandleFunc("/startupz", func(w http.ResponseWriter, r *http.Request) {
		result := checker.Startup(r.Context())
		if result.Status == health.StatusHealthy {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "OK")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})

	// Test startup probe before marking started
	req := httptest.NewRequest("GET", "/startupz", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	// Mark service as started
	checker.MarkStarted()

	// Test liveness probe
	req = httptest.NewRequest("GET", "/healthz", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Register a healthy check
	checker.RegisterCheck("backend", func(ctx context.Context) health.CheckResult {
		return health.CheckResult{
			Name:   "backend",
			Status: health.StatusHealthy,
		}
	})

	// Test readiness probe
	req = httptest.NewRequest("GET", "/readyz", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test startup probe
	req = httptest.NewRequest("GET", "/startupz", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
