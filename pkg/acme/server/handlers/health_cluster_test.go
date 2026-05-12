//go:build codec_json

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

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/degradation"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	metrics.Init()
	metrics.InitProduction()
}

func TestNewProductionHealthService(t *testing.T) {
	cbMgr := circuitbreaker.NewManager()
	dm := degradation.NewDegradationManager(nil)

	phs := NewProductionHealthService("1.0.0", nil, cbMgr, dm)

	assert.NotNil(t, phs)
	assert.Equal(t, "1.0.0", phs.version)
}

func TestDetailedHealthHandler(t *testing.T) {
	t.Run("healthy status without cluster", func(t *testing.T) {
		// When cluster service is nil, cluster health is unhealthy which causes degraded status
		cbMgr := circuitbreaker.NewManager()
		dm := degradation.NewDegradationManager(nil)
		phs := NewProductionHealthService("1.0.0", nil, cbMgr, dm)

		// Register healthy components
		phs.RegisterChecker("test", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
			return ComponentHealth{
				Status:  HealthStatusHealthy,
				Message: "Test component is healthy",
			}
		}))

		req := httptest.NewRequest("GET", "/health/detailed", nil)
		rec := httptest.NewRecorder()

		phs.DetailedHealthHandler(rec, req)

		// When cluster service is nil, cluster is unhealthy, causing degraded status
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

		var response DetailedHealthResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		// Status is degraded because cluster is not available
		assert.Equal(t, HealthStatusDegraded, response.Status)
		assert.Equal(t, "1.0.0", response.Version)
		assert.Contains(t, response.Components, "test")
		// Cluster should show unhealthy
		assert.NotNil(t, response.Cluster)
		assert.False(t, response.Cluster.Healthy)
	})

	t.Run("degraded status with open circuit breaker", func(t *testing.T) {
		cbMgr := circuitbreaker.NewManager()
		cb := cbMgr.Get("test-cb")
		cb.Trip() // Force circuit open

		dm := degradation.NewDegradationManager(nil)
		phs := NewProductionHealthService("1.0.0", nil, cbMgr, dm)

		req := httptest.NewRequest("GET", "/health/detailed", nil)
		rec := httptest.NewRecorder()

		phs.DetailedHealthHandler(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

		var response DetailedHealthResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, HealthStatusDegraded, response.Status)
		assert.Contains(t, response.CircuitBreakers, "test-cb")
		assert.Equal(t, "open", response.CircuitBreakers["test-cb"].State)
	})

	t.Run("degraded status with degradation mode active", func(t *testing.T) {
		cbMgr := circuitbreaker.NewManager()
		dm := degradation.NewDegradationManager(nil)
		dm.ForceEnterDegradedMode()

		phs := NewProductionHealthService("1.0.0", nil, cbMgr, dm)

		req := httptest.NewRequest("GET", "/health/detailed", nil)
		rec := httptest.NewRecorder()

		phs.DetailedHealthHandler(rec, req)

		var response DetailedHealthResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, HealthStatusDegraded, response.Status)
		assert.NotNil(t, response.Degradation)
		assert.True(t, response.Degradation.Active)
	})

	t.Run("unhealthy status with failed component", func(t *testing.T) {
		cbMgr := circuitbreaker.NewManager()
		dm := degradation.NewDegradationManager(nil)
		phs := NewProductionHealthService("1.0.0", nil, cbMgr, dm)

		phs.RegisterChecker("failing", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
			return ComponentHealth{
				Status:  HealthStatusUnhealthy,
				Message: "Component is down",
				Error:   "connection refused",
			}
		}))

		req := httptest.NewRequest("GET", "/health/detailed", nil)
		rec := httptest.NewRecorder()

		phs.DetailedHealthHandler(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

		var response DetailedHealthResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, HealthStatusUnhealthy, response.Status)
		assert.Equal(t, HealthStatusUnhealthy, response.Components["failing"].Status)
	})
}

func TestClusterHealthChecker(t *testing.T) {
	t.Run("nil cluster", func(t *testing.T) {
		checker := ClusterHealthChecker(nil)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusUnhealthy, health.Status)
		assert.Contains(t, health.Message, "not configured")
	})
}

func TestCAHealthChecker(t *testing.T) {
	t.Run("nil check function", func(t *testing.T) {
		checker := CAHealthChecker(nil)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusUnhealthy, health.Status)
	})

	t.Run("healthy CA", func(t *testing.T) {
		checker := CAHealthChecker(func() bool { return true })
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusHealthy, health.Status)
		assert.Contains(t, health.Message, "operational")
	})

	t.Run("unhealthy CA", func(t *testing.T) {
		checker := CAHealthChecker(func() bool { return false })
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusUnhealthy, health.Status)
	})
}

func TestStorageHealthChecker(t *testing.T) {
	t.Run("nil check function", func(t *testing.T) {
		checker := StorageHealthChecker(nil)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusUnhealthy, health.Status)
	})

	t.Run("healthy storage", func(t *testing.T) {
		checker := StorageHealthChecker(func(ctx context.Context) error { return nil })
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusHealthy, health.Status)
	})

	t.Run("unhealthy storage", func(t *testing.T) {
		checker := StorageHealthChecker(func(ctx context.Context) error {
			return assert.AnError
		})
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusUnhealthy, health.Status)
		assert.NotEmpty(t, health.Error)
	})
}

func TestNonceStoreHealthChecker(t *testing.T) {
	t.Run("nil check function", func(t *testing.T) {
		checker := NonceStoreHealthChecker(nil)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusDegraded, health.Status)
	})

	t.Run("healthy nonce store", func(t *testing.T) {
		checker := NonceStoreHealthChecker(func() bool { return true })
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusHealthy, health.Status)
	})
}

func TestCircuitBreakerHealthChecker(t *testing.T) {
	t.Run("nil manager", func(t *testing.T) {
		checker := CircuitBreakerHealthChecker(nil)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusHealthy, health.Status)
	})

	t.Run("all closed", func(t *testing.T) {
		mgr := circuitbreaker.NewManager()
		mgr.Get("cb1")
		mgr.Get("cb2")

		checker := CircuitBreakerHealthChecker(mgr)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusHealthy, health.Status)
	})

	t.Run("some open", func(t *testing.T) {
		mgr := circuitbreaker.NewManager()
		cb1 := mgr.Get("healthy-cb")
		cb2 := mgr.Get("tripped-cb")
		_ = cb1
		cb2.Trip()

		checker := CircuitBreakerHealthChecker(mgr)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusDegraded, health.Status)
	})
}

func TestDegradationHealthChecker(t *testing.T) {
	t.Run("nil manager", func(t *testing.T) {
		checker := DegradationHealthChecker(nil)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusHealthy, health.Status)
	})

	t.Run("not degraded", func(t *testing.T) {
		dm := degradation.NewDegradationManager(nil)

		checker := DegradationHealthChecker(dm)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusHealthy, health.Status)
	})

	t.Run("degraded", func(t *testing.T) {
		dm := degradation.NewDegradationManager(nil)
		dm.ForceEnterDegradedMode()

		checker := DegradationHealthChecker(dm)
		health := checker.CheckHealth(context.Background())

		assert.Equal(t, HealthStatusDegraded, health.Status)
	})
}

func TestMetricsHandler(t *testing.T) {
	cbMgr := circuitbreaker.NewManager()
	cbMgr.Get("test-cb")
	dm := degradation.NewDegradationManager(nil)

	phs := NewProductionHealthService("1.0.0", nil, cbMgr, dm)

	req := httptest.NewRequest("GET", "/health/metrics", nil)
	rec := httptest.NewRecorder()

	phs.MetricsHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var response map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Contains(t, response, "timestamp")
	assert.Contains(t, response, "uptime")
	assert.Contains(t, response, "circuit_breakers")
	assert.Contains(t, response, "degradation")
}

func TestStartupProbeHandler(t *testing.T) {
	t.Run("not ready - missing components", func(t *testing.T) {
		phs := NewProductionHealthService("1.0.0", nil, nil, nil)

		req := httptest.NewRequest("GET", "/health/startup", nil)
		rec := httptest.NewRecorder()

		phs.StartupProbeHandler(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})

	t.Run("ready - all components registered", func(t *testing.T) {
		phs := NewProductionHealthService("1.0.0", nil, nil, nil)

		// Register all critical components
		phs.RegisterChecker("ca", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
			return ComponentHealth{Status: HealthStatusHealthy}
		}))
		phs.RegisterChecker("storage", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
			return ComponentHealth{Status: HealthStatusHealthy}
		}))
		phs.RegisterChecker("cluster", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
			return ComponentHealth{Status: HealthStatusHealthy}
		}))

		req := httptest.NewRequest("GET", "/health/startup", nil)
		rec := httptest.NewRecorder()

		phs.StartupProbeHandler(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestFormatCircuitBreakerMessage(t *testing.T) {
	tests := []struct {
		open     int
		halfOpen int
		total    int
		contains []string
	}{
		{0, 0, 3, []string{"3 circuit breakers", "0 open", "0 half-open"}},
		{1, 0, 3, []string{"3 circuit breakers", "1 open", "0 half-open"}},
		{0, 2, 3, []string{"3 circuit breakers", "0 open", "2 half-open"}},
		{1, 1, 3, []string{"3 circuit breakers", "1 open", "1 half-open"}},
	}

	for _, tt := range tests {
		msg := formatCircuitBreakerMessage(tt.open, tt.halfOpen, tt.total)
		for _, contains := range tt.contains {
			assert.Contains(t, msg, contains)
		}
	}
}

func TestProductionHealthServiceConcurrency(t *testing.T) {
	cbMgr := circuitbreaker.NewManager()
	dm := degradation.NewDegradationManager(nil)
	phs := NewProductionHealthService("1.0.0", nil, cbMgr, dm)

	// Register some checkers
	for i := 0; i < 5; i++ {
		name := formatInt(i)
		phs.RegisterChecker("checker-"+name, HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
			time.Sleep(10 * time.Millisecond)
			return ComponentHealth{Status: HealthStatusHealthy}
		}))
	}

	// Make concurrent requests
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/health/detailed", nil)
			rec := httptest.NewRecorder()
			phs.DetailedHealthHandler(rec, req)
			done <- true
		}()
	}

	// Wait for all requests
	for i := 0; i < 10; i++ {
		<-done
	}
}
