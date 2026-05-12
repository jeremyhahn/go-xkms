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
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/degradation"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
)

// ClusterHealthService defines the minimal interface for checking cluster health.
// Any service that can report its health status satisfies this interface.
type ClusterHealthService interface {
	Healthy() bool
}

// DetailedHealthResponse provides comprehensive health status including
// cluster state, circuit breaker status, and degradation mode.
type DetailedHealthResponse struct {
	Status          HealthStatus                    `json:"status"`
	Timestamp       string                          `json:"timestamp"`
	Version         string                          `json:"version,omitempty"`
	Components      map[string]ComponentHealth      `json:"components,omitempty"`
	Cluster         *ClusterHealth                  `json:"cluster,omitempty"`
	CircuitBreakers map[string]CircuitBreakerHealth `json:"circuit_breakers,omitempty"`
	Degradation     *DegradationHealth              `json:"degradation,omitempty"`
}

// ClusterHealth represents the health of the cluster.
type ClusterHealth struct {
	Healthy       bool   `json:"healthy"`
	IsLeader      bool   `json:"is_leader"`
	FollowerCount int    `json:"follower_count"`
	ElectionCount uint64 `json:"election_count"`
	ClusterID     uint64 `json:"cluster_id,omitempty"`
	NodeID        uint64 `json:"node_id,omitempty"`
}

// CircuitBreakerHealth represents the health of a circuit breaker.
type CircuitBreakerHealth struct {
	State        string `json:"state"`
	FailureCount uint32 `json:"failure_count"`
	SuccessCount uint32 `json:"success_count"`
}

// DegradationHealth represents the degradation status.
type DegradationHealth struct {
	Active         bool    `json:"active"`
	ActiveSince    string  `json:"active_since,omitempty"`
	SlowPercentage float64 `json:"slow_percentage"`
	AverageLatency string  `json:"average_latency"`
}

// ProductionHealthService extends HealthService with production features.
type ProductionHealthService struct {
	*HealthService
	clusterService   ClusterHealthService
	cbManager        *circuitbreaker.Manager
	degradation      *degradation.DegradationManager
	metricsCollector *metrics.ClusterMetricsCollector
}

// NewProductionHealthService creates a new production health service.
func NewProductionHealthService(
	version string,
	clusterService ClusterHealthService,
	cbManager *circuitbreaker.Manager,
	degradationMgr *degradation.DegradationManager,
) *ProductionHealthService {
	return &ProductionHealthService{
		HealthService:    NewHealthService(version),
		clusterService:   clusterService,
		cbManager:        cbManager,
		degradation:      degradationMgr,
		metricsCollector: metrics.NewClusterMetricsCollector(),
	}
}

// DetailedHealthHandler returns a comprehensive health check endpoint.
// GET /health/detailed
// Returns detailed status of all components including cluster state.
func (phs *ProductionHealthService) DetailedHealthHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	response := DetailedHealthResponse{
		Status:          HealthStatusHealthy,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Version:         phs.version,
		Components:      make(map[string]ComponentHealth),
		CircuitBreakers: make(map[string]CircuitBreakerHealth),
	}

	// Run component health checks
	phs.mu.RLock()
	checkers := make(map[string]HealthChecker, len(phs.checkers))
	for name, checker := range phs.checkers {
		checkers[name] = checker
	}
	phs.mu.RUnlock()

	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, checker := range checkers {
		wg.Add(1)
		go func(name string, checker HealthChecker) {
			defer wg.Done()
			health := checker.CheckHealth(ctx)
			mu.Lock()
			response.Components[name] = health
			if health.Status == HealthStatusUnhealthy {
				response.Status = HealthStatusUnhealthy
			} else if health.Status == HealthStatusDegraded && response.Status != HealthStatusUnhealthy {
				response.Status = HealthStatusDegraded
			}
			mu.Unlock()
		}(name, checker)
	}

	// Check cluster health
	wg.Add(1)
	go func() {
		defer wg.Done()
		clusterHealth := phs.checkClusterHealth(ctx)
		mu.Lock()
		response.Cluster = clusterHealth
		if !clusterHealth.Healthy {
			if response.Status != HealthStatusUnhealthy {
				response.Status = HealthStatusDegraded
			}
		}
		mu.Unlock()
	}()

	wg.Wait()

	// Add circuit breaker status
	if phs.cbManager != nil {
		for _, cb := range phs.cbManager.List() {
			failures, successes := cb.Counts()
			response.CircuitBreakers[cb.Name()] = CircuitBreakerHealth{
				State:        cb.State().String(),
				FailureCount: failures,
				SuccessCount: successes,
			}

			// If any circuit breaker is open, mark as degraded
			if cb.State() == circuitbreaker.StateOpen {
				if response.Status == HealthStatusHealthy {
					response.Status = HealthStatusDegraded
				}
			}
		}
	}

	// Add degradation status
	if phs.degradation != nil {
		status := phs.degradation.Status()
		response.Degradation = &DegradationHealth{
			Active:         status.Degraded,
			SlowPercentage: status.SlowPercentage,
			AverageLatency: status.AverageLatency.String(),
		}
		if !status.DegradedSince.IsZero() {
			response.Degradation.ActiveSince = status.DegradedSince.Format(time.RFC3339)
		}

		if status.Degraded && response.Status == HealthStatusHealthy {
			response.Status = HealthStatusDegraded
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if response.Status == HealthStatusHealthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	encodeJSONWithLogger(w, response, nil)
}

// checkClusterHealth checks the health of the cluster service.
func (phs *ProductionHealthService) checkClusterHealth(ctx context.Context) *ClusterHealth {
	if phs.clusterService == nil {
		return &ClusterHealth{Healthy: false}
	}

	healthy := phs.clusterService.Healthy()

	// Update metrics
	phs.metricsCollector.UpdateClusterStatus(healthy, false, 0)

	return &ClusterHealth{
		Healthy: healthy,
	}
}

// ClusterHealthChecker creates a health checker for a cluster service.
func ClusterHealthChecker(svc ClusterHealthService) HealthChecker {
	return HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		if svc == nil {
			return ComponentHealth{
				Status:  HealthStatusUnhealthy,
				Message: "Cluster not configured",
			}
		}

		if !svc.Healthy() {
			return ComponentHealth{
				Status:  HealthStatusUnhealthy,
				Message: "Cluster is not healthy",
			}
		}

		return ComponentHealth{
			Status:  HealthStatusHealthy,
			Message: "Cluster is healthy",
		}
	})
}

// CAHealthChecker creates a health checker for the Certificate Authority.
func CAHealthChecker(checkFunc func() bool) HealthChecker {
	return HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		if checkFunc == nil || !checkFunc() {
			return ComponentHealth{
				Status:  HealthStatusUnhealthy,
				Message: "CA is not operational",
			}
		}

		return ComponentHealth{
			Status:  HealthStatusHealthy,
			Message: "CA is operational",
		}
	})
}

// StorageHealthChecker creates a health checker for storage backends.
func StorageHealthChecker(checkFunc func(ctx context.Context) error) HealthChecker {
	return HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		if checkFunc == nil {
			return ComponentHealth{
				Status:  HealthStatusUnhealthy,
				Message: "Storage check function not configured",
			}
		}

		if err := checkFunc(ctx); err != nil {
			return ComponentHealth{
				Status:  HealthStatusUnhealthy,
				Message: "Storage check failed",
				Error:   err.Error(),
			}
		}

		return ComponentHealth{
			Status:  HealthStatusHealthy,
			Message: "Storage is accessible",
		}
	})
}

// NonceStoreHealthChecker creates a health checker for the nonce store.
func NonceStoreHealthChecker(checkFunc func() bool) HealthChecker {
	return HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		if checkFunc == nil || !checkFunc() {
			return ComponentHealth{
				Status:  HealthStatusDegraded,
				Message: "Nonce store may have insufficient capacity",
			}
		}

		return ComponentHealth{
			Status:  HealthStatusHealthy,
			Message: "Nonce store is operational",
		}
	})
}

// CircuitBreakerHealthChecker creates a health checker for circuit breakers.
func CircuitBreakerHealthChecker(cbManager *circuitbreaker.Manager) HealthChecker {
	return HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		if cbManager == nil {
			return ComponentHealth{
				Status:  HealthStatusHealthy,
				Message: "No circuit breakers configured",
			}
		}

		status := cbManager.Status()
		openCount := 0
		halfOpenCount := 0

		for _, state := range status {
			switch state {
			case circuitbreaker.StateOpen:
				openCount++
			case circuitbreaker.StateHalfOpen:
				halfOpenCount++
			}
		}

		if openCount > 0 {
			return ComponentHealth{
				Status:  HealthStatusDegraded,
				Message: formatCircuitBreakerMessage(openCount, halfOpenCount, len(status)),
			}
		}

		if halfOpenCount > 0 {
			return ComponentHealth{
				Status:  HealthStatusDegraded,
				Message: formatCircuitBreakerMessage(openCount, halfOpenCount, len(status)),
			}
		}

		return ComponentHealth{
			Status:  HealthStatusHealthy,
			Message: formatCircuitBreakerMessage(openCount, halfOpenCount, len(status)),
		}
	})
}

// formatCircuitBreakerMessage formats a message about circuit breaker status.
func formatCircuitBreakerMessage(open, halfOpen, total int) string {
	return formatInt(total) + " circuit breakers: " +
		formatInt(open) + " open, " +
		formatInt(halfOpen) + " half-open"
}

// DegradationHealthChecker creates a health checker for degradation status.
func DegradationHealthChecker(dm *degradation.DegradationManager) HealthChecker {
	return HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		if dm == nil {
			return ComponentHealth{
				Status:  HealthStatusHealthy,
				Message: "Degradation management not configured",
			}
		}

		status := dm.Status()
		if status.Degraded {
			return ComponentHealth{
				Status:  HealthStatusDegraded,
				Message: "Service is in degraded mode",
			}
		}

		return ComponentHealth{
			Status:  HealthStatusHealthy,
			Message: "Service is operating normally",
		}
	})
}

// MetricsHandler returns metrics in JSON format for debugging.
// GET /health/metrics
// This is separate from the Prometheus /metrics endpoint.
func (phs *ProductionHealthService) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	metricsData := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(phs.startTime).String(),
	}

	// Add circuit breaker metrics
	if phs.cbManager != nil {
		cbMetrics := make(map[string]interface{})
		for _, cb := range phs.cbManager.List() {
			failures, successes := cb.Counts()
			cbMetrics[cb.Name()] = map[string]interface{}{
				"state":         cb.State().String(),
				"failure_count": failures,
				"success_count": successes,
			}
		}
		metricsData["circuit_breakers"] = cbMetrics
	}

	// Add degradation metrics
	if phs.degradation != nil {
		status := phs.degradation.Status()
		metricsData["degradation"] = map[string]interface{}{
			"active":          status.Degraded,
			"slow_percentage": status.SlowPercentage,
			"average_latency": status.AverageLatency.String(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(metricsData)
}

// StartupProbeHandler returns a startup probe endpoint.
// GET /health/startup
// Returns 200 when the service has completed initialization.
func (phs *ProductionHealthService) StartupProbeHandler(w http.ResponseWriter, r *http.Request) {
	// Check if all critical components are initialized
	criticalComponents := []string{"ca", "storage", "cluster"}
	allReady := true

	phs.mu.RLock()
	for _, name := range criticalComponents {
		if _, exists := phs.checkers[name]; !exists {
			allReady = false
			break
		}
	}
	phs.mu.RUnlock()

	if !allReady {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("still starting up"))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("started"))
}
