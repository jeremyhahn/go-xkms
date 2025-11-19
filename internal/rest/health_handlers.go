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

package rest

import (
	"net/http"

	"github.com/jeremyhahn/go-keychain/pkg/health"
)

// HealthCheckResponse represents the response for health check endpoints.
type HealthCheckResponse struct {
	// Status is the overall health status
	Status health.Status `json:"status"`
	// Message provides additional context
	Message string `json:"message,omitempty"`
	// Checks contains individual check results (for readiness)
	Checks []health.CheckResult `json:"checks,omitempty"`
}

// LivenessHandler handles GET /health/live requests.
//
// Liveness probes determine if the service is alive and should be restarted.
// This endpoint should ONLY fail if the service is in an unrecoverable state.
//
// Kubernetes documentation:
// https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
func (h *HandlerContext) LivenessHandler(w http.ResponseWriter, r *http.Request) {
	if h.HealthChecker == nil {
		// If no health checker configured, assume healthy
		resp := HealthCheckResponse{
			Status:  health.StatusHealthy,
			Message: "Service is alive",
		}
		writeJSON(w, resp, http.StatusOK)
		return
	}

	result := h.HealthChecker.Live(r.Context())

	resp := HealthCheckResponse{
		Status:  result.Status,
		Message: result.Message,
	}

	statusCode := http.StatusOK
	if result.Status == health.StatusUnhealthy {
		statusCode = http.StatusServiceUnavailable
	}

	writeJSON(w, resp, statusCode)
}

// ReadinessHandler handles GET /health/ready requests.
//
// Readiness probes determine if the service can accept traffic.
// This endpoint fails if dependencies are unavailable or the service cannot handle requests.
//
// The service may be alive but not ready (e.g., warming up, waiting for dependencies).
//
// Kubernetes documentation:
// https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
func (h *HandlerContext) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	if h.HealthChecker == nil {
		// If no health checker configured, assume ready
		resp := HealthCheckResponse{
			Status:  health.StatusHealthy,
			Message: "Service is ready",
		}
		writeJSON(w, resp, http.StatusOK)
		return
	}

	results := h.HealthChecker.Ready(r.Context())
	overallStatus := health.AggregateStatus(results)

	resp := HealthCheckResponse{
		Status: overallStatus,
		Checks: results,
	}

	// Set message based on status
	switch overallStatus {
	case health.StatusHealthy:
		resp.Message = "All checks passed"
	case health.StatusDegraded:
		resp.Message = "Service is degraded"
	case health.StatusUnhealthy:
		resp.Message = "One or more checks failed"
	}

	// Return appropriate HTTP status
	statusCode := http.StatusOK
	switch overallStatus {
	case health.StatusUnhealthy:
		statusCode = http.StatusServiceUnavailable
	case health.StatusDegraded:
		// Service is degraded but still serving traffic
		statusCode = http.StatusOK
	}

	writeJSON(w, resp, statusCode)
}

// StartupHandler handles GET /health/startup requests.
//
// Startup probes determine if the application has finished initializing.
// Kubernetes will not check liveness or readiness until startup succeeds.
//
// This is useful for applications with long initialization times.
// Once the startup probe succeeds, liveness and readiness probes take over.
//
// Kubernetes documentation:
// https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
func (h *HandlerContext) StartupHandler(w http.ResponseWriter, r *http.Request) {
	if h.HealthChecker == nil {
		// If no health checker configured, assume started
		resp := HealthCheckResponse{
			Status:  health.StatusHealthy,
			Message: "Service has started",
		}
		writeJSON(w, resp, http.StatusOK)
		return
	}

	result := h.HealthChecker.Startup(r.Context())

	resp := HealthCheckResponse{
		Status:  result.Status,
		Message: result.Message,
	}

	statusCode := http.StatusOK
	if result.Status == health.StatusUnhealthy {
		// Service not yet started - return 503
		statusCode = http.StatusServiceUnavailable
	}

	writeJSON(w, resp, statusCode)
}
