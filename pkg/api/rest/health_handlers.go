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

package rest

import (
	"net/http"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// HealthCheckResponse represents the response for health check endpoints.
type HealthCheckResponse struct {
	// Status is the overall health status
	Status qrdbsdk.HealthCheckStatus `json:"status"`
	// Message provides additional context
	Message string `json:"message,omitempty"`
	// Checks contains individual check results (for readiness)
	Checks []qrdbsdk.HealthCheckResult `json:"checks,omitempty"`
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
			Status:  qrdbsdk.HealthCheckStatusHealthy,
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
	if result.Status == qrdbsdk.HealthCheckStatusUnhealthy {
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
			Status:  qrdbsdk.HealthCheckStatusHealthy,
			Message: "Service is ready",
		}
		writeJSON(w, resp, http.StatusOK)
		return
	}

	results := h.HealthChecker.Ready(r.Context())
	overallStatus := qrdbsdk.AggregateHealthCheckStatus(results)

	resp := HealthCheckResponse{
		Status: overallStatus,
		Checks: results,
	}

	// Set message based on status
	switch overallStatus {
	case qrdbsdk.HealthCheckStatusHealthy:
		resp.Message = "All checks passed"
	case qrdbsdk.HealthCheckStatusDegraded:
		resp.Message = "Service is degraded"
	case qrdbsdk.HealthCheckStatusUnhealthy:
		resp.Message = "One or more checks failed"
	}

	// Return appropriate HTTP status
	statusCode := http.StatusOK
	switch overallStatus {
	case qrdbsdk.HealthCheckStatusUnhealthy:
		statusCode = http.StatusServiceUnavailable
	case qrdbsdk.HealthCheckStatusDegraded:
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
			Status:  qrdbsdk.HealthCheckStatusHealthy,
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
	if result.Status == qrdbsdk.HealthCheckStatusUnhealthy {
		// Service not yet started - return 503
		statusCode = http.StatusServiceUnavailable
	}

	writeJSON(w, resp, statusCode)
}
