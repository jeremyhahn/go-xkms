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

package qrdb

import (
	"encoding/json"
	"net/http"
)

// healthStatus represents the JSON response body for health endpoints.
type healthStatus struct {
	Status  string `json:"status"`
	Healthy bool   `json:"healthy"`
}

// HealthHandler provides HTTP health check endpoints backed by the
// QRDB admin service.
type HealthHandler struct {
	service Service
	config  *Config
}

// NewHealthHandler creates a HealthHandler for the given service and config.
func NewHealthHandler(svc Service, cfg *Config) *HealthHandler {
	return &HealthHandler{
		service: svc,
		config:  cfg,
	}
}

// Health handles HTTP health check requests. It queries the QRDB
// admin service for the current health status and returns a JSON
// response with an appropriate HTTP status code.
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	healthy := h.service.Healthy(ctx)

	status := &healthStatus{
		Status:  "healthy",
		Healthy: healthy,
	}
	code := http.StatusOK

	if !healthy {
		status.Status = "unhealthy"
		code = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(status)
}

// Ready handles HTTP readiness check requests. A service is considered
// ready when it is healthy and the QRDB admin reports a healthy status.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check transport-level health first.
	if !h.service.Healthy(ctx) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(&healthStatus{
			Status:  "not_ready",
			Healthy: false,
		})
		return
	}

	// Query admin health for deeper readiness signal.
	adminClient := h.service.Admin()
	healthResp, err := adminClient.Health(ctx)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(&healthStatus{
			Status:  "not_ready",
			Healthy: false,
		})
		return
	}

	status := &healthStatus{
		Status:  healthResp.Status,
		Healthy: true,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

// RegisterHealthEndpoints registers the health and readiness check
// endpoints on the given HTTP mux.
func RegisterHealthEndpoints(mux *http.ServeMux, handler *HealthHandler) {
	mux.HandleFunc("/health", handler.Health)
	mux.HandleFunc("/ready", handler.Ready)
}
