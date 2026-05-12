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
	"net/http"
	"sync"
	"time"
)

// HealthStatus represents the overall health status of the service.
type HealthStatus string

const (
	// HealthStatusHealthy indicates the service is fully operational.
	HealthStatusHealthy HealthStatus = "healthy"

	// HealthStatusDegraded indicates the service is operational but some components are unhealthy.
	HealthStatusDegraded HealthStatus = "degraded"

	// HealthStatusUnhealthy indicates the service is not operational.
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status     HealthStatus               `json:"status"`
	Timestamp  string                     `json:"timestamp"`
	Version    string                     `json:"version,omitempty"`
	Components map[string]ComponentHealth `json:"components,omitempty"`
}

// ComponentHealth represents the health status of a specific component.
type ComponentHealth struct {
	Status  HealthStatus `json:"status"`
	Message string       `json:"message,omitempty"`
	Error   string       `json:"error,omitempty"`
}

// HealthChecker defines the interface for checking component health.
type HealthChecker interface {
	CheckHealth(ctx context.Context) ComponentHealth
}

// HealthCheckerFunc is a function type that implements HealthChecker.
type HealthCheckerFunc func(ctx context.Context) ComponentHealth

// CheckHealth implements the HealthChecker interface.
func (f HealthCheckerFunc) CheckHealth(ctx context.Context) ComponentHealth {
	return f(ctx)
}

// HealthService manages health checks for the ACME server.
type HealthService struct {
	version   string
	checkers  map[string]HealthChecker
	mu        sync.RWMutex
	startTime time.Time
}

// NewHealthService creates a new health service.
func NewHealthService(version string) *HealthService {
	return &HealthService{
		version:   version,
		checkers:  make(map[string]HealthChecker),
		startTime: time.Now(),
	}
}

// RegisterChecker registers a health checker for a named component.
func (hs *HealthService) RegisterChecker(name string, checker HealthChecker) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.checkers[name] = checker
}

// HealthHandler returns a basic health check endpoint.
// GET /health
// Returns 200 OK if the service is running.
func (hs *HealthService) HealthHandler(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    HealthStatusHealthy,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   hs.version,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encodeJSONWithLogger(w, response, nil)
}

// ReadyHandler returns a readiness probe endpoint.
// GET /health/ready
// Checks all registered dependencies and returns 200 if ready, 503 if not ready.
func (hs *HealthService) ReadyHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	hs.mu.RLock()
	checkers := make(map[string]HealthChecker, len(hs.checkers))
	for name, checker := range hs.checkers {
		checkers[name] = checker
	}
	hs.mu.RUnlock()

	components := make(map[string]ComponentHealth)
	overallStatus := HealthStatusHealthy

	// Run health checks concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, checker := range checkers {
		wg.Add(1)
		go func(name string, checker HealthChecker) {
			defer wg.Done()

			health := checker.CheckHealth(ctx)

			mu.Lock()
			components[name] = health
			if health.Status == HealthStatusUnhealthy {
				overallStatus = HealthStatusUnhealthy
			} else if health.Status == HealthStatusDegraded && overallStatus != HealthStatusUnhealthy {
				overallStatus = HealthStatusDegraded
			}
			mu.Unlock()
		}(name, checker)
	}

	wg.Wait()

	response := HealthResponse{
		Status:     overallStatus,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Version:    hs.version,
		Components: components,
	}

	w.Header().Set("Content-Type", "application/json")
	if overallStatus == HealthStatusHealthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	encodeJSONWithLogger(w, response, nil)
}

// LiveHandler returns a liveness probe endpoint.
// GET /health/live
// Returns 200 OK if the service is alive and can handle requests.
func (hs *HealthService) LiveHandler(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(hs.startTime).Seconds()

	response := HealthResponse{
		Status:    HealthStatusHealthy,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   hs.version,
		Components: map[string]ComponentHealth{
			"uptime": {
				Status:  HealthStatusHealthy,
				Message: formatUptime(uptime),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encodeJSONWithLogger(w, response, nil)
}

// formatUptime formats uptime duration into a human-readable string.
func formatUptime(seconds float64) string {
	duration := time.Duration(seconds) * time.Second

	days := int(duration.Hours()) / 24
	hours := int(duration.Hours()) % 24
	minutes := int(duration.Minutes()) % 60
	secs := int(duration.Seconds()) % 60

	if days > 0 {
		return formatDuration(days, hours, minutes, secs, true)
	}
	return formatDuration(0, hours, minutes, secs, false)
}

// formatDuration formats duration components into a string.
func formatDuration(days, hours, minutes, seconds int, includeDays bool) string {
	if includeDays {
		return formatWithDays(days, hours, minutes, seconds)
	}
	return formatWithoutDays(hours, minutes, seconds)
}

// formatWithDays formats duration including days.
func formatWithDays(days, hours, minutes, seconds int) string {
	return formatTime(days, "d", hours, "h", minutes, "m", seconds, "s")
}

// formatWithoutDays formats duration without days.
func formatWithoutDays(hours, minutes, seconds int) string {
	return formatTime(hours, "h", minutes, "m", seconds, "s", 0, "")
}

// formatTime formats time components.
func formatTime(v1 int, u1 string, v2 int, u2 string, v3 int, u3 string, v4 int, u4 string) string {
	result := ""
	if v1 > 0 {
		result = appendUnit(result, v1, u1)
	}
	result = appendUnit(result, v2, u2)
	result = appendUnit(result, v3, u3)
	if v4 > 0 && u4 != "" {
		result = appendUnit(result, v4, u4)
	}
	return result
}

// appendUnit appends a time unit to the result string.
func appendUnit(result string, value int, unit string) string {
	if result != "" {
		result += " "
	}
	return result + formatValue(value, unit)
}

// formatValue formats a time value with its unit.
func formatValue(value int, unit string) string {
	return formatInt(value) + unit
}

// formatInt converts an integer to string.
func formatInt(value int) string {
	// Simple integer to string conversion
	if value == 0 {
		return "0"
	}

	negative := value < 0
	if negative {
		value = -value
	}

	digits := []byte{}
	for value > 0 {
		digit := byte('0' + (value % 10))
		digits = append([]byte{digit}, digits...)
		value /= 10
	}

	result := string(digits)
	if negative {
		result = "-" + result
	}
	return result
}
