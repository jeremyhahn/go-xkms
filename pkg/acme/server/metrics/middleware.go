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

package metrics

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code before writing the header.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Middleware returns an HTTP middleware that instruments handlers with Prometheus metrics.
// It records request counts, durations, and status codes for each endpoint.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a custom response writer to capture status code
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default to 200
		}

		// Extract endpoint name from path
		endpoint := extractEndpoint(r.URL.Path)

		// Call the next handler
		next.ServeHTTP(wrapped, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		status := strconv.Itoa(wrapped.statusCode)

		RecordRequest(endpoint, status)
		ObserveRequestDuration(endpoint, duration)

		// Record errors for 4xx and 5xx responses
		if wrapped.statusCode >= 400 {
			errorType := "client_error"
			if wrapped.statusCode >= 500 {
				errorType = "server_error"
			}
			RecordError(errorType)
		}
	})
}

// extractEndpoint extracts a normalized endpoint name from the request path.
// It removes ID parameters to create consistent metric labels.
// Examples:
//   - "/acme/account/123" -> "account"
//   - "/acme/order/456/finalize" -> "order-finalize"
//   - "/acme/challenge/789" -> "challenge"
func extractEndpoint(path string) string {
	// Remove leading/trailing slashes
	path = strings.Trim(path, "/")

	// Handle empty path
	if path == "" {
		return "unknown"
	}

	// Split by slashes
	parts := strings.Split(path, "/")

	// Remove "acme" prefix if present
	if len(parts) > 0 && parts[0] == "acme" {
		parts = parts[1:]
	}

	if len(parts) == 0 {
		return "unknown"
	}

	// Build endpoint name, skipping numeric IDs
	var endpoint []string
	for _, part := range parts {
		// Skip empty parts
		if part == "" {
			continue
		}
		// Skip numeric parts (IDs)
		if _, err := strconv.ParseUint(part, 10, 64); err != nil {
			endpoint = append(endpoint, part)
		}
	}

	if len(endpoint) == 0 {
		// All parts were numeric IDs, use the first part
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
		return "unknown"
	}

	return strings.Join(endpoint, "-")
}
