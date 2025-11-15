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

	"github.com/jeremyhahn/go-keychain/pkg/correlation"
)

// CorrelationMiddleware extracts or generates a correlation ID for request tracing.
// It checks for correlation IDs in the following order:
// 1. X-Correlation-ID header
// 2. X-Request-ID header
// 3. Generates a new UUID if neither is present
//
// The correlation ID is:
// - Added to the request context
// - Included in the response headers
// - Available for logging and distributed tracing
func (s *Server) CorrelationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to get correlation ID from headers
			correlationID := r.Header.Get(correlation.CorrelationIDHeader)
			if correlationID == "" {
				correlationID = r.Header.Get(correlation.RequestIDHeader)
			}
			if correlationID == "" {
				// Generate a new correlation ID if none provided
				correlationID = correlation.NewID()
			}

			// Add correlation ID to request context
			ctx := correlation.WithCorrelationID(r.Context(), correlationID)
			r = r.WithContext(ctx)

			// Add correlation ID to response headers for client tracking
			w.Header().Set(correlation.CorrelationIDHeader, correlationID)

			next.ServeHTTP(w, r)
		})
	}
}
