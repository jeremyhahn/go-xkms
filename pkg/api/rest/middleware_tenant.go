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
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TenantMiddleware enforces tenant isolation for REST API requests.
// It extracts tenant context from the authenticated identity, validates
// cross-tenant access, and injects the TenantBarrier into the request
// context for downstream handlers.
//
// Behavior:
//   - No identity or empty TenantID: passes through (system-level or bootstrap access)
//   - SO role: passes through with cross-tenant access
//   - No barrier registry configured: passes through
//   - Tenant not found in registry: returns 403 Forbidden
//   - Tenant barrier is sealed: returns 503 Service Unavailable
//   - Otherwise: injects TenantBarrier into context and continues
func (s *Server) TenantMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity := auth.GetIdentity(r.Context())

			// System-level or unauthenticated requests pass through.
			// Authentication middleware handles unauthenticated rejection;
			// this middleware only enforces tenant scoping.
			if identity == nil || identity.TenantID == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Security Officer role gets cross-tenant access per FIPS 140-2/3
			// separation of duties model.
			if identity.HasRole("so") {
				next.ServeHTTP(w, r)
				return
			}

			// No barrier registry configured; tenant enforcement disabled.
			if s.barrierRegistry == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Look up the tenant barrier from the registry.
			tb, err := s.barrierRegistry.Tenant(identity.TenantID)
			if err != nil {
				s.logger.Warn("tenant barrier not found",
					slog.String("tenant_id", identity.TenantID),
					slog.String("error", err.Error()))
				writeErrorWithMessage(w, ErrForbidden, "tenant not found", http.StatusForbidden)
				return
			}

			// Reject requests when the tenant barrier is sealed.
			if tb.IsSealed() {
				s.logger.Warn("tenant barrier is sealed",
					slog.String("tenant_id", identity.TenantID))
				writeErrorWithMessage(w, ErrServiceUnavailable, "tenant barrier is sealed", http.StatusServiceUnavailable)
				return
			}

			// Inject tenant barrier into context for downstream handlers.
			ctx := auth.WithTenantBarrier(r.Context(), tb)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}
