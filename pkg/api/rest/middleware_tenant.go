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
	"errors"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/tenantgate"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TenantMiddleware enforces tenant isolation for REST API requests. It
// delegates the decision to tenantgate.Access -- the transport-neutral gate
// shared with gRPC, QUIC, MCP, and the Unix domain socket listener -- and
// maps the result onto the REST wire shape.
//
// Behavior (see tenantgate.Access):
//   - Cross-tenant-scoped identity (nil, empty TenantID, or the reserved
//     system tenant): passes through (system-level or bootstrap access)
//   - SO role: passes through with cross-tenant access
//   - No barrier registry configured: passes through
//   - Tenant not found in registry: returns 403 Forbidden
//   - Tenant barrier is sealed: returns 503 Service Unavailable
//   - Otherwise: injects TenantBarrier into context and continues
func (s *Server) TenantMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity := auth.GetIdentity(r.Context())

			tb, err := tenantgate.Access(identity, s.barrierRegistry)
			if err != nil {
				var notFound *tenantgate.ErrTenantNotFound
				var sealed *tenantgate.ErrTenantSealed
				switch {
				case errors.As(err, &notFound):
					s.logger.Warn("tenant barrier not found",
						slog.String("tenant_id", notFound.TenantID),
						slog.String("error", notFound.Err.Error()))
					writeErrorWithMessage(w, ErrForbidden, "tenant not found", http.StatusForbidden)
				case errors.As(err, &sealed):
					s.logger.Warn("tenant barrier is sealed",
						slog.String("tenant_id", sealed.TenantID))
					writeErrorWithMessage(w, ErrServiceUnavailable, "tenant barrier is sealed", http.StatusServiceUnavailable)
				default:
					s.logger.Error("tenant access check failed", slog.String("error", err.Error()))
					writeErrorWithMessage(w, ErrInternalError, "tenant access check failed", http.StatusInternalServerError)
				}
				return
			}

			if tb != nil {
				ctx := auth.WithTenantBarrier(r.Context(), tb)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}
