// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package mcp

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/api/tenantgate"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// tenantAccess enforces tenant isolation for a JSON-RPC method. It delegates
// the decision to tenantgate.Access -- the transport-neutral gate shared with
// REST, gRPC, QUIC, and the Unix domain socket listener -- and maps the
// result onto JSON-RPC error codes. It runs unconditionally (independent of
// EnableRBAC), mirroring how the REST TenantMiddleware and the gRPC/QUIC
// tenant interceptors run independent of the RBAC decorator/authorizer.
//
// Behavior (see tenantgate.Access):
//   - Cross-tenant-scoped identity (nil, empty TenantID, or the reserved
//     system tenant): passes through (system-level or bootstrap access)
//   - SO role: passes through with cross-tenant access
//   - No barrier registry configured: passes through
//   - Tenant not found in registry: returns ErrCodeForbidden
//   - Tenant barrier is sealed: returns ErrCodeServiceUnavailable
//   - Otherwise: returns a context carrying the TenantBarrier
func (s *Server) tenantAccess(ctx context.Context, method string) (context.Context, error) {
	identity := auth.GetIdentity(ctx)

	tb, err := tenantgate.Access(identity, s.barrierRegistry)
	if err != nil {
		var notFound *tenantgate.ErrTenantNotFound
		var sealed *tenantgate.ErrTenantSealed
		switch {
		case errors.As(err, &notFound):
			s.logger.WarnContext(ctx, "MCP tenant barrier not found",
				slog.String("method", method),
				slog.String("tenant_id", notFound.TenantID),
				slog.String("error", notFound.Err.Error()))
			return ctx, &KeyOpError{Code: ErrCodeForbidden, Err: err}
		case errors.As(err, &sealed):
			s.logger.WarnContext(ctx, "MCP tenant barrier is sealed",
				slog.String("method", method),
				slog.String("tenant_id", sealed.TenantID))
			return ctx, &KeyOpError{Code: ErrCodeServiceUnavailable, Err: err}
		default:
			s.logger.ErrorContext(ctx, "MCP tenant access check failed",
				slog.String("method", method),
				slog.String("error", err.Error()))
			return ctx, &KeyOpError{Code: ErrCodeInternalError, Err: err}
		}
	}

	if tb != nil {
		ctx = auth.WithTenantBarrier(ctx, tb)
	}

	return ctx, nil
}
