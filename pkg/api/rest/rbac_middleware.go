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
	"context"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// RBACConfig holds configuration for RBAC middleware.
type RBACConfig struct {
	// Authorizer is the qrdb-backed authorizer used for permission checks.
	// A nil authorizer (or one without a backing RBAC client) allows every
	// request — authorization is treated as disabled.
	Authorizer *auth.Authorizer

	// Logger is the logging adapter.
	Logger *slog.Logger

	// SkipPaths are paths that should skip RBAC checks (e.g., health endpoints).
	SkipPaths map[string]bool
}

// RBACMiddleware enforces role-based access control on HTTP requests by
// delegating every decision to the hosted go-qrdb node's RBAC service via
// the xkms Authorizer. It carries no local role or permission model.
type RBACMiddleware struct {
	authorizer *auth.Authorizer
	logger     *slog.Logger
	skipPaths  map[string]bool
}

// NewRBACMiddleware creates a new RBAC middleware instance.
func NewRBACMiddleware(cfg *RBACConfig) *RBACMiddleware {
	if cfg.SkipPaths == nil {
		cfg.SkipPaths = make(map[string]bool)
	}

	return &RBACMiddleware{
		authorizer: cfg.Authorizer,
		logger:     cfg.Logger,
		skipPaths:  cfg.SkipPaths,
	}
}

// RequirePermission returns middleware that requires the authenticated
// identity to hold the given resource:action permission. The decision is
// delegated to the qrdb RBAC engine, scoped to the identity's tenant.
func (m *RBACMiddleware) RequirePermission(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			identity := auth.GetIdentity(ctx)
			if identity == nil {
				m.logger.Warn("RBAC check failed: no identity in context",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path))
				writeErrorWithMessage(w, ErrUnauthorized, "Authentication required", http.StatusUnauthorized)
				return
			}

			if err := m.authorizer.Authorize(ctx, identity, resource, action); err != nil {
				m.logger.Warn("RBAC access denied",
					slog.String("subject", identity.Subject),
					slog.String("resource", resource),
					slog.String("action", action),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("error", err.Error()))
				writeErrorWithMessage(w, ErrForbidden, "Access denied: insufficient permissions", http.StatusForbidden)
				return
			}

			m.logger.Debug("RBAC access granted",
				slog.String("subject", identity.Subject),
				slog.String("resource", resource),
				slog.String("action", action))

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns middleware that requires the identity to hold a
// specific role. Roles are read directly from the authenticated identity
// resolved from the qrdb identity plane.
func (m *RBACMiddleware) RequireRole(roleName string) func(http.Handler) http.Handler {
	return m.RequireAnyRole(roleName)
}

// RequireAnyRole returns middleware that requires the identity to hold at
// least one of the specified roles.
func (m *RBACMiddleware) RequireAnyRole(roleNames ...string) func(http.Handler) http.Handler {
	required := make(map[string]struct{}, len(roleNames))
	for _, n := range roleNames {
		required[n] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			identity := auth.GetIdentity(ctx)
			if identity == nil {
				m.logger.Warn("RBAC role check failed: no identity in context",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path))
				writeErrorWithMessage(w, ErrUnauthorized, "Authentication required", http.StatusUnauthorized)
				return
			}

			hasRole := false
			for _, role := range identity.Roles {
				if _, ok := required[role]; ok {
					hasRole = true
					break
				}
			}

			if !hasRole {
				m.logger.Warn("RBAC access denied: missing required role",
					slog.String("subject", identity.Subject),
					slog.Any("required_roles", roleNames),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path))
				writeErrorWithMessage(w, ErrForbidden, "Access denied: insufficient role", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// userRoleContextKey is a context key for storing the user's role.
type userRoleContextKey struct{}

// WithUserRole adds the user's role to the context.
func WithUserRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, userRoleContextKey{}, role)
}

// GetUserRole retrieves the user's role from the context.
func GetUserRole(ctx context.Context) string {
	if role, ok := ctx.Value(userRoleContextKey{}).(string); ok {
		return role
	}
	return ""
}
