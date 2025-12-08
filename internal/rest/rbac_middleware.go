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
	"context"
	"net/http"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/rbac"
)

// RBACConfig holds configuration for RBAC middleware.
type RBACConfig struct {
	// Adapter is the RBAC adapter to use for permission checks.
	Adapter rbac.RBACAdapter

	// Logger is the logging adapter.
	Logger logger.Logger

	// SkipPaths are paths that should skip RBAC checks (e.g., health endpoints).
	SkipPaths map[string]bool
}

// RBACMiddleware enforces role-based access control on HTTP requests.
// It checks if the authenticated user has the required permission for the
// requested resource and action.
type RBACMiddleware struct {
	adapter   rbac.RBACAdapter
	logger    logger.Logger
	skipPaths map[string]bool
}

// NewRBACMiddleware creates a new RBAC middleware instance.
func NewRBACMiddleware(cfg *RBACConfig) *RBACMiddleware {
	if cfg.SkipPaths == nil {
		cfg.SkipPaths = make(map[string]bool)
	}

	return &RBACMiddleware{
		adapter:   cfg.Adapter,
		logger:    cfg.Logger,
		skipPaths: cfg.SkipPaths,
	}
}

// RequirePermission returns middleware that requires a specific permission.
// This is the most flexible approach - explicitly declare the required permission.
func (m *RBACMiddleware) RequirePermission(resource, action string) func(http.Handler) http.Handler {
	permission := rbac.NewPermission(resource, action)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get identity from context
			identity := auth.GetIdentity(ctx)
			if identity == nil {
				m.logger.Warn("RBAC check failed: no identity in context",
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path))
				writeErrorWithMessage(w, ErrUnauthorized, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Check permission using the subject from identity
			hasPermission, err := m.adapter.CheckPermission(ctx, identity.Subject, permission)
			if err != nil {
				m.logger.Error("RBAC permission check failed",
					logger.String("subject", identity.Subject),
					logger.String("resource", resource),
					logger.String("action", action),
					logger.Error(err))
				writeErrorWithMessage(w, ErrInternalError, "Permission check failed", http.StatusInternalServerError)
				return
			}

			if !hasPermission {
				m.logger.Warn("RBAC access denied",
					logger.String("subject", identity.Subject),
					logger.String("resource", resource),
					logger.String("action", action),
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path))
				writeErrorWithMessage(w, ErrForbidden, "Access denied: insufficient permissions", http.StatusForbidden)
				return
			}

			m.logger.Debug("RBAC access granted",
				logger.String("subject", identity.Subject),
				logger.String("resource", resource),
				logger.String("action", action))

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns middleware that requires the user to have a specific role.
func (m *RBACMiddleware) RequireRole(roleName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get identity from context
			identity := auth.GetIdentity(ctx)
			if identity == nil {
				m.logger.Warn("RBAC role check failed: no identity in context",
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path))
				writeErrorWithMessage(w, ErrUnauthorized, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Get user roles
			roles, err := m.adapter.GetUserRoles(ctx, identity.Subject)
			if err != nil {
				m.logger.Error("RBAC role check failed",
					logger.String("subject", identity.Subject),
					logger.String("required_role", roleName),
					logger.Error(err))
				writeErrorWithMessage(w, ErrInternalError, "Role check failed", http.StatusInternalServerError)
				return
			}

			// Check if user has the required role
			hasRole := false
			for _, role := range roles {
				if role == roleName {
					hasRole = true
					break
				}
			}

			if !hasRole {
				m.logger.Warn("RBAC access denied: missing role",
					logger.String("subject", identity.Subject),
					logger.String("required_role", roleName),
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path))
				writeErrorWithMessage(w, ErrForbidden, "Access denied: insufficient role", http.StatusForbidden)
				return
			}

			m.logger.Debug("RBAC role check passed",
				logger.String("subject", identity.Subject),
				logger.String("role", roleName))

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole returns middleware that requires the user to have at least one of the specified roles.
func (m *RBACMiddleware) RequireAnyRole(roleNames ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get identity from context
			identity := auth.GetIdentity(ctx)
			if identity == nil {
				m.logger.Warn("RBAC role check failed: no identity in context",
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path))
				writeErrorWithMessage(w, ErrUnauthorized, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Get user roles
			roles, err := m.adapter.GetUserRoles(ctx, identity.Subject)
			if err != nil {
				m.logger.Error("RBAC role check failed",
					logger.String("subject", identity.Subject),
					logger.Error(err))
				writeErrorWithMessage(w, ErrInternalError, "Role check failed", http.StatusInternalServerError)
				return
			}

			// Check if user has any of the required roles
			hasRole := false
			for _, userRole := range roles {
				for _, requiredRole := range roleNames {
					if userRole == requiredRole {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}

			if !hasRole {
				m.logger.Warn("RBAC access denied: missing required role",
					logger.String("subject", identity.Subject),
					logger.Any("required_roles", roleNames),
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path))
				writeErrorWithMessage(w, ErrForbidden, "Access denied: insufficient role", http.StatusForbidden)
				return
			}

			m.logger.Debug("RBAC role check passed",
				logger.String("subject", identity.Subject))

			next.ServeHTTP(w, r)
		})
	}
}

// UserRoleContext is a context key for storing the user's role.
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

// Common permission shortcuts for key operations
var (
	PermissionKeysCreate  = rbac.NewPermission(rbac.ResourceKeys, rbac.ActionCreate)
	PermissionKeysRead    = rbac.NewPermission(rbac.ResourceKeys, rbac.ActionRead)
	PermissionKeysList    = rbac.NewPermission(rbac.ResourceKeys, rbac.ActionList)
	PermissionKeysDelete  = rbac.NewPermission(rbac.ResourceKeys, rbac.ActionDelete)
	PermissionKeysSign    = rbac.NewPermission(rbac.ResourceKeys, rbac.ActionSign)
	PermissionKeysVerify  = rbac.NewPermission(rbac.ResourceKeys, rbac.ActionVerify)
	PermissionKeysEncrypt = rbac.NewPermission(rbac.ResourceKeys, rbac.ActionEncrypt)
	PermissionKeysDecrypt = rbac.NewPermission(rbac.ResourceKeys, rbac.ActionDecrypt)
	PermissionKeysRotate  = rbac.NewPermission(rbac.ResourceKeys, rbac.ActionRotate)
	PermissionKeysImport  = rbac.NewPermission(rbac.ResourceKeys, rbac.ActionImport)
	PermissionKeysExport  = rbac.NewPermission(rbac.ResourceKeys, rbac.ActionExport)

	PermissionCertsCreate = rbac.NewPermission(rbac.ResourceCertificates, rbac.ActionCreate)
	PermissionCertsRead   = rbac.NewPermission(rbac.ResourceCertificates, rbac.ActionRead)
	PermissionCertsList   = rbac.NewPermission(rbac.ResourceCertificates, rbac.ActionList)
	PermissionCertsDelete = rbac.NewPermission(rbac.ResourceCertificates, rbac.ActionDelete)

	PermissionUsersCreate = rbac.NewPermission(rbac.ResourceUsers, rbac.ActionCreate)
	PermissionUsersRead   = rbac.NewPermission(rbac.ResourceUsers, rbac.ActionRead)
	PermissionUsersList   = rbac.NewPermission(rbac.ResourceUsers, rbac.ActionList)
	PermissionUsersUpdate = rbac.NewPermission(rbac.ResourceUsers, rbac.ActionUpdate)
	PermissionUsersDelete = rbac.NewPermission(rbac.ResourceUsers, rbac.ActionDelete)

	PermissionBackendsList = rbac.NewPermission(rbac.ResourceBackends, rbac.ActionList)
	PermissionBackendsRead = rbac.NewPermission(rbac.ResourceBackends, rbac.ActionRead)
)
