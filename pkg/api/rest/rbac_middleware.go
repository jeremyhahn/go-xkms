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

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// RBACConfig holds configuration for RBAC middleware.
type RBACConfig struct {
	// Authorizer is the qrdb-backed authorizer used for permission checks.
	// It must be usable (Enabled() true): rest.NewServer fails closed with
	// ErrAuthorizerRequired before constructing this middleware when RBAC is
	// enabled without a backing RBAC client, so the middleware never runs in
	// a fail-open (allow-all) configuration.
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

// TenantGate authorizes the tenant lifecycle routes (RouteAuthTenant) by the
// tenants each request reaches, as the ACME admin plane's tenant gate did
// before the routes moved here (go-xkms#794). A caller acting on its own
// tenant needs the route's Resource:Action; reaching any other tenant, or
// creating one, needs the route's cross-tenant permission
// (qrdbsdk.PermissionTenants*Cross). A caller confined to its own tenant that
// names another one is answered exactly as for an absent tenant (404), so the
// gate does not reveal which tenants exist.
//
// The gate runs whether or not RBAC is enabled for the other routes, and
// fails closed (503 ErrTenantAuthorizerUnavailable) without a qrdb-backed
// authorizer.
type TenantGate struct {
	authorizer *auth.Authorizer
	logger     *slog.Logger
}

// NewTenantGate returns the tenant lifecycle gate over authorizer.
func NewTenantGate(authorizer *auth.Authorizer, logger *slog.Logger) *TenantGate {
	return &TenantGate{authorizer: authorizer, logger: logger}
}

// Require returns middleware gating spec, a RouteAuthTenant route.
func (g *TenantGate) Require(spec RouteSpec) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			identity := auth.GetIdentity(ctx)
			if identity == nil {
				writeErrorWithMessage(w, ErrUnauthorized, "Authentication required", http.StatusUnauthorized)
				return
			}
			if !g.authorizer.Enabled() {
				writeError(w, ErrTenantAuthorizerUnavailable, http.StatusServiceUnavailable)
				return
			}

			resource, action, hidden := g.permission(spec, identity, r)
			err := g.authorizer.Authorize(ctx, identity, resource, action)
			if err == nil {
				next.ServeHTTP(w, r)
				return
			}
			g.logger.Warn("tenant route access denied",
				slog.String("subject", identity.Subject),
				slog.String("resource", resource),
				slog.String("action", action),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("error", err.Error()))
			switch {
			case errors.Is(err, auth.ErrUnauthenticated):
				writeErrorWithMessage(w, ErrUnauthorized, "Authentication required", http.StatusUnauthorized)
			case hidden:
				handleTenantError(w, qrdbsdk.ErrTenantMissing)
			default:
				writeErrorWithMessage(w, ErrForbidden, "Access denied: insufficient permissions", http.StatusForbidden)
			}
		})
	}
}

// permission returns the permission identity needs for spec on r, and
// whether a refusal must read as an absent tenant: the request names another
// tenant than the caller's, and the caller is confined to its own.
func (g *TenantGate) permission(spec RouteSpec, identity *auth.Identity, r *http.Request) (resource, action string, hidden bool) {
	cross := func() (string, string) {
		return qrdbsdk.PermissionResource(spec.CrossPermission), qrdbsdk.PermissionAction(spec.CrossPermission)
	}
	switch spec.Reach {
	case TenantReachTarget:
		if identity.TenantID == chi.URLParam(r, "tenantID") {
			return spec.Resource, spec.Action, false
		}
		resource, action = cross()
		return resource, action, !auth.IsCrossTenant(identity)
	case TenantReachList:
		if !auth.IsCrossTenant(identity) {
			return spec.Resource, spec.Action, false
		}
	}
	resource, action = cross()
	return resource, action, false
}
