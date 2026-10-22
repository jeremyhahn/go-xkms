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

package admin

import (
	"net/http"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Mount points of the two ACME admin route tables.
const (
	adminPathPrefix   = "/admin"
	tenantsPathPrefix = "/api/v1/tenants"
)

// Route is one ACME admin API route as a host mounts it: the HTTP method,
// the full path pattern ({name} segments, which gorilla/mux and chi both
// read), and the one qrdb permission a caller must hold to reach it.
//
// A tenant lifecycle route is gated by the tenant the call reaches, which a
// host cannot see: SelfPermission is set on such a route, and is what a call
// within the caller's own tenant needs, while Permission is what a call
// beyond it needs. A host mounts that route identity-gated and leaves its
// authorization to RegisterAuthorizedRoutes.
type Route struct {
	Method         string
	Path           string
	Permission     qrdbsdk.Permission
	SelfPermission qrdbsdk.Permission
}

// Routes returns every ACME admin route with its full path and permission,
// in registration order. It is the table a host that authorizes each route
// itself mounts — the unified server's admin module, through qrdb's
// HTTPRegistrar.Handle — and the same table RegisterRoutes and
// RegisterAuthorizedRoutes serve, so the two cannot drift.
func Routes() []Route {
	var out []Route
	out = appendRoutes(out, adminPathPrefix, adminRoutes())
	out = appendRoutes(out, tenantsPathPrefix, tenantRoutes())
	return out
}

// grant is the authorization a route requires: perm, or for a tenant
// lifecycle route (self set) self within the caller's own tenant and perm
// beyond it. list marks the tenant enumeration route, which names no
// tenant: a caller confined to its own tenant lists with self.
type grant struct {
	perm qrdbsdk.Permission
	self qrdbsdk.Permission
}

// route binds one table entry to the handler method that serves it. H is
// the handler set (*Handlers or *TenantHandlers) and path is relative to
// the table's mount point.
type route[H any] struct {
	method string
	path   string
	grant
	serve func(H, http.ResponseWriter, *http.Request)
}

// guardFunc wraps a route's handler with the authorization its host needs.
type guardFunc func(g grant, next http.HandlerFunc) http.Handler

// guardRoute is the guardFunc of a standalone host: the gate authorizes
// every route.
func (g *PermissionGate) guardRoute(gr grant, next http.HandlerFunc) http.Handler {
	if gr.self == "" {
		return g.WrapPermission(gr.perm, next)
	}
	return g.WrapTenant(qrdbsdk.PermissionResource(gr.self), qrdbsdk.PermissionAction(gr.self), gr.perm, next)
}

// guardReachRoute is the guardFunc of a host that authorizes every route
// against its Permission before dispatch and mounts a tenant lifecycle
// route identity-gated: only the tenant lifecycle routes are authorized
// here.
func (g *PermissionGate) guardReachRoute(gr grant, next http.HandlerFunc) http.Handler {
	if gr.self == "" {
		return next
	}
	return g.guardRoute(gr, next)
}

// adminRoute declares a route under /admin gated on resource:action.
func adminRoute(method, path, resource, action string, serve func(*Handlers, http.ResponseWriter, *http.Request)) route[*Handlers] {
	return route[*Handlers]{
		method: method,
		path:   path,
		grant:  grant{perm: qrdbsdk.Permission(resource + ":" + action)},
		serve:  serve,
	}
}

// tenantRoute declares a route under /api/v1/tenants gated on
// resource:action.
func tenantRoute(method, path, resource, action string, serve func(*TenantHandlers, http.ResponseWriter, *http.Request)) route[*TenantHandlers] {
	return tenantCrossRoute(method, path, qrdbsdk.Permission(resource+":"+action), serve)
}

// tenantCrossRoute declares a route under /api/v1/tenants gated on one whole
// qrdb permission, for the three-part cross-scope grants such as
// tenants:create:cross.
func tenantCrossRoute(method, path string, perm qrdbsdk.Permission, serve func(*TenantHandlers, http.ResponseWriter, *http.Request)) route[*TenantHandlers] {
	return route[*TenantHandlers]{method: method, path: path, grant: grant{perm: perm}, serve: serve}
}

// tenantReachRoute declares a tenant lifecycle route under
// /api/v1/tenants/{id}, gated by the tenant it reaches: resource:action
// within the caller's own tenant, cross beyond it (PermissionGate.WrapTenant).
func tenantReachRoute(method, path, resource, action string, cross qrdbsdk.Permission, serve func(*TenantHandlers, http.ResponseWriter, *http.Request)) route[*TenantHandlers] {
	return route[*TenantHandlers]{
		method: method,
		path:   path,
		grant:  grant{perm: cross, self: qrdbsdk.Permission(resource + ":" + action)},
		serve:  serve,
	}
}

// adminRoutes is the /admin route table.
func adminRoutes() []route[*Handlers] {
	return []route[*Handlers]{
		// Certificate management. /certificates/expiring must precede
		// /certificates/{serial}, or gorilla/mux matches "expiring" as a
		// serial number.
		adminRoute("GET", "/certificates", auth.ResourceCerts, auth.ActionList, (*Handlers).ListCertificates),
		adminRoute("GET", "/certificates/expiring", auth.ResourceCerts, auth.ActionList, (*Handlers).ListExpiringCertificates),
		adminRoute("GET", "/certificates/{serial}", auth.ResourceCerts, auth.ActionRead, (*Handlers).GetCertificate),
		adminRoute("POST", "/certificates/{serial}/revoke", auth.ResourceCerts, auth.ActionRevoke, (*Handlers).RevokeCertificate),

		// ACME account management.
		adminRoute("GET", "/accounts", auth.ResourceACMEAccounts, auth.ActionList, (*Handlers).ListAccounts),
		adminRoute("GET", "/accounts/{id}", auth.ResourceACMEAccounts, auth.ActionRead, (*Handlers).GetAccount),
		adminRoute("DELETE", "/accounts/{id}", auth.ResourceACMEAccounts, auth.ActionDisable, (*Handlers).DisableAccount),

		// ACME order management.
		adminRoute("GET", "/orders", auth.ResourceACMEOrders, auth.ActionList, (*Handlers).ListOrders),
		adminRoute("GET", "/orders/{id}", auth.ResourceACMEOrders, auth.ActionRead, (*Handlers).GetOrder),

		// Audit trail.
		adminRoute("GET", "/audit", auth.ResourceAudit, auth.ActionRead, (*Handlers).ListAuditLogs),

		// CA status and statistics.
		adminRoute("GET", "/status", auth.ResourceAdmin, auth.ActionStatus, (*Handlers).GetStatus),
		adminRoute("GET", "/stats", auth.ResourceAdmin, auth.ActionStatus, (*Handlers).GetStats),

		// Algorithm capability discovery.
		adminRoute("GET", "/algorithms", auth.ResourceAdmin, auth.ActionCapabilities, (*Handlers).GetAlgorithms),
	}
}

// tenantRoutes is the /api/v1/tenants route table.
func tenantRoutes() []route[*TenantHandlers] {
	return []route[*TenantHandlers]{
		// Tenant record updates. Create, list, get and delete belong to the
		// core xkms module's /api/v1/tenants routes (go-xkms#794). A call
		// within the caller's own tenant needs the self-scoped tenants:*
		// grant; a call reaching any other tenant needs qrdb's cross-scope
		// grant, which only a system-tenant caller holds.
		tenantReachRoute("PUT", "/{id}", auth.ResourceTenants, auth.ActionUpdate, qrdbsdk.PermissionTenantsUpdateCross, (*TenantHandlers).UpdateTenant),
		tenantReachRoute("PUT", "/{id}/status", auth.ResourceTenants, auth.ActionUpdate, qrdbsdk.PermissionTenantsUpdateCross, (*TenantHandlers).UpdateTenantStatus),

		// Tenant CA hierarchy. Creating or retiring a signing CA is strictly
		// more privileged than issuing a leaf certificate, so it is gated on
		// ca:* rather than certs:*.
		tenantRoute("POST", "/{id}/root-ca", auth.ResourceCA, auth.ActionCreate, (*TenantHandlers).CreateTenantRootCA),
		tenantRoute("GET", "/{id}/intermediate-cas", auth.ResourceCA, auth.ActionList, (*TenantHandlers).ListTenantIntermediateCAs),
		tenantRoute("POST", "/{id}/intermediate-cas", auth.ResourceCA, auth.ActionCreate, (*TenantHandlers).CreateTenantIntermediateCA),
		tenantRoute("GET", "/{id}/intermediate-cas/{caid}", auth.ResourceCA, auth.ActionRead, (*TenantHandlers).GetTenantIntermediateCA),
		tenantRoute("PUT", "/{id}/intermediate-cas/{caid}/status", auth.ResourceCA, auth.ActionUpdate, (*TenantHandlers).UpdateTenantIntermediateCAStatus),
		tenantRoute("PUT", "/{id}/default-intermediate-ca", auth.ResourceCA, auth.ActionUpdate, (*TenantHandlers).SetTenantDefaultIntermediateCA),
		tenantRoute("GET", "/{id}/ca-status", auth.ResourceCA, auth.ActionRead, (*TenantHandlers).GetTenantCAStatus),

		// External Account Bindings. acme_eab:create is the "endorser"
		// authority; a deployment that needs an endorse-only principal
		// creates a qrdb role holding exactly that permission.
		tenantRoute("GET", "/{id}/eab", auth.ResourceACMEEAB, auth.ActionList, (*TenantHandlers).ListTenantEABs),
		tenantRoute("POST", "/{id}/eab", auth.ResourceACMEEAB, auth.ActionCreate, (*TenantHandlers).CreateTenantEAB),
		tenantRoute("GET", "/{id}/eab/{kid}", auth.ResourceACMEEAB, auth.ActionRead, (*TenantHandlers).GetTenantEAB),
		tenantRoute("DELETE", "/{id}/eab/{kid}", auth.ResourceACMEEAB, auth.ActionDelete, (*TenantHandlers).DeleteTenantEAB),

		// Tenant role management.
		tenantRoute("GET", "/{id}/roles", auth.ResourceRoles, auth.ActionList, (*TenantHandlers).ListTenantRoles),
		tenantRoute("POST", "/{id}/roles", auth.ResourceRoles, auth.ActionCreate, (*TenantHandlers).CreateTenantRole),
		tenantRoute("GET", "/{id}/roles/{roleID}", auth.ResourceRoles, auth.ActionRead, (*TenantHandlers).GetTenantRole),
		tenantRoute("PUT", "/{id}/roles/{roleID}", auth.ResourceRoles, auth.ActionUpdate, (*TenantHandlers).UpdateTenantRole),
		tenantRoute("DELETE", "/{id}/roles/{roleID}", auth.ResourceRoles, auth.ActionDelete, (*TenantHandlers).DeleteTenantRole),

		// Tenant user management.
		tenantRoute("GET", "/{id}/users", auth.ResourceUsers, auth.ActionList, (*TenantHandlers).ListTenantUsers),
		tenantRoute("POST", "/{id}/users", auth.ResourceUsers, auth.ActionCreate, (*TenantHandlers).CreateTenantUser),
		tenantRoute("GET", "/{id}/users/{userID}", auth.ResourceUsers, auth.ActionRead, (*TenantHandlers).GetTenantUser),
		tenantRoute("PUT", "/{id}/users/{userID}", auth.ResourceUsers, auth.ActionUpdate, (*TenantHandlers).UpdateTenantUser),
		tenantRoute("DELETE", "/{id}/users/{userID}", auth.ResourceUsers, auth.ActionDelete, (*TenantHandlers).DeleteTenantUser),
	}
}

// appendRoutes appends routes to out as full-path Routes under prefix.
func appendRoutes[H any](out []Route, prefix string, routes []route[H]) []Route {
	for _, rt := range routes {
		out = append(out, Route{Method: rt.method, Path: prefix + rt.path, Permission: rt.perm, SelfPermission: rt.self})
	}
	return out
}

// mountRoutes registers routes, served by h, on a subrouter at prefix that
// runs authMiddleware first, with guard wrapping each handler.
func mountRoutes[H any](router *mux.Router, prefix string, authMiddleware AuthHandler, h H, routes []route[H], guard guardFunc) {
	sub := router.PathPrefix(prefix).Subrouter()
	if authMiddleware != nil {
		sub.Use(authMiddleware.Authenticate)
	}
	for _, rt := range routes {
		serve := rt.serve
		handler := func(w http.ResponseWriter, r *http.Request) { serve(h, w, r) }
		sub.Handle(rt.path, guard(rt.grant, handler)).Methods(rt.method)
	}
}
