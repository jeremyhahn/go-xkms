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

package apimodule

import (
	"io/fs"
	"net/http"
	"slices"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// AdminModuleName is the unique ServiceModule name go-xkms's ACME admin
// surface (API + SPA) registers under. It is distinct from ModuleName
// ("xkms") so qrdb's module registry shows two independently-composed
// capability planes on the same unified server: the wholesale crypto plane
// and the ACME admin plane.
const AdminModuleName = "xkms-admin"

// AdminRoute is one ACME admin API route AdminModule mounts: the HTTP
// method, the full path pattern ({name} segments), and the qrdb permission
// the unified server authorizes before the request reaches the resolved
// router. cmd/xkmsd supplies pkg/acme/admin's Routes table, converted
// field for field.
//
// SelfPermission is set on a route whose permission depends on the tenant
// the call reaches: SelfPermission within the caller's own tenant,
// Permission beyond it. The unified server cannot see that tenant, so
// AdminModule mounts such a route identity-gated and the resolved router
// authorizes it.
type AdminRoute struct {
	Method         string
	Path           string
	Permission     qrdbsdk.Permission
	SelfPermission qrdbsdk.Permission
}

// mountPermission is the permission the unified server authorizes rt
// against: its own, or go-qrdb's identity-gated sentinel for a route the
// resolved router authorizes by the tenant it reaches.
func (rt AdminRoute) mountPermission() qrdbsdk.Permission {
	if rt.SelfPermission != "" {
		return identityGatedPermission
	}
	return rt.Permission
}

// NilAdminRouterResolverError is returned by NewAdminModule when constructed
// without a router resolver: the module would have no way to ever reach the
// admin API, so construction fails instead of registering a dead surface.
type NilAdminRouterResolverError struct{}

// Error implements the error interface.
func (e *NilAdminRouterResolverError) Error() string {
	return "apimodule: NewAdminModule requires a non-nil admin router resolver"
}

// AdminRouterResolver returns the ACME admin surface's fully-assembled
// http.Handler, or nil while the host is still composing it. The returned
// handler routes and authenticates each request but does not authorize it:
// AdminModule mounts every AdminRoute through qrdb's HTTPRegistrar.Handle
// with the route's own permission, so the unified server's authentication
// chain (mTLS, then the xkms session JWT) and its RBAC decision have both
// run before the handler does. cmd/xkmsd builds it with pkg/acme/admin's
// RegisterAuthorizedRoutes.
//
// AdminModule deliberately does not import pkg/acme/admin. Doing so would
// cycle back through sdk/go, which already imports this package to
// re-export the crypto-plane Module; keeping AdminModule transport-generic
// (an http.Handler resolver plus a route table, exactly like Module's own
// RESTResolver/MCPResolver seams) avoids that cycle and keeps the admin
// package's composition entirely in the composing binary (cmd/xkmsd), where
// it already lives.
type AdminRouterResolver func() http.Handler

// AdminModuleOption configures optional AdminModule behavior at construction
// time.
type AdminModuleOption func(*AdminModule)

// WithAdminWebUI registers the admin SPA on the unified server under
// uiPrefix, serving assets from fsys. It mirrors WithWebUI's seam for the
// crypto-plane module (public by design — a login page must render before
// authentication) but mounts the admin plane's own SPA on its own prefix,
// never the crypto module's "/ui".
func WithAdminWebUI(uiPrefix string, fsys fs.FS, redirectRoot bool) AdminModuleOption {
	return func(m *AdminModule) {
		m.uiPrefix = uiPrefix
		m.uiAssets = fsys
		m.uiRedirectRoot = redirectRoot
	}
}

// AdminModule mounts go-xkms's ACME admin API and admin SPA as a qrdb
// ServiceModule, alongside — never instead of — the wholesale crypto-plane
// Module in module.go. A composing binary (cmd/xkmsd) registers it via
// server.WithExtraModules so it shares the same embedded qrdb node and
// operator-facing unified mTLS listener as the "xkms" module. It must never
// be registered on xkmsd's separate public ACME protocol listener
// (cmd/xkmsd/acme.go), which serves only RFC 8555 traffic.
type AdminModule struct {
	qrdbsdk.BaseModule

	resolveRouter AdminRouterResolver
	routes        []AdminRoute

	uiPrefix       string
	uiAssets       fs.FS
	uiRedirectRoot bool
}

// NewAdminModule constructs the ACME admin ServiceModule. resolveRouter
// late-binds because module registration happens during embedded qrdb node
// construction, before cmd/xkmsd has finished composing the admin service
// and its auth middleware. routes are the admin API routes the resolved
// router answers (pkg/acme/admin's Routes); construction fails without at
// least one, since a module registering no routes is a dead surface.
func NewAdminModule(resolveRouter AdminRouterResolver, routes []AdminRoute, opts ...AdminModuleOption) (*AdminModule, error) {
	if resolveRouter == nil {
		return nil, &NilAdminRouterResolverError{}
	}
	if len(routes) == 0 {
		return nil, &NoAdminRoutesError{}
	}
	m := &AdminModule{
		resolveRouter: resolveRouter,
		routes:        slices.Clone(routes),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// NoAdminRoutesError is returned by NewAdminModule when constructed without
// any admin API route to mount.
type NoAdminRoutesError struct{}

// Error implements the error interface.
func (e *NoAdminRoutesError) Error() string {
	return "apimodule: NewAdminModule requires at least one admin API route"
}

// Name uniquely identifies the module.
func (m *AdminModule) Name() string { return AdminModuleName }

// RegisterHTTP mounts each admin API route with its own permission, so the
// unified server authorizes every request before the resolved router serves
// it, and, when WithAdminWebUI configured one, the public admin SPA under its
// own prefix.
func (m *AdminModule) RegisterHTTP(r *qrdbsdk.ModuleHTTPRegistrar) {
	h := m.lazyAPIHandler()
	for _, rt := range m.routes {
		r.Handle(rt.Method, rt.Path, rt.mountPermission(), h)
	}

	if m.uiPrefix != "" && m.uiAssets != nil {
		ui := http.StripPrefix(m.uiPrefix, http.FileServer(http.FS(m.uiAssets)))
		r.HandlePublic(http.MethodGet, m.uiPrefix, ui.ServeHTTP)
		r.HandlePublic(http.MethodGet, m.uiPrefix+"/*", ui.ServeHTTP)
		if m.uiRedirectRoot {
			prefix := m.uiPrefix
			r.HandlePublic(http.MethodGet, "/", func(w http.ResponseWriter, req *http.Request) {
				http.Redirect(w, req, prefix, http.StatusFound)
			})
		}
	}
}

// lazyAPIHandler resolves the admin router on first use. It does not
// memoize: unlike the crypto-plane Module's REST/MCP surfaces (which bind
// once qrdb's own transports invoke RegisterGRPC), the admin router can
// legitimately still be nil on the first few requests during start-up, and
// re-checking the resolver is a cheap atomic load on the composing binary's
// side (see cmd/xkmsd's wiring) rather than something this module needs to
// cache.
func (m *AdminModule) lazyAPIHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := m.resolveRouter()
		if h == nil {
			http.Error(w, "xkms admin surface is not yet available (server still composing)",
				http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	}
}
