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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// AdminModuleName is the unique ServiceModule name go-xkms's ACME admin
// surface (API + SPA) registers under. It is distinct from ModuleName
// ("xkms") so qrdb's module registry shows two independently-composed
// capability planes on the same unified server: the wholesale crypto plane
// and the ACME admin plane.
const AdminModuleName = "xkms-admin"

// adminAPIMethods are the HTTP methods AdminModule forwards to the resolved
// router for each configured prefix. A method the inner router has no route
// for answers 404/405 from that router, exactly as it would if it were
// mounted directly on a top-level net/http server.
var adminAPIMethods = []string{
	http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch,
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
// handler is expected to authenticate and authorize every request itself
// (pkg/acme/admin's Handlers/TenantHandlers, wired with admin.AuthHandler and
// admin.PermissionGate — both backed by the same qrdb RBAC service every
// other transport uses): AdminModule deliberately does not import
// pkg/acme/admin. Doing so would cycle back through sdk/go, which already
// imports this package to re-export the crypto-plane Module; keeping
// AdminModule transport-generic (an http.Handler resolver, exactly like
// Module's own RESTResolver/MCPResolver seams) avoids that cycle and keeps
// the admin package's authn/authz composition entirely in the composing
// binary (cmd/xkmsd), where it already lives.
//
// Because the resolved handler is self-authenticating, AdminModule registers
// its routes as public at the qrdb layer — the qrdb node's own authenticators
// have no way to understand the admin plane's credential — mirroring how the
// crypto-plane Module's embedded web UI is public at the qrdb layer while its
// own REST surface still authenticates every request underneath (module_http.go).
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
	apiPrefixes   []string

	uiPrefix       string
	uiAssets       fs.FS
	uiRedirectRoot bool
}

// NewAdminModule constructs the ACME admin ServiceModule. resolveRouter
// late-binds because module registration happens during embedded qrdb node
// construction, before cmd/xkmsd has finished composing the admin service,
// its auth middleware, and its RBAC gate. apiPrefixes are the top-level path
// prefixes the resolved router answers under (the admin package's own route
// tables mount at "/admin" and "/api/v1/tenants" — see
// pkg/acme/admin/handlers.go and tenant_handlers.go); construction fails
// without at least one, since a module registering no routes is a dead
// surface.
func NewAdminModule(resolveRouter AdminRouterResolver, apiPrefixes []string, opts ...AdminModuleOption) (*AdminModule, error) {
	if resolveRouter == nil {
		return nil, &NilAdminRouterResolverError{}
	}
	if len(apiPrefixes) == 0 {
		return nil, &NilAdminAPIPrefixesError{}
	}
	m := &AdminModule{
		resolveRouter: resolveRouter,
		apiPrefixes:   apiPrefixes,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// NilAdminAPIPrefixesError is returned by NewAdminModule when constructed
// without any API path prefixes to mount the resolved router under.
type NilAdminAPIPrefixesError struct{}

// Error implements the error interface.
func (e *NilAdminAPIPrefixesError) Error() string {
	return "apimodule: NewAdminModule requires at least one admin API path prefix"
}

// Name uniquely identifies the module.
func (m *AdminModule) Name() string { return AdminModuleName }

// RegisterHTTP registers the admin API's route prefixes (public at the qrdb
// layer; see AdminRouterResolver's doc comment on why authn/authz still
// happens underneath) and, when WithAdminWebUI configured one, the admin SPA
// under its own prefix.
func (m *AdminModule) RegisterHTTP(r *qrdbsdk.ModuleHTTPRegistrar) {
	h := m.lazyAPIHandler()
	for _, prefix := range m.apiPrefixes {
		for _, method := range adminAPIMethods {
			r.HandlePublic(method, prefix, h)
			r.HandlePublic(method, prefix+"/*", h)
		}
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
