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
	"net/http"
	"sync/atomic"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
)

// identityGatedPermission is go-qrdb's identity-gated sentinel:
// authentication is required but authorization is deferred to the handler.
const identityGatedPermission = qrdbsdk.PermissionIdentityGated

// RESTResolver returns the *rest.Server whose handler surface backs the
// module's HTTP routes, or nil while the host is still composing it. It is
// a resolver for the same construction-order reason as ServiceResolver:
// RegisterHTTP fires during embedded-node construction, long before the
// REST wiring exists.
type RESTResolver func() *rest.Server

// WithWebUI registers the embedded web UI on the unified server under
// uiPrefix (a normalized mount prefix, e.g. "/ui"). The SPA is public by
// design (a login page must render before authentication) and late-binds
// through the REST resolver like every other route. redirectRoot also
// registers GET / as a redirect to the prefix.
func WithWebUI(uiPrefix string, redirectRoot bool) Option {
	return func(m *Module) {
		m.uiPrefix = uiPrefix
		m.uiRedirectRoot = redirectRoot
	}
}

// WithRESTServer wires the REST surface resolver consumed by RegisterHTTP.
// Without it the module registers no HTTP routes.
func WithRESTServer(resolve RESTResolver) Option {
	return func(m *Module) {
		m.resolveREST = resolve
	}
}

// RegisterHTTP registers the full xkms REST surface (pkg/api/rest Routes(),
// the same table the legacy router serves) onto the unified server's
// permission-recording registrar:
//
//   - public routes register via HandlePublic;
//   - authenticated-session routes register under the identity-gated
//     sentinel (auth required, authorization deferred to the handler);
//   - permission routes register under their resource:action permission,
//     enforced by qrdb's authorization layer.
//
// The route table registers unconditionally — with a host-supplied
// resolver (WithRESTServer), with the module's self-built surface
// (WithQRDBClient / WithWebAuthnConfig / WithSessionOptions / WithPIVLogin,
// or none of those, restServer's rest.NewHostServer fallback), or with
// neither. Handlers late-bind through restServer exactly like the gRPC
// surface: until the REST wiring composes, every route answers 503; if the
// host gave the module nothing it could build a working REST surface from,
// every route answers 503 with that construction failure's message instead
// of silently not existing. A route whose backing subsystem is not
// configured on the resolved server answers 501. Routes that appear more
// than once in the table (availability variants, e.g. the CA bundle
// endpoint's full-CA and bootstrap-only forms) register once, choosing the
// enabled variant at request time.
func (m *Module) RegisterHTTP(r *qrdbserver.ModuleHTTPRegistrar) {
	type routeKey struct{ method, pattern string }
	variants := map[routeKey][]rest.RouteSpec{}
	var order []routeKey
	for _, spec := range rest.Routes() {
		// The host serves its own /health.
		if rest.IsHostRoute(spec) {
			continue
		}
		key := routeKey{spec.Method, spec.Pattern}
		if _, seen := variants[key]; !seen {
			order = append(order, key)
		}
		variants[key] = append(variants[key], spec)
	}

	preflight := m.lazyPreflightHandler()
	preflighted := map[string]bool{}
	for _, key := range order {
		specs := variants[key]
		lead := specs[0]
		h := m.lazyHTTPHandler(specs)
		switch lead.Auth {
		case rest.RouteAuthPublic:
			r.HandlePublic(lead.Method, lead.Pattern, h)
		case rest.RouteAuthSession, rest.RouteAuthTenant:
			r.Handle(lead.Method, lead.Pattern, identityGatedPermission, h)
		default:
			r.Handle(lead.Method, lead.Pattern,
				qrdbsdk.Permission(lead.Resource+":"+lead.Action), h)
		}

		// A browser sends the CORS preflight without credentials, so it is
		// public on every pattern; the CORS policy decides it
		// (rest.Server.BindPreflight).
		if !preflighted[lead.Pattern] {
			preflighted[lead.Pattern] = true
			r.HandlePublic(http.MethodOptions, lead.Pattern, preflight)
		}
	}

	// Embedded web UI: the SPA is public by design (the login page renders
	// before authentication) and late-binds through the REST resolver.
	if m.uiPrefix != "" {
		ui := m.lazyUIHandler()
		r.HandlePublic("GET", m.uiPrefix, ui)
		r.HandlePublic("GET", m.uiPrefix+"/*", ui)
		if m.uiRedirectRoot {
			prefix := m.uiPrefix
			r.HandlePublic("GET", "/", func(w http.ResponseWriter, req *http.Request) {
				http.Redirect(w, req, prefix, http.StatusFound)
			})
		}
	}
}

// lazyUIHandler resolves the REST server's embedded web UI handler on first
// use, memoizing it once available. 503 while the host composes; 404 when
// the resolved server has no UI configured.
func (m *Module) lazyUIHandler() http.HandlerFunc {
	var bound atomic.Pointer[http.Handler]
	return func(w http.ResponseWriter, req *http.Request) {
		if h := bound.Load(); h != nil {
			(*h).ServeHTTP(w, req)
			return
		}
		srv, err := m.restServer()
		if err != nil {
			http.Error(w, "xkms web ui: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		if srv == nil {
			http.Error(w, "xkms web ui is not yet available (server still composing)",
				http.StatusServiceUnavailable)
			return
		}
		h, _, _, ok := srv.UIHandler()
		if !ok {
			http.NotFound(w, req)
			return
		}
		if !bound.CompareAndSwap(nil, &h) {
			h = *bound.Load()
		}
		h.ServeHTTP(w, req)
	}
}

// lazyPreflightHandler returns the CORS preflight handler every REST route
// pattern is mounted with (rest.Server.BindPreflight), binding it on first
// use. It is the same handler for every pattern: the configured CORS policy
// covers the whole REST surface, as on the legacy router.
func (m *Module) lazyPreflightHandler() http.HandlerFunc {
	var bound atomic.Pointer[http.Handler]
	return func(w http.ResponseWriter, req *http.Request) {
		if h := bound.Load(); h != nil {
			(*h).ServeHTTP(w, req)
			return
		}
		srv, err := m.restServer()
		if err != nil {
			http.Error(w, "xkms rest surface: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		if srv == nil {
			http.Error(w, "xkms rest surface is not yet available (server still composing)",
				http.StatusServiceUnavailable)
			return
		}
		h := srv.BindPreflight()
		if !bound.CompareAndSwap(nil, &h) {
			h = *bound.Load()
		}
		h.ServeHTTP(w, req)
	}
}

// lazyHTTPHandler returns a handler that resolves the REST surface on first
// use, memoizing the bound handler chain (group middleware + handler) once
// the enabled variant is known. Lock-free: concurrent first calls may both
// bind, and the CompareAndSwap keeps exactly one.
func (m *Module) lazyHTTPHandler(specs []rest.RouteSpec) http.HandlerFunc {
	var bound atomic.Pointer[http.Handler]
	return func(w http.ResponseWriter, req *http.Request) {
		if h := bound.Load(); h != nil {
			(*h).ServeHTTP(w, req)
			return
		}
		srv, err := m.restServer()
		if err != nil {
			http.Error(w, "xkms rest surface: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		if srv == nil {
			http.Error(w, "xkms rest surface is not yet available (server still composing)",
				http.StatusServiceUnavailable)
			return
		}
		var chosen *rest.RouteSpec
		for i := range specs {
			if srv.RouteEnabled(specs[i]) {
				chosen = &specs[i]
				break
			}
		}
		if chosen == nil {
			http.Error(w, "xkms subsystem for this route is not configured on this server",
				http.StatusNotImplemented)
			return
		}
		h := srv.BindRoute(*chosen)
		if !bound.CompareAndSwap(nil, &h) {
			h = *bound.Load()
		}
		h.ServeHTTP(w, req)
	}
}

// Compile-time proof the module implements qrdb's authentication fallback:
// the unified server consults it when its own authenticators produce no
// identity for a request on an xkms route.
var _ qrdbserver.ModuleAuthFallback = (*Module)(nil)

// AuthenticateHTTP authenticates a request with xkms's session-vehicle
// chain (the JWT pairs the FIDO2/PIV login ceremonies mint, plus mTLS).
// go-qrdb's REST middleware invokes it only after its own authenticators
// found no identity; the returned identity is finalized and authorized by
// qrdb's single enrichment + authorizer path. While the REST engine is
// still composing, authentication fails closed.
func (m *Module) AuthenticateHTTP(r *http.Request) (*qrdbsdk.Identity, error) {
	srv, err := m.restServer()
	if err != nil {
		return nil, err
	}
	if srv == nil {
		return nil, &SurfaceComposingError{Surface: "authentication"}
	}
	return srv.AuthenticateHTTP(r)
}

// SurfaceComposingError reports a module surface consulted before the
// backing engine finished composing. Authentication fails closed on it.
type SurfaceComposingError struct {
	// Surface names the consulted surface.
	Surface string
}

// Error describes the composing state.
func (e *SurfaceComposingError) Error() string {
	return "xkms module: " + e.Surface + " is not yet available (server still composing)"
}
