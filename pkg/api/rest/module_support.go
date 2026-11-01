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

	"github.com/go-chi/chi/v5"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/webui"
)

// BindRoute binds a RouteSpec's handler on s with the middleware profile its
// RouteGroup carries on the legacy router — authentication, tenant
// enforcement, and the login rate limiter — but WITHOUT the per-route RBAC
// decorator: on the unified API server the per-route permission is enforced
// by go-qrdb's authorization layer at the registration site
// (pkg/apimodule), and a second in-handler RBAC pass would double-authorize
// every call against a different decision point.
//
// Authentication is qrdb's: its middleware authenticates every non-public
// route (mTLS chain first, then the module's AuthenticateHTTP fallback for
// xkms session tokens) and binds the identity into the request context
// before the handler chain runs — the identity plane is shared by
// construction (xkms auth.Identity IS qrdb's Identity).
func (s *Server) BindRoute(spec RouteSpec) http.Handler {
	// The request body bound is xkms's own per-route concern, identical to
	// the legacy router's (registerRoutes).
	h := BodyLimitMiddleware(spec.bodyLimit())(spec.Handler(s))

	// A tenant lifecycle route's decision depends on the tenant it targets
	// (own tenant, or another one under a cross permission), which the
	// router's flat resource:action check cannot express; the module mounts
	// it identity-gated and TenantGate renders it here (go-xkms#794).
	if spec.Auth == RouteAuthTenant {
		h = s.tenantGate.Require(spec)(h)
	}

	// Authentication is NOT applied here: on the unified server go-qrdb's
	// middleware authenticates every non-public route — its own mTLS chain
	// first, then the module's fallback (Server.AuthenticateHTTP, the
	// composite jwt+mtls session vehicles) — and the ONE qrdb authorizer
	// renders the decision before the handler runs. Only xkms-specific
	// per-group concerns remain on the route chain.
	switch spec.Group {
	case GroupAPIv1, GroupSSH:
		h = s.TenantMiddleware()(h)
	case GroupAuthSession, GroupWebAuthn, GroupInvite:
		if s.authRateLimiter != nil && s.authRateLimiter.IsEnabled() {
			h = ratelimit.Middleware(s.authRateLimiter, s.trustedProxies)(h)
		}
	}

	// Binds the request to the ResponseWriter so writeError can log an
	// internal error it withholds from the client (go-xkms#1118), matching
	// setupRouter on the legacy router.
	h = s.errorLogMiddleware()(h)

	// Outermost: the configured CORS policy, as on the legacy router, so a
	// response to an allow-listed browser origin carries its
	// Access-Control-* headers. The preflight is BindPreflight's.
	return NewCORSMiddleware(s.cors)(h)
}

// BindPreflight returns the handler for a CORS preflight (OPTIONS) on a
// route BindRoute serves. The module mounts it public: a browser sends the
// preflight without credentials (Fetch standard, CORS-preflight fetch), so
// go-qrdb's authentication would refuse it before the policy runs. An
// allow-listed origin is answered 204 with the policy's headers
// (NewCORSMiddleware); any other preflight, or every preflight when no CORS
// policy is configured, is refused with ErrCORSPreflightRefused.
func (s *Server) BindPreflight() http.Handler {
	refuse := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, ErrCORSPreflightRefused, http.StatusForbidden)
	})
	return NewCORSMiddleware(s.cors)(refuse)
}

// AuthenticateHTTP authenticates a request with xkms's configured
// authenticator chain (the composite jwt+mtls session vehicles). It backs
// the module's qrdb ModuleAuthFallback: on the unified server, go-qrdb's
// middleware runs its own authenticators first and consults this method
// only when they produce no identity — the returned identity then flows
// through qrdb's store-resolved role enrichment and the ONE authorizer,
// exactly like an mTLS identity. Fails closed on any authentication error.
func (s *Server) AuthenticateHTTP(r *http.Request) (*auth.Identity, error) {
	if s.authenticator == nil {
		return nil, ErrAuthenticatorRequired
	}
	return s.authenticator.AuthenticateHTTP(r)
}

// RouteEnabled reports whether the route's backing subsystem is configured
// on s.
func (s *Server) RouteEnabled(spec RouteSpec) bool {
	return spec.Enabled == nil || spec.Enabled(s)
}

// UIHandler returns the embedded web UI as a standalone handler (SPA mount
// plus the browser security headers), together with its normalized mount
// prefix and whether GET / should redirect to it. ok is false when no UI is
// configured on this server. On the unified API server the module registers
// this under the prefix (pkg/apimodule); on the legacy loopback engine
// setupRouter mounts it directly.
func (s *Server) UIHandler() (h http.Handler, prefix string, redirectRoot bool, ok bool) {
	if s.ui == nil || !s.ui.Enabled || s.ui.Assets == nil {
		return nil, "", false, false
	}
	prefix, err := webui.NormalizePrefix(s.ui.PathPrefix)
	if err != nil {
		s.logger.Error("web UI handler: invalid path prefix",
			slog.String("prefix", s.ui.PathPrefix), slog.Any("error", err))
		return nil, "", false, false
	}
	r := chi.NewRouter()
	r.Use(SecurityHeadersMiddleware)
	if err := webui.MountChi(r, s.ui.Assets, prefix, s.logger); err != nil {
		s.logger.Error("web UI handler: mount failed", slog.Any("error", err))
		return nil, "", false, false
	}
	return r, prefix, s.ui.RedirectRoot, true
}
