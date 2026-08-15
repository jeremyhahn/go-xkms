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
// Authentication is single-pass: the identity plane is shared by
// construction (xkms auth.Identity is qrdb's Identity, read from qrdb's
// context key), so when qrdb's middleware has already authenticated the
// request the identity is visible to every xkms handler and the xkms
// authenticator is skipped; the xkms authenticator runs only for requests
// qrdb admitted without an identity (e.g. auth disabled), preserving the
// legacy contract.
func (s *Server) BindRoute(spec RouteSpec) http.Handler {
	var h http.Handler = spec.Handler(s)

	switch spec.Group {
	case GroupAPIv1, GroupSSH:
		h = s.TenantMiddleware()(h)
		h = s.upstreamOrLocalAuth(h)
	case GroupUsers:
		h = s.upstreamOrLocalAuth(h)
	case GroupAuthSession:
		if spec.Auth == RouteAuthSession {
			h = s.upstreamOrLocalAuth(h)
		}
		if s.authRateLimiter != nil && s.authRateLimiter.IsEnabled() {
			h = ratelimit.Middleware(s.authRateLimiter)(h)
		}
	case GroupWebAuthn:
		if s.authRateLimiter != nil && s.authRateLimiter.IsEnabled() {
			h = ratelimit.Middleware(s.authRateLimiter)(h)
		}
	}

	return h
}

// upstreamOrLocalAuth admits a request that already carries an
// authenticated identity (placed in the context by go-qrdb's middleware on
// the unified server) and otherwise runs xkms's own authentication
// middleware. The identity type and context key are shared with qrdb, so
// handlers observe the identical contract on both paths.
func (s *Server) upstreamOrLocalAuth(next http.Handler) http.Handler {
	local := s.AuthenticationMiddleware()(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.GetIdentity(r.Context()) != nil {
			next.ServeHTTP(w, r)
			return
		}
		local.ServeHTTP(w, r)
	})
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
