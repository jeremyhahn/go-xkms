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

// Package guard implements the one cross-origin policy shared by the ACME
// client and admin desktop GUI APIs (pkg/acme/gui/client/api and
// pkg/acme/gui/admin/api).
//
// Both routers can be reached two ways: mounted in-process behind a Wails
// AssetServer Handler, where no socket exists, or — the ACME client router
// only, via "trusted-acme-client serve" — on a TCP listener, where a
// cross-origin browser request is a real threat. WithInProcessTransport
// tells the guard which case it is in.
//
// On a network listener only a same-origin caller is served. In-process,
// every origin is accepted and answered with a permissive header, because a
// webview serves the frontend from a scheme of its own — wails://wails on
// Linux and macOS, http://wails.localhost on Windows — whose serialized
// origin varies by platform and may be opaque ("null"), so enforcing an
// origin there would reject the application's own user interface.
package guard

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

const (
	// AllowedMethods is the value of Access-Control-Allow-Methods sent on
	// every accepted, cross-origin-annotated request.
	AllowedMethods = "GET, POST, PUT, DELETE, OPTIONS"
	// AllowedHeaders is the value of Access-Control-Allow-Headers sent on
	// every accepted, cross-origin-annotated request.
	AllowedHeaders = "Content-Type, Authorization"
	// AnyOrigin is the wildcard Access-Control-Allow-Origin value used
	// in-process, where the caller's real origin is not knowable.
	AnyOrigin = "*"
)

// ErrForbiddenOrigin indicates the request came from a cross-origin caller,
// which only a network deployment of a guarded router rejects at all.
type ErrForbiddenOrigin struct {
	Origin string
}

// Error returns the error message.
func (e *ErrForbiddenOrigin) Error() string {
	return "gui/guard: forbidden origin: " + e.Origin
}

// DenyFunc writes the rejection to the caller in the response envelope of
// the router that installed the guard. Guard has already logged the
// rejection and chosen the status code by the time DenyFunc runs; DenyFunc
// need only serialize err.
type DenyFunc func(w http.ResponseWriter, r *http.Request, status int, err error)

// Option configures a Guard.
type Option func(*Guard)

// WithInProcessTransport declares that the router is mounted behind an
// in-process handler instead of a network listener. See the package doc for
// the rationale.
func WithInProcessTransport() Option {
	return func(g *Guard) {
		g.inProcess = true
	}
}

// Guard applies the cross-origin policy to every request reaching a router.
// Its zero value, produced by New, defends a network deployment: only
// same-origin callers are served.
type Guard struct {
	inProcess bool
	logger    *slog.Logger
	deny      DenyFunc
}

// New builds a Guard from the given options. deny writes a rejection in the
// caller's own response envelope; it must not be nil.
func New(logger *slog.Logger, deny DenyFunc, opts ...Option) *Guard {
	g := &Guard{logger: logger, deny: deny}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Middleware rejects cross-origin callers, annotates allowed ones with CORS
// headers and answers preflights.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			allow, ok := g.allowOrigin(origin, r.Host)
			if !ok {
				g.reject(w, r, &ErrForbiddenOrigin{Origin: origin})
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", allow)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", AllowedMethods)
			w.Header().Set("Access-Control-Allow-Headers", AllowedHeaders)
		}

		// A preflight carries no credentials and reveals nothing, so it is
		// answered as soon as the origin has been accepted.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AllowOrigin reports whether the caller may proceed and, when it may, the
// value to echo in Access-Control-Allow-Origin. Behind an in-process handler
// every origin is allowed and the wildcard is returned, because the
// webview's own origin is not knowable here. On a network listener only the
// request's own origin is allowed; an unparsable or opaque origin ("null")
// is not.
func (g *Guard) AllowOrigin(origin, host string) (string, bool) {
	return g.allowOrigin(origin, host)
}

func (g *Guard) allowOrigin(origin, host string) (string, bool) {
	if g.inProcess {
		return AnyOrigin, true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	if !strings.EqualFold(parsed.Host, host) {
		return "", false
	}
	return origin, true
}

// reject logs the rejection and delegates the response body to the deny
// callback supplied at construction.
func (g *Guard) reject(w http.ResponseWriter, r *http.Request, err error) {
	if g.logger != nil {
		g.logger.Warn("API request rejected",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("error", err.Error()),
		)
	}
	g.deny(w, r, http.StatusForbidden, err)
}
