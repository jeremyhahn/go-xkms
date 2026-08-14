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
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
)

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// newResponseWriter creates a new responseWriter.
func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// WriteHeader captures the status code.
func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

// Write ensures WriteHeader is called.
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// LoggingMiddleware logs HTTP requests using the configured logger.
func (s *Server) LoggingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := newResponseWriter(w)
			ctx := r.Context()

			// Get identity from context if available
			identity := auth.GetIdentity(ctx)
			subject := "anonymous"
			if identity != nil {
				subject = identity.Subject
			}

			// Use context-aware logging to include correlation ID
			s.logger.DebugContext(ctx, "Request started",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("subject", subject))

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
			s.logger.InfoContext(ctx, "Request completed",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", wrapped.statusCode),
				slog.String("duration", duration.String()),
				slog.String("subject", subject))
		})
	}
}

// corsAllowHeaders lists the request headers a cross-origin browser may send.
// The WebAuthn RP correlates its begin/finish ceremonies through the
// X-Session-Id (and, for login, X-User-Id) request headers, so they must be
// permitted or the preflight for /api/v1/webauthn/*/finish fails.
const corsAllowHeaders = "Content-Type, Authorization, " +
	webauthnhttp.HeaderSessionID + ", " + webauthnhttp.HeaderUserID

// corsExposeHeaders lists the response headers a cross-origin browser may read.
// The WebAuthn RP returns the session correlation identifiers on its begin
// responses; without exposing them a cross-origin client cannot complete the
// ceremony.
const corsExposeHeaders = webauthnhttp.HeaderSessionID + ", " + webauthnhttp.HeaderUserID

// CORSOptions configures cross-origin resource sharing for the REST router.
// A nil options value — or one with an empty AllowedOrigins list — disables
// CORS entirely: no CORS headers are emitted and preflight requests fall
// through to the router. The embedded web UI is served same-origin and needs
// no CORS; only deployments that intentionally serve browser clients from
// another origin should enable it.
type CORSOptions struct {
	// AllowedOrigins lists the exact origins (scheme://host[:port]) permitted
	// to make cross-origin requests. The wildcard "*" is honored but reported
	// as a compliance gap by config.ComplianceGaps.
	AllowedOrigins []string

	// AllowCredentials sets Access-Control-Allow-Credentials on allowed
	// responses. It is ignored for the wildcard origin: the Fetch standard
	// forbids credentials with "Access-Control-Allow-Origin: *".
	AllowCredentials bool

	// MaxAgeSeconds caps how long browsers may cache a preflight response.
	// Values <= 0 default to 3600.
	MaxAgeSeconds int
}

// allowsOrigin reports whether origin is in the allowlist, and whether the
// match was the wildcard entry.
func (o *CORSOptions) allowsOrigin(origin string) (allowed, wildcard bool) {
	for _, a := range o.AllowedOrigins {
		if a == "*" {
			return true, true
		}
		if strings.EqualFold(strings.TrimRight(a, "/"), origin) {
			return true, false
		}
	}
	return false, false
}

// NewCORSMiddleware returns middleware emitting CORS headers per opts. With
// nil opts (or no allowed origins) it is a pass-through: same-origin browsers
// need no CORS headers, and omitting them fails closed for everyone else.
func NewCORSMiddleware(opts *CORSOptions) func(http.Handler) http.Handler {
	if opts == nil || len(opts.AllowedOrigins) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	maxAge := opts.MaxAgeSeconds
	if maxAge <= 0 {
		maxAge = 3600
	}
	maxAgeValue := strconv.Itoa(maxAge)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Same-origin or non-browser request: no CORS headers apply.
				next.ServeHTTP(w, r)
				return
			}

			allowed, wildcard := opts.allowsOrigin(origin)
			if !allowed {
				// Not allow-listed: emit nothing and let the browser's
				// same-origin policy block the response. Preflights still
				// fall through so the 404/405 semantics stay unchanged.
				next.ServeHTTP(w, r)
				return
			}

			h := w.Header()
			if wildcard {
				// The Fetch standard forbids credentials with the wildcard
				// origin, so wildcard responses never carry the credentials
				// header — credentialed cross-origin access requires listing
				// the origin explicitly.
				h.Set("Access-Control-Allow-Origin", "*")
			} else {
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
				if opts.AllowCredentials {
					h.Set("Access-Control-Allow-Credentials", "true")
				}
			}
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
			h.Set("Access-Control-Expose-Headers", corsExposeHeaders)
			h.Set("Access-Control-Max-Age", maxAgeValue)

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RecoveryMiddleware recovers from panics and returns a 500 error.
func (s *Server) RecoveryMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					s.logger.Error("Panic recovered",
						slog.String("method", r.Method),
						slog.String("path", r.URL.Path),
						slog.Any("error", err))
					writeErrorWithMessage(w, ErrInternalError, "An unexpected error occurred", http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// ContentTypeMiddleware ensures Content-Type is set for JSON responses.
func ContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

// AuthenticationMiddleware authenticates HTTP requests.
//
// The single exemption is the init ceremony claim surface: while the ceremony
// has not yet reached the operational state, the exact paths named by
// publicCeremonyPaths are served without an identity assertion because the
// officer's first credential is the certificate those routes hand out. See
// middleware_init_public.go for the full rationale and the fail-closed
// conditions.
func (s *Server) AuthenticationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.isPublicCeremonyRequest(r) {
				s.logger.Debug("Serving init ceremony route without authentication",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("remote_addr", r.RemoteAddr))
				next.ServeHTTP(w, r)
				return
			}

			// Authenticate the request
			identity, err := s.authenticator.AuthenticateHTTP(r)
			if err != nil {
				s.logger.Warn("Authentication failed",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("remote_addr", r.RemoteAddr),
					slog.String("error", err.Error()))
				writeErrorWithMessage(w, ErrUnauthorized, "Authentication failed", http.StatusUnauthorized)
				return
			}

			// Store identity in context
			ctx := auth.WithIdentity(r.Context(), identity)
			r = r.WithContext(ctx)

			s.logger.Debug("Request authenticated",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("subject", identity.Subject))

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeadersMiddleware sets the browser security headers for the
// embedded web UI: a same-origin Content Security Policy that also refuses
// framing, MIME-type sniffing protection, and a no-referrer policy. It is
// applied to the UI mount only; API responses are not browser documents.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
