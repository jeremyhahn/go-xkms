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
	"net/http"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
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
			if slogAdapter, ok := s.logger.(*logger.SlogAdapter); ok {
				slogAdapter.DebugContext(ctx, "Request started",
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path),
					logger.String("subject", subject))
			} else {
				s.logger.Debug("Request started",
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path),
					logger.String("subject", subject))
			}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
			if slogAdapter, ok := s.logger.(*logger.SlogAdapter); ok {
				slogAdapter.InfoContext(ctx, "Request completed",
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path),
					logger.Int("status", wrapped.statusCode),
					logger.String("duration", duration.String()),
					logger.String("subject", subject))
			} else {
				s.logger.Info("Request completed",
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path),
					logger.Int("status", wrapped.statusCode),
					logger.String("duration", duration.String()),
					logger.String("subject", subject))
			}
		})
	}
}

// CORSMiddleware adds CORS headers to responses.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RecoveryMiddleware recovers from panics and returns a 500 error.
func (s *Server) RecoveryMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					s.logger.Error("Panic recovered",
						logger.String("method", r.Method),
						logger.String("path", r.URL.Path),
						logger.Any("error", err))
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
func (s *Server) AuthenticationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Authenticate the request
			identity, err := s.authenticator.AuthenticateHTTP(r)
			if err != nil {
				s.logger.Warn("Authentication failed",
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path),
					logger.String("remote_addr", r.RemoteAddr),
					logger.Error(err))
				writeErrorWithMessage(w, ErrUnauthorized, "Authentication failed", http.StatusUnauthorized)
				return
			}

			// Store identity in context
			ctx := auth.WithIdentity(r.Context(), identity)
			r = r.WithContext(ctx)

			s.logger.Debug("Request authenticated",
				logger.String("method", r.Method),
				logger.String("path", r.URL.Path),
				logger.String("subject", identity.Subject))

			next.ServeHTTP(w, r)
		})
	}
}
