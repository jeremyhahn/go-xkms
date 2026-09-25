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

package circuitbreaker

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// ErrHandlerFailed is the sentinel Middleware settles a breaker with when the
// wrapped handler responds with a 5xx status. It never reaches the client;
// Middleware itself writes the response for an open breaker, and a
// successful (non-5xx) request settles with a nil error.
var ErrHandlerFailed = errors.New("circuit breaker: handler responded with a server error")

// Middleware returns an HTTP middleware that protects next with cb: a request
// arriving while cb is open is rejected immediately with 503 and a
// Retry-After header, without reaching next. A request that is let through
// settles cb with the response's outcome -- a 5xx status counts as a
// failure, anything else as a success -- exactly like Execute would for a
// plain function call.
//
// Middleware uses Allow/Complete rather than Execute: next writes directly to
// the ResponseWriter, and Execute's goroutine-plus-timeout would let next
// keep writing to a connection the timed-out caller has already returned
// from.
func Middleware(cb *CircuitBreaker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adm, err := cb.Allow()
			if err != nil {
				writeCircuitOpenError(w, cb)
				return
			}

			wrapped := &statusCapturingWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(wrapped, r)

			if wrapped.statusCode >= http.StatusInternalServerError {
				cb.Complete(adm, ErrHandlerFailed)
			} else {
				cb.Complete(adm, nil)
			}
		})
	}
}

// statusCapturingWriter wraps http.ResponseWriter to capture the status code
// written by the handler, so Middleware can judge success without buffering
// or otherwise altering the response body.
type statusCapturingWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code.
func (w *statusCapturingWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// writeCircuitOpenError writes an HTTP 503 response for a request rejected
// because cb is open, with Retry-After set to cb's remaining reset timeout.
func writeCircuitOpenError(w http.ResponseWriter, cb *CircuitBreaker) {
	lastFailure := time.Unix(0, cb.lastFailureTime.Load())
	remaining := cb.resetTimeout - time.Since(lastFailure)
	if remaining < time.Second {
		remaining = time.Second
	}
	retryAfterSeconds := int(remaining.Seconds())

	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)

	body := `{"error":"service_unavailable","message":"Service temporarily unavailable. Circuit breaker is open.","retry_after":` +
		strconv.Itoa(retryAfterSeconds) + `}`
	if _, err := w.Write([]byte(body)); err != nil {
		slog.Debug("circuitbreaker: failed to write open-circuit response", "error", err)
	}
}
