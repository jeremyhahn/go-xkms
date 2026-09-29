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
	"context"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/correlation"
)

// withheldErrorLogMessage is the log message recorded for an internal error
// whose text an error response withheld from the client.
const withheldErrorLogMessage = "rest: internal error withheld from client"

// errorLogWriter is the http.ResponseWriter errorLogMiddleware hands down
// the handler chain. It carries the request and logger clientErrorText
// needs to log an internal error it withholds from the client: writeError's
// call sites pass only the ResponseWriter, so the writer is the one value
// that reaches the error path from every handler without changing any call
// site.
type errorLogWriter struct {
	http.ResponseWriter
	logger  *slog.Logger
	request *http.Request
}

// Unwrap returns the underlying ResponseWriter, following the
// http.ResponseController convention.
func (w *errorLogWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// errorLogMiddleware wraps the ResponseWriter in an errorLogWriter bound to
// the request and s.logger. It is installed on both REST mounts: setupRouter
// (the legacy loopback router) and BindRoute (the unified API server).
func (s *Server) errorLogMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&errorLogWriter{ResponseWriter: w, logger: s.logger, request: r}, r)
		})
	}
}

// findErrorLogWriter walks w's Unwrap chain for the errorLogWriter
// errorLogMiddleware installed, returning nil when w was not served through
// it.
func findErrorLogWriter(w http.ResponseWriter) *errorLogWriter {
	for {
		switch v := w.(type) {
		case *errorLogWriter:
			return v
		case interface{ Unwrap() http.ResponseWriter }:
			w = v.Unwrap()
		default:
			return nil
		}
	}
}

// logWithheldError logs err, the detail of an internal error response,
// with the request's method, path and correlation ID. A writer that was not
// served through errorLogMiddleware (a handler invoked directly) carries no
// request context, and a Server built without NewServer carries no logger;
// either way err is still logged, through slog.Default -- the logger
// NewServer itself uses when Config.Logger is nil.
func logWithheldError(w http.ResponseWriter, err error, statusCode int) {
	logger := slog.Default()
	ctx := context.Background()
	attrs := []any{
		slog.Int("status", statusCode),
		slog.Any("error", err),
	}

	if ew := findErrorLogWriter(w); ew != nil {
		if ew.logger != nil {
			logger = ew.logger
		}
		r := ew.request
		ctx = r.Context()
		attrs = append(attrs,
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path))
		if id := correlation.GetCorrelationID(ctx); id != "" {
			attrs = append(attrs, slog.String("request_id", id))
		}
	}

	logger.ErrorContext(ctx, withheldErrorLogMessage, attrs...)
}
