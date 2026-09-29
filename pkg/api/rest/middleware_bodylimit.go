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
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
)

const (
	// DefaultMaxBodyBytes bounds every REST request body unless its route
	// declares a larger RouteSpec.MaxBodyBytes. Every control-plane request
	// (key metadata, PINs, CSRs, WebAuthn ceremonies, tokens) fits in a
	// small fraction of it.
	DefaultMaxBodyBytes int64 = 1 << 20

	// BulkMaxBodyBytes bounds the data-plane routes that carry caller data
	// (sign, verify, encrypt, decrypt, seal, unseal). It matches the 4 MiB
	// receive limit of the gRPC transports, so the REST data plane accepts
	// what the gRPC one does, less the base64 expansion of JSON.
	BulkMaxBodyBytes int64 = 4 << 20
)

// RequestTooLargeError reports a request body larger than its route's bound.
// It is served as 413 Request Entity Too Large.
type RequestTooLargeError struct {
	// Limit is the route's body bound in bytes.
	Limit int64
}

// Error names the bound so a client can size its request to fit.
func (e *RequestTooLargeError) Error() string {
	return "request body exceeds " + strconv.FormatInt(e.Limit, 10) + " bytes"
}

// bodyLimit returns the route's request body bound.
func (spec RouteSpec) bodyLimit() int64 {
	if spec.MaxBodyBytes > 0 {
		return spec.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

// BodyLimitMiddleware bounds the request body to limit bytes and answers 413
// for a body over the bound.
//
// A declared Content-Length over the bound is refused before the handler
// runs. A body of unknown length (chunked) is wrapped in http.MaxBytesReader,
// so a handler reading it stops at the bound; the handler's own error
// response (usually a 400 for the failed decode) is then replaced by the 413,
// so every handler reports an oversized body the same way without each of
// them having to recognise *http.MaxBytesError.
func BodyLimitMiddleware(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				writeError(w, &RequestTooLargeError{Limit: limit}, http.StatusRequestEntityTooLarge)
				return
			}
			if r.Body == nil || r.Body == http.NoBody {
				next.ServeHTTP(w, r)
				return
			}

			lw := &bodyLimitWriter{ResponseWriter: w, limit: limit}
			r.Body = &limitedBody{ReadCloser: http.MaxBytesReader(w, r.Body, limit), exceeded: &lw.exceeded}
			next.ServeHTTP(lw, r)
		})
	}
}

// limitedBody records that the wrapped http.MaxBytesReader hit its bound.
type limitedBody struct {
	io.ReadCloser
	exceeded *atomic.Bool
}

// Read reads from the bounded body, recording an overflow.
func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		b.exceeded.Store(true)
	}
	return n, err
}

// bodyLimitWriter replaces the handler's response with a 413 when the
// request body overflowed before the response began.
type bodyLimitWriter struct {
	http.ResponseWriter
	limit       int64
	exceeded    atomic.Bool
	wroteHeader bool
	replaced    bool
}

// WriteHeader sends the handler's status, or the 413 when the body overflowed.
func (w *bodyLimitWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if w.exceeded.Load() {
		w.replaced = true
		writeError(w.ResponseWriter, &RequestTooLargeError{Limit: w.limit}, http.StatusRequestEntityTooLarge)
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write writes the handler's body, discarding it once the 413 replaced it.
func (w *bodyLimitWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.replaced {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap exposes the underlying writer to http.ResponseController.
func (w *bodyLimitWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
