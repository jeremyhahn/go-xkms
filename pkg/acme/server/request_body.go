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

package server

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// MaxRequestBodySize is the largest ACME request body the server reads, in
// bytes. Every ACME POST is a flattened JWS whose payload is base64url-encoded
// JSON, so a binary field inside the payload (a finalize CSR) is encoded twice
// and grows by 16/9. The largest request go-xkms accepts is a finalize
// carrying a TCG-CSR-IDEVID, which embeds the platform's UEFI boot event log,
// EK certificate and TPM attestation blobs: the real event log fixture in
// test/integration/tpm2/testdata (41,196 bytes) alone becomes ~72 KiB on the
// wire, so the 64 KiB a plain RFC 8555 CSR would need rejects genuine device
// enrollments. 256 KiB admits a TCG CSR of roughly 144 KiB — more than three
// times that event log — while bounding the memory one request can pin.
const MaxRequestBodySize int64 = 256 << 10

// RequestBodyError reports that an ACME request body could not be read in
// full: either it exceeded MaxRequestBodySize (TooLarge) or the transport
// failed mid-read.
type RequestBodyError struct {
	// Err is the underlying read error; an *http.MaxBytesError when the body
	// exceeded MaxRequestBodySize.
	Err error
}

// Error implements error.
func (e *RequestBodyError) Error() string {
	return "acme: read request body: " + e.Err.Error()
}

// Unwrap returns the underlying read error.
func (e *RequestBodyError) Unwrap() error {
	return e.Err
}

// TooLarge reports whether the body exceeded MaxRequestBodySize.
func (e *RequestBodyError) TooLarge() bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(e.Err, &maxBytesErr)
}

// Problem returns the RFC 7807 / RFC 8555 problem document for the failure:
// "malformed" with HTTP 413 for an oversized body, "malformed" with HTTP 400
// for any other read failure. RFC 8555 Section 6.7 defines no dedicated type
// for an oversized request, and "malformed" is the type it prescribes for a
// request the server cannot process as sent.
func (e *RequestBodyError) Problem() *entities.Error {
	if e.TooLarge() {
		return common.RequestTooLarge("Request body exceeds the " +
			strconv.FormatInt(MaxRequestBodySize, 10) + " byte limit")
	}
	return common.MalformedError("Failed to read request body", nil)
}

// bufferedBody replaces a request body once it has been read. It keeps the
// outcome of that single read — the bytes, or the error — so every later
// RequestBody call returns it without touching the connection again, and it
// still satisfies io.ReadCloser for any reader that consumes r.Body directly.
type bufferedBody struct {
	*bytes.Reader
	data []byte
	err  *RequestBodyError
}

// Close implements io.Closer. The connection's body is closed by net/http
// once the handler returns, so there is nothing to release here.
func (b *bufferedBody) Close() error {
	return nil
}

// RequestBody returns the body of r, reading it from the connection at most
// once and never more than MaxRequestBodySize bytes. The first call reads the
// body and replaces r.Body with a buffered copy; every later call — on r or
// on any request derived from it with WithContext, which shares the same
// Body — returns the same bytes, or the same *RequestBodyError, without
// reading again. RequestBodyMiddleware performs the first read for every
// ACME route, so a handler reached through the ACME router never reads the
// connection itself.
func RequestBody(r *http.Request) ([]byte, error) {
	data, err := readRequestBody(nil, r)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// readRequestBody implements RequestBody. w, when non-nil, lets
// http.MaxBytesReader tell the server to close the connection after an
// oversized body instead of draining it.
func readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, *RequestBodyError) {
	if buffered, ok := r.Body.(*bufferedBody); ok {
		return buffered.data, buffered.err
	}
	if r.Body == nil || r.Body == http.NoBody {
		r.Body = &bufferedBody{Reader: bytes.NewReader(nil)}
		return nil, nil
	}

	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBodySize))
	if err != nil {
		bodyErr := &RequestBodyError{Err: err}
		r.Body = &bufferedBody{Reader: bytes.NewReader(nil), err: bodyErr}
		return nil, bodyErr
	}
	r.Body = &bufferedBody{Reader: bytes.NewReader(data), data: data}
	return data, nil
}

// RequestBodyMiddleware reads the body of every request that carries one,
// once and capped at MaxRequestBodySize, before any other ACME middleware
// runs. An oversized body is refused with HTTP 413 and an RFC 7807 problem
// document, a failed read with HTTP 400; otherwise the buffered bytes are
// available to every later middleware and handler through RequestBody.
//
// It must be the outermost ACME middleware that touches the request, so the
// cap applies before anything else parses the body and no middleware below
// it ever reads the connection — in particular, a client trickling its body
// ties up only its own request, never a lock another request needs.
func RequestBodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := readRequestBody(w, r); err != nil {
			writeProblem(w, err.Problem())
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeProblem writes problem as an application/problem+json response with
// the problem's own HTTP status.
func writeProblem(w http.ResponseWriter, problem *entities.Error) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(problem.Status)
	if err := writeJSONError(w, problem); err != nil {
		// The status is already on the wire; the failure can only be logged.
		slog.Default().Error("failed to write ACME problem response", slog.String("error", err.Error()))
	}
}
