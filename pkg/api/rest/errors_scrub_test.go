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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/correlation"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// scrubMarker is a distinctive string standing in for internal detail (a
// storage path, a library message) that must never reach a client.
const scrubMarker = "SCRUB-MARKER-/var/lib/xkms/secret-path-1118"

// errScrubMarker is an unclassified service error carrying scrubMarker.
var errScrubMarker = errors.New("storage backend failed at " + scrubMarker)

// newScrubTestServer builds a real Server whose single backend's ListKeys
// returns listErr, logging into the returned buffer.
func newScrubTestServer(t *testing.T, listErr error) (*Server, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	ks := setupTestService(t, "test-backend")
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) { return nil, listErr }
	svc, err := xkms.Get()
	require.NoError(t, err)
	server, err := NewServer(&Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test-backend": ks},
		XKMSService:   svc,
		Logger:        slog.New(slog.NewTextHandler(&logs, nil)),
	})
	require.NoError(t, err)
	return server, &logs
}

// decodeErrorResponse decodes a REST error body.
func decodeErrorResponse(t *testing.T, w *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), w.Body.String())
	return resp
}

// TestRouter_InternalErrorWithheldAndLogged drives an unclassified service
// error through the full legacy router: the client sees a 500 carrying the
// fixed internal message and no trace of the marker, while the server log
// carries the marker with the request's method, path and correlation ID.
func TestRouter_InternalErrorWithheldAndLogged(t *testing.T) {
	server, logs := newScrubTestServer(t, errScrubMarker)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=test-backend", nil)
	req.Header.Set(correlation.CorrelationIDHeader, "req-1118")
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), scrubMarker)
	resp := decodeErrorResponse(t, w)
	assert.Equal(t, ErrInternalError.Error(), resp.Error)

	logged := logs.String()
	assert.Contains(t, logged, withheldErrorLogMessage)
	assert.Contains(t, logged, scrubMarker)
	assert.Contains(t, logged, "method=GET")
	assert.Contains(t, logged, "path=/api/v1/keys")
	assert.Contains(t, logged, "request_id=req-1118")
}

// TestRouter_ClientFaultKeepsMessage verifies a classified client-fault
// error still reaches the client verbatim and is not logged as withheld.
func TestRouter_ClientFaultKeepsMessage(t *testing.T) {
	notFound := fmt.Errorf("key signing-key: %w", storage.ErrNotFound)
	server, logs := newScrubTestServer(t, notFound)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=test-backend", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, notFound.Error(), decodeErrorResponse(t, w).Error)
	assert.NotContains(t, logs.String(), withheldErrorLogMessage)
}

// TestBindRoute_InternalErrorWithheldAndLogged verifies the unified API
// server's mount (BindRoute) installs the same request context: a handler's
// direct writeError(w, err, 500) is scrubbed and logged with the request.
func TestBindRoute_InternalErrorWithheldAndLogged(t *testing.T) {
	var logs bytes.Buffer
	s := &Server{logger: slog.New(slog.NewTextHandler(&logs, nil))}
	h := s.BindRoute(RouteSpec{
		Method:  http.MethodPost,
		Pattern: "/api/v1/probe",
		Group:   GroupRoot,
		Handler: func(*Server) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				writeError(w, errScrubMarker, http.StatusInternalServerError)
			}
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/probe", nil)
	req = req.WithContext(correlation.WithCorrelationID(req.Context(), "req-bind"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), scrubMarker)
	assert.Equal(t, ErrInternalError.Error(), decodeErrorResponse(t, w).Error)
	assert.Contains(t, logs.String(), scrubMarker)
	assert.Contains(t, logs.String(), "method=POST")
	assert.Contains(t, logs.String(), "path=/api/v1/probe")
	assert.Contains(t, logs.String(), "request_id=req-bind")
}

// TestWriteError_StatusClassification pins which statuses carry the error's
// own text and which withhold it.
func TestWriteError_StatusClassification(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		status   int
		wantText string
	}{
		{"bad request keeps text", ErrMissingKeyID, http.StatusBadRequest, ErrMissingKeyID.Error()},
		{"not found keeps text", backendNotFound(), http.StatusNotFound, backendNotFound().Error()},
		{"conflict keeps text", storage.ErrAlreadyExists, http.StatusConflict, storage.ErrAlreadyExists.Error()},
		{"unprocessable keeps text", ErrInvalidRequest, http.StatusUnprocessableEntity, ErrInvalidRequest.Error()},
		{"not implemented keeps text", ErrSealingNotSupported, http.StatusNotImplemented, ErrSealingNotSupported.Error()},
		{"service unavailable keeps text", ErrBarrierNotConfigured, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error()},
		{"internal withheld", errScrubMarker, http.StatusInternalServerError, ErrInternalError.Error()},
		{"bad gateway withheld", errScrubMarker, http.StatusBadGateway, ErrInternalError.Error()},
		{"gateway timeout withheld", errScrubMarker, http.StatusGatewayTimeout, ErrInternalError.Error()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			s := &Server{logger: slog.New(slog.NewTextHandler(&logs, nil))}
			h := s.errorLogMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeError(w, tt.err, tt.status)
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

			assert.Equal(t, tt.status, w.Code, "status code is never changed")
			assert.Equal(t, tt.wantText, decodeErrorResponse(t, w).Error)
			assert.NotContains(t, w.Body.String(), scrubMarker)
			if tt.wantText == ErrInternalError.Error() {
				assert.Contains(t, logs.String(), scrubMarker)
			} else {
				assert.Empty(t, logs.String())
			}
		})
	}
}

// backendNotFound is a wrapped client-fault error whose context (the name
// the caller sent) is client-safe.
func backendNotFound() error {
	return fmt.Errorf("backend %q: %w", "hsm-1", ErrBackendNotFound)
}

// TestWriteErrorWithMessage_InternalKeepsLiteralMessage verifies the
// caller-chosen message survives while the error field is scrubbed.
func TestWriteErrorWithMessage_InternalKeepsLiteralMessage(t *testing.T) {
	w := httptest.NewRecorder()
	writeErrorWithMessage(w, errScrubMarker, "audit query failed", http.StatusInternalServerError)

	resp := decodeErrorResponse(t, w)
	assert.Equal(t, ErrInternalError.Error(), resp.Error)
	assert.Equal(t, "audit query failed", resp.Message)
	assert.NotContains(t, w.Body.String(), scrubMarker)
}

// TestFindErrorLogWriter_ThroughWrappers verifies the request context is
// found behind a wrapping ResponseWriter that follows the Unwrap convention
// (LoggingMiddleware's responseWriter), and that an unwrapped writer yields
// nil.
func TestFindErrorLogWriter_ThroughWrappers(t *testing.T) {
	inner := &errorLogWriter{ResponseWriter: httptest.NewRecorder()}
	wrapped := newResponseWriter(inner)
	assert.Same(t, inner, findErrorLogWriter(wrapped))
	assert.Nil(t, findErrorLogWriter(httptest.NewRecorder()))
}

// TestLogWithheldError_NoRequestContextUsesDefaultLogger verifies an
// internal error written outside errorLogMiddleware (a handler invoked
// directly) is still withheld from the client and still logged.
func TestLogWithheldError_NoRequestContextUsesDefaultLogger(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	w := httptest.NewRecorder()
	writeError(w, errScrubMarker, http.StatusInternalServerError)

	assert.NotContains(t, w.Body.String(), scrubMarker)
	assert.Contains(t, logs.String(), scrubMarker)
	assert.Contains(t, logs.String(), "status=500")
}

// TestClientErrorText_AlreadyWithheldIsNotRelogged verifies an error that
// already is ErrInternalError (its call site withheld and logged the
// detail itself) is not logged a second time.
func TestClientErrorText_AlreadyWithheldIsNotRelogged(t *testing.T) {
	var logs bytes.Buffer
	s := &Server{logger: slog.New(slog.NewTextHandler(&logs, nil))}
	h := s.errorLogMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, ErrInternalError, http.StatusInternalServerError)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

	assert.Equal(t, ErrInternalError.Error(), decodeErrorResponse(t, w).Error)
	assert.Empty(t, logs.String())
}

// TestWriteSSHError_InternalWithheld verifies the SSH error envelope, which
// bypasses writeError, is scrubbed by the same rule.
func TestWriteSSHError_InternalWithheld(t *testing.T) {
	w := httptest.NewRecorder()
	writeSSHError(w, errScrubMarker)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), scrubMarker)
	assert.Contains(t, w.Body.String(), ErrInternalError.Error())
}

// TestWriteSSHError_ClientFaultKeepsText verifies a classified SSH
// client fault still carries its text.
func TestWriteSSHError_ClientFaultKeepsText(t *testing.T) {
	w := httptest.NewRecorder()
	bad := &SSHBadBodyError{}
	writeSSHError(w, bad)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), bad.Error())
}
