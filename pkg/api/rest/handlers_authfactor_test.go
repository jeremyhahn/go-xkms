// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// handlers_authfactor_test.go covers the user-side N-factor REST endpoints:
// parameter validation, the pass-through to the servicer, and the
// not-configured path taken when no qrdb node backs the service.
package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// stubAuthFactorService records what the handlers asked for and returns
// canned replies.
type stubAuthFactorService struct {
	addReq     *qrdbtransport.AuthFactorAddRequest
	listReq    *qrdbtransport.AuthFactorListRequest
	getReq     *qrdbtransport.AuthFactorGetRequest
	removeReq  *qrdbtransport.AuthFactorRemoveRequest
	rotateReq  *qrdbtransport.AuthFactorRotateRequest
	relabelReq *qrdbtransport.AuthFactorRelabelRequest
	loginReq   *qrdbtransport.AuthFactorLoginRequest

	err error
}

func (s *stubAuthFactorService) AddAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorAddRequest) (*qrdbtransport.AuthFactorAddResponse, error) {
	s.addReq = req
	return &qrdbtransport.AuthFactorAddResponse{}, s.err
}

func (s *stubAuthFactorService) ListAuthFactors(_ context.Context, req *qrdbtransport.AuthFactorListRequest) (*qrdbtransport.AuthFactorListResponse, error) {
	s.listReq = req
	return &qrdbtransport.AuthFactorListResponse{}, s.err
}

func (s *stubAuthFactorService) GetAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorGetRequest) (*qrdbtransport.AuthFactorGetResponse, error) {
	s.getReq = req
	return &qrdbtransport.AuthFactorGetResponse{}, s.err
}

func (s *stubAuthFactorService) RemoveAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorRemoveRequest) (*qrdbtransport.AuthFactorRemoveResponse, error) {
	s.removeReq = req
	return &qrdbtransport.AuthFactorRemoveResponse{}, s.err
}

func (s *stubAuthFactorService) RotateAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorRotateRequest) (*qrdbtransport.AuthFactorRotateResponse, error) {
	s.rotateReq = req
	return &qrdbtransport.AuthFactorRotateResponse{}, s.err
}

func (s *stubAuthFactorService) RelabelAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorRelabelRequest) (*qrdbtransport.AuthFactorRelabelResponse, error) {
	s.relabelReq = req
	return &qrdbtransport.AuthFactorRelabelResponse{}, s.err
}

func (s *stubAuthFactorService) LoginAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorLoginRequest) (*qrdbtransport.AuthFactorLoginResponse, error) {
	s.loginReq = req
	return &qrdbtransport.AuthFactorLoginResponse{}, s.err
}

// authFactorRouter mounts the handlers on a chi router so path parameters
// resolve exactly as they do in the server.
func authFactorRouter(h *AuthFactorHandlers) chi.Router {
	r := chi.NewRouter()
	r.Route("/factors", func(r chi.Router) {
		r.Get("/", h.ListHandler)
		r.Post("/", h.AddHandler)
		r.Post("/login", h.LoginHandler)
		r.Get("/{factorID}", h.GetHandler)
		r.Delete("/{factorID}", h.RemoveHandler)
		r.Patch("/{factorID}", h.RelabelHandler)
		r.Post("/{factorID}/rotate", h.RotateHandler)
	})
	return r
}

func serveAuthFactor(t *testing.T, stub *stubAuthFactorService, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, target, reader)
	w := httptest.NewRecorder()
	authFactorRouter(NewAuthFactorHandlers(stub, initTestLogger())).ServeHTTP(w, req)
	return w
}

func TestAuthFactorList_RequiresUserID(t *testing.T) {
	for _, target := range []string{"/factors", "/factors?user_id=", "/factors?user_id=abc", "/factors?user_id=0"} {
		w := serveAuthFactor(t, &stubAuthFactorService{}, http.MethodGet, target, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code, "target %q", target)
	}
}

func TestAuthFactorList_PassesUserID(t *testing.T) {
	stub := &stubAuthFactorService{}
	w := serveAuthFactor(t, stub, http.MethodGet, "/factors?user_id=42", nil)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, stub.listReq)
	assert.Equal(t, uint64(42), stub.listReq.UserID)
}

func TestAuthFactorAdd_RequiresUserIDAndType(t *testing.T) {
	w := serveAuthFactor(t, &stubAuthFactorService{}, http.MethodPost, "/factors",
		qrdbtransport.AuthFactorAddRequest{Type: "fido2"})
	assert.Equal(t, http.StatusBadRequest, w.Code, "a factor with no owner must be rejected")

	w = serveAuthFactor(t, &stubAuthFactorService{}, http.MethodPost, "/factors",
		qrdbtransport.AuthFactorAddRequest{UserID: 42})
	assert.Equal(t, http.StatusBadRequest, w.Code, "a factor with no type must be rejected")
}

func TestAuthFactorAdd_Success(t *testing.T) {
	stub := &stubAuthFactorService{}
	w := serveAuthFactor(t, stub, http.MethodPost, "/factors",
		qrdbtransport.AuthFactorAddRequest{UserID: 42, Type: "fido2", Label: "yubikey"})

	require.Equal(t, http.StatusCreated, w.Code)
	require.NotNil(t, stub.addReq)
	assert.Equal(t, uint64(42), stub.addReq.UserID)
	assert.Equal(t, "fido2", stub.addReq.Type)
	assert.Equal(t, "yubikey", stub.addReq.Label)
}

func TestAuthFactorAdd_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/factors", bytes.NewReader([]byte("{")))
	w := httptest.NewRecorder()
	authFactorRouter(NewAuthFactorHandlers(&stubAuthFactorService{}, initTestLogger())).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthFactorGet_PassesFactorID(t *testing.T) {
	stub := &stubAuthFactorService{}
	w := serveAuthFactor(t, stub, http.MethodGet, "/factors/factor-123", nil)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, stub.getReq)
	assert.Equal(t, "factor-123", stub.getReq.FactorID)
}

// TestAuthFactorRemove_ForceIsOptIn proves the last-active-factor guard is
// only bypassed when the caller explicitly asks. Defaulting force to true
// would let a routine delete lock a user out.
func TestAuthFactorRemove_ForceIsOptIn(t *testing.T) {
	stub := &stubAuthFactorService{}
	w := serveAuthFactor(t, stub, http.MethodDelete, "/factors/factor-123", nil)
	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, stub.removeReq)
	assert.False(t, stub.removeReq.Force, "force must default to false")

	stub = &stubAuthFactorService{}
	w = serveAuthFactor(t, stub, http.MethodDelete, "/factors/factor-123?force=true", nil)
	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, stub.removeReq)
	assert.True(t, stub.removeReq.Force, "force=true must be honored")
}

func TestAuthFactorRelabel_RequiresLabel(t *testing.T) {
	w := serveAuthFactor(t, &stubAuthFactorService{}, http.MethodPatch, "/factors/factor-123",
		qrdbtransport.AuthFactorRelabelRequest{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthFactorRelabel_Success(t *testing.T) {
	stub := &stubAuthFactorService{}
	w := serveAuthFactor(t, stub, http.MethodPatch, "/factors/factor-123",
		qrdbtransport.AuthFactorRelabelRequest{Label: "backup key"})

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, stub.relabelReq)
	assert.Equal(t, "factor-123", stub.relabelReq.FactorID, "the path must win over the body")
	assert.Equal(t, "backup key", stub.relabelReq.Label)
}

func TestAuthFactorRotate_UsesPathAsOldFactor(t *testing.T) {
	stub := &stubAuthFactorService{}
	w := serveAuthFactor(t, stub, http.MethodPost, "/factors/old-factor/rotate",
		qrdbtransport.AuthFactorRotateRequest{
			OldFactorID: "ignored-body-value",
			NewFactor:   qrdbtransport.AuthFactorAddRequest{Type: "piv"},
		})

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, stub.rotateReq)
	assert.Equal(t, "old-factor", stub.rotateReq.OldFactorID,
		"the factor being replaced is the one named in the path")
}

func TestAuthFactorRotate_RequiresNewFactorType(t *testing.T) {
	w := serveAuthFactor(t, &stubAuthFactorService{}, http.MethodPost, "/factors/old-factor/rotate",
		qrdbtransport.AuthFactorRotateRequest{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthFactorLogin_RequiresTypeAndLookupKey(t *testing.T) {
	w := serveAuthFactor(t, &stubAuthFactorService{}, http.MethodPost, "/factors/login",
		qrdbtransport.AuthFactorLoginRequest{LookupKey: []byte("key")})
	assert.Equal(t, http.StatusBadRequest, w.Code, "a login with no type must be rejected")

	w = serveAuthFactor(t, &stubAuthFactorService{}, http.MethodPost, "/factors/login",
		qrdbtransport.AuthFactorLoginRequest{Type: "fido2"})
	assert.Equal(t, http.StatusBadRequest, w.Code, "a login with no lookup key must be rejected")
}

func TestAuthFactorLogin_Success(t *testing.T) {
	stub := &stubAuthFactorService{}
	w := serveAuthFactor(t, stub, http.MethodPost, "/factors/login",
		qrdbtransport.AuthFactorLoginRequest{Type: "fido2", LookupKey: []byte("credential-id")})

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, stub.loginReq)
	assert.Equal(t, "fido2", stub.loginReq.Type)
	assert.Equal(t, []byte("credential-id"), stub.loginReq.LookupKey)
}

// TestAuthFactor_NotConfigured proves every endpoint reports 503 rather than
// panicking when no qrdb node backs the service.
func TestAuthFactor_NotConfigured(t *testing.T) {
	stub := &stubAuthFactorService{err: xkms.ErrNotConfigured}

	tests := []struct {
		name   string
		method string
		target string
		body   any
	}{
		{"list", http.MethodGet, "/factors?user_id=42", nil},
		{"add", http.MethodPost, "/factors", qrdbtransport.AuthFactorAddRequest{UserID: 42, Type: "fido2"}},
		{"get", http.MethodGet, "/factors/factor-123", nil},
		{"remove", http.MethodDelete, "/factors/factor-123", nil},
		{"relabel", http.MethodPatch, "/factors/factor-123", qrdbtransport.AuthFactorRelabelRequest{Label: "x"}},
		{"rotate", http.MethodPost, "/factors/factor-123/rotate", qrdbtransport.AuthFactorRotateRequest{NewFactor: qrdbtransport.AuthFactorAddRequest{Type: "piv"}}},
		{"login", http.MethodPost, "/factors/login", qrdbtransport.AuthFactorLoginRequest{Type: "fido2", LookupKey: []byte("k")}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := serveAuthFactor(t, stub, tc.method, tc.target, tc.body)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		})
	}
}
