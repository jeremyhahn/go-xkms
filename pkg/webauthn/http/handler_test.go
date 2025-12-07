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

package http

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHandler(t *testing.T) *Handler {
	svc, err := webauthn.NewService(webauthn.ServiceParams{
		Config: &webauthn.Config{
			RPID:          "example.com",
			RPDisplayName: "Example",
			RPOrigins:     []string{"https://example.com"},
		},
		UserStore:       webauthn.NewMemoryUserStore(),
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: webauthn.NewMemoryCredentialStore(),
	})
	require.NoError(t, err)
	return NewHandler(svc)
}

func TestHandler_BeginRegistration(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name       string
		method     string
		body       interface{}
		wantStatus int
		wantErr    string
	}{
		{
			name:       "wrong method",
			method:     http.MethodGet,
			body:       nil,
			wantStatus: http.StatusMethodNotAllowed,
			wantErr:    "method not allowed",
		},
		{
			name:       "invalid body",
			method:     http.MethodPost,
			body:       "not json",
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid request body",
		},
		{
			name:       "missing email",
			method:     http.MethodPost,
			body:       BeginRegistrationRequest{},
			wantStatus: http.StatusBadRequest,
			wantErr:    "email is required",
		},
		{
			name:   "success",
			method: http.MethodPost,
			body: BeginRegistrationRequest{
				Email:       "test@example.com",
				DisplayName: "Test User",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "success without display name",
			method: http.MethodPost,
			body: BeginRegistrationRequest{
				Email: "test2@example.com",
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != nil {
				if s, ok := tt.body.(string); ok {
					body = strings.NewReader(s)
				} else {
					b, _ := json.Marshal(tt.body)
					body = bytes.NewReader(b)
				}
			}

			req := httptest.NewRequest(tt.method, "/registration/begin", body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			h.BeginRegistration(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)

			if tt.wantErr != "" {
				var errResp ErrorResponse
				err := json.NewDecoder(rec.Body).Decode(&errResp)
				require.NoError(t, err)
				assert.Contains(t, errResp.Message, tt.wantErr)
			} else if tt.wantStatus == http.StatusOK {
				assert.NotEmpty(t, rec.Header().Get(HeaderSessionID))
			}
		})
	}
}

func TestHandler_FinishRegistration(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name       string
		method     string
		sessionID  string
		body       string
		wantStatus int
		wantErr    string
	}{
		{
			name:       "wrong method",
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
			wantErr:    "method not allowed",
		},
		{
			name:       "missing session ID",
			method:     http.MethodPost,
			body:       "{}",
			wantStatus: http.StatusBadRequest,
			wantErr:    "session ID header is required",
		},
		{
			name:       "invalid attestation response",
			method:     http.MethodPost,
			sessionID:  "test-session",
			body:       "not valid json",
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid attestation response",
		},
		{
			name:       "invalid attestation object",
			method:     http.MethodPost,
			sessionID:  "nonexistent",
			body:       `{"id":"test","rawId":"dGVzdA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYUdWc2JHOD0iLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIn0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIHRlc3RwVwEDAzn//ySLAQIDAQdhBGAEHw"}}`,
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid attestation response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/registration/finish", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.sessionID != "" {
				req.Header.Set(HeaderSessionID, tt.sessionID)
			}
			rec := httptest.NewRecorder()

			h.FinishRegistration(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)

			if tt.wantErr != "" {
				var errResp ErrorResponse
				err := json.NewDecoder(rec.Body).Decode(&errResp)
				require.NoError(t, err)
				assert.Contains(t, errResp.Message, tt.wantErr)
			}
		})
	}
}

func TestHandler_BeginLogin(t *testing.T) {
	h := newTestHandler(t)

	// First register a user
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"test@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	tests := []struct {
		name       string
		method     string
		body       interface{}
		wantStatus int
		wantErr    string
	}{
		{
			name:       "wrong method",
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
			wantErr:    "method not allowed",
		},
		{
			name:       "discoverable credentials (empty body)",
			method:     http.MethodPost,
			body:       nil,
			wantStatus: http.StatusOK,
		},
		{
			name:   "invalid user ID encoding",
			method: http.MethodPost,
			body: BeginLoginRequest{
				UserID: "not-valid-base64!@#$",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid user ID encoding",
		},
		{
			name:   "user not found by email",
			method: http.MethodPost,
			body: BeginLoginRequest{
				Email: "nonexistent@example.com",
			},
			wantStatus: http.StatusNotFound,
			wantErr:    "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != nil {
				b, _ := json.Marshal(tt.body)
				body = bytes.NewReader(b)
			} else {
				body = strings.NewReader("{}")
			}

			req := httptest.NewRequest(tt.method, "/login/begin", body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			h.BeginLogin(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)

			if tt.wantErr != "" {
				var errResp ErrorResponse
				err := json.NewDecoder(rec.Body).Decode(&errResp)
				require.NoError(t, err)
				assert.Contains(t, errResp.Message, tt.wantErr)
			} else if tt.wantStatus == http.StatusOK {
				assert.NotEmpty(t, rec.Header().Get(HeaderSessionID))
			}
		})
	}
}

func TestHandler_FinishLogin(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name       string
		method     string
		sessionID  string
		userID     string
		body       string
		wantStatus int
		wantErr    string
	}{
		{
			name:       "wrong method",
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
			wantErr:    "method not allowed",
		},
		{
			name:       "missing session ID",
			method:     http.MethodPost,
			body:       "{}",
			wantStatus: http.StatusBadRequest,
			wantErr:    "session ID header is required",
		},
		{
			name:       "invalid user ID encoding",
			method:     http.MethodPost,
			sessionID:  "test-session",
			userID:     "not-valid-base64!@#$",
			body:       "{}",
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid user ID encoding",
		},
		{
			name:       "invalid assertion response",
			method:     http.MethodPost,
			sessionID:  "test-session",
			body:       "not valid json",
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid assertion response",
		},
		{
			name:       "invalid assertion object",
			method:     http.MethodPost,
			sessionID:  "nonexistent",
			body:       `{"id":"test","rawId":"dGVzdA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYUdWc2JHOD0iLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIn0","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCIQDa"}}`,
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid assertion response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/login/finish", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.sessionID != "" {
				req.Header.Set(HeaderSessionID, tt.sessionID)
			}
			if tt.userID != "" {
				req.Header.Set(HeaderUserID, tt.userID)
			}
			rec := httptest.NewRecorder()

			h.FinishLogin(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)

			if tt.wantErr != "" {
				var errResp ErrorResponse
				err := json.NewDecoder(rec.Body).Decode(&errResp)
				require.NoError(t, err)
				assert.Contains(t, errResp.Message, tt.wantErr)
			}
		})
	}
}

func TestHandler_RegistrationStatus(t *testing.T) {
	h := newTestHandler(t)

	// First register a user
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"registered@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	tests := []struct {
		name       string
		method     string
		query      string
		userIDHdr  string
		wantStatus int
		wantErr    string
		wantReg    bool
	}{
		{
			name:       "wrong method",
			method:     http.MethodPost,
			wantStatus: http.StatusMethodNotAllowed,
			wantErr:    "method not allowed",
		},
		{
			name:       "no user ID - not registered",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
			wantReg:    false,
		},
		{
			name:       "user by email - not found",
			method:     http.MethodGet,
			query:      "email=notfound@example.com",
			wantStatus: http.StatusOK,
			wantReg:    false,
		},
		{
			name:       "user by email - found but no credentials",
			method:     http.MethodGet,
			query:      "email=registered@example.com",
			wantStatus: http.StatusOK,
			wantReg:    false, // User exists but has no finished registration
		},
		{
			name:       "invalid user ID encoding",
			method:     http.MethodGet,
			userIDHdr:  "not-valid-base64!@#$",
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid user ID encoding",
		},
		{
			name:       "valid user ID - not registered",
			method:     http.MethodGet,
			userIDHdr:  base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
			wantStatus: http.StatusOK,
			wantReg:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/registration/status"
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequest(tt.method, url, nil)
			if tt.userIDHdr != "" {
				req.Header.Set(HeaderUserID, tt.userIDHdr)
			}
			rec := httptest.NewRecorder()

			h.RegistrationStatus(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)

			if tt.wantErr != "" {
				var errResp ErrorResponse
				err := json.NewDecoder(rec.Body).Decode(&errResp)
				require.NoError(t, err)
				assert.Contains(t, errResp.Message, tt.wantErr)
			} else if tt.wantStatus == http.StatusOK {
				var resp RegistrationStatusResponse
				err := json.NewDecoder(rec.Body).Decode(&resp)
				require.NoError(t, err)
				assert.Equal(t, tt.wantReg, resp.Registered)
			}
		})
	}
}

func TestHandler_HandleServiceError(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "session not found",
			err:        webauthn.ErrSessionNotFound,
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrorCodeInvalidSession,
		},
		{
			name:       "session expired",
			err:        webauthn.ErrSessionExpired,
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrorCodeSessionExpired,
		},
		{
			name:       "user not found",
			err:        webauthn.ErrUserNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   ErrorCodeUserNotFound,
		},
		{
			name:       "no credentials",
			err:        webauthn.ErrNoCredentials,
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrorCodeNoCredentials,
		},
		{
			name:       "verification failed",
			err:        webauthn.ErrVerificationFailed,
			wantStatus: http.StatusUnauthorized,
			wantCode:   ErrorCodeVerificationFailed,
		},
		{
			name:       "invalid request",
			err:        webauthn.ErrInvalidRequest,
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrorCodeInvalidRequest,
		},
		{
			name:       "invalid response",
			err:        webauthn.ErrInvalidResponse,
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrorCodeInvalidRequest,
		},
		{
			name:       "unknown error",
			err:        assert.AnError,
			wantStatus: http.StatusInternalServerError,
			wantCode:   ErrorCodeInternalError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.handleServiceError(rec, tt.err)

			assert.Equal(t, tt.wantStatus, rec.Code)

			var errResp ErrorResponse
			err := json.NewDecoder(rec.Body).Decode(&errResp)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCode, errResp.Error)
		})
	}
}

func TestHandler_WriteJSON(t *testing.T) {
	h := newTestHandler(t)

	rec := httptest.NewRecorder()
	h.writeJSON(rec, http.StatusCreated, map[string]string{"key": "value"})

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var result map[string]string
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	assert.Equal(t, "value", result["key"])
}

func TestHandler_WriteError(t *testing.T) {
	h := newTestHandler(t)

	rec := httptest.NewRecorder()
	h.writeError(rec, http.StatusForbidden, "test_error", "test message")

	assert.Equal(t, http.StatusForbidden, rec.Code)

	var errResp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "test_error", errResp.Error)
	assert.Equal(t, "test message", errResp.Message)
}
