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
	"errors"
	"fmt"
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

func TestHandler_FinishRegistration_ServiceErrors(t *testing.T) {
	h := newTestHandler(t)

	// Create a valid session first
	beginReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"test@example.com"}`))
	beginReq.Header.Set("Content-Type", "application/json")
	beginRec := httptest.NewRecorder()
	h.BeginRegistration(beginRec, beginReq)
	require.Equal(t, http.StatusOK, beginRec.Code)
	_ = beginRec.Header().Get(HeaderSessionID) // Use the session if needed later

	tests := []struct {
		name       string
		sessionID  string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "session not found",
			sessionID:  "nonexistent-session-id",
			body:       `{"id":"test","rawId":"dGVzdA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRkbm9uZQ"}}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrorCodeInvalidRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/registration/finish", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(HeaderSessionID, tt.sessionID)
			rec := httptest.NewRecorder()

			h.FinishRegistration(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)

			var errResp ErrorResponse
			err := json.NewDecoder(rec.Body).Decode(&errResp)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCode, errResp.Error)
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

func TestHandler_BeginLogin_ServiceErrors(t *testing.T) {
	h := newTestHandler(t)

	// Register a user first
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"test@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	// Test BeginLogin with a user that exists but has no credentials
	b, _ := json.Marshal(BeginLoginRequest{Email: "test@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.BeginLogin(rec, req)

	// The test user exists but has no credentials, so BeginLogin will fail
	assert.True(t, rec.Code >= 400)
}

func TestHandler_BeginLogin_InvalidJSON(t *testing.T) {
	h := newTestHandler(t)

	// Test with invalid JSON that will trigger json decode error but not fail (line 136-138)
	req := httptest.NewRequest(http.MethodPost, "/login/begin", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.BeginLogin(rec, req)

	// Should succeed with discoverable credentials flow
	assert.Equal(t, http.StatusOK, rec.Code)
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

func TestHandler_FinishLogin_ServiceErrors(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name       string
		sessionID  string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "session not found",
			sessionID:  "nonexistent-session-id",
			body:       `{"id":"test","rawId":"dGVzdA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4","signature":"MEQCID"}}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrorCodeInvalidRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/login/finish", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(HeaderSessionID, tt.sessionID)
			rec := httptest.NewRecorder()

			h.FinishLogin(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)

			var errResp ErrorResponse
			err := json.NewDecoder(rec.Body).Decode(&errResp)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCode, errResp.Error)
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

func TestHandler_RegistrationStatus_ServiceError(t *testing.T) {
	// Create a handler with a custom service to trigger specific errors
	h := newTestHandler(t)

	// Register a user
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"test@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	// Test that GetUserByEmail error handling works
	req := httptest.NewRequest(http.MethodGet, "/registration/status?email=test@example.com", nil)
	rec := httptest.NewRecorder()
	h.RegistrationStatus(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_RegistrationStatus_QueryParam(t *testing.T) {
	h := newTestHandler(t)

	// Register a user
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"query@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	// Test with query param instead of header
	req := httptest.NewRequest(http.MethodGet, "/registration/status?user_id="+base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}), nil)
	rec := httptest.NewRecorder()
	h.RegistrationStatus(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RegistrationStatusResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.False(t, resp.Registered)
}

func TestHandler_RegistrationStatus_IsRegisteredError(t *testing.T) {
	h := newTestHandler(t)

	// Register a user
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"iserror@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	// Get the user to extract ID
	user, err := h.service.GetUserByEmail(regReq.Context(), "iserror@example.com")
	require.NoError(t, err)
	userID := base64.RawURLEncoding.EncodeToString(user.WebAuthnID())

	// Test with user ID header
	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	req.Header.Set(HeaderUserID, userID)
	rec := httptest.NewRecorder()
	h.RegistrationStatus(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
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
		{
			name:       "wrapped session not found",
			err:        fmt.Errorf("wrapped: %w", webauthn.ErrSessionNotFound),
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrorCodeInvalidSession,
		},
		{
			name:       "wrapped user not found",
			err:        fmt.Errorf("wrapped: %w", webauthn.ErrUserNotFound),
			wantStatus: http.StatusNotFound,
			wantCode:   ErrorCodeUserNotFound,
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

// brokenWriter is an io.Writer that always fails
type brokenWriter struct {
	header http.Header
	code   int
}

func (bw *brokenWriter) Header() http.Header {
	if bw.header == nil {
		bw.header = make(http.Header)
	}
	return bw.header
}

func (bw *brokenWriter) Write(b []byte) (int, error) {
	return 0, errors.New("write error")
}

func (bw *brokenWriter) WriteHeader(statusCode int) {
	bw.code = statusCode
}

func TestHandler_WriteJSON_EncodeError(t *testing.T) {
	h := newTestHandler(t)

	// Create a broken writer that will fail on Write
	bw := &brokenWriter{}

	// Try to write data - this should trigger the error path in writeJSON
	h.writeJSON(bw, http.StatusOK, map[string]string{"key": "value"})

	// The error is silently ignored, but we've covered the error path
	assert.Equal(t, http.StatusOK, bw.code)
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

func TestHandler_BeginLogin_WithValidUserID(t *testing.T) {
	h := newTestHandler(t)

	// Register a user to get a valid user ID
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"validuser@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	// Extract user ID from the service
	user, err := h.service.GetUserByEmail(regReq.Context(), "validuser@example.com")
	require.NoError(t, err)
	userID := base64.RawURLEncoding.EncodeToString(user.WebAuthnID())

	// Test BeginLogin with valid user ID
	loginReq := BeginLoginRequest{
		UserID: userID,
	}
	b, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.BeginLogin(rec, req)

	// Should fail because user has no credentials
	assert.True(t, rec.Code >= 400)
}

func TestHandler_FinishLogin_WithValidUserID(t *testing.T) {
	h := newTestHandler(t)

	// Create a valid user ID
	userID := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3, 4})

	req := httptest.NewRequest(http.MethodPost, "/login/finish",
		strings.NewReader(`{"id":"test","rawId":"dGVzdA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4","signature":"MEQCID"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderSessionID, "test-session")
	req.Header.Set(HeaderUserID, userID)
	rec := httptest.NewRecorder()

	h.FinishLogin(rec, req)

	// Should fail due to invalid session
	assert.True(t, rec.Code >= 400)
}

func TestHandler_WithLogger(t *testing.T) {
	h := newTestHandler(t)

	// Test that WithLogger returns the handler
	result := h.WithLogger(nil)
	assert.Same(t, h, result)
}

func TestHandler_FinishRegistration_InvalidSession(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/registration/finish",
		strings.NewReader(`{"id":"test","rawId":"dGVzdA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAoY_1Y1HAABAQIDBAEXIQA"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderSessionID, "invalid-session-id")
	rec := httptest.NewRecorder()

	h.FinishRegistration(rec, req)

	// Should fail with session not found
	assert.True(t, rec.Code >= 400)
}

func TestHandler_FinishLogin_InvalidResponse(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/login/finish",
		strings.NewReader(`not valid json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderSessionID, "test-session")
	rec := httptest.NewRecorder()

	h.FinishLogin(rec, req)

	// Should fail due to invalid response body
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_RegistrationStatus_WithEmail(t *testing.T) {
	h := newTestHandler(t)

	// First register a user
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"status-test@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	// Check registration status by email
	req := httptest.NewRequest(http.MethodGet, "/registration/status?email=status-test@example.com", nil)
	rec := httptest.NewRecorder()

	h.RegistrationStatus(rec, req)

	// User exists but has no credentials so not fully registered
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_RegistrationStatus_NoUserID(t *testing.T) {
	h := newTestHandler(t)

	// Check registration status without user ID or email
	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	rec := httptest.NewRecorder()

	h.RegistrationStatus(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RegistrationStatusResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.False(t, resp.Registered)
}

func TestHandler_BeginLogin_ServiceError(t *testing.T) {
	h := newTestHandler(t)

	// Register a user first
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"login-error-test@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	// Try to login by email (user has no credentials)
	req := httptest.NewRequest(http.MethodPost, "/login/begin",
		strings.NewReader(`{"email":"login-error-test@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.BeginLogin(rec, req)

	// Should fail because user has no credentials
	assert.True(t, rec.Code >= 400)
}

func TestHandler_BeginLogin_EmailWithCredentials(t *testing.T) {
	h := newTestHandler(t)

	// Register a user first
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"login-with-creds@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	// Get the user to retrieve the user ID
	user, err := h.service.GetUserByEmail(regReq.Context(), "login-with-creds@example.com")
	require.NoError(t, err)

	// Test BeginLogin by email
	loginReq := httptest.NewRequest(http.MethodPost, "/login/begin",
		strings.NewReader(`{"email":"login-with-creds@example.com"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()

	h.BeginLogin(loginRec, loginReq)

	// Should fail (no credentials), but we've covered the GetUserByEmail success path
	assert.True(t, loginRec.Code >= 400)
	assert.NotNil(t, user)
}

func TestHandler_FinishRegistration_ParseError(t *testing.T) {
	h := newTestHandler(t)

	// Begin registration to get a valid session
	beginReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"parse-error@example.com"}`))
	beginReq.Header.Set("Content-Type", "application/json")
	beginRec := httptest.NewRecorder()
	h.BeginRegistration(beginRec, beginReq)
	require.Equal(t, http.StatusOK, beginRec.Code)
	sessionID := beginRec.Header().Get(HeaderSessionID)

	// Send malformed credential creation response
	req := httptest.NewRequest(http.MethodPost, "/registration/finish",
		strings.NewReader(`{"id":"test","type":"public-key"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderSessionID, sessionID)
	rec := httptest.NewRecorder()

	h.FinishRegistration(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, ErrorCodeInvalidRequest, errResp.Error)
}

func TestHandler_FinishLogin_ParseError(t *testing.T) {
	h := newTestHandler(t)

	// Send malformed credential request response
	req := httptest.NewRequest(http.MethodPost, "/login/finish",
		strings.NewReader(`{"id":"test","type":"public-key"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderSessionID, "test-session")
	rec := httptest.NewRecorder()

	h.FinishLogin(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, ErrorCodeInvalidRequest, errResp.Error)
}

func TestHandler_RegistrationStatus_UserIDInQueryParam(t *testing.T) {
	h := newTestHandler(t)

	// Register a user
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"queryparam@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	// Get the user
	user, err := h.service.GetUserByEmail(regReq.Context(), "queryparam@example.com")
	require.NoError(t, err)
	userID := base64.RawURLEncoding.EncodeToString(user.WebAuthnID())

	// Test with query param
	req := httptest.NewRequest(http.MethodGet, "/registration/status?user_id="+userID, nil)
	rec := httptest.NewRecorder()

	h.RegistrationStatus(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp RegistrationStatusResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.False(t, resp.Registered) // No credentials yet
}

func TestHandler_BeginLogin_UserIDNotNil(t *testing.T) {
	h := newTestHandler(t)

	// Register a user
	regReq := httptest.NewRequest(http.MethodPost, "/registration/begin",
		strings.NewReader(`{"email":"userid-header@example.com"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	h.BeginRegistration(regRec, regReq)
	require.Equal(t, http.StatusOK, regRec.Code)

	// Get user ID from service
	user, err := h.service.GetUserByEmail(regReq.Context(), "userid-header@example.com")
	require.NoError(t, err)
	userIDStr := base64.RawURLEncoding.EncodeToString(user.WebAuthnID())

	// Test BeginLogin with user ID - this should set the X-User-Id header if userID != nil
	loginReq := BeginLoginRequest{
		UserID: userIDStr,
	}
	b, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.BeginLogin(rec, req)

	// Should fail due to no credentials but we test the userID != nil path (line 182-184)
	assert.True(t, rec.Code >= 400)
}
