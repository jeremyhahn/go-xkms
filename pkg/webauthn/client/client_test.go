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

package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockAdapter implements AuthenticatorAdapter for testing.
type mockAdapter struct {
	available        bool
	makeCredentialFn func(options []byte) ([]byte, error)
	getAssertionFn   func(options []byte) ([]byte, error)
}

func (m *mockAdapter) Available() bool { return m.available }

func (m *mockAdapter) MakeCredential(options []byte) ([]byte, error) {
	if m.makeCredentialFn != nil {
		return m.makeCredentialFn(options)
	}
	return nil, ErrCTAPOperationFailed
}

func (m *mockAdapter) GetAssertion(options []byte) ([]byte, error) {
	if m.getAssertionFn != nil {
		return m.getAssertionFn(options)
	}
	return nil, ErrCTAPOperationFailed
}

func TestNewClient_ValidConfig(t *testing.T) {
	adapter := NewSoftwareAdapter()
	c, err := NewClient(&Config{
		ServerURL:            "https://example.com",
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if c == nil {
		t.Fatal("NewClient() returned nil client")
	}
}

func TestNewClient_NilConfig(t *testing.T) {
	_, err := NewClient(nil)
	if err == nil {
		t.Fatal("NewClient(nil) should return error")
	}
	if !errors.Is(err, ErrNilConfig) {
		t.Errorf("error = %v, want %v", err, ErrNilConfig)
	}
}

func TestNewClient_EmptyServerURL(t *testing.T) {
	_, err := NewClient(&Config{
		ServerURL:            "",
		AuthenticatorAdapter: NewSoftwareAdapter(),
	})
	if err == nil {
		t.Fatal("NewClient() with empty ServerURL should return error")
	}
	if !errors.Is(err, ErrServerURLRequired) {
		t.Errorf("error = %v, want %v", err, ErrServerURLRequired)
	}
}

func TestNewClient_NilAdapter(t *testing.T) {
	_, err := NewClient(&Config{
		ServerURL:            "https://example.com",
		AuthenticatorAdapter: nil,
	})
	if err == nil {
		t.Fatal("NewClient() with nil adapter should return error")
	}
	if !errors.Is(err, ErrNilAuthenticatorAdapter) {
		t.Errorf("error = %v, want %v", err, ErrNilAuthenticatorAdapter)
	}
}

func TestNewClient_WithHTTPClient(t *testing.T) {
	httpClient := &http.Client{Timeout: 5 * time.Second}
	c, err := NewClient(&Config{
		ServerURL:            "https://example.com",
		HTTPClient:           httpClient,
		AuthenticatorAdapter: NewSoftwareAdapter(),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if c.httpClient != httpClient {
		t.Error("client should use the provided HTTP client")
	}
}

func TestNewClient_StripsTrailingSlash(t *testing.T) {
	c, err := NewClient(&Config{
		ServerURL:            "https://example.com/",
		AuthenticatorAdapter: NewSoftwareAdapter(),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if c.serverURL != "https://example.com" {
		t.Errorf("serverURL = %q, want %q", c.serverURL, "https://example.com")
	}
}

func TestNewClient_DefaultTimeout(t *testing.T) {
	c, err := NewClient(&Config{
		ServerURL:            "https://example.com",
		AuthenticatorAdapter: NewSoftwareAdapter(),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if c.config.Timeout != 30*time.Second {
		t.Errorf("default timeout = %v, want %v", c.config.Timeout, 30*time.Second)
	}
}

// writeJSON is a test helper that writes JSON to the response writer and checks for errors.
func writeJSON(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("failed to encode JSON response: %v", err)
	}
}

func TestRegister_Success(t *testing.T) {
	// Create a mock server that simulates the WebAuthn RP
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webauthn/registration/begin":
			w.Header().Set("X-Session-Id", "test-session-123")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "dGVzdC1jaGFsbGVuZ2UtMTIzNDU2Nzg5MDEyMzQ1Ng",
					"rp": map[string]interface{}{
						"id":   "localhost",
						"name": "Test RP",
					},
					"user": map[string]interface{}{
						"id":          "dXNlci0xMjM",
						"name":        "test@example.com",
						"displayName": "Test User",
					},
				},
			})
		case "/api/v1/webauthn/registration/finish":
			sessionID := r.Header.Get("X-Session-Id")
			if sessionID != "test-session-123" {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(t, w, map[string]string{
					"error":   "invalid_session",
					"message": "session ID mismatch",
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]string{
				"token":   "jwt-token-abc",
				"user_id": "user-123-encoded",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		makeCredentialFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]interface{}{
				"id":    "credential-id",
				"rawId": "credential-id",
				"type":  "public-key",
				"response": map[string]interface{}{
					"clientDataJSON":    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
					"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YQ",
				},
			})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	result, err := c.Register(context.Background(), &RegistrationRequest{
		Username: "test@example.com",
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	if result.UserID != "user-123-encoded" {
		t.Errorf("UserID = %q, want %q", result.UserID, "user-123-encoded")
	}
	if result.JWT != "jwt-token-abc" {
		t.Errorf("JWT = %q, want %q", result.JWT, "jwt-token-abc")
	}
}

func TestRegister_NilRequest(t *testing.T) {
	c, err := NewClient(&Config{
		ServerURL:            "https://example.com",
		AuthenticatorAdapter: NewSoftwareAdapter(),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), nil)
	if !errors.Is(err, ErrNilRequest) {
		t.Errorf("error = %v, want %v", err, ErrNilRequest)
	}
}

func TestRegister_EmptyUsername(t *testing.T) {
	c, err := NewClient(&Config{
		ServerURL:            "https://example.com",
		AuthenticatorAdapter: NewSoftwareAdapter(),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: ""})
	if !errors.Is(err, ErrUsernameRequired) {
		t.Errorf("error = %v, want %v", err, ErrUsernameRequired)
	}
}

func TestRegister_AuthenticatorNotAvailable(t *testing.T) {
	adapter := &mockAdapter{available: false}

	c, err := NewClient(&Config{
		ServerURL:            "https://example.com",
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "test@example.com"})
	if !errors.Is(err, ErrAuthenticatorNotFound) {
		t.Errorf("error = %v, want %v", err, ErrAuthenticatorNotFound)
	}
}

func TestRegister_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(t, w, map[string]string{
			"error":   "internal_error",
			"message": "something went wrong",
		})
	}))
	defer server.Close()

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: &mockAdapter{available: true},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Register() should return error for server error")
	}

	// The error should contain server error details
	var se *ServerError
	if !errors.As(err, &se) {
		// It may be wrapped in ClientError, check the chain
		var ce *ClientError
		if errors.As(err, &ce) {
			if !errors.As(ce.Err, &se) {
				t.Logf("error chain: %v", err)
			}
		}
	}
}

func TestRegister_AuthenticatorError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Session-Id", "session-456")
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, map[string]interface{}{
			"publicKey": map[string]interface{}{
				"challenge": "dGVzdC1jaGFsbGVuZ2U",
				"rp":        map[string]interface{}{"id": "localhost", "name": "Test"},
				"user":      map[string]interface{}{"id": "dXNlcg", "name": "test@example.com", "displayName": "Test"},
			},
		})
	}))
	defer server.Close()

	adapterErr := fmt.Errorf("authenticator device not connected")
	adapter := &mockAdapter{
		available: true,
		makeCredentialFn: func(options []byte) ([]byte, error) {
			return nil, adapterErr
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Register() should return error when authenticator fails")
	}
	if !errors.Is(err, ErrCTAPOperationFailed) {
		t.Errorf("error should wrap ErrCTAPOperationFailed, got: %v", err)
	}
}

func TestRegister_InvalidServerResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webauthn/registration/begin":
			// Return 200 but no session ID header
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write([]byte(`{"publicKey":{}}`)); err != nil {
				t.Errorf("failed to write response: %v", err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: &mockAdapter{available: true},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Register() should return error for missing session ID")
	}
	if !errors.Is(err, ErrInvalidServerResponse) {
		t.Errorf("error should wrap ErrInvalidServerResponse, got: %v", err)
	}
}

func TestRegister_FinishServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webauthn/registration/begin":
			w.Header().Set("X-Session-Id", "session-789")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "Y2hhbGxlbmdl",
					"rp":        map[string]interface{}{"id": "localhost", "name": "Test"},
					"user":      map[string]interface{}{"id": "dXNlcg", "name": "t@e.com", "displayName": "T"},
				},
			})
		case "/api/v1/webauthn/registration/finish":
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(t, w, map[string]string{
				"error":   "invalid_request",
				"message": "invalid attestation",
			})
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		makeCredentialFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]string{"id": "cred", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Register() should return error for finish server error")
	}
	if !errors.Is(err, ErrRegistrationFailed) {
		t.Errorf("error should wrap ErrRegistrationFailed, got: %v", err)
	}
}

func TestRegister_WithAuthToken(t *testing.T) {
	var capturedBeginAuth, capturedFinishAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webauthn/registration/begin":
			capturedBeginAuth = r.Header.Get("Authorization")
			w.Header().Set("X-Session-Id", "session-auth")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "dGVzdA",
					"rp":        map[string]interface{}{"id": "localhost", "name": "Test"},
					"user":      map[string]interface{}{"id": "dXNlcg", "name": "t@e.com", "displayName": "T"},
				},
			})
		case "/api/v1/webauthn/registration/finish":
			capturedFinishAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]string{
				"token":   "new-jwt",
				"user_id": "user1",
			})
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		makeCredentialFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]string{"id": "cred", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{
		Username:  "test@example.com",
		AuthToken: "setup-token-xyz",
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	if capturedBeginAuth != "Bearer setup-token-xyz" {
		t.Errorf("begin auth header = %q, want %q", capturedBeginAuth, "Bearer setup-token-xyz")
	}
	if capturedFinishAuth != "Bearer setup-token-xyz" {
		t.Errorf("finish auth header = %q, want %q", capturedFinishAuth, "Bearer setup-token-xyz")
	}
}

func TestLogin_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webauthn/login/begin":
			w.Header().Set("X-Session-Id", "login-session-1")
			w.Header().Set("X-User-Id", "user-id-encoded")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "bG9naW4tY2hhbGxlbmdl",
					"rpId":      "localhost",
				},
			})
		case "/api/v1/webauthn/login/finish":
			sessionID := r.Header.Get("X-Session-Id")
			if sessionID != "login-session-1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]string{
				"token":   "login-jwt-token",
				"user_id": "user-id-encoded",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		getAssertionFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]interface{}{
				"id":    "cred-id",
				"rawId": "cred-id",
				"type":  "public-key",
				"response": map[string]interface{}{
					"clientDataJSON":    "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
					"authenticatorData": "AAAA",
					"signature":         "c2lnbmF0dXJl",
				},
			})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	result, err := c.Login(context.Background(), &AuthenticationRequest{
		Username: "test@example.com",
	})
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}

	if result.JWT != "login-jwt-token" {
		t.Errorf("JWT = %q, want %q", result.JWT, "login-jwt-token")
	}
	if result.UserID != "user-id-encoded" {
		t.Errorf("UserID = %q, want %q", result.UserID, "user-id-encoded")
	}
}

func TestLogin_NilRequest(t *testing.T) {
	c, err := NewClient(&Config{
		ServerURL:            "https://example.com",
		AuthenticatorAdapter: NewSoftwareAdapter(),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), nil)
	if !errors.Is(err, ErrNilRequest) {
		t.Errorf("error = %v, want %v", err, ErrNilRequest)
	}
}

func TestLogin_EmptyUsername(t *testing.T) {
	c, err := NewClient(&Config{
		ServerURL:            "https://example.com",
		AuthenticatorAdapter: NewSoftwareAdapter(),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{Username: ""})
	if !errors.Is(err, ErrUsernameRequired) {
		t.Errorf("error = %v, want %v", err, ErrUsernameRequired)
	}
}

func TestLogin_AuthenticatorNotAvailable(t *testing.T) {
	adapter := &mockAdapter{available: false}
	c, err := NewClient(&Config{
		ServerURL:            "https://example.com",
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{Username: "test@example.com"})
	if !errors.Is(err, ErrAuthenticatorNotFound) {
		t.Errorf("error = %v, want %v", err, ErrAuthenticatorNotFound)
	}
}

func TestLogin_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(t, w, map[string]string{
			"error":   "internal_error",
			"message": "database down",
		})
	}))
	defer server.Close()

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: &mockAdapter{available: true},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Login() should return error for server error")
	}
}

func TestLogin_AuthenticatorError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Session-Id", "session-login")
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, map[string]interface{}{
			"publicKey": map[string]interface{}{
				"challenge": "Y2hhbGxlbmdl",
				"rpId":      "localhost",
			},
		})
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		getAssertionFn: func(options []byte) ([]byte, error) {
			return nil, fmt.Errorf("device disconnected")
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Login() should return error when authenticator fails")
	}
	if !errors.Is(err, ErrCTAPOperationFailed) {
		t.Errorf("error should wrap ErrCTAPOperationFailed, got: %v", err)
	}
}

func TestLogin_MissingSessionID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 200 but no session ID header
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"publicKey":{"challenge":"Y2hhbGxlbmdl","rpId":"localhost"}}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer server.Close()

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: &mockAdapter{available: true},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Login() should return error for missing session ID")
	}
	if !errors.Is(err, ErrInvalidServerResponse) {
		t.Errorf("error should wrap ErrInvalidServerResponse, got: %v", err)
	}
}

func TestLogin_FinishServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webauthn/login/begin":
			w.Header().Set("X-Session-Id", "session-login-2")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "Y2hhbGxlbmdl",
					"rpId":      "localhost",
				},
			})
		case "/api/v1/webauthn/login/finish":
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(t, w, map[string]string{
				"error":   "verification_failed",
				"message": "signature invalid",
			})
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		getAssertionFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]string{"id": "cred", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Login() should return error for finish server error")
	}
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("error should wrap ErrAuthenticationFailed, got: %v", err)
	}
}

func TestLogin_WithAuthToken(t *testing.T) {
	var capturedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webauthn/login/begin":
			capturedAuth = r.Header.Get("Authorization")
			w.Header().Set("X-Session-Id", "session-token")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "Y2hhbGxlbmdl",
					"rpId":      "localhost",
				},
			})
		case "/api/v1/webauthn/login/finish":
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]string{
				"token":   "jwt",
				"user_id": "u1",
			})
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		getAssertionFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]string{"id": "c", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{
		Username:  "test@example.com",
		AuthToken: "pre-auth-token",
	})
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}

	if capturedAuth != "Bearer pre-auth-token" {
		t.Errorf("auth header = %q, want %q", capturedAuth, "Bearer pre-auth-token")
	}
}

func TestAvailable_BothAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, map[string]bool{"registered": false})
	}))
	defer server.Close()

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: &mockAdapter{available: true},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if !c.Available(context.Background()) {
		t.Error("Available() should return true when both server and adapter are available")
	}
}

func TestAvailable_AdapterNotAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: &mockAdapter{available: false},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if c.Available(context.Background()) {
		t.Error("Available() should return false when adapter is not available")
	}
}

func TestAvailable_ServerUnreachable(t *testing.T) {
	// Use a server that we immediately close
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serverURL := server.URL
	server.Close()

	c, err := NewClient(&Config{
		ServerURL:            serverURL,
		AuthenticatorAdapter: &mockAdapter{available: true},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if c.Available(context.Background()) {
		t.Error("Available() should return false when server is unreachable")
	}
}

func TestAvailable_ServerReturns500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: &mockAdapter{available: true},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if c.Available(context.Background()) {
		t.Error("Available() should return false when server returns 500")
	}
}

func TestRegister_ServerUnavailable(t *testing.T) {
	// Use a closed server to simulate unreachable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serverURL := server.URL
	server.Close()

	c, err := NewClient(&Config{
		ServerURL:            serverURL,
		AuthenticatorAdapter: &mockAdapter{available: true},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Register() should return error when server is unreachable")
	}
	if !errors.Is(err, ErrServerUnavailable) {
		t.Errorf("error should wrap ErrServerUnavailable, got: %v", err)
	}
}

func TestLogin_ServerUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serverURL := server.URL
	server.Close()

	c, err := NewClient(&Config{
		ServerURL:            serverURL,
		AuthenticatorAdapter: &mockAdapter{available: true},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Login() should return error when server is unreachable")
	}
	if !errors.Is(err, ErrServerUnavailable) {
		t.Errorf("error should wrap ErrServerUnavailable, got: %v", err)
	}
}

func TestRegister_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay response to allow context cancellation
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: &mockAdapter{available: true},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = c.Register(ctx, &RegistrationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Register() should return error for cancelled context")
	}
}

func TestRegister_InvalidFinishResponseJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webauthn/registration/begin":
			w.Header().Set("X-Session-Id", "session-bad-json")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "dGVzdA",
					"rp":        map[string]interface{}{"id": "localhost", "name": "Test"},
					"user":      map[string]interface{}{"id": "dXNlcg", "name": "t@e.com", "displayName": "T"},
				},
			})
		case "/api/v1/webauthn/registration/finish":
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write([]byte("this is not json")); err != nil {
				t.Errorf("failed to write response: %v", err)
			}
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		makeCredentialFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]string{"id": "cred", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Register() should return error for invalid finish response JSON")
	}
	if !errors.Is(err, ErrInvalidServerResponse) {
		t.Errorf("error should wrap ErrInvalidServerResponse, got: %v", err)
	}
}

func TestLogin_InvalidFinishResponseJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webauthn/login/begin":
			w.Header().Set("X-Session-Id", "session-bad")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "Y2hhbGxlbmdl",
					"rpId":      "localhost",
				},
			})
		case "/api/v1/webauthn/login/finish":
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write([]byte("not-json")); err != nil {
				t.Errorf("failed to write response: %v", err)
			}
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		getAssertionFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]string{"id": "c", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Login() should return error for invalid finish response JSON")
	}
	if !errors.Is(err, ErrInvalidServerResponse) {
		t.Errorf("error should wrap ErrInvalidServerResponse, got: %v", err)
	}
}

func TestRegister_DisplayNameDefault(t *testing.T) {
	var capturedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/webauthn/registration/begin" {
			body, _ := io.ReadAll(r.Body)
			capturedBody = string(body)
			w.Header().Set("X-Session-Id", "session-dn")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "dGVzdA",
					"rp":        map[string]interface{}{"id": "localhost", "name": "Test"},
					"user":      map[string]interface{}{"id": "dXNlcg", "name": "t@e.com", "displayName": "T"},
				},
			})
		} else {
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]string{"token": "t", "user_id": "u"})
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		makeCredentialFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]string{"id": "cred", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{
		Username: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	// The display_name should default to the username
	if !strings.Contains(capturedBody, `"display_name":"alice@example.com"`) {
		t.Errorf("begin request body should contain display_name defaulting to username, got: %s", capturedBody)
	}
}

func TestParseServerError_InvalidJSON(t *testing.T) {
	err := parseServerError(400, []byte("not json"))
	se, ok := err.(*ServerError)
	if !ok {
		t.Fatalf("expected *ServerError, got %T", err)
	}
	if se.StatusCode != 400 {
		t.Errorf("StatusCode = %d, want 400", se.StatusCode)
	}
	if se.Message != "not json" {
		t.Errorf("Message = %q, want %q", se.Message, "not json")
	}
	if se.ErrorCode != "" {
		t.Errorf("ErrorCode = %q, want empty", se.ErrorCode)
	}
}

func TestParseServerError_ValidJSON(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"error":   "invalid_session",
		"message": "session not found",
	})

	err := parseServerError(400, body)
	se, ok := err.(*ServerError)
	if !ok {
		t.Fatalf("expected *ServerError, got %T", err)
	}
	if se.StatusCode != 400 {
		t.Errorf("StatusCode = %d, want 400", se.StatusCode)
	}
	if se.ErrorCode != "invalid_session" {
		t.Errorf("ErrorCode = %q, want %q", se.ErrorCode, "invalid_session")
	}
	if se.Message != "session not found" {
		t.Errorf("Message = %q, want %q", se.Message, "session not found")
	}
}

func TestLogin_UserIDPropagated(t *testing.T) {
	var capturedFinishUserID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webauthn/login/begin":
			w.Header().Set("X-Session-Id", "login-sess")
			w.Header().Set("X-User-Id", "propagated-user-id")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "Y2hhbGxlbmdl",
					"rpId":      "localhost",
				},
			})
		case "/api/v1/webauthn/login/finish":
			capturedFinishUserID = r.Header.Get("X-User-Id")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]string{
				"token":   "jwt",
				"user_id": "u",
			})
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		getAssertionFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]string{"id": "c", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{Username: "test@example.com"})
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}

	if capturedFinishUserID != "propagated-user-id" {
		t.Errorf("finish X-User-Id = %q, want %q", capturedFinishUserID, "propagated-user-id")
	}
}

func TestNewClient_WithTLSConfig(t *testing.T) {
	c, err := NewClient(&Config{
		ServerURL:            "https://example.com",
		AuthenticatorAdapter: NewSoftwareAdapter(),
		TLSConfig:            &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if c == nil {
		t.Fatal("NewClient() returned nil client")
	}
}

func TestRegister_FinishServerUnavailable(t *testing.T) {
	// Test that finishRegistration handles server connection failure
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// Begin registration succeeds
			w.Header().Set("X-Session-Id", "sess-fin-unavail")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "dGVzdA",
					"rp":        map[string]interface{}{"id": "localhost", "name": "Test"},
					"user":      map[string]interface{}{"id": "dXNlcg", "name": "t@e.com", "displayName": "T"},
				},
			})
		}
		// Second call (finish) - close the server to simulate unavailability
	}))

	// Create client pointing to the server
	adapter := &mockAdapter{
		available: true,
		makeCredentialFn: func(options []byte) ([]byte, error) {
			// Close the server after begin succeeds but before finish
			server.Close()
			return json.Marshal(map[string]string{"id": "cred", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Register() should return error when finish server is unreachable")
	}
}

func TestLogin_FinishServerUnavailable(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// Begin login succeeds
			w.Header().Set("X-Session-Id", "sess-login-unavail")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "Y2hhbGxlbmdl",
					"rpId":      "localhost",
				},
			})
		}
	}))

	adapter := &mockAdapter{
		available: true,
		getAssertionFn: func(options []byte) ([]byte, error) {
			// Close server after begin succeeds
			server.Close()
			return json.Marshal(map[string]string{"id": "c", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{Username: "test@example.com"})
	if err == nil {
		t.Fatal("Login() should return error when finish server is unreachable")
	}
}

func TestRegister_WithDisplayName(t *testing.T) {
	var capturedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/webauthn/registration/begin" {
			body, _ := io.ReadAll(r.Body)
			capturedBody = string(body)
			w.Header().Set("X-Session-Id", "session-dn2")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "dGVzdA",
					"rp":        map[string]interface{}{"id": "localhost", "name": "Test"},
					"user":      map[string]interface{}{"id": "dXNlcg", "name": "t@e.com", "displayName": "T"},
				},
			})
		} else {
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]string{"token": "t", "user_id": "u"})
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		makeCredentialFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]string{"id": "cred", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Register(context.Background(), &RegistrationRequest{
		Username:    "alice@example.com",
		DisplayName: "Alice Wonderland",
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	// When DisplayName is explicitly set, it should use that instead of the username
	if !strings.Contains(capturedBody, "Alice Wonderland") {
		t.Errorf("begin request body should contain explicit display_name, got: %s", capturedBody)
	}
}

func TestLogin_WithAuthTokenOnFinish(t *testing.T) {
	var capturedFinishAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/webauthn/login/begin":
			w.Header().Set("X-Session-Id", "session-auth-fin")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]interface{}{
				"publicKey": map[string]interface{}{
					"challenge": "Y2hhbGxlbmdl",
					"rpId":      "localhost",
				},
			})
		case "/api/v1/webauthn/login/finish":
			capturedFinishAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, map[string]string{
				"token":   "jwt",
				"user_id": "u1",
			})
		}
	}))
	defer server.Close()

	adapter := &mockAdapter{
		available: true,
		getAssertionFn: func(options []byte) ([]byte, error) {
			return json.Marshal(map[string]string{"id": "c", "type": "public-key"})
		},
	}

	c, err := NewClient(&Config{
		ServerURL:            server.URL,
		AuthenticatorAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = c.Login(context.Background(), &AuthenticationRequest{
		Username:  "test@example.com",
		AuthToken: "login-auth-token",
	})
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}

	if capturedFinishAuth != "Bearer login-auth-token" {
		t.Errorf("finish auth header = %q, want %q", capturedFinishAuth, "Bearer login-auth-token")
	}
}
