// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// mockURLExtractor implements URLExtractor for testing.
type mockURLExtractor struct {
	url string
}

func (m *mockURLExtractor) ExtractURL() string {
	return m.url
}

// TestNewTransport_Success tests successful transport creation.
func TestNewTransport_Success(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *transport.Config
		wantURL string
	}{
		{
			name: "HTTPS URL",
			cfg: &transport.Config{
				Address: "https://localhost:8443",
			},
			wantURL: "https://localhost:8443",
		},
		{
			name: "HTTP URL",
			cfg: &transport.Config{
				Address:  "http://localhost:8080",
				Insecure: true,
			},
			wantURL: "http://localhost:8080",
		},
		{
			name: "TCP address with TLS",
			cfg: &transport.Config{
				Address: "localhost:8443",
			},
			wantURL: "https://localhost:8443",
		},
		{
			name: "TCP address without TLS",
			cfg: &transport.Config{
				Address:  "localhost:8080",
				Insecure: true,
			},
			wantURL: "http://localhost:8080",
		},
		{
			name: "HTTPS URL with path",
			cfg: &transport.Config{
				Address: "https://localhost:8443/acme",
			},
			wantURL: "https://localhost:8443/acme",
		},
		{
			name: "with custom timeout",
			cfg: &transport.Config{
				Address: "https://localhost:8443",
				Timeout: 60 * time.Second,
			},
			wantURL: "https://localhost:8443",
		},
		{
			name: "with TLS config",
			cfg: &transport.Config{
				Address: "https://localhost:8443",
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
				},
			},
			wantURL: "https://localhost:8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := NewTransport(tt.cfg)
			if err != nil {
				t.Fatalf("NewTransport() error = %v", err)
			}
			defer tr.Close()

			restTr, ok := tr.(*Transport)
			if !ok {
				t.Fatal("transport is not *Transport")
			}

			if restTr.BaseURL() != tt.wantURL {
				t.Errorf("BaseURL() = %v, want %v", restTr.BaseURL(), tt.wantURL)
			}

			if !tr.Healthy() {
				t.Error("Healthy() = false, want true")
			}

			if tr.Conn() == nil {
				t.Error("Conn() = nil, want http.Client")
			}
		})
	}
}

// TestNewTransport_NilConfig tests transport creation with nil config.
func TestNewTransport_NilConfig(t *testing.T) {
	_, err := NewTransport(nil)
	if err == nil {
		t.Fatal("NewTransport(nil) error = nil, want error")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("error code = %v, want INVALID_INPUT", errors.Code(err))
	}
}

// TestNewTransport_InvalidAddress tests transport creation with invalid address.
func TestNewTransport_InvalidAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{
			name:    "Unix socket path",
			address: "/var/run/acme.sock",
		},
		{
			name:    "Unix URL",
			address: "unix:///var/run/acme.sock",
		},
		{
			name:    "Embedded address",
			address: "embedded://local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &transport.Config{
				Address: tt.address,
			}
			_, err := NewTransport(cfg)
			if err == nil {
				t.Fatal("NewTransport() error = nil, want error")
			}
			if !errors.IsInvalidInput(err) {
				t.Errorf("error code = %v, want INVALID_INPUT", errors.Code(err))
			}
		})
	}
}

// TestTransport_Request_Directory tests directory request.
func TestTransport_Request_Directory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/directory" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.Header().Set(HeaderReplayNonce, "test-nonce-12345")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"newNonce":   "https://localhost/acme/new-nonce",
			"newAccount": "https://localhost/acme/new-acct",
			"newOrder":   "https://localhost/acme/new-order",
			"revokeCert": "https://localhost/acme/revoke-cert",
			"keyChange":  "https://localhost/acme/key-change",
		})
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	resp, err := tr.Request(context.Background(), "directory", "get", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	result, ok := resp.(*Response)
	if !ok {
		t.Fatalf("response is not *Response")
	}

	if result.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %v, want %v", result.StatusCode, http.StatusOK)
	}

	if result.Nonce != "test-nonce-12345" {
		t.Errorf("Nonce = %v, want test-nonce-12345", result.Nonce)
	}

	if result.Data["newAccount"] != "https://localhost/acme/new-acct" {
		t.Errorf("newAccount = %v, want https://localhost/acme/new-acct", result.Data["newAccount"])
	}

	restTr := tr.(*Transport)
	if restTr.GetNonce() != "test-nonce-12345" {
		t.Errorf("GetNonce() = %v, want test-nonce-12345", restTr.GetNonce())
	}
}

// TestTransport_Request_Nonce tests nonce request.
func TestTransport_Request_Nonce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/acme/new-nonce" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodHead {
			t.Errorf("unexpected method: %s, want HEAD", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set(HeaderReplayNonce, "fresh-nonce-67890")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	resp, err := tr.Request(context.Background(), "nonce", "new", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	result, ok := resp.(*Response)
	if !ok {
		t.Fatalf("response is not *Response")
	}

	if result.Nonce != "fresh-nonce-67890" {
		t.Errorf("Nonce = %v, want fresh-nonce-67890", result.Nonce)
	}
}

// TestTransport_Request_AccountCreate tests account creation request.
func TestTransport_Request_AccountCreate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/acme/new-acct" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s, want POST", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		contentType := r.Header.Get(HeaderContentType)
		if contentType != ContentTypeJOSE {
			t.Errorf("Content-Type = %v, want %v", contentType, ContentTypeJOSE)
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)

		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.Header().Set(HeaderReplayNonce, "new-nonce-after-create")
		w.Header().Set(HeaderLocation, "https://localhost/acme/acct/123")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "valid",
			"contact": []string{"mailto:test@example.com"},
			"orders":  "https://localhost/acme/acct/123/orders",
		})
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	req := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:test@example.com"},
	}

	resp, err := tr.Request(context.Background(), "account", "create", req)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	result, ok := resp.(*Response)
	if !ok {
		t.Fatalf("response is not *Response")
	}

	if result.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %v, want %v", result.StatusCode, http.StatusCreated)
	}

	if result.Location != "https://localhost/acme/acct/123" {
		t.Errorf("Location = %v, want https://localhost/acme/acct/123", result.Location)
	}

	if result.Data["status"] != "valid" {
		t.Errorf("status = %v, want valid", result.Data["status"])
	}
}

// TestTransport_Request_OrderCreate tests order creation request.
func TestTransport_Request_OrderCreate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/acme/new-order" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.Header().Set(HeaderLocation, "https://localhost/acme/order/456")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "pending",
			"identifiers": []map[string]string{
				{"type": "dns", "value": "example.com"},
			},
			"authorizations": []string{"https://localhost/acme/authz/789"},
			"finalize":       "https://localhost/acme/order/456/finalize",
		})
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	req := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "dns", "value": "example.com"},
		},
	}

	resp, err := tr.Request(context.Background(), "order", "create", req)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	result, ok := resp.(*Response)
	if !ok {
		t.Fatalf("response is not *Response")
	}

	if result.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %v, want %v", result.StatusCode, http.StatusCreated)
	}

	if result.Location != "https://localhost/acme/order/456" {
		t.Errorf("Location = %v, want https://localhost/acme/order/456", result.Location)
	}
}

// TestTransport_Request_CertificateGet tests certificate retrieval.
func TestTransport_Request_CertificateGet(t *testing.T) {
	pemCert := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpE...
-----END CERTIFICATE-----`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/acme/cert/") {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s, want GET", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set(HeaderContentType, ContentTypePEM)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(pemCert))
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	req := &mockURLExtractor{url: server.URL + "/acme/cert/123"}

	resp, err := tr.Request(context.Background(), "certificate", "get", req)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	result, ok := resp.(*Response)
	if !ok {
		t.Fatalf("response is not *Response")
	}

	if !result.IsPEM {
		t.Error("IsPEM = false, want true")
	}

	if string(result.Body) != pemCert {
		t.Errorf("Body = %v, want %v", string(result.Body), pemCert)
	}
}

// TestTransport_Request_URLExtractor tests requests with URL extractor.
func TestTransport_Request_URLExtractor(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		method   string
		path     string
		wantPath string
	}{
		{
			name:     "account get",
			service:  "account",
			method:   "get",
			path:     "/acme/acct/123",
			wantPath: "/acme/acct/123",
		},
		{
			name:     "order get",
			service:  "order",
			method:   "get",
			path:     "/acme/order/456",
			wantPath: "/acme/order/456",
		},
		{
			name:     "authorization get",
			service:  "authorization",
			method:   "get",
			path:     "/acme/authz/789",
			wantPath: "/acme/authz/789",
		},
		{
			name:     "challenge get",
			service:  "challenge",
			method:   "get",
			path:     "/acme/challenge/abc",
			wantPath: "/acme/challenge/abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receivedPath := ""
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				w.Header().Set(HeaderContentType, ContentTypeJSON)
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{"status": "valid"})
			}))
			defer server.Close()

			cfg := &transport.Config{
				Address:  server.URL,
				Insecure: true,
			}
			tr, err := NewTransport(cfg)
			if err != nil {
				t.Fatalf("NewTransport() error = %v", err)
			}
			defer tr.Close()

			req := &mockURLExtractor{url: server.URL + tt.path}
			_, err = tr.Request(context.Background(), tt.service, tt.method, req)
			if err != nil {
				t.Fatalf("Request() error = %v", err)
			}

			if receivedPath != tt.wantPath {
				t.Errorf("received path = %v, want %v", receivedPath, tt.wantPath)
			}
		})
	}
}

// TestTransport_Request_UnknownRoute tests request with unknown route.
func TestTransport_Request_UnknownRoute(t *testing.T) {
	cfg := &transport.Config{
		Address:  "https://localhost:8443",
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "unknown", "method", nil)
	if err == nil {
		t.Fatal("Request() error = nil, want error")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("error code = %v, want INVALID_INPUT", errors.Code(err))
	}
	if !strings.Contains(err.Error(), "unknown route") {
		t.Errorf("error = %v, want to contain 'unknown route'", err)
	}
}

// TestTransport_Request_EmptyPath tests request that fails to build path.
func TestTransport_Request_EmptyPath(t *testing.T) {
	cfg := &transport.Config{
		Address:  "https://localhost:8443",
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	// Request without URL extractor for a route that requires it
	_, err = tr.Request(context.Background(), "account", "get", nil)
	if err == nil {
		t.Fatal("Request() error = nil, want error")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("error code = %v, want INVALID_INPUT", errors.Code(err))
	}
}

// TestTransport_Request_ClosedTransport tests request on closed transport.
func TestTransport_Request_ClosedTransport(t *testing.T) {
	cfg := &transport.Config{
		Address:  "https://localhost:8443",
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() error = nil, want error")
	}
	if !errors.IsUnavailable(err) {
		t.Errorf("error code = %v, want UNAVAILABLE", errors.Code(err))
	}
}

// TestTransport_Request_ContextCanceled tests request with canceled context.
func TestTransport_Request_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = tr.Request(ctx, "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() error = nil, want error")
	}
	if !errors.IsCanceled(err) {
		t.Errorf("error code = %v, want CANCELED", errors.Code(err))
	}
}

// TestTransport_Request_ACMEError tests ACME error response parsing.
// This test disables retries to directly test error code mapping.
func TestTransport_Request_ACMEError(t *testing.T) {
	tests := []struct {
		name     string
		acmeType string
		detail   string
		status   int
		wantCode errors.ErrorCode
	}{
		{
			name:     "bad nonce",
			acmeType: "urn:ietf:params:acme:error:badNonce",
			detail:   "JWS has an invalid anti-replay nonce",
			status:   http.StatusBadRequest,
			wantCode: errors.CodeACMEBadNonce,
		},
		{
			name:     "unauthorized",
			acmeType: "urn:ietf:params:acme:error:unauthorized",
			detail:   "Account is not authorized",
			status:   http.StatusForbidden,
			wantCode: errors.CodeACMEUnauthorized,
		},
		{
			name:     "account does not exist",
			acmeType: "urn:ietf:params:acme:error:accountDoesNotExist",
			detail:   "Account not found",
			status:   http.StatusNotFound,
			wantCode: errors.CodeACMEAccountDoesNotExist,
		},
		{
			name:     "rate limited",
			acmeType: "urn:ietf:params:acme:error:rateLimited",
			detail:   "Rate limit exceeded",
			status:   http.StatusTooManyRequests,
			wantCode: errors.CodeACMERateLimited,
		},
		{
			name:     "bad CSR",
			acmeType: "urn:ietf:params:acme:error:badCSR",
			detail:   "CSR is invalid",
			status:   http.StatusBadRequest,
			wantCode: errors.CodeACMEBadCSR,
		},
		{
			name:     "order not ready",
			acmeType: "urn:ietf:params:acme:error:orderNotReady",
			detail:   "Order is not ready for finalization",
			status:   http.StatusForbidden,
			wantCode: errors.CodeACMEOrderNotReady,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(HeaderContentType, ContentTypeProblemJSON)
				w.WriteHeader(tt.status)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"type":   tt.acmeType,
					"detail": tt.detail,
					"status": tt.status,
				})
			}))
			defer server.Close()

			// Disable retries to test error code directly
			cfg := &transport.Config{
				Address:    server.URL,
				Insecure:   true,
				MaxRetries: 1, // No retries
			}
			tr, err := NewTransport(cfg)
			if err != nil {
				t.Fatalf("NewTransport() error = %v", err)
			}
			defer tr.Close()

			_, err = tr.Request(context.Background(), "directory", "get", nil)
			if err == nil {
				t.Fatal("Request() error = nil, want error")
			}

			if errors.Code(err) != tt.wantCode {
				t.Errorf("error code = %v, want %v", errors.Code(err), tt.wantCode)
			}

			if !strings.Contains(err.Error(), tt.detail) {
				t.Errorf("error = %v, want to contain %v", err, tt.detail)
			}
		})
	}
}

// TestTransport_Request_HTTPStatusErrors tests HTTP status code error mapping.
// This test disables retries to directly test error code mapping.
func TestTransport_Request_HTTPStatusErrors(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		wantCode errors.ErrorCode
	}{
		{
			name:     "bad request",
			status:   http.StatusBadRequest,
			wantCode: errors.CodeInvalidInput,
		},
		{
			name:     "unauthorized",
			status:   http.StatusUnauthorized,
			wantCode: errors.CodeUnauthorized,
		},
		{
			name:     "forbidden",
			status:   http.StatusForbidden,
			wantCode: errors.CodeForbidden,
		},
		{
			name:     "not found",
			status:   http.StatusNotFound,
			wantCode: errors.CodeNotFound,
		},
		{
			name:     "conflict",
			status:   http.StatusConflict,
			wantCode: errors.CodeConflict,
		},
		{
			name:     "too many requests",
			status:   http.StatusTooManyRequests,
			wantCode: errors.CodeRateLimited,
		},
		{
			name:     "internal server error",
			status:   http.StatusInternalServerError,
			wantCode: errors.CodeInternal,
		},
		{
			name:     "bad gateway",
			status:   http.StatusBadGateway,
			wantCode: errors.CodeUnavailable,
		},
		{
			name:     "service unavailable",
			status:   http.StatusServiceUnavailable,
			wantCode: errors.CodeUnavailable,
		},
		{
			name:     "gateway timeout",
			status:   http.StatusGatewayTimeout,
			wantCode: errors.CodeTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			// Disable retries to test error code directly
			cfg := &transport.Config{
				Address:    server.URL,
				Insecure:   true,
				MaxRetries: 1, // No retries
			}
			tr, err := NewTransport(cfg)
			if err != nil {
				t.Fatalf("NewTransport() error = %v", err)
			}
			defer tr.Close()

			_, err = tr.Request(context.Background(), "directory", "get", nil)
			if err == nil {
				t.Fatal("Request() error = nil, want error")
			}

			if errors.Code(err) != tt.wantCode {
				t.Errorf("error code = %v, want %v", errors.Code(err), tt.wantCode)
			}
		})
	}
}

// TestTransport_Request_Retry tests retry behavior.
func TestTransport_Request_Retry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:         server.URL,
		Insecure:        true,
		MaxRetries:      5,
		RetryBackoff:    10 * time.Millisecond,
		MaxRetryBackoff: 100 * time.Millisecond,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	resp, err := tr.Request(context.Background(), "directory", "get", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	result, ok := resp.(*Response)
	if !ok {
		t.Fatalf("response is not *Response")
	}

	if result.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %v, want %v", result.StatusCode, http.StatusOK)
	}

	if attempts != 3 {
		t.Errorf("attempts = %v, want 3", attempts)
	}
}

// TestTransport_Request_RetryExhausted tests retry exhaustion.
func TestTransport_Request_RetryExhausted(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:      server.URL,
		Insecure:     true,
		MaxRetries:   3,
		RetryBackoff: 10 * time.Millisecond,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() error = nil, want error")
	}

	if attempts != 3 {
		t.Errorf("attempts = %v, want 3", attempts)
	}

	if !strings.Contains(err.Error(), "max retries exceeded") {
		t.Errorf("error = %v, want to contain 'max retries exceeded'", err)
	}
}

// TestTransport_Request_NonRetryableError tests non-retryable error handling.
func TestTransport_Request_NonRetryableError(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:      server.URL,
		Insecure:     true,
		MaxRetries:   5,
		RetryBackoff: 10 * time.Millisecond,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() error = nil, want error")
	}

	if attempts != 1 {
		t.Errorf("attempts = %v, want 1 (no retry for non-retryable error)", attempts)
	}
}

// TestTransport_Request_BadNonceRetry tests badNonce retry with nonce refresh.
func TestTransport_Request_BadNonceRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if r.URL.Path == "/acme/new-nonce" {
			w.Header().Set(HeaderReplayNonce, "fresh-nonce")
			w.WriteHeader(http.StatusOK)
			return
		}
		if attempts == 1 {
			w.Header().Set(HeaderContentType, ContentTypeProblemJSON)
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:badNonce",
				"detail": "JWS has an invalid anti-replay nonce",
				"status": 400,
			})
			return
		}
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:      server.URL,
		Insecure:     true,
		MaxRetries:   3,
		RetryBackoff: 10 * time.Millisecond,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	resp, err := tr.Request(context.Background(), "directory", "get", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	result, ok := resp.(*Response)
	if !ok {
		t.Fatal("response is not *Response")
	}

	if result.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %v, want %v", result.StatusCode, http.StatusOK)
	}

	// Should have made 3 total requests: first failed, nonce refresh, then success
	if attempts < 3 {
		t.Errorf("attempts = %v, want at least 3 (initial, nonce refresh, retry)", attempts)
	}
}

// TestTransport_RequestStream tests streaming (unsupported).
func TestTransport_RequestStream(t *testing.T) {
	cfg := &transport.Config{
		Address:  "https://localhost:8443",
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.RequestStream(context.Background(), "any", "method", nil)
	if err == nil {
		t.Fatal("RequestStream() error = nil, want error")
	}
	if !errors.IsUnimplemented(err) {
		t.Errorf("error code = %v, want UNIMPLEMENTED", errors.Code(err))
	}
}

// TestTransport_Close tests transport close behavior.
func TestTransport_Close(t *testing.T) {
	cfg := &transport.Config{
		Address:  "https://localhost:8443",
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	if !tr.Healthy() {
		t.Error("Healthy() = false before close, want true")
	}

	err = tr.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if tr.Healthy() {
		t.Error("Healthy() = true after close, want false")
	}

	// Second close should be idempotent
	err = tr.Close()
	if err != nil {
		t.Errorf("Close() second call error = %v", err)
	}
}

// TestTransport_Healthy tests health status.
func TestTransport_Healthy(t *testing.T) {
	cfg := &transport.Config{
		Address:  "https://localhost:8443",
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	if !tr.Healthy() {
		t.Error("Healthy() = false, want true initially")
	}
}

// TestTransport_Conn tests Conn method.
func TestTransport_Conn(t *testing.T) {
	cfg := &transport.Config{
		Address:  "https://localhost:8443",
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	conn := tr.Conn()
	if conn == nil {
		t.Error("Conn() = nil, want http.Client")
	}

	client, ok := conn.(*http.Client)
	if !ok {
		t.Error("Conn() is not *http.Client")
	}

	if client == nil {
		t.Error("Conn() client is nil")
	}
}

// TestTransport_BaseURL tests BaseURL method.
func TestTransport_BaseURL(t *testing.T) {
	cfg := &transport.Config{
		Address:  "https://acme.example.com:8443/v2",
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	restTr := tr.(*Transport)
	baseURL := restTr.BaseURL()

	if baseURL != "https://acme.example.com:8443/v2" {
		t.Errorf("BaseURL() = %v, want https://acme.example.com:8443/v2", baseURL)
	}
}

// TestTransport_GetNonce tests GetNonce method.
func TestTransport_GetNonce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderReplayNonce, "stored-nonce-value")
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	restTr := tr.(*Transport)

	// Initially empty
	if restTr.GetNonce() != "" {
		t.Errorf("GetNonce() = %v, want empty string initially", restTr.GetNonce())
	}

	// Make a request to populate nonce
	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	if restTr.GetNonce() != "stored-nonce-value" {
		t.Errorf("GetNonce() = %v, want stored-nonce-value", restTr.GetNonce())
	}
}

// TestFactory_Create tests Factory.Create method.
func TestFactory_Create(t *testing.T) {
	factory := NewFactory()

	cfg := &transport.Config{
		Address:  "https://localhost:8443",
		Insecure: true,
	}

	tr, err := factory.Create(cfg)
	if err != nil {
		t.Fatalf("Factory.Create() error = %v", err)
	}
	defer tr.Close()

	if tr == nil {
		t.Error("Factory.Create() returned nil transport")
	}

	if !tr.Healthy() {
		t.Error("Healthy() = false, want true")
	}
}

// TestFactory_Create_NilConfig tests Factory.Create with nil config.
func TestFactory_Create_NilConfig(t *testing.T) {
	factory := NewFactory()

	_, err := factory.Create(nil)
	if err == nil {
		t.Fatal("Factory.Create(nil) error = nil, want error")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("error code = %v, want INVALID_INPUT", errors.Code(err))
	}
}

// TestBuildRouteMap tests that all expected routes exist.
func TestBuildRouteMap(t *testing.T) {
	routes := buildRouteMap()

	expectedRoutes := []struct {
		key         string
		method      HTTPMethod
		requiresJWS bool
	}{
		{"directory/get", MethodGET, false},
		{"nonce/new", MethodHEAD, false},
		{"account/create", MethodPOST, true},
		{"account/get", MethodPOST, true},
		{"account/update", MethodPOST, true},
		{"account/deactivate", MethodPOST, true},
		{"account/keychange", MethodPOST, true},
		{"order/create", MethodPOST, true},
		{"order/get", MethodPOST, true},
		{"order/list", MethodGET, false},
		{"order/finalize", MethodPOST, true},
		{"authorization/get", MethodPOST, true},
		{"authorization/deactivate", MethodPOST, true},
		{"challenge/get", MethodPOST, true},
		{"challenge/respond", MethodPOST, true},
		{"certificate/get", MethodGET, false},
		{"certificate/revoke", MethodPOST, true},
	}

	for _, er := range expectedRoutes {
		t.Run(er.key, func(t *testing.T) {
			route, ok := routes[er.key]
			if !ok {
				t.Errorf("route %q not found", er.key)
				return
			}

			if route.Method != er.method {
				t.Errorf("route %q method = %v, want %v", er.key, route.Method, er.method)
			}

			if route.RequiresJWS != er.requiresJWS {
				t.Errorf("route %q requiresJWS = %v, want %v", er.key, route.RequiresJWS, er.requiresJWS)
			}

			if route.PathBuilder == nil {
				t.Errorf("route %q has nil PathBuilder", er.key)
			}
		})
	}
}

// TestPathBuilders tests path builder functions.
func TestPathBuilders(t *testing.T) {
	baseURL := "https://acme.example.com"

	tests := []struct {
		name     string
		builder  PathBuilder
		req      interface{}
		wantPath string
	}{
		{
			name:     "pathDirectory",
			builder:  pathDirectory,
			req:      nil,
			wantPath: "https://acme.example.com/directory",
		},
		{
			name:     "pathNewNonce",
			builder:  pathNewNonce,
			req:      nil,
			wantPath: "https://acme.example.com/acme/new-nonce",
		},
		{
			name:     "pathNewAccount",
			builder:  pathNewAccount,
			req:      nil,
			wantPath: "https://acme.example.com/acme/new-acct",
		},
		{
			name:     "pathKeyChange",
			builder:  pathKeyChange,
			req:      nil,
			wantPath: "https://acme.example.com/acme/key-change",
		},
		{
			name:     "pathNewOrder",
			builder:  pathNewOrder,
			req:      nil,
			wantPath: "https://acme.example.com/acme/new-order",
		},
		{
			name:     "pathRevokeCert",
			builder:  pathRevokeCert,
			req:      nil,
			wantPath: "https://acme.example.com/acme/revoke-cert",
		},
		{
			name:     "pathOrdersList with nil",
			builder:  pathOrdersList,
			req:      nil,
			wantPath: "https://acme.example.com/acme/orders",
		},
		{
			name:     "pathOrdersList with URL",
			builder:  pathOrdersList,
			req:      &mockURLExtractor{url: "https://other.com/orders"},
			wantPath: "https://other.com/orders",
		},
		{
			name:     "pathAccountByURL with extractor",
			builder:  pathAccountByURL,
			req:      &mockURLExtractor{url: "https://acme.example.com/acme/acct/123"},
			wantPath: "https://acme.example.com/acme/acct/123",
		},
		{
			name:     "pathAccountByURL without extractor",
			builder:  pathAccountByURL,
			req:      nil,
			wantPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.builder(baseURL, tt.req)
			if got != tt.wantPath {
				t.Errorf("path = %v, want %v", got, tt.wantPath)
			}
		})
	}
}

// TestACMEErrorWithSubproblems tests ACME error with subproblems.
func TestACMEErrorWithSubproblems(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeProblemJSON)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "urn:ietf:params:acme:error:compound",
			"detail": "Multiple problems occurred",
			"status": 400,
			"subproblems": []map[string]interface{}{
				{
					"type":   "urn:ietf:params:acme:error:rejectedIdentifier",
					"detail": "Identifier rejected: test.example.com",
					"identifier": map[string]string{
						"type":  "dns",
						"value": "test.example.com",
					},
				},
				{
					"type":   "urn:ietf:params:acme:error:rejectedIdentifier",
					"detail": "Identifier rejected: bad.example.com",
					"identifier": map[string]string{
						"type":  "dns",
						"value": "bad.example.com",
					},
				},
			},
		})
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:    server.URL,
		Insecure:   true,
		MaxRetries: 1,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() error = nil, want error")
	}

	if errors.Code(err) != errors.CodeACMECompound {
		t.Errorf("error code = %v, want CodeACMECompound", errors.Code(err))
	}

	ctx := errors.Context(err)
	if ctx == nil {
		t.Fatal("error context is nil")
	}

	subproblems, ok := ctx["subproblems"]
	if !ok {
		t.Error("subproblems not in error context")
	}
	if subproblems == nil {
		t.Error("subproblems is nil")
	}
}

// TestTransport_wrapHTTPError tests HTTP error wrapping.
func TestTransport_wrapHTTPError(t *testing.T) {
	cfg := &transport.Config{
		Address:  "https://localhost:8443",
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	restTr := tr.(*Transport)

	tests := []struct {
		name     string
		errStr   string
		wantCode errors.ErrorCode
	}{
		{
			name:     "connection refused",
			errStr:   "dial tcp: connection refused",
			wantCode: errors.CodeConnection,
		},
		{
			name:     "no such host",
			errStr:   "dial tcp: lookup invalid: no such host",
			wantCode: errors.CodeConnection,
		},
		{
			name:     "context canceled",
			errStr:   "context canceled",
			wantCode: errors.CodeCanceled,
		},
		{
			name:     "context deadline exceeded",
			errStr:   "context deadline exceeded",
			wantCode: errors.CodeTimeout,
		},
		{
			name:     "TLS error",
			errStr:   "tls: certificate verify failed",
			wantCode: errors.CodeConfiguration,
		},
		{
			name:     "x509 error",
			errStr:   "x509: certificate signed by unknown authority",
			wantCode: errors.CodeConfiguration,
		},
		{
			name:     "other error",
			errStr:   "some other network error",
			wantCode: errors.CodeTransport,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testErr := &testError{msg: tt.errStr}
			wrapped := restTr.wrapHTTPError(testErr)

			if errors.Code(wrapped) != tt.wantCode {
				t.Errorf("error code = %v, want %v", errors.Code(wrapped), tt.wantCode)
			}
		})
	}
}

// testError is a simple error for testing.
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// TestTransport_httpStatusToErrorCode tests HTTP status to error code mapping.
func TestTransport_httpStatusToErrorCode(t *testing.T) {
	cfg := &transport.Config{
		Address:  "https://localhost:8443",
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	restTr := tr.(*Transport)

	tests := []struct {
		status   int
		wantCode errors.ErrorCode
	}{
		{400, errors.CodeInvalidInput},
		{401, errors.CodeUnauthorized},
		{403, errors.CodeForbidden},
		{404, errors.CodeNotFound},
		{409, errors.CodeConflict},
		{429, errors.CodeRateLimited},
		{500, errors.CodeInternal},
		{502, errors.CodeUnavailable},
		{503, errors.CodeUnavailable},
		{504, errors.CodeTimeout},
		{418, errors.CodeInvalidInput}, // Other 4xx
		{599, errors.CodeInternal},     // Other 5xx
		{301, errors.CodeUnknown},      // Other status
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			got := restTr.httpStatusToErrorCode(tt.status)
			if got != tt.wantCode {
				t.Errorf("httpStatusToErrorCode(%d) = %v, want %v", tt.status, got, tt.wantCode)
			}
		})
	}
}

// TestResponse_Structure tests Response structure.
func TestResponse_Structure(t *testing.T) {
	resp := &Response{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"X-Custom": []string{"value"}},
		Body:       []byte(`{"key":"value"}`),
		Data:       map[string]interface{}{"key": "value"},
		Location:   "https://acme.example.com/resource",
		Nonce:      "test-nonce",
		IsPEM:      false,
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %v, want %v", resp.StatusCode, http.StatusOK)
	}

	if resp.Headers.Get("X-Custom") != "value" {
		t.Errorf("Headers[X-Custom] = %v, want value", resp.Headers.Get("X-Custom"))
	}

	if string(resp.Body) != `{"key":"value"}` {
		t.Errorf("Body = %v, want {\"key\":\"value\"}", string(resp.Body))
	}

	if resp.Data["key"] != "value" {
		t.Errorf("Data[key] = %v, want value", resp.Data["key"])
	}

	if resp.Location != "https://acme.example.com/resource" {
		t.Errorf("Location = %v, want https://acme.example.com/resource", resp.Location)
	}

	if resp.Nonce != "test-nonce" {
		t.Errorf("Nonce = %v, want test-nonce", resp.Nonce)
	}

	if resp.IsPEM {
		t.Error("IsPEM = true, want false")
	}
}

// TestACMEError_Structure tests ACMEError structure.
func TestACMEError_Structure(t *testing.T) {
	acmeErr := &ACMEError{
		Type:   "urn:ietf:params:acme:error:badNonce",
		Detail: "JWS has an invalid anti-replay nonce",
		Status: 400,
		Subproblems: []ACMEError{
			{
				Type:   "urn:ietf:params:acme:error:connection",
				Detail: "Connection failed",
			},
		},
		Identifier: &Identifier{
			Type:  "dns",
			Value: "example.com",
		},
	}

	if acmeErr.Type != "urn:ietf:params:acme:error:badNonce" {
		t.Errorf("Type = %v, want urn:ietf:params:acme:error:badNonce", acmeErr.Type)
	}

	if acmeErr.Detail != "JWS has an invalid anti-replay nonce" {
		t.Errorf("Detail = %v, want JWS has an invalid anti-replay nonce", acmeErr.Detail)
	}

	if acmeErr.Status != 400 {
		t.Errorf("Status = %v, want 400", acmeErr.Status)
	}

	if len(acmeErr.Subproblems) != 1 {
		t.Errorf("Subproblems length = %v, want 1", len(acmeErr.Subproblems))
	}

	if acmeErr.Identifier == nil {
		t.Error("Identifier is nil")
	} else {
		if acmeErr.Identifier.Type != "dns" {
			t.Errorf("Identifier.Type = %v, want dns", acmeErr.Identifier.Type)
		}
		if acmeErr.Identifier.Value != "example.com" {
			t.Errorf("Identifier.Value = %v, want example.com", acmeErr.Identifier.Value)
		}
	}
}

// TestTransport_ConnectionError tests connection error handling.
func TestTransport_ConnectionError(t *testing.T) {
	cfg := &transport.Config{
		Address:    "http://127.0.0.1:1", // Port 1 should refuse connection
		Insecure:   true,
		Timeout:    1 * time.Second,
		MaxRetries: 1,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() error = nil, want error")
	}

	// Should be connection or transport error
	code := errors.Code(err)
	if code != errors.CodeConnection && code != errors.CodeTransport {
		t.Errorf("error code = %v, want CONNECTION or TRANSPORT", code)
	}
}

// TestTransport_HealthyAfterFailedRequest tests health status after failed request.
func TestTransport_HealthyAfterFailedRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	// Initially healthy
	if !tr.Healthy() {
		t.Error("Healthy() = false, want true initially")
	}

	// Close the server to cause connection failure
	server.Close()

	// This request should fail and mark transport unhealthy
	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Error("Request() to closed server should fail")
	}

	if tr.Healthy() {
		t.Error("Healthy() = true after failed request, want false")
	}
}

// TestTransport_HealthyAfterSuccessfulRequest tests health recovery after successful request.
func TestTransport_HealthyAfterSuccessfulRequest(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	// Make successful request
	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	if !tr.Healthy() {
		t.Error("Healthy() = false after successful request, want true")
	}
}

// TestTransport_InvalidJSONResponse tests handling of invalid JSON response.
func TestTransport_InvalidJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json{"))
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() with invalid JSON should fail")
	}

	if errors.Code(err) != errors.CodeTransport {
		t.Errorf("error code = %v, want TRANSPORT", errors.Code(err))
	}
}

// TestTransport_EmptyResponse tests handling of empty response body.
func TestTransport_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		// Empty body
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:  server.URL,
		Insecure: true,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	resp, err := tr.Request(context.Background(), "directory", "get", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	result, ok := resp.(*Response)
	if !ok {
		t.Fatal("response is not *Response")
	}

	if result.Data != nil {
		t.Error("Data should be nil for empty response")
	}
}

// TestTransport_RetryBackoffCapped tests that retry backoff is capped.
func TestTransport_RetryBackoffCapped(t *testing.T) {
	attempts := 0
	start := time.Now()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 5 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address:         server.URL,
		Insecure:        true,
		MaxRetries:      10,
		RetryBackoff:    50 * time.Millisecond,
		MaxRetryBackoff: 100 * time.Millisecond,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	elapsed := time.Since(start)

	// With MaxRetryBackoff of 100ms, 4 retries should take < 800ms total
	// (4 waits, each capped at 100ms)
	if elapsed > 1*time.Second {
		t.Errorf("Request took too long (%v), backoff capping may not be working", elapsed)
	}
}

// TestConstants tests that constants are properly defined.
func TestConstants(t *testing.T) {
	if ContentTypeJSON != "application/json" {
		t.Errorf("ContentTypeJSON = %v, want application/json", ContentTypeJSON)
	}
	if ContentTypeProblemJSON != "application/problem+json" {
		t.Errorf("ContentTypeProblemJSON = %v, want application/problem+json", ContentTypeProblemJSON)
	}
	if ContentTypePEM != "application/pem-certificate-chain" {
		t.Errorf("ContentTypePEM = %v, want application/pem-certificate-chain", ContentTypePEM)
	}
	if ContentTypeJOSE != "application/jose+json" {
		t.Errorf("ContentTypeJOSE = %v, want application/jose+json", ContentTypeJOSE)
	}
	if HeaderReplayNonce != "Replay-Nonce" {
		t.Errorf("HeaderReplayNonce = %v, want Replay-Nonce", HeaderReplayNonce)
	}
	if HeaderLocation != "Location" {
		t.Errorf("HeaderLocation = %v, want Location", HeaderLocation)
	}
	if DefaultTimeout != 30*time.Second {
		t.Errorf("DefaultTimeout = %v, want 30s", DefaultTimeout)
	}
}
