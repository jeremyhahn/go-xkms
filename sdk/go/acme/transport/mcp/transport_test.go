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

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// TestNewTransport tests the NewTransport constructor.
func TestNewTransport(t *testing.T) {
	t.Run("success with TCP address", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9445",
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tr == nil {
			t.Fatal("expected transport to be non-nil")
		}
		defer tr.Close()

		if !tr.Healthy() {
			t.Error("expected transport to be healthy after creation")
		}
	})

	t.Run("success with HTTP URL", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "http://localhost:9445",
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer tr.Close()

		mcpTransport := tr.(*Transport)
		if mcpTransport.baseURL != "http://localhost:9445" {
			t.Errorf("expected baseURL http://localhost:9445, got %s", mcpTransport.baseURL)
		}
	})

	t.Run("success with HTTPS URL", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "https://localhost:8443",
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer tr.Close()

		mcpTransport := tr.(*Transport)
		if mcpTransport.baseURL != "https://localhost:8443" {
			t.Errorf("expected baseURL https://localhost:8443, got %s", mcpTransport.baseURL)
		}
	})

	t.Run("success with custom timeout", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9445",
			Timeout: 60 * time.Second,
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer tr.Close()

		mcpTransport := tr.(*Transport)
		if mcpTransport.httpClient.Timeout != 60*time.Second {
			t.Errorf("expected timeout 60s, got %v", mcpTransport.httpClient.Timeout)
		}
	})

	t.Run("success with auth token option", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9445",
		}
		tr, err := NewTransport(cfg, WithAuthToken("test-token"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer tr.Close()

		mcpTransport := tr.(*Transport)
		if mcpTransport.authToken != "test-token" {
			t.Errorf("expected auth token 'test-token', got %s", mcpTransport.authToken)
		}
	})

	t.Run("error with nil config", func(t *testing.T) {
		_, err := NewTransport(nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("error with empty address", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "",
		}
		_, err := NewTransport(cfg)
		if err == nil {
			t.Fatal("expected error for empty address")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})
}

// TestTransport_Request tests the Request method with a mock server.
func TestTransport_Request(t *testing.T) {
	t.Run("success with valid request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.URL.Path != MCPEndpoint {
				t.Errorf("expected path %s, got %s", MCPEndpoint, r.URL.Path)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
			}

			// Parse request
			var req JSONRPCRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("failed to decode request: %v", err)
				return
			}

			if req.JSONRPC != "2.0" {
				t.Errorf("expected jsonrpc 2.0, got %s", req.JSONRPC)
			}
			if req.Method != "acme.directory.get" {
				t.Errorf("expected method acme.directory.get, got %s", req.Method)
			}

			// Send response
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				Result:  json.RawMessage(`{"newNonce":"http://localhost:9445/acme/new-nonce"}`),
				ID:      req.ID,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &transport.Config{
			Address: strings.TrimPrefix(server.URL, "http://"),
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}
		defer tr.Close()

		result, err := tr.Request(context.Background(), "directory", "get", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		rawResult, ok := result.(json.RawMessage)
		if !ok {
			t.Fatalf("expected json.RawMessage, got %T", result)
		}

		var directoryResp map[string]interface{}
		if err := json.Unmarshal(rawResult, &directoryResp); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}

		if directoryResp["newNonce"] != "http://localhost:9445/acme/new-nonce" {
			t.Errorf("unexpected newNonce value: %v", directoryResp["newNonce"])
		}
	})

	t.Run("success with request params", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("failed to decode request: %v", err)
				return
			}

			params, ok := req.Params.(map[string]interface{})
			if !ok {
				t.Errorf("expected params to be map, got %T", req.Params)
				return
			}

			if params["contact"] == nil {
				t.Error("expected contact param to be present")
			}

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				Result:  json.RawMessage(`{"status":"valid"}`),
				ID:      req.ID,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &transport.Config{
			Address: strings.TrimPrefix(server.URL, "http://"),
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}
		defer tr.Close()

		params := map[string]interface{}{
			"contact":              []string{"mailto:test@example.com"},
			"termsOfServiceAgreed": true,
		}

		result, err := tr.Request(context.Background(), "account", "create", params)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result == nil {
			t.Fatal("expected result to be non-nil")
		}
	})

	t.Run("success with auth token", func(t *testing.T) {
		authTokenReceived := ""
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authTokenReceived = r.Header.Get("Authorization")

			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				Result:  json.RawMessage(`{"status":"ok"}`),
				ID:      req.ID,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &transport.Config{
			Address: strings.TrimPrefix(server.URL, "http://"),
		}
		tr, err := NewTransport(cfg, WithAuthToken("secret-token"))
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}
		defer tr.Close()

		_, err = tr.Request(context.Background(), "admin", "getStatus", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if authTokenReceived != "Bearer secret-token" {
			t.Errorf("expected auth header 'Bearer secret-token', got '%s'", authTokenReceived)
		}
	})

	t.Run("error with empty service", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9445",
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}
		defer tr.Close()

		_, err = tr.Request(context.Background(), "", "get", nil)
		if err == nil {
			t.Fatal("expected error for empty service")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("error with empty method", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9445",
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}
		defer tr.Close()

		_, err = tr.Request(context.Background(), "directory", "", nil)
		if err == nil {
			t.Fatal("expected error for empty method")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("error when transport is closed", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9445",
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}

		// Close the transport
		tr.Close()

		_, err = tr.Request(context.Background(), "directory", "get", nil)
		if err == nil {
			t.Fatal("expected error when transport is closed")
		}
		if !errors.IsUnavailable(err) {
			t.Errorf("expected unavailable error, got %v", err)
		}
	})

	t.Run("error with canceled context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate slow server
			time.Sleep(100 * time.Millisecond)
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				Result:  json.RawMessage(`{}`),
				ID:      req.ID,
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &transport.Config{
			Address: strings.TrimPrefix(server.URL, "http://"),
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}
		defer tr.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err = tr.Request(ctx, "directory", "get", nil)
		if err == nil {
			t.Fatal("expected error with canceled context")
		}
	})

	t.Run("error with JSON-RPC error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				Error: &JSONRPCError{
					Code:    ErrorCodeMethodNotFound,
					Message: "method not found",
				},
				ID: req.ID,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &transport.Config{
			Address: strings.TrimPrefix(server.URL, "http://"),
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}
		defer tr.Close()

		_, err = tr.Request(context.Background(), "unknown", "method", nil)
		if err == nil {
			t.Fatal("expected error for JSON-RPC error response")
		}
		if !errors.IsNotFound(err) {
			t.Errorf("expected not found error, got %v", err)
		}
	})

	t.Run("error with mismatched response ID", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			// Send response with wrong ID
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				Result:  json.RawMessage(`{}`),
				ID:      req.ID + 999, // Wrong ID
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &transport.Config{
			Address: strings.TrimPrefix(server.URL, "http://"),
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}
		defer tr.Close()

		_, err = tr.Request(context.Background(), "directory", "get", nil)
		if err == nil {
			t.Fatal("expected error for mismatched response ID")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got %v", err)
		}
	})
}

// TestTransport_HTTPErrors tests HTTP error handling.
func TestTransport_HTTPErrors(t *testing.T) {
	testCases := []struct {
		name         string
		statusCode   int
		expectedCode errors.ErrorCode
	}{
		{"bad request", http.StatusBadRequest, errors.CodeInvalidInput},
		{"unauthorized", http.StatusUnauthorized, errors.CodeUnauthorized},
		{"forbidden", http.StatusForbidden, errors.CodeForbidden},
		{"not found", http.StatusNotFound, errors.CodeNotFound},
		{"conflict", http.StatusConflict, errors.CodeConflict},
		{"rate limited", http.StatusTooManyRequests, errors.CodeRateLimited},
		{"internal error", http.StatusInternalServerError, errors.CodeInternal},
		{"service unavailable", http.StatusServiceUnavailable, errors.CodeUnavailable},
		{"gateway timeout", http.StatusGatewayTimeout, errors.CodeTimeout},
		{"unknown error", http.StatusTeapot, errors.CodeTransport},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte("error body"))
			}))
			defer server.Close()

			cfg := &transport.Config{
				Address: strings.TrimPrefix(server.URL, "http://"),
			}
			tr, err := NewTransport(cfg)
			if err != nil {
				t.Fatalf("failed to create transport: %v", err)
			}
			defer tr.Close()

			_, err = tr.Request(context.Background(), "directory", "get", nil)
			if err == nil {
				t.Fatal("expected error")
			}
			if errors.Code(err) != tc.expectedCode {
				t.Errorf("expected error code %v, got %v", tc.expectedCode, errors.Code(err))
			}
		})
	}
}

// flakyErrorBody is an http.Response.Body double that yields some bytes and
// then fails, so handleHTTPError's read of the error body can be driven into
// its error path deterministically.
type flakyErrorBody struct {
	remaining []byte
	err       error
}

func (f *flakyErrorBody) Read(p []byte) (int, error) {
	if len(f.remaining) == 0 {
		return 0, f.err
	}
	n := copy(p, f.remaining)
	f.remaining = f.remaining[n:]
	return n, nil
}

func (f *flakyErrorBody) Close() error { return nil }

// flakyBodyReadError is returned by flakyErrorBody once its buffered bytes
// are exhausted.
type flakyBodyReadError struct{}

func (flakyBodyReadError) Error() string { return "flaky error body: connection reset" }

// TestHandleHTTPError_BodyReadErrorSurfaces proves that a failure reading the
// HTTP error response body is reported in the resulting error rather than
// silently discarded (go-xkms#1347).
func TestHandleHTTPError_BodyReadErrorSurfaces(t *testing.T) {
	tr := &Transport{}
	resp := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       &flakyErrorBody{remaining: []byte("partial body"), err: flakyBodyReadError{}},
	}

	err := tr.handleHTTPError("mcp.test", resp)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), (flakyBodyReadError{}).Error()) {
		t.Errorf("expected the body read error to be included in %q", err.Error())
	}
	if !strings.Contains(err.Error(), "partial body") {
		t.Errorf("expected the bytes read before the failure to still be included in %q", err.Error())
	}
}

// TestTransport_JSONRPCErrors tests JSON-RPC error handling.
func TestTransport_JSONRPCErrors(t *testing.T) {
	testCases := []struct {
		name         string
		rpcCode      int
		expectedCode errors.ErrorCode
	}{
		{"parse error", ErrorCodeParse, errors.CodeInvalidInput},
		{"invalid request", ErrorCodeInvalidRequest, errors.CodeInvalidInput},
		{"method not found", ErrorCodeMethodNotFound, errors.CodeNotFound},
		{"invalid params", ErrorCodeInvalidParams, errors.CodeInvalidInput},
		{"internal error", ErrorCodeInternal, errors.CodeInternal},
		{"server error range", -32050, errors.CodeInternal},
		{"unknown error", -1, errors.CodeInternal},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req JSONRPCRequest
				json.NewDecoder(r.Body).Decode(&req)

				resp := JSONRPCResponse{
					JSONRPC: "2.0",
					Error: &JSONRPCError{
						Code:    tc.rpcCode,
						Message: "test error",
					},
					ID: req.ID,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			cfg := &transport.Config{
				Address: strings.TrimPrefix(server.URL, "http://"),
			}
			tr, err := NewTransport(cfg)
			if err != nil {
				t.Fatalf("failed to create transport: %v", err)
			}
			defer tr.Close()

			_, err = tr.Request(context.Background(), "directory", "get", nil)
			if err == nil {
				t.Fatal("expected error")
			}
			if errors.Code(err) != tc.expectedCode {
				t.Errorf("expected error code %v, got %v", tc.expectedCode, errors.Code(err))
			}
		})
	}
}

// TestTransport_Conn tests the Conn method.
func TestTransport_Conn(t *testing.T) {
	t.Run("returns http client", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9445",
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}
		defer tr.Close()

		conn := tr.Conn()
		if conn == nil {
			t.Fatal("expected conn to be non-nil")
		}

		_, ok := conn.(*http.Client)
		if !ok {
			t.Errorf("expected *http.Client, got %T", conn)
		}
	})
}

// TestTransport_Close tests the Close method.
func TestTransport_Close(t *testing.T) {
	t.Run("closes transport successfully", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9445",
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}

		if !tr.Healthy() {
			t.Error("expected transport to be healthy before close")
		}

		err = tr.Close()
		if err != nil {
			t.Errorf("unexpected error on close: %v", err)
		}

		if tr.Healthy() {
			t.Error("expected transport to be unhealthy after close")
		}
	})

	t.Run("multiple closes are safe", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9445",
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}

		// Close multiple times
		for i := 0; i < 3; i++ {
			err = tr.Close()
			if err != nil {
				t.Errorf("unexpected error on close %d: %v", i, err)
			}
		}
	})
}

// TestTransport_Healthy tests the Healthy method.
func TestTransport_Healthy(t *testing.T) {
	t.Run("returns true when transport is open", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9445",
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}
		defer tr.Close()

		if !tr.Healthy() {
			t.Error("expected transport to be healthy")
		}
	})

	t.Run("returns false when transport is closed", func(t *testing.T) {
		cfg := &transport.Config{
			Address: "localhost:9445",
		}
		tr, err := NewTransport(cfg)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}

		tr.Close()

		if tr.Healthy() {
			t.Error("expected transport to be unhealthy after close")
		}
	})
}

// TestMapMethodName tests the method name mapping function.
func TestMapMethodName(t *testing.T) {
	testCases := []struct {
		service  string
		method   string
		expected string
	}{
		// Directory methods
		{"directory", "get", "acme.directory.get"},
		{"directory", "unknown", "acme.directory.unknown"},

		// Nonce methods
		{"nonce", "new", "acme.nonce.new"},
		{"nonce", "get", "acme.nonce.get"},

		// Account methods
		{"account", "create", "acme.account.create"},
		{"account", "get", "acme.account.get"},
		{"account", "update", "acme.account.update"},
		{"account", "deactivate", "acme.account.deactivate"},
		{"account", "keyChange", "acme.account.keyChange"},

		// Order methods
		{"order", "create", "acme.order.create"},
		{"order", "get", "acme.order.get"},
		{"order", "list", "acme.order.list"},
		{"order", "finalize", "acme.order.finalize"},

		// Authorization methods
		{"authorization", "get", "acme.authorization.get"},
		{"authorization", "deactivate", "acme.authorization.deactivate"},

		// Challenge methods
		{"challenge", "get", "acme.challenge.get"},
		{"challenge", "submit", "acme.challenge.submit"},

		// Certificate methods
		{"certificate", "get", "acme.certificate.get"},
		{"certificate", "revoke", "acme.certificate.revoke"},
		{"certificate", "list", "acme.certificate.list"},
		{"certificate", "download", "acme.certificate.download"},

		// Admin methods
		{"admin", "createTenant", "admin.createTenant"},
		{"admin", "getTenant", "admin.getTenant"},
		{"admin", "updateTenant", "admin.updateTenant"},
		{"admin", "deleteTenant", "admin.deleteTenant"},
		{"admin", "listTenants", "admin.listTenants"},
		{"admin", "createEAB", "admin.createEAB"},
		{"admin", "getEAB", "admin.getEAB"},
		{"admin", "deleteEAB", "admin.deleteEAB"},
		{"admin", "listEABs", "admin.listEABs"},
		{"admin", "createPolicy", "admin.createPolicy"},
		{"admin", "getPolicy", "admin.getPolicy"},
		{"admin", "updatePolicy", "admin.updatePolicy"},
		{"admin", "deletePolicy", "admin.deletePolicy"},
		{"admin", "listPolicies", "admin.listPolicies"},
		{"admin", "listCertificates", "admin.listCertificates"},
		{"admin", "getCertificate", "admin.getCertificate"},
		{"admin", "revokeCertificate", "admin.revokeCertificate"},
		{"admin", "getStatus", "admin.getStatus"},
		{"admin", "getStats", "admin.getStats"},

		// Unknown service
		{"unknown", "method", "unknown.method"},
		{"custom", "operation", "custom.operation"},
	}

	for _, tc := range testCases {
		t.Run(tc.service+"/"+tc.method, func(t *testing.T) {
			result := mapMethodName(tc.service, tc.method)
			if result != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, result)
			}
		})
	}
}

// TestBuildBaseURL tests the base URL construction function.
func TestBuildBaseURL(t *testing.T) {
	testCases := []struct {
		address  string
		expected string
	}{
		{"localhost:9445", "http://localhost:9445"},
		{"http://localhost:9445", "http://localhost:9445"},
		{"https://localhost:8443", "https://localhost:8443"},
		{"192.168.1.1:9445", "http://192.168.1.1:9445"},
	}

	for _, tc := range testCases {
		t.Run(tc.address, func(t *testing.T) {
			parsed := transport.ParseAddress(tc.address)
			result := buildBaseURL(parsed, false)
			if result != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, result)
			}
		})
	}
}

// TestFactory tests the Factory type.
func TestFactory(t *testing.T) {
	t.Run("creates transport successfully", func(t *testing.T) {
		factory := NewFactory()
		cfg := &transport.Config{
			Address: "localhost:9445",
		}

		tr, err := factory.Create(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer tr.Close()

		if tr == nil {
			t.Fatal("expected transport to be non-nil")
		}
	})

	t.Run("creates transport with options", func(t *testing.T) {
		factory := NewFactory(WithAuthToken("factory-token"))
		cfg := &transport.Config{
			Address: "localhost:9445",
		}

		tr, err := factory.Create(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer tr.Close()

		mcpTransport := tr.(*Transport)
		if mcpTransport.authToken != "factory-token" {
			t.Errorf("expected auth token 'factory-token', got %s", mcpTransport.authToken)
		}
	})

	t.Run("propagates error for invalid config", func(t *testing.T) {
		factory := NewFactory()

		_, err := factory.Create(nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})
}

// TestConcurrentRequests tests thread safety of the transport.
func TestConcurrentRequests(t *testing.T) {
	var requestCount atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			Result:  json.RawMessage(`{"status":"ok"}`),
			ID:      req.ID,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address: strings.TrimPrefix(server.URL, "http://"),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	defer tr.Close()

	const numRequests = 100
	done := make(chan struct{}, numRequests)
	errCh := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, err := tr.Request(context.Background(), "directory", "get", nil)
			if err != nil {
				errCh <- err
			}
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		<-done
	}
	close(errCh)

	// Check for errors
	for err := range errCh {
		t.Errorf("concurrent request error: %v", err)
	}

	if requestCount.Load() != numRequests {
		t.Errorf("expected %d requests, got %d", numRequests, requestCount.Load())
	}
}

// TestUniqueRequestIDs verifies that request IDs are unique across concurrent requests.
func TestUniqueRequestIDs(t *testing.T) {
	requestIDs := make(chan int64, 100)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		requestIDs <- req.ID

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			Result:  json.RawMessage(`{}`),
			ID:      req.ID,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address: strings.TrimPrefix(server.URL, "http://"),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	defer tr.Close()

	const numRequests = 50
	done := make(chan struct{}, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			tr.Request(context.Background(), "directory", "get", nil)
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		<-done
	}
	close(requestIDs)

	// Check for duplicate IDs
	seenIDs := make(map[int64]bool)
	for id := range requestIDs {
		if seenIDs[id] {
			t.Errorf("duplicate request ID: %d", id)
		}
		seenIDs[id] = true
	}

	if len(seenIDs) != numRequests {
		t.Errorf("expected %d unique IDs, got %d", numRequests, len(seenIDs))
	}
}

// TestInvalidJSON tests handling of invalid JSON responses.
func TestInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	cfg := &transport.Config{
		Address: strings.TrimPrefix(server.URL, "http://"),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
	if !errors.IsInternal(err) {
		t.Errorf("expected internal error, got %v", err)
	}
}

// TestConnectionError tests handling of connection errors.
func TestConnectionError(t *testing.T) {
	cfg := &transport.Config{
		Address: "localhost:1", // Likely to fail connection
		Timeout: 100 * time.Millisecond,
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("expected connection error")
	}
	// Connection errors result in either CodeConnection or CodeTimeout
	code := errors.Code(err)
	if code != errors.CodeConnection && code != errors.CodeTimeout {
		t.Errorf("expected connection or timeout error, got %v", err)
	}
}

// TestInterfaceCompliance verifies interface implementation at runtime.
func TestInterfaceCompliance(t *testing.T) {
	cfg := &transport.Config{
		Address: "localhost:9445",
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	defer tr.Close()

	// Verify Transport interface
	_ = tr

	// Verify Factory interface
	_ = NewFactory()
}
