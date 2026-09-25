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

package unix

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// TestNewTransport_Success tests successful transport creation.
func TestNewTransport_Success(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 5 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ut, ok := tr.(*Transport)
	if !ok {
		t.Fatal("expected *Transport type")
	}

	if ut.SocketPath() != socketPath {
		t.Errorf("SocketPath() = %v, want %v", ut.SocketPath(), socketPath)
	}

	if ut.IsAbstract() {
		t.Error("IsAbstract() = true, want false")
	}
}

// TestNewTransport_UnixScheme tests transport creation with unix:// scheme.
func TestNewTransport_UnixScheme(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cfg := &transport.Config{
		Address: "unix://" + socketPath,
		Timeout: 5 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ut, ok := tr.(*Transport)
	if !ok {
		t.Fatal("expected *Transport type")
	}

	if ut.SocketPath() != socketPath {
		t.Errorf("SocketPath() = %v, want %v", ut.SocketPath(), socketPath)
	}
}

// TestNewTransport_AbstractSocket tests transport creation with abstract socket.
func TestNewTransport_AbstractSocket(t *testing.T) {
	t.Parallel()

	cfg := &transport.Config{
		Address: "unix-abstract://test-socket",
		Timeout: 5 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ut, ok := tr.(*Transport)
	if !ok {
		t.Fatal("expected *Transport type")
	}

	// Abstract sockets have null byte prepended
	if !strings.HasPrefix(ut.SocketPath(), "\x00") {
		t.Errorf("SocketPath() should start with null byte for abstract socket")
	}

	if !ut.IsAbstract() {
		t.Error("IsAbstract() = false, want true")
	}
}

// TestNewTransport_NilConfig tests that nil config returns an error.
func TestNewTransport_NilConfig(t *testing.T) {
	t.Parallel()

	_, err := NewTransport(nil)
	if err == nil {
		t.Fatal("NewTransport(nil) should return error")
	}

	if !caerrors.IsInvalidInput(err) {
		t.Errorf("expected InvalidInput error, got %v", err)
	}
}

// TestNewTransport_EmptyAddress tests that empty address returns an error.
func TestNewTransport_EmptyAddress(t *testing.T) {
	t.Parallel()

	cfg := &transport.Config{
		Address: "",
	}

	_, err := NewTransport(cfg)
	if err == nil {
		t.Fatal("NewTransport with empty address should return error")
	}

	if !caerrors.IsInvalidInput(err) {
		t.Errorf("expected InvalidInput error, got %v", err)
	}
}

// TestNewTransport_NonUnixAddress tests that non-Unix address returns an error.
func TestNewTransport_NonUnixAddress(t *testing.T) {
	t.Parallel()

	cfg := &transport.Config{
		Address: "localhost:8080",
	}

	_, err := NewTransport(cfg)
	if err == nil {
		t.Fatal("NewTransport with TCP address should return error")
	}

	if !caerrors.IsInvalidInput(err) {
		t.Errorf("expected InvalidInput error, got %v", err)
	}
}

// TestNewTransport_DefaultTimeout tests that default timeout is applied.
func TestNewTransport_DefaultTimeout(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cfg := &transport.Config{
		Address: socketPath,
		// No timeout specified
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ut := tr.(*Transport)
	if ut.client.Timeout != DefaultTimeout {
		t.Errorf("client.Timeout = %v, want %v", ut.client.Timeout, DefaultTimeout)
	}
}

// TestTransport_Close tests the Close method.
func TestTransport_Close(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cfg := &transport.Config{
		Address: socketPath,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	// Close should succeed
	err = tr.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Healthy should return false after close
	if tr.Healthy() {
		t.Error("Healthy() = true after Close(), want false")
	}

	// Second close should be idempotent
	err = tr.Close()
	if err != nil {
		t.Errorf("Close() second call error = %v", err)
	}
}

// TestTransport_Conn tests the Conn method.
func TestTransport_Conn(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cfg := &transport.Config{
		Address: socketPath,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	conn := tr.Conn()
	if conn == nil {
		t.Error("Conn() returned nil")
	}

	client, ok := conn.(*http.Client)
	if !ok {
		t.Error("Conn() did not return *http.Client")
	}

	if client == nil {
		t.Error("Conn() returned nil client")
	}
}

// TestTransport_Request_ClosedTransport tests Request on closed transport.
func TestTransport_Request_ClosedTransport(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cfg := &transport.Config{
		Address: socketPath,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	// Close the transport
	tr.Close()

	// Request should fail
	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("Request on closed transport should return error")
	}

	if !caerrors.IsUnavailable(err) {
		t.Errorf("expected Unavailable error, got %v", err)
	}
}

// TestTransport_Request_EmptyService tests Request with empty service.
func TestTransport_Request_EmptyService(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cfg := &transport.Config{
		Address: socketPath,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "", "get", nil)
	if err == nil {
		t.Fatal("Request with empty service should return error")
	}

	if !caerrors.IsInvalidInput(err) {
		t.Errorf("expected InvalidInput error, got %v", err)
	}
}

// TestTransport_Request_EmptyMethod tests Request with empty method.
func TestTransport_Request_EmptyMethod(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cfg := &transport.Config{
		Address: socketPath,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "", nil)
	if err == nil {
		t.Fatal("Request with empty method should return error")
	}

	if !caerrors.IsInvalidInput(err) {
		t.Errorf("expected InvalidInput error, got %v", err)
	}
}

// TestTransport_Request_UnknownEndpoint tests Request with unknown service/method.
func TestTransport_Request_UnknownEndpoint(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cfg := &transport.Config{
		Address: socketPath,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "unknown", "endpoint", nil)
	if err == nil {
		t.Fatal("Request with unknown endpoint should return error")
	}

	if !caerrors.IsNotFound(err) {
		t.Errorf("expected NotFound error, got %v", err)
	}
}

// TestFactory_Create tests the Factory.Create method.
func TestFactory_Create(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	factory := NewFactory()

	cfg := &transport.Config{
		Address: socketPath,
	}

	tr, err := factory.Create(cfg)
	if err != nil {
		t.Fatalf("Factory.Create() error = %v", err)
	}
	defer tr.Close()

	if tr == nil {
		t.Error("Factory.Create() returned nil transport")
	}
}

// TestFactory_Create_NilConfig tests Factory.Create with nil config.
func TestFactory_Create_NilConfig(t *testing.T) {
	t.Parallel()

	factory := NewFactory()

	_, err := factory.Create(nil)
	if err == nil {
		t.Fatal("Factory.Create(nil) should return error")
	}
}

// TestEndpointRegistry tests that all expected endpoints are registered.
func TestEndpointRegistry(t *testing.T) {
	t.Parallel()

	expectedEndpoints := []struct {
		service string
		method  string
	}{
		{"directory", "get"},
		{"nonce", "new"},
		{"nonce", "head"},
		{"nonce", "get"},
		{"account", "create"},
		{"account", "new"},
		{"account", "get"},
		{"account", "update"},
		{"account", "lookup"},
		{"order", "create"},
		{"order", "new"},
		{"order", "get"},
		{"order", "list"},
		{"authorization", "get"},
		{"challenge", "get"},
		{"challenge", "respond"},
		{"challenge", "complete"},
		{"finalize", "order"},
		{"finalize", "submit"},
		{"certificate", "get"},
		{"certificate", "revoke"},
		{"certificate", "download"},
		{"keychange", "change"},
		{"keychange", "rollover"},
		{"health", "check"},
		{"health", "ready"},
		{"health", "live"},
		{"health", "liveness"},
		{"health", "readiness"},
	}

	for _, ep := range expectedEndpoints {
		key := endpointKey(ep.service, ep.method)
		if _, ok := endpointRegistry[key]; !ok {
			t.Errorf("endpoint %s/%s not found in registry", ep.service, ep.method)
		}
	}
}

// TestResponse_JSON tests the Response.JSON method.
func TestResponse_JSON(t *testing.T) {
	t.Parallel()

	response := &Response{
		StatusCode: 200,
		Body:       []byte(`{"key":"value"}`),
	}

	var result map[string]string
	err := response.JSON(&result)
	if err != nil {
		t.Fatalf("Response.JSON() error = %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("Response.JSON() result = %v, want key=value", result)
	}
}

// TestResponse_JSON_InvalidJSON tests Response.JSON with invalid JSON.
func TestResponse_JSON_InvalidJSON(t *testing.T) {
	t.Parallel()

	response := &Response{
		StatusCode: 200,
		Body:       []byte(`invalid json`),
	}

	var result map[string]string
	err := response.JSON(&result)
	if err == nil {
		t.Fatal("Response.JSON() with invalid JSON should return error")
	}
}

// TestResponse_String tests the Response.String method.
func TestResponse_String(t *testing.T) {
	t.Parallel()

	response := &Response{
		StatusCode: 200,
		Body:       []byte("test body"),
	}

	if response.String() != "test body" {
		t.Errorf("Response.String() = %v, want 'test body'", response.String())
	}
}

// TestResponse_IsSuccess tests the Response.IsSuccess method.
func TestResponse_IsSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{"200 OK", 200, true},
		{"201 Created", 201, true},
		{"204 No Content", 204, true},
		{"299 edge case", 299, true},
		{"300 redirect", 300, false},
		{"400 Bad Request", 400, false},
		{"404 Not Found", 404, false},
		{"500 Internal Server Error", 500, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := &Response{StatusCode: tt.statusCode}
			if got := response.IsSuccess(); got != tt.want {
				t.Errorf("Response.IsSuccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHttpStatusToErrorCode tests the httpStatusToErrorCode function.
func TestHttpStatusToErrorCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		statusCode int
		want       caerrors.ErrorCode
	}{
		{http.StatusBadRequest, caerrors.CodeInvalidInput},
		{http.StatusUnauthorized, caerrors.CodeUnauthorized},
		{http.StatusForbidden, caerrors.CodeForbidden},
		{http.StatusNotFound, caerrors.CodeNotFound},
		{http.StatusMethodNotAllowed, caerrors.CodeInvalidInput},
		{http.StatusConflict, caerrors.CodeConflict},
		{http.StatusGone, caerrors.CodeNotFound},
		{http.StatusPreconditionFailed, caerrors.CodePreconditionFailed},
		{http.StatusTooManyRequests, caerrors.CodeRateLimited},
		{http.StatusInternalServerError, caerrors.CodeInternal},
		{http.StatusNotImplemented, caerrors.CodeUnimplemented},
		{http.StatusBadGateway, caerrors.CodeUnavailable},
		{http.StatusServiceUnavailable, caerrors.CodeUnavailable},
		{http.StatusGatewayTimeout, caerrors.CodeTimeout},
		// Unknown 4xx should map to InvalidInput
		{418, caerrors.CodeInvalidInput},
		// Unknown 5xx should map to Internal
		{599, caerrors.CodeInternal},
		// Success codes should map to Unknown
		{200, caerrors.CodeUnknown},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.statusCode), func(t *testing.T) {
			got := httpStatusToErrorCode(tt.statusCode)
			if got != tt.want {
				t.Errorf("httpStatusToErrorCode(%d) = %v, want %v", tt.statusCode, got, tt.want)
			}
		})
	}
}

// TestToString tests the toString function.
func TestToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input interface{}
		want  string
	}{
		{"string", "hello", "hello"},
		{"bytes", []byte("world"), "world"},
		{"int", 123, "123"},
		{"bool", true, "true"},
		{"nil", nil, "null"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toString(tt.input)
			if got != tt.want {
				t.Errorf("toString(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestEndpointKey tests the endpointKey function.
func TestEndpointKey(t *testing.T) {
	t.Parallel()

	key := endpointKey("service", "method")
	if key != "service/method" {
		t.Errorf("endpointKey() = %v, want 'service/method'", key)
	}
}

// setupTestServer creates a test HTTP server on a Unix socket.
func setupTestServer(t *testing.T, socketPath string, handler http.Handler) (*http.Server, func()) {
	t.Helper()

	// Remove socket file if it exists
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create Unix socket listener: %v", err)
	}

	server := &http.Server{Handler: handler}

	go func() {
		if err := server.Serve(listener); err != http.ErrServerClosed {
			t.Logf("server error: %v", err)
		}
	}()

	cleanup := func() {
		server.Close()
		listener.Close()
		os.Remove(socketPath)
	}

	// No readiness wait needed: the listener is already bound above, so a
	// caller dialing immediately queues in the kernel accept backlog even
	// before Serve's accept loop has started running.
	return server, cleanup
}

// TestTransport_Request_Success tests successful request/response cycle.
func TestTransport_Request_Success(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/directory" && r.Method == http.MethodGet {
			w.Header().Set("Replay-Nonce", "test-nonce")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   "/acme/new-nonce",
				"newAccount": "/acme/new-acct",
				"newOrder":   "/acme/new-order",
			})
			return
		}
		http.NotFound(w, r)
	})

	_, cleanup := setupTestServer(t, socketPath, handler)
	defer cleanup()

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 5 * time.Second,
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

	response, ok := resp.(*Response)
	if !ok {
		t.Fatal("expected *Response type")
	}

	if response.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", response.StatusCode, http.StatusOK)
	}

	if response.Nonce != "test-nonce" {
		t.Errorf("Nonce = %v, want 'test-nonce'", response.Nonce)
	}

	var directory map[string]string
	if err := response.JSON(&directory); err != nil {
		t.Fatalf("JSON() error = %v", err)
	}

	if directory["newAccount"] != "/acme/new-acct" {
		t.Errorf("directory[newAccount] = %v, want '/acme/new-acct'", directory["newAccount"])
	}
}

// TestTransport_Request_WithBody tests request with body.
func TestTransport_Request_WithBody(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	var receivedBody map[string]interface{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acme/new-acct" && r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Location", "/acme/acct/123")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})
			return
		}
		http.NotFound(w, r)
	})

	_, cleanup := setupTestServer(t, socketPath, handler)
	defer cleanup()

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 5 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	reqBody := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:test@example.com"},
	}

	resp, err := tr.Request(context.Background(), "account", "create", reqBody)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	response, ok := resp.(*Response)
	if !ok {
		t.Fatal("expected *Response type")
	}

	if response.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %d, want %d", response.StatusCode, http.StatusCreated)
	}

	if response.Location != "/acme/acct/123" {
		t.Errorf("Location = %v, want '/acme/acct/123'", response.Location)
	}

	if receivedBody["termsOfServiceAgreed"] != true {
		t.Errorf("receivedBody[termsOfServiceAgreed] = %v, want true", receivedBody["termsOfServiceAgreed"])
	}
}

// TestTransport_Request_WithPathParameter tests request with path parameter.
func TestTransport_Request_WithPathParameter(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acme/acct/test-id-123" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "valid",
			})
			return
		}
		http.NotFound(w, r)
	})

	_, cleanup := setupTestServer(t, socketPath, handler)
	defer cleanup()

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 5 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	reqBody := map[string]interface{}{
		"id": "test-id-123",
	}

	resp, err := tr.Request(context.Background(), "account", "get", reqBody)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	response, ok := resp.(*Response)
	if !ok {
		t.Fatal("expected *Response type")
	}

	if response.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", response.StatusCode, http.StatusOK)
	}
}

// TestTransport_Request_ErrorResponse tests handling of error responses.
func TestTransport_Request_ErrorResponse(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "urn:ietf:params:acme:error:unauthorized",
			"detail": "Account key not authorized",
			"status": 401,
		})
	})

	_, cleanup := setupTestServer(t, socketPath, handler)
	defer cleanup()

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 5 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() should return error for 401 response")
	}

	// Check that we get an ACME unauthorized error
	caErr, ok := err.(*caerrors.CAError)
	if !ok {
		t.Fatalf("expected *CAError, got %T", err)
	}

	if caErr.Code != caerrors.CodeACMEUnauthorized {
		t.Errorf("error code = %v, want %v", caErr.Code, caerrors.CodeACMEUnauthorized)
	}
}

// TestTransport_Request_NonACMEError tests handling of non-ACME error responses.
func TestTransport_Request_NonACMEError(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
	})

	_, cleanup := setupTestServer(t, socketPath, handler)
	defer cleanup()

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 5 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() should return error for 500 response")
	}

	if !caerrors.IsInternal(err) {
		t.Errorf("expected Internal error, got %v", err)
	}
}

// TestTransport_Request_ContextCanceled tests handling of canceled context.
func TestTransport_Request_ContextCanceled(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	// Handler that delays response
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(http.StatusOK)
	})

	_, cleanup := setupTestServer(t, socketPath, handler)
	defer cleanup()

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 5 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = tr.Request(ctx, "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() should return error for canceled context")
	}

	if !caerrors.IsCanceled(err) {
		t.Errorf("expected Canceled error, got %v", err)
	}
}

// TestTransport_Request_ContextTimeout tests handling of context timeout.
func TestTransport_Request_ContextTimeout(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	// Handler that delays response longer than timeout
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(http.StatusOK)
	})

	_, cleanup := setupTestServer(t, socketPath, handler)
	defer cleanup()

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 5 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err = tr.Request(ctx, "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() should return error for timeout")
	}

	if !caerrors.IsTimeout(err) {
		t.Errorf("expected Timeout error, got %v", err)
	}
}

// TestTransport_Request_ConnectionError tests handling of connection errors.
func TestTransport_Request_ConnectionError(t *testing.T) {
	t.Parallel()

	// Use a socket path that doesn't exist
	socketPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 100 * time.Millisecond,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	_, err = tr.Request(context.Background(), "directory", "get", nil)
	if err == nil {
		t.Fatal("Request() should return error for connection failure")
	}

	// Should be a connection error
	caErr, ok := err.(*caerrors.CAError)
	if !ok {
		t.Fatalf("expected *CAError, got %T", err)
	}

	if caErr.Code != caerrors.CodeConnection {
		t.Errorf("error code = %v, want %v", caErr.Code, caerrors.CodeConnection)
	}
}

// TestTransport_Healthy tests the Healthy method with a working server.
func TestTransport_Healthy(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	_, cleanup := setupTestServer(t, socketPath, handler)
	defer cleanup()

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 5 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	// Make a successful request to update health status
	_, _ = tr.Request(context.Background(), "directory", "get", nil)

	if !tr.Healthy() {
		t.Error("Healthy() = false after successful request, want true")
	}
}

// TestTransport_Request_HeadMethod tests HEAD requests (for nonce).
func TestTransport_Request_HeadMethod(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acme/new-nonce" && r.Method == http.MethodHead {
			w.Header().Set("Replay-Nonce", "new-nonce-value")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	})

	_, cleanup := setupTestServer(t, socketPath, handler)
	defer cleanup()

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 5 * time.Second,
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

	response, ok := resp.(*Response)
	if !ok {
		t.Fatal("expected *Response type")
	}

	if response.Nonce != "new-nonce-value" {
		t.Errorf("Nonce = %v, want 'new-nonce-value'", response.Nonce)
	}
}

// TestNewTransport_WithTLSConfig tests transport creation with TLS config.
func TestNewTransport_WithTLSConfig(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cfg := &transport.Config{
		Address:   socketPath,
		Timeout:   5 * time.Second,
		TLSConfig: nil, // TLS config would be set here for TLS over Unix socket
		Insecure:  false,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	ut, ok := tr.(*Transport)
	if !ok {
		t.Fatal("expected *Transport type")
	}

	// Verify HTTP transport was created correctly
	if ut.httpTransport == nil {
		t.Error("httpTransport is nil")
	}
}

// TestNewTransport_WithKeepalive tests transport creation with keepalive settings.
func TestNewTransport_WithKeepalive(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cfg := &transport.Config{
		Address:          socketPath,
		Timeout:          5 * time.Second,
		KeepaliveTime:    60 * time.Second,
		KeepaliveTimeout: 20 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	// Transport should be created successfully with custom keepalive
	if tr == nil {
		t.Error("NewTransport() returned nil")
	}
}

// TestTransport_Request_AllEndpoints tests all registered endpoints are accessible.
func TestTransport_Request_AllEndpoints(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	// Handler that responds to all paths
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path})
	})

	_, cleanup := setupTestServer(t, socketPath, handler)
	defer cleanup()

	cfg := &transport.Config{
		Address: socketPath,
		Timeout: 5 * time.Second,
	}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	// Test a sample of different endpoint types
	testCases := []struct {
		service string
		method  string
	}{
		{"directory", "get"},
		{"nonce", "get"},
		{"account", "create"},
		{"order", "create"},
		{"health", "check"},
	}

	for _, tc := range testCases {
		t.Run(tc.service+"/"+tc.method, func(t *testing.T) {
			_, err := tr.Request(context.Background(), tc.service, tc.method, nil)
			if err != nil {
				t.Errorf("Request(%s, %s) error = %v", tc.service, tc.method, err)
			}
		})
	}
}
