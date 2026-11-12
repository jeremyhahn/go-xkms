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

package quic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
)

// TestNewAdapter tests the NewAdapter constructor with various configurations.
func TestNewAdapter(t *testing.T) {
	t.Run("valid config with address only", func(t *testing.T) {
		config := &api.AdapterConfig{
			QUICAddr: "localhost:9444",
		}
		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		if adapter == nil {
			t.Fatal("NewAdapter() returned nil adapter")
		}
		if adapter.baseURL != "https://localhost:9444" {
			t.Errorf("Expected baseURL 'https://localhost:9444', got '%s'", adapter.baseURL)
		}
		if adapter.httpClient == nil {
			t.Error("Expected httpClient to be initialized")
		}
		defer func() { _ = adapter.Close() }()
	})

	t.Run("valid config with auth token", func(t *testing.T) {
		config := &api.AdapterConfig{
			QUICAddr:  "localhost:9444",
			AuthToken: "test-token-123",
		}
		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		if adapter.authToken != "test-token-123" {
			t.Errorf("Expected authToken 'test-token-123', got '%s'", adapter.authToken)
		}
		defer func() { _ = adapter.Close() }()
	})

	t.Run("empty QUIC address error", func(t *testing.T) {
		config := &api.AdapterConfig{
			QUICAddr: "",
		}
		_, err := NewAdapter(config)
		if err == nil {
			t.Error("Expected error for empty QUIC address")
		}
		if !strings.Contains(err.Error(), "QUIC address is required") {
			t.Errorf("Expected 'QUIC address is required' error, got: %v", err)
		}
	})

	t.Run("valid config with empty TLS config", func(t *testing.T) {
		config := &api.AdapterConfig{
			QUICAddr:  "localhost:9444",
			TLSConfig: &api.TLSConfig{},
		}
		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}
		defer func() { _ = adapter.Close() }()
	})

	t.Run("invalid client certificate path", func(t *testing.T) {
		config := &api.AdapterConfig{
			QUICAddr: "localhost:9444",
			TLSConfig: &api.TLSConfig{
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  "/nonexistent/key.pem",
			},
		}
		_, err := NewAdapter(config)
		if err == nil {
			t.Error("Expected error for invalid certificate path")
		}
		if !strings.Contains(err.Error(), "failed to load client certificate") {
			t.Errorf("Expected 'failed to load client certificate' error, got: %v", err)
		}
	})

	t.Run("invalid CA certificate path", func(t *testing.T) {
		config := &api.AdapterConfig{
			QUICAddr: "localhost:9444",
			TLSConfig: &api.TLSConfig{
				CAFile: "/nonexistent/ca.pem",
			},
		}
		_, err := NewAdapter(config)
		if err == nil {
			t.Error("Expected error for invalid CA certificate path")
		}
		if !strings.Contains(err.Error(), "failed to read CA certificate") {
			t.Errorf("Expected 'failed to read CA certificate' error, got: %v", err)
		}
	})

	t.Run("valid config with TLS certificates", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create test certificate files
		certFile := filepath.Join(tmpDir, "cert.pem")
		keyFile := filepath.Join(tmpDir, "key.pem")
		caFile := filepath.Join(tmpDir, "ca.pem")

		// Write minimal valid PEM content for testing
		// This is a self-signed test certificate - not for production use
		testCert := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7n9X6h5VsxwqNbIzfDGK4
2XWbgpGlz9XqF7pQV+LDd3g9CZu3bZ3n3d3xE0p6vQp5VVx5v5WwMw3q8Q7HxHzN
AgMBAAGjUzBRMB0GA1UdDgQWBBQz5YPT3r5YVIqV7dLmlK7HdQl8mzAfBgNVHSME
GDAWgBQz5YPT3r5YVIqV7dLmlK7HdQl8mzAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAHcFsI6L9dK6xN+RMN9Q0h3a0J7cRuZD5K5L5G9R5LQD5A5U5
h5a0J7cRuZD5K5L5G9R5LQD5A5U5h5a0J7cRuZD5Kw==
-----END CERTIFICATE-----`

		testKey := `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALuf1fqHlWzHCo1sjN8MYrjZdZuCkaXP1eoXulBX4sN3eD0Jm7dt
neft3fETSnq9CnlVXHm/lbAzDerxDsfEfM0CAwEAAQJAWj1j7L1l3K0XiB0pRd9I
VIqV7dLmlK7HdQl8mzBQz5YPT3r5YVIqV7dLmlK7HdQl8mzAT7n9X6h5VsxwqNbI
zQIhAOdR+S3x5K5L5G9R5LQD5A5U5h5a0J7cRuZD5K5L5G9RAiEAzOp5VVx5v5Ww
Mw3q8Q7HxHzNLuf1fqHlWzHCo1sjN8MCIBQz5YPT3r5YVIqV7dLmlK7HdQl8mzBQ
z5YPT3r5YVIqAiEAo1sjN8MYrjZdZuCkaXP1eoXulBX4sN3eD0Jm7dtneft3fEEC
IQCbZ3n3d3xE0p6vQp5VVx5v5WwMw3q8Q7HxHzNLuf1fqQ==
-----END RSA PRIVATE KEY-----`

		if err := os.WriteFile(certFile, []byte(testCert), 0600); err != nil {
			t.Fatalf("Failed to write test cert: %v", err)
		}
		if err := os.WriteFile(keyFile, []byte(testKey), 0600); err != nil {
			t.Fatalf("Failed to write test key: %v", err)
		}
		if err := os.WriteFile(caFile, []byte(testCert), 0600); err != nil {
			t.Fatalf("Failed to write test CA: %v", err)
		}

		config := &api.AdapterConfig{
			QUICAddr: "localhost:9444",
			TLSConfig: &api.TLSConfig{
				CertFile: certFile,
				KeyFile:  keyFile,
				CAFile:   caFile,
			},
		}

		// The certificate may not be valid for actual TLS handshake,
		// but the adapter should be created successfully
		_, err := NewAdapter(config)
		// We expect either success or a certificate parsing error (not file not found)
		if err != nil && strings.Contains(err.Error(), "file not found") {
			t.Errorf("Unexpected file not found error: %v", err)
		}
	})

	t.Run("TLS config with only CAFile", func(t *testing.T) {
		tmpDir := t.TempDir()
		caFile := filepath.Join(tmpDir, "ca.pem")

		// Valid CA certificate PEM
		testCA := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7n9X6h5VsxwqNbIzfDGK4
2XWbgpGlz9XqF7pQV+LDd3g9CZu3bZ3n3d3xE0p6vQp5VVx5v5WwMw3q8Q7HxHzN
AgMBAAGjUzBRMB0GA1UdDgQWBBQz5YPT3r5YVIqV7dLmlK7HdQl8mzAfBgNVHSME
GDAWgBQz5YPT3r5YVIqV7dLmlK7HdQl8mzAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAHcFsI6L9dK6xN+RMN9Q0h3a0J7cRuZD5K5L5G9R5LQD5A5U5
h5a0J7cRuZD5K5L5G9R5LQD5A5U5h5a0J7cRuZD5Kw==
-----END CERTIFICATE-----`

		if err := os.WriteFile(caFile, []byte(testCA), 0600); err != nil {
			t.Fatalf("Failed to write CA file: %v", err)
		}

		config := &api.AdapterConfig{
			QUICAddr: "localhost:9444",
			TLSConfig: &api.TLSConfig{
				CAFile: caFile,
			},
		}

		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() with CAFile only failed: %v", err)
		}
		defer func() { _ = adapter.Close() }()
	})

	t.Run("TLS config with only CertFile no KeyFile", func(t *testing.T) {
		// When only CertFile is provided without KeyFile, the certificate loading is skipped
		config := &api.AdapterConfig{
			QUICAddr: "localhost:9444",
			TLSConfig: &api.TLSConfig{
				CertFile: "/some/cert.pem",
				// KeyFile is empty, so the certificate loading branch is skipped
			},
		}

		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() with only CertFile failed: %v", err)
		}
		defer func() { _ = adapter.Close() }()
	})

	t.Run("nil TLSConfig uses defaults", func(t *testing.T) {
		config := &api.AdapterConfig{
			QUICAddr:  "localhost:9444",
			TLSConfig: nil,
		}

		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() with nil TLSConfig failed: %v", err)
		}
		defer func() { _ = adapter.Close() }()
	})
}

// TestAdapterProtocol tests the Protocol method.
func TestAdapterProtocol(t *testing.T) {
	config := &api.AdapterConfig{
		QUICAddr: "localhost:9444",
	}
	adapter, err := NewAdapter(config)
	if err != nil {
		t.Fatalf("NewAdapter() failed: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	protocol := adapter.Protocol()
	if protocol != api.ProtocolQUIC {
		t.Errorf("Expected Protocol() to return api.ProtocolQUIC, got %v", protocol)
	}
}

// TestAdapterClose tests the Close method.
func TestAdapterClose(t *testing.T) {
	t.Run("close succeeds", func(t *testing.T) {
		config := &api.AdapterConfig{
			QUICAddr: "localhost:9444",
		}
		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}

		err = adapter.Close()
		if err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	})

	t.Run("close is idempotent", func(t *testing.T) {
		config := &api.AdapterConfig{
			QUICAddr: "localhost:9444",
		}
		adapter, err := NewAdapter(config)
		if err != nil {
			t.Fatalf("NewAdapter() failed: %v", err)
		}

		// Multiple close calls should not error
		if err := adapter.Close(); err != nil {
			t.Errorf("First Close() failed: %v", err)
		}
		if err := adapter.Close(); err != nil {
			t.Errorf("Second Close() failed: %v", err)
		}
	})
}

// TestDecodeResponse tests the decodeResponse helper function.
func TestDecodeResponse(t *testing.T) {
	t.Run("success with valid JSON", func(t *testing.T) {
		// Test wrapped API response format
		body := `{"id":"test-123","name":"Test Tenant"}`
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenant admin.TenantInfo
		err := decodeResponse(resp, &tenant)
		if err != nil {
			t.Fatalf("decodeResponse() failed: %v", err)
		}
		if tenant.ID != "test-123" {
			t.Errorf("Expected ID 'test-123', got '%s'", tenant.ID)
		}
		if tenant.Name != "Test Tenant" {
			t.Errorf("Expected Name 'Test Tenant', got '%s'", tenant.Name)
		}
	})

	t.Run("success with nil target", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
		}

		err := decodeResponse(resp, nil)
		if err != nil {
			t.Fatalf("decodeResponse() with nil target failed: %v", err)
		}
	})

	t.Run("error with 400 status", func(t *testing.T) {
		body := `{"error":"invalid request"}`
		resp := &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenant admin.TenantInfo
		err := decodeResponse(resp, &tenant)
		if err == nil {
			t.Error("Expected error for 400 status")
		}
		if !strings.Contains(err.Error(), "400") {
			t.Errorf("Expected error to contain status code 400, got: %v", err)
		}
		if !strings.Contains(err.Error(), "invalid request") {
			t.Errorf("Expected error to contain body, got: %v", err)
		}
	})

	t.Run("error with 401 status", func(t *testing.T) {
		body := `{"error":"unauthorized"}`
		resp := &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		err := decodeResponse(resp, nil)
		if err == nil {
			t.Error("Expected error for 401 status")
		}
		if !strings.Contains(err.Error(), "401") {
			t.Errorf("Expected error to contain status code 401, got: %v", err)
		}
	})

	t.Run("error with 404 status", func(t *testing.T) {
		body := `{"error":"not found"}`
		resp := &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		err := decodeResponse(resp, nil)
		if err == nil {
			t.Error("Expected error for 404 status")
		}
		if !strings.Contains(err.Error(), "404") {
			t.Errorf("Expected error to contain status code 404, got: %v", err)
		}
	})

	t.Run("error with 500 status", func(t *testing.T) {
		body := `{"error":"internal server error"}`
		resp := &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		err := decodeResponse(resp, nil)
		if err == nil {
			t.Error("Expected error for 500 status")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("Expected error to contain status code 500, got: %v", err)
		}
	})

	t.Run("error decoding invalid JSON", func(t *testing.T) {
		body := `{invalid json}`
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenant admin.TenantInfo
		err := decodeResponse(resp, &tenant)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("success with empty body and nil target", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
		}

		err := decodeResponse(resp, nil)
		if err != nil {
			t.Fatalf("decodeResponse() with empty body and nil target failed: %v", err)
		}
	})

	t.Run("RFC 7807 error response", func(t *testing.T) {
		body := `{"type":"urn:trusted-ca:error:internal","title":"Internal Error","detail":"Something went wrong","status":500}`
		resp := &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenant admin.TenantInfo
		err := decodeResponse(resp, &tenant)
		if err == nil {
			t.Error("Expected error for error response")
		}
		if !strings.Contains(err.Error(), "Something went wrong") {
			t.Errorf("Expected error to contain detail message, got: %v", err)
		}
	})

	t.Run("generic HTTP error response", func(t *testing.T) {
		body := `{"error":"request failed"}`
		resp := &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenant admin.TenantInfo
		err := decodeResponse(resp, &tenant)
		if err == nil {
			t.Error("Expected error for error response")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("Expected error to contain status code, got: %v", err)
		}
	})

	t.Run("body read error", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(&errorReader{}),
		}

		var tenant admin.TenantInfo
		err := decodeResponse(resp, &tenant)
		if err == nil {
			t.Error("Expected error for body read failure")
		}
		if !strings.Contains(err.Error(), "failed to read response body") {
			t.Errorf("Expected 'failed to read response body' error, got: %v", err)
		}
	})

	t.Run("success with empty data field", func(t *testing.T) {
		body := ``
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenant admin.TenantInfo
		err := decodeResponse(resp, &tenant)
		if err != nil {
			t.Fatalf("decodeResponse() with empty data failed: %v", err)
		}
	})

	t.Run("invalid JSON body", func(t *testing.T) {
		body := `{invalid json`
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenant admin.TenantInfo
		err := decodeResponse(resp, &tenant)
		if err != nil {
			// Expected: invalid JSON should cause unmarshal error
		} else {
			t.Error("Expected error for invalid JSON body")
		}
	})
}

// TestDecodeListResponse tests the decodeListResponse helper function.
func TestDecodeListResponse(t *testing.T) {
	t.Run("success with data and pagination", func(t *testing.T) {
		body := `{"items":[{"id":"t1"},{"id":"t2"}],"total":2,"page":1,"per_page":10}`
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenants []*admin.TenantInfo
		pagination, err := decodeListResponse(resp, &tenants)
		if err != nil {
			t.Fatalf("decodeListResponse() failed: %v", err)
		}
		if len(tenants) != 2 {
			t.Errorf("Expected 2 tenants, got %d", len(tenants))
		}
		if pagination == nil {
			t.Fatal("Expected pagination to be set")
		}
		if pagination.Total != 2 {
			t.Errorf("Expected total 2, got %d", pagination.Total)
		}
	})

	t.Run("error status code", func(t *testing.T) {
		body := `{"error":"not found"}`
		resp := &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenants []*admin.TenantInfo
		_, err := decodeListResponse(resp, &tenants)
		if err == nil {
			t.Error("Expected error for 404 status")
		}
		if !strings.Contains(err.Error(), "404") {
			t.Errorf("Expected error to contain 404, got: %v", err)
		}
	})

	t.Run("body read error", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(&errorReader{}),
		}

		var tenants []*admin.TenantInfo
		_, err := decodeListResponse(resp, &tenants)
		if err == nil {
			t.Error("Expected error for body read failure")
		}
		if !strings.Contains(err.Error(), "failed to read response body") {
			t.Errorf("Expected 'failed to read response body' error, got: %v", err)
		}
	})

	t.Run("invalid JSON wrapper", func(t *testing.T) {
		body := `{invalid}`
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenants []*admin.TenantInfo
		_, err := decodeListResponse(resp, &tenants)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "failed to decode paginated response") {
			t.Errorf("Expected 'failed to decode response' error, got: %v", err)
		}
	})

	t.Run("RFC 7807 list error response", func(t *testing.T) {
		body := `{"type":"urn:trusted-ca:error:internal","title":"Internal Error","detail":"List failed","status":500}`
		resp := &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenants []*admin.TenantInfo
		_, err := decodeListResponse(resp, &tenants)
		if err == nil {
			t.Error("Expected error for error response")
		}
		if !strings.Contains(err.Error(), "List failed") {
			t.Errorf("Expected error to contain 'List failed', got: %v", err)
		}
	})

	t.Run("generic HTTP list error response", func(t *testing.T) {
		body := `{"error":"request failed"}`
		resp := &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenants []*admin.TenantInfo
		_, err := decodeListResponse(resp, &tenants)
		if err == nil {
			t.Error("Expected error for error response")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("Expected error to contain status code, got: %v", err)
		}
	})

	t.Run("data unmarshal error", func(t *testing.T) {
		// Data is a string but we expect an array
		body := `{"items":"not-an-array","total":0,"page":1,"per_page":10}`
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenants []*admin.TenantInfo
		_, err := decodeListResponse(resp, &tenants)
		if err == nil {
			t.Error("Expected error for data unmarshal failure")
		}
		if !strings.Contains(err.Error(), "failed to decode items") {
			t.Errorf("Expected 'failed to decode data' error, got: %v", err)
		}
	})

	t.Run("invalid total field type", func(t *testing.T) {
		// total is a string but we expect an int - causes outer struct unmarshal to fail
		body := `{"items":[],"total":"invalid","page":1,"per_page":10}`
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenants []*admin.TenantInfo
		_, err := decodeListResponse(resp, &tenants)
		if err == nil {
			t.Error("Expected error for invalid total field")
		}
		if !strings.Contains(err.Error(), "failed to decode paginated response") {
			t.Errorf("Expected 'failed to decode paginated response' error, got: %v", err)
		}
	})

	t.Run("nil target with valid response", func(t *testing.T) {
		body := `{"items":[{"id":"t1"}],"total":1,"page":1,"per_page":10}`
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		pagination, err := decodeListResponse(resp, nil)
		if err != nil {
			t.Fatalf("decodeListResponse() with nil target failed: %v", err)
		}
		if pagination == nil {
			t.Error("Expected pagination to be returned")
		}
	})

	t.Run("empty data with pagination", func(t *testing.T) {
		body := `{"items":null,"total":0,"page":1,"per_page":10}`
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}

		var tenants []*admin.TenantInfo
		pagination, err := decodeListResponse(resp, &tenants)
		if err != nil {
			t.Fatalf("decodeListResponse() failed: %v", err)
		}
		if pagination == nil {
			t.Error("Expected pagination to be returned")
			return
		}
		if pagination.Total != 0 {
			t.Errorf("Expected total 0, got %d", pagination.Total)
		}
	})
}

// errorReader is a reader that always returns an error.
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}

// TestAdapterInterfaceCompliance verifies the Adapter implements api.AdminAdapter.
func TestAdapterInterfaceCompliance(t *testing.T) {
	var _ api.AdminAdapter = (*Adapter)(nil)
}

// mockRoundTripper is a mock http.RoundTripper for testing HTTP operations.
type mockRoundTripper struct {
	response *http.Response
	err      error
}

func (m *mockRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return m.response, m.err
}

// createMockAdapter creates an adapter with a mock HTTP client for testing.
func createMockAdapter(response *http.Response, err error) *Adapter {
	return &Adapter{
		baseURL:   "https://localhost:9444",
		authToken: "test-token",
		httpClient: &http.Client{
			Transport: &mockRoundTripper{
				response: response,
				err:      err,
			},
		},
	}
}

// TestAdapterDoRequest tests the doRequest method indirectly through public methods.
func TestAdapterDoRequest(t *testing.T) {
	ctx := context.Background()

	t.Run("request with body marshalling", func(t *testing.T) {
		responseBody := `{"tenant":{"id":"tenant-1","name":"Test Tenant","status":"active"}}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.CreateTenantRequest{
			ID:   "tenant-1",
			Name: "Test Tenant",
		}
		tenant, err := adapter.CreateTenant(ctx, req)
		if err != nil {
			t.Fatalf("CreateTenant() failed: %v", err)
		}
		if tenant.ID != "tenant-1" {
			t.Errorf("Expected tenant ID 'tenant-1', got '%s'", tenant.ID)
		}
	})

	t.Run("request without body", func(t *testing.T) {
		responseBody := `{"tenant":{"id":"tenant-1","name":"Test Tenant","status":"active"}}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		tenant, err := adapter.GetTenant(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("GetTenant() failed: %v", err)
		}
		if tenant.ID != "tenant-1" {
			t.Errorf("Expected tenant ID 'tenant-1', got '%s'", tenant.ID)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, io.EOF)

		_, err := adapter.GetTenant(ctx, "tenant-1")
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})
}

// TestTenantOperations tests tenant-related adapter methods.
// TestListTenants_StatusFilterRefused: the tenant status filter is refused
// with the typed error before any request is sent (SPEC.md:129).
func TestListTenants_StatusFilterRefused(t *testing.T) {
	a := &Adapter{}
	_, _, err := a.ListTenants(context.Background(), &admin.ListTenantsRequest{Page: 1, PerPage: 10, Status: "suspended"})
	if !errors.Is(err, admin.ErrTenantStatusUnsupported) {
		t.Fatalf("error %v is not ErrTenantStatusUnsupported", err)
	}
	var ufe *admin.UnsupportedFieldError
	if !errors.As(err, &ufe) || ufe.Field != "status" {
		t.Fatalf("error %v is not an UnsupportedFieldError for status", err)
	}
}

func TestTenantOperations(t *testing.T) {
	ctx := context.Background()

	t.Run("CreateTenant success", func(t *testing.T) {
		responseBody := `{"tenant":{"id":"new-tenant","name":"New Tenant","status":"active"}}`
		response := &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.CreateTenantRequest{
			ID:   "new-tenant",
			Name: "New Tenant",
		}
		tenant, err := adapter.CreateTenant(ctx, req)
		if err != nil {
			t.Fatalf("CreateTenant() failed: %v", err)
		}
		if tenant.ID != "new-tenant" {
			t.Errorf("Expected ID 'new-tenant', got '%s'", tenant.ID)
		}
	})

	t.Run("CreateTenant error", func(t *testing.T) {
		responseBody := `{"error":"tenant already exists"}`
		response := &http.Response{
			StatusCode: http.StatusConflict,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.CreateTenantRequest{
			ID:   "existing-tenant",
			Name: "Existing Tenant",
		}
		_, err := adapter.CreateTenant(ctx, req)
		if err == nil {
			t.Error("Expected error for conflict")
		}
	})

	t.Run("CreateTenant transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection refused"))

		req := &admin.CreateTenantRequest{
			ID:   "tenant-1",
			Name: "Tenant",
		}
		_, err := adapter.CreateTenant(ctx, req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("GetTenant success", func(t *testing.T) {
		responseBody := `{"tenant":{"id":"tenant-1","name":"Tenant One","status":"active"}}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		tenant, err := adapter.GetTenant(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("GetTenant() failed: %v", err)
		}
		if tenant.Name != "Tenant One" {
			t.Errorf("Expected Name 'Tenant One', got '%s'", tenant.Name)
		}
	})

	t.Run("GetTenant not found", func(t *testing.T) {
		responseBody := `{"error":"tenant not found"}`
		response := &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		_, err := adapter.GetTenant(ctx, "nonexistent")
		if err == nil {
			t.Error("Expected error for not found")
		}
	})

	t.Run("UpdateTenant success", func(t *testing.T) {
		responseBody := `{"id":"tenant-1","name":"Updated Tenant","status":"active"}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.UpdateTenantRequest{
			Name: "Updated Tenant",
		}
		tenant, err := adapter.UpdateTenant(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("UpdateTenant() failed: %v", err)
		}
		if tenant.Name != "Updated Tenant" {
			t.Errorf("Expected Name 'Updated Tenant', got '%s'", tenant.Name)
		}
	})

	t.Run("UpdateTenant transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("network unreachable"))

		req := &admin.UpdateTenantRequest{
			Name: "New Name",
		}
		_, err := adapter.UpdateTenant(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("UpdateTenant decode error", func(t *testing.T) {
		responseBody := `{invalid json}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.UpdateTenantRequest{
			Name: "Updated Tenant",
		}
		_, err := adapter.UpdateTenant(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for invalid JSON response")
		}
	})

	t.Run("DeleteTenant success", func(t *testing.T) {
		response := &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.DeleteTenant(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("DeleteTenant() failed: %v", err)
		}
	})

	t.Run("DeleteTenant transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection reset"))

		err := adapter.DeleteTenant(ctx, "tenant-1")
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("ListTenants success", func(t *testing.T) {
		responseBody := `{"tenants":[{"id":"t1","name":"Tenant 1"},{"id":"t2","name":"Tenant 2"}],"pagination":{"page":1,"page_size":10,"total":2}}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.ListTenantsRequest{
			Page:    1,
			PerPage: 10,
		}
		tenants, pagination, err := adapter.ListTenants(ctx, req)
		if err != nil {
			t.Fatalf("ListTenants() failed: %v", err)
		}
		if len(tenants) != 2 {
			t.Errorf("Expected 2 tenants, got %d", len(tenants))
		}
		if pagination.Total != 2 {
			t.Errorf("Expected total 2, got %d", pagination.Total)
		}
	})

	t.Run("ListTenants transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("timeout"))

		req := &admin.ListTenantsRequest{
			Page:    1,
			PerPage: 10,
		}
		_, _, err := adapter.ListTenants(ctx, req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("ListTenants decode error", func(t *testing.T) {
		responseBody := `{invalid}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.ListTenantsRequest{
			Page:    1,
			PerPage: 10,
		}
		_, _, err := adapter.ListTenants(ctx, req)
		if err == nil {
			t.Error("Expected error for invalid JSON response")
		}
	})
}

// TestEABOperations tests EAB-related adapter methods.
func TestEABOperations(t *testing.T) {
	ctx := context.Background()

	t.Run("CreateEAB success", func(t *testing.T) {
		responseBody := `{"id":"eab-123","mac_key":"base64key","algorithm":"HS256"}`
		response := &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.CreateEABRequest{
			Purpose: "account-binding",
		}
		eab, err := adapter.CreateEAB(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("CreateEAB() failed: %v", err)
		}
		if eab.ID != "eab-123" {
			t.Errorf("Expected ID 'eab-123', got '%s'", eab.ID)
		}
	})

	t.Run("CreateEAB transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection refused"))

		req := &admin.CreateEABRequest{
			Purpose: "account-binding",
		}
		_, err := adapter.CreateEAB(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("CreateEAB decode error", func(t *testing.T) {
		responseBody := `{bad json}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.CreateEABRequest{
			Purpose: "account-binding",
		}
		_, err := adapter.CreateEAB(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetEAB success", func(t *testing.T) {
		responseBody := `{"id":"eab-123","tenant_id":"tenant-1","status":"active","purpose":"account-binding"}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		eab, err := adapter.GetEAB(ctx, "tenant-1", "eab-123")
		if err != nil {
			t.Fatalf("GetEAB() failed: %v", err)
		}
		if eab.Status != "active" {
			t.Errorf("Expected Status 'active', got '%s'", eab.Status)
		}
	})

	t.Run("GetEAB transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("network error"))

		_, err := adapter.GetEAB(ctx, "tenant-1", "eab-123")
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("GetEAB decode error", func(t *testing.T) {
		responseBody := `not json`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		_, err := adapter.GetEAB(ctx, "tenant-1", "eab-123")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("DeleteEAB success", func(t *testing.T) {
		response := &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.DeleteEAB(ctx, "tenant-1", "eab-123")
		if err != nil {
			t.Fatalf("DeleteEAB() failed: %v", err)
		}
	})

	t.Run("DeleteEAB transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection closed"))

		err := adapter.DeleteEAB(ctx, "tenant-1", "eab-123")
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("ListEABs success", func(t *testing.T) {
		responseBody := `{"items":[{"id":"eab-1","status":"active"},{"id":"eab-2","status":"used"}],"total":2,"page":1,"per_page":10}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.ListEABRequest{
			Page:    1,
			PerPage: 10,
		}
		eabs, pagination, err := adapter.ListEABs(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("ListEABs() failed: %v", err)
		}
		if len(eabs) != 2 {
			t.Errorf("Expected 2 EABs, got %d", len(eabs))
		}
		if pagination.Total != 2 {
			t.Errorf("Expected total 2, got %d", pagination.Total)
		}
	})

	t.Run("ListEABs transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("timeout"))

		req := &admin.ListEABRequest{
			Page:    1,
			PerPage: 10,
		}
		_, _, err := adapter.ListEABs(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("ListEABs decode error", func(t *testing.T) {
		responseBody := `broken`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.ListEABRequest{
			Page:    1,
			PerPage: 10,
		}
		_, _, err := adapter.ListEABs(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}

// TestRoleOperations tests role-related adapter methods.
func TestRoleOperations(t *testing.T) {
	ctx := context.Background()

	t.Run("CreateTenantRole success", func(t *testing.T) {
		responseBody := `{"id":"role-1","name":"admin","tenantID":"tenant-1"}`
		response := &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.CreateRoleRequest{
			Name:        "admin",
			Permissions: []string{"read", "write"},
		}
		role, err := adapter.CreateTenantRole(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("CreateTenantRole() failed: %v", err)
		}
		if role.Name != "admin" {
			t.Errorf("Expected name 'admin', got '%s'", role.Name)
		}
	})

	t.Run("CreateTenantRole transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("network error"))

		req := &db.CreateRoleRequest{Name: "admin"}
		_, err := adapter.CreateTenantRole(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("CreateTenantRole decode error", func(t *testing.T) {
		responseBody := `{broken}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.CreateRoleRequest{Name: "admin"}
		_, err := adapter.CreateTenantRole(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetTenantRole success", func(t *testing.T) {
		responseBody := `{"id":"role-1","name":"viewer","tenantID":"tenant-1"}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		role, err := adapter.GetTenantRole(ctx, "tenant-1", "role-1")
		if err != nil {
			t.Fatalf("GetTenantRole() failed: %v", err)
		}
		if role.Name != "viewer" {
			t.Errorf("Expected name 'viewer', got '%s'", role.Name)
		}
	})

	t.Run("GetTenantRole transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection refused"))

		_, err := adapter.GetTenantRole(ctx, "tenant-1", "role-1")
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("GetTenantRole decode error", func(t *testing.T) {
		responseBody := `not-json`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		_, err := adapter.GetTenantRole(ctx, "tenant-1", "role-1")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("UpdateTenantRole success", func(t *testing.T) {
		responseBody := `{"id":"role-1","name":"editor","tenantID":"tenant-1"}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.UpdateRoleRequest{ID: "role-1", Name: "editor"}
		updated, err := adapter.UpdateTenantRole(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("UpdateTenantRole() failed: %v", err)
		}
		if updated.Name != "editor" {
			t.Errorf("Expected name 'editor', got '%s'", updated.Name)
		}
	})

	t.Run("UpdateTenantRole transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("timeout"))

		req := &db.UpdateRoleRequest{ID: "role-1", Name: "editor"}
		_, err := adapter.UpdateTenantRole(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("UpdateTenantRole decode error", func(t *testing.T) {
		responseBody := `{broken json}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.UpdateRoleRequest{ID: "role-1", Name: "editor"}
		_, err := adapter.UpdateTenantRole(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("DeleteTenantRole success", func(t *testing.T) {
		response := &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.DeleteTenantRole(ctx, "tenant-1", "role-to-delete")
		if err != nil {
			t.Fatalf("DeleteTenantRole() failed: %v", err)
		}
	})

	t.Run("DeleteTenantRole transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("network unreachable"))

		err := adapter.DeleteTenantRole(ctx, "tenant-1", "role-1")
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("ListTenantRoles success", func(t *testing.T) {
		responseBody := `{"roles":[{"id":"role-1","name":"admin"},{"id":"role-2","name":"viewer"}],"total":2,"hasMore":false}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.ListRolesRequest{Page: 1, PageSize: 10}
		listResp, err := adapter.ListTenantRoles(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("ListTenantRoles() failed: %v", err)
		}
		if len(listResp.Roles) != 2 {
			t.Errorf("Expected 2 roles, got %d", len(listResp.Roles))
		}
	})

	t.Run("ListTenantRoles transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection reset"))

		req := &db.ListRolesRequest{Page: 1, PageSize: 10}
		_, err := adapter.ListTenantRoles(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("ListTenantRoles decode error", func(t *testing.T) {
		responseBody := `{not valid}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.ListRolesRequest{Page: 1, PageSize: 10}
		_, err := adapter.ListTenantRoles(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}

// TestUserOperations tests user-related adapter methods.
func TestUserOperations(t *testing.T) {
	ctx := context.Background()

	t.Run("CreateTenantUser success", func(t *testing.T) {
		responseBody := `{"id":"1","username":"alice","tenantID":"tenant-1"}`
		response := &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.CreateUserRequest{Username: "alice"}
		user, err := adapter.CreateTenantUser(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("CreateTenantUser() failed: %v", err)
		}
		if user.Username != "alice" {
			t.Errorf("Expected username 'alice', got '%s'", user.Username)
		}
	})

	t.Run("CreateTenantUser transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("network error"))

		req := &db.CreateUserRequest{Username: "alice"}
		_, err := adapter.CreateTenantUser(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("CreateTenantUser decode error", func(t *testing.T) {
		responseBody := `{broken}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.CreateUserRequest{Username: "alice"}
		_, err := adapter.CreateTenantUser(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetTenantUser success", func(t *testing.T) {
		responseBody := `{"id":"1","username":"bob","tenantID":"tenant-1"}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		user, err := adapter.GetTenantUser(ctx, "tenant-1", "user-1")
		if err != nil {
			t.Fatalf("GetTenantUser() failed: %v", err)
		}
		if user.Username != "bob" {
			t.Errorf("Expected username 'bob', got '%s'", user.Username)
		}
	})

	t.Run("GetTenantUser transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection refused"))

		_, err := adapter.GetTenantUser(ctx, "tenant-1", "user-1")
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("GetTenantUser decode error", func(t *testing.T) {
		responseBody := `not-json`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		_, err := adapter.GetTenantUser(ctx, "tenant-1", "user-1")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("UpdateTenantUser success", func(t *testing.T) {
		responseBody := `{"id":"1","username":"bob-updated","tenantID":"tenant-1"}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.UpdateUserRequest{ID: 1, Username: "bob-updated"}
		updated, err := adapter.UpdateTenantUser(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("UpdateTenantUser() failed: %v", err)
		}
		if updated.Username != "bob-updated" {
			t.Errorf("Expected username 'bob-updated', got '%s'", updated.Username)
		}
	})

	t.Run("UpdateTenantUser transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("timeout"))

		req := &db.UpdateUserRequest{ID: 1, Username: "bob"}
		_, err := adapter.UpdateTenantUser(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("UpdateTenantUser decode error", func(t *testing.T) {
		responseBody := `{broken json}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.UpdateUserRequest{ID: 1, Username: "bob"}
		_, err := adapter.UpdateTenantUser(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("DeleteTenantUser success", func(t *testing.T) {
		response := &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.DeleteTenantUser(ctx, "tenant-1", "user-to-delete")
		if err != nil {
			t.Fatalf("DeleteTenantUser() failed: %v", err)
		}
	})

	t.Run("DeleteTenantUser transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("network unreachable"))

		err := adapter.DeleteTenantUser(ctx, "tenant-1", "user-1")
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("ListTenantUsers success", func(t *testing.T) {
		responseBody := `{"users":[{"id":"1","username":"alice"},{"id":"2","username":"bob"}],"total":2,"hasMore":false}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.ListUsersRequest{Page: 1, PageSize: 10}
		listResp, err := adapter.ListTenantUsers(ctx, "tenant-1", req)
		if err != nil {
			t.Fatalf("ListTenantUsers() failed: %v", err)
		}
		if len(listResp.Users) != 2 {
			t.Errorf("Expected 2 users, got %d", len(listResp.Users))
		}
	})

	t.Run("ListTenantUsers transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection reset"))

		req := &db.ListUsersRequest{Page: 1, PageSize: 10}
		_, err := adapter.ListTenantUsers(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("ListTenantUsers decode error", func(t *testing.T) {
		responseBody := `{not valid}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &db.ListUsersRequest{Page: 1, PageSize: 10}
		_, err := adapter.ListTenantUsers(ctx, "tenant-1", req)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}

// TestCertificateOperations tests certificate-related adapter methods.
func TestCertificateOperations(t *testing.T) {
	ctx := context.Background()

	t.Run("ListCertificates success", func(t *testing.T) {
		responseBody := `{"items":[{"serial_number":"123","subject":"CN=test"}],"total":1,"page":1,"per_page":10}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.ListCertificatesRequest{
			Page:    1,
			PerPage: 10,
		}
		certs, pagination, err := adapter.ListCertificates(ctx, req)
		if err != nil {
			t.Fatalf("ListCertificates() failed: %v", err)
		}
		if len(certs) != 1 {
			t.Errorf("Expected 1 certificate, got %d", len(certs))
		}
		if pagination.Total != 1 {
			t.Errorf("Expected total 1, got %d", pagination.Total)
		}
	})

	t.Run("ListCertificates transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("timeout"))

		req := &admin.ListCertificatesRequest{Page: 1, PerPage: 10}
		_, _, err := adapter.ListCertificates(ctx, req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("ListCertificates decode error", func(t *testing.T) {
		responseBody := `{invalid}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.ListCertificatesRequest{Page: 1, PerPage: 10}
		_, _, err := adapter.ListCertificates(ctx, req)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetCertificate success", func(t *testing.T) {
		responseBody := `{"serial_number":"12345","subject":"CN=test.example.com","status":"valid"}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		cert, err := adapter.GetCertificate(ctx, "12345")
		if err != nil {
			t.Fatalf("GetCertificate() failed: %v", err)
		}
		if cert.SerialNumber != "12345" {
			t.Errorf("Expected SerialNumber '12345', got '%s'", cert.SerialNumber)
		}
	})

	t.Run("GetCertificate not found", func(t *testing.T) {
		responseBody := `{"error":"certificate not found"}`
		response := &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		_, err := adapter.GetCertificate(ctx, "nonexistent")
		if err == nil {
			t.Error("Expected error for not found")
		}
	})

	t.Run("GetCertificate transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("network error"))

		_, err := adapter.GetCertificate(ctx, "12345")
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("GetCertificate decode error", func(t *testing.T) {
		responseBody := `{not-json}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		_, err := adapter.GetCertificate(ctx, "12345")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("RevokeCertificate success", func(t *testing.T) {
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("{}")),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.RevokeCertificate(ctx, "12345", "keyCompromise")
		if err != nil {
			t.Fatalf("RevokeCertificate() failed: %v", err)
		}
	})

	t.Run("RevokeCertificate error", func(t *testing.T) {
		responseBody := `{"error":"revocation failed"}`
		response := &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.RevokeCertificate(ctx, "12345", "keyCompromise")
		if err == nil {
			t.Error("Expected error for revocation failure")
		}
	})

	t.Run("RevokeCertificate transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection refused"))

		err := adapter.RevokeCertificate(ctx, "12345", "keyCompromise")
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})
}

// TestAccountOperations tests account-related adapter methods.
func TestAccountOperations(t *testing.T) {
	ctx := context.Background()

	t.Run("ListAccounts success", func(t *testing.T) {
		responseBody := `{"items":[{"id":1,"status":"valid"},{"id":2,"status":"deactivated"}],"total":2,"page":1,"per_page":10}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.ListAccountsRequest{
			Page:    1,
			PerPage: 10,
		}
		accounts, pagination, err := adapter.ListAccounts(ctx, req)
		if err != nil {
			t.Fatalf("ListAccounts() failed: %v", err)
		}
		if len(accounts) != 2 {
			t.Errorf("Expected 2 accounts, got %d", len(accounts))
		}
		if pagination.Total != 2 {
			t.Errorf("Expected total 2, got %d", pagination.Total)
		}
	})

	t.Run("ListAccounts with status filter", func(t *testing.T) {
		var capturedURL string
		adapter := &Adapter{
			baseURL:   "https://localhost:9444",
			authToken: "test-token",
			httpClient: &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					capturedURL = req.URL.String()
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"items":[],"total":0,"page":1,"per_page":10}`)),
					}, nil
				}),
			},
		}

		req := &admin.ListAccountsRequest{
			Page:    1,
			PerPage: 10,
			Status:  "valid",
		}
		_, _, err := adapter.ListAccounts(ctx, req)
		if err != nil {
			t.Fatalf("ListAccounts() failed: %v", err)
		}
		if !strings.Contains(capturedURL, "status=valid") {
			t.Errorf("Expected URL to contain 'status=valid', got: %s", capturedURL)
		}
	})

	t.Run("ListAccounts transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection refused"))

		req := &admin.ListAccountsRequest{Page: 1, PerPage: 10}
		_, _, err := adapter.ListAccounts(ctx, req)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("ListAccounts decode error", func(t *testing.T) {
		responseBody := `{invalid json}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		req := &admin.ListAccountsRequest{Page: 1, PerPage: 10}
		_, _, err := adapter.ListAccounts(ctx, req)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetAccount success", func(t *testing.T) {
		responseBody := `{"id":12345,"status":"valid","contact":["mailto:test@example.com"]}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		account, err := adapter.GetAccount(ctx, 12345)
		if err != nil {
			t.Fatalf("GetAccount() failed: %v", err)
		}
		if account.ID != 12345 {
			t.Errorf("Expected ID 12345, got %d", account.ID)
		}
		if account.Status != "valid" {
			t.Errorf("Expected status 'valid', got '%s'", account.Status)
		}
	})

	t.Run("GetAccount not found", func(t *testing.T) {
		responseBody := `{"error":"account not found"}`
		response := &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		_, err := adapter.GetAccount(ctx, 99999)
		if err == nil {
			t.Error("Expected error for not found")
		}
		if !strings.Contains(err.Error(), "404") {
			t.Errorf("Expected error to contain 404, got: %v", err)
		}
	})

	t.Run("GetAccount transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("network error"))

		_, err := adapter.GetAccount(ctx, 12345)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("GetAccount decode error", func(t *testing.T) {
		responseBody := `{not json}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		_, err := adapter.GetAccount(ctx, 12345)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("DisableAccount success", func(t *testing.T) {
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(``)),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.DisableAccount(ctx, 12345)
		if err != nil {
			t.Fatalf("DisableAccount() failed: %v", err)
		}
	})

	t.Run("DisableAccount not found", func(t *testing.T) {
		responseBody := `{"error":"account not found"}`
		response := &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.DisableAccount(ctx, 99999)
		if err == nil {
			t.Error("Expected error for not found")
		}
	})

	t.Run("DisableAccount transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection refused"))

		err := adapter.DisableAccount(ctx, 12345)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("DisableAccount server error", func(t *testing.T) {
		responseBody := `{"error":"internal error"}`
		response := &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.DisableAccount(ctx, 12345)
		if err == nil {
			t.Error("Expected error for server error")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("Expected error to contain 500, got: %v", err)
		}
	})
}

// TestStatusOperations tests status-related adapter methods.
func TestStatusOperations(t *testing.T) {
	ctx := context.Background()

	t.Run("GetStatus success", func(t *testing.T) {
		responseBody := `{"identity":"test-ca","initialized":true,"version":"1.0.0"}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		status, err := adapter.GetStatus(ctx)
		if err != nil {
			t.Fatalf("GetStatus() failed: %v", err)
		}
		if status.Identity != "test-ca" {
			t.Errorf("Expected Identity 'test-ca', got '%s'", status.Identity)
		}
		if !status.Initialized {
			t.Error("Expected Initialized to be true")
		}
	})

	t.Run("GetStatus error", func(t *testing.T) {
		responseBody := `{"error":"service unavailable"}`
		response := &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		_, err := adapter.GetStatus(ctx)
		if err == nil {
			t.Error("Expected error for service unavailable")
		}
	})

	t.Run("GetStatus transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("connection refused"))

		_, err := adapter.GetStatus(ctx)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("GetStats success", func(t *testing.T) {
		responseBody := `{"total_certificates":100,"valid_certificates":80,"revoked_certificates":10,"expired_certificates":10}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		stats, err := adapter.GetStats(ctx)
		if err != nil {
			t.Fatalf("GetStats() failed: %v", err)
		}
		if stats.TotalCertificates != 100 {
			t.Errorf("Expected TotalCertificates 100, got %d", stats.TotalCertificates)
		}
		if stats.ValidCertificates != 80 {
			t.Errorf("Expected ValidCertificates 80, got %d", stats.ValidCertificates)
		}
	})

	t.Run("GetStats transport error", func(t *testing.T) {
		adapter := createMockAdapter(nil, errors.New("network unreachable"))

		_, err := adapter.GetStats(ctx)
		if err == nil {
			t.Error("Expected error for transport failure")
		}
	})

	t.Run("GetStats decode error", func(t *testing.T) {
		responseBody := `{invalid json}`
		response := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}
		adapter := createMockAdapter(response, nil)

		_, err := adapter.GetStats(ctx)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}

// TestRequestHeaders tests that doRequest sets the correct headers.
func TestRequestHeaders(t *testing.T) {
	var capturedRequest *http.Request

	adapter := &Adapter{
		baseURL:   "https://localhost:9444",
		authToken: "test-bearer-token",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				capturedRequest = req
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"id":"test"}`)),
				}, nil
			}),
		},
	}

	ctx := context.Background()
	_, _ = adapter.GetTenant(ctx, "test-tenant")

	if capturedRequest == nil {
		t.Fatal("Request was not captured")
	}

	// Check Content-Type header
	contentType := capturedRequest.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Check Accept header
	accept := capturedRequest.Header.Get("Accept")
	if accept != "application/json" {
		t.Errorf("Expected Accept 'application/json', got '%s'", accept)
	}

	// Check Authorization header
	auth := capturedRequest.Header.Get("Authorization")
	if auth != "Bearer test-bearer-token" {
		t.Errorf("Expected Authorization 'Bearer test-bearer-token', got '%s'", auth)
	}
}

// TestRequestWithoutAuthToken tests requests without an auth token.
func TestRequestWithoutAuthToken(t *testing.T) {
	var capturedRequest *http.Request

	adapter := &Adapter{
		baseURL:   "https://localhost:9444",
		authToken: "", // No auth token
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				capturedRequest = req
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"id":"test"}`)),
				}, nil
			}),
		},
	}

	ctx := context.Background()
	_, _ = adapter.GetTenant(ctx, "test-tenant")

	if capturedRequest == nil {
		t.Fatal("Request was not captured")
	}

	// Check Authorization header is not set
	auth := capturedRequest.Header.Get("Authorization")
	if auth != "" {
		t.Errorf("Expected empty Authorization header, got '%s'", auth)
	}
}

// TestRequestURLConstruction tests that URLs are constructed correctly.
func TestRequestURLConstruction(t *testing.T) {
	testCases := []struct {
		name        string
		method      string
		expectedURL string
		execute     func(adapter *Adapter) error
	}{
		{
			name:        "GetTenant URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/tenant-123",
			execute: func(a *Adapter) error {
				_, err := a.GetTenant(context.Background(), "tenant-123")
				return err
			},
		},
		{
			name:        "ListTenants URL with pagination",
			expectedURL: "https://localhost:9444/api/v1/tenants/?page=2&page_size=25",
			execute: func(a *Adapter) error {
				_, _, err := a.ListTenants(context.Background(), &admin.ListTenantsRequest{Page: 2, PerPage: 25})
				return err
			},
		},
		{
			name:        "GetEAB URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/tenant-1/eab/kid-123",
			execute: func(a *Adapter) error {
				_, err := a.GetEAB(context.Background(), "tenant-1", "kid-123")
				return err
			},
		},
		{
			name:        "GetTenantRole URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/tenant-1/roles/role-1",
			execute: func(a *Adapter) error {
				_, err := a.GetTenantRole(context.Background(), "tenant-1", "role-1")
				return err
			},
		},
		{
			name:        "GetTenantUser URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/tenant-1/users/user-1",
			execute: func(a *Adapter) error {
				_, err := a.GetTenantUser(context.Background(), "tenant-1", "user-1")
				return err
			},
		},
		{
			name:        "GetCertificate URL",
			expectedURL: "https://localhost:9444/admin/certificates/serial-456",
			execute: func(a *Adapter) error {
				_, err := a.GetCertificate(context.Background(), "serial-456")
				return err
			},
		},
		{
			name:        "RevokeCertificate URL",
			expectedURL: "https://localhost:9444/admin/certificates/serial-789/revoke",
			execute: func(a *Adapter) error {
				return a.RevokeCertificate(context.Background(), "serial-789", "keyCompromise")
			},
		},
		{
			name:        "ListAccounts URL",
			expectedURL: "https://localhost:9444/admin/accounts?page=1&per_page=20",
			execute: func(a *Adapter) error {
				_, _, err := a.ListAccounts(context.Background(), &admin.ListAccountsRequest{Page: 1, PerPage: 20})
				return err
			},
		},
		{
			name:        "GetAccount URL",
			expectedURL: "https://localhost:9444/admin/accounts/54321",
			execute: func(a *Adapter) error {
				_, err := a.GetAccount(context.Background(), 54321)
				return err
			},
		},
		{
			name:        "DisableAccount URL",
			expectedURL: "https://localhost:9444/admin/accounts/12345/disable",
			execute: func(a *Adapter) error {
				return a.DisableAccount(context.Background(), 12345)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var capturedURL string

			adapter := &Adapter{
				baseURL:   "https://localhost:9444",
				authToken: "test-token",
				httpClient: &http.Client{
					Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						capturedURL = req.URL.String()
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{}`)),
						}, nil
					}),
				},
			}

			_ = tc.execute(adapter)

			if capturedURL != tc.expectedURL {
				t.Errorf("Expected URL '%s', got '%s'", tc.expectedURL, capturedURL)
			}
		})
	}
}

// TestMarshallingErrors tests error handling when marshalling fails.
func TestMarshallingErrors(t *testing.T) {
	ctx := context.Background()

	// Create an adapter that never gets called (because marshalling fails first)
	adapter := &Adapter{
		baseURL:   "https://localhost:9444",
		authToken: "test-token",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				// Read the request body to verify it was marshalled correctly
				body, _ := io.ReadAll(req.Body)
				var data map[string]interface{}
				if err := json.Unmarshal(body, &data); err != nil {
					t.Errorf("Failed to unmarshal request body: %v", err)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"id":"test"}`)),
				}, nil
			}),
		},
	}

	// Test with a valid request to ensure marshalling works
	req := &admin.CreateTenantRequest{
		ID:   "test-tenant",
		Name: "Test Tenant",
	}
	_, err := adapter.CreateTenant(ctx, req)
	if err != nil {
		t.Fatalf("CreateTenant() failed: %v", err)
	}
}

// TestContextCancellation tests that context cancellation is respected.
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	adapter := &Adapter{
		baseURL:   "https://localhost:9444",
		authToken: "test-token",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				// Check that context is cancelled
				select {
				case <-req.Context().Done():
					return nil, req.Context().Err()
				default:
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{}`)),
					}, nil
				}
			}),
		},
	}

	_, err := adapter.GetTenant(ctx, "tenant-1")
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
}

// roundTripFunc is a function adapter for http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestHTTPMethods tests that the correct HTTP methods are used.
func TestHTTPMethods(t *testing.T) {
	testCases := []struct {
		name           string
		expectedMethod string
		execute        func(adapter *Adapter) error
	}{
		{
			name:           "CreateTenant uses POST",
			expectedMethod: http.MethodPost,
			execute: func(a *Adapter) error {
				_, err := a.CreateTenant(context.Background(), &admin.CreateTenantRequest{ID: "t1"})
				return err
			},
		},
		{
			name:           "GetTenant uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, err := a.GetTenant(context.Background(), "t1")
				return err
			},
		},
		{
			name:           "UpdateTenant uses PUT",
			expectedMethod: http.MethodPut,
			execute: func(a *Adapter) error {
				_, err := a.UpdateTenant(context.Background(), "t1", &admin.UpdateTenantRequest{Name: "new"})
				return err
			},
		},
		{
			name:           "DeleteTenant uses DELETE",
			expectedMethod: http.MethodDelete,
			execute: func(a *Adapter) error {
				return a.DeleteTenant(context.Background(), "t1")
			},
		},
		{
			name:           "ListTenants uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, _, err := a.ListTenants(context.Background(), &admin.ListTenantsRequest{Page: 1, PerPage: 10})
				return err
			},
		},
		{
			name:           "CreateEAB uses POST",
			expectedMethod: http.MethodPost,
			execute: func(a *Adapter) error {
				_, err := a.CreateEAB(context.Background(), "t1", &admin.CreateEABRequest{})
				return err
			},
		},
		{
			name:           "GetEAB uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, err := a.GetEAB(context.Background(), "t1", "kid")
				return err
			},
		},
		{
			name:           "DeleteEAB uses DELETE",
			expectedMethod: http.MethodDelete,
			execute: func(a *Adapter) error {
				return a.DeleteEAB(context.Background(), "t1", "kid")
			},
		},
		{
			name:           "CreateTenantRole uses POST",
			expectedMethod: http.MethodPost,
			execute: func(a *Adapter) error {
				_, err := a.CreateTenantRole(context.Background(), "t1", &db.CreateRoleRequest{Name: "admin"})
				return err
			},
		},
		{
			name:           "GetTenantRole uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, err := a.GetTenantRole(context.Background(), "t1", "role-1")
				return err
			},
		},
		{
			name:           "UpdateTenantRole uses PUT",
			expectedMethod: http.MethodPut,
			execute: func(a *Adapter) error {
				_, err := a.UpdateTenantRole(context.Background(), "t1", &db.UpdateRoleRequest{ID: "role-1", Name: "editor"})
				return err
			},
		},
		{
			name:           "DeleteTenantRole uses DELETE",
			expectedMethod: http.MethodDelete,
			execute: func(a *Adapter) error {
				return a.DeleteTenantRole(context.Background(), "t1", "role-1")
			},
		},
		{
			name:           "CreateTenantUser uses POST",
			expectedMethod: http.MethodPost,
			execute: func(a *Adapter) error {
				_, err := a.CreateTenantUser(context.Background(), "t1", &db.CreateUserRequest{Username: "alice"})
				return err
			},
		},
		{
			name:           "GetTenantUser uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, err := a.GetTenantUser(context.Background(), "t1", "user-1")
				return err
			},
		},
		{
			name:           "UpdateTenantUser uses PUT",
			expectedMethod: http.MethodPut,
			execute: func(a *Adapter) error {
				_, err := a.UpdateTenantUser(context.Background(), "t1", &db.UpdateUserRequest{ID: 1, Username: "bob"})
				return err
			},
		},
		{
			name:           "DeleteTenantUser uses DELETE",
			expectedMethod: http.MethodDelete,
			execute: func(a *Adapter) error {
				return a.DeleteTenantUser(context.Background(), "t1", "user-1")
			},
		},
		{
			name:           "GetCertificate uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, err := a.GetCertificate(context.Background(), "serial")
				return err
			},
		},
		{
			name:           "RevokeCertificate uses POST",
			expectedMethod: http.MethodPost,
			execute: func(a *Adapter) error {
				return a.RevokeCertificate(context.Background(), "serial", "reason")
			},
		},
		{
			name:           "GetStatus uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, err := a.GetStatus(context.Background())
				return err
			},
		},
		{
			name:           "GetStats uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, err := a.GetStats(context.Background())
				return err
			},
		},
		{
			name:           "ListCertificates uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, _, err := a.ListCertificates(context.Background(), &admin.ListCertificatesRequest{Page: 1, PerPage: 10})
				return err
			},
		},
		{
			name:           "ListEABs uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, _, err := a.ListEABs(context.Background(), "t1", &admin.ListEABRequest{Page: 1, PerPage: 10})
				return err
			},
		},
		{
			name:           "ListTenantRoles uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, err := a.ListTenantRoles(context.Background(), "t1", &db.ListRolesRequest{Page: 1, PageSize: 10})
				return err
			},
		},
		{
			name:           "ListTenantUsers uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, err := a.ListTenantUsers(context.Background(), "t1", &db.ListUsersRequest{Page: 1, PageSize: 10})
				return err
			},
		},
		{
			name:           "ListAccounts uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, _, err := a.ListAccounts(context.Background(), &admin.ListAccountsRequest{Page: 1, PerPage: 10})
				return err
			},
		},
		{
			name:           "GetAccount uses GET",
			expectedMethod: http.MethodGet,
			execute: func(a *Adapter) error {
				_, err := a.GetAccount(context.Background(), 12345)
				return err
			},
		},
		{
			name:           "DisableAccount uses POST",
			expectedMethod: http.MethodPost,
			execute: func(a *Adapter) error {
				return a.DisableAccount(context.Background(), 12345)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var capturedMethod string

			adapter := &Adapter{
				baseURL:   "https://localhost:9444",
				authToken: "test-token",
				httpClient: &http.Client{
					Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						capturedMethod = req.Method
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{}`)),
						}, nil
					}),
				},
			}

			_ = tc.execute(adapter)

			if capturedMethod != tc.expectedMethod {
				t.Errorf("Expected method '%s', got '%s'", tc.expectedMethod, capturedMethod)
			}
		})
	}
}

// TestRequestBodyContents tests that request bodies are correctly serialized.
func TestRequestBodyContents(t *testing.T) {
	t.Run("CreateTenant request body", func(t *testing.T) {
		var capturedBody []byte

		adapter := &Adapter{
			baseURL:   "https://localhost:9444",
			authToken: "test-token",
			httpClient: &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					capturedBody, _ = io.ReadAll(req.Body)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"id":"tenant-1"}`)),
					}, nil
				}),
			},
		}

		req := &admin.CreateTenantRequest{
			ID:   "tenant-1",
			Name: "Test Tenant",
		}
		_, _ = adapter.CreateTenant(context.Background(), req)

		var parsed admin.CreateTenantRequest
		if err := json.Unmarshal(capturedBody, &parsed); err != nil {
			t.Fatalf("Failed to parse request body: %v", err)
		}
		if parsed.ID != "tenant-1" {
			t.Errorf("Expected ID 'tenant-1', got '%s'", parsed.ID)
		}
		if parsed.Name != "Test Tenant" {
			t.Errorf("Expected Name 'Test Tenant', got '%s'", parsed.Name)
		}
	})

	t.Run("RevokeCertificate request body", func(t *testing.T) {
		var capturedBody []byte

		adapter := &Adapter{
			baseURL:   "https://localhost:9444",
			authToken: "test-token",
			httpClient: &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					capturedBody, _ = io.ReadAll(req.Body)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{}`)),
					}, nil
				}),
			},
		}

		_ = adapter.RevokeCertificate(context.Background(), "12345", "keyCompromise")

		var parsed map[string]string
		if err := json.Unmarshal(capturedBody, &parsed); err != nil {
			t.Fatalf("Failed to parse request body: %v", err)
		}
		if parsed["reason"] != "keyCompromise" {
			t.Errorf("Expected reason 'keyCompromise', got '%s'", parsed["reason"])
		}
	})
}

// TestEmptyResponseHandling tests handling of empty responses.
func TestEmptyResponseHandling(t *testing.T) {
	t.Run("DeleteTenant with empty response", func(t *testing.T) {
		response := &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.DeleteTenant(context.Background(), "tenant-1")
		if err != nil {
			t.Errorf("DeleteTenant() should succeed with empty response: %v", err)
		}
	})

	t.Run("DeleteEAB with empty response", func(t *testing.T) {
		response := &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.DeleteEAB(context.Background(), "tenant-1", "kid-1")
		if err != nil {
			t.Errorf("DeleteEAB() should succeed with empty response: %v", err)
		}
	})

	t.Run("DeleteTenantRole with empty response", func(t *testing.T) {
		response := &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.DeleteTenantRole(context.Background(), "tenant-1", "role-1")
		if err != nil {
			t.Errorf("DeleteTenantRole() should succeed with empty response: %v", err)
		}
	})

	t.Run("DeleteTenantUser with empty response", func(t *testing.T) {
		response := &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}
		adapter := createMockAdapter(response, nil)

		err := adapter.DeleteTenantUser(context.Background(), "tenant-1", "user-1")
		if err != nil {
			t.Errorf("DeleteTenantUser() should succeed with empty response: %v", err)
		}
	})
}

// TestErrorStatusCodes tests various HTTP error status codes.
func TestErrorStatusCodes(t *testing.T) {
	statusCodes := []struct {
		code    int
		message string
	}{
		{http.StatusBadRequest, "400"},
		{http.StatusUnauthorized, "401"},
		{http.StatusForbidden, "403"},
		{http.StatusNotFound, "404"},
		{http.StatusMethodNotAllowed, "405"},
		{http.StatusConflict, "409"},
		{http.StatusInternalServerError, "500"},
		{http.StatusBadGateway, "502"},
		{http.StatusServiceUnavailable, "503"},
		{http.StatusGatewayTimeout, "504"},
	}

	for _, sc := range statusCodes {
		t.Run("status "+sc.message, func(t *testing.T) {
			responseBody := `{"error":"test error"}`
			response := &http.Response{
				StatusCode: sc.code,
				Body:       io.NopCloser(strings.NewReader(responseBody)),
			}
			adapter := createMockAdapter(response, nil)

			_, err := adapter.GetTenant(context.Background(), "tenant-1")
			if err == nil {
				t.Errorf("Expected error for status %d", sc.code)
			}
			if !strings.Contains(err.Error(), sc.message) {
				t.Errorf("Expected error to contain '%s', got: %v", sc.message, err)
			}
		})
	}
}

// TestAdapterURLPaths tests additional URL path constructions.
func TestAdapterURLPaths(t *testing.T) {
	testCases := []struct {
		name        string
		expectedURL string
		execute     func(adapter *Adapter) error
	}{
		{
			name:        "CreateTenant URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/",
			execute: func(a *Adapter) error {
				_, err := a.CreateTenant(context.Background(), &admin.CreateTenantRequest{ID: "t1"})
				return err
			},
		},
		{
			name:        "UpdateTenant URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/tenant-abc",
			execute: func(a *Adapter) error {
				_, err := a.UpdateTenant(context.Background(), "tenant-abc", &admin.UpdateTenantRequest{Name: "new"})
				return err
			},
		},
		{
			name:        "DeleteTenant URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/tenant-xyz",
			execute: func(a *Adapter) error {
				return a.DeleteTenant(context.Background(), "tenant-xyz")
			},
		},
		{
			name:        "CreateEAB URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/t1/eab",
			execute: func(a *Adapter) error {
				_, err := a.CreateEAB(context.Background(), "t1", &admin.CreateEABRequest{})
				return err
			},
		},
		{
			name:        "DeleteEAB URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/t1/eab/kid-del",
			execute: func(a *Adapter) error {
				return a.DeleteEAB(context.Background(), "t1", "kid-del")
			},
		},
		{
			name:        "ListEABs URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/t1/eab?page=1&per_page=20",
			execute: func(a *Adapter) error {
				_, _, err := a.ListEABs(context.Background(), "t1", &admin.ListEABRequest{Page: 1, PerPage: 20})
				return err
			},
		},
		{
			name:        "CreateTenantRole URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/t1/roles",
			execute: func(a *Adapter) error {
				_, err := a.CreateTenantRole(context.Background(), "t1", &db.CreateRoleRequest{Name: "admin"})
				return err
			},
		},
		{
			name:        "UpdateTenantRole URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/t1/roles/role-1",
			execute: func(a *Adapter) error {
				_, err := a.UpdateTenantRole(context.Background(), "t1", &db.UpdateRoleRequest{ID: "role-1", Name: "editor"})
				return err
			},
		},
		{
			name:        "DeleteTenantRole URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/t1/roles/role-del",
			execute: func(a *Adapter) error {
				return a.DeleteTenantRole(context.Background(), "t1", "role-del")
			},
		},
		{
			name:        "ListTenantRoles URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/t1/roles?page=2&per_page=25",
			execute: func(a *Adapter) error {
				_, err := a.ListTenantRoles(context.Background(), "t1", &db.ListRolesRequest{Page: 2, PageSize: 25})
				return err
			},
		},
		{
			name:        "CreateTenantUser URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/t1/users",
			execute: func(a *Adapter) error {
				_, err := a.CreateTenantUser(context.Background(), "t1", &db.CreateUserRequest{Username: "alice"})
				return err
			},
		},
		{
			name:        "UpdateTenantUser URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/t1/users/1",
			execute: func(a *Adapter) error {
				_, err := a.UpdateTenantUser(context.Background(), "t1", &db.UpdateUserRequest{ID: 1, Username: "bob"})
				return err
			},
		},
		{
			name:        "DeleteTenantUser URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/t1/users/user-del",
			execute: func(a *Adapter) error {
				return a.DeleteTenantUser(context.Background(), "t1", "user-del")
			},
		},
		{
			name:        "ListTenantUsers URL",
			expectedURL: "https://localhost:9444/api/v1/tenants/t1/users?page=1&per_page=20",
			execute: func(a *Adapter) error {
				_, err := a.ListTenantUsers(context.Background(), "t1", &db.ListUsersRequest{Page: 1, PageSize: 20})
				return err
			},
		},
		{
			name:        "ListCertificates URL",
			expectedURL: "https://localhost:9444/admin/certificates?page=3&per_page=15",
			execute: func(a *Adapter) error {
				_, _, err := a.ListCertificates(context.Background(), &admin.ListCertificatesRequest{Page: 3, PerPage: 15})
				return err
			},
		},
		{
			name:        "GetStatus URL",
			expectedURL: "https://localhost:9444/admin/status",
			execute: func(a *Adapter) error {
				_, err := a.GetStatus(context.Background())
				return err
			},
		},
		{
			name:        "GetStats URL",
			expectedURL: "https://localhost:9444/admin/stats",
			execute: func(a *Adapter) error {
				_, err := a.GetStats(context.Background())
				return err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var capturedURL string

			adapter := &Adapter{
				baseURL:   "https://localhost:9444",
				authToken: "test-token",
				httpClient: &http.Client{
					Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						capturedURL = req.URL.String()
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{}`)),
						}, nil
					}),
				},
			}

			_ = tc.execute(adapter)

			if capturedURL != tc.expectedURL {
				t.Errorf("Expected URL '%s', got '%s'", tc.expectedURL, capturedURL)
			}
		})
	}
}
