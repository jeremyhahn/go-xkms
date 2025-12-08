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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockRoundTripper implements http.RoundTripper for testing QUIC client
type mockRoundTripper struct {
	handler http.Handler
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Create a response recorder-like mechanism
	rec := &mockResponseWriter{
		headers: make(http.Header),
		code:    http.StatusOK,
	}

	m.handler.ServeHTTP(rec, req)

	return &http.Response{
		StatusCode: rec.code,
		Header:     rec.headers,
		Body:       io.NopCloser(bytes.NewReader(rec.body.Bytes())),
		Request:    req,
	}, nil
}

type mockResponseWriter struct {
	headers http.Header
	body    bytes.Buffer
	code    int
}

func (m *mockResponseWriter) Header() http.Header {
	return m.headers
}

func (m *mockResponseWriter) Write(data []byte) (int, error) {
	return m.body.Write(data)
}

func (m *mockResponseWriter) WriteHeader(code int) {
	m.code = code
}

// createMockQUICHandler creates the HTTP handler for mock QUIC server
func createMockQUICHandler() http.Handler {
	mux := http.NewServeMux()

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy","version":"1.0.0"}`))
	})

	// List backends
	mux.HandleFunc("/api/v1/backends", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"backends":[{"id":"software","type":"software","hardware_backed":false}]}`))
		}
	})

	// Get backend
	mux.HandleFunc("/api/v1/backends/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"software","type":"software","hardware_backed":false}`))
		}
	})

	// Keys endpoints
	mux.HandleFunc("/api/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			// List keys
			_, _ = w.Write([]byte(`{"keys":[{"key_id":"test-key","key_type":"RSA","backend":"software"}]}`))
		case http.MethodPost:
			// Generate key
			_, _ = w.Write([]byte(`{"key_id":"new-key","key_type":"RSA","public_key_pem":"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"}`))
		}
	})

	// Import key
	mux.HandleFunc("/api/v1/keys/import", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"key_id":"imported-key","message":"key imported"}`))
	})

	// Get/Delete key and operations
	mux.HandleFunc("/api/v1/keys/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		// Handle sign endpoint
		if strings.Contains(path, "/sign") {
			_, _ = w.Write([]byte(`{"signature":"c2lnbmF0dXJl"}`))
			return
		}

		// Handle verify endpoint
		if strings.Contains(path, "/verify") {
			_, _ = w.Write([]byte(`{"valid":true,"message":"signature verified"}`))
			return
		}

		// Handle encrypt-asym endpoint (must be before /encrypt check)
		if strings.Contains(path, "/encrypt-asym") {
			_, _ = w.Write([]byte(`{"ciphertext":"YXN5bS1jaXBoZXJ0ZXh0"}`))
			return
		}

		// Handle encrypt endpoint
		if strings.Contains(path, "/encrypt") {
			_, _ = w.Write([]byte(`{"ciphertext":"Y2lwaGVydGV4dA==","nonce":"bm9uY2U=","tag":"dGFn"}`))
			return
		}

		// Handle decrypt endpoint
		if strings.Contains(path, "/decrypt") {
			_, _ = w.Write([]byte(`{"plaintext":"cGxhaW50ZXh0"}`))
			return
		}

		// Handle export endpoint
		if strings.Contains(path, "/export") {
			_, _ = w.Write([]byte(`{"key_id":"test-key","wrapped_key":"d3JhcHBlZA==","algorithm":"AES-KWP"}`))
			return
		}

		// Handle rotate endpoint - POST /api/v1/keys/{keyID}/rotate
		if strings.Contains(path, "/rotate") {
			_, _ = w.Write([]byte(`{"success":true,"key_id":"test-key","public_key_pem":"-----BEGIN PUBLIC KEY-----\nrotated\n-----END PUBLIC KEY-----"}`))
			return
		}

		switch r.Method {
		case http.MethodGet:
			// Get key
			_, _ = w.Write([]byte(`{"key_id":"test-key","key_type":"RSA","backend":"software","public_key_pem":"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"}`))
		case http.MethodDelete:
			// Delete key
			_, _ = w.Write([]byte(`{"success":true,"message":"key deleted"}`))
		}
	})

	// Certificates endpoints - List and Save
	mux.HandleFunc("/api/v1/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			// List certificates
			_, _ = w.Write([]byte(`{"certificates":[{"key_id":"cert-1"},{"key_id":"cert-2"}]}`))
		case http.MethodPost:
			// Save certificate
			w.WriteHeader(http.StatusOK)
		}
	})

	mux.HandleFunc("/api/v1/certs/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		// Handle certificate chain endpoints
		if strings.Contains(path, "/chain") {
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte(`{"key_id":"test-key","chain_pem":["-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"]}`))
			case http.MethodPost:
				w.WriteHeader(http.StatusOK)
			}
			return
		}

		switch r.Method {
		case http.MethodGet:
			// Get certificate
			_, _ = w.Write([]byte(`{"key_id":"test-key","certificate_pem":"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"}`))
		case http.MethodDelete:
			// Delete certificate
			w.WriteHeader(http.StatusOK)
		}
	})

	// Import parameters endpoint - POST /api/v1/keys/import-params
	mux.HandleFunc("/api/v1/keys/import-params", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"wrapping_public_key":"d3JhcHBpbmcta2V5","import_token":"dG9rZW4=","algorithm":"RSA_AES_KEY_WRAP_SHA_256"}`))
	})

	// Wrap key endpoint - POST /api/v1/keys/wrap
	mux.HandleFunc("/api/v1/keys/wrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"wrapped_key_material":"d3JhcHBlZC1rZXk=","algorithm":"RSA_AES_KEY_WRAP_SHA_256"}`))
	})

	// Unwrap key endpoint - POST /api/v1/keys/unwrap
	mux.HandleFunc("/api/v1/keys/unwrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_material":"dW53cmFwcGVkLWtleQ=="}`))
	})

	// Copy key endpoint - POST /api/v1/keys/copy
	mux.HandleFunc("/api/v1/keys/copy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"key_id":"dest-key","message":"key copied"}`))
	})

	// TLS certificate endpoint - GET /api/v1/tls/{keyID}
	mux.HandleFunc("/api/v1/tls/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"test-key","private_key_pem":"-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----","certificate_pem":"-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----","chain_pem":"-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"}`))
	})

	return mux
}

// createMockQUICClient creates a QUIC client with mock HTTP transport
func createMockQUICClient(t *testing.T) *quicClient {
	t.Helper()

	handler := createMockQUICHandler()
	transport := &mockRoundTripper{handler: handler}

	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	return client
}

func TestQUICClient_WithMockServer_Health(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.Health(ctx)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("Health() Status = %v, want healthy", resp.Status)
	}

	if resp.Version != "1.0.0" {
		t.Errorf("Health() Version = %v, want 1.0.0", resp.Version)
	}
}

func TestQUICClient_WithMockServer_ListBackends(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.ListBackends(ctx)
	if err != nil {
		t.Fatalf("ListBackends() error = %v", err)
	}

	if len(resp.Backends) != 1 {
		t.Errorf("ListBackends() len = %d, want 1", len(resp.Backends))
	}
}

func TestQUICClient_WithMockServer_GetBackend(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.GetBackend(ctx, "software")
	if err != nil {
		t.Fatalf("GetBackend() error = %v", err)
	}

	if resp.ID != "software" {
		t.Errorf("GetBackend() ID = %v, want software", resp.ID)
	}
}

func TestQUICClient_WithMockServer_GenerateKey(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.GenerateKey(ctx, &GenerateKeyRequest{
		KeyID:   "new-key",
		Backend: "software",
		KeyType: "RSA",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if resp.KeyID != "new-key" {
		t.Errorf("GenerateKey() KeyID = %v, want new-key", resp.KeyID)
	}
}

func TestQUICClient_WithMockServer_ListKeys(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.ListKeys(ctx, "software")
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	if len(resp.Keys) != 1 {
		t.Errorf("ListKeys() len = %d, want 1", len(resp.Keys))
	}
}

func TestQUICClient_WithMockServer_GetKey(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.GetKey(ctx, "software", "test-key")
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetKey() KeyID = %v, want test-key", resp.KeyID)
	}
}

func TestQUICClient_WithMockServer_DeleteKey(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.DeleteKey(ctx, "software", "test-key")
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("DeleteKey() Success = false, want true")
	}
}

func TestQUICClient_WithMockServer_Sign(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.Sign(ctx, &SignRequest{
		KeyID:   "test-key",
		Backend: "software",
		Data:    json.RawMessage(`"dGVzdA=="`),
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if resp.Signature == nil {
		t.Error("Sign() Signature is nil")
	}
}

func TestQUICClient_WithMockServer_Sign_WithHash(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.Sign(ctx, &SignRequest{
		KeyID:   "test-key",
		Backend: "software",
		Data:    json.RawMessage(`"dGVzdA=="`),
		Hash:    "SHA256",
	})
	if err != nil {
		t.Fatalf("Sign() with hash error = %v", err)
	}

	if resp.Signature == nil {
		t.Error("Sign() with hash Signature is nil")
	}
}

func TestQUICClient_WithMockServer_Verify(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.Verify(ctx, &VerifyRequest{
		KeyID:     "test-key",
		Backend:   "software",
		Data:      json.RawMessage(`"dGVzdA=="`),
		Signature: json.RawMessage(`"c2lnbmF0dXJl"`),
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !resp.Valid {
		t.Error("Verify() Valid = false, want true")
	}
}

func TestQUICClient_WithMockServer_Verify_WithHash(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.Verify(ctx, &VerifyRequest{
		KeyID:     "test-key",
		Backend:   "software",
		Data:      json.RawMessage(`"dGVzdA=="`),
		Signature: json.RawMessage(`"c2lnbmF0dXJl"`),
		Hash:      "SHA256",
	})
	if err != nil {
		t.Fatalf("Verify() with hash error = %v", err)
	}

	if !resp.Valid {
		t.Error("Verify() with hash Valid = false, want true")
	}
}

func TestQUICClient_WithMockServer_Encrypt(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.Encrypt(ctx, &EncryptRequest{
		KeyID:     "test-key",
		Backend:   "software",
		Plaintext: json.RawMessage(`"cGxhaW50ZXh0"`),
	})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if resp.Ciphertext == nil {
		t.Error("Encrypt() Ciphertext is nil")
	}
}

func TestQUICClient_WithMockServer_Encrypt_WithAdditionalData(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.Encrypt(ctx, &EncryptRequest{
		KeyID:          "test-key",
		Backend:        "software",
		Plaintext:      json.RawMessage(`"cGxhaW50ZXh0"`),
		AdditionalData: json.RawMessage(`"YWFk"`),
	})
	if err != nil {
		t.Fatalf("Encrypt() with additional data error = %v", err)
	}

	if resp.Ciphertext == nil {
		t.Error("Encrypt() with additional data Ciphertext is nil")
	}
}

func TestQUICClient_WithMockServer_Decrypt(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.Decrypt(ctx, &DecryptRequest{
		KeyID:      "test-key",
		Backend:    "software",
		Ciphertext: json.RawMessage(`"Y2lwaGVydGV4dA=="`),
	})
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if resp.Plaintext == nil {
		t.Error("Decrypt() Plaintext is nil")
	}
}

func TestQUICClient_WithMockServer_Decrypt_WithNonceTagAad(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.Decrypt(ctx, &DecryptRequest{
		KeyID:          "test-key",
		Backend:        "software",
		Ciphertext:     json.RawMessage(`"Y2lwaGVydGV4dA=="`),
		Nonce:          json.RawMessage(`"bm9uY2U="`),
		Tag:            json.RawMessage(`"dGFn"`),
		AdditionalData: json.RawMessage(`"YWFk"`),
	})
	if err != nil {
		t.Fatalf("Decrypt() with nonce/tag/aad error = %v", err)
	}

	if resp.Plaintext == nil {
		t.Error("Decrypt() with nonce/tag/aad Plaintext is nil")
	}
}

func TestQUICClient_WithMockServer_EncryptAsym(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.EncryptAsym(ctx, &EncryptAsymRequest{
		KeyID:     "test-key",
		Backend:   "software",
		Plaintext: json.RawMessage(`"cGxhaW50ZXh0"`),
		Hash:      "SHA256",
	})
	if err != nil {
		t.Fatalf("EncryptAsym() error = %v", err)
	}

	if resp.Ciphertext == nil {
		t.Error("EncryptAsym() Ciphertext is nil")
	}
}

func TestQUICClient_WithMockServer_EncryptAsym_WithoutHash(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.EncryptAsym(ctx, &EncryptAsymRequest{
		KeyID:     "test-key",
		Backend:   "software",
		Plaintext: json.RawMessage(`"cGxhaW50ZXh0"`),
	})
	if err != nil {
		t.Fatalf("EncryptAsym() without hash error = %v", err)
	}

	if resp.Ciphertext == nil {
		t.Error("EncryptAsym() without hash Ciphertext is nil")
	}
}

func TestQUICClient_WithMockServer_GetCertificate(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.GetCertificate(ctx, "software", "test-key")
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	if resp.CertificatePEM == "" {
		t.Error("GetCertificate() CertificatePEM is empty")
	}
}

func TestQUICClient_WithMockServer_SaveCertificate(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	err := client.SaveCertificate(ctx, &SaveCertificateRequest{
		KeyID:          "test-key",
		Backend:        "software",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	})
	if err != nil {
		t.Fatalf("SaveCertificate() error = %v", err)
	}
}

func TestQUICClient_WithMockServer_DeleteCertificate(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	err := client.DeleteCertificate(ctx, "software", "test-key")
	if err != nil {
		t.Fatalf("DeleteCertificate() error = %v", err)
	}
}

func TestQUICClient_WithMockServer_ImportKey(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.ImportKey(ctx, &ImportKeyRequest{
		KeyID:              "imported-key",
		Backend:            "software",
		WrappedKeyMaterial: []byte("wrapped-key-data"),
	})
	if err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("ImportKey() Success = false, want true")
	}
}

func TestQUICClient_WithMockServer_ExportKey(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.ExportKey(ctx, &ExportKeyRequest{
		KeyID:     "test-key",
		Backend:   "software",
		Algorithm: "AES-KWP",
	})
	if err != nil {
		t.Fatalf("ExportKey() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("ExportKey() KeyID = %v, want test-key", resp.KeyID)
	}
}

// Test error handling
func TestQUICClient_WithMockServer_doRequest_APIKey(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "test-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
			APIKey:   "test-api-key",
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	data, err := client.doRequest(ctx, http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatalf("doRequest() with API key error = %v", err)
	}

	if !strings.Contains(string(data), "ok") {
		t.Errorf("doRequest() response = %s, want ok", string(data))
	}
}

func TestQUICClient_WithMockServer_doRequest_CustomHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customHeader := r.Header.Get("X-Custom-Header")
		if customHeader != "custom-value" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"missing header"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
			Headers: map[string]string{
				"X-Custom-Header": "custom-value",
			},
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	data, err := client.doRequest(ctx, http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatalf("doRequest() with custom headers error = %v", err)
	}

	if !strings.Contains(string(data), "ok") {
		t.Errorf("doRequest() response = %s, want ok", string(data))
	}
}

func TestQUICClient_WithMockServer_doRequest_ServerError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.doRequest(ctx, http.MethodGet, "/test", nil)
	if err == nil {
		t.Fatal("doRequest() expected error for server error")
	}

	if !strings.Contains(err.Error(), "internal server error") {
		t.Errorf("doRequest() error = %v, want to contain 'internal server error'", err)
	}
}

func TestQUICClient_WithMockServer_doRequest_ServerErrorMessage(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"bad request message"}`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.doRequest(ctx, http.MethodGet, "/test", nil)
	if err == nil {
		t.Fatal("doRequest() expected error for bad request")
	}

	if !strings.Contains(err.Error(), "bad request message") {
		t.Errorf("doRequest() error = %v, want to contain 'bad request message'", err)
	}
}

func TestQUICClient_WithMockServer_doRequest_ServerErrorUnparseable(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.doRequest(ctx, http.MethodGet, "/test", nil)
	if err == nil {
		t.Fatal("doRequest() expected error for unparseable response")
	}

	if !strings.Contains(err.Error(), "503") {
		t.Errorf("doRequest() error = %v, want to contain status code 503", err)
	}
}

func TestQUICClient_WithMockServer_doRequest_WithBody(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"missing content type"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	body := map[string]string{"key": "value"}
	data, err := client.doRequest(ctx, http.MethodPost, "/test", body)
	if err != nil {
		t.Fatalf("doRequest() with body error = %v", err)
	}

	if !strings.Contains(string(data), "ok") {
		t.Errorf("doRequest() response = %s, want ok", string(data))
	}
}

// Test JSON parse error paths
func TestQUICClient_WithMockServer_Health_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.Health(ctx)
	if err == nil {
		t.Fatal("Health() expected parse error")
	}
}

func TestQUICClient_WithMockServer_ListBackends_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.ListBackends(ctx)
	if err == nil {
		t.Fatal("ListBackends() expected parse error")
	}
}

func TestQUICClient_WithMockServer_GetBackend_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.GetBackend(ctx, "software")
	if err == nil {
		t.Fatal("GetBackend() expected parse error")
	}
}

func TestQUICClient_WithMockServer_GenerateKey_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.GenerateKey(ctx, &GenerateKeyRequest{KeyID: "test"})
	if err == nil {
		t.Fatal("GenerateKey() expected parse error")
	}
}

func TestQUICClient_WithMockServer_ListKeys_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.ListKeys(ctx, "software")
	if err == nil {
		t.Fatal("ListKeys() expected parse error")
	}
}

func TestQUICClient_WithMockServer_GetKey_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.GetKey(ctx, "software", "test")
	if err == nil {
		t.Fatal("GetKey() expected parse error")
	}
}

func TestQUICClient_WithMockServer_DeleteKey_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.DeleteKey(ctx, "software", "test")
	if err == nil {
		t.Fatal("DeleteKey() expected parse error")
	}
}

func TestQUICClient_WithMockServer_Sign_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.Sign(ctx, &SignRequest{KeyID: "test", Backend: "software", Data: json.RawMessage(`"dGVzdA=="`)})
	if err == nil {
		t.Fatal("Sign() expected parse error")
	}
}

func TestQUICClient_WithMockServer_Verify_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.Verify(ctx, &VerifyRequest{KeyID: "test", Backend: "software", Data: json.RawMessage(`"dGVzdA=="`), Signature: json.RawMessage(`"c2ln"`)})
	if err == nil {
		t.Fatal("Verify() expected parse error")
	}
}

func TestQUICClient_WithMockServer_Encrypt_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.Encrypt(ctx, &EncryptRequest{KeyID: "test", Backend: "software", Plaintext: json.RawMessage(`"dGVzdA=="`)})
	if err == nil {
		t.Fatal("Encrypt() expected parse error")
	}
}

func TestQUICClient_WithMockServer_Decrypt_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.Decrypt(ctx, &DecryptRequest{KeyID: "test", Backend: "software", Ciphertext: json.RawMessage(`"Y2lwaGVy"`)})
	if err == nil {
		t.Fatal("Decrypt() expected parse error")
	}
}

func TestQUICClient_WithMockServer_GetCertificate_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.GetCertificate(ctx, "software", "test")
	if err == nil {
		t.Fatal("GetCertificate() expected parse error")
	}
}

func TestQUICClient_WithMockServer_ImportKey_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.ImportKey(ctx, &ImportKeyRequest{KeyID: "test", Backend: "software", WrappedKeyMaterial: []byte("wrapped-key-data")})
	if err == nil {
		t.Fatal("ImportKey() expected parse error")
	}
}

func TestQUICClient_WithMockServer_ExportKey_ParseError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	transport := &mockRoundTripper{handler: handler}
	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	ctx := context.Background()
	_, err := client.ExportKey(ctx, &ExportKeyRequest{KeyID: "test", Backend: "software", Algorithm: "AES-KWP"})
	if err == nil {
		t.Fatal("ExportKey() expected parse error")
	}
}

func TestQUICClient_WithMockServer_RotateKey(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.RotateKey(ctx, &RotateKeyRequest{
		Backend: "software",
		KeyID:   "test-key",
	})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("RotateKey().Success = false, want true")
	}
	if resp.KeyID != "test-key" {
		t.Errorf("RotateKey().KeyID = %v, want test-key", resp.KeyID)
	}
}

func TestQUICClient_WithMockServer_GetImportParameters(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.GetImportParameters(ctx, &GetImportParametersRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Algorithm: "RSA_AES_KEY_WRAP_SHA_256",
	})
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}

	if len(resp.WrappingPublicKey) == 0 {
		t.Error("GetImportParameters().WrappingPublicKey is empty")
	}
	if resp.Algorithm != "RSA_AES_KEY_WRAP_SHA_256" {
		t.Errorf("GetImportParameters().Algorithm = %v, want RSA_AES_KEY_WRAP_SHA_256", resp.Algorithm)
	}
}

func TestQUICClient_WithMockServer_WrapKey(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.WrapKey(ctx, &WrapKeyRequest{
		Backend:     "software",
		KeyMaterial: []byte("key-material"),
		Algorithm:   "RSA_AES_KEY_WRAP_SHA_256",
	})
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}

	if len(resp.WrappedKeyMaterial) == 0 {
		t.Error("WrapKey().WrappedKeyMaterial is empty")
	}
}

func TestQUICClient_WithMockServer_UnwrapKey(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.UnwrapKey(ctx, &UnwrapKeyRequest{
		Backend:            "software",
		WrappedKeyMaterial: []byte("wrapped-key"),
		Algorithm:          "RSA_AES_KEY_WRAP_SHA_256",
	})
	if err != nil {
		t.Fatalf("UnwrapKey() error = %v", err)
	}

	if len(resp.KeyMaterial) == 0 {
		t.Error("UnwrapKey().KeyMaterial is empty")
	}
}

func TestQUICClient_WithMockServer_CopyKey(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.CopyKey(ctx, &CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "source-key",
		DestBackend:   "pkcs11",
		DestKeyID:     "dest-key",
		Algorithm:     "RSA_AES_KEY_WRAP_SHA_256",
	})
	if err != nil {
		t.Fatalf("CopyKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("CopyKey().Success = false, want true")
	}
	if resp.KeyID != "dest-key" {
		t.Errorf("CopyKey().KeyID = %v, want dest-key", resp.KeyID)
	}
}

func TestQUICClient_WithMockServer_ListCertificates(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.ListCertificates(ctx, "software")
	if err != nil {
		t.Fatalf("ListCertificates() error = %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("ListCertificates() count = %d, want 2", len(resp.Certificates))
	}
}

func TestQUICClient_WithMockServer_SaveCertificateChain(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	err := client.SaveCertificateChain(ctx, &SaveCertificateChainRequest{
		Backend:  "software",
		KeyID:    "test-key",
		ChainPEM: []string{"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"},
	})
	if err != nil {
		t.Fatalf("SaveCertificateChain() error = %v", err)
	}
}

func TestQUICClient_WithMockServer_GetCertificateChain(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.GetCertificateChain(ctx, "software", "test-key")
	if err != nil {
		t.Fatalf("GetCertificateChain() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetCertificateChain().KeyID = %v, want test-key", resp.KeyID)
	}
	if len(resp.ChainPEM) == 0 {
		t.Error("GetCertificateChain().ChainPEM is empty")
	}
}

func TestQUICClient_WithMockServer_GetTLSCertificate(t *testing.T) {
	client := createMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.GetTLSCertificate(ctx, "software", "test-key")
	if err != nil {
		t.Fatalf("GetTLSCertificate() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetTLSCertificate().KeyID = %v, want test-key", resp.KeyID)
	}
	if resp.PrivateKeyPEM == "" {
		t.Error("GetTLSCertificate().PrivateKeyPEM is empty")
	}
	if resp.CertificatePEM == "" {
		t.Error("GetTLSCertificate().CertificatePEM is empty")
	}
}

func TestQUICClient_NotConnected_RotateKey(t *testing.T) {
	client := &quicClient{
		config:    &Config{Address: "test", Protocol: ProtocolQUIC},
		connected: false,
	}
	_, err := client.RotateKey(context.Background(), &RotateKeyRequest{})
	if err != ErrNotConnected {
		t.Errorf("RotateKey() error = %v, want ErrNotConnected", err)
	}
}

func TestQUICClient_NotConnected_GetImportParameters(t *testing.T) {
	client := &quicClient{
		config:    &Config{Address: "test", Protocol: ProtocolQUIC},
		connected: false,
	}
	_, err := client.GetImportParameters(context.Background(), &GetImportParametersRequest{})
	if err != ErrNotConnected {
		t.Errorf("GetImportParameters() error = %v, want ErrNotConnected", err)
	}
}

func TestQUICClient_NotConnected_WrapKey(t *testing.T) {
	client := &quicClient{
		config:    &Config{Address: "test", Protocol: ProtocolQUIC},
		connected: false,
	}
	_, err := client.WrapKey(context.Background(), &WrapKeyRequest{})
	if err != ErrNotConnected {
		t.Errorf("WrapKey() error = %v, want ErrNotConnected", err)
	}
}

func TestQUICClient_NotConnected_UnwrapKey(t *testing.T) {
	client := &quicClient{
		config:    &Config{Address: "test", Protocol: ProtocolQUIC},
		connected: false,
	}
	_, err := client.UnwrapKey(context.Background(), &UnwrapKeyRequest{})
	if err != ErrNotConnected {
		t.Errorf("UnwrapKey() error = %v, want ErrNotConnected", err)
	}
}

func TestQUICClient_NotConnected_CopyKey(t *testing.T) {
	client := &quicClient{
		config:    &Config{Address: "test", Protocol: ProtocolQUIC},
		connected: false,
	}
	_, err := client.CopyKey(context.Background(), &CopyKeyRequest{})
	if err != ErrNotConnected {
		t.Errorf("CopyKey() error = %v, want ErrNotConnected", err)
	}
}

func TestQUICClient_NotConnected_ListCertificates(t *testing.T) {
	client := &quicClient{
		config:    &Config{Address: "test", Protocol: ProtocolQUIC},
		connected: false,
	}
	_, err := client.ListCertificates(context.Background(), "software")
	if err != ErrNotConnected {
		t.Errorf("ListCertificates() error = %v, want ErrNotConnected", err)
	}
}

func TestQUICClient_NotConnected_SaveCertificateChain(t *testing.T) {
	client := &quicClient{
		config:    &Config{Address: "test", Protocol: ProtocolQUIC},
		connected: false,
	}
	err := client.SaveCertificateChain(context.Background(), &SaveCertificateChainRequest{})
	if err != ErrNotConnected {
		t.Errorf("SaveCertificateChain() error = %v, want ErrNotConnected", err)
	}
}

func TestQUICClient_NotConnected_GetCertificateChain(t *testing.T) {
	client := &quicClient{
		config:    &Config{Address: "test", Protocol: ProtocolQUIC},
		connected: false,
	}
	_, err := client.GetCertificateChain(context.Background(), "software", "test-key")
	if err != ErrNotConnected {
		t.Errorf("GetCertificateChain() error = %v, want ErrNotConnected", err)
	}
}

func TestQUICClient_NotConnected_GetTLSCertificate(t *testing.T) {
	client := &quicClient{
		config:    &Config{Address: "test", Protocol: ProtocolQUIC},
		connected: false,
	}
	_, err := client.GetTLSCertificate(context.Background(), "software", "test-key")
	if err != ErrNotConnected {
		t.Errorf("GetTLSCertificate() error = %v, want ErrNotConnected", err)
	}
}

// Test newQUICClient URL handling
func TestNewQUICClient_URLHandling(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		wantBaseURL string
	}{
		{
			name:        "without https prefix",
			address:     "localhost:443",
			wantBaseURL: "https://localhost:443",
		},
		{
			name:        "with https prefix",
			address:     "https://localhost:443",
			wantBaseURL: "https://localhost:443",
		},
		{
			name:        "with trailing slash",
			address:     "https://localhost:443/",
			wantBaseURL: "https://localhost:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := newQUICClient(&Config{
				Address:  tt.address,
				Protocol: ProtocolQUIC,
			})
			if err != nil {
				t.Fatalf("newQUICClient() error = %v", err)
			}

			if client.baseURL != tt.wantBaseURL {
				t.Errorf("newQUICClient() baseURL = %v, want %v", client.baseURL, tt.wantBaseURL)
			}
		})
	}
}

// createInvalidJSONMockHandler creates a handler that returns invalid JSON for all endpoints
func createInvalidJSONMockHandler() http.Handler {
	mux := http.NewServeMux()

	// Health endpoint still works
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	mux.HandleFunc("/api/v1/backends", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/backends/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/import-params", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/wrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/unwrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/copy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/certs/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/tls/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	return mux
}

func createInvalidJSONMockQUICClient(t *testing.T) *quicClient {
	t.Helper()

	handler := createInvalidJSONMockHandler()
	transport := &mockRoundTripper{handler: handler}

	client := &quicClient{
		config: &Config{
			Address:  "mock-server:443",
			Protocol: ProtocolQUIC,
		},
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL:   "https://mock-server:443",
		connected: true,
	}

	return client
}

func TestQUICClient_JSONParseErrors(t *testing.T) {
	client := createInvalidJSONMockQUICClient(t)
	defer func() { _ = client.Close() }()

	ctx := context.Background()

	t.Run("ListBackends JSON parse error", func(t *testing.T) {
		_, err := client.ListBackends(ctx)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetBackend JSON parse error", func(t *testing.T) {
		_, err := client.GetBackend(ctx, "software")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GenerateKey JSON parse error", func(t *testing.T) {
		_, err := client.GenerateKey(ctx, &GenerateKeyRequest{
			KeyID:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ListKeys JSON parse error", func(t *testing.T) {
		_, err := client.ListKeys(ctx, "software")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetKey JSON parse error", func(t *testing.T) {
		_, err := client.GetKey(ctx, "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("DeleteKey JSON parse error", func(t *testing.T) {
		_, err := client.DeleteKey(ctx, "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Sign JSON parse error", func(t *testing.T) {
		data, _ := json.Marshal([]byte("test"))
		_, err := client.Sign(ctx, &SignRequest{
			KeyID:   "test-key",
			Backend: "software",
			Data:    data,
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Verify JSON parse error", func(t *testing.T) {
		data, _ := json.Marshal([]byte("test"))
		sig, _ := json.Marshal([]byte("sig"))
		_, err := client.Verify(ctx, &VerifyRequest{
			KeyID:     "test-key",
			Backend:   "software",
			Data:      data,
			Signature: sig,
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Encrypt JSON parse error", func(t *testing.T) {
		plaintext, _ := json.Marshal([]byte("test"))
		_, err := client.Encrypt(ctx, &EncryptRequest{
			KeyID:     "test-key",
			Backend:   "software",
			Plaintext: plaintext,
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Decrypt JSON parse error", func(t *testing.T) {
		ciphertext, _ := json.Marshal([]byte("test"))
		_, err := client.Decrypt(ctx, &DecryptRequest{
			KeyID:      "test-key",
			Backend:    "software",
			Ciphertext: ciphertext,
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("EncryptAsym JSON parse error", func(t *testing.T) {
		plaintext, _ := json.Marshal([]byte("test"))
		_, err := client.EncryptAsym(ctx, &EncryptAsymRequest{
			KeyID:     "test-key",
			Backend:   "software",
			Plaintext: plaintext,
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetCertificate JSON parse error", func(t *testing.T) {
		_, err := client.GetCertificate(ctx, "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ImportKey JSON parse error", func(t *testing.T) {
		_, err := client.ImportKey(ctx, &ImportKeyRequest{
			KeyID:              "test-key",
			Backend:            "software",
			WrappedKeyMaterial: []byte("test"),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ExportKey JSON parse error", func(t *testing.T) {
		_, err := client.ExportKey(ctx, &ExportKeyRequest{
			KeyID:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("RotateKey JSON parse error", func(t *testing.T) {
		_, err := client.RotateKey(ctx, &RotateKeyRequest{
			Backend: "software",
			KeyID:   "test-key",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetImportParameters JSON parse error", func(t *testing.T) {
		_, err := client.GetImportParameters(ctx, &GetImportParametersRequest{
			Backend:   "software",
			Algorithm: "RSA_AES_KEY_WRAP_SHA_256",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("WrapKey JSON parse error", func(t *testing.T) {
		_, err := client.WrapKey(ctx, &WrapKeyRequest{
			Backend:     "software",
			KeyMaterial: []byte("test"),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("UnwrapKey JSON parse error", func(t *testing.T) {
		_, err := client.UnwrapKey(ctx, &UnwrapKeyRequest{
			Backend:            "software",
			WrappedKeyMaterial: []byte("test"),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("CopyKey JSON parse error", func(t *testing.T) {
		_, err := client.CopyKey(ctx, &CopyKeyRequest{
			SourceBackend: "software",
			SourceKeyID:   "test-key",
			DestBackend:   "tpm2",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ListCertificates JSON parse error", func(t *testing.T) {
		_, err := client.ListCertificates(ctx, "software")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetCertificateChain JSON parse error", func(t *testing.T) {
		_, err := client.GetCertificateChain(ctx, "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetTLSCertificate JSON parse error", func(t *testing.T) {
		_, err := client.GetTLSCertificate(ctx, "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}
