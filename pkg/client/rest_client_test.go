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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockRESTServer creates a test HTTP server for REST client testing
func mockRESTServer(t *testing.T) *httptest.Server {
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

	// Import parameters endpoint
	mux.HandleFunc("/api/v1/keys/import-params", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"wrapping_public_key":"d3JhcHBpbmcta2V5","import_token":"dG9rZW4=","algorithm":"RSA_AES_KEY_WRAP_SHA_256"}`))
	})

	// Wrap key endpoint
	mux.HandleFunc("/api/v1/keys/wrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"wrapped_key_material":"d3JhcHBlZC1rZXk=","algorithm":"AES-KWP"}`))
	})

	// Unwrap key endpoint
	mux.HandleFunc("/api/v1/keys/unwrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_material":"dW53cmFwcGVkLWtleQ=="}`))
	})

	// Copy key endpoint
	mux.HandleFunc("/api/v1/keys/copy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"dest_key_id":"copied-key","message":"key copied"}`))
	})

	// Get/Delete key
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

		// Handle rotate endpoint
		if strings.Contains(path, "/rotate") {
			_, _ = w.Write([]byte(`{"key_id":"test-key","public_key_pem":"-----BEGIN PUBLIC KEY-----\nrotated\n-----END PUBLIC KEY-----"}`))
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

	// Import key
	mux.HandleFunc("/api/v1/keys/import", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"key_id":"imported-key","message":"key imported"}`))
	})

	// Certificates endpoints
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

		// Handle chain endpoints
		if strings.Contains(path, "/chain") {
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte(`{"key_id":"test-key","chain_pem":["-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----","-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----"]}`))
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

	// TLS endpoint
	mux.HandleFunc("/api/v1/tls/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"test-key","private_key_pem":"-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----","certificate_pem":"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----","chain_pem":"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"}`))
	})

	// Key versions endpoint - use trailing slash to match all subpaths
	mux.HandleFunc("/api/v1/keys/test-key/versions/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		// Handle enable-all
		if strings.Contains(path, "/enable-all") {
			_, _ = w.Write([]byte(`{"key_id":"test-key","count":3,"message":"all versions enabled"}`))
			return
		}

		// Handle disable-all
		if strings.Contains(path, "/disable-all") {
			_, _ = w.Write([]byte(`{"key_id":"test-key","count":3,"message":"all versions disabled"}`))
			return
		}

		// Handle enable specific version
		if strings.Contains(path, "/enable") {
			_, _ = w.Write([]byte(`{"key_id":"test-key","version":1,"status":"enabled"}`))
			return
		}

		// Handle disable specific version
		if strings.Contains(path, "/disable") {
			_, _ = w.Write([]byte(`{"key_id":"test-key","version":1,"status":"disabled"}`))
			return
		}

		// List versions (exact match without trailing slash or just /versions/)
		_, _ = w.Write([]byte(`{"key_id":"test-key","versions":[{"version":1,"status":"enabled","created_at":"2025-01-01T00:00:00Z"},{"version":2,"status":"enabled","created_at":"2025-01-02T00:00:00Z"},{"version":3,"status":"disabled","created_at":"2025-01-03T00:00:00Z"}],"total":3}`))
	})

	// Exact match for list versions (without trailing slash)
	mux.HandleFunc("/api/v1/keys/test-key/versions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"test-key","versions":[{"version":1,"status":"enabled","created_at":"2025-01-01T00:00:00Z"},{"version":2,"status":"enabled","created_at":"2025-01-02T00:00:00Z"},{"version":3,"status":"disabled","created_at":"2025-01-03T00:00:00Z"}],"total":3}`))
	})

	return httptest.NewServer(mux)
}

func TestRESTClient_Connect(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)

	err = rc.Connect(context.Background())
	if err != nil {
		t.Errorf("Connect() error = %v", err)
	}

	if !rc.connected {
		t.Error("Expected connected = true")
	}
}

func TestRESTClient_Close(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	err = rc.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if rc.connected {
		t.Error("Expected connected = false after Close")
	}
}

func TestRESTClient_Health(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("Health() status = %v, want healthy", resp.Status)
	}
	if resp.Version != "1.0.0" {
		t.Errorf("Health() version = %v, want 1.0.0", resp.Version)
	}
}

func TestRESTClient_ListBackends(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.ListBackends(context.Background())
	if err != nil {
		t.Fatalf("ListBackends() error = %v", err)
	}

	if len(resp.Backends) != 1 {
		t.Errorf("ListBackends() count = %d, want 1", len(resp.Backends))
	}
	if resp.Backends[0].ID != "software" {
		t.Errorf("ListBackends()[0].ID = %v, want software", resp.Backends[0].ID)
	}
}

func TestRESTClient_GetBackend(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.GetBackend(context.Background(), "software")
	if err != nil {
		t.Fatalf("GetBackend() error = %v", err)
	}

	if resp.ID != "software" {
		t.Errorf("GetBackend().ID = %v, want software", resp.ID)
	}
}

func TestRESTClient_GenerateKey(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.GenerateKey(context.Background(), &GenerateKeyRequest{
		KeyID:   "new-key",
		Backend: "software",
		KeyType: "RSA",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if resp.KeyID != "new-key" {
		t.Errorf("GenerateKey().KeyID = %v, want new-key", resp.KeyID)
	}
	if resp.KeyType != "RSA" {
		t.Errorf("GenerateKey().KeyType = %v, want RSA", resp.KeyType)
	}
}

func TestRESTClient_ListKeys(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.ListKeys(context.Background(), "software")
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	if len(resp.Keys) != 1 {
		t.Errorf("ListKeys() count = %d, want 1", len(resp.Keys))
	}
}

func TestRESTClient_GetKey(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.GetKey(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetKey().KeyID = %v, want test-key", resp.KeyID)
	}
}

func TestRESTClient_DeleteKey(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.DeleteKey(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("DeleteKey().Success = false, want true")
	}
}

func TestRESTClient_Sign(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	data, _ := json.Marshal([]byte("test data"))
	resp, err := rc.Sign(context.Background(), &SignRequest{
		Backend: "software",
		KeyID:   "test-key",
		Data:    data,
		Hash:    "SHA256",
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(resp.Signature) == 0 {
		t.Error("Sign().Signature is empty")
	}
}

func TestRESTClient_Verify(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	data, _ := json.Marshal([]byte("test data"))
	sig, _ := json.Marshal([]byte("signature"))
	resp, err := rc.Verify(context.Background(), &VerifyRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Data:      data,
		Signature: sig,
		Hash:      "SHA256",
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !resp.Valid {
		t.Error("Verify().Valid = false, want true")
	}
}

func TestRESTClient_Encrypt(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	plaintext, _ := json.Marshal([]byte("test data"))
	resp, err := rc.Encrypt(context.Background(), &EncryptRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if len(resp.Ciphertext) == 0 {
		t.Error("Encrypt().Ciphertext is empty")
	}
}

func TestRESTClient_Decrypt(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	ciphertext, _ := json.Marshal([]byte("ciphertext"))
	resp, err := rc.Decrypt(context.Background(), &DecryptRequest{
		Backend:    "software",
		KeyID:      "test-key",
		Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if len(resp.Plaintext) == 0 {
		t.Error("Decrypt().Plaintext is empty")
	}
}

func TestRESTClient_GetCertificate(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.GetCertificate(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetCertificate().KeyID = %v, want test-key", resp.KeyID)
	}
}

func TestRESTClient_SaveCertificate(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	err = rc.SaveCertificate(context.Background(), &SaveCertificateRequest{
		Backend:        "software",
		KeyID:          "test-key",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	})
	if err != nil {
		t.Fatalf("SaveCertificate() error = %v", err)
	}
}

func TestRESTClient_DeleteCertificate(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	err = rc.DeleteCertificate(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("DeleteCertificate() error = %v", err)
	}
}

func TestRESTClient_ImportKey(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	wrappedKey, _ := json.Marshal([]byte("wrapped-key-data"))
	resp, err := rc.ImportKey(context.Background(), &ImportKeyRequest{
		Backend:            "software",
		KeyID:              "imported-key",
		KeyType:            "RSA",
		WrappedKeyMaterial: wrappedKey,
		Algorithm:          "AES-KWP",
	})
	if err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("ImportKey().Success = false, want true")
	}
}

func TestRESTClient_ExportKey(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.ExportKey(context.Background(), &ExportKeyRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Algorithm: "AES-KWP",
	})
	if err != nil {
		t.Fatalf("ExportKey() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("ExportKey().KeyID = %v, want test-key", resp.KeyID)
	}
}

func TestRESTClient_NotConnected(t *testing.T) {
	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  "http://localhost:9999",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	// Don't connect

	_, err = rc.Health(context.Background())
	if err != ErrNotConnected {
		t.Errorf("Health() error = %v, want ErrNotConnected", err)
	}

	_, err = rc.ListBackends(context.Background())
	if err != ErrNotConnected {
		t.Errorf("ListBackends() error = %v, want ErrNotConnected", err)
	}
}

func TestRESTClient_ErrorResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})
	mux.HandleFunc("/api/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid request"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, _ := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	_, err := rc.ListKeys(context.Background(), "software")
	if err == nil {
		t.Error("Expected error for bad request")
	}
	if !strings.Contains(err.Error(), "invalid request") {
		t.Errorf("Error should contain 'invalid request', got: %v", err)
	}
}

func TestRESTClient_TLSConfig(t *testing.T) {
	cfg := &Config{
		Protocol:              ProtocolREST,
		Address:               "https://localhost:8443",
		TLSEnabled:            true,
		TLSInsecureSkipVerify: true,
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	if !rc.config.TLSEnabled {
		t.Error("Expected TLSEnabled = true")
	}
	if !rc.config.TLSInsecureSkipVerify {
		t.Error("Expected TLSInsecureSkipVerify = true")
	}
}

func TestRESTClient_Headers(t *testing.T) {
	var receivedHeaders http.Header

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, _ := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
		JWTToken: "test-jwt-token",
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
		},
	})

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	_, _ = rc.Health(context.Background())

	if receivedHeaders.Get("Authorization") != "Bearer test-jwt-token" {
		t.Errorf("Authorization = %v, want Bearer test-jwt-token", receivedHeaders.Get("Authorization"))
	}
	if receivedHeaders.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("X-Custom-Header = %v, want custom-value", receivedHeaders.Get("X-Custom-Header"))
	}
}

func TestRESTClient_URLNormalization(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		wantBase string
	}{
		{"with trailing slash", "http://localhost:8080/", "http://localhost:8080"},
		{"without trailing slash", "http://localhost:8080", "http://localhost:8080"},
		{"with https", "https://localhost:8443", "https://localhost:8443"},
		{"without scheme tls enabled", "localhost:8443", "https://localhost:8443"},
		{"without scheme tls disabled", "localhost:8080", "http://localhost:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Protocol:   ProtocolREST,
				Address:    tt.address,
				TLSEnabled: strings.Contains(tt.name, "tls enabled"),
			}

			client, err := New(cfg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			rc := client.(*restClient)
			if rc.baseURL != tt.wantBase {
				t.Errorf("baseURL = %v, want %v", rc.baseURL, tt.wantBase)
			}
		})
	}
}

func TestRESTClient_Connect_TLS_CAFileError(t *testing.T) {
	cfg := &Config{
		Address:    "localhost:8443",
		Protocol:   ProtocolREST,
		TLSEnabled: true,
		TLSCAFile:  "/nonexistent/ca.pem",
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	err = rc.Connect(context.Background())
	if err == nil {
		t.Error("Connect() should error with nonexistent CA file")
	}
}

func TestRESTClient_Connect_TLS_InvalidCA(t *testing.T) {
	// Create a temp file with invalid CA content
	tmpDir, err := os.MkdirTemp("", "rest-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	caFile := filepath.Join(tmpDir, "invalid-ca.pem")
	if err := os.WriteFile(caFile, []byte("invalid certificate content"), 0600); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	cfg := &Config{
		Address:    "localhost:8443",
		Protocol:   ProtocolREST,
		TLSEnabled: true,
		TLSCAFile:  caFile,
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	err = rc.Connect(context.Background())
	if err == nil {
		t.Error("Connect() should error with invalid CA content")
	}
}

func TestRESTClient_Connect_TLS_CertError(t *testing.T) {
	cfg := &Config{
		Address:     "localhost:8443",
		Protocol:    ProtocolREST,
		TLSEnabled:  true,
		TLSCertFile: "/nonexistent/cert.pem",
		TLSKeyFile:  "/nonexistent/key.pem",
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	err = rc.Connect(context.Background())
	if err == nil {
		t.Error("Connect() should error with nonexistent cert/key files")
	}
}

func TestRESTClient_JSONParseErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	mux.HandleFunc("/api/v1/backends", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/backends/software", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`invalid json`))
		} else {
			_, _ = w.Write([]byte(`invalid json`))
		}
	})

	mux.HandleFunc("/api/v1/keys/test-key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet, http.MethodDelete:
			_, _ = w.Write([]byte(`invalid json`))
		}
	})

	mux.HandleFunc("/api/v1/keys/test-key/sign", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/test-key/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/test-key/encrypt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/test-key/decrypt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/certs/test-key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/import", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/test-key/export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, _ := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	t.Run("ListBackends JSON parse error", func(t *testing.T) {
		_, err := rc.ListBackends(context.Background())
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetBackend JSON parse error", func(t *testing.T) {
		_, err := rc.GetBackend(context.Background(), "software")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GenerateKey JSON parse error", func(t *testing.T) {
		_, err := rc.GenerateKey(context.Background(), &GenerateKeyRequest{
			KeyID:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ListKeys JSON parse error", func(t *testing.T) {
		_, err := rc.ListKeys(context.Background(), "software")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetKey JSON parse error", func(t *testing.T) {
		_, err := rc.GetKey(context.Background(), "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("DeleteKey JSON parse error", func(t *testing.T) {
		_, err := rc.DeleteKey(context.Background(), "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Sign JSON parse error", func(t *testing.T) {
		_, err := rc.Sign(context.Background(), &SignRequest{
			KeyID:   "test-key",
			Backend: "software",
			Data:    json.RawMessage(`"test"`),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Verify JSON parse error", func(t *testing.T) {
		_, err := rc.Verify(context.Background(), &VerifyRequest{
			KeyID:     "test-key",
			Backend:   "software",
			Data:      json.RawMessage(`"test"`),
			Signature: json.RawMessage(`"sig"`),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Encrypt JSON parse error", func(t *testing.T) {
		_, err := rc.Encrypt(context.Background(), &EncryptRequest{
			KeyID:     "test-key",
			Backend:   "software",
			Plaintext: json.RawMessage(`"test"`),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Decrypt JSON parse error", func(t *testing.T) {
		_, err := rc.Decrypt(context.Background(), &DecryptRequest{
			KeyID:      "test-key",
			Backend:    "software",
			Ciphertext: json.RawMessage(`"test"`),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetCertificate JSON parse error", func(t *testing.T) {
		_, err := rc.GetCertificate(context.Background(), "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ImportKey JSON parse error", func(t *testing.T) {
		_, err := rc.ImportKey(context.Background(), &ImportKeyRequest{
			KeyID:              "test-key",
			Backend:            "software",
			WrappedKeyMaterial: []byte("test"),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ExportKey JSON parse error", func(t *testing.T) {
		_, err := rc.ExportKey(context.Background(), &ExportKeyRequest{
			KeyID:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}

func TestRESTClient_ErrorResponseMessage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	mux.HandleFunc("/api/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"bad request message"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, _ := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	_, err := rc.ListKeys(context.Background(), "software")
	if err == nil {
		t.Error("Expected error for bad request")
	}
	if !strings.Contains(err.Error(), "bad request message") {
		t.Errorf("Error should contain 'bad request message', got: %v", err)
	}
}

func TestRESTClient_ErrorResponseNoJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	mux.HandleFunc("/api/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`Internal Server Error`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, _ := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	_, err := rc.ListKeys(context.Background(), "software")
	if err == nil {
		t.Error("Expected error for server error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("Error should contain status code 500, got: %v", err)
	}
}

func TestRESTClient_RotateKey(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.RotateKey(context.Background(), &RotateKeyRequest{
		Backend: "software",
		KeyID:   "test-key",
	})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("RotateKey().KeyID = %v, want test-key", resp.KeyID)
	}
}

func TestRESTClient_GetImportParameters(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.GetImportParameters(context.Background(), &GetImportParametersRequest{
		Backend:   "software",
		Algorithm: "RSA_AES_KEY_WRAP_SHA_256",
	})
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}

	if len(resp.WrappingPublicKey) == 0 {
		t.Error("GetImportParameters().WrappingPublicKey is empty")
	}
}

func TestRESTClient_WrapKey(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.WrapKey(context.Background(), &WrapKeyRequest{
		Backend:     "software",
		Algorithm:   "AES-KWP",
		KeyMaterial: []byte("test-key-material"),
	})
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}

	if len(resp.WrappedKeyMaterial) == 0 {
		t.Error("WrapKey().WrappedKeyMaterial is empty")
	}
}

func TestRESTClient_UnwrapKey(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.UnwrapKey(context.Background(), &UnwrapKeyRequest{
		Backend:            "software",
		Algorithm:          "AES-KWP",
		WrappedKeyMaterial: []byte("wrapped-key"),
	})
	if err != nil {
		t.Fatalf("UnwrapKey() error = %v", err)
	}

	if len(resp.KeyMaterial) == 0 {
		t.Error("UnwrapKey().KeyMaterial is empty")
	}
}

func TestRESTClient_CopyKey(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.CopyKey(context.Background(), &CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "test-key",
		DestBackend:   "tpm2",
		DestKeyID:     "copied-key",
	})
	if err != nil {
		t.Fatalf("CopyKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("CopyKey().Success = false, want true")
	}
}

func TestRESTClient_ListCertificates(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.ListCertificates(context.Background(), "software")
	if err != nil {
		t.Fatalf("ListCertificates() error = %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("ListCertificates() count = %d, want 2", len(resp.Certificates))
	}
}

func TestRESTClient_SaveCertificateChain(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	err = rc.SaveCertificateChain(context.Background(), &SaveCertificateChainRequest{
		Backend: "software",
		KeyID:   "test-key",
		ChainPEM: []string{
			"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----",
		},
	})
	if err != nil {
		t.Fatalf("SaveCertificateChain() error = %v", err)
	}
}

func TestRESTClient_GetCertificateChain(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.GetCertificateChain(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("GetCertificateChain() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetCertificateChain().KeyID = %v, want test-key", resp.KeyID)
	}
	if len(resp.ChainPEM) != 2 {
		t.Errorf("GetCertificateChain().ChainPEM count = %d, want 2", len(resp.ChainPEM))
	}
}

func TestRESTClient_GetTLSCertificate(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.GetTLSCertificate(context.Background(), "software", "test-key")
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

func TestRESTClient_EncryptAsym(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	plaintext, _ := json.Marshal([]byte("test data"))
	resp, err := rc.EncryptAsym(context.Background(), &EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Plaintext: plaintext,
		Hash:      "SHA256",
	})
	if err != nil {
		t.Fatalf("EncryptAsym() error = %v", err)
	}

	if len(resp.Ciphertext) == 0 {
		t.Error("EncryptAsym().Ciphertext is empty")
	}
}

func TestRESTClient_NewMethodsJSONParseErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
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

	mux.HandleFunc("/api/v1/keys/test-key/rotate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/test-key/encrypt-asym", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/certs/test-key/chain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/tls/test-key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, _ := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	t.Run("RotateKey JSON parse error", func(t *testing.T) {
		_, err := rc.RotateKey(context.Background(), &RotateKeyRequest{
			Backend: "software",
			KeyID:   "test-key",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetImportParameters JSON parse error", func(t *testing.T) {
		_, err := rc.GetImportParameters(context.Background(), &GetImportParametersRequest{
			Backend:   "software",
			Algorithm: "RSA_AES_KEY_WRAP_SHA_256",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("WrapKey JSON parse error", func(t *testing.T) {
		_, err := rc.WrapKey(context.Background(), &WrapKeyRequest{
			Backend:     "software",
			KeyMaterial: []byte("test"),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("UnwrapKey JSON parse error", func(t *testing.T) {
		_, err := rc.UnwrapKey(context.Background(), &UnwrapKeyRequest{
			Backend:            "software",
			WrappedKeyMaterial: []byte("test"),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("CopyKey JSON parse error", func(t *testing.T) {
		_, err := rc.CopyKey(context.Background(), &CopyKeyRequest{
			SourceBackend: "software",
			SourceKeyID:   "test-key",
			DestBackend:   "tpm2",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ListCertificates JSON parse error", func(t *testing.T) {
		_, err := rc.ListCertificates(context.Background(), "software")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetCertificateChain JSON parse error", func(t *testing.T) {
		_, err := rc.GetCertificateChain(context.Background(), "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetTLSCertificate JSON parse error", func(t *testing.T) {
		_, err := rc.GetTLSCertificate(context.Background(), "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("EncryptAsym JSON parse error", func(t *testing.T) {
		plaintext, _ := json.Marshal([]byte("test"))
		_, err := rc.EncryptAsym(context.Background(), &EncryptAsymRequest{
			Backend:   "software",
			KeyID:     "test-key",
			Plaintext: plaintext,
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}

func TestRESTClient_ListKeyVersions(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.ListKeyVersions(context.Background(), &ListKeyVersionsRequest{
		Backend: "software",
		KeyID:   "test-key",
	})
	if err != nil {
		t.Fatalf("ListKeyVersions() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("ListKeyVersions().KeyID = %v, want test-key", resp.KeyID)
	}
	if len(resp.Versions) != 3 {
		t.Errorf("ListKeyVersions() version count = %d, want 3", len(resp.Versions))
	}
}

func TestRESTClient_EnableKeyVersion(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.EnableKeyVersion(context.Background(), &EnableKeyVersionRequest{
		Backend: "software",
		KeyID:   "test-key",
		Version: 1,
	})
	if err != nil {
		t.Fatalf("EnableKeyVersion() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("EnableKeyVersion().KeyID = %v, want test-key", resp.KeyID)
	}
	if resp.Status != "enabled" {
		t.Errorf("EnableKeyVersion().Status = %v, want enabled", resp.Status)
	}
}

func TestRESTClient_DisableKeyVersion(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.DisableKeyVersion(context.Background(), &DisableKeyVersionRequest{
		Backend: "software",
		KeyID:   "test-key",
		Version: 1,
	})
	if err != nil {
		t.Fatalf("DisableKeyVersion() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("DisableKeyVersion().KeyID = %v, want test-key", resp.KeyID)
	}
	if resp.Status != "disabled" {
		t.Errorf("DisableKeyVersion().Status = %v, want disabled", resp.Status)
	}
}

func TestRESTClient_EnableAllKeyVersions(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.EnableAllKeyVersions(context.Background(), &EnableAllKeyVersionsRequest{
		Backend: "software",
		KeyID:   "test-key",
	})
	if err != nil {
		t.Fatalf("EnableAllKeyVersions() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("EnableAllKeyVersions().KeyID = %v, want test-key", resp.KeyID)
	}
	if resp.Count != 3 {
		t.Errorf("EnableAllKeyVersions().Count = %d, want 3", resp.Count)
	}
}

func TestRESTClient_DisableAllKeyVersions(t *testing.T) {
	server := mockRESTServer(t)
	defer server.Close()

	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  server.URL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)
	_ = rc.Connect(context.Background())

	resp, err := rc.DisableAllKeyVersions(context.Background(), &DisableAllKeyVersionsRequest{
		Backend: "software",
		KeyID:   "test-key",
	})
	if err != nil {
		t.Fatalf("DisableAllKeyVersions() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("DisableAllKeyVersions().KeyID = %v, want test-key", resp.KeyID)
	}
	if resp.Count != 3 {
		t.Errorf("DisableAllKeyVersions().Count = %d, want 3", resp.Count)
	}
}

func TestRESTClient_NotConnected_KeyVersions(t *testing.T) {
	client, err := New(&Config{
		Protocol: ProtocolREST,
		Address:  "http://localhost:9999",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rc := client.(*restClient)

	t.Run("ListKeyVersions not connected", func(t *testing.T) {
		_, err := rc.ListKeyVersions(context.Background(), &ListKeyVersionsRequest{
			Backend: "software",
			KeyID:   "test-key",
		})
		if err != ErrNotConnected {
			t.Errorf("ListKeyVersions() error = %v, want ErrNotConnected", err)
		}
	})

	t.Run("EnableKeyVersion not connected", func(t *testing.T) {
		_, err := rc.EnableKeyVersion(context.Background(), &EnableKeyVersionRequest{
			Backend: "software",
			KeyID:   "test-key",
			Version: 1,
		})
		if err != ErrNotConnected {
			t.Errorf("EnableKeyVersion() error = %v, want ErrNotConnected", err)
		}
	})

	t.Run("DisableKeyVersion not connected", func(t *testing.T) {
		_, err := rc.DisableKeyVersion(context.Background(), &DisableKeyVersionRequest{
			Backend: "software",
			KeyID:   "test-key",
			Version: 1,
		})
		if err != ErrNotConnected {
			t.Errorf("DisableKeyVersion() error = %v, want ErrNotConnected", err)
		}
	})

	t.Run("EnableAllKeyVersions not connected", func(t *testing.T) {
		_, err := rc.EnableAllKeyVersions(context.Background(), &EnableAllKeyVersionsRequest{
			Backend: "software",
			KeyID:   "test-key",
		})
		if err != ErrNotConnected {
			t.Errorf("EnableAllKeyVersions() error = %v, want ErrNotConnected", err)
		}
	})

	t.Run("DisableAllKeyVersions not connected", func(t *testing.T) {
		_, err := rc.DisableAllKeyVersions(context.Background(), &DisableAllKeyVersionsRequest{
			Backend: "software",
			KeyID:   "test-key",
		})
		if err != ErrNotConnected {
			t.Errorf("DisableAllKeyVersions() error = %v, want ErrNotConnected", err)
		}
	})
}
