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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockUnixServer creates a test Unix socket server
func mockUnixServer(t *testing.T) (string, func()) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "keychain-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	socketPath := filepath.Join(tmpDir, "test.sock")

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
			_, _ = w.Write([]byte(`{"keys":[{"key_id":"test-key","key_type":"RSA","backend":"software"}]}`))
		case http.MethodPost:
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

	// Get/Delete/Sign/Verify/Encrypt/Decrypt/Export/Rotate key
	mux.HandleFunc("/api/v1/keys/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		if strings.Contains(path, "/sign") {
			_, _ = w.Write([]byte(`{"signature":"c2lnbmF0dXJl"}`))
			return
		}
		if strings.Contains(path, "/verify") {
			_, _ = w.Write([]byte(`{"valid":true,"message":"signature verified"}`))
			return
		}
		if strings.Contains(path, "/encrypt-asym") {
			_, _ = w.Write([]byte(`{"ciphertext":"YXN5bS1jaXBoZXJ0ZXh0"}`))
			return
		}
		if strings.Contains(path, "/encrypt") {
			_, _ = w.Write([]byte(`{"ciphertext":"Y2lwaGVydGV4dA==","nonce":"bm9uY2U=","tag":"dGFn"}`))
			return
		}
		if strings.Contains(path, "/decrypt") {
			_, _ = w.Write([]byte(`{"plaintext":"cGxhaW50ZXh0"}`))
			return
		}
		if strings.Contains(path, "/export") {
			_, _ = w.Write([]byte(`{"key_id":"test-key","wrapped_key":"d3JhcHBlZA==","algorithm":"AES-KWP"}`))
			return
		}
		if strings.Contains(path, "/rotate") {
			_, _ = w.Write([]byte(`{"key_id":"test-key","public_key_pem":"-----BEGIN PUBLIC KEY-----\nrotated\n-----END PUBLIC KEY-----"}`))
			return
		}

		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"key_id":"test-key","key_type":"RSA","backend":"software"}`))
		case http.MethodDelete:
			_, _ = w.Write([]byte(`{"success":true,"message":"key deleted"}`))
		}
	})

	// Import key
	mux.HandleFunc("/api/v1/keys/import", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"key_id":"imported-key","message":"key imported"}`))
	})

	// Certificates
	mux.HandleFunc("/api/v1/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"certificates":[{"key_id":"cert-1"},{"key_id":"cert-2"}]}`))
		case http.MethodPost:
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
			_, _ = w.Write([]byte(`{"key_id":"test-key","certificate_pem":"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		}
	})

	// TLS endpoint
	mux.HandleFunc("/api/v1/tls/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"test-key","private_key_pem":"-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----","certificate_pem":"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----","chain_pem":"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"}`))
	})

	// Create Unix socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create Unix socket: %v", err)
	}

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()

	cleanup := func() {
		_ = server.Close()
		_ = listener.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return socketPath, cleanup
}

func TestUnixClient_Connect(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)

	err = uc.Connect(context.Background())
	if err != nil {
		t.Errorf("Connect() error = %v", err)
	}

	if !uc.connected {
		t.Error("Expected connected = true")
	}
}

func TestUnixClient_Close(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	err = uc.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if uc.connected {
		t.Error("Expected connected = false after Close")
	}
}

func TestUnixClient_Health(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("Health() status = %v, want healthy", resp.Status)
	}
}

func TestUnixClient_ListBackends(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.ListBackends(context.Background())
	if err != nil {
		t.Fatalf("ListBackends() error = %v", err)
	}

	if len(resp.Backends) != 1 {
		t.Errorf("ListBackends() count = %d, want 1", len(resp.Backends))
	}
}

func TestUnixClient_GetBackend(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.GetBackend(context.Background(), "software")
	if err != nil {
		t.Fatalf("GetBackend() error = %v", err)
	}

	if resp.ID != "software" {
		t.Errorf("GetBackend().ID = %v, want software", resp.ID)
	}
}

func TestUnixClient_GenerateKey(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.GenerateKey(context.Background(), &GenerateKeyRequest{
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
}

func TestUnixClient_ListKeys(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.ListKeys(context.Background(), "software")
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	if len(resp.Keys) != 1 {
		t.Errorf("ListKeys() count = %d, want 1", len(resp.Keys))
	}
}

func TestUnixClient_GetKey(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.GetKey(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetKey().KeyID = %v, want test-key", resp.KeyID)
	}
}

func TestUnixClient_DeleteKey(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.DeleteKey(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("DeleteKey().Success = false, want true")
	}
}

func TestUnixClient_Sign(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	data, _ := json.Marshal([]byte("test data"))
	resp, err := uc.Sign(context.Background(), &SignRequest{
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

func TestUnixClient_Verify(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	data, _ := json.Marshal([]byte("test data"))
	sig, _ := json.Marshal([]byte("signature"))
	resp, err := uc.Verify(context.Background(), &VerifyRequest{
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

func TestUnixClient_Encrypt(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	plaintext, _ := json.Marshal([]byte("test data"))
	resp, err := uc.Encrypt(context.Background(), &EncryptRequest{
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

func TestUnixClient_Decrypt(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	ciphertext, _ := json.Marshal([]byte("ciphertext"))
	resp, err := uc.Decrypt(context.Background(), &DecryptRequest{
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

func TestUnixClient_GetCertificate(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.GetCertificate(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetCertificate().KeyID = %v, want test-key", resp.KeyID)
	}
}

func TestUnixClient_SaveCertificate(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	err = uc.SaveCertificate(context.Background(), &SaveCertificateRequest{
		Backend:        "software",
		KeyID:          "test-key",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	})
	if err != nil {
		t.Fatalf("SaveCertificate() error = %v", err)
	}
}

func TestUnixClient_DeleteCertificate(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	err = uc.DeleteCertificate(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("DeleteCertificate() error = %v", err)
	}
}

func TestUnixClient_ImportKey(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	wrappedKey, _ := json.Marshal([]byte("wrapped-key-data"))
	resp, err := uc.ImportKey(context.Background(), &ImportKeyRequest{
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

func TestUnixClient_ExportKey(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.ExportKey(context.Background(), &ExportKeyRequest{
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

func TestUnixClient_RotateKey(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.RotateKey(context.Background(), &RotateKeyRequest{
		Backend: "software",
		KeyID:   "test-key",
	})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("RotateKey().KeyID = %v, want test-key", resp.KeyID)
	}
	if resp.PublicKeyPEM == "" {
		t.Error("RotateKey().PublicKeyPEM is empty")
	}
}

func TestUnixClient_GetImportParameters(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.GetImportParameters(context.Background(), &GetImportParametersRequest{
		Backend:   "software",
		Algorithm: "RSA_AES_KEY_WRAP_SHA_256",
	})
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}

	if len(resp.WrappingPublicKey) == 0 {
		t.Error("GetImportParameters().WrappingPublicKey is empty")
	}
	if len(resp.ImportToken) == 0 {
		t.Error("GetImportParameters().ImportToken is empty")
	}
}

func TestUnixClient_WrapKey(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.WrapKey(context.Background(), &WrapKeyRequest{
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

func TestUnixClient_UnwrapKey(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.UnwrapKey(context.Background(), &UnwrapKeyRequest{
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

func TestUnixClient_CopyKey(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.CopyKey(context.Background(), &CopyKeyRequest{
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

func TestUnixClient_ListCertificates(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.ListCertificates(context.Background(), "software")
	if err != nil {
		t.Fatalf("ListCertificates() error = %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("ListCertificates() count = %d, want 2", len(resp.Certificates))
	}
}

func TestUnixClient_SaveCertificateChain(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	err = uc.SaveCertificateChain(context.Background(), &SaveCertificateChainRequest{
		Backend: "software",
		KeyID:   "test-key",
		ChainPEM: []string{
			"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----",
			"-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----",
		},
	})
	if err != nil {
		t.Fatalf("SaveCertificateChain() error = %v", err)
	}
}

func TestUnixClient_GetCertificateChain(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.GetCertificateChain(context.Background(), "software", "test-key")
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

func TestUnixClient_GetTLSCertificate(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	resp, err := uc.GetTLSCertificate(context.Background(), "software", "test-key")
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

func TestUnixClient_EncryptAsym(t *testing.T) {
	socketPath, cleanup := mockUnixServer(t)
	defer cleanup()

	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	plaintext, _ := json.Marshal([]byte("test data"))
	resp, err := uc.EncryptAsym(context.Background(), &EncryptAsymRequest{
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

func TestUnixClient_NotConnected(t *testing.T) {
	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  "/tmp/nonexistent.sock",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	// Don't connect

	_, err = uc.Health(context.Background())
	if err != ErrNotConnected {
		t.Errorf("Health() error = %v, want ErrNotConnected", err)
	}

	_, err = uc.ListBackends(context.Background())
	if err != ErrNotConnected {
		t.Errorf("ListBackends() error = %v, want ErrNotConnected", err)
	}
}

func TestUnixClient_ConnectionFailed(t *testing.T) {
	client, err := New(&Config{
		Protocol: ProtocolUnix,
		Address:  "/tmp/nonexistent.sock",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	uc := client.(*unixClient)
	err = uc.Connect(context.Background())

	if err == nil {
		t.Error("Expected connection error")
	}
}

func TestUnixClient_Headers(t *testing.T) {
	var receivedHeaders http.Header

	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "keychain-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create Unix socket: %v", err)
	}
	defer func() { _ = listener.Close() }()

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	defer func() { _ = server.Close() }()

	client, _ := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
		JWTToken: "test-jwt-token",
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
		},
	})

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	_, _ = uc.Health(context.Background())

	if receivedHeaders.Get("Authorization") != "Bearer test-jwt-token" {
		t.Errorf("Authorization = %v, want Bearer test-jwt-token", receivedHeaders.Get("Authorization"))
	}
	if receivedHeaders.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("X-Custom-Header = %v, want custom-value", receivedHeaders.Get("X-Custom-Header"))
	}
}

func TestUnixClient_JSONParseErrors(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "keychain-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

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

	mux.HandleFunc("/api/v1/keys/test-key/rotate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/keys/test-key/encrypt-asym", func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("/api/v1/certs/test-key/chain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	mux.HandleFunc("/api/v1/tls/test-key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	})

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create Unix socket: %v", err)
	}
	defer func() { _ = listener.Close() }()

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	defer func() { _ = server.Close() }()

	client, _ := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	t.Run("ListBackends JSON parse error", func(t *testing.T) {
		_, err := uc.ListBackends(context.Background())
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetBackend JSON parse error", func(t *testing.T) {
		_, err := uc.GetBackend(context.Background(), "software")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GenerateKey JSON parse error", func(t *testing.T) {
		_, err := uc.GenerateKey(context.Background(), &GenerateKeyRequest{
			KeyID:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ListKeys JSON parse error", func(t *testing.T) {
		_, err := uc.ListKeys(context.Background(), "software")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetKey JSON parse error", func(t *testing.T) {
		_, err := uc.GetKey(context.Background(), "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("DeleteKey JSON parse error", func(t *testing.T) {
		_, err := uc.DeleteKey(context.Background(), "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Sign JSON parse error", func(t *testing.T) {
		_, err := uc.Sign(context.Background(), &SignRequest{
			KeyID:   "test-key",
			Backend: "software",
			Data:    json.RawMessage(`"test"`),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Verify JSON parse error", func(t *testing.T) {
		_, err := uc.Verify(context.Background(), &VerifyRequest{
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
		_, err := uc.Encrypt(context.Background(), &EncryptRequest{
			KeyID:     "test-key",
			Backend:   "software",
			Plaintext: json.RawMessage(`"test"`),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Decrypt JSON parse error", func(t *testing.T) {
		_, err := uc.Decrypt(context.Background(), &DecryptRequest{
			KeyID:      "test-key",
			Backend:    "software",
			Ciphertext: json.RawMessage(`"test"`),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetCertificate JSON parse error", func(t *testing.T) {
		_, err := uc.GetCertificate(context.Background(), "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ImportKey JSON parse error", func(t *testing.T) {
		_, err := uc.ImportKey(context.Background(), &ImportKeyRequest{
			KeyID:              "test-key",
			Backend:            "software",
			WrappedKeyMaterial: []byte("test"),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ExportKey JSON parse error", func(t *testing.T) {
		_, err := uc.ExportKey(context.Background(), &ExportKeyRequest{
			KeyID:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("RotateKey JSON parse error", func(t *testing.T) {
		_, err := uc.RotateKey(context.Background(), &RotateKeyRequest{
			Backend: "software",
			KeyID:   "test-key",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetImportParameters JSON parse error", func(t *testing.T) {
		_, err := uc.GetImportParameters(context.Background(), &GetImportParametersRequest{
			Backend:   "software",
			Algorithm: "RSA_AES_KEY_WRAP_SHA_256",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("WrapKey JSON parse error", func(t *testing.T) {
		_, err := uc.WrapKey(context.Background(), &WrapKeyRequest{
			Backend:     "software",
			KeyMaterial: []byte("test"),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("UnwrapKey JSON parse error", func(t *testing.T) {
		_, err := uc.UnwrapKey(context.Background(), &UnwrapKeyRequest{
			Backend:            "software",
			WrappedKeyMaterial: []byte("test"),
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("CopyKey JSON parse error", func(t *testing.T) {
		_, err := uc.CopyKey(context.Background(), &CopyKeyRequest{
			SourceBackend: "software",
			SourceKeyID:   "test-key",
			DestBackend:   "tpm2",
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("ListCertificates JSON parse error", func(t *testing.T) {
		_, err := uc.ListCertificates(context.Background(), "software")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetCertificateChain JSON parse error", func(t *testing.T) {
		_, err := uc.GetCertificateChain(context.Background(), "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("GetTLSCertificate JSON parse error", func(t *testing.T) {
		_, err := uc.GetTLSCertificate(context.Background(), "software", "test-key")
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("EncryptAsym JSON parse error", func(t *testing.T) {
		plaintext, _ := json.Marshal([]byte("test"))
		_, err := uc.EncryptAsym(context.Background(), &EncryptAsymRequest{
			Backend:   "software",
			KeyID:     "test-key",
			Plaintext: plaintext,
		})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}

func TestUnixClient_KeyVersionManagement(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "keychain-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	mux := http.NewServeMux()

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	// ListKeyVersions
	mux.HandleFunc("/api/v1/keys/test-key/versions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"test-key","versions":[{"version":1,"status":"enabled","created_at":"2025-01-01T00:00:00Z"},{"version":2,"status":"disabled","created_at":"2025-01-02T00:00:00Z"}],"total":2}`))
	})

	// EnableKeyVersion
	mux.HandleFunc("/api/v1/keys/test-key/versions/2/enable", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"test-key","version":2,"status":"enabled"}`))
	})

	// DisableKeyVersion
	mux.HandleFunc("/api/v1/keys/test-key/versions/1/disable", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"test-key","version":1,"status":"disabled"}`))
	})

	// EnableAllKeyVersions
	mux.HandleFunc("/api/v1/keys/test-key/versions/enable-all", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"test-key","count":2,"message":"all versions enabled"}`))
	})

	// DisableAllKeyVersions
	mux.HandleFunc("/api/v1/keys/test-key/versions/disable-all", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"test-key","count":2,"message":"all versions disabled"}`))
	})

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create Unix socket: %v", err)
	}
	defer func() { _ = listener.Close() }()

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	defer func() { _ = server.Close() }()

	client, _ := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	t.Run("ListKeyVersions", func(t *testing.T) {
		resp, err := uc.ListKeyVersions(context.Background(), &ListKeyVersionsRequest{
			Backend: "software",
			KeyID:   "test-key",
		})
		if err != nil {
			t.Fatalf("ListKeyVersions() error = %v", err)
		}
		if resp.KeyID != "test-key" {
			t.Errorf("ListKeyVersions().KeyID = %v, want test-key", resp.KeyID)
		}
		if resp.Total != 2 {
			t.Errorf("ListKeyVersions().Total = %d, want 2", resp.Total)
		}
		if len(resp.Versions) != 2 {
			t.Errorf("ListKeyVersions() versions count = %d, want 2", len(resp.Versions))
		}
		if resp.Versions[0].Version != 1 {
			t.Errorf("ListKeyVersions().Versions[0].Version = %d, want 1", resp.Versions[0].Version)
		}
		if resp.Versions[0].Status != "enabled" {
			t.Errorf("ListKeyVersions().Versions[0].Status = %s, want enabled", resp.Versions[0].Status)
		}
	})

	t.Run("EnableKeyVersion", func(t *testing.T) {
		resp, err := uc.EnableKeyVersion(context.Background(), &EnableKeyVersionRequest{
			Backend: "software",
			KeyID:   "test-key",
			Version: 2,
		})
		if err != nil {
			t.Fatalf("EnableKeyVersion() error = %v", err)
		}
		if resp.KeyID != "test-key" {
			t.Errorf("EnableKeyVersion().KeyID = %v, want test-key", resp.KeyID)
		}
		if resp.Version != 2 {
			t.Errorf("EnableKeyVersion().Version = %d, want 2", resp.Version)
		}
		if resp.Status != "enabled" {
			t.Errorf("EnableKeyVersion().Status = %s, want enabled", resp.Status)
		}
	})

	t.Run("DisableKeyVersion", func(t *testing.T) {
		resp, err := uc.DisableKeyVersion(context.Background(), &DisableKeyVersionRequest{
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
		if resp.Version != 1 {
			t.Errorf("DisableKeyVersion().Version = %d, want 1", resp.Version)
		}
		if resp.Status != "disabled" {
			t.Errorf("DisableKeyVersion().Status = %s, want disabled", resp.Status)
		}
	})

	t.Run("EnableAllKeyVersions", func(t *testing.T) {
		resp, err := uc.EnableAllKeyVersions(context.Background(), &EnableAllKeyVersionsRequest{
			Backend: "software",
			KeyID:   "test-key",
		})
		if err != nil {
			t.Fatalf("EnableAllKeyVersions() error = %v", err)
		}
		if resp.KeyID != "test-key" {
			t.Errorf("EnableAllKeyVersions().KeyID = %v, want test-key", resp.KeyID)
		}
		if resp.Count != 2 {
			t.Errorf("EnableAllKeyVersions().Count = %d, want 2", resp.Count)
		}
		if resp.Message != "all versions enabled" {
			t.Errorf("EnableAllKeyVersions().Message = %s, want all versions enabled", resp.Message)
		}
	})

	t.Run("DisableAllKeyVersions", func(t *testing.T) {
		resp, err := uc.DisableAllKeyVersions(context.Background(), &DisableAllKeyVersionsRequest{
			Backend: "software",
			KeyID:   "test-key",
		})
		if err != nil {
			t.Fatalf("DisableAllKeyVersions() error = %v", err)
		}
		if resp.KeyID != "test-key" {
			t.Errorf("DisableAllKeyVersions().KeyID = %v, want test-key", resp.KeyID)
		}
		if resp.Count != 2 {
			t.Errorf("DisableAllKeyVersions().Count = %d, want 2", resp.Count)
		}
		if resp.Message != "all versions disabled" {
			t.Errorf("DisableAllKeyVersions().Message = %s, want all versions disabled", resp.Message)
		}
	})
}

func TestUnixClient_ErrorResponseHandling(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "keychain-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test.sock")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	mux.HandleFunc("/api/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
	})

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create Unix socket: %v", err)
	}
	defer func() { _ = listener.Close() }()

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	defer func() { _ = server.Close() }()

	client, _ := New(&Config{
		Protocol: ProtocolUnix,
		Address:  socketPath,
	})

	uc := client.(*unixClient)
	_ = uc.Connect(context.Background())

	_, err = uc.ListKeys(context.Background(), "software")
	if err == nil {
		t.Error("Expected error for bad request")
	}
	if !strings.Contains(err.Error(), "bad request") {
		t.Errorf("Error should contain 'bad request', got: %v", err)
	}
}
