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
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"google.golang.org/grpc"
)

// setupTestUnixServer creates a test gRPC server listening on a Unix socket
func setupTestUnixServer(t *testing.T) (string, *grpc.Server) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "unix-grpc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	socketPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to listen on Unix socket: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(grpcServer, &mockKeystoreServer{})

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	t.Cleanup(func() {
		grpcServer.Stop()
		_ = os.RemoveAll(tmpDir)
	})

	return socketPath, grpcServer
}

func TestNewUnixGRPCClient(t *testing.T) {
	cfg := &Config{
		Address:  "/tmp/test.sock",
		Protocol: ProtocolUnixGRPC,
	}

	client, err := newUnixGRPCClient(cfg)
	if err != nil {
		t.Fatalf("newUnixGRPCClient() error = %v", err)
	}

	if client == nil {
		t.Fatal("newUnixGRPCClient() returned nil")
	}

	if client.config != cfg {
		t.Error("client.config does not match input config")
	}
}

func TestUnixGRPCClient_Connect(t *testing.T) {
	socketPath, _ := setupTestUnixServer(t)

	cfg := &Config{
		Address:  socketPath,
		Protocol: ProtocolUnixGRPC,
	}

	client, err := newUnixGRPCClient(cfg)
	if err != nil {
		t.Fatalf("newUnixGRPCClient() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		t.Errorf("Connect() error = %v", err)
	}

	if !client.connected {
		t.Error("client.connected should be true after successful Connect()")
	}

	// Clean up
	err = client.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestUnixGRPCClient_Connect_NonexistentSocket(t *testing.T) {
	cfg := &Config{
		Address:  "/tmp/nonexistent-socket-12345.sock",
		Protocol: ProtocolUnixGRPC,
	}

	client, err := newUnixGRPCClient(cfg)
	if err != nil {
		t.Fatalf("newUnixGRPCClient() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err == nil {
		t.Error("Connect() should error with nonexistent socket")
	}

	if client.connected {
		t.Error("client.connected should be false after failed Connect()")
	}
}

func TestUnixGRPCClient_NotConnected(t *testing.T) {
	cfg := &Config{
		Address:  "/tmp/test.sock",
		Protocol: ProtocolUnixGRPC,
	}

	client, err := newUnixGRPCClient(cfg)
	if err != nil {
		t.Fatalf("newUnixGRPCClient() error = %v", err)
	}

	ctx := context.Background()

	t.Run("Health returns error when not connected", func(t *testing.T) {
		_, err := client.Health(ctx)
		if err != ErrNotConnected {
			t.Errorf("Health() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("ListBackends returns error when not connected", func(t *testing.T) {
		_, err := client.ListBackends(ctx)
		if err != ErrNotConnected {
			t.Errorf("ListBackends() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("GetBackend returns error when not connected", func(t *testing.T) {
		_, err := client.GetBackend(ctx, "test-backend")
		if err != ErrNotConnected {
			t.Errorf("GetBackend() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("GenerateKey returns error when not connected", func(t *testing.T) {
		_, err := client.GenerateKey(ctx, &GenerateKeyRequest{
			KeyID:   "test-key",
			Backend: "test-backend",
		})
		if err != ErrNotConnected {
			t.Errorf("GenerateKey() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("ListKeys returns error when not connected", func(t *testing.T) {
		_, err := client.ListKeys(ctx, "test-backend")
		if err != ErrNotConnected {
			t.Errorf("ListKeys() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("GetKey returns error when not connected", func(t *testing.T) {
		_, err := client.GetKey(ctx, "test-backend", "test-key")
		if err != ErrNotConnected {
			t.Errorf("GetKey() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("DeleteKey returns error when not connected", func(t *testing.T) {
		_, err := client.DeleteKey(ctx, "test-backend", "test-key")
		if err != ErrNotConnected {
			t.Errorf("DeleteKey() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("Sign returns error when not connected", func(t *testing.T) {
		_, err := client.Sign(ctx, &SignRequest{
			KeyID:   "test-key",
			Backend: "test-backend",
			Data:    json.RawMessage(`"dGVzdA=="`),
		})
		if err != ErrNotConnected {
			t.Errorf("Sign() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("Verify returns error when not connected", func(t *testing.T) {
		_, err := client.Verify(ctx, &VerifyRequest{
			KeyID:     "test-key",
			Backend:   "test-backend",
			Data:      json.RawMessage(`"dGVzdA=="`),
			Signature: json.RawMessage(`"c2ln"`),
		})
		if err != ErrNotConnected {
			t.Errorf("Verify() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("Encrypt returns error when not connected", func(t *testing.T) {
		_, err := client.Encrypt(ctx, &EncryptRequest{
			KeyID:     "test-key",
			Backend:   "test-backend",
			Plaintext: json.RawMessage(`"dGVzdA=="`),
		})
		if err != ErrNotConnected {
			t.Errorf("Encrypt() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("Decrypt returns error when not connected", func(t *testing.T) {
		_, err := client.Decrypt(ctx, &DecryptRequest{
			KeyID:      "test-key",
			Backend:    "test-backend",
			Ciphertext: json.RawMessage(`"Y2lwaGVy"`),
		})
		if err != ErrNotConnected {
			t.Errorf("Decrypt() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("GetCertificate returns error when not connected", func(t *testing.T) {
		_, err := client.GetCertificate(ctx, "test-backend", "test-key")
		if err != ErrNotConnected {
			t.Errorf("GetCertificate() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("SaveCertificate returns error when not connected", func(t *testing.T) {
		err := client.SaveCertificate(ctx, &SaveCertificateRequest{
			KeyID:          "test-key",
			CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		})
		if err != ErrNotConnected {
			t.Errorf("SaveCertificate() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("DeleteCertificate returns error when not connected", func(t *testing.T) {
		err := client.DeleteCertificate(ctx, "test-backend", "test-key")
		if err != ErrNotConnected {
			t.Errorf("DeleteCertificate() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("ImportKey returns error when not connected", func(t *testing.T) {
		_, err := client.ImportKey(ctx, &ImportKeyRequest{
			KeyID:              "test-key",
			Backend:            "test-backend",
			WrappedKeyMaterial: []byte("wrapped-key-data"),
		})
		if err != ErrNotConnected {
			t.Errorf("ImportKey() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("ExportKey returns error when not connected", func(t *testing.T) {
		_, err := client.ExportKey(ctx, &ExportKeyRequest{
			KeyID:   "test-key",
			Backend: "test-backend",
		})
		if err != ErrNotConnected {
			t.Errorf("ExportKey() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("RotateKey returns error when not connected", func(t *testing.T) {
		_, err := client.RotateKey(ctx, &RotateKeyRequest{
			KeyID:   "test-key",
			Backend: "test-backend",
		})
		if err != ErrNotConnected {
			t.Errorf("RotateKey() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("GetImportParameters returns error when not connected", func(t *testing.T) {
		_, err := client.GetImportParameters(ctx, &GetImportParametersRequest{
			Backend: "test-backend",
		})
		if err != ErrNotConnected {
			t.Errorf("GetImportParameters() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("WrapKey returns error when not connected", func(t *testing.T) {
		_, err := client.WrapKey(ctx, &WrapKeyRequest{
			Backend:     "test-backend",
			KeyMaterial: []byte("test"),
		})
		if err != ErrNotConnected {
			t.Errorf("WrapKey() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("UnwrapKey returns error when not connected", func(t *testing.T) {
		_, err := client.UnwrapKey(ctx, &UnwrapKeyRequest{
			Backend:            "test-backend",
			WrappedKeyMaterial: []byte("test"),
		})
		if err != ErrNotConnected {
			t.Errorf("UnwrapKey() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("CopyKey returns error when not connected", func(t *testing.T) {
		_, err := client.CopyKey(ctx, &CopyKeyRequest{
			SourceBackend: "test-backend",
			SourceKeyID:   "test-key",
		})
		if err != ErrNotConnected {
			t.Errorf("CopyKey() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("ListCertificates returns error when not connected", func(t *testing.T) {
		_, err := client.ListCertificates(ctx, "test-backend")
		if err != ErrNotConnected {
			t.Errorf("ListCertificates() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("SaveCertificateChain returns error when not connected", func(t *testing.T) {
		err := client.SaveCertificateChain(ctx, &SaveCertificateChainRequest{
			KeyID:    "test-key",
			Backend:  "test-backend",
			ChainPEM: []string{"cert"},
		})
		if err != ErrNotConnected {
			t.Errorf("SaveCertificateChain() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("GetCertificateChain returns error when not connected", func(t *testing.T) {
		_, err := client.GetCertificateChain(ctx, "test-backend", "test-key")
		if err != ErrNotConnected {
			t.Errorf("GetCertificateChain() error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("GetTLSCertificate returns error when not connected", func(t *testing.T) {
		_, err := client.GetTLSCertificate(ctx, "test-backend", "test-key")
		if err != ErrNotConnected {
			t.Errorf("GetTLSCertificate() error = %v, want %v", err, ErrNotConnected)
		}
	})
}

func TestUnixGRPCClient_Operations(t *testing.T) {
	socketPath, _ := setupTestUnixServer(t)

	cfg := &Config{
		Address:  socketPath,
		Protocol: ProtocolUnixGRPC,
	}

	client, err := newUnixGRPCClient(cfg)
	if err != nil {
		t.Fatalf("newUnixGRPCClient() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	t.Run("Health", func(t *testing.T) {
		resp, err := client.Health(ctx)
		if err != nil {
			t.Errorf("Health() error = %v", err)
		}
		if resp.Status != "healthy" {
			t.Errorf("Health() status = %q, want %q", resp.Status, "healthy")
		}
		if resp.Version != "1.0.0" {
			t.Errorf("Health() version = %q, want %q", resp.Version, "1.0.0")
		}
	})

	t.Run("ListBackends", func(t *testing.T) {
		resp, err := client.ListBackends(ctx)
		if err != nil {
			t.Errorf("ListBackends() error = %v", err)
		}
		if len(resp.Backends) != 1 {
			t.Errorf("ListBackends() returned %d backends, want 1", len(resp.Backends))
		}
		if resp.Backends[0].ID != "software" {
			t.Errorf("ListBackends() backend ID = %q, want %q", resp.Backends[0].ID, "software")
		}
	})

	t.Run("GetBackend", func(t *testing.T) {
		resp, err := client.GetBackend(ctx, "test-backend")
		if err != nil {
			t.Errorf("GetBackend() error = %v", err)
		}
		if resp.ID != "test-backend" {
			t.Errorf("GetBackend() backend ID = %q, want %q", resp.ID, "test-backend")
		}
	})

	t.Run("GenerateKey", func(t *testing.T) {
		resp, err := client.GenerateKey(ctx, &GenerateKeyRequest{
			KeyID:   "test-key",
			Backend: "test-backend",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Errorf("GenerateKey() error = %v", err)
		}
		if resp.KeyID != "test-key" {
			t.Errorf("GenerateKey() key ID = %q, want %q", resp.KeyID, "test-key")
		}
	})

	t.Run("ListKeys", func(t *testing.T) {
		resp, err := client.ListKeys(ctx, "test-backend")
		if err != nil {
			t.Errorf("ListKeys() error = %v", err)
		}
		if len(resp.Keys) != 1 {
			t.Errorf("ListKeys() returned %d keys, want 1", len(resp.Keys))
		}
	})

	t.Run("GetKey", func(t *testing.T) {
		resp, err := client.GetKey(ctx, "test-backend", "test-key")
		if err != nil {
			t.Errorf("GetKey() error = %v", err)
		}
		if resp.KeyID != "test-key" {
			t.Errorf("GetKey() key ID = %q, want %q", resp.KeyID, "test-key")
		}
	})

	t.Run("DeleteKey", func(t *testing.T) {
		resp, err := client.DeleteKey(ctx, "test-backend", "test-key")
		if err != nil {
			t.Errorf("DeleteKey() error = %v", err)
		}
		if !resp.Success {
			t.Error("DeleteKey() success = false, want true")
		}
	})

	t.Run("Sign", func(t *testing.T) {
		resp, err := client.Sign(ctx, &SignRequest{
			KeyID:   "test-key",
			Backend: "test-backend",
			Data:    json.RawMessage(`"dGVzdA=="`),
			Hash:    "SHA256",
		})
		if err != nil {
			t.Errorf("Sign() error = %v", err)
		}
		if len(resp.Signature) == 0 {
			t.Error("Sign() returned empty signature")
		}
	})

	t.Run("Verify", func(t *testing.T) {
		resp, err := client.Verify(ctx, &VerifyRequest{
			KeyID:     "test-key",
			Backend:   "test-backend",
			Data:      json.RawMessage(`"dGVzdA=="`),
			Signature: json.RawMessage(`"c2ln"`),
			Hash:      "SHA256",
		})
		if err != nil {
			t.Errorf("Verify() error = %v", err)
		}
		if !resp.Valid {
			t.Error("Verify() valid = false, want true")
		}
	})

	t.Run("Encrypt", func(t *testing.T) {
		resp, err := client.Encrypt(ctx, &EncryptRequest{
			KeyID:     "test-key",
			Backend:   "test-backend",
			Plaintext: json.RawMessage(`"dGVzdA=="`),
		})
		if err != nil {
			t.Errorf("Encrypt() error = %v", err)
		}
		if len(resp.Ciphertext) == 0 {
			t.Error("Encrypt() returned empty ciphertext")
		}
	})

	t.Run("Decrypt", func(t *testing.T) {
		resp, err := client.Decrypt(ctx, &DecryptRequest{
			KeyID:      "test-key",
			Backend:    "test-backend",
			Ciphertext: json.RawMessage(`"Y2lwaGVy"`),
			Nonce:      json.RawMessage(`"bm9uY2U="`),
			Tag:        json.RawMessage(`"dGFn"`),
		})
		if err != nil {
			t.Errorf("Decrypt() error = %v", err)
		}
		if len(resp.Plaintext) == 0 {
			t.Error("Decrypt() returned empty plaintext")
		}
	})

	t.Run("GetCertificate", func(t *testing.T) {
		resp, err := client.GetCertificate(ctx, "test-backend", "test-key")
		if err != nil {
			t.Errorf("GetCertificate() error = %v", err)
		}
		if resp.CertificatePEM == "" {
			t.Error("GetCertificate() returned empty certificate")
		}
	})

	t.Run("SaveCertificate", func(t *testing.T) {
		err := client.SaveCertificate(ctx, &SaveCertificateRequest{
			KeyID:          "test-key",
			Backend:        "test-backend",
			CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		})
		if err != nil {
			t.Errorf("SaveCertificate() error = %v", err)
		}
	})

	t.Run("DeleteCertificate", func(t *testing.T) {
		err := client.DeleteCertificate(ctx, "test-backend", "test-key")
		if err != nil {
			t.Errorf("DeleteCertificate() error = %v", err)
		}
	})

	t.Run("ImportKey", func(t *testing.T) {
		resp, err := client.ImportKey(ctx, &ImportKeyRequest{
			KeyID:              "test-key",
			Backend:            "test-backend",
			WrappedKeyMaterial: []byte("wrapped-key-data"),
			Algorithm:          "RSAES_OAEP_SHA_256",
		})
		if err != nil {
			t.Errorf("ImportKey() error = %v", err)
		}
		if !resp.Success {
			t.Error("ImportKey() success = false, want true")
		}
	})

	t.Run("ExportKey", func(t *testing.T) {
		resp, err := client.ExportKey(ctx, &ExportKeyRequest{
			KeyID:     "test-key",
			Backend:   "test-backend",
			Algorithm: "RSAES_OAEP_SHA_256",
		})
		if err != nil {
			t.Errorf("ExportKey() error = %v", err)
		}
		if len(resp.WrappedKeyMaterial) == 0 {
			t.Error("ExportKey() returned empty wrapped key")
		}
	})

	t.Run("RotateKey", func(t *testing.T) {
		resp, err := client.RotateKey(ctx, &RotateKeyRequest{
			KeyID:   "test-key",
			Backend: "test-backend",
		})
		if err != nil {
			t.Errorf("RotateKey() error = %v", err)
		}
		if resp.KeyID != "test-key" {
			t.Errorf("RotateKey() key ID = %q, want %q", resp.KeyID, "test-key")
		}
		if resp.PublicKeyPEM == "" {
			t.Error("RotateKey() returned empty public key")
		}
	})

	t.Run("GetImportParameters", func(t *testing.T) {
		resp, err := client.GetImportParameters(ctx, &GetImportParametersRequest{
			Backend:   "test-backend",
			KeyID:     "test-key",
			Algorithm: "RSA_AES_KEY_WRAP_SHA_256",
		})
		if err != nil {
			t.Errorf("GetImportParameters() error = %v", err)
		}
		if len(resp.WrappingPublicKey) == 0 {
			t.Error("GetImportParameters() returned empty wrapping public key")
		}
		if len(resp.ImportToken) == 0 {
			t.Error("GetImportParameters() returned empty import token")
		}
	})

	t.Run("WrapKey", func(t *testing.T) {
		resp, err := client.WrapKey(ctx, &WrapKeyRequest{
			Backend:     "test-backend",
			KeyMaterial: []byte("test-key-material"),
			Algorithm:   "AES-KWP",
		})
		if err != nil {
			t.Errorf("WrapKey() error = %v", err)
		}
		if len(resp.WrappedKeyMaterial) == 0 {
			t.Error("WrapKey() returned empty wrapped key")
		}
	})

	t.Run("UnwrapKey", func(t *testing.T) {
		resp, err := client.UnwrapKey(ctx, &UnwrapKeyRequest{
			Backend:            "test-backend",
			WrappedKeyMaterial: []byte("wrapped-key"),
			Algorithm:          "AES-KWP",
		})
		if err != nil {
			t.Errorf("UnwrapKey() error = %v", err)
		}
		if len(resp.KeyMaterial) == 0 {
			t.Error("UnwrapKey() returned empty key material")
		}
	})

	t.Run("CopyKey", func(t *testing.T) {
		resp, err := client.CopyKey(ctx, &CopyKeyRequest{
			SourceBackend: "test-backend",
			SourceKeyID:   "test-key",
			DestBackend:   "dest-backend",
			DestKeyID:     "dest-key",
		})
		if err != nil {
			t.Errorf("CopyKey() error = %v", err)
		}
		if !resp.Success {
			t.Error("CopyKey() success = false, want true")
		}
	})

	t.Run("ListCertificates", func(t *testing.T) {
		resp, err := client.ListCertificates(ctx, "test-backend")
		if err != nil {
			t.Errorf("ListCertificates() error = %v", err)
		}
		if len(resp.Certificates) == 0 {
			t.Error("ListCertificates() returned empty list")
		}
	})

	t.Run("SaveCertificateChain", func(t *testing.T) {
		err := client.SaveCertificateChain(ctx, &SaveCertificateChainRequest{
			Backend: "test-backend",
			KeyID:   "test-key",
			ChainPEM: []string{
				"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----",
				"-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----",
			},
		})
		if err != nil {
			t.Errorf("SaveCertificateChain() error = %v", err)
		}
	})

	t.Run("GetCertificateChain", func(t *testing.T) {
		resp, err := client.GetCertificateChain(ctx, "test-backend", "test-key")
		if err != nil {
			t.Errorf("GetCertificateChain() error = %v", err)
		}
		if resp.KeyID != "test-key" {
			t.Errorf("GetCertificateChain() key ID = %q, want %q", resp.KeyID, "test-key")
		}
		if len(resp.ChainPEM) == 0 {
			t.Error("GetCertificateChain() returned empty chain")
		}
	})

	t.Run("GetTLSCertificate", func(t *testing.T) {
		resp, err := client.GetTLSCertificate(ctx, "test-backend", "test-key")
		if err != nil {
			t.Errorf("GetTLSCertificate() error = %v", err)
		}
		if resp.KeyID != "test-key" {
			t.Errorf("GetTLSCertificate() key ID = %q, want %q", resp.KeyID, "test-key")
		}
		if resp.CertificatePEM == "" {
			t.Error("GetTLSCertificate() returned empty certificate")
		}
	})

	t.Run("EncryptAsym returns ErrNotSupported", func(t *testing.T) {
		_, err := client.EncryptAsym(ctx, &EncryptAsymRequest{
			Backend:   "test-backend",
			KeyID:     "test-key",
			Plaintext: json.RawMessage(`"dGVzdA=="`),
		})
		if err == nil {
			t.Error("EncryptAsym() should return error")
		}
	})
}

func TestUnixGRPCClient_Close(t *testing.T) {
	socketPath, _ := setupTestUnixServer(t)

	cfg := &Config{
		Address:  socketPath,
		Protocol: ProtocolUnixGRPC,
	}

	client, err := newUnixGRPCClient(cfg)
	if err != nil {
		t.Fatalf("newUnixGRPCClient() error = %v", err)
	}

	// Close with nil connection should not error
	err = client.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}

	if client.connected {
		t.Error("client.connected should be false after Close()")
	}

	// Connect and then close
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	err = client.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}

	if client.connected {
		t.Error("client.connected should be false after Close()")
	}
}

func TestUnixGRPCClient_Reconnect(t *testing.T) {
	socketPath, _ := setupTestUnixServer(t)

	cfg := &Config{
		Address:  socketPath,
		Protocol: ProtocolUnixGRPC,
	}

	client, err := newUnixGRPCClient(cfg)
	if err != nil {
		t.Fatalf("newUnixGRPCClient() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First connection
	err = client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	// Test operation
	_, err = client.Health(ctx)
	if err != nil {
		t.Errorf("Health() error = %v", err)
	}

	// Close connection
	err = client.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Reconnect
	err = client.Connect(ctx)
	if err != nil {
		t.Fatalf("Reconnect() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	// Test operation after reconnect
	resp, err := client.Health(ctx)
	if err != nil {
		t.Errorf("Health() after reconnect error = %v", err)
	}
	if resp.Status != "healthy" {
		t.Errorf("Health() status = %q, want %q", resp.Status, "healthy")
	}
}

func TestUnixGRPCClient_URLParsing(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		protocol Protocol
	}{
		{
			name:     "unix URL defaults to gRPC",
			url:      "unix:///tmp/keychain.sock",
			protocol: ProtocolUnixGRPC,
		},
		{
			name:     "unix+http URL uses HTTP",
			url:      "unix+http:///tmp/keychain.sock",
			protocol: ProtocolUnix,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewFromURL(tt.url)
			if err != nil {
				t.Fatalf("NewFromURL() error = %v", err)
			}

			// Type assertion to check the underlying implementation
			switch tt.protocol {
			case ProtocolUnixGRPC:
				if _, ok := client.(*unixGRPCClient); !ok {
					t.Errorf("Expected unixGRPCClient, got %T", client)
				}
			case ProtocolUnix:
				if _, ok := client.(*unixClient); !ok {
					t.Errorf("Expected unixClient, got %T", client)
				}
			}
		})
	}
}
