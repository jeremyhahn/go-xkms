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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewQUICClient(t *testing.T) {
	cfg := &Config{
		Address:  "localhost:9090",
		Protocol: "quic",
	}

	client, err := newQUICClient(cfg)
	if err != nil {
		t.Fatalf("newQUICClient() error = %v", err)
	}

	if client == nil {
		t.Fatal("newQUICClient() returned nil")
	}

	if client.config != cfg {
		t.Error("client.config does not match input config")
	}
}

func TestQUICClient_NotConnected(t *testing.T) {
	cfg := &Config{
		Address:  "localhost:9090",
		Protocol: "quic",
	}

	client, err := newQUICClient(cfg)
	if err != nil {
		t.Fatalf("newQUICClient() error = %v", err)
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
}

func TestQUICClient_Close(t *testing.T) {
	cfg := &Config{
		Address:  "localhost:9090",
		Protocol: "quic",
	}

	client, err := newQUICClient(cfg)
	if err != nil {
		t.Fatalf("newQUICClient() error = %v", err)
	}

	// Close with nil connection should not error
	err = client.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}

	if client.connected {
		t.Error("client.connected should be false after Close()")
	}
}

func TestQUICClient_Connect_TLS_CAFileError(t *testing.T) {
	cfg := &Config{
		Address:    "localhost:9090",
		Protocol:   "quic",
		TLSEnabled: true,
		TLSCAFile:  "/nonexistent/ca.pem",
	}

	client, err := newQUICClient(cfg)
	if err != nil {
		t.Fatalf("newQUICClient() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = client.Connect(ctx)
	if err == nil {
		t.Error("Connect() should error with nonexistent CA file")
	}
}

func TestQUICClient_Connect_TLS_InvalidCA(t *testing.T) {
	// Create a temp file with invalid CA content
	tmpDir, err := os.MkdirTemp("", "quic-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	caFile := filepath.Join(tmpDir, "invalid-ca.pem")
	if err := os.WriteFile(caFile, []byte("invalid certificate content"), 0600); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	cfg := &Config{
		Address:    "localhost:9090",
		Protocol:   "quic",
		TLSEnabled: true,
		TLSCAFile:  caFile,
	}

	client, err := newQUICClient(cfg)
	if err != nil {
		t.Fatalf("newQUICClient() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = client.Connect(ctx)
	if err == nil {
		t.Error("Connect() should error with invalid CA content")
	}
}

func TestQUICClient_Connect_TLS_CertError(t *testing.T) {
	cfg := &Config{
		Address:     "localhost:9090",
		Protocol:    "quic",
		TLSEnabled:  true,
		TLSCertFile: "/nonexistent/cert.pem",
		TLSKeyFile:  "/nonexistent/key.pem",
	}

	client, err := newQUICClient(cfg)
	if err != nil {
		t.Fatalf("newQUICClient() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = client.Connect(ctx)
	if err == nil {
		t.Error("Connect() should error with nonexistent cert/key files")
	}
}

func TestQUICClient_Connect_Timeout(t *testing.T) {
	cfg := &Config{
		Address:               "localhost:59998", // unlikely to be in use
		Protocol:              "quic",
		TLSEnabled:            true,
		TLSInsecureSkipVerify: true,
	}

	client, err := newQUICClient(cfg)
	if err != nil {
		t.Fatalf("newQUICClient() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = client.Connect(ctx)
	// Should fail because no server is running
	if err == nil {
		t.Error("Connect() should error when connection times out")
	}
}
