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

package cli

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/client"
)

func TestNewConfig_Defaults(t *testing.T) {
	cfg := NewConfig()

	if cfg.Backend != "software" {
		t.Errorf("Backend = %v, want software", cfg.Backend)
	}
	if cfg.KeyDir != "keychain-data/keys" {
		t.Errorf("KeyDir = %v, want keychain-data/keys", cfg.KeyDir)
	}
	if cfg.OutputFormat != "text" {
		t.Errorf("OutputFormat = %v, want text", cfg.OutputFormat)
	}
	if cfg.Verbose {
		t.Error("Verbose should be false by default")
	}
	if cfg.Server != "" {
		t.Errorf("Server should be empty by default, got %v", cfg.Server)
	}
}

func TestConfig_IsRemote(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{"empty server", "", false},
		{"unix socket", "unix:///var/run/keychain.sock", true},
		{"http url", "http://localhost:8443", true},
		{"https url", "https://localhost:8443", true},
		{"grpc url", "grpc://localhost:9443", true},
		{"quic url", "quic://localhost:8444", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Server = tt.server

			if got := cfg.IsRemote(); got != tt.want {
				t.Errorf("IsRemote() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_CreateClient_Unix(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "" // Empty means use Unix socket

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClient_REST(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "http://localhost:8443"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClient_HTTPS(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "https://localhost:8443"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClient_GRPC(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "grpc://localhost:9443"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClient_GRPCS(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "grpcs://localhost:9443"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClient_QUIC(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "quic://localhost:8444"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClient_UnixURL(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "unix:///var/run/keychain/keychain.sock"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClient_WithTLS(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "https://localhost:8443"
	cfg.TLSInsecure = true
	cfg.TLSCert = "/path/to/cert.pem"
	cfg.TLSKey = "/path/to/key.pem"
	cfg.TLSCACert = "/path/to/ca.pem"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClient_WithJWTToken(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "http://localhost:8443"
	cfg.JWTToken = "test-jwt-token"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientWithTLS_Unix(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "unix:///tmp/test.sock"
	cfg.TLSInsecure = true // Forces createClientWithTLS path

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientWithTLS_DefaultREST(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "localhost:8443" // No scheme, should default to REST
	cfg.TLSInsecure = true

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestHasPrefix(t *testing.T) {
	tests := []struct {
		s      string
		prefix string
		want   bool
	}{
		{"http://localhost", "http://", true},
		{"https://localhost", "http://", false},
		{"grpc://localhost", "grpc://", true},
		{"", "http://", false},
		{"h", "http://", false},
	}

	for _, tt := range tests {
		if got := hasPrefix(tt.s, tt.prefix); got != tt.want {
			t.Errorf("hasPrefix(%q, %q) = %v, want %v", tt.s, tt.prefix, got, tt.want)
		}
	}
}

func TestTrimPrefix(t *testing.T) {
	tests := []struct {
		s      string
		prefix string
		want   string
	}{
		{"http://localhost", "http://", "localhost"},
		{"https://localhost", "http://", "https://localhost"},
		{"grpc://localhost", "grpc://", "localhost"},
		{"", "http://", ""},
	}

	for _, tt := range tests {
		if got := trimPrefix(tt.s, tt.prefix); got != tt.want {
			t.Errorf("trimPrefix(%q, %q) = %v, want %v", tt.s, tt.prefix, got, tt.want)
		}
	}
}

func TestDefaultUnixSocketPath(t *testing.T) {
	// Verify the client's default path matches what we expect
	if client.DefaultUnixSocketPath != "keychain-data/keychain.sock" {
		t.Errorf("DefaultUnixSocketPath = %v, want keychain-data/keychain.sock",
			client.DefaultUnixSocketPath)
	}
}
