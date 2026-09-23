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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestLoad_Success tests successful loading of a valid config file
func TestLoad_Success(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  host: "localhost"
  rest_port: 8443
  grpc_port: 9443
  quic_port: 8444
  mcp_port: 9444

protocols:
  rest: true
  grpc: true
  quic: false
  mcp: false

logging:
  level: "info"
  format: "json"

tls:
  enabled: true
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"

auth:
  enabled: false

ratelimit:
  enabled: false

metrics:
  enabled: true
  path: "/metrics"
  port: 9090

health:
  enabled: true
  path: "/health"

storage:
  backend: "qrdb"
  path: "/data/xkms"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/xkms/pkcs8"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if cfg == nil {
		t.Fatal("Load() returned nil config")
		return
	}

	// Validate server config
	if cfg.Server.Host != "localhost" {
		t.Errorf("Server.Host = %v, want localhost", cfg.Server.Host)
	}
	if cfg.Server.RESTPort != 8443 {
		t.Errorf("Server.RESTPort = %v, want 8443", cfg.Server.RESTPort)
	}
	if cfg.Server.GRPCPort != 9443 {
		t.Errorf("Server.GRPCPort = %v, want 9443", cfg.Server.GRPCPort)
	}

	// Validate protocols
	if !cfg.Protocols.REST {
		t.Error("Protocols.REST = false, want true")
	}
	if !cfg.Protocols.GRPC {
		t.Error("Protocols.GRPC = false, want true")
	}

	// Validate logging
	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level = %v, want info", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format = %v, want json", cfg.Logging.Format)
	}

	// Validate storage
	if cfg.Storage.Backend != "qrdb" {
		t.Errorf("Storage.Backend = %v, want qrdb", cfg.Storage.Backend)
	}
	if cfg.Storage.Path != "/data/xkms" {
		t.Errorf("Storage.Path = %v, want /data/xkms", cfg.Storage.Path)
	}

	// Validate default backend
	if string(cfg.Default) != "pkcs8" {
		t.Errorf("Default = %v, want pkcs8", cfg.Default)
	}

	// Validate backends
	if cfg.Backends.PKCS8 == nil {
		t.Fatal("Backends.PKCS8 is nil")
	}
	if !cfg.Backends.PKCS8.Enabled {
		t.Error("Backends.PKCS8.Enabled = false, want true")
	}
}

// TestLoad_FileNotFound tests loading a non-existent config file
func TestLoad_FileNotFound(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}

	if cfg != nil {
		t.Errorf("Load() = %v, want nil", cfg)
	}
}

// TestLoad_InvalidYAML tests loading an invalid YAML file
func TestLoad_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	invalidContent := `
server:
  host: "localhost"
  invalid: [unclosed array
`

	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}

	if cfg != nil {
		t.Errorf("Load() = %v, want nil", cfg)
	}
}

// TestLoad_ValidationFailure tests loading a config that fails validation
func TestLoad_ValidationFailure(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid_config.yaml")

	// Missing required storage backend
	invalidContent := `
server:
  host: "localhost"
  rest_port: 8443
  grpc_port: 9443

protocols:
  rest: true
  grpc: false
  quic: false
  mcp: false

logging:
  level: "info"
  format: "json"

tls:
  enabled: false

auth:
  enabled: false

storage:
  backend: ""
  path: ""

default_backend: ""

backends:
  pkcs8:
    enabled: false
`

	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}

	if cfg != nil {
		t.Errorf("Load() = %v, want nil", cfg)
	}
}

// TestValidate_ServerPorts tests validation of server ports
func TestValidate_ServerPorts(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid REST port",
			config: Config{
				Protocols: ProtocolsConfig{REST: true},
				Server:    ServerConfig{RESTPort: 8443},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			},
			wantError: false,
		},
		{
			name: "invalid REST port - too low",
			config: Config{
				Protocols: ProtocolsConfig{REST: true},
				Server:    ServerConfig{RESTPort: 0},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			},
			wantError: true,
			errorMsg:  "invalid REST port",
		},
		{
			name: "invalid REST port - too high",
			config: Config{
				Protocols: ProtocolsConfig{REST: true},
				Server:    ServerConfig{RESTPort: 65536},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			},
			wantError: true,
			errorMsg:  "invalid REST port",
		},
		{
			name: "invalid gRPC port",
			config: Config{
				Protocols: ProtocolsConfig{GRPC: true},
				Server:    ServerConfig{GRPCPort: -1},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			},
			wantError: true,
			errorMsg:  "invalid gRPC port",
		},
		{
			name: "invalid QUIC port",
			config: Config{
				Protocols: ProtocolsConfig{QUIC: true},
				Server:    ServerConfig{QUICPort: 100000},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			},
			wantError: true,
			errorMsg:  "invalid QUIC port",
		},
		{
			name: "invalid MCP port",
			config: Config{
				Protocols: ProtocolsConfig{MCP: true},
				Server:    ServerConfig{MCPPort: 0},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			},
			wantError: true,
			errorMsg:  "invalid MCP port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError && err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

// TestValidate_Protocols tests validation of protocol configuration
func TestValidate_Protocols(t *testing.T) {
	baseConfig := Config{
		Server:   ServerConfig{RESTPort: 8443},
		Logging:  LoggingConfig{Level: "info", Format: "json"},
		Storage:  StorageConfig{Backend: "qrdb", Path: "/data"},
		TLS:      TLSConfig{Enabled: true},
		Default:  "pkcs8",
		Backends: BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
	}

	// No protocols enabled - should fail
	cfg := baseConfig
	cfg.Protocols = ProtocolsConfig{REST: false, GRPC: false, QUIC: false, MCP: false}
	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() error = nil, want error for no protocols enabled")
	}

	// At least one protocol enabled - should pass
	cfg = baseConfig
	cfg.Protocols = ProtocolsConfig{REST: true}
	err = cfg.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v, want nil for REST enabled", err)
	}
}

// TestValidate_Logging tests validation of logging configuration
func TestValidate_Logging(t *testing.T) {
	tests := []struct {
		name      string
		level     string
		format    string
		wantError bool
	}{
		{"valid - debug json", "debug", "json", false},
		{"valid - info text", "info", "text", false},
		{"valid - warn console", "warn", "console", false},
		{"valid - error json", "error", "json", false},
		{"valid - fatal json", "fatal", "json", false},
		{"valid - uppercase level", "INFO", "json", false},
		{"valid - uppercase format", "info", "JSON", false},
		{"invalid level", "invalid", "json", true},
		{"invalid format", "info", "invalid", true},
		{"empty level", "", "json", true},
		{"empty format", "info", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Protocols: ProtocolsConfig{REST: true},
				Server:    ServerConfig{RESTPort: 8443},
				Logging:   LoggingConfig{Level: tt.level, Format: tt.format},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			}

			err := cfg.Validate()
			if tt.wantError && err == nil {
				t.Error("Validate() error = nil, want error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
			}
		})
	}
}

// TestValidate_TLS tests validation of TLS configuration
func TestValidate_TLS(t *testing.T) {
	tests := []struct {
		name      string
		tls       TLSConfig
		wantError bool
	}{
		{
			name:      "TLS disabled",
			tls:       TLSConfig{Enabled: false},
			wantError: false,
		},
		{
			name: "TLS enabled with cert and key",
			tls: TLSConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			wantError: false,
		},
		{
			name: "TLS enabled without cert",
			tls: TLSConfig{
				Enabled: true,
				KeyFile: "/path/to/key.pem",
			},
			wantError: true,
		},
		{
			name: "TLS enabled without key",
			tls: TLSConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
			},
			wantError: true,
		},
	}

	// Test CA-backed TLS separately since it needs a CA config on the Config struct
	t.Run("TLS enabled with CA config (no cert/key needed)", func(t *testing.T) {
		cfg := Config{
			Protocols: ProtocolsConfig{REST: true},
			Server:    ServerConfig{RESTPort: 8443},
			Logging:   LoggingConfig{Level: "info", Format: "json"},
			TLS:       TLSConfig{Enabled: true, ServerCN: "test-server"},
			Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
			Default:   "pkcs8",
			Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			CA:        &ca.MultiIdentityCAConfig{}, // CA present — cert_file/key_file not required
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() error = %v, want nil (CA-backed TLS should not require cert/key files)", err)
		}
	})

	// Network-serving deployments never require cert_file/key_file: the
	// unified API server's transports carry a persisted bootstrap
	// certificate until the CA issues the real one, so the legacy
	// file-required rule below does not apply to them.
	t.Run("network-serving without cert/key files is valid (bootstrap certificate)", func(t *testing.T) {
		cfg := Config{
			Protocols: ProtocolsConfig{REST: true},
			Server:    ServerConfig{RESTPort: 8443},
			Logging:   LoggingConfig{Level: "info", Format: "json"},
			TLS:       TLSConfig{Enabled: true},
			Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
			Default:   "pkcs8",
			Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() error = %v, want nil (network-serving TLS should not require cert/key files)", err)
		}
	})

	// The legacy cert_file/key_file-required rule only applies to
	// non-network-serving (local IPC) deployments, so these cases run with
	// no network protocol enabled to keep exercising it.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Protocols: ProtocolsConfig{Unix: true},
				Server:    ServerConfig{RESTPort: 8443},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				TLS:       tt.tls,
				Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			}

			err := cfg.Validate()
			if tt.wantError && err == nil {
				t.Error("Validate() error = nil, want error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
			}
		})
	}
}

// TestValidate_Storage tests validation of storage configuration
func TestValidate_Storage(t *testing.T) {
	tests := []struct {
		name      string
		storage   StorageConfig
		wantError bool
	}{
		{
			name:      "valid storage",
			storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
			wantError: false,
		},
		{
			// An unspecified backend now defaults to durable PebbleDB rather
			// than erroring (production paths never fall back to non-durable).
			name:      "missing backend defaults to pebble",
			storage:   StorageConfig{Backend: "", Path: "/data"},
			wantError: false,
		},
		{
			name:      "missing path",
			storage:   StorageConfig{Backend: "filesystem", Path: ""},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Protocols: ProtocolsConfig{Unix: true},
				Server:    ServerConfig{RESTPort: 8443},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   tt.storage,
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			}

			err := cfg.Validate()
			if tt.wantError && err == nil {
				t.Error("Validate() error = nil, want error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
			}
		})
	}
}

// TestValidate_DefaultBackend tests validation of default backend
func TestValidate_DefaultBackend(t *testing.T) {
	cfg := Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
		Default:   "",
		Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() error = nil, want error for empty default_backend")
	}
}

// TestValidate_Backends tests validation of backend configurations
func TestValidate_Backends(t *testing.T) {
	tests := []struct {
		name      string
		backends  BackendsConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid PKCS8 backend",
			backends: BackendsConfig{
				PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"},
			},
			wantError: false,
		},
		{
			name: "PKCS8 enabled without path",
			backends: BackendsConfig{
				PKCS8: &PKCS8Config{Enabled: true, Path: ""},
			},
			wantError: true,
			errorMsg:  "PKCS8 backend path is required",
		},
		{
			name: "valid TPM2 backend",
			backends: BackendsConfig{
				TPM2: &TPM2Config{Enabled: true, DevicePath: "/dev/tpm0"},
			},
			wantError: false,
		},
		{
			name: "TPM2 enabled without device path",
			backends: BackendsConfig{
				TPM2: &TPM2Config{Enabled: true, DevicePath: ""},
			},
			wantError: true,
			errorMsg:  "TPM2 device_path is required",
		},
		{
			name: "valid PKCS11 backend",
			backends: BackendsConfig{
				PKCS11: &PKCS11Config{Enabled: true, Library: "/usr/lib/libpkcs11.so"},
			},
			wantError: false,
		},
		{
			name: "PKCS11 enabled without library",
			backends: BackendsConfig{
				PKCS11: &PKCS11Config{Enabled: true, Library: ""},
			},
			wantError: true,
			errorMsg:  "PKCS11 library is required",
		},
		{
			name: "valid AWS KMS backend",
			backends: BackendsConfig{
				AWSKMS: &AWSKMSConfig{Enabled: true},
			},
			wantError: false,
		},
		{
			name: "valid GCP KMS backend",
			backends: BackendsConfig{
				GCPKMS: &GCPKMSConfig{Enabled: true},
			},
			wantError: false,
		},
		{
			name: "valid Azure KV backend",
			backends: BackendsConfig{
				AzureKV: &AzureKVConfig{Enabled: true},
			},
			wantError: false,
		},
		{
			name: "valid Vault backend",
			backends: BackendsConfig{
				Vault: &VaultConfig{Enabled: true},
			},
			wantError: false,
		},
		{
			name:      "no backends enabled",
			backends:  BackendsConfig{},
			wantError: true,
			errorMsg:  "at least one backend must be enabled",
		},
		{
			name: "all backends disabled",
			backends: BackendsConfig{
				PKCS8:  &PKCS8Config{Enabled: false},
				TPM2:   &TPM2Config{Enabled: false},
				PKCS11: &PKCS11Config{Enabled: false},
			},
			wantError: true,
			errorMsg:  "at least one backend must be enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Protocols: ProtocolsConfig{REST: true},
				Server:    ServerConfig{RESTPort: 8443},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends:  tt.backends,
			}

			err := cfg.Validate()
			if tt.wantError && err == nil {
				t.Error("Validate() error = nil, want error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
			}
		})
	}
}

// TestGetEnabledBackends tests the GetEnabledBackends method
func TestGetEnabledBackends(t *testing.T) {
	tests := []struct {
		name     string
		backends BackendsConfig
		want     []string
	}{
		{
			name: "single backend - PKCS8",
			backends: BackendsConfig{
				PKCS8: &PKCS8Config{Enabled: true},
			},
			want: []string{"pkcs8"},
		},
		{
			name: "single backend - TPM2",
			backends: BackendsConfig{
				TPM2: &TPM2Config{Enabled: true},
			},
			want: []string{"tpm2"},
		},
		{
			name: "multiple backends",
			backends: BackendsConfig{
				PKCS8:  &PKCS8Config{Enabled: true},
				TPM2:   &TPM2Config{Enabled: true},
				PKCS11: &PKCS11Config{Enabled: true},
			},
			want: []string{"pkcs8", "tpm2", "pkcs11"},
		},
		{
			name: "all backends enabled",
			backends: BackendsConfig{
				PKCS8:   &PKCS8Config{Enabled: true},
				TPM2:    &TPM2Config{Enabled: true},
				PKCS11:  &PKCS11Config{Enabled: true},
				AWSKMS:  &AWSKMSConfig{Enabled: true},
				GCPKMS:  &GCPKMSConfig{Enabled: true},
				AzureKV: &AzureKVConfig{Enabled: true},
				Vault:   &VaultConfig{Enabled: true},
			},
			want: []string{"pkcs8", "tpm2", "pkcs11", "awskms", "gcpkms", "azurekv", "vault"},
		},
		{
			name: "mixed enabled and disabled",
			backends: BackendsConfig{
				PKCS8:  &PKCS8Config{Enabled: true},
				TPM2:   &TPM2Config{Enabled: false},
				PKCS11: &PKCS11Config{Enabled: true},
				AWSKMS: &AWSKMSConfig{Enabled: false},
				GCPKMS: &GCPKMSConfig{Enabled: true},
			},
			want: []string{"pkcs8", "pkcs11", "gcpkms"},
		},
		{
			name:     "no backends",
			backends: BackendsConfig{},
			want:     nil,
		},
		{
			name: "all backends disabled",
			backends: BackendsConfig{
				PKCS8:  &PKCS8Config{Enabled: false},
				TPM2:   &TPM2Config{Enabled: false},
				PKCS11: &PKCS11Config{Enabled: false},
			},
			want: nil,
		},
		{
			name: "nil backend configs",
			backends: BackendsConfig{
				PKCS8:  nil,
				TPM2:   &TPM2Config{Enabled: true},
				PKCS11: nil,
			},
			want: []string{"tpm2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Backends: tt.backends}
			got := cfg.GetEnabledBackends()

			if len(got) != len(tt.want) {
				t.Errorf("GetEnabledBackends() returned %d backends, want %d", len(got), len(tt.want))
				t.Errorf("got: %v, want: %v", got, tt.want)
				return
			}

			for i, backend := range got {
				if backend != tt.want[i] {
					t.Errorf("GetEnabledBackends()[%d] = %v, want %v", i, backend, tt.want[i])
				}
			}
		})
	}
}

// TestLoad_WithEnvOverrides tests loading config with environment variable overrides
func TestLoad_WithEnvOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  host: "localhost"
  rest_port: 8443
  grpc_port: 9443

protocols:
  rest: true
  grpc: false
  quic: false
  mcp: false

logging:
  level: "info"
  format: "json"

tls:
  enabled: true

auth:
  enabled: false

storage:
  backend: "qrdb"
  path: "/data"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/pkcs8"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Set environment variables
	_ = os.Setenv("XKMS_SERVER_HOST", "0.0.0.0")
	_ = os.Setenv("XKMS_SERVER_REST_PORT", "9000")
	_ = os.Setenv("XKMS_LOGGING_LEVEL", "debug")
	defer func() {
		_ = os.Unsetenv("XKMS_SERVER_HOST")
		_ = os.Unsetenv("XKMS_SERVER_REST_PORT")
		_ = os.Unsetenv("XKMS_LOGGING_LEVEL")
	}()

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	// Verify environment overrides were applied
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Server.Host = %v, want 0.0.0.0 (env override)", cfg.Server.Host)
	}
	if cfg.Server.RESTPort != 9000 {
		t.Errorf("Server.RESTPort = %v, want 9000 (env override)", cfg.Server.RESTPort)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %v, want debug (env override)", cfg.Logging.Level)
	}
}

// TestGetRateLimitConfig tests the GetRateLimitConfig method
func TestGetRateLimitConfig(t *testing.T) {
	cfg := Config{
		RateLimit: RateLimitConfig{
			Enabled:            true,
			RequestsPerMin:     6000,
			Burst:              200,
			CleanupIntervalSec: 300,
		},
	}

	rlCfg := cfg.GetRateLimitConfig()

	if rlCfg == nil {
		t.Fatal("GetRateLimitConfig() returned nil")
	}

	if !rlCfg.Enabled {
		t.Error("GetRateLimitConfig().Enabled = false, want true")
	}

	if rlCfg.RequestsPerMin != 6000 {
		t.Errorf("GetRateLimitConfig().RequestsPerMin = %v, want 6000", rlCfg.RequestsPerMin)
	}

	if rlCfg.Burst != 200 {
		t.Errorf("GetRateLimitConfig().Burst = %v, want 200", rlCfg.Burst)
	}

	if rlCfg.CleanupIntervalSec != 300 {
		t.Errorf("GetRateLimitConfig().CleanupIntervalSec = %v, want 300", rlCfg.CleanupIntervalSec)
	}
}

// TestGetRateLimitConfig_Disabled tests GetRateLimitConfig with disabled rate limiting
func TestGetRateLimitConfig_Disabled(t *testing.T) {
	cfg := Config{
		RateLimit: RateLimitConfig{
			Enabled: false,
		},
	}

	rlCfg := cfg.GetRateLimitConfig()

	if rlCfg == nil {
		t.Fatal("GetRateLimitConfig() returned nil")
	}

	if rlCfg.Enabled {
		t.Error("GetRateLimitConfig().Enabled = true, want false")
	}
}

// TestGetRNGConfig tests the GetRNGConfig method
func TestGetRNGConfig(t *testing.T) {
	tests := []struct {
		name         string
		input        RNGConfig
		wantMode     string
		wantFallback string
	}{
		{
			name:         "empty config - defaults applied",
			input:        RNGConfig{},
			wantMode:     "auto",
			wantFallback: "software",
		},
		{
			name: "explicit mode - no fallback",
			input: RNGConfig{
				Mode: "tpm2",
			},
			wantMode:     "tpm2",
			wantFallback: "software",
		},
		{
			name: "explicit mode and fallback",
			input: RNGConfig{
				Mode:         "tpm2",
				FallbackMode: "pkcs11",
			},
			wantMode:     "tpm2",
			wantFallback: "pkcs11",
		},
		{
			name: "software mode",
			input: RNGConfig{
				Mode: "software",
			},
			wantMode:     "software",
			wantFallback: "software",
		},
		{
			name: "auto mode explicitly set",
			input: RNGConfig{
				Mode:         "auto",
				FallbackMode: "software",
			},
			wantMode:     "auto",
			wantFallback: "software",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{RNG: tt.input}
			rngCfg := cfg.GetRNGConfig()

			if rngCfg == nil {
				t.Fatal("GetRNGConfig() returned nil")
			}

			if rngCfg.Mode != tt.wantMode {
				t.Errorf("GetRNGConfig().Mode = %v, want %v", rngCfg.Mode, tt.wantMode)
			}

			if rngCfg.FallbackMode != tt.wantFallback {
				t.Errorf("GetRNGConfig().FallbackMode = %v, want %v", rngCfg.FallbackMode, tt.wantFallback)
			}
		})
	}
}

// TestGetRNGConfig_TPM2Settings tests GetRNGConfig preserves TPM2 settings
func TestGetRNGConfig_TPM2Settings(t *testing.T) {
	cfg := Config{
		RNG: RNGConfig{
			Mode:         "tpm2",
			FallbackMode: "software",
			TPM2: &RNGTPM2Config{
				Device:        "/dev/tpmrm0",
				UseSimulator:  false,
				SimulatorHost: "localhost",
				SimulatorPort: 2321,
			},
		},
	}

	rngCfg := cfg.GetRNGConfig()

	if rngCfg.TPM2 == nil {
		t.Fatal("GetRNGConfig().TPM2 should not be nil")
	}

	if rngCfg.TPM2.Device != "/dev/tpmrm0" {
		t.Errorf("GetRNGConfig().TPM2.Device = %v, want /dev/tpmrm0", rngCfg.TPM2.Device)
	}

	if rngCfg.TPM2.UseSimulator {
		t.Error("GetRNGConfig().TPM2.UseSimulator = true, want false")
	}
}

// TestValidate_SoftwareBackend tests validation of software backend
func TestValidate_SoftwareBackend(t *testing.T) {
	cfg := Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
		TLS:       TLSConfig{Enabled: true},
		Default:   "software",
		Backends: BackendsConfig{
			Software: &SoftwareConfig{Enabled: true, Path: "/data/software"},
		},
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v, want nil for software backend", err)
	}
}

// TestGetEnabledBackends_SoftwareBackend tests GetEnabledBackends with software backend
func TestGetEnabledBackends_SoftwareBackend(t *testing.T) {
	cfg := Config{
		Backends: BackendsConfig{
			Software: &SoftwareConfig{Enabled: true},
			PKCS8:    &PKCS8Config{Enabled: true},
		},
	}

	backends := cfg.GetEnabledBackends()

	if len(backends) != 2 {
		t.Errorf("GetEnabledBackends() returned %d backends, want 2", len(backends))
		return
	}

	// Check software is first
	if backends[0] != "software" {
		t.Errorf("GetEnabledBackends()[0] = %v, want software", backends[0])
	}

	if backends[1] != "pkcs8" {
		t.Errorf("GetEnabledBackends()[1] = %v, want pkcs8", backends[1])
	}
}

// TestValidate_InvalidDefaultBackend tests validation with invalid default backend
func TestValidate_InvalidDefaultBackend(t *testing.T) {
	cfg := Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
		Default:   "nonexistent",
		Backends:  BackendsConfig{},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should return error for invalid default backend")
	}
}

// TestCredentialsConfig_YAMLParsing tests YAML loading of the credentials section.
func TestCredentialsConfig_YAMLParsing(t *testing.T) {
	tests := []struct {
		name             string
		yaml             string
		expectedStrategy string
	}{
		{
			name: "seal_strategy set to barrier",
			yaml: `
server:
  host: "localhost"
  rest_port: 8443
  grpc_port: 9443

protocols:
  rest: true

logging:
  level: "info"
  format: "json"

tls:
  enabled: true

storage:
  backend: "qrdb"
  path: "/data/xkms"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/xkms/pkcs8"

credentials:
  seal_strategy: "barrier"
`,
			expectedStrategy: "barrier",
		},
		{
			name: "seal_strategy set to tpm2",
			yaml: `
server:
  host: "localhost"
  rest_port: 8443
  grpc_port: 9443

protocols:
  rest: true

logging:
  level: "info"
  format: "json"

tls:
  enabled: true

storage:
  backend: "qrdb"
  path: "/data/xkms"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/xkms/pkcs8"

credentials:
  seal_strategy: "tpm2"
`,
			expectedStrategy: "tpm2",
		},
		{
			name: "seal_strategy set to software",
			yaml: `
server:
  host: "localhost"
  rest_port: 8443
  grpc_port: 9443

protocols:
  rest: true

logging:
  level: "info"
  format: "json"

tls:
  enabled: true

storage:
  backend: "qrdb"
  path: "/data/xkms"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/xkms/pkcs8"

credentials:
  seal_strategy: "software"
`,
			expectedStrategy: "software",
		},
		{
			name: "credentials section omitted defaults to empty string",
			yaml: `
server:
  host: "localhost"
  rest_port: 8443
  grpc_port: 9443

protocols:
  rest: true

logging:
  level: "info"
  format: "json"

tls:
  enabled: true

storage:
  backend: "qrdb"
  path: "/data/xkms"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/xkms/pkcs8"
`,
			expectedStrategy: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")

			if err := os.WriteFile(configPath, []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("Failed to write test config file: %v", err)
			}

			cfg, err := Load(configPath)
			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}

			if cfg.Credentials.SealStrategy != tt.expectedStrategy {
				t.Errorf("Credentials.SealStrategy = %q, want %q",
					cfg.Credentials.SealStrategy, tt.expectedStrategy)
			}
		})
	}
}

// TestValidate_NoisePort tests validation of Noise protocol port
func TestValidate_NoisePort(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid Noise port",
			config: Config{
				Protocols: ProtocolsConfig{Noise: true},
				Server:    ServerConfig{NoisePort: 9000},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			},
			wantError: false,
		},
		{
			name: "invalid Noise port - zero",
			config: Config{
				Protocols: ProtocolsConfig{Noise: true},
				Server:    ServerConfig{NoisePort: 0},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			},
			wantError: true,
			errorMsg:  "invalid Noise port",
		},
		{
			name: "invalid Noise port - too high",
			config: Config{
				Protocols: ProtocolsConfig{Noise: true},
				Server:    ServerConfig{NoisePort: 70000},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			},
			wantError: true,
			errorMsg:  "invalid Noise port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Fatal("Validate() error = nil, want error")
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errorMsg)
				}
			} else if err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

// TestValidate_UnixSocketProtocol tests validation of Unix socket protocol field
func TestValidate_UnixSocketProtocol(t *testing.T) {
	baseConfig := func() Config {
		return Config{
			Protocols: ProtocolsConfig{REST: true},
			Server:    ServerConfig{RESTPort: 8443},
			Logging:   LoggingConfig{Level: "info", Format: "json"},
			Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
			TLS:       TLSConfig{Enabled: true},
			Default:   "pkcs8",
			Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
		}
	}

	tests := []struct {
		name      string
		unix      UnixConfig
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid grpc protocol",
			unix:      UnixConfig{Enabled: true, Protocol: "grpc"},
			wantError: false,
		},
		{
			name:      "valid http protocol",
			unix:      UnixConfig{Enabled: true, Protocol: "http"},
			wantError: false,
		},
		{
			name:      "empty protocol is valid (default)",
			unix:      UnixConfig{Enabled: true, Protocol: ""},
			wantError: false,
		},
		{
			name:      "invalid protocol",
			unix:      UnixConfig{Enabled: true, Protocol: "websocket"},
			wantError: true,
			errorMsg:  "invalid Unix socket protocol",
		},
		{
			name:      "disabled unix socket skips validation",
			unix:      UnixConfig{Enabled: false, Protocol: "invalid"},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Unix = tt.unix
			err := cfg.Validate()
			if tt.wantError {
				if err == nil {
					t.Fatal("Validate() error = nil, want error")
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errorMsg)
				}
			} else if err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

// TestValidate_RNGMode tests validation of RNG mode configuration
func TestValidate_RNGMode(t *testing.T) {
	baseConfig := func() Config {
		return Config{
			Protocols: ProtocolsConfig{REST: true},
			Server:    ServerConfig{RESTPort: 8443},
			Logging:   LoggingConfig{Level: "info", Format: "json"},
			Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
			TLS:       TLSConfig{Enabled: true},
			Default:   "pkcs8",
			Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
		}
	}

	tests := []struct {
		name         string
		mode         string
		fallbackMode string
		wantError    bool
		errorMsg     string
	}{
		{
			name:      "valid auto mode",
			mode:      "auto",
			wantError: false,
		},
		{
			name:      "valid software mode",
			mode:      "software",
			wantError: false,
		},
		{
			name:      "valid tpm2 mode",
			mode:      "tpm2",
			wantError: false,
		},
		{
			name:      "valid pkcs11 mode",
			mode:      "pkcs11",
			wantError: false,
		},
		{
			name:      "empty mode is valid (default)",
			mode:      "",
			wantError: false,
		},
		{
			name:      "invalid mode",
			mode:      "hardware",
			wantError: true,
			errorMsg:  "invalid RNG mode",
		},
		{
			name:         "valid software fallback mode",
			fallbackMode: "software",
			wantError:    false,
		},
		{
			name:         "valid tpm2 fallback mode",
			fallbackMode: "tpm2",
			wantError:    false,
		},
		{
			name:         "valid pkcs11 fallback mode",
			fallbackMode: "pkcs11",
			wantError:    false,
		},
		{
			name:         "invalid fallback mode",
			fallbackMode: "random",
			wantError:    true,
			errorMsg:     "invalid RNG fallback mode",
		},
		{
			name:         "empty fallback mode is valid (default)",
			fallbackMode: "",
			wantError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.RNG.Mode = tt.mode
			cfg.RNG.FallbackMode = tt.fallbackMode
			err := cfg.Validate()
			if tt.wantError {
				if err == nil {
					t.Fatal("Validate() error = nil, want error")
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errorMsg)
				}
			} else if err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

// TestValidate_PhoneBackend tests validation of Phone backend configuration
func TestValidate_PhoneBackend(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid phone backend with BLE transport",
			config: Config{
				Protocols: ProtocolsConfig{REST: true},
				Server:    ServerConfig{RESTPort: 8443},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends: BackendsConfig{
					Phone: &PhoneConfig{Enabled: true, Transport: "ble"},
				},
			},
			wantError: false,
		},
		{
			name: "valid phone backend with TCP transport",
			config: Config{
				Protocols: ProtocolsConfig{REST: true},
				Server:    ServerConfig{RESTPort: 8443},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends: BackendsConfig{
					Phone: &PhoneConfig{Enabled: true, Transport: "tcp"},
				},
			},
			wantError: false,
		},
		{
			name: "phone backend with empty transport",
			config: Config{
				Protocols: ProtocolsConfig{REST: true},
				Server:    ServerConfig{RESTPort: 8443},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends: BackendsConfig{
					Phone: &PhoneConfig{Enabled: true, Transport: ""},
				},
			},
			wantError: true,
			errorMsg:  "phone backend transport is required",
		},
		{
			name: "phone backend with invalid transport",
			config: Config{
				Protocols: ProtocolsConfig{REST: true},
				Server:    ServerConfig{RESTPort: 8443},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends: BackendsConfig{
					Phone: &PhoneConfig{Enabled: true, Transport: "usb"},
				},
			},
			wantError: true,
			errorMsg:  "invalid phone backend transport",
		},
		{
			name: "disabled phone backend skips validation",
			config: Config{
				Protocols: ProtocolsConfig{REST: true},
				Server:    ServerConfig{RESTPort: 8443},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
				TLS:       TLSConfig{Enabled: true},
				Default:   "pkcs8",
				Backends: BackendsConfig{
					PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"},
					Phone: &PhoneConfig{Enabled: false, Transport: "invalid"},
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Fatal("Validate() error = nil, want error")
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errorMsg)
				}
			} else if err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

// TestValidate_SoftwareBackendEmptyPath tests that software backend requires a path
func TestValidate_SoftwareBackendEmptyPath(t *testing.T) {
	cfg := Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
		TLS:       TLSConfig{Enabled: true},
		Default:   "software",
		Backends: BackendsConfig{
			Software: &SoftwareConfig{Enabled: true, Path: ""},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want error for empty software path")
	}
	if !strings.Contains(err.Error(), "software backend path is required") {
		t.Errorf("Validate() error = %v, want error about software backend path", err)
	}
}

// TestGetEnabledBackends_PhoneBackend tests that GetEnabledBackends includes the phone backend
func TestGetEnabledBackends_PhoneBackend(t *testing.T) {
	cfg := Config{
		Backends: BackendsConfig{
			PKCS8: &PKCS8Config{Enabled: true},
			Phone: &PhoneConfig{Enabled: true},
		},
	}
	backends := cfg.GetEnabledBackends()
	if len(backends) != 2 {
		t.Fatalf("GetEnabledBackends() returned %d backends, want 2; got %v", len(backends), backends)
	}
	found := false
	for _, b := range backends {
		if b == "phone" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetEnabledBackends() = %v, want phone backend included", backends)
	}
}

// TestGetEnabledBackends_PhoneOnly tests that GetEnabledBackends works with only the phone backend
func TestGetEnabledBackends_PhoneOnly(t *testing.T) {
	cfg := Config{
		Backends: BackendsConfig{
			Phone: &PhoneConfig{Enabled: true},
		},
	}
	backends := cfg.GetEnabledBackends()
	if len(backends) != 1 {
		t.Fatalf("GetEnabledBackends() returned %d backends, want 1; got %v", len(backends), backends)
	}
	if backends[0] != "phone" {
		t.Errorf("GetEnabledBackends()[0] = %v, want phone", backends[0])
	}
}

// TestValidate_UnixProtocolCaseSensitivity verifies the protocol matching is case-insensitive
func TestValidate_UnixProtocolCaseSensitivity(t *testing.T) {
	cfg := Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
		TLS:       TLSConfig{Enabled: true},
		Default:   "pkcs8",
		Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
		Unix:      UnixConfig{Enabled: true, Protocol: "GRPC"},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v, want nil for uppercase GRPC protocol", err)
	}
}

// TestStorageConfig_QRDB tests validation of QRDB storage backend configuration.
func TestStorageConfig_QRDB(t *testing.T) {
	tests := []struct {
		name      string
		storage   StorageConfig
		wantError bool
		errSubstr string
	}{
		{
			name: "valid qrdb config",
			storage: StorageConfig{
				Backend: "qrdb",
				QRDB: QRDBConfig{
					Address:   "https://localhost:63002",
					Transport: "rest",
				},
			},
			wantError: false,
		},
		{
			name: "qrdb missing address",
			storage: StorageConfig{
				Backend: "qrdb",
				QRDB: QRDBConfig{
					Transport: "rest",
				},
			},
			wantError: true,
			errSubstr: "qrdb storage address is required",
		},
		{
			name: "qrdb does not require path",
			storage: StorageConfig{
				Backend: "qrdb",
				Path:    "",
				QRDB: QRDBConfig{
					Address:   "https://node1:63002",
					Transport: "grpc",
				},
			},
			wantError: false,
		},
		{
			name: "qrdb with tls",
			storage: StorageConfig{
				Backend: "qrdb",
				QRDB: QRDBConfig{
					Address:   "https://node1:63002",
					Transport: "rest",
					TLS: TLSConfig{
						Enabled:  true,
						CertFile: "/path/to/cert.pem",
						KeyFile:  "/path/to/key.pem",
					},
				},
			},
			wantError: false,
		},
		{
			name: "file backend still requires path",
			storage: StorageConfig{
				Backend: "file",
				Path:    "",
			},
			wantError: true,
			errSubstr: "storage path must be specified",
		},
		{
			name: "memory backend requires path",
			storage: StorageConfig{
				Backend: "memory",
				Path:    "/data",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Protocols: ProtocolsConfig{Unix: true},
				Server:    ServerConfig{RESTPort: 8443},
				Logging:   LoggingConfig{Level: "info", Format: "json"},
				Storage:   tt.storage,
				Default:   "pkcs8",
				Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
			}

			err := cfg.Validate()
			if tt.wantError {
				if err == nil {
					t.Error("Validate() error = nil, want error")
					return
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Validate() error = %v, want substring %q", err, tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() error = %v, want nil", err)
				}
			}
		})
	}
}

// TestStorageConfig_QRDBDefaults verifies the zero value of QRDBConfig.
func TestStorageConfig_QRDBDefaults(t *testing.T) {
	sc := StorageConfig{Backend: "file", Path: "/data"}
	if sc.QRDB.Address != "" {
		t.Errorf("QRDBConfig.Address zero value = %q, want empty", sc.QRDB.Address)
	}
	if sc.QRDB.Transport != "" {
		t.Errorf("QRDBConfig.Transport zero value = %q, want empty", sc.QRDB.Transport)
	}
}

// TestConfig_ComplianceGaps verifies the secure-by-default posture check that
// the daemon uses to refuse an insecure start.
func TestConfig_ComplianceGaps(t *testing.T) {
	// A fully compliant config reports no gaps. A real (non-noop) auth type is
	// required: auth.enabled alone is not sufficient if the type resolves to the
	// no-op authenticator.
	secure := &Config{}
	secure.Barrier.Enabled = true
	secure.TLS.Enabled = true
	secure.Auth.Enabled = true
	secure.Auth.Type = "mtls"
	secure.CA = &ca.MultiIdentityCAConfig{}
	if gaps := secure.ComplianceGaps(); len(gaps) != 0 {
		t.Errorf("compliant config should report no gaps, got %v", gaps)
	}

	// auth.enabled=true but a no-op / empty auth type is still effectively
	// anonymous, so it is reported as a gap.
	for _, noopType := range []string{"", "noop", "none", "NoOp"} {
		c := &Config{}
		c.Barrier.Enabled = true
		c.TLS.Enabled = true
		c.Auth.Enabled = true
		c.Auth.Type = noopType
		c.CA = &ca.MultiIdentityCAConfig{}
		if gaps := c.ComplianceGaps(); len(gaps) != 1 {
			t.Errorf("auth.type=%q should report 1 gap (no-op auth), got %d: %v", noopType, len(gaps), gaps)
		}
	}

	// A zero-value config is insecure on all four dimensions.
	if gaps := (&Config{}).ComplianceGaps(); len(gaps) != 4 {
		t.Errorf("zero config should report 4 gaps, got %d: %v", len(gaps), gaps)
	}

	// Each dimension is independently detected.
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantGap int
	}{
		{"only barrier off", func(c *Config) {
			c.TLS.Enabled = true
			c.Auth.Enabled = true
			c.Auth.Type = "mtls"
			c.CA = &ca.MultiIdentityCAConfig{}
		}, 1},
		{"only tls off", func(c *Config) {
			c.Barrier.Enabled = true
			c.Auth.Enabled = true
			c.Auth.Type = "mtls"
			c.CA = &ca.MultiIdentityCAConfig{}
		}, 1},
		{"only auth off", func(c *Config) {
			c.Barrier.Enabled = true
			c.TLS.Enabled = true
			c.CA = &ca.MultiIdentityCAConfig{}
		}, 1},
		{"only ca missing", func(c *Config) {
			c.Barrier.Enabled = true
			c.TLS.Enabled = true
			c.Auth.Enabled = true
			c.Auth.Type = "mtls"
		}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{}
			tt.mutate(c)
			if gaps := c.ComplianceGaps(); len(gaps) != tt.wantGap {
				t.Errorf("got %d gaps, want %d: %v", len(gaps), tt.wantGap, gaps)
			}
		})
	}
}

// TestConfig_ComplianceGaps_ClusterCAKeyProtection verifies that a plaintext
// ("none") cluster CA key protection is flagged as a gap only when cluster ACME
// enrollment is actually enabled, and that secure protection modes are not.
func TestConfig_ComplianceGaps_ClusterCAKeyProtection(t *testing.T) {
	base := func() *Config {
		c := &Config{}
		c.Barrier.Enabled = true
		c.TLS.Enabled = true
		c.Auth.Enabled = true
		c.Auth.Type = "mtls"
		c.CA = &ca.MultiIdentityCAConfig{}
		c.Cluster.Enabled = true
		c.Cluster.RaftEnrollment.ACME.Enabled = true
		return c
	}

	// Plaintext cluster CA key with ACME enrollment on → one gap.
	c := base()
	c.Cluster.RaftEnrollment.CAKeyProtection = "none"
	gaps := c.ComplianceGaps()
	if len(gaps) != 1 {
		t.Fatalf("plaintext cluster CA key should report 1 gap, got %d: %v", len(gaps), gaps)
	}
	if !strings.Contains(gaps[0], "cluster CA key protection is plaintext") {
		t.Errorf("unexpected gap message: %q", gaps[0])
	}

	// Secure protection modes are not a gap.
	for _, mode := range []string{"", "auto", "tpm2", "pkcs11", "passphrase", "NONE "} {
		c := base()
		c.Cluster.RaftEnrollment.CAKeyProtection = strings.TrimSpace(mode)
		if mode == "NONE " {
			// A trimmed "none" is still plaintext; this asserts trimming applies.
			if gaps := c.ComplianceGaps(); len(gaps) != 1 {
				t.Errorf("mode %q (trimmed none) should report 1 gap, got %v", mode, gaps)
			}
			continue
		}
		if gaps := c.ComplianceGaps(); len(gaps) != 0 {
			t.Errorf("mode %q should report no gaps, got %v", mode, gaps)
		}
	}

	// Plaintext but cluster ACME enrollment OFF → not flagged (the keystore is
	// not used).
	c = base()
	c.Cluster.RaftEnrollment.ACME.Enabled = false
	c.Cluster.RaftEnrollment.CAKeyProtection = "none"
	if gaps := c.ComplianceGaps(); len(gaps) != 0 {
		t.Errorf("plaintext CA key with ACME off should not be flagged, got %v", gaps)
	}
}

// TestConfig_ComplianceGaps_RBACWithoutIdentityPlane verifies that enabling
// RBAC against a storage backend that provides no qrdb identity plane is
// reported as a posture gap.
//
// This is a fail-open, not a fail-closed: auth.enable_rbac=true with a non-qrdb
// backend leaves Server.rbacAuthorizer nil, and every transport (REST, gRPC,
// QUIC, MCP) then admits every authenticated caller with every permission. The
// operator asked for role enforcement and silently got none, so the daemon must
// refuse to start.
func TestConfig_ComplianceGaps_RBACWithoutIdentityPlane(t *testing.T) {
	// baseline returns a config that is compliant on every other dimension, so
	// any gap reported is attributable to the RBAC/storage combination alone.
	// The barrier passphrase matters: selecting the qrdb backend also brings the
	// embedded data plane under the auto-unseal check, and without a boot secret
	// that would report its own gap and mask the one under test.
	baseline := func() *Config {
		c := &Config{}
		c.Barrier.Enabled = true
		c.Barrier.Passphrase = types.SecretValue{Raw: "test-boot-secret"}
		c.TLS.Enabled = true
		c.Auth.Enabled = true
		c.Auth.Type = "mtls"
		c.CA = &ca.MultiIdentityCAConfig{}
		return c
	}

	tests := []struct {
		name       string
		enableRBAC bool
		backend    string
		wantGap    bool
	}{
		{"rbac on, qrdb backend", true, "qrdb", false},
		{"rbac on, qrdb backend cased", true, "QRDB", false},
		{"rbac on, pebble backend", true, "pebble", true},
		{"rbac on, file backend", true, "file", true},
		{"rbac on, memory backend", true, "memory", true},
		{"rbac on, unset backend", true, "", true},
		{"rbac off, pebble backend", false, "pebble", false},
		{"rbac off, unset backend", false, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseline()
			c.Auth.EnableRBAC = tt.enableRBAC
			c.Storage.Backend = tt.backend

			gaps := c.ComplianceGaps()
			if tt.wantGap {
				if len(gaps) != 1 {
					t.Fatalf("want exactly the RBAC gap, got %d: %v", len(gaps), gaps)
				}
				if !strings.Contains(gaps[0], "enable_rbac") {
					t.Errorf("gap should name auth.enable_rbac, got %q", gaps[0])
				}
				return
			}
			if len(gaps) != 0 {
				t.Errorf("want no gaps, got %v", gaps)
			}
		})
	}
}
