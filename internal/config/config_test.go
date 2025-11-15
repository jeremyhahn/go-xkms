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

package config

import (
	"os"
	"path/filepath"
	"testing"
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
  backend: "filesystem"
  path: "/data/keychain"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/keychain/pkcs8"
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
	if cfg.Storage.Backend != "filesystem" {
		t.Errorf("Storage.Backend = %v, want filesystem", cfg.Storage.Backend)
	}
	if cfg.Storage.Path != "/data/keychain" {
		t.Errorf("Storage.Path = %v, want /data/keychain", cfg.Storage.Path)
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

// TestApplyEnvOverrides_ServerSettings tests environment variable overrides for server settings
func TestApplyEnvOverrides_ServerSettings(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		initial  Config
		expected Config
	}{
		{
			name: "override host",
			env: map[string]string{
				"KEYSTORE_HOST": "0.0.0.0",
			},
			initial: Config{
				Server: ServerConfig{Host: "localhost"},
			},
			expected: Config{
				Server: ServerConfig{Host: "0.0.0.0"},
			},
		},
		{
			name: "override REST port",
			env: map[string]string{
				"KEYSTORE_REST_PORT": "9000",
			},
			initial: Config{
				Server: ServerConfig{RESTPort: 8443},
			},
			expected: Config{
				Server: ServerConfig{RESTPort: 9000},
			},
		},
		{
			name: "override gRPC port",
			env: map[string]string{
				"KEYSTORE_GRPC_PORT": "9001",
			},
			initial: Config{
				Server: ServerConfig{GRPCPort: 9443},
			},
			expected: Config{
				Server: ServerConfig{GRPCPort: 9001},
			},
		},
		{
			name: "override MCP port",
			env: map[string]string{
				"KEYSTORE_MCP_PORT": "9002",
			},
			initial: Config{
				Server: ServerConfig{MCPPort: 9444},
			},
			expected: Config{
				Server: ServerConfig{MCPPort: 9002},
			},
		},
		{
			name: "override multiple server settings",
			env: map[string]string{
				"KEYSTORE_HOST":      "127.0.0.1",
				"KEYSTORE_REST_PORT": "8080",
				"KEYSTORE_GRPC_PORT": "9090",
			},
			initial: Config{
				Server: ServerConfig{
					Host:     "localhost",
					RESTPort: 8443,
					GRPCPort: 9443,
				},
			},
			expected: Config{
				Server: ServerConfig{
					Host:     "127.0.0.1",
					RESTPort: 8080,
					GRPCPort: 9090,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.env {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			cfg := tt.initial
			applyEnvOverrides(&cfg)

			if cfg.Server.Host != tt.expected.Server.Host {
				t.Errorf("Server.Host = %v, want %v", cfg.Server.Host, tt.expected.Server.Host)
			}
			if cfg.Server.RESTPort != tt.expected.Server.RESTPort {
				t.Errorf("Server.RESTPort = %v, want %v", cfg.Server.RESTPort, tt.expected.Server.RESTPort)
			}
			if cfg.Server.GRPCPort != tt.expected.Server.GRPCPort {
				t.Errorf("Server.GRPCPort = %v, want %v", cfg.Server.GRPCPort, tt.expected.Server.GRPCPort)
			}
			if cfg.Server.MCPPort != tt.expected.Server.MCPPort {
				t.Errorf("Server.MCPPort = %v, want %v", cfg.Server.MCPPort, tt.expected.Server.MCPPort)
			}
		})
	}
}

// TestApplyEnvOverrides_InvalidPorts tests error handling for invalid port values
func TestApplyEnvOverrides_InvalidPorts(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		initial     Config
		expectedCfg Config // Expected config when invalid value is provided (should keep default)
	}{
		{
			name: "invalid REST port - not a number",
			env: map[string]string{
				"KEYSTORE_REST_PORT": "invalid",
			},
			initial: Config{
				Server: ServerConfig{RESTPort: 8443},
			},
			expectedCfg: Config{
				Server: ServerConfig{RESTPort: 8443}, // Should keep default
			},
		},
		{
			name: "invalid gRPC port - empty string",
			env: map[string]string{
				"KEYSTORE_GRPC_PORT": "",
			},
			initial: Config{
				Server: ServerConfig{GRPCPort: 9443},
			},
			expectedCfg: Config{
				Server: ServerConfig{GRPCPort: 9443}, // Should keep default
			},
		},
		{
			name: "invalid QUIC port - special characters",
			env: map[string]string{
				"KEYSTORE_QUIC_PORT": "abc123",
			},
			initial: Config{
				Server: ServerConfig{QUICPort: 8444},
			},
			expectedCfg: Config{
				Server: ServerConfig{QUICPort: 8444}, // Should keep default
			},
		},
		{
			name: "invalid MCP port - decimal",
			env: map[string]string{
				"KEYSTORE_MCP_PORT": "9000.5",
			},
			initial: Config{
				Server: ServerConfig{MCPPort: 9444},
			},
			expectedCfg: Config{
				Server: ServerConfig{MCPPort: 9444}, // Should keep default
			},
		},
		{
			name: "invalid REST port - negative number",
			env: map[string]string{
				"KEYSTORE_REST_PORT": "-1000",
			},
			initial: Config{
				Server: ServerConfig{RESTPort: 8443},
			},
			expectedCfg: Config{
				Server: ServerConfig{RESTPort: 8443}, // Should keep default
			},
		},
		{
			name: "valid QUIC port override",
			env: map[string]string{
				"KEYSTORE_QUIC_PORT": "7777",
			},
			initial: Config{
				Server: ServerConfig{QUICPort: 8444},
			},
			expectedCfg: Config{
				Server: ServerConfig{QUICPort: 7777}, // Should accept valid value
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.env {
				if value != "" {
					os.Setenv(key, value)
					defer os.Unsetenv(key)
				}
			}

			cfg := tt.initial
			applyEnvOverrides(&cfg)

			if cfg.Server.RESTPort != tt.expectedCfg.Server.RESTPort {
				t.Errorf("Server.RESTPort = %v, want %v", cfg.Server.RESTPort, tt.expectedCfg.Server.RESTPort)
			}
			if cfg.Server.GRPCPort != tt.expectedCfg.Server.GRPCPort {
				t.Errorf("Server.GRPCPort = %v, want %v", cfg.Server.GRPCPort, tt.expectedCfg.Server.GRPCPort)
			}
			if cfg.Server.QUICPort != tt.expectedCfg.Server.QUICPort {
				t.Errorf("Server.QUICPort = %v, want %v", cfg.Server.QUICPort, tt.expectedCfg.Server.QUICPort)
			}
			if cfg.Server.MCPPort != tt.expectedCfg.Server.MCPPort {
				t.Errorf("Server.MCPPort = %v, want %v", cfg.Server.MCPPort, tt.expectedCfg.Server.MCPPort)
			}
		})
	}
}

// TestApplyEnvOverrides_Logging tests environment variable overrides for logging settings
func TestApplyEnvOverrides_Logging(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		initial  LoggingConfig
		expected LoggingConfig
	}{
		{
			name: "override log level",
			env: map[string]string{
				"KEYSTORE_LOG_LEVEL": "debug",
			},
			initial:  LoggingConfig{Level: "info"},
			expected: LoggingConfig{Level: "debug"},
		},
		{
			name: "override log format",
			env: map[string]string{
				"KEYSTORE_LOG_FORMAT": "text",
			},
			initial:  LoggingConfig{Format: "json"},
			expected: LoggingConfig{Format: "text"},
		},
		{
			name: "override both level and format",
			env: map[string]string{
				"KEYSTORE_LOG_LEVEL":  "warn",
				"KEYSTORE_LOG_FORMAT": "console",
			},
			initial:  LoggingConfig{Level: "info", Format: "json"},
			expected: LoggingConfig{Level: "warn", Format: "console"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.env {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			cfg := Config{Logging: tt.initial}
			applyEnvOverrides(&cfg)

			if cfg.Logging.Level != tt.expected.Level {
				t.Errorf("Logging.Level = %v, want %v", cfg.Logging.Level, tt.expected.Level)
			}
			if cfg.Logging.Format != tt.expected.Format {
				t.Errorf("Logging.Format = %v, want %v", cfg.Logging.Format, tt.expected.Format)
			}
		})
	}
}

// TestApplyEnvOverrides_Storage tests environment variable overrides for storage settings
func TestApplyEnvOverrides_Storage(t *testing.T) {
	tmpDir := t.TempDir()

	os.Setenv("KEYSTORE_DATA_DIR", tmpDir)
	defer os.Unsetenv("KEYSTORE_DATA_DIR")

	cfg := Config{
		Storage: StorageConfig{Path: "/old/path"},
		Backends: BackendsConfig{
			PKCS8: &PKCS8Config{
				Enabled: true,
				Path:    "pkcs8",
			},
		},
	}

	applyEnvOverrides(&cfg)

	if cfg.Storage.Path != tmpDir {
		t.Errorf("Storage.Path = %v, want %v", cfg.Storage.Path, tmpDir)
	}

	expectedPKCS8Path := filepath.Join(tmpDir, "pkcs8")
	if cfg.Backends.PKCS8.Path != expectedPKCS8Path {
		t.Errorf("Backends.PKCS8.Path = %v, want %v", cfg.Backends.PKCS8.Path, expectedPKCS8Path)
	}
}

// TestApplyEnvOverrides_TPM2 tests environment variable overrides for TPM2 settings
func TestApplyEnvOverrides_TPM2(t *testing.T) {
	os.Setenv("TPM_DEVICE_PATH", "/dev/tpmrm0")
	defer os.Unsetenv("TPM_DEVICE_PATH")

	cfg := Config{
		Backends: BackendsConfig{
			TPM2: &TPM2Config{
				Enabled:    true,
				DevicePath: "/dev/tpm0",
			},
		},
	}

	applyEnvOverrides(&cfg)

	if cfg.Backends.TPM2.DevicePath != "/dev/tpmrm0" {
		t.Errorf("Backends.TPM2.DevicePath = %v, want /dev/tpmrm0", cfg.Backends.TPM2.DevicePath)
	}
}

// TestApplyEnvOverrides_PKCS11 tests environment variable overrides for PKCS11 settings
func TestApplyEnvOverrides_PKCS11(t *testing.T) {
	os.Setenv("PKCS11_LIBRARY", "/usr/lib/libpkcs11.so")
	defer os.Unsetenv("PKCS11_LIBRARY")

	cfg := Config{
		Backends: BackendsConfig{
			PKCS11: &PKCS11Config{
				Enabled: true,
				Library: "/old/path/libpkcs11.so",
			},
		},
	}

	applyEnvOverrides(&cfg)

	if cfg.Backends.PKCS11.Library != "/usr/lib/libpkcs11.so" {
		t.Errorf("Backends.PKCS11.Library = %v, want /usr/lib/libpkcs11.so", cfg.Backends.PKCS11.Library)
	}
}

// TestApplyEnvOverrides_AWSKMS tests environment variable overrides for AWS KMS settings
func TestApplyEnvOverrides_AWSKMS(t *testing.T) {
	envVars := map[string]string{
		"AWS_REGION":            "us-west-2",
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_ENDPOINT":          "http://localhost:4566",
	}

	for key, value := range envVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	cfg := Config{
		Backends: BackendsConfig{
			AWSKMS: &AWSKMSConfig{
				Enabled:   true,
				Region:    "us-east-1",
				AccessKey: "old_key",
				SecretKey: "old_secret",
				Endpoint:  "old_endpoint",
			},
		},
	}

	applyEnvOverrides(&cfg)

	if cfg.Backends.AWSKMS.Region != "us-west-2" {
		t.Errorf("Backends.AWSKMS.Region = %v, want us-west-2", cfg.Backends.AWSKMS.Region)
	}
	if cfg.Backends.AWSKMS.AccessKey != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Backends.AWSKMS.AccessKey = %v, want AKIAIOSFODNN7EXAMPLE", cfg.Backends.AWSKMS.AccessKey)
	}
	if cfg.Backends.AWSKMS.SecretKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("Backends.AWSKMS.SecretKey = %v, want wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", cfg.Backends.AWSKMS.SecretKey)
	}
	if cfg.Backends.AWSKMS.Endpoint != "http://localhost:4566" {
		t.Errorf("Backends.AWSKMS.Endpoint = %v, want http://localhost:4566", cfg.Backends.AWSKMS.Endpoint)
	}
}

// TestApplyEnvOverrides_GCPKMS tests environment variable overrides for GCP KMS settings
func TestApplyEnvOverrides_GCPKMS(t *testing.T) {
	envVars := map[string]string{
		"GCP_PROJECT_ID":                 "my-project",
		"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/creds.json",
	}

	for key, value := range envVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	cfg := Config{
		Backends: BackendsConfig{
			GCPKMS: &GCPKMSConfig{
				Enabled:     true,
				ProjectID:   "old-project",
				Credentials: "/old/path/creds.json",
			},
		},
	}

	applyEnvOverrides(&cfg)

	if cfg.Backends.GCPKMS.ProjectID != "my-project" {
		t.Errorf("Backends.GCPKMS.ProjectID = %v, want my-project", cfg.Backends.GCPKMS.ProjectID)
	}
	if cfg.Backends.GCPKMS.Credentials != "/path/to/creds.json" {
		t.Errorf("Backends.GCPKMS.Credentials = %v, want /path/to/creds.json", cfg.Backends.GCPKMS.Credentials)
	}
}

// TestApplyEnvOverrides_AzureKV tests environment variable overrides for Azure Key Vault settings
func TestApplyEnvOverrides_AzureKV(t *testing.T) {
	envVars := map[string]string{
		"AZURE_KEYVAULT_URL":  "https://myvault.vault.azure.net/",
		"AZURE_TENANT_ID":     "tenant-123",
		"AZURE_CLIENT_ID":     "client-456",
		"AZURE_CLIENT_SECRET": "secret-789",
	}

	for key, value := range envVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	cfg := Config{
		Backends: BackendsConfig{
			AzureKV: &AzureKVConfig{
				Enabled:      true,
				VaultURL:     "https://oldvault.vault.azure.net/",
				TenantID:     "old-tenant",
				ClientID:     "old-client",
				ClientSecret: "old-secret",
			},
		},
	}

	applyEnvOverrides(&cfg)

	if cfg.Backends.AzureKV.VaultURL != "https://myvault.vault.azure.net/" {
		t.Errorf("Backends.AzureKV.VaultURL = %v, want https://myvault.vault.azure.net/", cfg.Backends.AzureKV.VaultURL)
	}
	if cfg.Backends.AzureKV.TenantID != "tenant-123" {
		t.Errorf("Backends.AzureKV.TenantID = %v, want tenant-123", cfg.Backends.AzureKV.TenantID)
	}
	if cfg.Backends.AzureKV.ClientID != "client-456" {
		t.Errorf("Backends.AzureKV.ClientID = %v, want client-456", cfg.Backends.AzureKV.ClientID)
	}
	if cfg.Backends.AzureKV.ClientSecret != "secret-789" {
		t.Errorf("Backends.AzureKV.ClientSecret = %v, want secret-789", cfg.Backends.AzureKV.ClientSecret)
	}
}

// TestApplyEnvOverrides_Vault tests environment variable overrides for Vault settings
func TestApplyEnvOverrides_Vault(t *testing.T) {
	envVars := map[string]string{
		"VAULT_ADDR":      "http://vault:8200",
		"VAULT_TOKEN":     "s.token123",
		"VAULT_NAMESPACE": "admin",
	}

	for key, value := range envVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	cfg := Config{
		Backends: BackendsConfig{
			Vault: &VaultConfig{
				Enabled:   true,
				Address:   "http://localhost:8200",
				Token:     "old-token",
				Namespace: "old-namespace",
			},
		},
	}

	applyEnvOverrides(&cfg)

	if cfg.Backends.Vault.Address != "http://vault:8200" {
		t.Errorf("Backends.Vault.Address = %v, want http://vault:8200", cfg.Backends.Vault.Address)
	}
	if cfg.Backends.Vault.Token != "s.token123" {
		t.Errorf("Backends.Vault.Token = %v, want s.token123", cfg.Backends.Vault.Token)
	}
	if cfg.Backends.Vault.Namespace != "admin" {
		t.Errorf("Backends.Vault.Namespace = %v, want admin", cfg.Backends.Vault.Namespace)
	}
}

// TestApplyEnvOverrides_NilBackends tests that env overrides don't crash with nil backends
func TestApplyEnvOverrides_NilBackends(t *testing.T) {
	envVars := map[string]string{
		"TPM_DEVICE_PATH": "/dev/tpm0",
		"PKCS11_LIBRARY":  "/usr/lib/libpkcs11.so",
		"AWS_REGION":      "us-west-2",
		"VAULT_ADDR":      "http://vault:8200",
	}

	for key, value := range envVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	cfg := Config{
		Backends: BackendsConfig{
			// All backends are nil
		},
	}

	// Should not panic
	applyEnvOverrides(&cfg)
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
				Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
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
				Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
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
				Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
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
				Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
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
				Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
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
				Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
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
		Storage:  StorageConfig{Backend: "filesystem", Path: "/data"},
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Protocols: ProtocolsConfig{REST: true},
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
			name:      "missing backend",
			storage:   StorageConfig{Backend: "", Path: "/data"},
			wantError: true,
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
				Protocols: ProtocolsConfig{REST: true},
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
				Storage:   StorageConfig{Backend: "filesystem", Path: "/data"},
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
  enabled: false

auth:
  enabled: false

storage:
  backend: "filesystem"
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
	os.Setenv("KEYSTORE_HOST", "0.0.0.0")
	os.Setenv("KEYSTORE_REST_PORT", "9000")
	os.Setenv("KEYSTORE_LOG_LEVEL", "debug")
	defer func() {
		os.Unsetenv("KEYSTORE_HOST")
		os.Unsetenv("KEYSTORE_REST_PORT")
		os.Unsetenv("KEYSTORE_LOG_LEVEL")
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

// TestApplyEnvOverrides_StorageWithAbsolutePath tests that absolute paths are not modified
func TestApplyEnvOverrides_StorageWithAbsolutePath(t *testing.T) {
	tmpDir := t.TempDir()

	os.Setenv("KEYSTORE_DATA_DIR", tmpDir)
	defer os.Unsetenv("KEYSTORE_DATA_DIR")

	absolutePath := "/absolute/path/to/pkcs8"
	cfg := Config{
		Storage: StorageConfig{Path: "/old/path"},
		Backends: BackendsConfig{
			PKCS8: &PKCS8Config{
				Enabled: true,
				Path:    absolutePath,
			},
		},
	}

	applyEnvOverrides(&cfg)

	// Absolute path should remain unchanged
	if cfg.Backends.PKCS8.Path != absolutePath {
		t.Errorf("Backends.PKCS8.Path = %v, want %v (absolute path should not change)",
			cfg.Backends.PKCS8.Path, absolutePath)
	}
}
