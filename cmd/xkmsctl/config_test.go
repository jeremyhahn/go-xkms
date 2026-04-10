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

package main

import (
	"context"
	"crypto"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/user"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestNewConfig_Defaults(t *testing.T) {
	cfg := NewConfig()

	if cfg.Backend != "software" {
		t.Errorf("Backend = %v, want software", cfg.Backend)
	}
	if cfg.KeyDir != "xkms-data/keys" {
		t.Errorf("KeyDir = %v, want xkms-data/keys", cfg.KeyDir)
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
	if cfg.Protocol != "" {
		t.Errorf("Protocol should be empty by default, got %v", cfg.Protocol)
	}
}

func TestConfig_IsLocal(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		want     bool
	}{
		{"embedded protocol", "embedded", true},
		{"rest protocol", "rest", false},
		{"grpc protocol", "grpc", false},
		{"quic protocol", "quic", false},
		{"unix protocol", "unix", false},
		{"mcp protocol", "mcp", false},
		{"empty protocol", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Protocol = tt.protocol

			if got := cfg.IsLocal(); got != tt.want {
				t.Errorf("IsLocal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_IsRemote(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{"empty server", "", false},
		{"unix socket", "unix:///var/run/xkms.sock", true},
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

func TestConfig_CreateCertStorage(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := NewConfig()
	cfg.KeyDir = tmpDir

	certStorage, err := cfg.CreateCertStorage()
	if err != nil {
		t.Fatalf("CreateCertStorage() returned error: %v", err)
	}
	if certStorage == nil {
		t.Fatal("CreateCertStorage() returned nil")
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
	cfg.Server = "unix:///var/run/xkms/xkms.sock"

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
	cfg.TLSCACert = "/path/to/ca.pem" // Forces createClientWithTLS path

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
	cfg.Server = "localhost:8443"     // No scheme, should default to REST
	cfg.TLSCACert = "/path/to/ca.pem" // Forces createClientWithTLS path

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientWithTLS_HTTP(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "http://localhost:8443"
	cfg.TLSCACert = "/path/to/ca.pem" // Forces createClientWithTLS path

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientWithTLS_GRPC(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "grpc://localhost:9443"
	cfg.TLSCACert = "/path/to/ca.pem" // Forces createClientWithTLS path

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientWithTLS_GRPCS(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "grpcs://localhost:9443"
	cfg.TLSCACert = "/path/to/ca.pem" // Forces createClientWithTLS path

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientWithTLS_QUIC(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "quic://localhost:8444"
	cfg.TLSCACert = "/path/to/ca.pem" // Forces createClientWithTLS path

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientWithTLS_MCP(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "mcp://localhost:9444"
	cfg.TLSCACert = "/path/to/ca.pem" // Forces createClientWithTLS path

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientWithTLS_MCPS(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "mcps://localhost:9444"
	cfg.TLSCACert = "/path/to/ca.pem" // Forces createClientWithTLS path

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
	if client.DefaultUnixSocketPath != "xkms-data/xkms.sock" {
		t.Errorf("DefaultUnixSocketPath = %v, want xkms-data/xkms.sock",
			client.DefaultUnixSocketPath)
	}
}

func TestConfig_Fields(t *testing.T) {
	cfg := &Config{
		ConfigFile:         "/path/to/config.yaml",
		Backend:            "software",
		KeyDir:             "/path/to/keys",
		OutputFormat:       "json",
		Verbose:            true,
		Protocol:           "embedded",
		Server:             "http://localhost:8443",
		TLSCert:            "/path/to/cert.pem",
		TLSKey:             "/path/to/key.pem",
		TLSCACert:          "/path/to/ca.pem",
		JWTToken:           "test-token",
		TPM2Device:         "/dev/tpmrm0",
		TPM2UseSimulator:   true,
		TPM2EncryptSession: true,
		TPM2SRKHandle:      0x81000001,
		TPM2EKHandle:       0x81010001,
	}

	if cfg.ConfigFile != "/path/to/config.yaml" {
		t.Error("ConfigFile not set correctly")
	}
	if cfg.Backend != "software" {
		t.Error("Backend not set correctly")
	}
	if cfg.KeyDir != "/path/to/keys" {
		t.Error("KeyDir not set correctly")
	}
	if cfg.OutputFormat != "json" {
		t.Error("OutputFormat not set correctly")
	}
	if !cfg.Verbose {
		t.Error("Verbose not set correctly")
	}
	if cfg.Protocol != "embedded" {
		t.Error("Protocol not set correctly")
	}
	if cfg.Server != "http://localhost:8443" {
		t.Error("Server not set correctly")
	}
	if cfg.TLSCert != "/path/to/cert.pem" {
		t.Error("TLSCert not set correctly")
	}
	if cfg.TLSKey != "/path/to/key.pem" {
		t.Error("TLSKey not set correctly")
	}
	if cfg.TLSCACert != "/path/to/ca.pem" {
		t.Error("TLSCACert not set correctly")
	}
	if cfg.JWTToken != "test-token" {
		t.Error("JWTToken not set correctly")
	}
	if cfg.TPM2Device != "/dev/tpmrm0" {
		t.Error("TPM2Device not set correctly")
	}
	if !cfg.TPM2UseSimulator {
		t.Error("TPM2UseSimulator not set correctly")
	}
	if !cfg.TPM2EncryptSession {
		t.Error("TPM2EncryptSession not set correctly")
	}
	if cfg.TPM2SRKHandle != 0x81000001 {
		t.Error("TPM2SRKHandle not set correctly")
	}
	if cfg.TPM2EKHandle != 0x81010001 {
		t.Error("TPM2EKHandle not set correctly")
	}
}

func TestConfig_CreateCertStorage_WithTempDir(t *testing.T) {
	tmpDir := t.TempDir()
	keyDir := filepath.Join(tmpDir, "certs")

	cfg := NewConfig()
	cfg.KeyDir = keyDir

	certStorage, err := cfg.CreateCertStorage()
	if err != nil {
		t.Fatalf("CreateCertStorage() returned error: %v", err)
	}
	if certStorage == nil {
		t.Fatal("CreateCertStorage() returned nil")
	}
}

// ============================================================================
// Protocol-based client creation tests
// ============================================================================

func TestConfig_CreateClientFromProtocol_Unix(t *testing.T) {
	cfg := NewConfig()
	cfg.Protocol = "unix"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientFromProtocol_REST(t *testing.T) {
	cfg := NewConfig()
	cfg.Protocol = "rest"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientFromProtocol_GRPC(t *testing.T) {
	cfg := NewConfig()
	cfg.Protocol = "grpc"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientFromProtocol_QUIC(t *testing.T) {
	cfg := NewConfig()
	cfg.Protocol = "quic"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientFromProtocol_MCP(t *testing.T) {
	cfg := NewConfig()
	cfg.Protocol = "mcp"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

func TestConfig_CreateClientFromProtocol_Embedded(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	cfg.Protocol = "embedded"
	cfg.KeyDir = tmpDir

	// Reset xkms service before test
	xkms.Reset()

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}

	// Clean up
	xkms.Reset()
}

func TestConfig_CreateClientFromProtocol_UnsupportedProtocol(t *testing.T) {
	cfg := NewConfig()
	cfg.Protocol = "unknown-protocol"

	_, err := cfg.CreateClient()
	if err == nil {
		t.Fatal("CreateClient() should return error for unsupported protocol")
	}
}

func TestConfig_CreateClientFromProtocol_WithCustomServer(t *testing.T) {
	cfg := NewConfig()
	cfg.Protocol = "rest"
	cfg.Server = "http://custom-server:9999"

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() returned error: %v", err)
	}
	if cl == nil {
		t.Fatal("CreateClient() returned nil")
	}
}

// ============================================================================
// CreateUserStore tests
// ============================================================================

// configMockUserStore implements user.Store for config tests
type configMockUserStore struct{}

func (m *configMockUserStore) Create(_ context.Context, _, _ string, _ user.Role, _ string) (*user.User, error) {
	return nil, nil
}
func (m *configMockUserStore) GetByID(_ context.Context, _ []byte) (*user.User, error) {
	return nil, nil
}
func (m *configMockUserStore) GetByUsername(_ context.Context, _ string) (*user.User, error) {
	return nil, nil
}
func (m *configMockUserStore) GetByCertFingerprint(_ context.Context, _ string) (*user.User, error) {
	return nil, nil
}
func (m *configMockUserStore) Update(_ context.Context, _ *user.User) error {
	return nil
}
func (m *configMockUserStore) Delete(_ context.Context, _ []byte) error {
	return nil
}
func (m *configMockUserStore) List(_ context.Context) ([]*user.User, error) {
	return nil, nil
}
func (m *configMockUserStore) ListByTenant(_ context.Context, _ string) ([]*user.User, error) {
	return nil, nil
}
func (m *configMockUserStore) Count(_ context.Context) (int, error) {
	return 0, nil
}
func (m *configMockUserStore) HasAnyUsers(_ context.Context) (bool, error) {
	return false, nil
}
func (m *configMockUserStore) CountAdmins(_ context.Context) (int, error) {
	return 0, nil
}
func (m *configMockUserStore) SaveSession(_ context.Context, _ string, _ []byte, _ time.Duration) error {
	return nil
}
func (m *configMockUserStore) GetSession(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}
func (m *configMockUserStore) DeleteSession(_ context.Context, _ string) error {
	return nil
}
func (m *configMockUserStore) Close() error {
	return nil
}

func TestConfig_CreateUserStore_WithFactory(t *testing.T) {
	mockStore := &configMockUserStore{}

	cfg := NewConfig()
	cfg.UserStoreFactory = func(storagePath string) (user.Store, error) {
		return mockStore, nil
	}

	store, err := cfg.CreateUserStore(t.TempDir())
	if err != nil {
		t.Fatalf("CreateUserStore() returned error: %v", err)
	}
	if store != mockStore {
		t.Error("CreateUserStore() should return the injected mock store")
	}
}

func TestConfig_CreateUserStore_FactoryError(t *testing.T) {
	expectedErr := errors.New("factory creation failed")

	cfg := NewConfig()
	cfg.UserStoreFactory = func(storagePath string) (user.Store, error) {
		return nil, expectedErr
	}

	_, err := cfg.CreateUserStore(t.TempDir())
	if err == nil {
		t.Fatal("CreateUserStore() should return error from factory")
	}
	if err != expectedErr {
		t.Errorf("CreateUserStore() error = %v, want %v", err, expectedErr)
	}
}

func TestConfig_CreateUserStore_DefaultPath_Success(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	// No UserStoreFactory set - uses default openUserStore path

	store, err := cfg.CreateUserStore(tmpDir)
	if err != nil {
		t.Fatalf("CreateUserStore() returned error: %v", err)
	}
	if store == nil {
		t.Fatal("CreateUserStore() returned nil store")
	}
	defer func() { _ = store.Close() }()
}

func TestConfig_CreateUserStore_DefaultPath_InvalidPath(t *testing.T) {
	cfg := NewConfig()
	// No UserStoreFactory set - uses default openUserStore path

	// Use an invalid path that cannot be created
	invalidPath := "/dev/null/invalid/user/store/path"

	_, err := cfg.CreateUserStore(invalidPath)
	if err == nil {
		t.Fatal("CreateUserStore() should return error for invalid path")
	}
}

func TestConfig_CreateUserStore_FactoryReceivesPath(t *testing.T) {
	expectedPath := "/expected/storage/path"
	var receivedPath string

	cfg := NewConfig()
	cfg.UserStoreFactory = func(storagePath string) (user.Store, error) {
		receivedPath = storagePath
		return &configMockUserStore{}, nil
	}

	_, err := cfg.CreateUserStore(expectedPath)
	if err != nil {
		t.Fatalf("CreateUserStore() returned error: %v", err)
	}
	if receivedPath != expectedPath {
		t.Errorf("Factory received path %q, want %q", receivedPath, expectedPath)
	}
}

func TestConfig_CreateUserStore_NilFactory(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	cfg.UserStoreFactory = nil // Explicitly nil

	store, err := cfg.CreateUserStore(tmpDir)
	if err != nil {
		t.Fatalf("CreateUserStore() returned error: %v", err)
	}
	if store == nil {
		t.Fatal("CreateUserStore() returned nil store")
	}
	defer func() { _ = store.Close() }()
}

// ============================================================================
// CreateBackend tests
// ============================================================================

// configTestBackend implements types.KeyProvider for config tests
type configTestBackend struct{}

func (m *configTestBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}
func (m *configTestBackend) Capabilities() types.Capabilities {
	return types.Capabilities{}
}
func (m *configTestBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (m *configTestBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (m *configTestBackend) DeleteKey(attrs *types.KeyAttributes) error {
	return nil
}
func (m *configTestBackend) ListKeys() ([]*types.KeyAttributes, error) {
	return nil, nil
}
func (m *configTestBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, nil
}
func (m *configTestBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, nil
}
func (m *configTestBackend) RotateKey(attrs *types.KeyAttributes) error {
	return nil
}
func (m *configTestBackend) Close() error {
	return nil
}

func TestConfig_CreateBackend_WithFactory(t *testing.T) {
	mockBe := &configTestBackend{}

	cfg := NewConfig()
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBe, nil
	}

	backend, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("CreateBackend() returned error: %v", err)
	}
	if backend != mockBe {
		t.Error("CreateBackend() should return the injected mock backend")
	}
}

func TestConfig_CreateBackend_FactoryError(t *testing.T) {
	expectedErr := errors.New("backend factory failed")

	cfg := NewConfig()
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return nil, expectedErr
	}

	_, err := cfg.CreateBackend()
	if err == nil {
		t.Fatal("CreateBackend() should return error from factory")
	}
	if err != expectedErr {
		t.Errorf("CreateBackend() error = %v, want %v", err, expectedErr)
	}
}

func TestConfig_CreateBackend_DefaultPath_Success(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.BackendFactory = nil // Use default path

	backend, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("CreateBackend() returned error: %v", err)
	}
	if backend == nil {
		t.Fatal("CreateBackend() returned nil backend")
	}
	defer func() { _ = backend.Close() }()
}

func TestConfig_CreateBackend_InvalidPath(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = "/dev/null/invalid/path"
	cfg.BackendFactory = nil // Use default path

	_, err := cfg.CreateBackend()
	if err == nil {
		t.Fatal("CreateBackend() should return error for invalid path")
	}
}

func TestConfig_CreateBackend_FactoryReceivesConfig(t *testing.T) {
	var receivedCfg *Config

	cfg := NewConfig()
	cfg.Backend = "test-backend"
	cfg.KeyDir = "/custom/path"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		receivedCfg = c
		return &configTestBackend{}, nil
	}

	_, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("CreateBackend() returned error: %v", err)
	}
	if receivedCfg != cfg {
		t.Error("BackendFactory should receive the same config")
	}
	if receivedCfg.Backend != "test-backend" {
		t.Errorf("BackendFactory received Backend = %v, want test-backend", receivedCfg.Backend)
	}
	if receivedCfg.KeyDir != "/custom/path" {
		t.Errorf("BackendFactory received KeyDir = %v, want /custom/path", receivedCfg.KeyDir)
	}
}

// ============================================================================
// createXKMSService tests
// ============================================================================

func TestConfig_createXKMSService_Success(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.Backend = "software"

	// Reset xkms service before test
	xkms.Reset()

	svc, err := cfg.createXKMSService()
	if err != nil {
		t.Fatalf("createXKMSService() returned error: %v", err)
	}
	if svc == nil {
		t.Fatal("createXKMSService() returned nil service")
	}

	// Clean up
	xkms.Reset()
}

func TestConfig_createXKMSService_InvalidKeyDir(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = "/dev/null/invalid/keydir"
	cfg.Backend = "software"

	// Reset xkms service before test
	xkms.Reset()
	defer xkms.Reset()

	_, err := cfg.createXKMSService()
	if err == nil {
		t.Fatal("createXKMSService() should return error for invalid KeyDir")
	}
}

func TestConfig_createXKMSService_InvalidCertPath(t *testing.T) {
	cfg := NewConfig()
	// Set KeyDir to a path where we can't create the certs subdirectory
	cfg.KeyDir = "/dev/null"
	cfg.Backend = "software"

	// Reset xkms service before test
	xkms.Reset()
	defer xkms.Reset()

	_, err := cfg.createXKMSService()
	if err == nil {
		t.Fatal("createXKMSService() should return error for invalid cert path")
	}
}

func TestConfig_createXKMSService_ResetsPreviousService(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.Backend = "software"

	// Reset xkms service before test
	xkms.Reset()

	// Create first service
	svc1, err := cfg.createXKMSService()
	if err != nil {
		t.Fatalf("createXKMSService() first call returned error: %v", err)
	}
	if svc1 == nil {
		t.Fatal("createXKMSService() first call returned nil")
	}

	// Create second service (should reset the first one)
	tmpDir2 := t.TempDir()
	cfg2 := NewConfig()
	cfg2.KeyDir = tmpDir2
	cfg2.Backend = "software"

	svc2, err := cfg2.createXKMSService()
	if err != nil {
		t.Fatalf("createXKMSService() second call returned error: %v", err)
	}
	if svc2 == nil {
		t.Fatal("createXKMSService() second call returned nil")
	}

	// Clean up
	xkms.Reset()
}

func TestConfig_createXKMSService_DifferentBackendNames(t *testing.T) {
	testCases := []struct {
		name    string
		backend string
	}{
		{"software backend", "software"},
		{"custom backend", "custom"},
		{"pkcs8 backend", "pkcs8"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			cfg := NewConfig()
			cfg.KeyDir = tmpDir
			cfg.Backend = tc.backend

			// Reset xkms service before test
			xkms.Reset()
			defer xkms.Reset()

			svc, err := cfg.createXKMSService()
			if err != nil {
				t.Fatalf("createXKMSService() returned error: %v", err)
			}
			if svc == nil {
				t.Fatal("createXKMSService() returned nil service")
			}
		})
	}
}
