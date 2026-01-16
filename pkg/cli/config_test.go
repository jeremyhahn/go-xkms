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
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/client"
	"github.com/jeremyhahn/go-keychain/pkg/user"
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
	if cfg.UseLocal {
		t.Error("UseLocal should be false by default")
	}
}

func TestConfig_IsLocal(t *testing.T) {
	tests := []struct {
		name     string
		useLocal bool
		want     bool
	}{
		{"use local true", true, true},
		{"use local false", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.UseLocal = tt.useLocal

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

func TestConfig_CreateBackend_Software(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = tmpDir

	be, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("CreateBackend() returned error: %v", err)
	}
	if be == nil {
		t.Fatal("CreateBackend() returned nil")
	}
	defer func() { _ = be.Close() }()
}

func TestConfig_CreateBackend_UnsupportedBackends(t *testing.T) {
	unsupportedBackends := []string{"pkcs11", "awskms", "gcpkms", "azurekv", "vault"}

	for _, backend := range unsupportedBackends {
		t.Run(backend, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Backend = backend

			_, err := cfg.CreateBackend()
			if err == nil {
				t.Errorf("CreateBackend(%s) should return error for unsupported backend", backend)
			}
		})
	}
}

func TestConfig_CreateBackend_Unknown(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"

	_, err := cfg.CreateBackend()
	if err == nil {
		t.Error("CreateBackend() should return error for unknown backend")
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

func TestConfig_CreateClientWithTLS_HTTP(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "http://localhost:8443"
	cfg.TLSInsecure = true // Forces createClientWithTLS path

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
	cfg.TLSInsecure = true // Forces createClientWithTLS path

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
	cfg.TLSInsecure = true // Forces createClientWithTLS path

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
	cfg.TLSInsecure = true // Forces createClientWithTLS path

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

func TestConfig_Fields(t *testing.T) {
	cfg := &Config{
		ConfigFile:         "/path/to/config.yaml",
		Backend:            "software",
		KeyDir:             "/path/to/keys",
		OutputFormat:       "json",
		Verbose:            true,
		UseLocal:           true,
		Server:             "http://localhost:8443",
		TLSInsecure:        true,
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
	if !cfg.UseLocal {
		t.Error("UseLocal not set correctly")
	}
	if cfg.Server != "http://localhost:8443" {
		t.Error("Server not set correctly")
	}
	if !cfg.TLSInsecure {
		t.Error("TLSInsecure not set correctly")
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

func TestConfig_CreateBackend_SoftwareWithTempDir(t *testing.T) {
	tmpDir := t.TempDir()
	keyDir := filepath.Join(tmpDir, "keys")

	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = keyDir

	be, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("CreateBackend() returned error: %v", err)
	}
	if be == nil {
		t.Fatal("CreateBackend() returned nil")
	}
	defer func() { _ = be.Close() }()
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
// CreateUserStore tests
// ============================================================================

// configMockUserStore implements user.Store for config tests
type configMockUserStore struct{}

func (m *configMockUserStore) Create(_ context.Context, _, _ string, _ user.Role) (*user.User, error) {
	return nil, nil
}
func (m *configMockUserStore) GetByID(_ context.Context, _ []byte) (*user.User, error) {
	return nil, nil
}
func (m *configMockUserStore) GetByUsername(_ context.Context, _ string) (*user.User, error) {
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
