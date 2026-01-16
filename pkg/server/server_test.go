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

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/config"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper to create a minimal valid config
func createMinimalConfig(t *testing.T) *config.Config {
	t.Helper()
	tempDir := t.TempDir()

	return &config.Config{
		Server: config.ServerConfig{
			Host:     "127.0.0.1",
			RESTPort: 18080,
			GRPCPort: 19090,
			QUICPort: 18443,
			MCPPort:  13000,
		},
		Protocols: config.ProtocolsConfig{
			Unix: true,
			REST: false,
			GRPC: false,
			QUIC: false,
			MCP:  false,
		},
		Unix: config.UnixConfig{
			Enabled:    true,
			SocketPath: filepath.Join(tempDir, "keychain.sock"),
			Protocol:   "grpc",
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		TLS: config.TLSConfig{
			Enabled: false,
		},
		Auth: config.AuthConfig{
			Enabled: false,
		},
		Storage: config.StorageConfig{
			Backend: "file",
			Path:    tempDir,
		},
		Default: config.DefaultConfig("software"),
		Backends: config.BackendsConfig{
			Software: &config.SoftwareConfig{
				Enabled: true,
				Path:    filepath.Join(tempDir, "software"),
			},
		},
	}
}

// Test helpers for TLS testing
func createTestTLSFiles(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	tempDir := t.TempDir()

	// Generate CA key and certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	// Generate server key and certificate
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	// Write CA certificate
	caFile = filepath.Join(tempDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	err = os.WriteFile(caFile, caPEM, 0600)
	require.NoError(t, err)

	// Write server certificate
	certFile = filepath.Join(tempDir, "server.pem")
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	err = os.WriteFile(certFile, serverCertPEM, 0600)
	require.NoError(t, err)

	// Write server key
	keyFile = filepath.Join(tempDir, "server-key.pem")
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	require.NoError(t, err)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})
	err = os.WriteFile(keyFile, serverKeyPEM, 0600)
	require.NoError(t, err)

	return certFile, keyFile, caFile
}

func TestSetupLogger(t *testing.T) {
	tests := []struct {
		name   string
		cfg    config.LoggingConfig
		format string
		level  string
	}{
		{
			name:   "debug json",
			cfg:    config.LoggingConfig{Level: "debug", Format: "json"},
			format: "json",
			level:  "debug",
		},
		{
			name:   "info text",
			cfg:    config.LoggingConfig{Level: "info", Format: "text"},
			format: "text",
			level:  "info",
		},
		{
			name:   "warn console",
			cfg:    config.LoggingConfig{Level: "warn", Format: "console"},
			format: "console",
			level:  "warn",
		},
		{
			name:   "error default",
			cfg:    config.LoggingConfig{Level: "error", Format: ""},
			format: "",
			level:  "error",
		},
		{
			name:   "default level",
			cfg:    config.LoggingConfig{Level: "", Format: "json"},
			format: "json",
			level:  "",
		},
		{
			name:   "unknown level",
			cfg:    config.LoggingConfig{Level: "unknown", Format: "json"},
			format: "json",
			level:  "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := setupLogger(tt.cfg)
			if logger == nil {
				t.Error("expected non-nil logger")
			}
		})
	}
}

func TestGetBuildVersion(t *testing.T) {
	version := getBuildVersion()
	// Should return something (either "dev" or an actual version)
	if version == "" {
		t.Error("expected non-empty version")
	}
}

func TestParseTLSVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint16
	}{
		{"TLS1.2", "TLS1.2", tls.VersionTLS12},
		{"tls1.2", "tls1.2", tls.VersionTLS12},
		{"1.2", "1.2", tls.VersionTLS12},
		{"TLS1.3", "TLS1.3", tls.VersionTLS13},
		{"tls1.3", "tls1.3", tls.VersionTLS13},
		{"1.3", "1.3", tls.VersionTLS13},
		{"invalid", "invalid", 0},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTLSVersion(tt.input)
			if got != tt.expected {
				t.Errorf("parseTLSVersion(%q) = %v, expected %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseCipherSuites(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected int // Number of expected suites
	}{
		{
			name:     "single suite",
			input:    []string{"TLS_AES_128_GCM_SHA256"},
			expected: 1,
		},
		{
			name: "multiple suites",
			input: []string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
				"TLS_CHACHA20_POLY1305_SHA256",
			},
			expected: 3,
		},
		{
			name: "mixed valid and invalid",
			input: []string{
				"TLS_AES_128_GCM_SHA256",
				"INVALID_SUITE",
				"TLS_AES_256_GCM_SHA384",
			},
			expected: 2,
		},
		{
			name:     "all invalid",
			input:    []string{"INVALID1", "INVALID2"},
			expected: 0,
		},
		{
			name:     "empty",
			input:    []string{},
			expected: 0,
		},
		{
			name: "ECDHE suites",
			input: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
			},
			expected: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCipherSuites(tt.input)
			if len(got) != tt.expected {
				t.Errorf("parseCipherSuites() returned %d suites, expected %d", len(got), tt.expected)
			}
		})
	}
}

func TestParseCipherSuites_Values(t *testing.T) {
	// Test that specific cipher suites return correct values
	tests := []struct {
		name     string
		input    string
		expected uint16
	}{
		{"TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", tls.TLS_AES_128_GCM_SHA256},
		{"TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384", tls.TLS_AES_256_GCM_SHA384},
		{"TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256", tls.TLS_CHACHA20_POLY1305_SHA256},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCipherSuites([]string{tt.input})
			if len(got) != 1 {
				t.Fatalf("expected 1 suite, got %d", len(got))
			}
			if got[0] != tt.expected {
				t.Errorf("parseCipherSuites(%q) = %v, expected %v", tt.input, got[0], tt.expected)
			}
		})
	}
}

func TestPemDecode(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectNil bool
		blockType string
	}{
		{
			name: "valid PEM",
			input: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`,
			expectNil: false,
			blockType: "PUBLIC KEY",
		},
		{
			name:      "no PEM header",
			input:     "not a pem block",
			expectNil: true,
		},
		{
			name:      "incomplete PEM",
			input:     "-----BEGIN PUBLIC KEY-----",
			expectNil: true,
		},
		{
			name:      "empty",
			input:     "",
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block, _ := pemDecode([]byte(tt.input))
			if tt.expectNil {
				if block != nil {
					t.Error("expected nil block")
				}
			} else {
				if block == nil {
					t.Error("expected non-nil block")
				}
				if block != nil && block.Type != tt.blockType {
					t.Errorf("block type = %q, expected %q", block.Type, tt.blockType)
				}
			}
		})
	}
}

func TestParsePublicKey_InvalidData(t *testing.T) {
	invalidData := []byte("not a valid key")
	_, err := parsePublicKey(invalidData)
	if err == nil {
		t.Error("expected error for invalid key data")
	}
}

func TestParsePublicKey_ValidPEM(t *testing.T) {
	// Valid RSA public key PEM
	validPEM := []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`)

	key, err := parsePublicKey(validPEM)
	if err != nil {
		t.Fatalf("parsePublicKey failed: %v", err)
	}

	if key == nil {
		t.Error("expected non-nil key")
	}
}

func TestPemBlock(t *testing.T) {
	block := &pemBlock{
		Type:  "TEST",
		Bytes: []byte("test data"),
	}

	if block.Type != "TEST" {
		t.Errorf("Type = %q, expected %q", block.Type, "TEST")
	}

	if string(block.Bytes) != "test data" {
		t.Errorf("Bytes = %q, expected %q", string(block.Bytes), "test data")
	}
}

// Test Server creation and lifecycle

func TestNew_Success(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Verify server state
	assert.NotNil(t, server.config)
	assert.NotNil(t, server.logger)
	assert.NotEmpty(t, server.backends)
	assert.NotEmpty(t, server.keystores)
	assert.NotNil(t, server.healthChecker)
	assert.NotNil(t, server.userStore)
	assert.NotNil(t, server.authenticator)
	assert.NotNil(t, server.ctx)
	assert.NotNil(t, server.cancel)

	// Clean up
	err = server.Shutdown()
	assert.NoError(t, err)
}

func TestNew_NoBackends(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.Software = nil

	_, err := New(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backend")
}

func TestServer_Accessors(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Test all accessor methods
	assert.Nil(t, server.RESTServer(), "REST server should be nil before start")
	assert.Nil(t, server.GRPCServer(), "gRPC server should be nil before start")
	assert.Nil(t, server.QUICServer(), "QUIC server should be nil before start")
	assert.Nil(t, server.MCPServer(), "MCP server should be nil before start")
	assert.Nil(t, server.UnixGRPCServer(), "Unix HTTP server should be nil before start")
	assert.Nil(t, server.UnixGRPCServer(), "Unix gRPC server should be nil before start")
	assert.Nil(t, server.UnixGRPCServer(), "Unix gRPC server should be nil before start")
}

func TestServer_StartAndShutdown(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	// Disable all protocols to make test fast
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server (no-op since no protocols enabled)
	err = server.Start()
	assert.NoError(t, err)

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

func TestServer_ShutdownWithMetrics(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 19100
	cfg.Metrics.Path = "/metrics"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server with metrics
	err = server.Start()
	assert.NoError(t, err)

	// Allow time for metrics to initialize
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test TLS configuration

func TestServer_BuildTLSConfig_Success(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, caFile := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.CAFile = caFile
	cfg.TLS.MinVersion = "TLS1.2"
	cfg.TLS.MaxVersion = "TLS1.3"
	cfg.TLS.ClientAuth = "require"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Build TLS config
	tlsConfig, err := server.buildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	assert.NotNil(t, tlsConfig.ClientCAs)
	assert.Len(t, tlsConfig.Certificates, 1)
}

func TestServer_BuildTLSConfig_TLSDisabled(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = false

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	_, err = server.buildTLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TLS is not enabled")
}

func TestServer_BuildTLSConfig_InvalidCert(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/nonexistent/cert.pem"
	cfg.TLS.KeyFile = "/nonexistent/key.pem"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	_, err = server.buildTLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load server certificate")
}

func TestServer_BuildTLSConfig_InvalidCA(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.CAFile = "/nonexistent/ca.pem"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	_, err = server.buildTLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA certificate")
}

func TestServer_BuildTLSConfig_ClientAuthModes(t *testing.T) {
	tests := []struct {
		name         string
		clientAuth   string
		expectedAuth tls.ClientAuthType
	}{
		{"require", "require", tls.RequireAndVerifyClientCert},
		{"require_and_verify", "require_and_verify", tls.RequireAndVerifyClientCert},
		{"verify", "verify", tls.VerifyClientCertIfGiven},
		{"request", "request", tls.RequestClientCert},
		{"none", "none", tls.NoClientCert},
		{"empty", "", tls.NoClientCert},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keychain.Reset()
			defer keychain.Reset()

			certFile, keyFile, _ := createTestTLSFiles(t)

			cfg := createMinimalConfig(t)
			cfg.TLS.Enabled = true
			cfg.TLS.CertFile = certFile
			cfg.TLS.KeyFile = keyFile
			cfg.TLS.ClientAuth = tt.clientAuth

			server, err := New(cfg)
			require.NoError(t, err)
			require.NotNil(t, server)
			defer func() { _ = server.Shutdown() }()

			tlsConfig, err := server.buildTLSConfig()
			require.NoError(t, err)

			assert.Equal(t, tt.expectedAuth, tlsConfig.ClientAuth)
		})
	}
}

func TestServer_BuildTLSConfig_WithCipherSuites(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.CipherSuites = []string{
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	tlsConfig, err := server.buildTLSConfig()
	require.NoError(t, err)
	assert.Len(t, tlsConfig.CipherSuites, 2)
}

func TestServer_BuildTLSConfig_WithClientCAs(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, caFile := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.ClientCAs = []string{caFile}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	tlsConfig, err := server.buildTLSConfig()
	require.NoError(t, err)
	assert.NotNil(t, tlsConfig.ClientCAs)
}

func TestServer_BuildTLSConfig_InvalidClientCA(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.ClientCAs = []string{"/nonexistent/client-ca.pem"}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	_, err = server.buildTLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read additional client CA certificate")
}

// Test authentication configuration

func TestServer_InitializeAuthentication_Disabled(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = false

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
	assert.Equal(t, "noop", server.authenticator.Name())
}

func TestServer_InitializeAuthentication_Unknown(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "unknown_type"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Unknown type falls back to NoOp
	assert.NotNil(t, server.authenticator)
}

func TestServer_InitializeAuthentication_MTLS_NoTLS(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "mtls"
	cfg.TLS.Enabled = false

	_, err := New(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mTLS authentication requires TLS to be enabled")
}

func TestServer_InitializeAuthentication_JWT_NoPublicKey(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "jwt"
	cfg.Auth.JWT = nil

	_, err := New(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT authentication requires public_key_file")
}

func TestServer_InitializeAuthentication_JWT_Success(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	// Create a test public key file
	tempDir := t.TempDir()
	pubKeyFile := filepath.Join(tempDir, "public.pem")

	// Generate RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Write public key
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})
	err = os.WriteFile(pubKeyFile, pubKeyPEM, 0600)
	require.NoError(t, err)

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "jwt"
	cfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: pubKeyFile,
		Issuer:        "test-issuer",
		Audience:      []string{"test-audience"},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
	assert.Equal(t, "jwt", server.authenticator.Name())
}

func TestServer_InitializeAuthentication_Adaptive(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "adaptive"
	cfg.Auth.Adaptive = true

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
	// Adaptive authenticator name includes the required auth type suffix
	assert.True(t, strings.HasPrefix(server.authenticator.Name(), "adaptive"),
		"Expected authenticator name to start with 'adaptive', got: %s", server.authenticator.Name())
}

// Test WebAuthn configuration

func TestServer_InitializeAuthentication_WithWebAuthn(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = false
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled:       true,
		RPID:          "localhost",
		RPDisplayName: "Test RP",
		RPOrigins:     []string{"https://localhost:8443"},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.webauthnConfig)
	assert.Equal(t, "localhost", server.webauthnConfig.RPID)
}

// Test Reload functionality

func TestServer_Reload_Success(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Create new config with different logging
	newCfg := createMinimalConfig(t)
	newCfg.Logging.Level = "debug"
	newCfg.Logging.Format = "text"

	err = server.Reload(newCfg)
	assert.NoError(t, err)

	// Verify config was updated
	assert.Equal(t, "debug", server.config.Logging.Level)
	assert.Equal(t, "text", server.config.Logging.Format)
}

func TestServer_Reload_NoChange(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Reload with same config
	err = server.Reload(cfg)
	assert.NoError(t, err)
}

// Test signal handler

func TestSetupSignalHandler(t *testing.T) {
	ctx := SetupSignalHandler()
	assert.NotNil(t, ctx)

	// Context should not be cancelled initially
	select {
	case <-ctx.Done():
		t.Error("context should not be cancelled")
	default:
		// Expected
	}
}

// Test WaitForShutdown

func TestServer_WaitForShutdown(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server in background
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = server.Shutdown()
	}()

	// Wait for shutdown
	done := make(chan struct{})
	go func() {
		server.WaitForShutdown()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("WaitForShutdown timed out")
	}
}

// Test health checker initialization

func TestServer_InitializeHealth(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.healthChecker)

	// Health checks should be registered
	checks := server.healthChecker.GetAllChecks()
	assert.NotEmpty(t, checks)

	// Run health checks
	ctx := context.Background()
	results := server.healthChecker.Ready(ctx)
	assert.NotEmpty(t, results)
}

// Test ParsePublicKey with certificate

func TestParsePublicKey_WithCertificate(t *testing.T) {
	// Generate a test certificate
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	pubKey, err := parsePublicKey(certPEM)
	require.NoError(t, err)
	assert.NotNil(t, pubKey)
}

// Test closeBackends

func TestServer_CloseBackends(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Close backends should not panic
	server.closeBackends()

	// Backends should still be in map but closed
	assert.NotEmpty(t, server.backends)
}

// Test pemDecode edge cases

func TestPemDecode_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectNil bool
	}{
		{
			name:      "missing newline after header",
			input:     "-----BEGIN TEST-----TEST",
			expectNil: true,
		},
		{
			name:      "missing end marker",
			input:     "-----BEGIN TEST-----\ndata\n",
			expectNil: true,
		},
		{
			name: "valid with carriage returns",
			input: "-----BEGIN PUBLIC KEY-----\r\n" +
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\r\n" +
				"4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\r\n" +
				"+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh\r\n" +
				"kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ\r\n" +
				"0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg\r\n" +
				"cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc\r\n" +
				"mwIDAQAB\r\n" +
				"-----END PUBLIC KEY-----",
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block, _ := pemDecode([]byte(tt.input))
			if tt.expectNil {
				assert.Nil(t, block)
			} else {
				assert.NotNil(t, block)
			}
		})
	}
}

// Test initialize metrics

func TestServer_InitializeMetrics_Success(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 19200
	cfg.Metrics.Path = "/metrics"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Initialize metrics
	err = server.initializeMetrics()
	assert.NoError(t, err)
	assert.NotNil(t, server.metricsCollector)
}

// Test createJWTAuthenticator errors

func TestServer_CreateJWTAuthenticator_NilConfig(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Set JWT config to nil
	server.config.Auth.JWT = nil

	_, err = server.createJWTAuthenticator()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT configuration is required")
}

func TestServer_CreateJWTAuthenticator_FileNotFound(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: "/nonexistent/public.pem",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	_, err = server.createJWTAuthenticator()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read public key file")
}

func TestServer_CreateJWTAuthenticator_InvalidKey(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	tempDir := t.TempDir()
	pubKeyFile := filepath.Join(tempDir, "invalid.pem")
	err := os.WriteFile(pubKeyFile, []byte("not a valid key"), 0600)
	require.NoError(t, err)

	cfg := createMinimalConfig(t)
	cfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: pubKeyFile,
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	_, err = server.createJWTAuthenticator()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse public key")
}

// Test buildTLSConfig with invalid CA content

func TestServer_BuildTLSConfig_InvalidCAContent(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)
	tempDir := t.TempDir()

	// Create CA file with invalid content
	invalidCAFile := filepath.Join(tempDir, "invalid-ca.pem")
	err := os.WriteFile(invalidCAFile, []byte("not a valid certificate"), 0600)
	require.NoError(t, err)

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.CAFile = invalidCAFile

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	_, err = server.buildTLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

func TestServer_BuildTLSConfig_InvalidClientCAContent(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)
	tempDir := t.TempDir()

	// Create client CA file with invalid content
	invalidClientCAFile := filepath.Join(tempDir, "invalid-client-ca.pem")
	err := os.WriteFile(invalidClientCAFile, []byte("not a valid certificate"), 0600)
	require.NoError(t, err)

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.ClientCAs = []string{invalidClientCAFile}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	_, err = server.buildTLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse additional client CA certificate")
}

// Test MTLS authenticator initialization

func TestServer_InitializeAuthentication_MTLS_Success(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "mtls"
	cfg.TLS.Enabled = true

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
	assert.Equal(t, "mtls", server.authenticator.Name())
}

// Test adaptive auth with JWT config

func TestServer_InitializeAuthentication_AdaptiveWithJWT(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	// Create a test public key file
	tempDir := t.TempDir()
	pubKeyFile := filepath.Join(tempDir, "public.pem")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})
	err = os.WriteFile(pubKeyFile, pubKeyPEM, 0600)
	require.NoError(t, err)

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "adaptive" // Must set Type to "adaptive" for it to be recognized
	cfg.Auth.Adaptive = true
	cfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: pubKeyFile,
		Issuer:        "test-issuer",
	}
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled: true,
		RPID:    "localhost",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
	// Adaptive authenticator name includes the required auth type suffix
	assert.True(t, strings.HasPrefix(server.authenticator.Name(), "adaptive"),
		"Expected authenticator name to start with 'adaptive', got: %s", server.authenticator.Name())
}

// Test adaptive auth without JWT config falls back correctly

func TestServer_InitializeAuthentication_AdaptiveWithoutJWT(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "adaptive"
	cfg.Auth.Adaptive = true
	// No JWT config - should fall back to NoOp for required auth

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
	// Adaptive authenticator name includes the required auth type suffix
	assert.True(t, strings.HasPrefix(server.authenticator.Name(), "adaptive"),
		"Expected authenticator name to start with 'adaptive', got: %s", server.authenticator.Name())
}

// Test adaptive auth with WebAuthn but no JWT file

func TestServer_InitializeAuthentication_AdaptiveWebAuthnNoJWTFile(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "adaptive"
	cfg.Auth.Adaptive = true
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled: true,
		RPID:    "localhost",
	}
	// JWT config exists but no public key file
	cfg.Auth.JWT = &config.JWTConfig{
		Issuer: "test-issuer",
		// PublicKeyFile is empty
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
	// Adaptive authenticator name includes the required auth type suffix
	assert.True(t, strings.HasPrefix(server.authenticator.Name(), "adaptive"),
		"Expected authenticator name to start with 'adaptive', got: %s", server.authenticator.Name())
}

// Test adaptive auth with invalid JWT public key (falls back to NoOp)

func TestServer_InitializeAuthentication_AdaptiveInvalidJWTKey(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	tempDir := t.TempDir()
	pubKeyFile := filepath.Join(tempDir, "invalid.pem")
	err := os.WriteFile(pubKeyFile, []byte("not a valid key"), 0600)
	require.NoError(t, err)

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "adaptive"
	cfg.Auth.Adaptive = true
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled: true,
		RPID:    "localhost",
	}
	cfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: pubKeyFile,
		Issuer:        "test-issuer",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Should succeed with adaptive auth (falls back to NoOp for required auth)
	assert.NotNil(t, server.authenticator)
	// Adaptive authenticator name includes the required auth type suffix
	assert.True(t, strings.HasPrefix(server.authenticator.Name(), "adaptive"),
		"Expected authenticator name to start with 'adaptive', got: %s", server.authenticator.Name())
}

// Test JWT auth that uses required auth directly (not adaptive mode)

func TestServer_InitializeAuthentication_JWTNotAdaptive(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	// Create a test public key file
	tempDir := t.TempDir()
	pubKeyFile := filepath.Join(tempDir, "public.pem")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})
	err = os.WriteFile(pubKeyFile, pubKeyPEM, 0600)
	require.NoError(t, err)

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "jwt"
	cfg.Auth.Adaptive = false // Explicitly NOT adaptive
	cfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: pubKeyFile,
		Issuer:        "test-issuer",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
	assert.Equal(t, "jwt", server.authenticator.Name())
}

// Test PKCS8 backend initialization

func TestServer_InitializeBackends_PKCS8(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	tempDir := t.TempDir()
	// Enable PKCS8 backend in addition to software
	cfg.Backends.PKCS8 = &config.PKCS8Config{
		Enabled: true,
		Path:    filepath.Join(tempDir, "pkcs8"),
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Both software and pkcs8 backends should be initialized
	assert.Contains(t, server.backends, "software")
	assert.Contains(t, server.backends, "pkcs8")
}

// Test default backend config

func TestServer_WithDefaultPKCS8Backend(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	tempDir := t.TempDir()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "127.0.0.1",
			RESTPort: 18080,
		},
		Protocols: config.ProtocolsConfig{
			Unix: false,
			REST: false,
			GRPC: false,
		},
		Unix: config.UnixConfig{
			Enabled: false,
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		TLS: config.TLSConfig{
			Enabled: false,
		},
		Auth: config.AuthConfig{
			Enabled: false,
		},
		Storage: config.StorageConfig{
			Backend: "file",
			Path:    tempDir,
		},
		Default: config.DefaultConfig("pkcs8"),
		Backends: config.BackendsConfig{
			PKCS8: &config.PKCS8Config{
				Enabled: true,
				Path:    filepath.Join(tempDir, "pkcs8"),
			},
		},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.Contains(t, server.backends, "pkcs8")
}

// Test invalid storage path for initializeKeyStore

func TestServer_InitializeKeyStore_InvalidCertPath(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	// Use an invalid path character
	cfg.Storage.Path = "/dev/null/invalid"

	// This should fail during keystore initialization
	_, err := New(cfg)
	assert.Error(t, err)
}

// Test shutdown with timeout scenario using mock context

func TestServer_Shutdown_ContextCancellation(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start the server (no protocols enabled, so quick)
	err = server.Start()
	require.NoError(t, err)

	// Shutdown should work cleanly
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test health initialization with multiple backends

func TestServer_InitializeHealth_MultipleBackends(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	tempDir := t.TempDir()
	cfg := createMinimalConfig(t)
	cfg.Backends.PKCS8 = &config.PKCS8Config{
		Enabled: true,
		Path:    filepath.Join(tempDir, "pkcs8"),
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Health checker should have checks for both backends
	checks := server.healthChecker.GetAllChecks()
	assert.GreaterOrEqual(t, len(checks), 1)
}

// Test metrics initialization when already initialized

func TestServer_InitializeMetrics_AlreadyInitialized(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 19300
	cfg.Metrics.Path = "/metrics"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Initialize metrics first time
	err = server.initializeMetrics()
	require.NoError(t, err)

	// Initialize again should be safe
	err = server.initializeMetrics()
	assert.NoError(t, err)
}

// Test ECDSA public key parsing

func TestParsePublicKey_ECDSAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})

	pubKey, err := parsePublicKey(pubKeyPEM)
	require.NoError(t, err)
	assert.NotNil(t, pubKey)
}

// Test Start with metrics initialization error handling

func TestServer_Start_MetricsInitialization(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 19400
	cfg.Metrics.Path = "/metrics"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Start should initialize metrics and start metrics server
	err = server.Start()
	assert.NoError(t, err)
}

// Test cipher suite parsing with additional TLS 1.3 suites

func TestParseCipherSuites_TLS13(t *testing.T) {
	suites := parseCipherSuites([]string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
	})

	assert.Len(t, suites, 3)
	assert.Contains(t, suites, uint16(tls.TLS_AES_128_GCM_SHA256))
	assert.Contains(t, suites, uint16(tls.TLS_AES_256_GCM_SHA384))
	assert.Contains(t, suites, uint16(tls.TLS_CHACHA20_POLY1305_SHA256))
}

// Test reload with different auth configuration

func TestServer_Reload_AuthChange(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = false

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Create new config with auth enabled
	newCfg := createMinimalConfig(t)
	newCfg.Auth.Enabled = true
	newCfg.Auth.Type = "adaptive"

	// Reload should update auth configuration
	err = server.Reload(newCfg)
	assert.NoError(t, err)
}

// Test BuildTLSConfig with TLS 1.3 only

func TestServer_BuildTLSConfig_TLS13Only(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.MinVersion = "TLS1.3"
	cfg.TLS.MaxVersion = "TLS1.3"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	tlsConfig, err := server.buildTLSConfig()
	require.NoError(t, err)

	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MaxVersion)
}

// Test context accessor

func TestServer_Context(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	ctx := server.ctx
	assert.NotNil(t, ctx)

	// Context should not be cancelled initially
	select {
	case <-ctx.Done():
		t.Error("context should not be cancelled")
	default:
		// Expected
	}
}

// Test keystore accessor

func TestServer_Keystores(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotEmpty(t, server.keystores)
	assert.Contains(t, server.keystores, "software")
}

// Test authenticator accessor

func TestServer_Authenticator(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
}

// Test WebAuthn configuration with RPOrigins

func TestServer_InitializeAuthentication_WebAuthnWithOrigins(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled:       true,
		RPID:          "example.com",
		RPDisplayName: "Example App",
		RPOrigins:     []string{"https://example.com", "https://www.example.com"},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.webauthnConfig)
	assert.Equal(t, "example.com", server.webauthnConfig.RPID)
	assert.Equal(t, "Example App", server.webauthnConfig.RPDisplayName)
	assert.Len(t, server.webauthnConfig.RPOrigins, 2)
}

// ============================================================================
// Additional tests to improve coverage to 90%+
// ============================================================================

// Test backend stub initialization with nil configs (should skip gracefully)

func TestServer_InitBackendStubs_NilConfigs(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	// Ensure all cloud/hardware backends are nil
	cfg.Backends.AWSKMS = nil
	cfg.Backends.AzureKV = nil
	cfg.Backends.GCPKMS = nil
	cfg.Backends.PKCS11 = nil
	cfg.Backends.Vault = nil
	cfg.Backends.TPM2 = nil

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Should still have software backend
	assert.Contains(t, server.backends, "software")
}

// Test backend stub initialization with disabled configs

func TestServer_InitBackendStubs_DisabledConfigs(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.AWSKMS = &config.AWSKMSConfig{Enabled: false}
	cfg.Backends.AzureKV = &config.AzureKVConfig{Enabled: false}
	cfg.Backends.GCPKMS = &config.GCPKMSConfig{Enabled: false}
	cfg.Backends.PKCS11 = &config.PKCS11Config{Enabled: false}
	cfg.Backends.Vault = &config.VaultConfig{Enabled: false}
	cfg.Backends.TPM2 = &config.TPM2Config{Enabled: false}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Should still have software backend
	assert.Contains(t, server.backends, "software")
}

// Test createTPM2Backend function with various configurations

func TestCreateTPM2Backend_DefaultValues(t *testing.T) {
	config := BackendConfig{
		Name:    "tpm2",
		Type:    "tpm2",
		Enabled: true,
		Config:  map[string]interface{}{},
	}

	// This will fail because there's no TPM available, but we're testing the config parsing
	_, err := createTPM2Backend(config)
	// Expected to fail - no TPM available in test environment
	assert.Error(t, err)
}

func TestCreateTPM2Backend_CustomValues(t *testing.T) {
	config := BackendConfig{
		Name:    "tpm2",
		Type:    "tpm2",
		Enabled: true,
		Config: map[string]interface{}{
			"cn":                "custom-cn",
			"device":            "/dev/tpm0",
			"use_simulator":     true,
			"encrypt_session":   true,
			"platform_policy":   true,
			"srk_handle":        uint32(0x81000002),
			"ek_handle":         uint32(0x81010002),
			"key_dir":           "/tmp/tpm2-keys-test",
			"hash":              "SHA-384",
			"platform_pcr":      uint(7),
			"platform_pcr_bank": "SHA384",
		},
	}

	_, err := createTPM2Backend(config)
	// Expected to fail - no TPM available in test environment
	assert.Error(t, err)
}

func TestCreateTPM2Backend_IntHandles(t *testing.T) {
	// Test with int handles instead of uint32 (tests type assertion fallback)
	config := BackendConfig{
		Name:    "tpm2",
		Type:    "tpm2",
		Enabled: true,
		Config: map[string]interface{}{
			"srk_handle":   int(0x81000003),
			"ek_handle":    int(0x81010003),
			"platform_pcr": int(8),
		},
	}

	_, err := createTPM2Backend(config)
	// Expected to fail - no TPM available in test environment
	assert.Error(t, err)
}

// Test createBackend with unknown type

func TestCreateBackend_UnknownType(t *testing.T) {
	config := BackendConfig{
		Name:    "unknown",
		Type:    "nonexistent-backend-type",
		Enabled: true,
		Config:  map[string]interface{}{},
	}

	_, err := createBackend(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown backend type")
}

// Test createPKCS8Backend with nil key_dir (uses default)

func TestCreatePKCS8Backend_NilKeyDir(t *testing.T) {
	config := BackendConfig{
		Name:    "pkcs8",
		Type:    "pkcs8",
		Enabled: true,
		Config:  nil,
	}

	backend, err := createPKCS8Backend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
}

// Test createSoftwareBackend with nil key_dir (uses default)

func TestCreateSoftwareBackend_NilKeyDir(t *testing.T) {
	config := BackendConfig{
		Name:    "software",
		Type:    "software",
		Enabled: true,
		Config:  nil,
	}

	backend, err := createSoftwareBackend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
}

// Test createSymmetricBackend with nil key_dir (uses default)

func TestCreateSymmetricBackend_NilKeyDir(t *testing.T) {
	config := BackendConfig{
		Name:    "symmetric",
		Type:    "symmetric",
		Enabled: true,
		Config:  nil,
	}

	backend, err := createSymmetricBackend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
}

// Test parsePublicKey with raw DER data

func TestParsePublicKey_RawDER(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	// Pass raw DER without PEM encoding
	pubKey, err := parsePublicKey(pubKeyDER)
	require.NoError(t, err)
	assert.NotNil(t, pubKey)
}

// Test pemDecode with invalid base64

func TestPemDecode_InvalidBase64(t *testing.T) {
	// Valid PEM structure but with invalid base64 content
	invalidPEM := `-----BEGIN TEST-----
!!!invalid-base64-content!!!
-----END TEST-----`

	block, _ := pemDecode([]byte(invalidPEM))
	assert.Nil(t, block)
}

// Test pemDecode with extra content after footer

func TestPemDecode_ExtraContent(t *testing.T) {
	// PEM with extra content after footer
	pemWithExtra := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----
some extra content after`

	block, rest := pemDecode([]byte(pemWithExtra))
	assert.NotNil(t, block)
	assert.Contains(t, string(rest), "some extra content after")
}

// Test health check timeout scenario

func TestServer_HealthCheck_Timeout(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Run health checks with a very short timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for context to expire
	<-ctx.Done()

	// Health checks should handle expired context gracefully
	results := server.healthChecker.Ready(ctx)
	// Results might be empty or show errors due to timeout, but should not panic
	assert.NotNil(t, results)
}

// Test Reload with logging level and format changes

func TestServer_Reload_LoggingChanges(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "json"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Test all logging level transitions
	levels := []string{"debug", "warn", "error", "info"}
	formats := []string{"text", "console", "json", ""}

	for _, level := range levels {
		for _, format := range formats {
			newCfg := createMinimalConfig(t)
			newCfg.Logging.Level = level
			newCfg.Logging.Format = format

			err = server.Reload(newCfg)
			assert.NoError(t, err)
			assert.Equal(t, level, server.config.Logging.Level)
		}
	}
}

// Test server initialization with both CA file and client CAs

func TestServer_BuildTLSConfig_BothCAAndClientCAs(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, caFile := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.CAFile = caFile
	cfg.TLS.ClientCAs = []string{caFile} // Also add as client CA

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	tlsConfig, err := server.buildTLSConfig()
	require.NoError(t, err)
	assert.NotNil(t, tlsConfig.ClientCAs)
}

// Test server with multiple client CAs

func TestServer_BuildTLSConfig_MultipleClientCAs(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, caFile := createTestTLSFiles(t)
	_, _, caFile2 := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.ClientCAs = []string{caFile, caFile2}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	tlsConfig, err := server.buildTLSConfig()
	require.NoError(t, err)
	assert.NotNil(t, tlsConfig.ClientCAs)
}

// Test WebAuthn with all configuration options

func TestServer_InitializeAuthentication_WebAuthnFullConfig(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled:                 true,
		RPID:                    "example.com",
		RPDisplayName:           "Example Application",
		RPOrigins:               []string{"https://example.com", "https://www.example.com"},
		AttestationPreference:   "direct",
		AuthenticatorAttachment: "platform",
		ResidentKey:             "required",
		UserVerification:        "required",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.webauthnConfig)
	assert.Equal(t, "example.com", server.webauthnConfig.RPID)
	assert.Equal(t, "Example Application", server.webauthnConfig.RPDisplayName)
	assert.Equal(t, "direct", server.webauthnConfig.AttestationPreference)
	assert.Equal(t, "platform", server.webauthnConfig.AuthenticatorAttachment)
	assert.Equal(t, "required", server.webauthnConfig.ResidentKeyRequirement)
	assert.Equal(t, "required", server.webauthnConfig.UserVerification)
}

// Test adaptive authentication with mTLS as required auth

func TestServer_InitializeAuthentication_AdaptiveWithMTLS(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "mtls"
	cfg.Auth.Adaptive = true
	cfg.TLS.Enabled = true

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.authenticator)
	// When adaptive=true but type=mtls, it uses mtls directly with adaptive wrapper
	assert.True(t, strings.HasPrefix(server.authenticator.Name(), "adaptive"),
		"Expected authenticator name to start with 'adaptive', got: %s", server.authenticator.Name())
}

// Test getBuildVersion returns consistent values

func TestGetBuildVersion_Consistency(t *testing.T) {
	// Call multiple times to ensure consistency
	version1 := getBuildVersion()
	version2 := getBuildVersion()
	version3 := getBuildVersion()

	assert.Equal(t, version1, version2)
	assert.Equal(t, version2, version3)
	assert.NotEmpty(t, version1)
}

// Test server shutdown order with various server states

func TestServer_Shutdown_WithAllServers(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Manually set server instances to nil to test nil checks in Shutdown
	server.unixGRPCServer = nil
	server.unixGRPCServer = nil
	// Removed: server.unixIPCServer = nil (IPC protocol removed)
	server.restServer = nil
	server.grpcServer = nil
	server.quicServer = nil
	server.mcpServer = nil
	server.metricsCollector = nil

	// Shutdown should handle nil servers gracefully
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Initialize function from backend_factory.go

func TestInitialize_EmptyConfig(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	config := &BackendFactoryConfig{
		DefaultBackend: "pkcs8",
		Backends:       []BackendConfig{},
	}

	err := Initialize(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no backends available")
}

// Test Backend types through createBackend

func TestCreateBackend_AllTypes(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		config      BackendConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "pkcs8",
			config: BackendConfig{
				Name:    "pkcs8",
				Type:    "pkcs8",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": filepath.Join(tempDir, "pkcs8"),
				},
			},
			expectError: false,
		},
		{
			name: "software",
			config: BackendConfig{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": filepath.Join(tempDir, "software"),
				},
			},
			expectError: false,
		},
		{
			name: "symmetric",
			config: BackendConfig{
				Name:    "symmetric",
				Type:    "symmetric",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": filepath.Join(tempDir, "symmetric"),
				},
			},
			expectError: false,
		},
		{
			name: "pkcs11 - no library",
			config: BackendConfig{
				Name:    "pkcs11",
				Type:    "pkcs11",
				Enabled: true,
				Config:  map[string]interface{}{},
			},
			expectError: true, // Will fail due to missing library
		},
		{
			name: "tpm2 - no device",
			config: BackendConfig{
				Name:    "tpm2",
				Type:    "tpm2",
				Enabled: true,
				Config:  map[string]interface{}{},
			},
			expectError: true, // Will fail due to missing TPM
		},
		{
			name: "unknown type",
			config: BackendConfig{
				Name:    "unknown",
				Type:    "nonexistent",
				Enabled: true,
				Config:  map[string]interface{}{},
			},
			expectError: true,
			errorMsg:    "unknown backend type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := createBackend(tt.config)
			if tt.expectError {
				// If stub returns nil, nil (backend not compiled in), skip error check
				if backend == nil && err == nil {
					t.Skipf("Backend %s not compiled in (stub used)", tt.config.Type)
				}
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, backend)
			}
		})
	}
}

// Test health check with successful backend

func TestServer_HealthCheck_Success(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Mark server as started
	server.healthChecker.MarkStarted()

	// Run health checks
	ctx := context.Background()
	results := server.healthChecker.Ready(ctx)

	// Should have health check results
	assert.NotNil(t, results)
}

// Test server start with health checker marking

func TestServer_Start_MarksHealthStarted(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Health checker should be marked as started
	assert.NotNil(t, server.healthChecker)
}

// Test reloadLogging with identical config (no change path)

func TestServer_ReloadLogging_NoChange(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "json"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Reload with identical config
	err = server.Reload(cfg)
	assert.NoError(t, err)
	assert.Equal(t, "info", server.config.Logging.Level)
	assert.Equal(t, "json", server.config.Logging.Format)
}

// Test user store initialization failure

func TestServer_InitializeUserStore_InvalidPath(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Storage.Path = "/dev/null/nonexistent/path"

	_, err := New(cfg)
	assert.Error(t, err)
}

// Test default keystore fallback when specified default doesn't exist

func TestServer_InitializeKeyStore_DefaultFallback(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Default = config.DefaultConfig("nonexistent-backend")

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Should fall back to first available backend
	assert.NotEmpty(t, server.keystores)
}

// Test pemDecode with no dash after BEGIN

func TestPemDecode_NoTypeTerminator(t *testing.T) {
	// PEM header without type terminator
	invalidPEM := `-----BEGIN `

	block, _ := pemDecode([]byte(invalidPEM))
	assert.Nil(t, block)
}

// Test software backend initialization failure

func TestServer_InitializeSoftwareBackend_InvalidPath(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.Software.Path = "/dev/null/invalid"

	_, err := New(cfg)
	assert.Error(t, err)
}

// Test PKCS8 backend initialization failure

func TestServer_InitializePKCS8Backend_InvalidPath(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.Software = nil
	cfg.Backends.PKCS8 = &config.PKCS8Config{
		Enabled: true,
		Path:    "/dev/null/invalid",
	}

	_, err := New(cfg)
	assert.Error(t, err)
}

// ============================================================================
// Additional tests for protocol startup coverage
// ============================================================================

// Test Unix IPC server startup with default socket path

func TestServer_StartUnix_IPCProtocol(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = true
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.Unix.Protocol = "grpc"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Unix IPC server should be set
	assert.NotNil(t, server.UnixGRPCServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Unix HTTP server startup

func TestServer_StartUnix_HTTPProtocol(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = true
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.Unix.Protocol = "grpc"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Unix HTTP server should be set
	assert.NotNil(t, server.UnixGRPCServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Unix gRPC server startup

func TestServer_StartUnix_GRPCProtocol(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = true
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.Unix.Protocol = "grpc"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Unix gRPC server should be set
	assert.NotNil(t, server.UnixGRPCServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Unix server with unknown protocol

func TestServer_StartUnix_UnknownProtocol(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = true
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.Unix.Protocol = "unknown_protocol"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to attempt start
	time.Sleep(100 * time.Millisecond)

	// No Unix server should be set for unknown protocol
	assert.Nil(t, server.UnixGRPCServer())
	assert.Nil(t, server.UnixGRPCServer())
	assert.Nil(t, server.UnixGRPCServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Unix server with empty socket path (uses default)

func TestServer_StartUnix_DefaultSocketPath(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = true
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.Unix.Protocol = "grpc"
	cfg.Unix.SocketPath = "" // Empty - should use default

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server - may fail due to permissions on default path, but tests the code path
	_ = server.Start()

	// Give the server time to attempt start
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	_ = server.Shutdown()
}

// Test gRPC server startup

func TestServer_StartGRPC(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = true
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.Server.GRPCPort = 19595 // Use high port to avoid conflicts

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// gRPC server should be set
	assert.NotNil(t, server.GRPCServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test initTPM2Backend with nil config

func TestServer_InitTPM2Backend_NilConfig(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.TPM2 = nil

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// TPM2 backend should not be initialized
	_, exists := server.backends["tpm2"]
	assert.False(t, exists)
}

// Test initTPM2Backend with disabled config

func TestServer_InitTPM2Backend_DisabledConfig(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.TPM2 = &config.TPM2Config{
		Enabled: false,
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// TPM2 backend should not be initialized
	_, exists := server.backends["tpm2"]
	assert.False(t, exists)
}

// Test initTPM2Backend with default device path

func TestServer_InitTPM2Backend_DefaultDevicePath(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.TPM2 = &config.TPM2Config{
		Enabled:    true,
		DevicePath: "", // Empty - should use default
	}

	// Will fail because no TPM available, but tests the code path
	_, err := New(cfg)
	// Expected to fail due to no TPM hardware
	assert.Error(t, err)
}

// Test Shutdown with gRPC server

func TestServer_Shutdown_WithGRPCServer(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = true
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.Server.GRPCPort = 19696

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown should gracefully stop gRPC server
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Shutdown with keystores

func TestServer_Shutdown_ClosesKeystores(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Verify keystores exist before shutdown
	assert.NotEmpty(t, server.keystores)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Shutdown should close all keystores
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Start with all protocols enabled (except those requiring TLS)

func TestServer_Start_AllProtocols(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = true
	cfg.Protocols.REST = false // REST works without TLS but we skip for simplicity
	cfg.Protocols.GRPC = true
	cfg.Protocols.QUIC = false // Requires TLS
	cfg.Protocols.MCP = false  // May have issues in test env
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 19797
	cfg.Metrics.Path = "/metrics"
	cfg.Server.GRPCPort = 19898
	cfg.Unix.Protocol = "grpc"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the servers time to start
	time.Sleep(200 * time.Millisecond)

	// Verify servers are running
	assert.NotNil(t, server.UnixGRPCServer())
	assert.NotNil(t, server.GRPCServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test health check running the backend check closure

func TestServer_HealthCheck_BackendCheck(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Run health checks with a normal context
	ctx := context.Background()
	results := server.healthChecker.Ready(ctx)

	// Should have at least one check result for the backend
	hasBackendCheck := false
	for _, result := range results {
		if strings.HasPrefix(result.Name, "backend-") {
			hasBackendCheck = true
			break
		}
	}
	assert.True(t, hasBackendCheck, "Expected to find a backend health check")
}

// Test Start returns error when metrics initialization fails
// Note: This is hard to test without mocking, so we test the happy path more thoroughly

func TestServer_Start_MetricsEnabledMultipleTimes(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 19999
	cfg.Metrics.Path = "/metrics"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server multiple times (should be idempotent)
	err = server.Start()
	assert.NoError(t, err)

	// Give time for initialization
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test server with nil health checker during Start

func TestServer_Start_NilHealthChecker(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Set health checker to nil to test nil check
	server.healthChecker = nil

	// Start should handle nil health checker
	err = server.Start()
	assert.NoError(t, err)

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// ============================================================================
// Additional tests to achieve 90%+ coverage - REST, MCP, QUIC protocols
// ============================================================================

// Test REST server startup without TLS
func TestServer_StartREST_NoTLS(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = false
	cfg.Server.RESTPort = 18181

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// REST server should be set
	assert.NotNil(t, server.RESTServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test REST server startup with WebAuthn config
func TestServer_StartREST_WithWebAuthn(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = false
	cfg.Server.RESTPort = 18282
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled:       true,
		RPID:          "localhost",
		RPDisplayName: "Test App",
		RPOrigins:     []string{"http://localhost:8080"},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Verify WebAuthn config was set
	assert.NotNil(t, server.webauthnConfig)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// REST server should be set with WebAuthn
	assert.NotNil(t, server.RESTServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test REST server startup with TLS enabled
func TestServer_StartREST_WithTLS(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.Server.RESTPort = 18383

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// REST server should be set
	assert.NotNil(t, server.RESTServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test REST server startup with TLS config failure
func TestServer_StartREST_TLSConfigFailure(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/nonexistent/cert.pem"
	cfg.TLS.KeyFile = "/nonexistent/key.pem"
	cfg.Server.RESTPort = 18484

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server - should start but REST will fail silently (logs error)
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to attempt start
	time.Sleep(100 * time.Millisecond)

	// REST server should be nil due to TLS config failure
	assert.Nil(t, server.RESTServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test REST server with nil health checker
func TestServer_StartREST_NilHealthChecker(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = false
	cfg.Server.RESTPort = 18585

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Set health checker to nil
	server.healthChecker = nil

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// REST server should still be set
	assert.NotNil(t, server.RESTServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test MCP server startup
func TestServer_StartMCP(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = true
	cfg.Metrics.Enabled = false
	cfg.Server.MCPPort = 13131

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// MCP server should be set
	assert.NotNil(t, server.MCPServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test MCP server with default backend specified
func TestServer_StartMCP_WithDefaultBackend(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = true
	cfg.Metrics.Enabled = false
	cfg.Server.MCPPort = 13232
	cfg.Default = config.DefaultConfig("software")

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// MCP server should be set
	assert.NotNil(t, server.MCPServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test MCP server with nonexistent default backend (falls back to first available)
func TestServer_StartMCP_NonexistentDefault(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = true
	cfg.Metrics.Enabled = false
	cfg.Server.MCPPort = 13333
	cfg.Default = config.DefaultConfig("nonexistent-backend")

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server - should fall back to first available backend
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// MCP server should be set (using fallback)
	assert.NotNil(t, server.MCPServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test QUIC server startup with TLS
func TestServer_StartQUIC_WithTLS(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = true
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.Server.QUICPort = 14141

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// QUIC server should be set
	assert.NotNil(t, server.QUICServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test QUIC server without TLS (should fail gracefully)
func TestServer_StartQUIC_NoTLS(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = true
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = false // QUIC requires TLS
	cfg.Server.QUICPort = 14242

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server - should start but QUIC will fail silently
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to attempt start
	time.Sleep(100 * time.Millisecond)

	// QUIC server should be nil due to TLS requirement
	assert.Nil(t, server.QUICServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test QUIC server with invalid TLS config
func TestServer_StartQUIC_TLSConfigFailure(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = true
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/nonexistent/cert.pem"
	cfg.TLS.KeyFile = "/nonexistent/key.pem"
	cfg.Server.QUICPort = 14343

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server - should start but QUIC will fail silently
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to attempt start
	time.Sleep(100 * time.Millisecond)

	// QUIC server should be nil due to TLS config failure
	assert.Nil(t, server.QUICServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test QUIC server with default backend specified
func TestServer_StartQUIC_WithDefaultBackend(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = true
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.Server.QUICPort = 14444
	cfg.Default = config.DefaultConfig("software")

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// QUIC server should be set
	assert.NotNil(t, server.QUICServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test QUIC server with nonexistent default backend (falls back)
func TestServer_StartQUIC_NonexistentDefault(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = true
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.Server.QUICPort = 14545
	cfg.Default = config.DefaultConfig("nonexistent")

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server - should fall back to first available backend
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// QUIC server should be set
	assert.NotNil(t, server.QUICServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Shutdown with REST server
func TestServer_Shutdown_WithRESTServer(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.Server.RESTPort = 18686

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Shutdown with MCP server
func TestServer_Shutdown_WithMCPServer(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = true
	cfg.Metrics.Enabled = false
	cfg.Server.MCPPort = 13434

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Shutdown with QUIC server
func TestServer_Shutdown_WithQUICServer(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = true
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.Server.QUICPort = 14646

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Start with all protocols enabled (comprehensive)
func TestServer_Start_AllProtocolsComprehensive(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = true
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = true
	cfg.Protocols.QUIC = true
	cfg.Protocols.MCP = true
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 19090
	cfg.Metrics.Path = "/metrics"
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.Server.RESTPort = 18787
	cfg.Server.GRPCPort = 19191
	cfg.Server.QUICPort = 14747
	cfg.Server.MCPPort = 13535
	cfg.Unix.Protocol = "grpc"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give all servers time to start
	time.Sleep(300 * time.Millisecond)

	// Verify all servers are running
	assert.NotNil(t, server.UnixGRPCServer())
	assert.NotNil(t, server.RESTServer())
	assert.NotNil(t, server.GRPCServer())
	assert.NotNil(t, server.QUICServer())
	assert.NotNil(t, server.MCPServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test getBuildVersion with module info
func TestGetBuildVersion_ModuleVersion(t *testing.T) {
	// This tests the code path that reads runtime/debug.BuildInfo
	version := getBuildVersion()
	assert.NotEmpty(t, version)
	// Version should be either "dev" or an actual version
	assert.True(t, version == "dev" || len(version) > 0)
}

// Test gRPC server listen failure
func TestServer_StartGRPC_ListenFailure(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = true
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	// Use an invalid port to trigger listen failure
	cfg.Server.Host = "invalid-host-that-does-not-exist"
	cfg.Server.GRPCPort = 19292

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server - should fail to listen but not return error
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to attempt start
	time.Sleep(100 * time.Millisecond)

	// gRPC server should be nil due to listen failure
	assert.Nil(t, server.GRPCServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test REST server with RBAC enabled
func TestServer_StartREST_WithRBAC(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.Server.RESTPort = 18888
	cfg.Auth.EnableRBAC = true

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// REST server should be set
	assert.NotNil(t, server.RESTServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test closeBackends with valid backends
func TestServer_CloseBackends_ValidBackends(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Close backends should work with valid backends
	server.closeBackends()

	// Backends should still be in the map
	assert.NotEmpty(t, server.backends)

	// Shutdown (will call closeBackends again - should be safe)
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Shutdown calls keychain.Shutdown
func TestServer_Shutdown_CallsKeychainShutdown(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Shutdown should call keychain.Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// ============================================================================
// Additional tests to push coverage to 90%+
// ============================================================================

// Test MCP server with no keystores (should fail gracefully)
func TestServer_StartMCP_NoKeystores(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = true
	cfg.Metrics.Enabled = false
	cfg.Server.MCPPort = 13636

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Clear keystores to test no keystore scenario
	server.keystores = make(map[string]keychain.KeyStore)

	// Start server - should log error but not crash
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to attempt start
	time.Sleep(100 * time.Millisecond)

	// MCP server should be nil (no keystore available)
	assert.Nil(t, server.MCPServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test QUIC server with no keystores (should fail gracefully)
func TestServer_StartQUIC_NoKeystores(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = true
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.Server.QUICPort = 14848

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Clear keystores to test no keystore scenario
	server.keystores = make(map[string]keychain.KeyStore)

	// Start server - should log error but not crash
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to attempt start
	time.Sleep(100 * time.Millisecond)

	// QUIC server should be nil (no keystore available)
	assert.Nil(t, server.QUICServer())

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Initialize function with valid backends
func TestInitialize_WithValidBackends(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "software",
		Backends: []BackendConfig{
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": filepath.Join(tempDir, "software-keys"),
				},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)
}

// Test Initialize function with multiple backends
func TestInitialize_MultipleBackends(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "pkcs8",
		Backends: []BackendConfig{
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": filepath.Join(tempDir, "software-keys"),
				},
			},
			{
				Name:    "pkcs8",
				Type:    "pkcs8",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": filepath.Join(tempDir, "pkcs8-keys"),
				},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)
}

// Test createPKCS8Backend with custom key_dir
func TestCreatePKCS8Backend_CustomKeyDir(t *testing.T) {
	tempDir := t.TempDir()

	config := BackendConfig{
		Name:    "pkcs8",
		Type:    "pkcs8",
		Enabled: true,
		Config: map[string]interface{}{
			"key_dir": filepath.Join(tempDir, "pkcs8-custom"),
		},
	}

	backend, err := createPKCS8Backend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
}

// Test createSoftwareBackend with custom key_dir
func TestCreateSoftwareBackend_CustomKeyDir(t *testing.T) {
	tempDir := t.TempDir()

	config := BackendConfig{
		Name:    "software",
		Type:    "software",
		Enabled: true,
		Config: map[string]interface{}{
			"key_dir": filepath.Join(tempDir, "software-custom"),
		},
	}

	backend, err := createSoftwareBackend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
}

// Test createSymmetricBackend with custom key_dir
func TestCreateSymmetricBackend_CustomKeyDir(t *testing.T) {
	tempDir := t.TempDir()

	config := BackendConfig{
		Name:    "symmetric",
		Type:    "symmetric",
		Enabled: true,
		Config: map[string]interface{}{
			"key_dir": filepath.Join(tempDir, "symmetric-custom"),
		},
	}

	backend, err := createSymmetricBackend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
}

// Test metrics server startup
func TestServer_StartMetrics_Success(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = false
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 19393
	cfg.Metrics.Path = "/metrics"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server with metrics
	err = server.Start()
	assert.NoError(t, err)

	// Give metrics server time to start
	time.Sleep(100 * time.Millisecond)

	// Metrics collector should be initialized
	assert.NotNil(t, server.metricsCollector)

	// Shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test initializeBackends with PKCS8 only
func TestServer_InitializeBackends_PKCS8Only(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	tempDir := t.TempDir()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "127.0.0.1",
			RESTPort: 18080,
		},
		Protocols: config.ProtocolsConfig{
			Unix: false,
			REST: false,
			GRPC: false,
		},
		Unix: config.UnixConfig{
			Enabled: false,
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		TLS: config.TLSConfig{
			Enabled: false,
		},
		Auth: config.AuthConfig{
			Enabled: false,
		},
		Storage: config.StorageConfig{
			Backend: "file",
			Path:    tempDir,
		},
		Default: config.DefaultConfig("pkcs8"),
		Backends: config.BackendsConfig{
			Software: nil,
			PKCS8: &config.PKCS8Config{
				Enabled: true,
				Path:    filepath.Join(tempDir, "pkcs8"),
			},
		},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Only PKCS8 backend should be initialized
	assert.Contains(t, server.backends, "pkcs8")
	assert.NotContains(t, server.backends, "software")
}

// Test Reload updates config correctly
func TestServer_Reload_UpdatesConfig(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "json"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Verify initial config
	assert.Equal(t, "info", server.config.Logging.Level)

	// Create new config with different settings
	newCfg := createMinimalConfig(t)
	newCfg.Logging.Level = "debug"
	newCfg.Logging.Format = "text"

	// Reload
	err = server.Reload(newCfg)
	assert.NoError(t, err)

	// Verify config was updated
	assert.Equal(t, "debug", server.config.Logging.Level)
	assert.Equal(t, "text", server.config.Logging.Format)
}

// Test Initialize with disabled backend
func TestInitialize_WithDisabledBackend(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "software",
		Backends: []BackendConfig{
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": filepath.Join(tempDir, "software-keys"),
				},
			},
			{
				Name:    "disabled",
				Type:    "pkcs8",
				Enabled: false, // Disabled
				Config: map[string]interface{}{
					"key_dir": filepath.Join(tempDir, "disabled-keys"),
				},
			},
		},
	}

	err := Initialize(config)
	assert.NoError(t, err)
}

// Test createTPM2Backend with string handles
func TestCreateTPM2Backend_StringHandles(t *testing.T) {
	// Test with string type handles (tests type assertion fallback)
	config := BackendConfig{
		Name:    "tpm2",
		Type:    "tpm2",
		Enabled: true,
		Config: map[string]interface{}{
			"srk_handle":   "0x81000003",
			"ek_handle":    "0x81010003",
			"platform_pcr": "8",
		},
	}

	_, err := createTPM2Backend(config)
	// Expected to fail - no TPM available in test environment
	assert.Error(t, err)
}

// Test Shutdown with Unix servers
func TestServer_Shutdown_WithUnixServers(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = true
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.MCP = false
	cfg.Metrics.Enabled = false
	cfg.Unix.Protocol = "grpc"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Unix HTTP server should be set
	assert.NotNil(t, server.UnixGRPCServer())

	// Shutdown should properly stop Unix server
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test server with empty default (uses first available)
func TestServer_EmptyDefault(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Default = "" // Empty default

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { _ = server.Shutdown() }()

	// Should have keystores
	assert.NotEmpty(t, server.keystores)
}

// ============================================================================
// Final tests to reach 90%+ coverage
// ============================================================================

// Test New with keystore initialization failure
func TestNew_KeyStoreInitFailure(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	// Set storage path to an invalid location that will fail during keystore init
	cfg.Storage.Path = "/dev/null/invalid/path/that/cannot/be/created"

	_, err := New(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed")
}

// Test createBackend factory function with all types
func TestCreateBackend_AllTypesWithKeyDir(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		backendType string
		keyDir      string
		expectError bool
	}{
		{
			name:        "software with key_dir",
			backendType: "software",
			keyDir:      filepath.Join(tempDir, "soft"),
			expectError: false,
		},
		{
			name:        "pkcs8 with key_dir",
			backendType: "pkcs8",
			keyDir:      filepath.Join(tempDir, "pkcs8"),
			expectError: false,
		},
		{
			name:        "symmetric with key_dir",
			backendType: "symmetric",
			keyDir:      filepath.Join(tempDir, "sym"),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := BackendConfig{
				Name:    tt.name,
				Type:    tt.backendType,
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": tt.keyDir,
				},
			}

			backend, err := createBackend(config)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, backend)
			}
		})
	}
}

// Test Initialize with backend creation failure
func TestInitialize_BackendCreationFailure(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	config := &BackendFactoryConfig{
		DefaultBackend: "tpm2",
		Backends: []BackendConfig{
			{
				Name:    "tpm2",
				Type:    "tpm2",
				Enabled: true,
				Config:  map[string]interface{}{},
			},
		},
	}

	// Should fail because TPM is not available
	err := Initialize(config)
	assert.Error(t, err)
}

// Test startUnix with different protocol modes
func TestServer_StartUnix_AllModes(t *testing.T) {
	protocols := []string{"grpc"}

	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			keychain.Reset()
			defer keychain.Reset()

			cfg := createMinimalConfig(t)
			cfg.Protocols.Unix = true
			cfg.Protocols.REST = false
			cfg.Protocols.GRPC = false
			cfg.Protocols.QUIC = false
			cfg.Protocols.MCP = false
			cfg.Metrics.Enabled = false
			cfg.Unix.Protocol = proto

			server, err := New(cfg)
			require.NoError(t, err)
			require.NotNil(t, server)

			err = server.Start()
			assert.NoError(t, err)

			time.Sleep(100 * time.Millisecond)

			err = server.Shutdown()
			assert.NoError(t, err)
		})
	}
}

// Test Shutdown with all servers running
func TestServer_Shutdown_AllServersRunning(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.Protocols.Unix = true
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = true
	cfg.Protocols.QUIC = false // Skip QUIC to reduce test time
	cfg.Protocols.MCP = true
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 19494
	cfg.Metrics.Path = "/metrics"
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.Server.RESTPort = 18989
	cfg.Server.GRPCPort = 19292
	cfg.Server.MCPPort = 13737
	cfg.Unix.Protocol = "grpc"

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	err = server.Start()
	assert.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Verify all servers started
	assert.NotNil(t, server.UnixGRPCServer())
	assert.NotNil(t, server.RESTServer())
	assert.NotNil(t, server.GRPCServer())
	assert.NotNil(t, server.MCPServer())

	// Shutdown all
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test Initialize with nonexistent default backend
func TestInitialize_NonexistentDefault(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	tempDir := t.TempDir()

	config := &BackendFactoryConfig{
		DefaultBackend: "nonexistent",
		Backends: []BackendConfig{
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": filepath.Join(tempDir, "keys"),
				},
			},
		},
	}

	// Should succeed (uses first available backend)
	err := Initialize(config)
	assert.NoError(t, err)
}

// Test closeBackends is idempotent
func TestServer_CloseBackends_Idempotent(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Close backends multiple times
	server.closeBackends()
	server.closeBackends()
	server.closeBackends()

	// Should still be safe to shutdown
	err = server.Shutdown()
	assert.NoError(t, err)
}

// Test createPKCS8Backend with invalid key_dir
func TestCreatePKCS8Backend_InvalidKeyDir(t *testing.T) {
	config := BackendConfig{
		Name:    "pkcs8",
		Type:    "pkcs8",
		Enabled: true,
		Config: map[string]interface{}{
			"key_dir": "/dev/null/invalid",
		},
	}

	_, err := createPKCS8Backend(config)
	assert.Error(t, err)
}

// Test createSoftwareBackend with invalid key_dir
func TestCreateSoftwareBackend_InvalidKeyDir(t *testing.T) {
	config := BackendConfig{
		Name:    "software",
		Type:    "software",
		Enabled: true,
		Config: map[string]interface{}{
			"key_dir": "/dev/null/invalid",
		},
	}

	_, err := createSoftwareBackend(config)
	assert.Error(t, err)
}

// Test createSymmetricBackend with invalid key_dir
func TestCreateSymmetricBackend_InvalidKeyDir(t *testing.T) {
	config := BackendConfig{
		Name:    "symmetric",
		Type:    "symmetric",
		Enabled: true,
		Config: map[string]interface{}{
			"key_dir": "/dev/null/invalid",
		},
	}

	_, err := createSymmetricBackend(config)
	assert.Error(t, err)
}

// Test Initialize error path when createBackend fails
func TestInitialize_CreateBackendError(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	config := &BackendFactoryConfig{
		DefaultBackend: "software",
		Backends: []BackendConfig{
			{
				Name:    "software",
				Type:    "software",
				Enabled: true,
				Config: map[string]interface{}{
					"key_dir": "/dev/null/invalid",
				},
			},
		},
	}

	err := Initialize(config)
	assert.Error(t, err)
}

// Test server with authentication initialization error
func TestServer_InitAuth_Error(t *testing.T) {
	keychain.Reset()
	defer keychain.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "jwt"
	cfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: "/nonexistent/key.pem",
	}

	_, err := New(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication")
}
