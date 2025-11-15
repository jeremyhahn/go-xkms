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
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-keychain/internal/testutil"
)

func TestLoadTLSConfig_Disabled(t *testing.T) {
	cfg := &TLSConfig{
		Enabled: false,
	}

	tlsConfig, err := cfg.LoadTLSConfig()

	if err != nil {
		t.Fatalf("LoadTLSConfig() error = %v, want nil", err)
	}

	if tlsConfig != nil {
		t.Errorf("LoadTLSConfig() = %v, want nil for disabled TLS", tlsConfig)
	}
}

func TestLoadTLSConfig_ValidConfig(t *testing.T) {
	// Generate test certificates
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	// Create temp directory for test files
	tmpDir := t.TempDir()

	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, serverCert.KeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	tlsConfig, err := cfg.LoadTLSConfig()

	if err != nil {
		t.Fatalf("LoadTLSConfig() error = %v, want nil", err)
	}

	if tlsConfig == nil {
		t.Fatal("LoadTLSConfig() returned nil config")
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("len(Certificates) = %v, want 1", len(tlsConfig.Certificates))
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want TLS 1.2", tlsConfig.MinVersion)
	}
}

func TestLoadTLSConfig_MissingCertFile(t *testing.T) {
	cfg := &TLSConfig{
		Enabled:  true,
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}

	_, err := cfg.LoadTLSConfig()

	if err == nil {
		t.Fatal("LoadTLSConfig() should return error for missing cert file")
	}
}

func TestLoadTLSConfig_MissingKeyFile(t *testing.T) {
	// Create a valid cert but no key
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  "/nonexistent/key.pem",
	}

	_, err = cfg.LoadTLSConfig()

	if err == nil {
		t.Fatal("LoadTLSConfig() should return error for missing key file")
	}
}

func TestLoadTLSConfig_WithTLSVersions(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, serverCert.KeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		MinVersion: "TLS1.3",
		MaxVersion: "TLS1.3",
	}

	tlsConfig, err := cfg.LoadTLSConfig()

	if err != nil {
		t.Fatalf("LoadTLSConfig() error = %v, want nil", err)
	}

	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", tlsConfig.MinVersion)
	}

	if tlsConfig.MaxVersion != tls.VersionTLS13 {
		t.Errorf("MaxVersion = %v, want TLS 1.3", tlsConfig.MaxVersion)
	}
}

func TestLoadTLSConfig_WithCipherSuites(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, serverCert.KeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
		CipherSuites: []string{
			"TLS_AES_128_GCM_SHA256",
			"TLS_AES_256_GCM_SHA384",
		},
	}

	tlsConfig, err := cfg.LoadTLSConfig()

	if err != nil {
		t.Fatalf("LoadTLSConfig() error = %v, want nil", err)
	}

	if len(tlsConfig.CipherSuites) != 2 {
		t.Errorf("len(CipherSuites) = %v, want 2", len(tlsConfig.CipherSuites))
	}
}

func TestLoadTLSConfig_InvalidCipherSuite(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, serverCert.KeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
		CipherSuites: []string{
			"INVALID_CIPHER_SUITE",
		},
	}

	_, err = cfg.LoadTLSConfig()

	if err == nil {
		t.Fatal("LoadTLSConfig() should return error for invalid cipher suite")
	}
}

func TestLoadTLSConfig_PreferServerCiphers(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, serverCert.KeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:             true,
		CertFile:            certFile,
		KeyFile:             keyFile,
		PreferServerCiphers: true,
	}

	tlsConfig, err := cfg.LoadTLSConfig()

	if err != nil {
		t.Fatalf("LoadTLSConfig() error = %v, want nil", err)
	}

	if !tlsConfig.PreferServerCipherSuites {
		t.Error("PreferServerCipherSuites should be true")
	}
}

func TestLoadTLSConfig_WithClientAuth(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	caFile := filepath.Join(tmpDir, "ca.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, serverCert.KeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	if err := os.WriteFile(caFile, ca.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		ClientAuth: "require_and_verify",
		CAFile:     caFile,
	}

	tlsConfig, err := cfg.LoadTLSConfig()

	if err != nil {
		t.Fatalf("LoadTLSConfig() error = %v, want nil", err)
	}

	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsConfig.ClientAuth)
	}

	if tlsConfig.ClientCAs == nil {
		t.Error("ClientCAs should not be nil")
	}
}

func TestParseTLSVersion(t *testing.T) {
	tests := []struct {
		version  string
		expected uint16
	}{
		{"TLS1.0", tls.VersionTLS10},
		{"TLS1.1", tls.VersionTLS11},
		{"TLS1.2", tls.VersionTLS12},
		{"TLS1.3", tls.VersionTLS13},
		{"unknown", tls.VersionTLS12}, // Default
		{"", tls.VersionTLS12},        // Default
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			result := parseTLSVersion(tt.version)

			if result != tt.expected {
				t.Errorf("parseTLSVersion(%s) = %v, want %v", tt.version, result, tt.expected)
			}
		})
	}
}

func TestParseClientAuthType(t *testing.T) {
	tests := []struct {
		authType    string
		expected    tls.ClientAuthType
		expectError bool
	}{
		{"none", tls.NoClientCert, false},
		{"", tls.NoClientCert, false},
		{"request", tls.RequestClientCert, false},
		{"require", tls.RequireAnyClientCert, false},
		{"verify", tls.VerifyClientCertIfGiven, false},
		{"require_and_verify", tls.RequireAndVerifyClientCert, false},
		{"unknown", tls.NoClientCert, true},
		{"invalid", tls.NoClientCert, true},
	}

	for _, tt := range tests {
		t.Run(tt.authType, func(t *testing.T) {
			result, err := parseClientAuthType(tt.authType)

			if tt.expectError {
				if err == nil {
					t.Error("parseClientAuthType() should return error")
				}
			} else {
				if err != nil {
					t.Errorf("parseClientAuthType() error = %v, want nil", err)
				}

				if result != tt.expected {
					t.Errorf("parseClientAuthType(%s) = %v, want %v", tt.authType, result, tt.expected)
				}
			}
		})
	}
}

func TestParseCipherSuites_Valid(t *testing.T) {
	suites := []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}

	result, err := parseCipherSuites(suites)

	if err != nil {
		t.Fatalf("parseCipherSuites() error = %v, want nil", err)
	}

	if len(result) != 4 {
		t.Errorf("len(result) = %v, want 4", len(result))
	}

	expectedIDs := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	for i, expected := range expectedIDs {
		if result[i] != expected {
			t.Errorf("result[%d] = %v, want %v", i, result[i], expected)
		}
	}
}

func TestParseCipherSuites_Invalid(t *testing.T) {
	suites := []string{
		"TLS_AES_128_GCM_SHA256",
		"INVALID_CIPHER",
	}

	_, err := parseCipherSuites(suites)

	if err == nil {
		t.Fatal("parseCipherSuites() should return error for invalid cipher")
	}
}

func TestLoadCertPool_SingleCA(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	if err := os.WriteFile(caFile, ca.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	pool, err := loadCertPool(caFile, nil)

	if err != nil {
		t.Fatalf("loadCertPool() error = %v, want nil", err)
	}

	if pool == nil {
		t.Fatal("loadCertPool() returned nil pool")
	}
}

func TestLoadCertPool_MultipleCA(t *testing.T) {
	ca1, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA1: %v", err)
	}

	ca2, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA2: %v", err)
	}

	tmpDir := t.TempDir()
	caFile1 := filepath.Join(tmpDir, "ca1.pem")
	caFile2 := filepath.Join(tmpDir, "ca2.pem")

	if err := os.WriteFile(caFile1, ca1.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA1 file: %v", err)
	}

	if err := os.WriteFile(caFile2, ca2.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA2 file: %v", err)
	}

	pool, err := loadCertPool(caFile1, []string{caFile2})

	if err != nil {
		t.Fatalf("loadCertPool() error = %v, want nil", err)
	}

	if pool == nil {
		t.Fatal("loadCertPool() returned nil pool")
	}
}

func TestLoadCertPool_InvalidCAFile(t *testing.T) {
	_, err := loadCertPool("/nonexistent/ca.pem", nil)

	if err == nil {
		t.Fatal("loadCertPool() should return error for invalid CA file")
	}
}

func TestLoadCertPool_InvalidCAContent(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "invalid.pem")

	// Write invalid PEM content
	if err := os.WriteFile(caFile, []byte("invalid content"), 0644); err != nil {
		t.Fatalf("Failed to write invalid CA file: %v", err)
	}

	_, err := loadCertPool(caFile, nil)

	if err == nil {
		t.Fatal("loadCertPool() should return error for invalid CA content")
	}
}

func TestLoadCertPool_AdditionalCAError(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	if err := os.WriteFile(caFile, ca.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	// Include a non-existent additional CA
	_, err = loadCertPool(caFile, []string{"/nonexistent/ca2.pem"})

	if err == nil {
		t.Fatal("loadCertPool() should return error for invalid additional CA")
	}
}

func TestLoadCertPool_EmptyMainCA(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	if err := os.WriteFile(caFile, ca.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	// Load with empty main CA file but valid additional CAs
	pool, err := loadCertPool("", []string{caFile})

	if err != nil {
		t.Fatalf("loadCertPool() error = %v, want nil", err)
	}

	if pool == nil {
		t.Fatal("loadCertPool() returned nil pool")
	}
}

func TestLoadTLSConfig_ClientAuthNone(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, serverCert.KeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		ClientAuth: "none",
	}

	tlsConfig, err := cfg.LoadTLSConfig()

	if err != nil {
		t.Fatalf("LoadTLSConfig() error = %v, want nil", err)
	}

	if tlsConfig.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", tlsConfig.ClientAuth)
	}
}

func TestLoadTLSConfig_EmptyClientAuth(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, serverCert.KeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		ClientAuth: "",
	}

	tlsConfig, err := cfg.LoadTLSConfig()

	if err != nil {
		t.Fatalf("LoadTLSConfig() error = %v, want nil", err)
	}

	if tlsConfig == nil {
		t.Fatal("LoadTLSConfig() returned nil config")
	}
}

func TestLoadTLSConfig_NoMaxVersion(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, serverCert.KeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		MinVersion: "TLS1.2",
		MaxVersion: "", // Empty, should not set MaxVersion
	}

	tlsConfig, err := cfg.LoadTLSConfig()

	if err != nil {
		t.Fatalf("LoadTLSConfig() error = %v, want nil", err)
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want TLS 1.2", tlsConfig.MinVersion)
	}

	// MaxVersion should be 0 (not set) when not specified
	if tlsConfig.MaxVersion != 0 {
		t.Errorf("MaxVersion = %v, want 0 (not set)", tlsConfig.MaxVersion)
	}
}

func TestLoadTLSConfig_ClientAuthWithoutCA(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, serverCert.KeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		ClientAuth: "require",
		// No CAFile or ClientCAs - should still work but ClientCAs will be nil
	}

	tlsConfig, err := cfg.LoadTLSConfig()

	if err != nil {
		t.Fatalf("LoadTLSConfig() error = %v, want nil", err)
	}

	if tlsConfig.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAnyClientCert", tlsConfig.ClientAuth)
	}

	// ClientCAs should be nil since no CA files were provided
	if tlsConfig.ClientCAs != nil {
		t.Error("ClientCAs should be nil when no CA files provided")
	}
}

func TestLoadTLSConfig_InvalidClientAuthType(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, serverCert.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	if err := os.WriteFile(keyFile, serverCert.KeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := &TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		ClientAuth: "invalid_auth_type",
	}

	_, err = cfg.LoadTLSConfig()

	if err == nil {
		t.Fatal("LoadTLSConfig() should return error for invalid client auth type")
	}
}
