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

package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// createTestCerts creates temporary test certificates for mTLS testing.
func createTestCerts(t *testing.T) (certFile, keyFile, caFile string, cleanup func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	cleanup = func() {
		os.RemoveAll(tmpDir)
	}

	// Generate CA private key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		cleanup()
		t.Fatalf("failed to generate CA key: %v", err)
	}

	// Create CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		cleanup()
		t.Fatalf("failed to create CA cert: %v", err)
	}

	// Write CA certificate
	caFile = filepath.Join(tmpDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		cleanup()
		t.Fatalf("failed to write CA file: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		cleanup()
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	// Generate client private key
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		cleanup()
		t.Fatalf("failed to generate client key: %v", err)
	}

	// Create client certificate
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		cleanup()
		t.Fatalf("failed to create client cert: %v", err)
	}

	// Write client certificate
	certFile = filepath.Join(tmpDir, "client.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		cleanup()
		t.Fatalf("failed to write cert file: %v", err)
	}

	// Write client key
	keyFile = filepath.Join(tmpDir, "client-key.pem")
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		cleanup()
		t.Fatalf("failed to marshal client key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		cleanup()
		t.Fatalf("failed to write key file: %v", err)
	}

	return certFile, keyFile, caFile, cleanup
}

func TestLoadTLSConfig_EmptyConfig(t *testing.T) {
	cfg, err := LoadTLSConfig(TLSConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion TLS1.3, got %v", cfg.MinVersion)
	}
}

func TestLoadTLSConfig_EnforcesTLS13(t *testing.T) {
	cfg, err := LoadTLSConfig(TLSConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 enforcement, got MinVersion=%v", cfg.MinVersion)
	}
}

func TestLoadTLSConfig_WithServerName(t *testing.T) {
	cfg, err := LoadTLSConfig(TLSConfig{
		ServerName: "example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ServerName != "example.com" {
		t.Errorf("expected ServerName='example.com', got %q", cfg.ServerName)
	}
}

func TestLoadTLSConfig_WithClientCert(t *testing.T) {
	certFile, keyFile, _, cleanup := createTestCerts(t)
	defer cleanup()

	cfg, err := LoadTLSConfig(TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
}

func TestLoadTLSConfig_WithInvalidCert(t *testing.T) {
	_, err := LoadTLSConfig(TLSConfig{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("expected error for invalid cert file")
	}
	if errors.Code(err) != errors.CodeConfiguration {
		t.Errorf("expected Configuration error, got %v", errors.Code(err))
	}
}

func TestLoadTLSConfig_WithCAFile(t *testing.T) {
	_, _, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	cfg, err := LoadTLSConfig(TLSConfig{
		CAFile: caFile,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestLoadTLSConfig_WithInvalidCAFile(t *testing.T) {
	_, err := LoadTLSConfig(TLSConfig{
		CAFile: "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("expected error for invalid CA file")
	}
	if errors.Code(err) != errors.CodeConfiguration {
		t.Errorf("expected Configuration error, got %v", errors.Code(err))
	}
}

func TestLoadTLSConfig_WithInvalidCACert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write invalid PEM data
	invalidCA := filepath.Join(tmpDir, "invalid-ca.pem")
	if err := os.WriteFile(invalidCA, []byte("not a valid certificate"), 0600); err != nil {
		t.Fatalf("failed to write invalid CA: %v", err)
	}

	_, err = LoadTLSConfig(TLSConfig{
		CAFile: invalidCA,
	})
	if err == nil {
		t.Fatal("expected error for invalid CA cert content")
	}
	if errors.Code(err) != errors.CodeConfiguration {
		t.Errorf("expected Configuration error, got %v", errors.Code(err))
	}
}

func TestLoadTLSConfig_FullMTLS(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	cfg, err := LoadTLSConfig(TLSConfig{
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     caFile,
		ServerName: "test.local",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
	if cfg.ServerName != "test.local" {
		t.Errorf("expected ServerName='test.local', got %q", cfg.ServerName)
	}
}

func TestLoadTLSConfigFromFiles(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	cfg, err := LoadTLSConfigFromFiles(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestLoadTLSConfigFromFiles_PartialFiles(t *testing.T) {
	certFile, keyFile, _, cleanup := createTestCerts(t)
	defer cleanup()

	// Only cert and key, no CA
	cfg, err := LoadTLSConfigFromFiles(certFile, keyFile, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
	if cfg.RootCAs != nil {
		t.Error("expected RootCAs to be nil when CAFile is empty")
	}
}

func TestValidateTLSConfig_NilConfig(t *testing.T) {
	err := ValidateTLSConfig(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected InvalidInput error, got %v", err)
	}
}

func TestValidateTLSConfig_ValidTLS13Config(t *testing.T) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	err := ValidateTLSConfig(cfg)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateTLSConfig_RejectsTLS12(t *testing.T) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	err := ValidateTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for TLS 1.2")
	}
	if errors.Code(err) != errors.CodeConfiguration {
		t.Errorf("expected Configuration error, got %v", errors.Code(err))
	}
}

func TestValidateTLSConfig_RejectsDeprecatedTLSVersion(t *testing.T) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS10,
	}

	err := ValidateTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for deprecated TLS version")
	}
	if errors.Code(err) != errors.CodeConfiguration {
		t.Errorf("expected Configuration error, got %v", errors.Code(err))
	}
}

func TestValidateTLSConfig_ZeroMinVersion(t *testing.T) {
	// MinVersion = 0 means Go defaults (which is TLS 1.2+)
	cfg := &tls.Config{
		MinVersion: 0,
	}

	err := ValidateTLSConfig(cfg)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCloneTLSConfig_NilConfig(t *testing.T) {
	result := CloneTLSConfig(nil)
	if result != nil {
		t.Error("expected nil result for nil input")
	}
}

func TestCloneTLSConfig_ValidConfig(t *testing.T) {
	original := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: "example.com",
	}

	clone := CloneTLSConfig(original)

	if clone == nil {
		t.Fatal("expected non-nil clone")
	}
	if clone == original {
		t.Error("clone should be a different instance")
	}
	if clone.MinVersion != original.MinVersion {
		t.Error("MinVersion should be copied")
	}
	if clone.ServerName != original.ServerName {
		t.Error("ServerName should be copied")
	}
}

func TestTLSConfig_Struct(t *testing.T) {
	cfg := TLSConfig{
		CertFile:   "/path/to/cert.pem",
		KeyFile:    "/path/to/key.pem",
		CAFile:     "/path/to/ca.pem",
		ServerName: "server.example.com",
	}

	if cfg.CertFile != "/path/to/cert.pem" {
		t.Error("CertFile not set correctly")
	}
	if cfg.KeyFile != "/path/to/key.pem" {
		t.Error("KeyFile not set correctly")
	}
	if cfg.CAFile != "/path/to/ca.pem" {
		t.Error("CAFile not set correctly")
	}
	if cfg.ServerName != "server.example.com" {
		t.Error("ServerName not set correctly")
	}
}
