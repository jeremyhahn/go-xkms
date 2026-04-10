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

package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCertBundle generates a CA certificate and a signed server/client
// certificate pair, writing them to disk and returning the file paths.
type testCertBundle struct {
	CACertPath     string
	ServerCertPath string
	ServerKeyPath  string
	ClientCertPath string
	ClientKeyPath  string
}

func generateTestCerts(t *testing.T) *testCertBundle {
	t.Helper()
	dir := t.TempDir()

	// Generate CA key and certificate.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	// Write CA cert.
	caCertPath := filepath.Join(dir, "ca.pem")
	writePEM(t, caCertPath, "CERTIFICATE", caCertDER)

	// Generate server cert.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}

	serverCertPath := filepath.Join(dir, "server-cert.pem")
	serverKeyPath := filepath.Join(dir, "server-key.pem")
	writePEM(t, serverCertPath, "CERTIFICATE", serverCertDER)
	writeECKey(t, serverKeyPath, serverKey)

	// Generate client cert.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-agent"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client cert: %v", err)
	}

	clientCertPath := filepath.Join(dir, "client-cert.pem")
	clientKeyPath := filepath.Join(dir, "client-key.pem")
	writePEM(t, clientCertPath, "CERTIFICATE", clientCertDER)
	writeECKey(t, clientKeyPath, clientKey)

	return &testCertBundle{
		CACertPath:     caCertPath,
		ServerCertPath: serverCertPath,
		ServerKeyPath:  serverKeyPath,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
	}
}

func writePEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	pemData := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: data})
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func writeECKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	writePEM(t, path, "EC PRIVATE KEY", keyDER)
}

func TestServer_BuildTLSConfig_WithCerts(t *testing.T) {
	certs := generateTestCerts(t)

	cfg := DefaultConfig()
	cfg.ListenAddress = "localhost:0"
	cfg.TLSCertFile = certs.ServerCertPath
	cfg.TLSKeyFile = certs.ServerKeyPath

	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(cfg, enrollment, testLogger())

	tlsConfig, err := server.buildTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("TLS config should not be nil")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}
}

func TestServer_BuildTLSConfig_WithCA(t *testing.T) {
	certs := generateTestCerts(t)

	cfg := DefaultConfig()
	cfg.ListenAddress = "localhost:0"
	cfg.TLSCertFile = certs.ServerCertPath
	cfg.TLSKeyFile = certs.ServerKeyPath
	cfg.TLSCAFile = certs.CACertPath

	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(cfg, enrollment, testLogger())

	tlsConfig, err := server.buildTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsConfig.ClientCAs == nil {
		t.Error("client CAs should be set when CA file is configured")
	}
}

func TestServer_BuildTLSConfig_InvalidCAFile(t *testing.T) {
	certs := generateTestCerts(t)

	cfg := DefaultConfig()
	cfg.TLSCertFile = certs.ServerCertPath
	cfg.TLSKeyFile = certs.ServerKeyPath
	cfg.TLSCAFile = "/nonexistent/ca.pem"

	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(cfg, enrollment, testLogger())

	_, err := server.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid CA file")
	}
}

func TestServer_BuildTLSConfig_InvalidCAPEM(t *testing.T) {
	certs := generateTestCerts(t)

	// Write a file with invalid PEM content.
	badCAPath := filepath.Join(t.TempDir(), "bad-ca.pem")
	if err := os.WriteFile(badCAPath, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("failed to create bad CA file: %v", err)
	}

	cfg := DefaultConfig()
	cfg.TLSCertFile = certs.ServerCertPath
	cfg.TLSKeyFile = certs.ServerKeyPath
	cfg.TLSCAFile = badCAPath

	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(cfg, enrollment, testLogger())

	_, err := server.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid CA PEM")
	}
}

func TestClient_BuildTLSConfig_WithCerts(t *testing.T) {
	certs := generateTestCerts(t)

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = "localhost:9443"
	clientCfg.TLSCertFile = certs.ClientCertPath
	clientCfg.TLSKeyFile = certs.ClientKeyPath

	client, _ := NewClient(clientCfg, testLogger())

	tlsConfig, err := client.buildTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("TLS config should not be nil")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}
}

func TestClient_BuildTLSConfig_WithCA(t *testing.T) {
	certs := generateTestCerts(t)

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = "localhost:9443"
	clientCfg.TLSCertFile = certs.ClientCertPath
	clientCfg.TLSKeyFile = certs.ClientKeyPath
	clientCfg.TLSCAFile = certs.CACertPath

	client, _ := NewClient(clientCfg, testLogger())

	tlsConfig, err := client.buildTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsConfig.RootCAs == nil {
		t.Error("root CAs should be set when CA file is configured")
	}
}

func TestClient_BuildTLSConfig_InvalidCAFile(t *testing.T) {
	certs := generateTestCerts(t)

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = "localhost:9443"
	clientCfg.TLSCertFile = certs.ClientCertPath
	clientCfg.TLSKeyFile = certs.ClientKeyPath
	clientCfg.TLSCAFile = "/nonexistent/ca.pem"

	client, _ := NewClient(clientCfg, testLogger())

	_, err := client.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid CA file")
	}
}

func TestClient_BuildTLSConfig_InvalidCAPEM(t *testing.T) {
	certs := generateTestCerts(t)

	badCAPath := filepath.Join(t.TempDir(), "bad-ca.pem")
	if err := os.WriteFile(badCAPath, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("failed to create bad CA file: %v", err)
	}

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = "localhost:9443"
	clientCfg.TLSCertFile = certs.ClientCertPath
	clientCfg.TLSKeyFile = certs.ClientKeyPath
	clientCfg.TLSCAFile = badCAPath

	client, _ := NewClient(clientCfg, testLogger())

	_, err := client.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid CA PEM")
	}
}

func TestClient_BuildDialOptions_WithTLS(t *testing.T) {
	certs := generateTestCerts(t)

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = "localhost:9443"
	clientCfg.TLSCertFile = certs.ClientCertPath
	clientCfg.TLSKeyFile = certs.ClientKeyPath

	client, _ := NewClient(clientCfg, testLogger())

	opts, err := client.buildDialOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts) == 0 {
		t.Error("should have at least one dial option")
	}
}

func TestServer_StartWithTLS(t *testing.T) {
	certs := generateTestCerts(t)

	cfg := DefaultConfig()
	cfg.ListenAddress = "localhost:0"
	cfg.TLSCertFile = certs.ServerCertPath
	cfg.TLSKeyFile = certs.ServerKeyPath

	enrollment, _ := testEnrollmentService(t)
	server, err := NewServer(cfg, enrollment, testLogger())
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("start with TLS failed: %v", err)
	}
	defer server.Stop()

	if !server.IsRunning() {
		t.Error("server should be running")
	}
}

func TestServer_StartWithMTLS(t *testing.T) {
	certs := generateTestCerts(t)

	cfg := DefaultConfig()
	cfg.ListenAddress = "localhost:0"
	cfg.TLSCertFile = certs.ServerCertPath
	cfg.TLSKeyFile = certs.ServerKeyPath
	cfg.TLSCAFile = certs.CACertPath

	enrollment, _ := testEnrollmentService(t)
	server, err := NewServer(cfg, enrollment, testLogger())
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("start with mTLS failed: %v", err)
	}
	defer server.Stop()

	if !server.IsRunning() {
		t.Error("server should be running")
	}
}
