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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ListenAddress = "localhost:0" // Use ephemeral port.
	enrollment, _ := testEnrollmentService(t)

	server, err := NewServer(cfg, enrollment, testLogger())
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	return server
}

func TestNewServer_NilConfig(t *testing.T) {
	enrollment, _ := testEnrollmentService(t)
	_, err := NewServer(nil, enrollment, testLogger())
	if !errors.Is(err, ErrNilConfig) {
		t.Errorf("expected ErrNilConfig, got %v", err)
	}
}

func TestNewServer_NilEnrollment(t *testing.T) {
	_, err := NewServer(DefaultConfig(), nil, testLogger())
	if !errors.Is(err, ErrNilEnrollmentService) {
		t.Errorf("expected ErrNilEnrollmentService, got %v", err)
	}
}

func TestNewServer_NilLogger(t *testing.T) {
	enrollment, _ := testEnrollmentService(t)
	_, err := NewServer(DefaultConfig(), enrollment, nil)
	if !errors.Is(err, ErrNilLogger) {
		t.Errorf("expected ErrNilLogger, got %v", err)
	}
}

func TestServer_StartStop(t *testing.T) {
	server := testServer(t)

	if server.IsRunning() {
		t.Error("server should not be running before Start")
	}

	if err := server.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	if !server.IsRunning() {
		t.Error("server should be running after Start")
	}

	addr := server.Addr()
	if addr == "" {
		t.Error("server should have an address after Start")
	}

	// No wait needed: Start already binds the listener and reports the
	// address synchronously (confirmed above), so Stop needs nothing more.
	if err := server.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	if server.IsRunning() {
		t.Error("server should not be running after Stop")
	}
}

func TestServer_DoubleStart(t *testing.T) {
	server := testServer(t)

	if err := server.Start(); err != nil {
		t.Fatalf("first start failed: %v", err)
	}
	defer server.Stop()

	err := server.Start()
	if !errors.Is(err, ErrServerAlreadyRunning) {
		t.Errorf("expected ErrServerAlreadyRunning, got %v", err)
	}
}

func TestServer_StopWithoutStart(t *testing.T) {
	server := testServer(t)

	err := server.Stop()
	if !errors.Is(err, ErrServerNotStarted) {
		t.Errorf("expected ErrServerNotStarted, got %v", err)
	}
}

func TestServer_ConnectedAgents_Empty(t *testing.T) {
	server := testServer(t)

	if err := server.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer server.Stop()

	agents := server.ConnectedAgents()
	if len(agents) != 0 {
		t.Errorf("expected no connected agents, got %d", len(agents))
	}
}

func TestServer_Addr_NotStarted(t *testing.T) {
	server := testServer(t)
	if server.Addr() != "" {
		t.Error("addr should be empty when not started")
	}
}

func TestServer_RecordActivity(t *testing.T) {
	server := testServer(t)

	server.recordActivity(nil, "", "192.168.1.100:12345")

	agents := server.ConnectedAgents()
	if len(agents) != 1 {
		t.Fatalf("expected 1 connected agent, got %d", len(agents))
	}
	if agents[0].Info.Address != "192.168.1.100:12345" {
		t.Errorf("expected address 192.168.1.100:12345, got %q", agents[0].Info.Address)
	}

	// Recording again must update the last activity, and the earlier
	// snapshot must not change underneath the caller.
	first := agents[0].LastActivity
	time.Sleep(10 * time.Millisecond)
	server.recordActivity(nil, "", "192.168.1.100:12345")

	updated := server.ConnectedAgents()
	if !updated[0].LastActivity.After(first) {
		t.Error("last activity should have been updated")
	}
	if !agents[0].LastActivity.Equal(first) {
		t.Error("an earlier snapshot must not observe later activity")
	}
}

func TestServer_GRPCServerOptions_Plaintext(t *testing.T) {
	server := testServer(t)

	opts := server.grpcServerOptions(nil)

	// MaxRecvMsgSize, MaxSendMsgSize, ConnectionTimeout, MaxConcurrentStreams,
	// KeepaliveEnforcementPolicy, the tracking interceptor, and the stats
	// handler -- no grpc.Creds without a TLS config (go-xkms#1263).
	const wantPlaintext = 7
	if len(opts) != wantPlaintext {
		t.Errorf("expected %d server options without TLS, got %d", wantPlaintext, len(opts))
	}
}

func TestServer_GRPCServerOptions_TLSAddsCredentials(t *testing.T) {
	server := testServer(t)

	plaintext := server.grpcServerOptions(nil)
	withTLS := server.grpcServerOptions(&tls.Config{MinVersion: tls.VersionTLS13})

	if len(withTLS) != len(plaintext)+1 {
		t.Errorf("expected TLS config to add exactly one option (grpc.Creds), got %d vs %d", len(withTLS), len(plaintext))
	}
}

func TestServer_GRPCServerOptions_HonorsCustomHardeningConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddress = "localhost:0"
	cfg.MaxRecvMsgSize = 1024
	cfg.MaxSendMsgSize = 1024
	cfg.ConnectionTimeout = 5 * time.Second
	cfg.MaxConcurrentStreams = 10
	enrollment, _ := testEnrollmentService(t)
	server, err := NewServer(cfg, enrollment, testLogger())
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// A server built from these hardening options must still start and
	// stop cleanly (mirrors pkg/api/unix's TestGRPCServer_MessageSizeLimits
	// / TestGRPCServer_ConcurrentStreamLimit seam).
	if err := server.Start(); err != nil {
		t.Fatalf("start failed with custom hardening config: %v", err)
	}
	if err := server.Stop(); err != nil {
		t.Fatalf("stop failed with custom hardening config: %v", err)
	}
}

func TestServer_BuildTLSConfig_NoCerts(t *testing.T) {
	server := testServer(t)

	tlsConfig, err := server.buildTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsConfig != nil {
		t.Error("TLS config should be nil when no cert files are configured")
	}
}

func TestServer_BuildTLSConfig_InvalidCerts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSCertFile = "/nonexistent/cert.pem"
	cfg.TLSKeyFile = "/nonexistent/key.pem"

	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(cfg, enrollment, testLogger())

	_, err := server.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid cert files")
	}
}

// TestServer_BuildTLSConfig_MTLSInstallsRevocationCheck proves the fix for
// the first security bug: an mTLS server (ClientCAs configured) must wire
// VerifyConnection so every connection is checked against the enrollment
// store and the CA's revocation state, not just chain validity.
func TestServer_BuildTLSConfig_MTLSInstallsRevocationCheck(t *testing.T) {
	certFile, keyFile, caFile := writeTestServerTLSFiles(t)

	cfg := DefaultConfig()
	cfg.TLSCertFile = certFile
	cfg.TLSKeyFile = keyFile
	cfg.TLSCAFile = caFile

	enrollment, _ := testEnrollmentService(t)
	server, err := NewServer(cfg, enrollment, testLogger())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	tlsConfig, err := server.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if tlsConfig.VerifyConnection == nil {
		t.Fatal("mTLS config does not install a connection verifier")
	}
}

// TestServer_BuildTLSConfig_SessionTicketsDisabled proves the fix for
// go-xkms#1285: the server never issues session tickets, so a TLS
// connection can never resume and skip the full handshake - and the
// VerifyConnection check installed above - that a fresh connection runs.
func TestServer_BuildTLSConfig_SessionTicketsDisabled(t *testing.T) {
	certFile, keyFile, caFile := writeTestServerTLSFiles(t)

	cfg := DefaultConfig()
	cfg.TLSCertFile = certFile
	cfg.TLSKeyFile = keyFile
	cfg.TLSCAFile = caFile

	enrollment, _ := testEnrollmentService(t)
	server, err := NewServer(cfg, enrollment, testLogger())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	tlsConfig, err := server.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if !tlsConfig.SessionTicketsDisabled {
		t.Fatal("server TLS config must disable session tickets (go-xkms#1285)")
	}
}

// TestServer_VerifyConnection_EnrolledAgentAccepted proves an agent
// whose certificate is enrolled and not revoked connects successfully.
func TestServer_VerifyConnection_EnrolledAgentAccepted(t *testing.T) {
	server, _ := testServerWithStore(t)

	csrPEM := testCSR(t)
	code, err := server.enrollment.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	certPEM, _, err := server.enrollment.EnrollWithCode(code.Code, csrPEM)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	leaf := parseTestCertPEM(t, certPEM)
	cs := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	if err := server.verifyConnection(cs); err != nil {
		t.Errorf("expected an enrolled agent's certificate to be accepted, got %v", err)
	}
}

// TestServer_VerifyConnection_RevokedCertificateRejected proves the
// fix for the first security bug: a certificate the CA reports as revoked
// is refused even though it still chains to the trusted CA.
func TestServer_VerifyConnection_RevokedCertificateRejected(t *testing.T) {
	server, _ := testServerWithStore(t)
	ca := server.enrollment.ca.(*mockCAService)

	csrPEM := testCSR(t)
	code, err := server.enrollment.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	certPEM, _, err := server.enrollment.EnrollWithCode(code.Code, csrPEM)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	ca.isRevokedFunc = func(string) (bool, error) { return true, nil }

	leaf := parseTestCertPEM(t, certPEM)
	cs := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	err = server.verifyConnection(cs)
	if !errors.Is(err, ErrCertificateRevoked) {
		t.Errorf("expected ErrCertificateRevoked, got %v", err)
	}
}

// TestServer_VerifyConnection_UnenrolledCertificateRejected proves the
// fix for the second security bug's connection-time half: a certificate
// with no matching record in the enrollment store - whether it was never
// enrolled or was removed - is refused regardless of revocation status.
func TestServer_VerifyConnection_UnenrolledCertificateRejected(t *testing.T) {
	server, _ := testServerWithStore(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "never-enrolled"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	cs := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	err = server.verifyConnection(cs)
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("expected ErrAgentNotFound, got %v", err)
	}
}

// TestServer_VerifyConnection_EmptyChain proves the handshake is
// refused, rather than panicking, when no verified chain is available.
func TestServer_VerifyConnection_EmptyChain(t *testing.T) {
	server, _ := testServerWithStore(t)

	if err := server.verifyConnection(tls.ConnectionState{}); !errors.Is(err, ErrCertificateInvalid) {
		t.Errorf("expected ErrCertificateInvalid, got %v", err)
	}
	cs := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}
	if err := server.verifyConnection(cs); !errors.Is(err, ErrCertificateInvalid) {
		t.Errorf("expected ErrCertificateInvalid, got %v", err)
	}
}

// testServerWithStore is like testServer but exposes the MemoryStore
// backing the server's enrollment service.
func testServerWithStore(t *testing.T) (*Server, *MemoryStore) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ListenAddress = "localhost:0"
	enrollment, store := testEnrollmentServiceWithStore(t)

	server, err := NewServer(cfg, enrollment, testLogger())
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	return server, store
}

// writeTestServerTLSFiles writes a self-signed server certificate/key pair
// and a CA certificate to temporary files, returning their paths.
func writeTestServerTLSFiles(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test agent server CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test agent server"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}

	dir := t.TempDir()
	certFile = writeTestPEMFile(t, dir, "server-cert.pem", "CERTIFICATE", serverDER)
	keyFile = writeTestKeyFile(t, dir, "server-key.pem", serverKey)
	caFile = writeTestPEMFile(t, dir, "ca-cert.pem", "CERTIFICATE", caDER)
	return certFile, keyFile, caFile
}

// writeTestPEMFile PEM-encodes der under the given block type and writes it
// to name inside dir, returning the file's path.
func writeTestPEMFile(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// writeTestKeyFile PKCS#8-encodes an EC private key and writes it as PEM
// to name inside dir, returning the file's path.
func writeTestKeyFile(t *testing.T, dir, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return writeTestPEMFile(t, dir, name, "PRIVATE KEY", der)
}
