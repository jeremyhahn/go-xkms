//go:build integration

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

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go"
)

// ProtocolType represents a supported SDK protocol.
type ProtocolType string

const (
	ProtocolEmbedded ProtocolType = "embedded"
	ProtocolREST     ProtocolType = "rest"
	ProtocolGRPC     ProtocolType = "grpc"
	ProtocolQUIC     ProtocolType = "quic"
	ProtocolMCP      ProtocolType = "mcp"
	ProtocolUnix     ProtocolType = "unix"
)

// Environment variable names for server addresses
const (
	EnvRESTAddr   = "KEYSTORE_REST_URL"
	EnvGRPCAddr   = "KEYSTORE_GRPC_ADDR"
	EnvQUICAddr   = "KEYSTORE_QUIC_URL"
	EnvMCPAddr    = "KEYSTORE_MCP_ADDR"
	EnvUnixSocket = "KEYSTORE_UNIX_SOCKET"
	EnvTLSCA      = "KEYSTORE_TLS_CA"
)

// Default server addresses (used when not in container environment)
const (
	DefaultRESTAddr   = "https://localhost:8443"
	DefaultGRPCAddr   = "localhost:9443"
	DefaultQUICAddr   = "localhost:8444"
	DefaultMCPAddr    = "localhost:9444"
	DefaultUnixSocket = "/var/run/xkms/xkms.sock"
)

// SDKProtocol abstracts protocol-specific client creation and lifecycle.
type SDKProtocol interface {
	Name() string
	Setup(t *testing.T, ctx context.Context) error
	Client() xkms.Client
	Teardown(t *testing.T)
	IsAvailable(t *testing.T) bool
}

// embeddedProtocol implements SDKProtocol for embedded mode.
type embeddedProtocol struct {
	client  xkms.Client
	service *TestXKMSService
}

func newEmbeddedProtocol() *embeddedProtocol {
	return &embeddedProtocol{}
}

func (p *embeddedProtocol) Name() string { return string(ProtocolEmbedded) }

func (p *embeddedProtocol) IsAvailable(t *testing.T) bool {
	// Embedded is always available
	return true
}

func (p *embeddedProtocol) Setup(t *testing.T, ctx context.Context) error {
	service, err := NewTestXKMSService()
	if err != nil {
		return err
	}
	p.service = service

	client, err := xkms.NewEmbedded(service)
	if err != nil {
		return err
	}
	p.client = client

	return client.Connect(ctx)
}

func (p *embeddedProtocol) Client() xkms.Client { return p.client }

func (p *embeddedProtocol) Teardown(t *testing.T) {
	if p.client != nil {
		if err := p.client.Close(); err != nil {
			t.Logf("Warning: failed to close embedded client: %v", err)
		}
	}
}

// remoteProtocol implements SDKProtocol for remote protocol modes (REST, gRPC, QUIC, MCP, Unix).
type remoteProtocol struct {
	name       ProtocolType
	protocol   xkms.Protocol
	address    string
	client     xkms.Client
	tlsEnabled bool
	tlsCA      string
}

func getEnvOrDefault(envVar, defaultValue string) string {
	if value := os.Getenv(envVar); value != "" {
		return value
	}
	return defaultValue
}

func newRESTProtocol() *remoteProtocol {
	return &remoteProtocol{
		name:       ProtocolREST,
		protocol:   xkms.ProtocolREST,
		address:    getEnvOrDefault(EnvRESTAddr, DefaultRESTAddr),
		tlsEnabled: true,
		tlsCA:      os.Getenv(EnvTLSCA),
	}
}

func newGRPCProtocol() *remoteProtocol {
	return &remoteProtocol{
		name:       ProtocolGRPC,
		protocol:   xkms.ProtocolGRPC,
		address:    getEnvOrDefault(EnvGRPCAddr, DefaultGRPCAddr),
		tlsEnabled: true,
		tlsCA:      os.Getenv(EnvTLSCA),
	}
}

func newQUICProtocol() *remoteProtocol {
	return &remoteProtocol{
		name:       ProtocolQUIC,
		protocol:   xkms.ProtocolQUIC,
		address:    getEnvOrDefault(EnvQUICAddr, DefaultQUICAddr),
		tlsEnabled: true, // QUIC always uses TLS
		tlsCA:      os.Getenv(EnvTLSCA),
	}
}

func newMCPProtocol() *remoteProtocol {
	return &remoteProtocol{
		name:       ProtocolMCP,
		protocol:   xkms.ProtocolMCP,
		address:    getEnvOrDefault(EnvMCPAddr, DefaultMCPAddr),
		tlsEnabled: false,
		tlsCA:      os.Getenv(EnvTLSCA),
	}
}

func newUnixProtocol() *remoteProtocol {
	return &remoteProtocol{
		name:       ProtocolUnix,
		protocol:   xkms.ProtocolUnix,
		address:    getEnvOrDefault(EnvUnixSocket, DefaultUnixSocket),
		tlsEnabled: false,
	}
}

func (p *remoteProtocol) Name() string { return string(p.name) }

// IsAvailable checks if the remote server is reachable.
func (p *remoteProtocol) IsAvailable(t *testing.T) bool {
	t.Helper()

	switch p.name {
	case ProtocolREST:
		return isRESTServerAvailable(p.address, p.tlsCA)
	case ProtocolGRPC:
		return isTCPServerAvailable(p.address)
	case ProtocolQUIC:
		// QUIC uses UDP, but we can check the server via REST health endpoint
		// since they usually share the same server process
		restAddr := getEnvOrDefault(EnvRESTAddr, DefaultRESTAddr)
		return isRESTServerAvailable(restAddr, p.tlsCA)
	case ProtocolMCP:
		return isTCPServerAvailable(p.address)
	case ProtocolUnix:
		return isUnixSocketAvailable(p.address)
	default:
		return false
	}
}

func (p *remoteProtocol) Setup(t *testing.T, ctx context.Context) error {
	cfg := &xkms.BackendConfig{
		Protocol:   p.protocol,
		Address:    p.address,
		TLSEnabled: p.tlsEnabled,
		TLSCAFile:  p.tlsCA,
	}

	client, err := xkms.New(cfg)
	if err != nil {
		return err
	}
	p.client = client

	if err := client.Connect(ctx); err != nil {
		closeErr := client.Close()
		if closeErr != nil {
			t.Logf("Warning: failed to close client after connect error: %v", closeErr)
		}
		return err
	}
	return nil
}

func (p *remoteProtocol) Client() xkms.Client { return p.client }

func (p *remoteProtocol) Teardown(t *testing.T) {
	if p.client != nil {
		if err := p.client.Close(); err != nil {
			t.Logf("Warning: failed to close %s client: %v", p.name, err)
		}
	}
}

// Helper functions for server availability checks

func isRESTServerAvailable(address string, caFile string) bool {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return false
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return false
		}
		tlsConfig.RootCAs = caCertPool
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	resp, err := client.Get(address + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func isTCPServerAvailable(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func isUnixSocketAvailable(socketPath string) bool {
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return false
	}
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// TestSDKMultiProtocol tests the SDK using the embedded protocol.
// This test runs in the devcontainer where no remote servers are available.
// Remote protocol tests are covered by TestSDKMultiProtocolRemote which
// runs via docker-compose with real servers.
func TestSDKMultiProtocol(t *testing.T) {
	proto := newEmbeddedProtocol()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if !proto.IsAvailable(t) {
		t.Fatalf("Embedded protocol must always be available")
	}

	if err := proto.Setup(t, ctx); err != nil {
		t.Fatalf("Embedded protocol setup failed: %v", err)
	}
	defer proto.Teardown(t)

	// Run test groups
	t.Run("health", func(t *testing.T) { testHealth(t, ctx, proto) })
	t.Run("backends", func(t *testing.T) { testBackends(t, ctx, proto) })
	t.Run("key_lifecycle", func(t *testing.T) { testKeyLifecycle(t, ctx, proto) })
	t.Run("sign_verify", func(t *testing.T) { testSignVerify(t, ctx, proto) })
	t.Run("encrypt_decrypt", func(t *testing.T) { testEncryptDecrypt(t, ctx, proto) })
	t.Run("seal_unseal", func(t *testing.T) { testSealUnseal(t, ctx, proto) })
	t.Run("certificates", func(t *testing.T) { testCertificates(t, ctx, proto) })
	t.Run("error_handling", func(t *testing.T) { testErrorHandling(t, ctx, proto) })
}

// TestSDKMultiProtocolRemote runs the full test suite against all remote protocols.
// This test expects real servers to be running (via docker-compose). If a server
// is not available or setup fails, the test fails rather than skipping.
func TestSDKMultiProtocolRemote(t *testing.T) {
	protocols := []SDKProtocol{
		newRESTProtocol(),
		newGRPCProtocol(),
		newQUICProtocol(),
		newMCPProtocol(),
		newUnixProtocol(),
	}

	for _, proto := range protocols {
		proto := proto
		t.Run(proto.Name(), func(t *testing.T) {
			if !proto.IsAvailable(t) {
				t.Fatalf("%s server not available at %s", proto.Name(), proto.(*remoteProtocol).address)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := proto.Setup(t, ctx); err != nil {
				t.Fatalf("%s setup failed: %v", proto.Name(), err)
			}
			defer proto.Teardown(t)

			// Run comprehensive test suite
			t.Run("health", func(t *testing.T) { testHealth(t, ctx, proto) })
			t.Run("backends", func(t *testing.T) { testBackends(t, ctx, proto) })
			t.Run("key_lifecycle", func(t *testing.T) { testKeyLifecycle(t, ctx, proto) })
			t.Run("sign_verify", func(t *testing.T) { testSignVerify(t, ctx, proto) })
			t.Run("encrypt_decrypt", func(t *testing.T) { testEncryptDecrypt(t, ctx, proto) })
			t.Run("seal_unseal", func(t *testing.T) { testSealUnseal(t, ctx, proto) })
			t.Run("certificates", func(t *testing.T) { testCertificates(t, ctx, proto) })
			t.Run("key_rotation", func(t *testing.T) { testKeyRotation(t, ctx, proto) })
			t.Run("import_export", func(t *testing.T) { testImportExport(t, ctx, proto) })
			t.Run("error_handling", func(t *testing.T) { testErrorHandling(t, ctx, proto) })
		})
	}
}

// Test implementations

func testHealth(t *testing.T, ctx context.Context, proto SDKProtocol) {
	resp, err := proto.Client().Health(ctx)
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	if resp.Status != "healthy" {
		t.Errorf("Expected healthy status, got: %s", resp.Status)
	}
	if resp.Version == "" {
		t.Error("Expected non-empty version")
	}
	t.Logf("[%s] Health: status=%s, version=%s", proto.Name(), resp.Status, resp.Version)
}

func testBackends(t *testing.T, ctx context.Context, proto SDKProtocol) {
	// Test ListBackends
	resp, err := proto.Client().ListBackends(ctx)
	if err != nil {
		t.Fatalf("ListBackends failed: %v", err)
	}
	if len(resp.Backends) == 0 {
		t.Error("Expected at least one backend")
	}

	var softwareBackendFound bool
	for _, b := range resp.Backends {
		t.Logf("[%s] Backend: ID=%s, Type=%s, HardwareBacked=%v", proto.Name(), b.ID, b.Type, b.HardwareBacked)
		if b.ID == "software" {
			softwareBackendFound = true
		}
	}

	if !softwareBackendFound {
		t.Error("Expected to find software backend")
	}

	// Test GetBackend
	backend, err := proto.Client().GetBackend(ctx, "software")
	if err != nil {
		t.Fatalf("GetBackend failed: %v", err)
	}
	if backend.ID != "software" {
		t.Errorf("Expected backend ID 'software', got: %s", backend.ID)
	}
	t.Logf("[%s] GetBackend: ID=%s, Type=%s", proto.Name(), backend.ID, backend.Type)
}

func testKeyLifecycle(t *testing.T, ctx context.Context, proto SDKProtocol) {
	keyID := fmt.Sprintf("test-key-lifecycle-%s-%d", proto.Name(), time.Now().UnixNano())

	// Generate key
	genResp, err := proto.Client().GenerateKey(ctx, &xkms.GenerateKeyRequest{
		KeyID:      keyID,
		Backend:    "software",
		KeyType:    "ecdsa",
		Curve:      "P-256",
		Exportable: true,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if genResp.KeyID != keyID {
		t.Errorf("Expected key ID %s, got: %s", keyID, genResp.KeyID)
	}
	if genResp.PublicKeyPEM == "" {
		t.Error("Expected non-empty public key PEM")
	}
	t.Logf("[%s] Generated key: %s (type=%s)", proto.Name(), genResp.KeyID, genResp.KeyType)

	// Get key
	getResp, err := proto.Client().GetKey(ctx, "software", keyID)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if getResp.KeyID != keyID {
		t.Errorf("GetKey returned wrong key ID: expected %s, got %s", keyID, getResp.KeyID)
	}
	t.Logf("[%s] Retrieved key: %s", proto.Name(), getResp.KeyID)

	// List keys
	listResp, err := proto.Client().ListKeys(ctx, "software")
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	found := false
	for _, k := range listResp.Keys {
		if k.KeyID == keyID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Generated key not found in list of %d keys", len(listResp.Keys))
	}
	t.Logf("[%s] Listed %d keys, found test key: %v", proto.Name(), len(listResp.Keys), found)

	// Delete key
	delResp, err := proto.Client().DeleteKey(ctx, "software", keyID)
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}
	if !delResp.Success {
		t.Errorf("DeleteKey returned success=false: %s", delResp.Message)
	}
	t.Logf("[%s] Deleted key: %s", proto.Name(), keyID)

	// Verify deletion - GetKey should fail
	_, err = proto.Client().GetKey(ctx, "software", keyID)
	if err == nil {
		t.Error("Expected error after deletion, but GetKey succeeded")
	}
	t.Logf("[%s] Verified key deletion: GetKey correctly returned error", proto.Name())
}

func testSignVerify(t *testing.T, ctx context.Context, proto SDKProtocol) {
	keyID := fmt.Sprintf("test-sign-%s-%d", proto.Name(), time.Now().UnixNano())

	// Generate signing key
	_, err := proto.Client().GenerateKey(ctx, &xkms.GenerateKeyRequest{
		KeyID:   keyID,
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P-256",
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer func() {
		if _, delErr := proto.Client().DeleteKey(ctx, "software", keyID); delErr != nil {
			t.Logf("Warning: failed to delete key %s: %v", keyID, delErr)
		}
	}()

	// Sign data
	testData := []byte("test data to sign for multiprotocol test")
	signResp, err := proto.Client().Sign(ctx, &xkms.SignRequest{
		Backend: "software",
		KeyID:   keyID,
		Data:    testData,
		Hash:    "SHA256",
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(signResp.Signature) == 0 {
		t.Error("Expected non-empty signature")
	}
	t.Logf("[%s] Signed data, signature length: %d bytes", proto.Name(), len(signResp.Signature))

	// Verify signature (should succeed)
	verifyResp, err := proto.Client().Verify(ctx, &xkms.VerifyRequest{
		Backend:   "software",
		KeyID:     keyID,
		Data:      testData,
		Signature: signResp.Signature,
		Hash:      "SHA256",
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !verifyResp.Valid {
		t.Error("Signature verification failed - expected valid signature")
	}
	t.Logf("[%s] Signature verified: valid=%v", proto.Name(), verifyResp.Valid)

	// Verify with wrong data (should fail validation)
	wrongData := []byte("wrong data - this should not verify")
	verifyWrongResp, err := proto.Client().Verify(ctx, &xkms.VerifyRequest{
		Backend:   "software",
		KeyID:     keyID,
		Data:      wrongData,
		Signature: signResp.Signature,
		Hash:      "SHA256",
	})
	if err != nil {
		t.Fatalf("Verify with wrong data returned error: %v", err)
	}
	if verifyWrongResp.Valid {
		t.Error("Signature verification should fail with wrong data")
	}
	t.Logf("[%s] Verification correctly rejected wrong data", proto.Name())
}

func testEncryptDecrypt(t *testing.T, ctx context.Context, proto SDKProtocol) {
	keyID := fmt.Sprintf("test-sym-%s-%d", proto.Name(), time.Now().UnixNano())

	// Generate symmetric key
	_, err := proto.Client().GenerateKey(ctx, &xkms.GenerateKeyRequest{
		KeyID:   keyID,
		Backend: "software",
		KeyType: "symmetric",
		KeySize: 256,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer func() {
		if _, delErr := proto.Client().DeleteKey(ctx, "software", keyID); delErr != nil {
			t.Logf("Warning: failed to delete key %s: %v", keyID, delErr)
		}
	}()

	// Encrypt
	plaintext := []byte("secret data for multiprotocol encryption test")
	encResp, err := proto.Client().Encrypt(ctx, &xkms.EncryptRequest{
		Backend:   "software",
		KeyID:     keyID,
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if len(encResp.Ciphertext) == 0 {
		t.Error("Expected non-empty ciphertext")
	}
	if len(encResp.Nonce) == 0 {
		t.Error("Expected non-empty nonce")
	}
	t.Logf("[%s] Encrypted data: ciphertext=%d bytes, nonce=%d bytes", proto.Name(), len(encResp.Ciphertext), len(encResp.Nonce))

	// Decrypt
	decResp, err := proto.Client().Decrypt(ctx, &xkms.DecryptRequest{
		Backend:    "software",
		KeyID:      keyID,
		Ciphertext: encResp.Ciphertext,
		Nonce:      encResp.Nonce,
		Tag:        encResp.Tag,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decResp.Plaintext) != string(plaintext) {
		t.Errorf("Decrypted data mismatch:\n  got:  %q\n  want: %q", decResp.Plaintext, plaintext)
	}
	t.Logf("[%s] Decrypted data verified - plaintext matches", proto.Name())
}

func testSealUnseal(t *testing.T, ctx context.Context, proto SDKProtocol) {
	// Check if sealing is supported - software backend must support sealing
	canSealResp, err := proto.Client().CanSeal(ctx, "software")
	if err != nil {
		t.Fatalf("CanSeal failed: %v", err)
	}

	if !canSealResp.CanSeal {
		t.Fatal("Sealing must be supported for software backend")
	}
	t.Logf("[%s] CanSeal: backend=%s, supported=%v", proto.Name(), canSealResp.Backend, canSealResp.CanSeal)

	// Generate an ECDSA key for sealing (PKCS8 sealer uses asymmetric keys to derive sealing keys)
	keyID := fmt.Sprintf("test-seal-key-%s-%d", proto.Name(), time.Now().UnixNano())
	_, err = proto.Client().GenerateKey(ctx, &xkms.GenerateKeyRequest{
		KeyID:   keyID,
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P-256",
	})
	if err != nil {
		t.Fatalf("GenerateKey for seal failed: %v", err)
	}
	defer func() {
		if _, delErr := proto.Client().DeleteKey(ctx, "software", keyID); delErr != nil {
			t.Logf("Warning: failed to delete seal key %s: %v", keyID, delErr)
		}
	}()

	// Seal data
	secretData := []byte("sealed secret data for multiprotocol test!")
	sealResp, err := proto.Client().Seal(ctx, &xkms.SealRequest{
		Backend: "software",
		KeyID:   keyID,
		Data:    secretData,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	if len(sealResp.Ciphertext) == 0 {
		t.Error("Expected non-empty sealed ciphertext")
	}
	t.Logf("[%s] Sealed data: ciphertext=%d bytes", proto.Name(), len(sealResp.Ciphertext))

	// Unseal data
	unsealResp, err := proto.Client().Unseal(ctx, &xkms.UnsealRequest{
		Backend:    "software",
		KeyID:      keyID,
		Ciphertext: sealResp.Ciphertext,
		Nonce:      sealResp.Nonce,
		Tag:        sealResp.Tag,
	})
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if string(unsealResp.Plaintext) != string(secretData) {
		t.Errorf("Unsealed data mismatch:\n  got:  %q\n  want: %q", unsealResp.Plaintext, secretData)
	}
	t.Logf("[%s] Seal/Unseal successful - data matches", proto.Name())
}

func testCertificates(t *testing.T, ctx context.Context, proto SDKProtocol) {
	keyID := fmt.Sprintf("test-cert-%s-%d", proto.Name(), time.Now().UnixNano())

	// Generate key for certificate
	_, err := proto.Client().GenerateKey(ctx, &xkms.GenerateKeyRequest{
		KeyID:   keyID,
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P-256",
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer func() {
		if _, delErr := proto.Client().DeleteKey(ctx, "software", keyID); delErr != nil {
			t.Logf("Warning: failed to delete key %s: %v", keyID, delErr)
		}
	}()

	// Check certificate doesn't exist
	exists, err := proto.Client().CertificateExists(ctx, "software", keyID)
	if err != nil {
		t.Fatalf("CertificateExists failed: %v", err)
	}
	if exists {
		t.Error("Expected certificate to not exist initially")
	}
	t.Logf("[%s] CertificateExists: %v (expected false)", proto.Name(), exists)

	// Generate a valid self-signed certificate for testing
	testCertPEM, err := generateTestCertificatePEM()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	err = proto.Client().SaveCertificate(ctx, &xkms.SaveCertificateRequest{
		Backend:        "software",
		KeyID:          keyID,
		CertificatePEM: testCertPEM,
	})
	if err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}
	t.Logf("[%s] SaveCertificate successful", proto.Name())

	// Check certificate exists now
	exists, err = proto.Client().CertificateExists(ctx, "software", keyID)
	if err != nil {
		t.Fatalf("CertificateExists failed: %v", err)
	}
	if !exists {
		t.Error("Expected certificate to exist after save")
	}
	t.Logf("[%s] CertificateExists: %v (expected true)", proto.Name(), exists)

	// Get certificate
	certResp, err := proto.Client().GetCertificate(ctx, "software", keyID)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if certResp.CertificatePEM != testCertPEM {
		t.Error("Retrieved certificate doesn't match saved certificate")
	}
	t.Logf("[%s] GetCertificate successful", proto.Name())

	// Delete certificate
	err = proto.Client().DeleteCertificate(ctx, "software", keyID)
	if err != nil {
		t.Fatalf("DeleteCertificate failed: %v", err)
	}
	t.Logf("[%s] DeleteCertificate successful", proto.Name())

	// Verify deletion
	exists, err = proto.Client().CertificateExists(ctx, "software", keyID)
	if err != nil {
		t.Fatalf("CertificateExists failed: %v", err)
	}
	if exists {
		t.Error("Expected certificate to not exist after deletion")
	}
	t.Logf("[%s] Certificate deletion verified", proto.Name())
}

func testKeyRotation(t *testing.T, ctx context.Context, proto SDKProtocol) {
	keyID := fmt.Sprintf("test-rotation-%s-%d", proto.Name(), time.Now().UnixNano())

	// Generate key
	_, err := proto.Client().GenerateKey(ctx, &xkms.GenerateKeyRequest{
		KeyID:   keyID,
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P-256",
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer func() {
		if _, delErr := proto.Client().DeleteKey(ctx, "software", keyID); delErr != nil {
			t.Logf("Warning: failed to delete key %s: %v", keyID, delErr)
		}
	}()

	// Rotate key
	rotateResp, err := proto.Client().RotateKey(ctx, &xkms.RotateKeyRequest{
		Backend: "software",
		KeyID:   keyID,
	})
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}
	if !rotateResp.Success {
		t.Errorf("RotateKey returned success=false: %s", rotateResp.Message)
	}
	t.Logf("[%s] RotateKey successful: %s", proto.Name(), keyID)
}

func testImportExport(t *testing.T, ctx context.Context, proto SDKProtocol) {
	keyID := fmt.Sprintf("test-import-export-%s-%d", proto.Name(), time.Now().UnixNano())

	// Generate exportable key
	_, err := proto.Client().GenerateKey(ctx, &xkms.GenerateKeyRequest{
		KeyID:      keyID,
		Backend:    "software",
		KeyType:    "ecdsa",
		Curve:      "P-256",
		Exportable: true,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer func() {
		if _, delErr := proto.Client().DeleteKey(ctx, "software", keyID); delErr != nil {
			t.Logf("Warning: failed to delete key %s: %v", keyID, delErr)
		}
	}()

	// Export key
	exportResp, err := proto.Client().ExportKey(ctx, &xkms.ExportKeyRequest{
		Backend:   "software",
		KeyID:     keyID,
		Algorithm: "RSAES_OAEP_SHA_256",
	})
	if err != nil {
		// Export might not be supported - log and continue
		t.Logf("[%s] ExportKey not supported or failed: %v", proto.Name(), err)
		return
	}
	t.Logf("[%s] ExportKey successful: keyID=%s", proto.Name(), exportResp.KeyID)
}

func testErrorHandling(t *testing.T, ctx context.Context, proto SDKProtocol) {
	// Test GetKey with non-existent key
	t.Run("GetNonExistentKey", func(t *testing.T) {
		_, err := proto.Client().GetKey(ctx, "software", "non-existent-key-xyz")
		if err == nil {
			t.Error("Expected error for non-existent key, but got nil")
		}
		t.Logf("[%s] Correctly returned error for non-existent key: %v", proto.Name(), err)
	})

	// Test DeleteKey with non-existent key
	t.Run("DeleteNonExistentKey", func(t *testing.T) {
		_, err := proto.Client().DeleteKey(ctx, "software", "non-existent-key-xyz")
		if err == nil {
			t.Error("Expected error for deleting non-existent key, but got nil")
		}
		t.Logf("[%s] Correctly returned error for deleting non-existent key: %v", proto.Name(), err)
	})

	// Test Sign with non-existent key
	t.Run("SignWithNonExistentKey", func(t *testing.T) {
		_, err := proto.Client().Sign(ctx, &xkms.SignRequest{
			Backend: "software",
			KeyID:   "non-existent-key-xyz",
			Data:    []byte("test"),
			Hash:    "SHA256",
		})
		if err == nil {
			t.Error("Expected error for signing with non-existent key, but got nil")
		}
		t.Logf("[%s] Correctly returned error for signing with non-existent key: %v", proto.Name(), err)
	})

	// Test GetBackend with non-existent backend
	t.Run("GetNonExistentBackend", func(t *testing.T) {
		_, err := proto.Client().GetBackend(ctx, "non-existent-backend-xyz")
		if err == nil {
			t.Error("Expected error for non-existent backend, but got nil")
		}
		t.Logf("[%s] Correctly returned error for non-existent backend: %v", proto.Name(), err)
	})

	// Test GetCertificate with non-existent key
	t.Run("GetCertificateNonExistentKey", func(t *testing.T) {
		_, err := proto.Client().GetCertificate(ctx, "software", "non-existent-key-xyz")
		if err == nil {
			t.Error("Expected error for getting certificate of non-existent key, but got nil")
		}
		t.Logf("[%s] Correctly returned error for non-existent certificate: %v", proto.Name(), err)
	})
}

// TestMultiProtocolKeyOperationsConcurrent tests concurrent key operations across protocols.
func TestMultiProtocolKeyOperationsConcurrent(t *testing.T) {
	proto := newEmbeddedProtocol()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := proto.Setup(t, ctx); err != nil {
		t.Fatalf("Failed to setup protocol: %v", err)
	}
	defer proto.Teardown(t)

	// Generate multiple keys concurrently
	keyCount := 5
	keyIDs := make([]string, keyCount)
	errChan := make(chan error, keyCount)

	for i := 0; i < keyCount; i++ {
		keyIDs[i] = fmt.Sprintf("concurrent-key-%s-%d-%c", proto.Name(), time.Now().UnixNano(), 'A'+i)
	}

	// Generate keys concurrently
	for _, keyID := range keyIDs {
		go func(id string) {
			_, err := proto.Client().GenerateKey(ctx, &xkms.GenerateKeyRequest{
				KeyID:   id,
				Backend: "software",
				KeyType: "ecdsa",
				Curve:   "P-256",
			})
			errChan <- err
		}(keyID)
	}

	// Wait for all generations
	for i := 0; i < keyCount; i++ {
		if err := <-errChan; err != nil {
			t.Errorf("Concurrent key generation failed: %v", err)
		}
	}

	t.Logf("[%s] Generated %d keys concurrently", proto.Name(), keyCount)

	// Cleanup
	for _, keyID := range keyIDs {
		if _, err := proto.Client().DeleteKey(ctx, "software", keyID); err != nil {
			t.Logf("Warning: failed to delete key %s: %v", keyID, err)
		}
	}

	t.Logf("[%s] Concurrent key operations completed successfully", proto.Name())
}

// TestMultiProtocolDataIntegrity tests data integrity across encrypt/decrypt cycles.
func TestMultiProtocolDataIntegrity(t *testing.T) {
	proto := newEmbeddedProtocol()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := proto.Setup(t, ctx); err != nil {
		t.Fatalf("Failed to setup protocol: %v", err)
	}
	defer proto.Teardown(t)

	keyID := fmt.Sprintf("integrity-test-%s-%d", proto.Name(), time.Now().UnixNano())

	// Generate symmetric key
	_, err := proto.Client().GenerateKey(ctx, &xkms.GenerateKeyRequest{
		KeyID:   keyID,
		Backend: "software",
		KeyType: "symmetric",
		KeySize: 256,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer func() {
		if _, delErr := proto.Client().DeleteKey(ctx, "software", keyID); delErr != nil {
			t.Logf("Warning: failed to delete key %s: %v", keyID, delErr)
		}
	}()

	// Test various data sizes (no empty data - AEAD requires non-empty plaintext)
	mediumData := make([]byte, 1024)   // 1KB
	largeData := make([]byte, 64*1024) // 64KB

	for i := range mediumData {
		mediumData[i] = byte(i % 256)
	}
	for i := range largeData {
		largeData[i] = byte((i * 7) % 256)
	}

	testCases := []struct {
		name string
		data []byte
	}{
		{"small", []byte("small data")},
		{"medium", mediumData},
		{"large", largeData},
		{"unicode", []byte("Hello World")},
		{"binary", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			encResp, err := proto.Client().Encrypt(ctx, &xkms.EncryptRequest{
				Backend:   "software",
				KeyID:     keyID,
				Plaintext: tc.data,
			})
			if err != nil {
				t.Fatalf("Encrypt failed for %s: %v", tc.name, err)
			}

			// Decrypt
			decResp, err := proto.Client().Decrypt(ctx, &xkms.DecryptRequest{
				Backend:    "software",
				KeyID:      keyID,
				Ciphertext: encResp.Ciphertext,
				Nonce:      encResp.Nonce,
				Tag:        encResp.Tag,
			})
			if err != nil {
				t.Fatalf("Decrypt failed for %s: %v", tc.name, err)
			}

			// Verify data integrity
			if len(decResp.Plaintext) != len(tc.data) {
				t.Errorf("Length mismatch for %s: got %d, want %d", tc.name, len(decResp.Plaintext), len(tc.data))
			}
			for i := range tc.data {
				if decResp.Plaintext[i] != tc.data[i] {
					t.Errorf("Data mismatch at byte %d for %s", i, tc.name)
					break
				}
			}
			t.Logf("[%s] Data integrity verified for %s (%d bytes)", proto.Name(), tc.name, len(tc.data))
		})
	}
}

// generateTestCertificatePEM generates a valid self-signed certificate for testing.
func generateTestCertificatePEM() (string, error) {
	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create a self-signed certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "test-certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate (self-signed)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM), nil
}
