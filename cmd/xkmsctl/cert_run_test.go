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

// cert_run_test.go exercises the "xkmsctl cert" command tree's Run closures
// (save, get, delete, list, exists, save-chain, get-chain, generate-ca,
// issue), which are anonymous cobra closures invisible to per-function
// coverage tooling. generate-ca and issue never touch the network — they
// are pure local X.509 operations — so they are tested directly with no
// mock client required.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockCertRunClient implements client.Client for the cert.go command tree.
type mockCertRunClient struct {
	mockBackendsClient

	connectErr error

	getCertResp *client.GetCertificateResponse
	getCertErr  error

	saveCertErr error

	deleteCertErr error

	certExistsVal bool
	certExistsErr error

	listCertsResp *client.ListCertificatesResponse
	listCertsErr  error

	saveChainErr error

	getChainResp *client.GetCertificateChainResponse
	getChainErr  error
}

func (m *mockCertRunClient) Connect(context.Context) error { return m.connectErr }

func (m *mockCertRunClient) GetCertificate(context.Context, string, string) (*client.GetCertificateResponse, error) {
	return m.getCertResp, m.getCertErr
}

func (m *mockCertRunClient) SaveCertificate(context.Context, *client.SaveCertificateRequest) error {
	return m.saveCertErr
}

func (m *mockCertRunClient) DeleteCertificate(context.Context, string, string) error {
	return m.deleteCertErr
}

func (m *mockCertRunClient) CertificateExists(context.Context, string, string) (bool, error) {
	return m.certExistsVal, m.certExistsErr
}

func (m *mockCertRunClient) ListCertificates(context.Context, string, ...transport.ListOption) (*client.ListCertificatesResponse, error) {
	return m.listCertsResp, m.listCertsErr
}

func (m *mockCertRunClient) SaveCertificateChain(context.Context, *client.SaveCertificateChainRequest) error {
	return m.saveChainErr
}

func (m *mockCertRunClient) GetCertificateChain(context.Context, string, string) (*client.GetCertificateChainResponse, error) {
	return m.getChainResp, m.getChainErr
}

func newCertRunConfig(format string, mock *mockCertRunClient) *Config {
	return &Config{
		OutputFormat: format,
		Backend:      "software",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func writeCertFile(t *testing.T, cn string) string {
	t.Helper()
	pemBytes := makeSelfSignedCert(t, cn)
	p := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(p, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------------------------------------------------------------------------
// certSaveCmd
// ---------------------------------------------------------------------------

func TestCertSaveCmd_ReadFileError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		certSaveCmd.Run(certSaveCmd, []string{"key-1", "/nonexistent/cert.pem"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertSaveCmd_BadPEM(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	p := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(p, []byte("not-pem"), 0600); err != nil {
		t.Fatal(err)
	}
	code := captureExit(t, func() {
		certSaveCmd.Run(certSaveCmd, []string{"key-1", p})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertSaveCmd_Success(t *testing.T) {
	mock := &mockCertRunClient{}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	p := writeCertFile(t, "save-me")

	out := captureStdout(t, func() {
		certSaveCmd.Run(certSaveCmd, []string{"key-1", p})
	})
	if !strings.Contains(out, "Successfully saved certificate") {
		t.Errorf("expected success message, got: %q", out)
	}
}

func TestCertSaveCmd_ClientError(t *testing.T) {
	mock := &mockCertRunClient{saveCertErr: errors.New("boom")}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	p := writeCertFile(t, "save-me")
	code := captureExit(t, func() {
		certSaveCmd.Run(certSaveCmd, []string{"key-1", p})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// certGetCmd
// ---------------------------------------------------------------------------

func TestCertGetCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		certGetCmd.Run(certGetCmd, []string{"key-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertGetCmd_GetError(t *testing.T) {
	mock := &mockCertRunClient{getCertErr: errors.New("not found")}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	code := captureExit(t, func() {
		certGetCmd.Run(certGetCmd, []string{"key-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertGetCmd_BadPEM(t *testing.T) {
	mock := &mockCertRunClient{getCertResp: &client.GetCertificateResponse{KeyID: "key-1", CertificatePEM: "not-pem"}}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	code := captureExit(t, func() {
		certGetCmd.Run(certGetCmd, []string{"key-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertGetCmd_Success(t *testing.T) {
	certPEM := makeSelfSignedCert(t, "get-me")
	mock := &mockCertRunClient{getCertResp: &client.GetCertificateResponse{KeyID: "key-1", CertificatePEM: string(certPEM)}}
	withGlobalConfig(t, newCertRunConfig("json", mock))
	out := captureStdout(t, func() {
		certGetCmd.Run(certGetCmd, []string{"key-1"})
	})
	if !strings.Contains(out, "get-me") {
		t.Errorf("expected subject CN in output, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// certDeleteCmd
// ---------------------------------------------------------------------------

func TestCertDeleteCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		certDeleteCmd.Run(certDeleteCmd, []string{"key-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertDeleteCmd_DeleteError(t *testing.T) {
	mock := &mockCertRunClient{deleteCertErr: errors.New("boom")}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	code := captureExit(t, func() {
		certDeleteCmd.Run(certDeleteCmd, []string{"key-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertDeleteCmd_Success(t *testing.T) {
	mock := &mockCertRunClient{}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	out := captureStdout(t, func() {
		certDeleteCmd.Run(certDeleteCmd, []string{"key-1"})
	})
	if !strings.Contains(out, "Successfully deleted certificate") {
		t.Errorf("expected success message, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// certListCmd
// ---------------------------------------------------------------------------

func TestCertListCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		certListCmd.Run(certListCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertListCmd_ListError(t *testing.T) {
	mock := &mockCertRunClient{listCertsErr: errors.New("boom")}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	code := captureExit(t, func() {
		certListCmd.Run(certListCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertListCmd_Success(t *testing.T) {
	mock := &mockCertRunClient{listCertsResp: &client.ListCertificatesResponse{
		Certificates: []client.CertificateInfo{{KeyID: "key-1"}, {KeyID: "key-2"}},
	}}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	out := captureStdout(t, func() {
		certListCmd.Run(certListCmd, nil)
	})
	if !strings.Contains(out, "key-1") || !strings.Contains(out, "key-2") {
		t.Errorf("expected both key IDs in output, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// certExistsCmd
// ---------------------------------------------------------------------------

func TestCertExistsCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		certExistsCmd.Run(certExistsCmd, []string{"key-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertExistsCmd_Error(t *testing.T) {
	mock := &mockCertRunClient{certExistsErr: errors.New("boom")}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	code := captureExit(t, func() {
		certExistsCmd.Run(certExistsCmd, []string{"key-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertExistsCmd_True(t *testing.T) {
	mock := &mockCertRunClient{certExistsVal: true}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	out := captureStdout(t, func() {
		certExistsCmd.Run(certExistsCmd, []string{"key-1"})
	})
	if !strings.Contains(out, "key-1") {
		t.Errorf("expected key-1 in output, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// certSaveChainCmd
// ---------------------------------------------------------------------------

func TestCertSaveChainCmd_ReadFileError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		certSaveChainCmd.Run(certSaveChainCmd, []string{"key-1", "/nonexistent/cert.pem"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertSaveChainCmd_BadPEM(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	p := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(p, []byte("not-pem"), 0600); err != nil {
		t.Fatal(err)
	}
	code := captureExit(t, func() {
		certSaveChainCmd.Run(certSaveChainCmd, []string{"key-1", p})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertSaveChainCmd_Success(t *testing.T) {
	mock := &mockCertRunClient{}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	leaf := writeCertFile(t, "leaf")
	root := writeCertFile(t, "root")

	out := captureStdout(t, func() {
		certSaveChainCmd.Run(certSaveChainCmd, []string{"key-1", leaf, root})
	})
	if !strings.Contains(out, "2 certificates") {
		t.Errorf("expected chain count in output, got: %q", out)
	}
}

func TestCertSaveChainCmd_ClientError(t *testing.T) {
	mock := &mockCertRunClient{saveChainErr: errors.New("boom")}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	leaf := writeCertFile(t, "leaf")

	code := captureExit(t, func() {
		certSaveChainCmd.Run(certSaveChainCmd, []string{"key-1", leaf})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// certGetChainCmd
// ---------------------------------------------------------------------------

func TestCertGetChainCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		certGetChainCmd.Run(certGetChainCmd, []string{"key-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertGetChainCmd_GetError(t *testing.T) {
	mock := &mockCertRunClient{getChainErr: errors.New("boom")}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	code := captureExit(t, func() {
		certGetChainCmd.Run(certGetChainCmd, []string{"key-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertGetChainCmd_BadPEM(t *testing.T) {
	mock := &mockCertRunClient{getChainResp: &client.GetCertificateChainResponse{ChainPEM: []string{"not-pem"}}}
	withGlobalConfig(t, newCertRunConfig("text", mock))
	code := captureExit(t, func() {
		certGetChainCmd.Run(certGetChainCmd, []string{"key-1"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertGetChainCmd_Success(t *testing.T) {
	leafPEM := makeSelfSignedCert(t, "leaf")
	rootPEM := makeSelfSignedCert(t, "root")
	mock := &mockCertRunClient{getChainResp: &client.GetCertificateChainResponse{
		ChainPEM: []string{string(leafPEM), string(rootPEM)},
	}}
	withGlobalConfig(t, newCertRunConfig("json", mock))
	out := captureStdout(t, func() {
		certGetChainCmd.Run(certGetChainCmd, []string{"key-1"})
	})
	if !strings.Contains(out, "leaf") {
		t.Errorf("expected leaf in output, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// certGenerateCACmd (pure local X.509 - no client required)
// ---------------------------------------------------------------------------

// newCertGenerateCACmdCopy resets certGenerateCACmd's flags to a clean copy
// so each test is isolated.
func resetCertGenerateCAFlags(t *testing.T) {
	t.Helper()
	_ = certGenerateCACmd.Flags().Set("cn", "")
	_ = certGenerateCACmd.Flags().Set("org", "Go xKMS")
	_ = certGenerateCACmd.Flags().Set("ou", "")
	_ = certGenerateCACmd.Flags().Set("country", "")
	_ = certGenerateCACmd.Flags().Set("province", "")
	_ = certGenerateCACmd.Flags().Set("locality", "")
	_ = certGenerateCACmd.Flags().Set("validity", "3650")
	_ = certGenerateCACmd.Flags().Set("key-algorithm", "ecdsa")
	_ = certGenerateCACmd.Flags().Set("key-size", "256")
	_ = certGenerateCACmd.Flags().Set("output", "")
	_ = certGenerateCACmd.Flags().Set("key-output", "")
}

func TestCertGenerateCACmd_MissingCN(t *testing.T) {
	resetCertGenerateCAFlags(t)
	t.Cleanup(func() { resetCertGenerateCAFlags(t) })
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	code := captureExit(t, func() {
		certGenerateCACmd.Run(certGenerateCACmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for missing --cn, got %d", code)
	}
}

func TestCertGenerateCACmd_TextToStdout(t *testing.T) {
	resetCertGenerateCAFlags(t)
	t.Cleanup(func() { resetCertGenerateCAFlags(t) })
	_ = certGenerateCACmd.Flags().Set("cn", "Test Root CA")
	_ = certGenerateCACmd.Flags().Set("org", "Acme")
	_ = certGenerateCACmd.Flags().Set("ou", "Eng")
	_ = certGenerateCACmd.Flags().Set("country", "US")
	_ = certGenerateCACmd.Flags().Set("province", "CA")
	_ = certGenerateCACmd.Flags().Set("locality", "SF")
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	out := captureStdout(t, func() {
		certGenerateCACmd.Run(certGenerateCACmd, nil)
	})
	if !strings.Contains(out, "Test Root CA") {
		t.Errorf("expected CA subject in output, got: %q", out)
	}
	if !strings.Contains(out, "BEGIN CERTIFICATE") || !strings.Contains(out, "BEGIN PRIVATE KEY") {
		t.Errorf("expected inline PEM blocks in output, got: %q", out)
	}
}

func TestCertGenerateCACmd_JSONToFiles(t *testing.T) {
	resetCertGenerateCAFlags(t)
	t.Cleanup(func() { resetCertGenerateCAFlags(t) })
	dir := t.TempDir()
	certOut := filepath.Join(dir, "ca.crt")
	keyOut := filepath.Join(dir, "ca.key")
	_ = certGenerateCACmd.Flags().Set("cn", "File Root CA")
	_ = certGenerateCACmd.Flags().Set("output", certOut)
	_ = certGenerateCACmd.Flags().Set("key-output", keyOut)
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	out := captureStdout(t, func() {
		certGenerateCACmd.Run(certGenerateCACmd, nil)
	})
	if !strings.Contains(out, "\"success\"") {
		t.Errorf("expected success field in JSON output, got: %q", out)
	}
	if _, err := os.Stat(certOut); err != nil {
		t.Errorf("expected certificate file to be written: %v", err)
	}
	if _, err := os.Stat(keyOut); err != nil {
		t.Errorf("expected key file to be written: %v", err)
	}
}

func TestCertGenerateCACmd_RSAKeyAlgorithm(t *testing.T) {
	resetCertGenerateCAFlags(t)
	t.Cleanup(func() { resetCertGenerateCAFlags(t) })
	_ = certGenerateCACmd.Flags().Set("cn", "RSA Root CA")
	_ = certGenerateCACmd.Flags().Set("key-algorithm", "rsa")
	_ = certGenerateCACmd.Flags().Set("key-size", "2048")
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	out := captureStdout(t, func() {
		certGenerateCACmd.Run(certGenerateCACmd, nil)
	})
	if !strings.Contains(out, "RSA Root CA") {
		t.Errorf("expected CA subject in output, got: %q", out)
	}
}

func TestCertGenerateCACmd_Ed25519KeyAlgorithm(t *testing.T) {
	resetCertGenerateCAFlags(t)
	t.Cleanup(func() { resetCertGenerateCAFlags(t) })
	_ = certGenerateCACmd.Flags().Set("cn", "Ed25519 Root CA")
	_ = certGenerateCACmd.Flags().Set("key-algorithm", "ed25519")
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	out := captureStdout(t, func() {
		certGenerateCACmd.Run(certGenerateCACmd, nil)
	})
	if !strings.Contains(out, "Ed25519 Root CA") {
		t.Errorf("expected CA subject in output, got: %q", out)
	}
}

func TestCertGenerateCACmd_WriteCertFileError(t *testing.T) {
	resetCertGenerateCAFlags(t)
	t.Cleanup(func() { resetCertGenerateCAFlags(t) })
	_ = certGenerateCACmd.Flags().Set("cn", "Bad Output CA")
	_ = certGenerateCACmd.Flags().Set("output", "/nonexistent-dir/ca.crt")
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	code := captureExit(t, func() {
		certGenerateCACmd.Run(certGenerateCACmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for unwritable output path, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// certIssueCmd (pure local X.509 - no client required)
// ---------------------------------------------------------------------------

func resetCertIssueFlags(t *testing.T) {
	t.Helper()
	_ = certIssueCmd.Flags().Set("ca-cert", "")
	_ = certIssueCmd.Flags().Set("ca-key", "")
	_ = certIssueCmd.Flags().Set("cn", "")
	_ = certIssueCmd.Flags().Set("type", "server")
	_ = certIssueCmd.Flags().Set("org", "")
	_ = certIssueCmd.Flags().Set("ou", "")
	_ = certIssueCmd.Flags().Set("country", "")
	_ = certIssueCmd.Flags().Set("province", "")
	_ = certIssueCmd.Flags().Set("locality", "")
	_ = certIssueCmd.Flags().Set("validity", "365")
	_ = certIssueCmd.Flags().Set("key-algorithm", "ecdsa")
	_ = certIssueCmd.Flags().Set("key-size", "256")
	_ = certIssueCmd.Flags().Set("dns", "")
	_ = certIssueCmd.Flags().Set("ip", "")
	_ = certIssueCmd.Flags().Set("email", "")
	_ = certIssueCmd.Flags().Set("output", "")
	_ = certIssueCmd.Flags().Set("key-output", "")
}

// writeCAFiles generates a CA certificate/key pair on disk for --ca-cert /
// --ca-key inputs to certIssueCmd.
func writeCAFiles(t *testing.T) (certPath, keyPath string, ca *x509.Certificate, key interface{}) {
	t.Helper()
	caCert, caKey, err := generateCA("Issuer Test CA", "Acme", "", "", "", "", 3650, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "ca.crt")
	keyPath = filepath.Join(dir, "ca.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, caCert, caKey
}

func TestCertIssueCmd_MissingCACert(t *testing.T) {
	resetCertIssueFlags(t)
	t.Cleanup(func() { resetCertIssueFlags(t) })
	withGlobalConfig(t, &Config{OutputFormat: "text"})
	code := captureExit(t, func() {
		certIssueCmd.Run(certIssueCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertIssueCmd_MissingCAKey(t *testing.T) {
	resetCertIssueFlags(t)
	t.Cleanup(func() { resetCertIssueFlags(t) })
	certPath, _, _, _ := writeCAFiles(t)
	_ = certIssueCmd.Flags().Set("ca-cert", certPath)
	withGlobalConfig(t, &Config{OutputFormat: "text"})
	code := captureExit(t, func() {
		certIssueCmd.Run(certIssueCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertIssueCmd_MissingCN(t *testing.T) {
	resetCertIssueFlags(t)
	t.Cleanup(func() { resetCertIssueFlags(t) })
	certPath, keyPath, _, _ := writeCAFiles(t)
	_ = certIssueCmd.Flags().Set("ca-cert", certPath)
	_ = certIssueCmd.Flags().Set("ca-key", keyPath)
	withGlobalConfig(t, &Config{OutputFormat: "text"})
	code := captureExit(t, func() {
		certIssueCmd.Run(certIssueCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertIssueCmd_CACertFileMissing(t *testing.T) {
	resetCertIssueFlags(t)
	t.Cleanup(func() { resetCertIssueFlags(t) })
	_ = certIssueCmd.Flags().Set("ca-cert", "/nonexistent/ca.crt")
	_ = certIssueCmd.Flags().Set("ca-key", "/nonexistent/ca.key")
	_ = certIssueCmd.Flags().Set("cn", "server.example.com")
	withGlobalConfig(t, &Config{OutputFormat: "text"})
	code := captureExit(t, func() {
		certIssueCmd.Run(certIssueCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertIssueCmd_CAKeyFileMissing(t *testing.T) {
	resetCertIssueFlags(t)
	t.Cleanup(func() { resetCertIssueFlags(t) })
	certPath, _, _, _ := writeCAFiles(t)
	_ = certIssueCmd.Flags().Set("ca-cert", certPath)
	_ = certIssueCmd.Flags().Set("ca-key", "/nonexistent/ca.key")
	_ = certIssueCmd.Flags().Set("cn", "server.example.com")
	withGlobalConfig(t, &Config{OutputFormat: "text"})
	code := captureExit(t, func() {
		certIssueCmd.Run(certIssueCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCertIssueCmd_InvalidIP(t *testing.T) {
	resetCertIssueFlags(t)
	t.Cleanup(func() { resetCertIssueFlags(t) })
	certPath, keyPath, _, _ := writeCAFiles(t)
	_ = certIssueCmd.Flags().Set("ca-cert", certPath)
	_ = certIssueCmd.Flags().Set("ca-key", keyPath)
	_ = certIssueCmd.Flags().Set("cn", "server.example.com")
	_ = certIssueCmd.Flags().Set("ip", "not-an-ip")
	withGlobalConfig(t, &Config{OutputFormat: "text"})
	code := captureExit(t, func() {
		certIssueCmd.Run(certIssueCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for invalid IP, got %d", code)
	}
}

func TestCertIssueCmd_ServerCertSuccessJSONToFiles(t *testing.T) {
	resetCertIssueFlags(t)
	t.Cleanup(func() { resetCertIssueFlags(t) })
	certPath, keyPath, _, _ := writeCAFiles(t)
	dir := t.TempDir()
	outCert := filepath.Join(dir, "server.crt")
	outKey := filepath.Join(dir, "server.key")

	_ = certIssueCmd.Flags().Set("ca-cert", certPath)
	_ = certIssueCmd.Flags().Set("ca-key", keyPath)
	_ = certIssueCmd.Flags().Set("cn", "server.example.com")
	_ = certIssueCmd.Flags().Set("type", "server")
	_ = certIssueCmd.Flags().Set("dns", "server.example.com, www.example.com")
	_ = certIssueCmd.Flags().Set("ip", "127.0.0.1, ::1")
	_ = certIssueCmd.Flags().Set("output", outCert)
	_ = certIssueCmd.Flags().Set("key-output", outKey)
	withGlobalConfig(t, &Config{OutputFormat: "json"})

	out := captureStdout(t, func() {
		certIssueCmd.Run(certIssueCmd, nil)
	})
	if !strings.Contains(out, "dns_names") || !strings.Contains(out, "ip_addresses") {
		t.Errorf("expected SANs reflected in JSON output, got: %q", out)
	}
	if _, err := os.Stat(outCert); err != nil {
		t.Errorf("expected cert file written: %v", err)
	}
	if _, err := os.Stat(outKey); err != nil {
		t.Errorf("expected key file written: %v", err)
	}
}

func TestCertIssueCmd_ClientCertWithEmailTextOutput(t *testing.T) {
	resetCertIssueFlags(t)
	t.Cleanup(func() { resetCertIssueFlags(t) })
	certPath, keyPath, _, _ := writeCAFiles(t)

	_ = certIssueCmd.Flags().Set("ca-cert", certPath)
	_ = certIssueCmd.Flags().Set("ca-key", keyPath)
	_ = certIssueCmd.Flags().Set("cn", "alice@example.com")
	_ = certIssueCmd.Flags().Set("type", "client")
	_ = certIssueCmd.Flags().Set("key-algorithm", "rsa")
	_ = certIssueCmd.Flags().Set("key-size", "2048")
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	out := captureStdout(t, func() {
		certIssueCmd.Run(certIssueCmd, nil)
	})
	if !strings.Contains(out, "Email Addresses") {
		t.Errorf("expected email addresses in text output, got: %q", out)
	}
	if !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Errorf("expected inline PEM in output, got: %q", out)
	}
}

func TestCertIssueCmd_DefaultCertTypeEd25519(t *testing.T) {
	resetCertIssueFlags(t)
	t.Cleanup(func() { resetCertIssueFlags(t) })
	certPath, keyPath, _, _ := writeCAFiles(t)

	_ = certIssueCmd.Flags().Set("ca-cert", certPath)
	_ = certIssueCmd.Flags().Set("ca-key", keyPath)
	_ = certIssueCmd.Flags().Set("cn", "both-auth.example.com")
	_ = certIssueCmd.Flags().Set("type", "both")
	_ = certIssueCmd.Flags().Set("key-algorithm", "ed25519")
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	out := captureStdout(t, func() {
		certIssueCmd.Run(certIssueCmd, nil)
	})
	if !strings.Contains(out, "both-auth.example.com") {
		t.Errorf("expected CN in output, got: %q", out)
	}
}

func TestCertIssueCmd_WriteCertFileError(t *testing.T) {
	resetCertIssueFlags(t)
	t.Cleanup(func() { resetCertIssueFlags(t) })
	certPath, keyPath, _, _ := writeCAFiles(t)

	_ = certIssueCmd.Flags().Set("ca-cert", certPath)
	_ = certIssueCmd.Flags().Set("ca-key", keyPath)
	_ = certIssueCmd.Flags().Set("cn", "bad-output.example.com")
	_ = certIssueCmd.Flags().Set("output", "/nonexistent-dir/server.crt")
	withGlobalConfig(t, &Config{OutputFormat: "text"})

	code := captureExit(t, func() {
		certIssueCmd.Run(certIssueCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}
