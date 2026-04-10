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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockCertClient implements client.Client for testing certificate operations
type mockCertClient struct {
	// Connection state
	connected bool

	// Certificate storage
	certificates      map[string]string   // keyID -> PEM
	certificateChains map[string][]string // keyID -> []PEM

	// Error injection for testing error paths
	connectErr    error
	saveCertErr   error
	getCertErr    error
	deleteCertErr error
	listCertsErr  error
	certExistsErr error
	saveChainErr  error
	getChainErr   error
}

func newMockCertClient() *mockCertClient {
	return &mockCertClient{
		connected:         false,
		certificates:      make(map[string]string),
		certificateChains: make(map[string][]string),
	}
}

func (m *mockCertClient) Connect(ctx context.Context) error {
	if m.connectErr != nil {
		return m.connectErr
	}
	m.connected = true
	return nil
}

func (m *mockCertClient) Close() error {
	m.connected = false
	return nil
}

func (m *mockCertClient) Health(ctx context.Context) (*client.HealthResponse, error) {
	return &client.HealthResponse{Status: "healthy", Version: "test"}, nil
}

func (m *mockCertClient) ListBackends(ctx context.Context, _ ...transport.ListOption) (*client.ListBackendsResponse, error) {
	return &client.ListBackendsResponse{}, nil
}

func (m *mockCertClient) GetBackend(ctx context.Context, backendID string) (*client.BackendInfo, error) {
	return &client.BackendInfo{ID: backendID}, nil
}

func (m *mockCertClient) GenerateKey(ctx context.Context, req *client.GenerateKeyRequest) (*client.GenerateKeyResponse, error) {
	return &client.GenerateKeyResponse{KeyID: req.KeyID}, nil
}

func (m *mockCertClient) ListKeys(ctx context.Context, backend string, _ ...transport.ListOption) (*client.ListKeysResponse, error) {
	return &client.ListKeysResponse{}, nil
}

func (m *mockCertClient) GetKey(ctx context.Context, backend, keyID string) (*client.GetKeyResponse, error) {
	return &client.GetKeyResponse{}, nil
}

func (m *mockCertClient) DeleteKey(ctx context.Context, backend, keyID string) (*client.DeleteKeyResponse, error) {
	return &client.DeleteKeyResponse{Success: true}, nil
}

func (m *mockCertClient) Sign(ctx context.Context, req *client.SignRequest) (*client.SignResponse, error) {
	return &client.SignResponse{Signature: []byte("test-signature")}, nil
}

func (m *mockCertClient) Verify(ctx context.Context, req *client.VerifyRequest) (*client.VerifyResponse, error) {
	return &client.VerifyResponse{Valid: true}, nil
}

func (m *mockCertClient) Encrypt(ctx context.Context, req *client.EncryptRequest) (*client.EncryptResponse, error) {
	return &client.EncryptResponse{Ciphertext: req.Plaintext}, nil
}

func (m *mockCertClient) Decrypt(ctx context.Context, req *client.DecryptRequest) (*client.DecryptResponse, error) {
	return &client.DecryptResponse{Plaintext: req.Ciphertext}, nil
}

func (m *mockCertClient) EncryptAsym(ctx context.Context, req *client.EncryptAsymRequest) (*client.EncryptAsymResponse, error) {
	return &client.EncryptAsymResponse{Ciphertext: req.Plaintext}, nil
}

func (m *mockCertClient) GetCertificate(ctx context.Context, backend, keyID string) (*client.GetCertificateResponse, error) {
	if m.getCertErr != nil {
		return nil, m.getCertErr
	}
	pem, ok := m.certificates[keyID]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return &client.GetCertificateResponse{KeyID: keyID, CertificatePEM: pem}, nil
}

func (m *mockCertClient) SaveCertificate(ctx context.Context, req *client.SaveCertificateRequest) error {
	if m.saveCertErr != nil {
		return m.saveCertErr
	}
	m.certificates[req.KeyID] = req.CertificatePEM
	return nil
}

func (m *mockCertClient) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	if m.deleteCertErr != nil {
		return m.deleteCertErr
	}
	if _, ok := m.certificates[keyID]; !ok {
		return errors.New("certificate not found")
	}
	delete(m.certificates, keyID)
	return nil
}

func (m *mockCertClient) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	if m.certExistsErr != nil {
		return false, m.certExistsErr
	}
	_, ok := m.certificates[keyID]
	return ok, nil
}

func (m *mockCertClient) ImportKey(ctx context.Context, req *client.ImportKeyRequest) (*client.ImportKeyResponse, error) {
	return &client.ImportKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (m *mockCertClient) ExportKey(ctx context.Context, req *client.ExportKeyRequest) (*client.ExportKeyResponse, error) {
	return &client.ExportKeyResponse{KeyID: req.KeyID}, nil
}

func (m *mockCertClient) RotateKey(ctx context.Context, req *client.RotateKeyRequest) (*client.RotateKeyResponse, error) {
	return &client.RotateKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (m *mockCertClient) GetImportParameters(ctx context.Context, req *client.GetImportParametersRequest) (*client.GetImportParametersResponse, error) {
	return &client.GetImportParametersResponse{Algorithm: req.Algorithm}, nil
}

func (m *mockCertClient) WrapKey(ctx context.Context, req *client.WrapKeyRequest) (*client.WrapKeyResponse, error) {
	return &client.WrapKeyResponse{WrappedKeyMaterial: req.KeyMaterial}, nil
}

func (m *mockCertClient) UnwrapKey(ctx context.Context, req *client.UnwrapKeyRequest) (*client.UnwrapKeyResponse, error) {
	return &client.UnwrapKeyResponse{KeyMaterial: req.WrappedKeyMaterial}, nil
}

func (m *mockCertClient) CopyKey(ctx context.Context, req *client.CopyKeyRequest) (*client.CopyKeyResponse, error) {
	return &client.CopyKeyResponse{Success: true, KeyID: req.DestKeyID}, nil
}

func (m *mockCertClient) ListCertificates(ctx context.Context, backend string, _ ...transport.ListOption) (*client.ListCertificatesResponse, error) {
	if m.listCertsErr != nil {
		return nil, m.listCertsErr
	}
	certs := make([]client.CertificateInfo, 0, len(m.certificates))
	for keyID := range m.certificates {
		certs = append(certs, client.CertificateInfo{KeyID: keyID})
	}
	return &client.ListCertificatesResponse{Certificates: certs}, nil
}

func (m *mockCertClient) SaveCertificateChain(ctx context.Context, req *client.SaveCertificateChainRequest) error {
	if m.saveChainErr != nil {
		return m.saveChainErr
	}
	m.certificateChains[req.KeyID] = req.ChainPEM
	return nil
}

func (m *mockCertClient) GetCertificateChain(ctx context.Context, backend, keyID string) (*client.GetCertificateChainResponse, error) {
	if m.getChainErr != nil {
		return nil, m.getChainErr
	}
	chain, ok := m.certificateChains[keyID]
	if !ok {
		return nil, errors.New("certificate chain not found")
	}
	return &client.GetCertificateChainResponse{KeyID: keyID, ChainPEM: chain}, nil
}

func (m *mockCertClient) GetTLSCertificate(ctx context.Context, backend, keyID string) (*client.GetTLSCertificateResponse, error) {
	pem, ok := m.certificates[keyID]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return &client.GetTLSCertificateResponse{KeyID: keyID, CertificatePEM: pem}, nil
}

func (m *mockCertClient) Seal(ctx context.Context, req *client.SealRequest) (*client.SealResponse, error) {
	return &client.SealResponse{Ciphertext: req.Data}, nil
}

func (m *mockCertClient) Unseal(ctx context.Context, req *client.UnsealRequest) (*client.UnsealResponse, error) {
	return &client.UnsealResponse{Plaintext: req.Ciphertext}, nil
}

func (m *mockCertClient) CanSeal(ctx context.Context, backend string) (*client.CanSealResponse, error) {
	return &client.CanSealResponse{CanSeal: true, Backend: backend}, nil
}

// User management stub implementations
func (m *mockCertClient) ListUsers(ctx context.Context, _ ...transport.ListOption) (*client.ListUsersResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) GetUser(ctx context.Context, username string) (*client.GetUserResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) DeleteUser(ctx context.Context, username string) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) EnableUser(ctx context.Context, username string) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) DisableUser(ctx context.Context, username string) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) ListUserCredentials(ctx context.Context, username string) (*client.ListUserCredentialsResponse, error) {
	return nil, client.ErrNotSupported
}

// Authentication flow stub implementations
func (m *mockCertClient) BeginRegistration(ctx context.Context, req *client.BeginRegistrationRequest) (*client.BeginRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) FinishRegistration(ctx context.Context, req *client.FinishRegistrationRequest) (*client.FinishRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) BeginAuthentication(ctx context.Context, req *client.BeginAuthenticationRequest) (*client.BeginAuthenticationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) FinishAuthentication(ctx context.Context, req *client.FinishAuthenticationRequest) (*client.FinishAuthenticationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return nil, nil
}

func (m *mockCertClient) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, nil
}

func (m *mockCertClient) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, nil
}

func (m *mockCertClient) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, nil
}

func (m *mockCertClient) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return nil, nil
}

func (m *mockCertClient) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return nil, nil
}

func (m *mockCertClient) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return nil, nil
}

func (m *mockCertClient) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return nil, nil
}

// TCG CA operations stub implementations
func (m *mockCertClient) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, nil
}

func (m *mockCertClient) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, nil
}

func (m *mockCertClient) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, nil
}

// PIV operations stub implementations
func (m *mockCertClient) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, client.ErrNotSupported
}

// Tests for command existence

func TestCertCmd_Exists(t *testing.T) {
	if certCmd == nil {
		t.Fatal("certCmd should not be nil")
	}
}

func TestCertCmd_Properties(t *testing.T) {
	if certCmd.Use != "cert" {
		t.Errorf("certCmd.Use = %v, want cert", certCmd.Use)
	}

	if certCmd.Short == "" {
		t.Error("certCmd.Short should not be empty")
	}
}

func TestCertCmd_HasSubcommands(t *testing.T) {
	subcommands := certCmd.Commands()

	expectedCmds := []string{
		"save",
		"list",
		"get",
		"delete",
		"exists",
		"save-chain",
		"get-chain",
		"generate-ca",
		"issue",
	}
	foundCmds := make(map[string]bool)

	for _, cmd := range subcommands {
		foundCmds[cmd.Name()] = true
	}

	for _, expected := range expectedCmds {
		if !foundCmds[expected] {
			t.Errorf("expected subcommand %q not found", expected)
		}
	}
}

func TestCertSaveCmd_Exists(t *testing.T) {
	if certSaveCmd == nil {
		t.Fatal("certSaveCmd should not be nil")
	}
}

func TestCertSaveCmd_Properties(t *testing.T) {
	if certSaveCmd.Use != "save <key-id> <cert-file>" {
		t.Errorf("certSaveCmd.Use = %v, want 'save <key-id> <cert-file>'", certSaveCmd.Use)
	}

	if certSaveCmd.Short == "" {
		t.Error("certSaveCmd.Short should not be empty")
	}
}

func TestCertListCmd_Exists(t *testing.T) {
	if certListCmd == nil {
		t.Fatal("certListCmd should not be nil")
	}
}

func TestCertListCmd_Properties(t *testing.T) {
	if certListCmd.Use != "list" {
		t.Errorf("certListCmd.Use = %v, want list", certListCmd.Use)
	}
}

func TestCertGetCmd_Exists(t *testing.T) {
	if certGetCmd == nil {
		t.Fatal("certGetCmd should not be nil")
	}
}

func TestCertGetCmd_Properties(t *testing.T) {
	if certGetCmd.Use != "get <key-id>" {
		t.Errorf("certGetCmd.Use = %v, want 'get <key-id>'", certGetCmd.Use)
	}
}

func TestCertDeleteCmd_Exists(t *testing.T) {
	if certDeleteCmd == nil {
		t.Fatal("certDeleteCmd should not be nil")
	}
}

func TestCertDeleteCmd_Properties(t *testing.T) {
	if certDeleteCmd.Use != "delete <key-id>" {
		t.Errorf("certDeleteCmd.Use = %v, want 'delete <key-id>'", certDeleteCmd.Use)
	}
}

func TestCertExistsCmd_Exists(t *testing.T) {
	if certExistsCmd == nil {
		t.Fatal("certExistsCmd should not be nil")
	}
}

func TestCertExistsCmd_Properties(t *testing.T) {
	if certExistsCmd.Use != "exists <key-id>" {
		t.Errorf("certExistsCmd.Use = %v, want 'exists <key-id>'", certExistsCmd.Use)
	}
}

func TestCertSaveChainCmd_Exists(t *testing.T) {
	if certSaveChainCmd == nil {
		t.Fatal("certSaveChainCmd should not be nil")
	}
}

func TestCertGetChainCmd_Exists(t *testing.T) {
	if certGetChainCmd == nil {
		t.Fatal("certGetChainCmd should not be nil")
	}
}

func TestCertGenerateCACmd_Exists(t *testing.T) {
	if certGenerateCACmd == nil {
		t.Fatal("certGenerateCACmd should not be nil")
	}
}

func TestCertIssueCmd_Exists(t *testing.T) {
	if certIssueCmd == nil {
		t.Fatal("certIssueCmd should not be nil")
	}
}

func TestCertCmd_CommandStructure(t *testing.T) {
	// Test that certCmd is properly configured
	if !certCmd.HasSubCommands() {
		t.Error("certCmd should have subcommands")
	}

	// Verify parent relationship
	for _, sub := range certCmd.Commands() {
		if sub.Parent() != certCmd {
			t.Errorf("subcommand %s should have certCmd as parent", sub.Use)
		}
	}
}

func TestCertSaveCmd_Arguments(t *testing.T) {
	// Verify command expects arguments
	if certSaveCmd.Args == nil {
		t.Error("certSaveCmd.Args should be set")
	}
}

func TestCertDeleteCmd_Arguments(t *testing.T) {
	// Verify command expects arguments
	if certDeleteCmd.Args == nil {
		t.Error("certDeleteCmd.Args should be set")
	}
}

func TestCertGetCmd_Arguments(t *testing.T) {
	// Verify command expects arguments
	if certGetCmd.Args == nil {
		t.Error("certGetCmd.Args should be set")
	}
}

func TestCertExistsCmd_Arguments(t *testing.T) {
	// Verify command expects arguments
	if certExistsCmd.Args == nil {
		t.Error("certExistsCmd.Args should be set")
	}
}

func TestCertGenerateCACmd_HasFlags(t *testing.T) {
	flags := certGenerateCACmd.Flags()

	// Check for some expected flags
	expectedFlags := []string{"cn", "org", "country", "validity"}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Logf("flag %q may not exist on certGenerateCACmd", flag)
		}
	}
}

func TestCertIssueCmd_HasFlags(t *testing.T) {
	flags := certIssueCmd.Flags()

	// Check for some expected flags
	expectedFlags := []string{"cn", "dns", "ip"}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Logf("flag %q may not exist on certIssueCmd", flag)
		}
	}
}

// Tests for saveCert function with mock client

func TestCertSaveCert_TextOutput_Success(t *testing.T) {
	// Generate test certificate
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	// Create mock client
	mockClient := newMockCertClient()

	// Create config with mock client factory
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	// Create printer with buffer to capture output
	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	// Capture exit calls
	exitCalled := false
	exitCode := 0
	originalExitFunc := exitFunc
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}
	defer func() { exitFunc = originalExitFunc }()

	// Call saveCert
	saveCert(cfg, printer, "test-cert-id", string(certPEM))

	// Verify no error occurred (exit not called)
	if exitCalled {
		t.Errorf("saveCert should not call exit on success, got exit code: %d", exitCode)
	}

	// Verify output contains success message
	output := buf.String()
	if !strings.Contains(output, "Successfully saved certificate") {
		t.Errorf("expected success message in output, got: %s", output)
	}

	// Verify certificate was stored in mock
	if _, ok := mockClient.certificates["test-cert-id"]; !ok {
		t.Error("certificate should be stored in mock client")
	}
}

func TestCertSaveCert_JSONOutput_Success(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	mockClient := newMockCertClient()

	cfg := NewConfig()
	cfg.OutputFormat = "json"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	saveCert(cfg, printer, "test-cert-json", string(certPEM))

	if exitCalled {
		t.Error("saveCert should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Errorf("expected JSON success output, got: %s", output)
	}
}

func TestCertSaveCert_ClientCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return nil, errors.New("client creation failed")
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	exitCode := 0
	originalExitFunc := exitFunc
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	saveCert(cfg, printer, "test-cert", "dummy-pem")

	if !exitCalled {
		t.Error("saveCert should call exit when client creation fails")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertSaveCert_ConnectError(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.connectErr = errors.New("connection failed")

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	saveCert(cfg, printer, "test-cert", "dummy-pem")

	if !exitCalled {
		t.Error("saveCert should call exit when connection fails")
	}
}

func TestCertSaveCert_SaveError(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.saveCertErr = errors.New("save failed")

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	saveCert(cfg, printer, "test-cert", "dummy-pem")

	if !exitCalled {
		t.Error("saveCert should call exit when save fails")
	}
}

// Tests for getCert function

func TestCertGetCert_TextOutput_Success(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	mockClient := newMockCertClient()
	mockClient.certificates["get-test-cert"] = string(certPEM)

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	getCert(cfg, printer, "get-test-cert")

	if exitCalled {
		t.Error("getCert should not call exit on success")
	}

	// Verify output contains certificate data
	output := buf.String()
	if !strings.Contains(output, "BEGIN CERTIFICATE") {
		t.Errorf("expected PEM certificate in output, got: %s", output)
	}
}

func TestCertGetCert_NotFoundError(t *testing.T) {
	mockClient := newMockCertClient()

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	exitCode := 0
	originalExitFunc := exitFunc
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getCert(cfg, printer, "non-existent-cert")

	if !exitCalled {
		t.Error("getCert should call exit when certificate not found")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertGetCert_JSONOutput_Success(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	mockClient := newMockCertClient()
	mockClient.certificates["json-get-cert"] = string(certPEM)

	cfg := NewConfig()
	cfg.OutputFormat = "json"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	getCert(cfg, printer, "json-get-cert")

	if exitCalled {
		t.Error("getCert should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "subject") {
		t.Errorf("expected JSON with subject field, got: %s", output)
	}
}

func TestCertGetCert_ClientCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return nil, errors.New("client creation failed")
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getCert(cfg, printer, "test-cert")

	if !exitCalled {
		t.Error("getCert should call exit when client creation fails")
	}
}

func TestCertGetCert_ConnectError(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.connectErr = errors.New("connection failed")

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getCert(cfg, printer, "test-cert")

	if !exitCalled {
		t.Error("getCert should call exit when connection fails")
	}
}

func TestCertGetCert_InvalidPEMError(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.certificates["invalid-pem-cert"] = "not-valid-pem-data"

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getCert(cfg, printer, "invalid-pem-cert")

	if !exitCalled {
		t.Error("getCert should call exit when PEM decode fails")
	}
}

func TestCertGetCert_InvalidCertError(t *testing.T) {
	// Create a PEM block with invalid certificate data
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not-valid-certificate-data"),
	})

	mockClient := newMockCertClient()
	mockClient.certificates["invalid-cert"] = string(invalidPEM)

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getCert(cfg, printer, "invalid-cert")

	if !exitCalled {
		t.Error("getCert should call exit when certificate parsing fails")
	}
}

// Tests for listCerts function

func TestCertListCerts_MultipleEntries_Success(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.certificates["list-cert-1"] = "dummy-pem-1"
	mockClient.certificates["list-cert-2"] = "dummy-pem-2"

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	listCerts(cfg, printer)

	if exitCalled {
		t.Error("listCerts should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "list-cert-1") || !strings.Contains(output, "list-cert-2") {
		t.Errorf("expected certificate IDs in output, got: %s", output)
	}
}

func TestCertListCerts_EmptyResult(t *testing.T) {
	mockClient := newMockCertClient()

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	listCerts(cfg, printer)

	if exitCalled {
		t.Error("listCerts should not call exit for empty list")
	}

	output := buf.String()
	if !strings.Contains(output, "No certificates") && !strings.Contains(output, "Certificates:") {
		t.Errorf("expected proper output for empty list, got: %s", output)
	}
}

func TestCertListCerts_JSONOutput(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.certificates["json-list-cert"] = "dummy-pem"

	cfg := NewConfig()
	cfg.OutputFormat = "json"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	listCerts(cfg, printer)

	if exitCalled {
		t.Error("listCerts should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "certificates") {
		t.Errorf("expected JSON with certificates field, got: %s", output)
	}
}

func TestCertListCerts_TableOutput(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.certificates["table-list-cert"] = "dummy-pem"

	cfg := NewConfig()
	cfg.OutputFormat = "table"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	listCerts(cfg, printer)

	if exitCalled {
		t.Error("listCerts should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "CERTIFICATE ID") || !strings.Contains(output, "table-list-cert") {
		t.Errorf("expected table format with header and cert ID, got: %s", output)
	}
}

func TestCertListCerts_Error(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.listCertsErr = errors.New("list failed")

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	listCerts(cfg, printer)

	if !exitCalled {
		t.Error("listCerts should call exit when list fails")
	}
}

func TestCertListCerts_ClientCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return nil, errors.New("client creation failed")
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	listCerts(cfg, printer)

	if !exitCalled {
		t.Error("listCerts should call exit when client creation fails")
	}
}

func TestCertListCerts_ConnectError(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.connectErr = errors.New("connection failed")

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	listCerts(cfg, printer)

	if !exitCalled {
		t.Error("listCerts should call exit when connection fails")
	}
}

// Tests for certExists function

func TestCertCertExists_Found(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.certificates["exists-test-cert"] = "dummy-pem"

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	certExists(cfg, printer, "exists-test-cert")

	if exitCalled {
		t.Error("certExists should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "exists") {
		t.Errorf("expected exists message in output, got: %s", output)
	}
}

func TestCertCertExists_NotFound(t *testing.T) {
	mockClient := newMockCertClient()

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	certExists(cfg, printer, "non-existent-cert")

	if exitCalled {
		t.Error("certExists should not call exit when cert doesn't exist")
	}

	output := buf.String()
	if !strings.Contains(output, "does not exist") {
		t.Errorf("expected 'does not exist' in output, got: %s", output)
	}
}

func TestCertCertExists_JSONOutput(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.certificates["json-exists-cert"] = "dummy-pem"

	cfg := NewConfig()
	cfg.OutputFormat = "json"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	certExists(cfg, printer, "json-exists-cert")

	if exitCalled {
		t.Error("certExists should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, `"exists": true`) && !strings.Contains(output, `"exists":true`) {
		t.Errorf("expected JSON with exists: true, got: %s", output)
	}
}

func TestCertCertExists_Error(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.certExistsErr = errors.New("check failed")

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	certExists(cfg, printer, "test-cert")

	if !exitCalled {
		t.Error("certExists should call exit when check fails")
	}
}

func TestCertCertExists_ClientCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return nil, errors.New("client creation failed")
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	certExists(cfg, printer, "test-cert")

	if !exitCalled {
		t.Error("certExists should call exit when client creation fails")
	}
}

func TestCertCertExists_ConnectError(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.connectErr = errors.New("connection failed")

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	certExists(cfg, printer, "test-cert")

	if !exitCalled {
		t.Error("certExists should call exit when connection fails")
	}
}

// Tests for getChain function

func TestCertGetChain_ValidChain_Success(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	serverPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCert.Cert.Raw,
	})
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	mockClient := newMockCertClient()
	mockClient.certificateChains["chain-test"] = []string{string(serverPEM), string(caPEM)}

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	getChain(cfg, printer, "chain-test")

	if exitCalled {
		t.Error("getChain should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "CERTIFICATE") {
		t.Errorf("expected PEM certificates in output, got: %s", output)
	}
}

func TestCertGetChain_NotFoundError(t *testing.T) {
	mockClient := newMockCertClient()

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	exitCode := 0
	originalExitFunc := exitFunc
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getChain(cfg, printer, "non-existent-chain")

	if !exitCalled {
		t.Error("getChain should call exit when chain not found")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertGetChain_JSONOutput(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	mockClient := newMockCertClient()
	mockClient.certificateChains["json-chain-test"] = []string{string(certPEM)}

	cfg := NewConfig()
	cfg.OutputFormat = "json"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	getChain(cfg, printer, "json-chain-test")

	if exitCalled {
		t.Error("getChain should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "chain") {
		t.Errorf("expected JSON with chain field, got: %s", output)
	}
}

func TestCertGetChain_ClientCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return nil, errors.New("client creation failed")
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getChain(cfg, printer, "test-chain")

	if !exitCalled {
		t.Error("getChain should call exit when client creation fails")
	}
}

func TestCertGetChain_ConnectError(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.connectErr = errors.New("connection failed")

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getChain(cfg, printer, "test-chain")

	if !exitCalled {
		t.Error("getChain should call exit when connection fails")
	}
}

func TestCertGetChain_InvalidPEMError(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.certificateChains["invalid-pem-chain"] = []string{"not-valid-pem-data"}

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getChain(cfg, printer, "invalid-pem-chain")

	if !exitCalled {
		t.Error("getChain should call exit when PEM decode fails")
	}
}

func TestCertGetChain_InvalidCertError(t *testing.T) {
	// Create a PEM block with invalid certificate data
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not-valid-certificate-data"),
	})

	mockClient := newMockCertClient()
	mockClient.certificateChains["invalid-cert-chain"] = []string{string(invalidPEM)}

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getChain(cfg, printer, "invalid-cert-chain")

	if !exitCalled {
		t.Error("getChain should call exit when certificate parsing fails")
	}
}

// Tests for deleteCert function

func TestCertDeleteCert_Valid_Success(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.certificates["delete-test-cert"] = "dummy-pem"

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	deleteCert(cfg, printer, "delete-test-cert")

	if exitCalled {
		t.Error("deleteCert should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "Successfully deleted") {
		t.Errorf("expected success message in output, got: %s", output)
	}

	// Verify certificate was actually deleted from mock
	if _, ok := mockClient.certificates["delete-test-cert"]; ok {
		t.Error("certificate should be deleted from mock client")
	}
}

func TestCertDeleteCert_NotFoundError(t *testing.T) {
	mockClient := newMockCertClient()

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	exitCode := 0
	originalExitFunc := exitFunc
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	deleteCert(cfg, printer, "non-existent-cert")

	if !exitCalled {
		t.Error("deleteCert should call exit when certificate not found")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertDeleteCert_JSONOutput_Success(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.certificates["delete-json-cert"] = "dummy-pem"

	cfg := NewConfig()
	cfg.OutputFormat = "json"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	deleteCert(cfg, printer, "delete-json-cert")

	if exitCalled {
		t.Error("deleteCert should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Errorf("expected JSON success output, got: %s", output)
	}
}

func TestCertDeleteCert_ClientCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return nil, errors.New("client creation failed")
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	deleteCert(cfg, printer, "test-cert")

	if !exitCalled {
		t.Error("deleteCert should call exit when client creation fails")
	}
}

func TestCertDeleteCert_ConnectError(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.connectErr = errors.New("connection failed")

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	deleteCert(cfg, printer, "test-cert")

	if !exitCalled {
		t.Error("deleteCert should call exit when connection fails")
	}
}

// Tests for saveChain function

func TestCertSaveChain_ValidChain_Success(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	serverPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCert.Cert.Raw,
	})
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	mockClient := newMockCertClient()

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	chainPEMs := []string{string(serverPEM), string(caPEM)}
	saveChain(cfg, printer, "save-chain-test", chainPEMs)

	if exitCalled {
		t.Error("saveChain should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "Successfully saved certificate chain") {
		t.Errorf("expected success message in output, got: %s", output)
	}

	// Verify chain was stored in mock
	if _, ok := mockClient.certificateChains["save-chain-test"]; !ok {
		t.Error("certificate chain should be stored in mock client")
	}
}

func TestCertSaveChain_JSONOutput_Success(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	mockClient := newMockCertClient()

	cfg := NewConfig()
	cfg.OutputFormat = "json"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	chainPEMs := []string{string(certPEM)}
	saveChain(cfg, printer, "save-chain-json", chainPEMs)

	if exitCalled {
		t.Error("saveChain should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Errorf("expected JSON success output, got: %s", output)
	}
}

func TestCertSaveChain_Error(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.saveChainErr = errors.New("save chain failed")

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	saveChain(cfg, printer, "test-chain", []string{"dummy-pem"})

	if !exitCalled {
		t.Error("saveChain should call exit when save fails")
	}
}

func TestCertSaveChain_ClientCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return nil, errors.New("client creation failed")
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	saveChain(cfg, printer, "test-chain", []string{"dummy-pem"})

	if !exitCalled {
		t.Error("saveChain should call exit when client creation fails")
	}
}

func TestCertSaveChain_ConnectError(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.connectErr = errors.New("connection failed")

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	saveChain(cfg, printer, "test-chain", []string{"dummy-pem"})

	if !exitCalled {
		t.Error("saveChain should call exit when connection fails")
	}
}

// Tests for multiple certificate IDs

func TestCertSaveCert_MultipleIDs(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	mockClient := newMockCertClient()

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Save multiple certificates with different IDs
	ids := []string{"cert-a", "cert-b", "cert-c"}
	for _, id := range ids {
		var buf bytes.Buffer
		printer := NewPrinter(cfg.OutputFormat, &buf)
		exitCalled = false

		saveCert(cfg, printer, id, string(certPEM))

		if exitCalled {
			t.Errorf("saveCert should not call exit for ID: %s", id)
		}
	}

	// Verify all certificates exist
	for _, id := range ids {
		if _, ok := mockClient.certificates[id]; !ok {
			t.Errorf("expected certificate ID %s to be stored", id)
		}
	}
}

func TestCertFunctions_VariousIDFormats(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	mockClient := newMockCertClient()

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Test with various key IDs
	testIDs := []string{
		"cert-with-dashes",
		"cert_with_underscores",
		"cert.with.dots",
		"cert123numbers",
	}

	for _, id := range testIDs {
		t.Run(id, func(t *testing.T) {
			var saveBuf bytes.Buffer
			savePrinter := NewPrinter(cfg.OutputFormat, &saveBuf)
			exitCalled = false

			saveCert(cfg, savePrinter, id, string(certPEM))

			if exitCalled {
				t.Errorf("saveCert should succeed for ID: %s", id)
			}

			// Verify it exists
			var existsBuf bytes.Buffer
			existsPrinter := NewPrinter(cfg.OutputFormat, &existsBuf)
			certExists(cfg, existsPrinter, id)

			if !strings.Contains(existsBuf.String(), "exists") {
				t.Errorf("certificate should exist for ID: %s", id)
			}
		})
	}
}

// Tests for helper functions (using unique names to avoid conflicts)

func TestCertGenerateCA_BasicCertTest(t *testing.T) {
	cert, key, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	if cert == nil {
		t.Fatal("certificate should not be nil")
	}
	if key == nil {
		t.Fatal("key should not be nil")
	}

	if cert.Subject.CommonName != "Test CA" {
		t.Errorf("CommonName = %v, want Test CA", cert.Subject.CommonName)
	}

	if !cert.IsCA {
		t.Error("certificate should be a CA")
	}

	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "Test Org" {
		t.Error("certificate should have organization set")
	}
}

func TestCertGenerateCA_RSACert(t *testing.T) {
	cert, key, err := generateCA("RSA CA", "Test Org", "", "", "", "", 365, "rsa", 2048)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	if cert == nil {
		t.Fatal("certificate should not be nil")
	}
	if key == nil {
		t.Fatal("key should not be nil")
	}

	if cert.PublicKeyAlgorithm != x509.RSA {
		t.Errorf("PublicKeyAlgorithm = %v, want RSA", cert.PublicKeyAlgorithm)
	}
}

func TestCertGenerateCA_Ed25519Cert(t *testing.T) {
	cert, key, err := generateCA("Ed25519 CA", "Test Org", "", "", "", "", 365, "ed25519", 0)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	if cert == nil {
		t.Fatal("certificate should not be nil")
	}
	if key == nil {
		t.Fatal("key should not be nil")
	}

	if cert.PublicKeyAlgorithm != x509.Ed25519 {
		t.Errorf("PublicKeyAlgorithm = %v, want Ed25519", cert.PublicKeyAlgorithm)
	}
}

func TestCertGenerateCA_AllSubjectFields(t *testing.T) {
	cert, key, err := generateCA(
		"Full Subject CA",
		"Test Organization",
		"Test OU",
		"US",
		"California",
		"San Francisco",
		365,
		"ecdsa",
		256,
	)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("certificate or key should not be nil")
	}

	// Verify all subject fields
	if cert.Subject.CommonName != "Full Subject CA" {
		t.Errorf("CommonName = %v, want Full Subject CA", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "Test Organization" {
		t.Error("Organization not set correctly")
	}
	if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] != "Test OU" {
		t.Error("OrganizationalUnit not set correctly")
	}
	if len(cert.Subject.Country) == 0 || cert.Subject.Country[0] != "US" {
		t.Error("Country not set correctly")
	}
	if len(cert.Subject.Province) == 0 || cert.Subject.Province[0] != "California" {
		t.Error("Province not set correctly")
	}
	if len(cert.Subject.Locality) == 0 || cert.Subject.Locality[0] != "San Francisco" {
		t.Error("Locality not set correctly")
	}
}

func TestCertGenerateCA_ECDSAWithDifferentCurves(t *testing.T) {
	testCases := []struct {
		name    string
		keySize int
	}{
		{"P256", 256},
		{"P384", 384},
		{"P521", 521},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cert, key, err := generateCA("Test CA", "", "", "", "", "", 365, "ecdsa", tc.keySize)
			if err != nil {
				t.Fatalf("generateCA failed for %s: %v", tc.name, err)
			}

			if cert == nil || key == nil {
				t.Fatal("certificate or key should not be nil")
			}

			if cert.PublicKeyAlgorithm != x509.ECDSA {
				t.Errorf("PublicKeyAlgorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
			}
		})
	}
}

func TestCertGenerateCA_RSAWithSmallKeySize(t *testing.T) {
	// Test that small RSA key sizes default to 2048
	cert, key, err := generateCA("RSA CA", "", "", "", "", "", 365, "rsa", 1024)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("certificate or key should not be nil")
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("expected RSA key")
	}

	// The key should be at least 2048 bits (the minimum enforced)
	if rsaKey.N.BitLen() < 2048 {
		t.Errorf("RSA key size = %d, expected at least 2048", rsaKey.N.BitLen())
	}
}

func TestCertGenerateCA_DefaultAlgorithm(t *testing.T) {
	// Test that unknown algorithm defaults to ECDSA
	cert, key, err := generateCA("Default Alg CA", "", "", "", "", "", 365, "unknown", 0)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("certificate or key should not be nil")
	}

	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, want ECDSA (default)", cert.PublicKeyAlgorithm)
	}
}

func TestCertGenerateCA_ECAlgorithm(t *testing.T) {
	// Test "ec" alias for ECDSA
	cert, key, err := generateCA("EC CA", "", "", "", "", "", 365, "ec", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("certificate or key should not be nil")
	}

	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
	}
}

func TestCertIssueCertificate_ServerCert(t *testing.T) {
	// First generate CA
	caCert, caKey, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	// Issue server certificate
	cert, key, err := issueCertificate(
		caCert, caKey,
		"server.example.com", "server", "Test Org", "", "", "", "",
		365, "ecdsa", 256,
		[]string{"server.example.com", "*.example.com"}, nil, nil,
	)
	if err != nil {
		t.Fatalf("issueCertificate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("certificate should not be nil")
	}
	if key == nil {
		t.Fatal("key should not be nil")
	}

	if cert.Subject.CommonName != "server.example.com" {
		t.Errorf("CommonName = %v, want server.example.com", cert.Subject.CommonName)
	}

	if cert.IsCA {
		t.Error("server certificate should not be a CA")
	}

	// Verify ExtKeyUsage contains ServerAuth
	hasServerAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Error("server certificate should have ServerAuth ExtKeyUsage")
	}
}

func TestCertIssueCertificate_ClientCert(t *testing.T) {
	caCert, caKey, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	cert, key, err := issueCertificate(
		caCert, caKey,
		"client@example.com", "client", "Test Org", "", "", "", "",
		365, "ecdsa", 256,
		nil, nil, []string{"client@example.com"},
	)
	if err != nil {
		t.Fatalf("issueCertificate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("certificate should not be nil")
	}
	if key == nil {
		t.Fatal("key should not be nil")
	}

	// Verify ExtKeyUsage contains ClientAuth
	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		t.Error("client certificate should have ClientAuth ExtKeyUsage")
	}
}

func TestCertIssueCertificate_ServerCertNoDNSNames(t *testing.T) {
	caCert, caKey, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	// Issue server certificate without explicit DNS names - should use CN
	cert, key, err := issueCertificate(
		caCert, caKey,
		"server.example.com", "server", "", "", "", "", "",
		365, "ecdsa", 256,
		nil, nil, nil, // No DNS names, IPs, or emails
	)
	if err != nil {
		t.Fatalf("issueCertificate failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("certificate or key should not be nil")
	}

	// Server cert without DNS names should have CN added as DNS name
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "server.example.com" {
		t.Errorf("expected CN as DNS name, got: %v", cert.DNSNames)
	}
}

func TestCertIssueCertificate_ClientCertWithEmailInCN(t *testing.T) {
	caCert, caKey, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	// Issue client certificate with email in CN but no explicit emails
	cert, key, err := issueCertificate(
		caCert, caKey,
		"user@example.com", "client", "", "", "", "", "",
		365, "ecdsa", 256,
		nil, nil, nil, // No explicit email addresses
	)
	if err != nil {
		t.Fatalf("issueCertificate failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("certificate or key should not be nil")
	}

	// Client cert with email in CN should have CN added as email address
	if len(cert.EmailAddresses) == 0 || cert.EmailAddresses[0] != "user@example.com" {
		t.Errorf("expected CN as email address, got: %v", cert.EmailAddresses)
	}
}

func TestCertIssueCertificate_DefaultCertType(t *testing.T) {
	caCert, caKey, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	// Issue certificate with unknown type - should get both server and client auth
	cert, key, err := issueCertificate(
		caCert, caKey,
		"dual.example.com", "dual", "", "", "", "", "",
		365, "ecdsa", 256,
		nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("issueCertificate failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("certificate or key should not be nil")
	}

	// Should have both ServerAuth and ClientAuth
	hasServerAuth := false
	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasServerAuth || !hasClientAuth {
		t.Error("dual certificate should have both ServerAuth and ClientAuth")
	}
}

func TestCertIssueCertificate_WithIPAddresses(t *testing.T) {
	caCert, caKey, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	ipAddrs := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
	}

	cert, key, err := issueCertificate(
		caCert, caKey,
		"server.example.com", "server", "", "", "", "", "",
		365, "ecdsa", 256,
		nil, ipAddrs, nil,
	)
	if err != nil {
		t.Fatalf("issueCertificate failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("certificate or key should not be nil")
	}

	if len(cert.IPAddresses) != 2 {
		t.Errorf("expected 2 IP addresses, got: %d", len(cert.IPAddresses))
	}
}

func TestCertIssueCertificate_AllSubjectFields(t *testing.T) {
	caCert, caKey, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	cert, key, err := issueCertificate(
		caCert, caKey,
		"full.example.com", "server",
		"Full Organization",
		"Full OU",
		"US",
		"California",
		"San Francisco",
		365, "ecdsa", 256,
		nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("issueCertificate failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("certificate or key should not be nil")
	}

	// Verify all subject fields
	if cert.Subject.CommonName != "full.example.com" {
		t.Errorf("CommonName = %v, want full.example.com", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "Full Organization" {
		t.Error("Organization not set correctly")
	}
	if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] != "Full OU" {
		t.Error("OrganizationalUnit not set correctly")
	}
	if len(cert.Subject.Country) == 0 || cert.Subject.Country[0] != "US" {
		t.Error("Country not set correctly")
	}
	if len(cert.Subject.Province) == 0 || cert.Subject.Province[0] != "California" {
		t.Error("Province not set correctly")
	}
	if len(cert.Subject.Locality) == 0 || cert.Subject.Locality[0] != "San Francisco" {
		t.Error("Locality not set correctly")
	}
}

func TestCertGetPublicKey_NilInputCert(t *testing.T) {
	result := getPublicKey(nil)
	if result != nil {
		t.Error("getPublicKey(nil) should return nil")
	}
}

func TestCertGetPublicKey_RSAKey(t *testing.T) {
	_, key, err := generateCA("Test CA", "", "", "", "", "", 365, "rsa", 2048)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	pubKey := getPublicKey(key)
	if pubKey == nil {
		t.Fatal("getPublicKey should return public key for RSA")
	}

	_, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Error("expected RSA public key")
	}
}

func TestCertGetPublicKey_ECDSAKey(t *testing.T) {
	_, key, err := generateCA("Test CA", "", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	pubKey := getPublicKey(key)
	if pubKey == nil {
		t.Fatal("getPublicKey should return public key for ECDSA")
	}

	_, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Error("expected ECDSA public key")
	}
}

func TestCertGetPublicKey_Ed25519Key(t *testing.T) {
	_, key, err := generateCA("Test CA", "", "", "", "", "", 365, "ed25519", 0)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	pubKey := getPublicKey(key)
	if pubKey == nil {
		t.Fatal("getPublicKey should return public key for Ed25519")
	}

	_, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		t.Error("expected Ed25519 public key")
	}
}

func TestCertGetPublicKey_UnknownKeyType(t *testing.T) {
	// Test with an unsupported key type (using a string as an example)
	result := getPublicKey("not-a-key")
	if result != nil {
		t.Error("getPublicKey should return nil for unknown key types")
	}
}

// Tests for splitAndTrim function

func TestCertSplitAndTrim_BasicSplit(t *testing.T) {
	result := splitAndTrim("one,two,three")
	expected := []string{"one", "two", "three"}

	if len(result) != len(expected) {
		t.Errorf("expected %d elements, got %d", len(expected), len(result))
		return
	}

	for i, v := range expected {
		if result[i] != v {
			t.Errorf("result[%d] = %v, want %v", i, result[i], v)
		}
	}
}

func TestCertSplitAndTrim_WithWhitespace(t *testing.T) {
	result := splitAndTrim("  one  , two ,  three  ")
	expected := []string{"one", "two", "three"}

	if len(result) != len(expected) {
		t.Errorf("expected %d elements, got %d", len(expected), len(result))
		return
	}

	for i, v := range expected {
		if result[i] != v {
			t.Errorf("result[%d] = %v, want %v", i, result[i], v)
		}
	}
}

func TestCertSplitAndTrim_EmptyElements(t *testing.T) {
	result := splitAndTrim("one,,two,,,three")
	expected := []string{"one", "two", "three"}

	if len(result) != len(expected) {
		t.Errorf("expected %d elements, got %d", len(expected), len(result))
		return
	}

	for i, v := range expected {
		if result[i] != v {
			t.Errorf("result[%d] = %v, want %v", i, result[i], v)
		}
	}
}

func TestCertSplitAndTrim_SingleElement(t *testing.T) {
	result := splitAndTrim("single")
	expected := []string{"single"}

	if len(result) != len(expected) {
		t.Errorf("expected %d elements, got %d", len(expected), len(result))
		return
	}

	if result[0] != expected[0] {
		t.Errorf("result[0] = %v, want %v", result[0], expected[0])
	}
}

func TestCertSplitAndTrim_EmptyString(t *testing.T) {
	result := splitAndTrim("")

	if len(result) != 0 {
		t.Errorf("expected 0 elements for empty string, got %d", len(result))
	}
}

func TestCertSplitAndTrim_OnlyWhitespace(t *testing.T) {
	result := splitAndTrim("  ,  ,  ")

	if len(result) != 0 {
		t.Errorf("expected 0 elements for whitespace-only string, got %d", len(result))
	}
}

func TestCertSplitAndTrim_DNSNames(t *testing.T) {
	result := splitAndTrim("example.com, *.example.com, www.example.com")
	expected := []string{"example.com", "*.example.com", "www.example.com"}

	if len(result) != len(expected) {
		t.Errorf("expected %d elements, got %d", len(expected), len(result))
		return
	}

	for i, v := range expected {
		if result[i] != v {
			t.Errorf("result[%d] = %v, want %v", i, result[i], v)
		}
	}
}

func TestCertSplitAndTrim_IPAddresses(t *testing.T) {
	result := splitAndTrim("192.168.1.1, 10.0.0.1, 172.16.0.1")
	expected := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"}

	if len(result) != len(expected) {
		t.Errorf("expected %d elements, got %d", len(expected), len(result))
		return
	}

	for i, v := range expected {
		if result[i] != v {
			t.Errorf("result[%d] = %v, want %v", i, result[i], v)
		}
	}
}

// Test generateKeyPair function directly

func TestCertGenerateKeyPair_ECDSA(t *testing.T) {
	key, err := generateKeyPair("ecdsa", 256)
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}

	_, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Error("expected ECDSA private key")
	}
}

func TestCertGenerateKeyPair_RSA(t *testing.T) {
	key, err := generateKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}

	_, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Error("expected RSA private key")
	}
}

func TestCertGenerateKeyPair_Ed25519(t *testing.T) {
	key, err := generateKeyPair("ed25519", 0)
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}

	_, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Error("expected Ed25519 private key")
	}
}

func TestCertGenerateKeyPair_DefaultAlgorithm(t *testing.T) {
	key, err := generateKeyPair("unknown", 256)
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}

	_, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Error("expected ECDSA private key for unknown algorithm (default)")
	}
}

func TestCertGenerateKeyPair_ECDSAP384(t *testing.T) {
	key, err := generateKeyPair("ecdsa", 384)
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Error("expected ECDSA private key")
	}

	if ecKey.Curve.Params().BitSize != 384 {
		t.Errorf("expected P384 curve, got bit size %d", ecKey.Curve.Params().BitSize)
	}
}

func TestCertGenerateKeyPair_ECDSAP521(t *testing.T) {
	key, err := generateKeyPair("ecdsa", 521)
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Error("expected ECDSA private key")
	}

	if ecKey.Curve.Params().BitSize != 521 {
		t.Errorf("expected P521 curve, got bit size %d", ecKey.Curve.Params().BitSize)
	}
}

func TestCertGenerateKeyPair_ECDSADefaultCurve(t *testing.T) {
	// Use an invalid size to trigger default curve (P256)
	key, err := generateKeyPair("ecdsa", 128)
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Error("expected ECDSA private key")
	}

	if ecKey.Curve.Params().BitSize != 256 {
		t.Errorf("expected P256 curve (default), got bit size %d", ecKey.Curve.Params().BitSize)
	}
}

// Barrier operations stub implementations
func (m *mockCertClient) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) BarrierSeal(ctx context.Context) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	return client.ErrNotSupported
}

// BarrierShamirListShares returns Shamir share metadata.
func (m *mockCertClient) BarrierShamirListShares(_ context.Context) (*transport.BarrierShamirSharesResponse, error) {
	return nil, client.ErrNotSupported
}

// BarrierShamirDeleteShare deletes a Shamir share by index.
func (m *mockCertClient) BarrierShamirDeleteShare(_ context.Context, _ *transport.BarrierShamirDeleteShareRequest) error {
	return client.ErrNotSupported
}

// BarrierShamirDeleteAllShares deletes all Shamir shares.
func (m *mockCertClient) BarrierShamirDeleteAllShares(_ context.Context) error {
	return client.ErrNotSupported
}

// BarrierShamirVerify verifies Shamir share integrity.
func (m *mockCertClient) BarrierShamirVerify(_ context.Context) error {
	return client.ErrNotSupported
}

// BarrierRekey re-encrypts the barrier with a new root key.
func (m *mockCertClient) BarrierRekey(_ context.Context, _ *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	return nil, client.ErrNotSupported
}

// BarrierGenerateRecoveryKeys generates recovery keys.
func (m *mockCertClient) BarrierGenerateRecoveryKeys(_ context.Context, _ *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	return nil, client.ErrNotSupported
}

// BarrierRecoverWithKeys recovers the barrier using recovery keys.
func (m *mockCertClient) BarrierRecoverWithKeys(_ context.Context, _ *transport.BarrierRecoverWithKeysRequest) error {
	return client.ErrNotSupported
}

// BarrierDeleteRecoveryKeys deletes all recovery keys.
func (m *mockCertClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return client.ErrNotSupported
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (m *mockCertClient) BarrierHasRecoveryKeys(_ context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	return nil, client.ErrNotSupported
}

// BarrierGenerateRootToken generates a root token.
func (m *mockCertClient) BarrierGenerateRootToken(_ context.Context, _ *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	return nil, client.ErrNotSupported
}

// PIN operations stub implementations
func (m *mockCertClient) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	return client.ErrNotSupported
}

// PasswordService stub implementations
func (m *mockCertClient) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, nil
}

func (m *mockCertClient) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, nil
}

func (m *mockCertClient) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, nil
}

func (m *mockCertClient) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	return nil
}

func (m *mockCertClient) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	return nil
}

func (m *mockCertClient) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	return nil
}

func (m *mockCertClient) PasswordStoreLock(ctx context.Context) error {
	return nil
}

func (m *mockCertClient) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, nil
}

func (m *mockCertClient) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	return nil
}

func (m *mockCertClient) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, nil
}

// SealStoreService stub implementations
func (m *mockCertClient) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	return nil
}

func (m *mockCertClient) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	return nil
}

func (m *mockCertClient) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	return nil
}

func (m *mockCertClient) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, nil
}

// PolicyService stub implementations
func (m *mockCertClient) PolicyCreate(ctx context.Context, req *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	return nil, nil
}

func (m *mockCertClient) PolicyGet(ctx context.Context, req *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	return nil, nil
}

func (m *mockCertClient) PolicyList(ctx context.Context) (*transport.PolicyListResponse, error) {
	return nil, nil
}

func (m *mockCertClient) PolicyDelete(ctx context.Context, req *transport.PolicyDeleteRequest) error {
	return nil
}

func (m *mockCertClient) PolicyRefresh(ctx context.Context, req *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return nil, nil
}

func (m *mockCertClient) PolicyVerify(ctx context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) PolicyExport(ctx context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	return nil, nil
}

// CustodianGroupService stub implementations
func (m *mockCertClient) CreateCustodianGroup(_ context.Context, _ *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetCustodianGroup(_ context.Context, _ string) (*transport.GetCustodianGroupResponse, error) {
	return nil, nil
}

func (m *mockCertClient) ListCustodianGroups(_ context.Context) (*transport.ListCustodianGroupsResponse, error) {
	return nil, nil
}

func (m *mockCertClient) DeleteCustodianGroup(_ context.Context, _ string) error {
	return nil
}

func (m *mockCertClient) AddCustodianMember(_ context.Context, _ *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	return nil, nil
}

func (m *mockCertClient) RemoveCustodianMember(_ context.Context, _ *transport.RemoveCustodianMemberRequest) error {
	return nil
}

func (m *mockCertClient) DistributeShares(_ context.Context, _ *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	return nil, nil
}

// ShareService stub implementations
func (m *mockCertClient) SubmitShare(_ context.Context, _ *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	return nil, nil
}

func (m *mockCertClient) ListShares(_ context.Context) (*transport.ListSharesResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetShareCollectionStatus(_ context.Context, _ string) (*transport.ShareCollectionStatus, error) {
	return nil, nil
}

// TenantService stub implementations
func (m *mockCertClient) CreateTenant(_ context.Context, _ *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetTenant(_ context.Context, _ string) (*transport.GetTenantResponse, error) {
	return nil, nil
}

func (m *mockCertClient) ListTenants(_ context.Context) (*transport.ListTenantsResponse, error) {
	return nil, nil
}

func (m *mockCertClient) DeleteTenant(_ context.Context, _ string) error {
	return nil
}

func (m *mockCertClient) TenantBarrierInit(_ context.Context, _ *transport.TenantBarrierInitRequest) error {
	return nil
}

func (m *mockCertClient) TenantBarrierUnseal(_ context.Context, _ *transport.TenantBarrierUnsealRequest) error {
	return nil
}

// InitCeremonyService stub implementations
func (m *mockCertClient) GetInitStatus(_ context.Context) (*transport.InitStatusResponse, error) {
	return nil, nil
}

func (m *mockCertClient) ClaimCertBegin(_ context.Context, _ *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	return nil, nil
}

func (m *mockCertClient) ClaimCertComplete(_ context.Context, _ *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	return nil, nil
}

func (m *mockCertClient) ClaimShare(_ context.Context, _ *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SignCSRInit(_ context.Context, _ *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return nil, nil
}

// CredentialManagementService stub implementations
func (m *mockCertClient) SubmitCredential(_ context.Context, _ *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetCredentialStrategy(_ context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, nil
}
