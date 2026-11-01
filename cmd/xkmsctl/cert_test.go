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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"reflect"
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

	// TLS certificate bundle (certificate + chain; the private key is never
	// part of this response, by design — go-xkms#627).
	tlsChains     map[string][]string // keyID -> chain PEM entries
	getTLSCertErr error
}

func newMockCertClient() *mockCertClient {
	return &mockCertClient{
		connected:         false,
		certificates:      make(map[string]string),
		certificateChains: make(map[string][]string),
		tlsChains:         make(map[string][]string),
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

func (m *mockCertClient) CreateOTAImageKey(ctx context.Context, req *client.OTAImageKeyRequest) (*client.GenerateKeyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) RotateOTAImageKey(ctx context.Context, req *client.OTAImageKeyRequest) (*client.RotateKeyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SignOTAImage(ctx context.Context, req *client.OTAImageSignRequest) (*client.SignResponse, error) {
	return nil, nil
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
	if m.getTLSCertErr != nil {
		return nil, m.getTLSCertErr
	}
	pem, ok := m.certificates[keyID]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return &client.GetTLSCertificateResponse{
		KeyID:          keyID,
		CertificatePEM: pem,
		ChainPEM:       m.tlsChains[keyID],
	}, nil
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

func (m *mockCertClient) GetInvite(ctx context.Context, req *client.GetInviteRequest) (*client.GetInviteResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) BeginInviteRegistration(ctx context.Context, req *client.BeginInviteRegistrationRequest) (*client.BeginInviteRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) FinishInviteRegistration(ctx context.Context, req *client.FinishInviteRegistrationRequest) (*client.FinishInviteRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCertClient) ActivateInvitePIV(ctx context.Context, req *client.ActivateInvitePIVRequest) (*client.ActivateInvitePIVResponse, error) {
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

func (m *mockCertClient) IssueLAKCertificate(ctx context.Context, req *transport.IssueLAKCertificateRequest) (*transport.IssueLAKCertificateResponse, error) {
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

// Tests for helper functions (using unique names to avoid conflicts)

// TestCertGenerateCA_UsesCanonicalCAProfile locks in that generateCA is
// wired to pkg/ca's canonical CA profile (client.NewCAProfile, aliased from
// pkg/ca.NewCAProfile / pkg/ca.ProfileNameCA) instead of a hand-rolled
// template. It reads the profile's current KeyUsage rather than hardcoding
// the expected flags, so a change to that profile is observable here without
// editing this test — the same profile the platform root CA and every
// tenant root CA (pkg/acme/admin.TenantAwareAdminService.CreateTenantRootCA)
// are issued with.
func TestCertGenerateCA_UsesCanonicalCAProfile(t *testing.T) {
	cert, _, err := generateCA("Profile Wiring CA", "", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	want := client.NewCAProfile()
	if cert.KeyUsage != want.KeyUsage() {
		t.Errorf("KeyUsage = %v, want %v (from client.NewCAProfile)", cert.KeyUsage, want.KeyUsage())
	}
	if !cert.IsCA {
		t.Error("expected IsCA true from the canonical CA profile")
	}
	if !cert.BasicConstraintsValid {
		t.Error("expected BasicConstraintsValid true from the canonical CA profile")
	}
}

// TestCertIssue_UsesCanonicalLeafProfiles is the leaf counterpart of
// TestCertGenerateCA_UsesCanonicalCAProfile: it proves a change to the
// canonical server/client profiles is observable from the CLI.
//
// The CLI previously built its own near-copy of client.NewServerProfile()
// that differed only in Basic Constraints. A near-copy is how issuance shapes
// drift: it stays correct until someone edits the canonical profile, and then
// only the CLI is left behind. Each expectation is read from the canonical
// profile at run time rather than written out here, so this test tracks the
// profile instead of restating it.
func TestCertIssue_UsesCanonicalLeafProfiles(t *testing.T) {
	caCert, caKey, err := generateCA("Leaf Profile Wiring CA", "", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	tests := []struct {
		certType string
		want     client.ProfileProvider
	}{
		{"server", client.NewServerProfile()},
		{"client", client.NewClientProfile()},
	}

	for _, tt := range tests {
		t.Run(tt.certType, func(t *testing.T) {
			cert, _, err := issueCertificate(
				caCert, caKey,
				"leaf.example.com", tt.certType, "", "", "", "", "",
				365, "ecdsa", 256, nil, nil, nil)
			if err != nil {
				t.Fatalf("issueCertificate(%s) failed: %v", tt.certType, err)
			}

			if cert.KeyUsage != tt.want.KeyUsage() {
				t.Errorf("KeyUsage = %v, want %v (from the canonical %s profile)",
					cert.KeyUsage, tt.want.KeyUsage(), tt.certType)
			}
			if got, want := cert.ExtKeyUsage, tt.want.ExtKeyUsage(); !reflect.DeepEqual(got, want) {
				t.Errorf("ExtKeyUsage = %v, want %v (from the canonical %s profile)",
					got, want, tt.certType)
			}
			if !cert.BasicConstraintsValid {
				t.Error("expected BasicConstraintsValid from the canonical leaf profile")
			}
			if cert.IsCA {
				t.Error("a leaf certificate must not be a CA")
			}
		})
	}
}

// TestCertIssue_DualPurposeCarriesBothEKUs covers the certType default, which
// has no canonical profile. Its key usage is still taken from the canonical
// server profile rather than restated, so it cannot drift away from it.
func TestCertIssue_DualPurposeCarriesBothEKUs(t *testing.T) {
	caCert, caKey, err := generateCA("Dual Purpose CA", "", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	cert, _, err := issueCertificate(
		caCert, caKey,
		"dual.example.com", "", "", "", "", "", "",
		365, "ecdsa", 256, nil, nil, nil)
	if err != nil {
		t.Fatalf("issueCertificate failed: %v", err)
	}

	if want := client.NewServerProfile().KeyUsage(); cert.KeyUsage != want {
		t.Errorf("KeyUsage = %v, want %v (from the canonical server profile)", cert.KeyUsage, want)
	}
	wantEKU := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if !reflect.DeepEqual(cert.ExtKeyUsage, wantEKU) {
		t.Errorf("ExtKeyUsage = %v, want %v", cert.ExtKeyUsage, wantEKU)
	}
	if !cert.BasicConstraintsValid {
		t.Error("expected BasicConstraintsValid on the dual-purpose leaf")
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

func TestCertGetPublicKey_UnknownKeyType(t *testing.T) {
	// Test with an unsupported key type (using a string as an example)
	result := getPublicKey("not-a-key")
	if result != nil {
		t.Error("getPublicKey should return nil for unknown key types")
	}
}

// Tests for splitAndTrim function

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

// TestCertGenerateKeyPair_RSA_RefusesOversizedKey proves generateKeyPair
// refuses a modulus above the 4096-bit ceiling before rsa.GenerateKey ever
// runs. rsa.GenerateKey cannot be cancelled and its cost grows with the
// cube of the modulus size, so an unbounded --key-size would otherwise pin
// this CLI process's CPU core for minutes to hours (go-xkms#1260).
func TestCertGenerateKeyPair_RSA_RefusesOversizedKey(t *testing.T) {
	_, err := generateKeyPair("rsa", 65536)
	if !errors.Is(err, ErrRSAKeySizeTooLarge) {
		t.Fatalf("generateKeyPair(rsa, 65536) error = %v, want ErrRSAKeySizeTooLarge", err)
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

func (m *mockCertClient) BarrierSeal(ctx context.Context) error {
	return client.ErrNotSupported
}

func (m *mockCertClient) BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	return nil, client.ErrNotSupported
}

// BarrierDeleteRecoveryKeys deletes all recovery keys.
func (m *mockCertClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return client.ErrNotSupported
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
func (m *mockCertClient) PasswordVaultStatus(_ context.Context) (*transport.PasswordVaultStatusResponse, error) {
	return nil, nil
}
func (m *mockCertClient) PasswordVaultEnroll(_ context.Context, _ *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}
func (m *mockCertClient) PasswordVaultRotate(_ context.Context, _ *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}
func (m *mockCertClient) PasswordVaultRemoveFactor(_ context.Context, _ *transport.PasswordVaultRemoveFactorRequest) error {
	return nil
}
func (m *mockCertClient) PasswordVaultRecover(_ context.Context, _ *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
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

func (m *mockCertClient) EscrowKey(ctx context.Context, req *transport.EscrowRequest) ([]*transport.EscrowReceipt, error) {
	return nil, nil
}

func (m *mockCertClient) RecoverKey(ctx context.Context, req *transport.RecoverRequest) (*transport.RecoverResponse, error) {
	return nil, nil
}

func (m *mockCertClient) ListEscrowed(ctx context.Context) ([]transport.EscrowRecord, error) {
	return nil, nil
}

func (m *mockCertClient) RevokeEscrow(ctx context.Context, escrowID string) error {
	return nil
}

func (m *mockCertClient) ListKeyVersions(context.Context, *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockCertClient) EnableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockCertClient) DisableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockCertClient) RetireKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockCertClient) EnableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockCertClient) DisableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockCertClient) RotateScopeKeys(context.Context, *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	return nil, nil
}

func (m *mockCertClient) TPMPolicyCreate(context.Context, *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockCertClient) TPMPolicyGet(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockCertClient) TPMPolicyList(context.Context, *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	return nil, nil
}

func (m *mockCertClient) TPMPolicyUpdate(context.Context, *transport.TPMPolicyUpdateRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockCertClient) TPMPolicyRevoke(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockCertClient) TPMPolicyVerify(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) TPMPolicyDelete(context.Context, *transport.TPMPolicyDeleteRequest) error {
	return nil
}

func (m *mockCertClient) TPMPolicyObjects(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return nil, nil
}

func (m *mockCertClient) TPMPolicySetAutoUnseal(context.Context, *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockCertClient) TPMPolicySetDescription(context.Context, *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

// OIDC credential operations are not exercised by this double.
func (*mockCertClient) OIDCCredentialCreate(context.Context, *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockCertClient) OIDCCredentialImport(context.Context, *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockCertClient) OIDCCredentialGet(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockCertClient) OIDCCredentialList(context.Context, *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	return nil, nil
}
func (*mockCertClient) TrustRootList(context.Context, *transport.TrustRootListRequest) (*transport.TrustRootListResponse, error) {
	return nil, nil
}
func (*mockCertClient) TrustRootGet(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*mockCertClient) TrustRootImport(context.Context, *transport.TrustRootImportRequest) (*transport.TrustRootImportResponse, error) {
	return nil, nil
}
func (*mockCertClient) TrustRootQuarantine(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*mockCertClient) TrustRootRemove(context.Context, *transport.TrustRootRequest) error {
	return nil
}
func (*mockCertClient) OIDCCredentialDelete(context.Context, *transport.OIDCCredentialRef) error {
	return nil
}
func (*mockCertClient) OIDCCredentialRefresh(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockCertClient) OIDCCredentialGetAccessToken(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	return nil, nil
}
func (*mockCertClient) OIDCCredentialDeviceStart(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockCertClient) OIDCCredentialDevicePoll(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}

func (m *mockCertClient) TPMObjectPolicy(context.Context, *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) TPMPolicyRotateAuthority(context.Context, *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetTenantTPMMode(context.Context, string) (*transport.TenantTPMModeResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SetTenantTPMMode(context.Context, *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	return nil, nil
}

func (m *mockCertClient) TenantVTPMStatus(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (m *mockCertClient) TenantVTPMStart(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (m *mockCertClient) TenantVTPMStop(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (m *mockCertClient) DeleteBackup(_ context.Context, _ string) error {
	return nil
}

func (m *mockCertClient) DeleteCustodianGroup(_ context.Context, _ string) error {
	return nil
}

func (m *mockCertClient) Algorithms(_ context.Context) (*transport.AlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockCertClient) DeleteShare(_ context.Context, _, _ string, _ int) error {
	return nil
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

func (m *mockCertClient) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}

func (m *mockCertClient) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, nil
}

// CredentialManagementService stub implementations
func (m *mockCertClient) SubmitCredential(_ context.Context, _ *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetCredentialStrategy(_ context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) CreateUser(_ context.Context, _ *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	return nil, nil
}

func (m *mockCertClient) ListUsers(_ context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetUser(_ context.Context, _ string) (*transport.GetUserResponse, error) {
	return nil, nil
}

func (m *mockCertClient) DeleteUser(_ context.Context, _ string) error {
	return nil
}

func (m *mockCertClient) EnableUser(_ context.Context, _ string) error {
	return nil
}

func (m *mockCertClient) DisableUser(_ context.Context, _ string) error {
	return nil
}

func (m *mockCertClient) BindUserCert(_ context.Context, _, _ string, _ int64) error {
	return nil
}

func (m *mockCertClient) ListUserCredentials(_ context.Context, _ string) (*transport.ListUserCredentialsResponse, error) {
	return nil, nil
}

func (*mockCertClient) SetSigningKeyBinding(context.Context, *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*mockCertClient) GetSigningKeyBinding(context.Context, *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*mockCertClient) ListSigningKeyBindings(context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	return nil, nil
}
func (*mockCertClient) DeleteSigningKeyBinding(context.Context, *transport.DeleteSigningKeyBindingRequest) error {
	return nil
}
func (*mockCertClient) ResolveSigningKey(context.Context, *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	return nil, nil
}
