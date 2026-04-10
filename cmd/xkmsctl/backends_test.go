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
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func TestBackendsCmd_Exists(t *testing.T) {
	if backendsCmd == nil {
		t.Fatal("backendsCmd should not be nil")
	}
}

func TestBackendsCmd_Properties(t *testing.T) {
	if backendsCmd.Use != "backends" {
		t.Errorf("backendsCmd.Use = %v, want backends", backendsCmd.Use)
	}

	if backendsCmd.Short == "" {
		t.Error("backendsCmd.Short should not be empty")
	}
}

func TestBackendsCmd_HasSubcommands(t *testing.T) {
	subcommands := backendsCmd.Commands()

	// Check for list and info subcommands
	foundList := false
	foundInfo := false

	for _, cmd := range subcommands {
		name := cmd.Name()
		if name == "list" {
			foundList = true
		}
		// The info command Use is "info <backend>", but Name() returns "info"
		if strings.HasPrefix(cmd.Use, "info") {
			foundInfo = true
		}
	}

	if !foundList {
		t.Error("expected subcommand 'list' not found")
	}

	if !foundInfo {
		t.Error("expected subcommand 'info' not found")
	}
}

func TestBackendsListCmd_Exists(t *testing.T) {
	if backendsListCmd == nil {
		t.Fatal("backendsListCmd should not be nil")
	}
}

func TestBackendsListCmd_Properties(t *testing.T) {
	if backendsListCmd.Use != "list" {
		t.Errorf("backendsListCmd.Use = %v, want list", backendsListCmd.Use)
	}

	if backendsListCmd.Short == "" {
		t.Error("backendsListCmd.Short should not be empty")
	}
}

func TestBackendsInfoCmd_Exists(t *testing.T) {
	if backendsInfoCmd == nil {
		t.Fatal("backendsInfoCmd should not be nil")
	}
}

func TestBackendsInfoCmd_Properties(t *testing.T) {
	if backendsInfoCmd.Use != "info <backend>" {
		t.Errorf("backendsInfoCmd.Use = %v, want 'info <backend>'", backendsInfoCmd.Use)
	}

	if backendsInfoCmd.Short == "" {
		t.Error("backendsInfoCmd.Short should not be empty")
	}
}

func TestConvertBackendInfoToCapabilities_Full(t *testing.T) {
	info := &client.BackendInfo{
		ID:             "software",
		Type:           "software",
		HardwareBacked: false,
		Capabilities: transport.BackendCapabilities{
			Keys:                true,
			Signing:             true,
			Decryption:          true,
			KeyRotation:         true,
			SymmetricEncryption: true,
			Import:              true,
			Export:              true,
			KeyAgreement:        true,
			ECIES:               true,
		},
	}

	caps := convertBackendInfoToCapabilities(info)

	if !caps.Keys {
		t.Error("caps.Keys should be true")
	}
	if caps.HardwareBacked {
		t.Error("caps.HardwareBacked should be false")
	}
	if !caps.Signing {
		t.Error("caps.Signing should be true")
	}
	if !caps.Decryption {
		t.Error("caps.Decryption should be true")
	}
	if !caps.KeyRotation {
		t.Error("caps.KeyRotation should be true")
	}
	if !caps.SymmetricEncryption {
		t.Error("caps.SymmetricEncryption should be true")
	}
	if !caps.Import {
		t.Error("caps.Import should be true")
	}
	if !caps.Export {
		t.Error("caps.Export should be true")
	}
	if !caps.KeyAgreement {
		t.Error("caps.KeyAgreement should be true")
	}
	if !caps.ECIES {
		t.Error("caps.ECIES should be true")
	}
}

func TestConvertBackendInfoToCapabilities_Partial(t *testing.T) {
	info := &client.BackendInfo{
		ID:             "tpm2",
		Type:           "tpm2",
		HardwareBacked: true,
		Capabilities: transport.BackendCapabilities{
			Keys:       true,
			Signing:    true,
			Decryption: true,
		},
	}

	caps := convertBackendInfoToCapabilities(info)

	if !caps.Keys {
		t.Error("caps.Keys should be true")
	}
	if !caps.HardwareBacked {
		t.Error("caps.HardwareBacked should be true")
	}
	if !caps.Signing {
		t.Error("caps.Signing should be true")
	}
	if !caps.Decryption {
		t.Error("caps.Decryption should be true")
	}
	if caps.KeyRotation {
		t.Error("caps.KeyRotation should be false")
	}
	if caps.SymmetricEncryption {
		t.Error("caps.SymmetricEncryption should be false")
	}
}

func TestConvertBackendInfoToCapabilities_Empty(t *testing.T) {
	info := &client.BackendInfo{
		ID:             "empty",
		Type:           "empty",
		HardwareBacked: false,
		Capabilities:   transport.BackendCapabilities{},
	}

	caps := convertBackendInfoToCapabilities(info)

	if caps.Keys {
		t.Error("caps.Keys should be false")
	}
	if caps.HardwareBacked {
		t.Error("caps.HardwareBacked should be false")
	}
	if caps.Signing {
		t.Error("caps.Signing should be false")
	}
}

func TestConvertBackendInfoToCapabilities_ZeroValue(t *testing.T) {
	info := &client.BackendInfo{
		ID:             "zero",
		Type:           "zero",
		HardwareBacked: true,
	}

	caps := convertBackendInfoToCapabilities(info)

	if caps.Keys {
		t.Error("caps.Keys should be false")
	}
	if !caps.HardwareBacked {
		t.Error("caps.HardwareBacked should be true (from info)")
	}
	if caps.Signing {
		t.Error("caps.Signing should be false")
	}
	if caps.Decryption {
		t.Error("caps.Decryption should be false")
	}
}

// mockBackendsClient is a mock client for testing backend operations
type mockBackendsClient struct {
	listBackendsResp *client.ListBackendsResponse
	listBackendsErr  error
	getBackendResp   *client.BackendInfo
	getBackendErr    error
	connectErr       error
}

func (m *mockBackendsClient) Connect(ctx context.Context) error {
	return m.connectErr
}

func (m *mockBackendsClient) Close() error {
	return nil
}

func (m *mockBackendsClient) Health(ctx context.Context) (*client.HealthResponse, error) {
	return &client.HealthResponse{Status: "ok"}, nil
}

func (m *mockBackendsClient) ListBackends(ctx context.Context, _ ...transport.ListOption) (*client.ListBackendsResponse, error) {
	return m.listBackendsResp, m.listBackendsErr
}

func (m *mockBackendsClient) GetBackend(ctx context.Context, backendID string) (*client.BackendInfo, error) {
	return m.getBackendResp, m.getBackendErr
}

func (m *mockBackendsClient) GenerateKey(ctx context.Context, req *client.GenerateKeyRequest) (*client.GenerateKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ListKeys(ctx context.Context, backend string, _ ...transport.ListOption) (*client.ListKeysResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetKey(ctx context.Context, backend, keyID string) (*client.GetKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeleteKey(ctx context.Context, backend, keyID string) (*client.DeleteKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Sign(ctx context.Context, req *client.SignRequest) (*client.SignResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Verify(ctx context.Context, req *client.VerifyRequest) (*client.VerifyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Encrypt(ctx context.Context, req *client.EncryptRequest) (*client.EncryptResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Decrypt(ctx context.Context, req *client.DecryptRequest) (*client.DecryptResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) EncryptAsym(ctx context.Context, req *client.EncryptAsymRequest) (*client.EncryptAsymResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetCertificate(ctx context.Context, backend, keyID string) (*client.GetCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SaveCertificate(ctx context.Context, req *client.SaveCertificateRequest) error {
	return nil
}

func (m *mockBackendsClient) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *mockBackendsClient) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	return false, nil
}

func (m *mockBackendsClient) ImportKey(ctx context.Context, req *client.ImportKeyRequest) (*client.ImportKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ExportKey(ctx context.Context, req *client.ExportKeyRequest) (*client.ExportKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) RotateKey(ctx context.Context, req *client.RotateKeyRequest) (*client.RotateKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetImportParameters(ctx context.Context, req *client.GetImportParametersRequest) (*client.GetImportParametersResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) WrapKey(ctx context.Context, req *client.WrapKeyRequest) (*client.WrapKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) UnwrapKey(ctx context.Context, req *client.UnwrapKeyRequest) (*client.UnwrapKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) CopyKey(ctx context.Context, req *client.CopyKeyRequest) (*client.CopyKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ListCertificates(ctx context.Context, backend string, _ ...transport.ListOption) (*client.ListCertificatesResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SaveCertificateChain(ctx context.Context, req *client.SaveCertificateChainRequest) error {
	return nil
}

func (m *mockBackendsClient) GetCertificateChain(ctx context.Context, backend, keyID string) (*client.GetCertificateChainResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetTLSCertificate(ctx context.Context, backend, keyID string) (*client.GetTLSCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Seal(ctx context.Context, req *client.SealRequest) (*client.SealResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Unseal(ctx context.Context, req *client.UnsealRequest) (*client.UnsealResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) CanSeal(ctx context.Context, backend string) (*client.CanSealResponse, error) {
	return nil, nil
}

// User management stub implementations
func (m *mockBackendsClient) ListUsers(ctx context.Context, _ ...transport.ListOption) (*client.ListUsersResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) GetUser(ctx context.Context, username string) (*client.GetUserResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) DeleteUser(ctx context.Context, username string) error {
	return client.ErrNotSupported
}

func (m *mockBackendsClient) EnableUser(ctx context.Context, username string) error {
	return client.ErrNotSupported
}

func (m *mockBackendsClient) DisableUser(ctx context.Context, username string) error {
	return client.ErrNotSupported
}

func (m *mockBackendsClient) ListUserCredentials(ctx context.Context, username string) (*client.ListUserCredentialsResponse, error) {
	return nil, client.ErrNotSupported
}

// Authentication flow stub implementations
func (m *mockBackendsClient) BeginRegistration(ctx context.Context, req *client.BeginRegistrationRequest) (*client.BeginRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) FinishRegistration(ctx context.Context, req *client.FinishRegistrationRequest) (*client.FinishRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) BeginAuthentication(ctx context.Context, req *client.BeginAuthenticationRequest) (*client.BeginAuthenticationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) FinishAuthentication(ctx context.Context, req *client.FinishAuthenticationRequest) (*client.FinishAuthenticationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return nil, nil
}

// TCG CA operations stub implementations
func (m *mockBackendsClient) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, nil
}

// PIV operations stub implementations
func (m *mockBackendsClient) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return client.ErrNotSupported
}

func (m *mockBackendsClient) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return client.ErrNotSupported
}

func (m *mockBackendsClient) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return client.ErrNotSupported
}

func (m *mockBackendsClient) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, client.ErrNotSupported
}

func TestListBackends_Success(t *testing.T) {
	mockClient := &mockBackendsClient{
		listBackendsResp: &client.ListBackendsResponse{
			Backends: []client.BackendInfo{
				{ID: "software", Type: "software"},
				{ID: "tpm2", Type: "tpm2"},
				{ID: "pkcs11", Type: "pkcs11"},
			},
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	listBackends(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "software") {
		t.Error("listBackends output should contain 'software'")
	}
	if !strings.Contains(output, "tpm2") {
		t.Error("listBackends output should contain 'tpm2'")
	}
	if !strings.Contains(output, "pkcs11") {
		t.Error("listBackends output should contain 'pkcs11'")
	}
}

func TestListBackends_ClientCreateError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("client create failed")
		},
	}

	// Should not panic
	listBackends(cfg, printer)
}

func TestListBackends_ConnectError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockBackendsClient{
		connectErr: errors.New("connect failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Should not panic
	listBackends(cfg, printer)
}

func TestListBackends_ListBackendsError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockBackendsClient{
		listBackendsErr: errors.New("list backends failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Should not panic
	listBackends(cfg, printer)
}

func TestListBackends_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockBackendsClient{
				listBackendsResp: &client.ListBackendsResponse{
					Backends: []client.BackendInfo{
						{ID: "software", Type: "software"},
					},
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			listBackends(cfg, printer)

			if buf.Len() == 0 {
				t.Errorf("listBackends with %s format should produce output", format)
			}
		})
	}
}

func TestBackendInfo_Success(t *testing.T) {
	mockClient := &mockBackendsClient{
		getBackendResp: &client.BackendInfo{
			ID:             "software",
			Type:           "software",
			HardwareBacked: false,
			Capabilities: transport.BackendCapabilities{
				Keys:        true,
				Signing:     true,
				Decryption:  true,
				KeyRotation: true,
			},
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	backendInfo(cfg, printer, "software")

	output := buf.String()
	if !strings.Contains(output, "software") {
		t.Error("backendInfo output should contain 'software'")
	}
}

func TestBackendInfo_ClientCreateError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("client create failed")
		},
	}

	// Should not panic
	backendInfo(cfg, printer, "software")
}

func TestBackendInfo_ConnectError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockBackendsClient{
		connectErr: errors.New("connect failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Should not panic
	backendInfo(cfg, printer, "software")
}

func TestBackendInfo_GetBackendError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockBackendsClient{
		getBackendErr: errors.New("get backend failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Should not panic
	backendInfo(cfg, printer, "unknown")
}

func TestBackendInfo_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockBackendsClient{
				getBackendResp: &client.BackendInfo{
					ID:             "software",
					Type:           "software",
					HardwareBacked: false,
					Capabilities: transport.BackendCapabilities{
						Keys:    true,
						Signing: true,
					},
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			backendInfo(cfg, printer, "software")

			if buf.Len() == 0 {
				t.Errorf("backendInfo with %s format should produce output", format)
			}
		})
	}
}

// Ensure types.Capabilities is properly accessible
func TestTypesCapabilities_Fields(t *testing.T) {
	caps := types.Capabilities{
		Keys:                true,
		HardwareBacked:      true,
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: true,
		Import:              true,
		Export:              true,
		KeyAgreement:        true,
		ECIES:               true,
	}

	if !caps.Keys {
		t.Error("caps.Keys should be true")
	}
	if !caps.HardwareBacked {
		t.Error("caps.HardwareBacked should be true")
	}
}

// Barrier operations stub implementations
func (m *mockBackendsClient) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	return nil
}

func (m *mockBackendsClient) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	return nil
}

func (m *mockBackendsClient) BarrierSeal(ctx context.Context) error {
	return nil
}

func (m *mockBackendsClient) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	return nil
}

// BarrierShamirListShares returns Shamir share metadata.
func (m *mockBackendsClient) BarrierShamirListShares(_ context.Context) (*transport.BarrierShamirSharesResponse, error) {
	return nil, nil
}

// BarrierShamirDeleteShare deletes a Shamir share by index.
func (m *mockBackendsClient) BarrierShamirDeleteShare(_ context.Context, _ *transport.BarrierShamirDeleteShareRequest) error {
	return nil
}

// BarrierShamirDeleteAllShares deletes all Shamir shares.
func (m *mockBackendsClient) BarrierShamirDeleteAllShares(_ context.Context) error {
	return nil
}

// BarrierShamirVerify verifies Shamir share integrity.
func (m *mockBackendsClient) BarrierShamirVerify(_ context.Context) error {
	return nil
}

// BarrierRekey re-encrypts the barrier with a new root key.
func (m *mockBackendsClient) BarrierRekey(_ context.Context, _ *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	return nil, nil
}

// BarrierGenerateRecoveryKeys generates recovery keys.
func (m *mockBackendsClient) BarrierGenerateRecoveryKeys(_ context.Context, _ *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	return nil, nil
}

// BarrierRecoverWithKeys recovers the barrier using recovery keys.
func (m *mockBackendsClient) BarrierRecoverWithKeys(_ context.Context, _ *transport.BarrierRecoverWithKeysRequest) error {
	return nil
}

// BarrierDeleteRecoveryKeys deletes all recovery keys.
func (m *mockBackendsClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return nil
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (m *mockBackendsClient) BarrierHasRecoveryKeys(_ context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	return nil, nil
}

// BarrierGenerateRootToken generates a root token.
func (m *mockBackendsClient) BarrierGenerateRootToken(_ context.Context, _ *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	return nil, nil
}

// PIN operations stub implementations
func (m *mockBackendsClient) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	return nil
}

func (m *mockBackendsClient) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	return nil
}

func (m *mockBackendsClient) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	return nil
}

func (m *mockBackendsClient) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	return nil
}

func (m *mockBackendsClient) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	return nil
}

func (m *mockBackendsClient) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	return nil
}

func (m *mockBackendsClient) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	return nil
}

// PasswordService stub implementations
func (m *mockBackendsClient) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	return nil
}

func (m *mockBackendsClient) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	return nil
}

func (m *mockBackendsClient) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	return nil
}

func (m *mockBackendsClient) PasswordStoreLock(ctx context.Context) error {
	return nil
}

func (m *mockBackendsClient) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	return nil
}

func (m *mockBackendsClient) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, nil
}

// SealStoreService stub implementations
func (m *mockBackendsClient) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	return nil
}

func (m *mockBackendsClient) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	return nil
}

func (m *mockBackendsClient) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	return nil
}

func (m *mockBackendsClient) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, nil
}

// PolicyService stub implementations
func (m *mockBackendsClient) PolicyCreate(ctx context.Context, req *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PolicyGet(ctx context.Context, req *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PolicyList(ctx context.Context) (*transport.PolicyListResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PolicyDelete(ctx context.Context, req *transport.PolicyDeleteRequest) error {
	return nil
}

func (m *mockBackendsClient) PolicyRefresh(ctx context.Context, req *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PolicyVerify(ctx context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PolicyExport(ctx context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	return nil, nil
}

// CustodianGroupService stub implementations
func (m *mockBackendsClient) CreateCustodianGroup(_ context.Context, _ *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetCustodianGroup(_ context.Context, _ string) (*transport.GetCustodianGroupResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ListCustodianGroups(_ context.Context) (*transport.ListCustodianGroupsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeleteCustodianGroup(_ context.Context, _ string) error {
	return nil
}

func (m *mockBackendsClient) AddCustodianMember(_ context.Context, _ *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) RemoveCustodianMember(_ context.Context, _ *transport.RemoveCustodianMemberRequest) error {
	return nil
}

func (m *mockBackendsClient) DistributeShares(_ context.Context, _ *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	return nil, nil
}

// ShareService stub implementations
func (m *mockBackendsClient) SubmitShare(_ context.Context, _ *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ListShares(_ context.Context) (*transport.ListSharesResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetShareCollectionStatus(_ context.Context, _ string) (*transport.ShareCollectionStatus, error) {
	return nil, nil
}

// TenantService stub implementations
func (m *mockBackendsClient) CreateTenant(_ context.Context, _ *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetTenant(_ context.Context, _ string) (*transport.GetTenantResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ListTenants(_ context.Context) (*transport.ListTenantsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeleteTenant(_ context.Context, _ string) error {
	return nil
}

func (m *mockBackendsClient) TenantBarrierInit(_ context.Context, _ *transport.TenantBarrierInitRequest) error {
	return nil
}

func (m *mockBackendsClient) TenantBarrierUnseal(_ context.Context, _ *transport.TenantBarrierUnsealRequest) error {
	return nil
}

// InitCeremonyService stub implementations
func (m *mockBackendsClient) GetInitStatus(_ context.Context) (*transport.InitStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ClaimCertBegin(_ context.Context, _ *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ClaimCertComplete(_ context.Context, _ *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ClaimShare(_ context.Context, _ *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SignCSRInit(_ context.Context, _ *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return nil, nil
}

// CredentialManagementService stub implementations
func (m *mockBackendsClient) SubmitCredential(_ context.Context, _ *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetCredentialStrategy(_ context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, nil
}
