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

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	client "github.com/jeremyhahn/go-keychain/sdk/go"
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
		Capabilities: map[string]interface{}{
			"keys":                 true,
			"signing":              true,
			"decryption":           true,
			"key_rotation":         true,
			"symmetric_encryption": true,
			"import":               true,
			"export":               true,
			"key_agreement":        true,
			"ecies":                true,
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
		Capabilities: map[string]interface{}{
			"keys":       true,
			"signing":    true,
			"decryption": true,
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
		Capabilities:   map[string]interface{}{},
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

func TestConvertBackendInfoToCapabilities_NilCapabilities(t *testing.T) {
	info := &client.BackendInfo{
		ID:             "nil",
		Type:           "nil",
		HardwareBacked: true,
		Capabilities:   nil,
	}

	caps := convertBackendInfoToCapabilities(info)

	if caps.Keys {
		t.Error("caps.Keys should be false")
	}
	if !caps.HardwareBacked {
		t.Error("caps.HardwareBacked should be true (from info)")
	}
}

func TestConvertBackendInfoToCapabilities_WrongTypes(t *testing.T) {
	info := &client.BackendInfo{
		ID:             "wrong",
		Type:           "wrong",
		HardwareBacked: false,
		Capabilities: map[string]interface{}{
			"keys":    "yes", // string instead of bool
			"signing": 1,     // int instead of bool
		},
	}

	caps := convertBackendInfoToCapabilities(info)

	// Should default to false because type assertion fails
	if caps.Keys {
		t.Error("caps.Keys should be false (type assertion failed)")
	}
	if caps.Signing {
		t.Error("caps.Signing should be false (type assertion failed)")
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

func (m *mockBackendsClient) ListBackends(ctx context.Context) (*client.ListBackendsResponse, error) {
	return m.listBackendsResp, m.listBackendsErr
}

func (m *mockBackendsClient) GetBackend(ctx context.Context, backendID string) (*client.BackendInfo, error) {
	return m.getBackendResp, m.getBackendErr
}

func (m *mockBackendsClient) GenerateKey(ctx context.Context, req *client.GenerateKeyRequest) (*client.GenerateKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ListKeys(ctx context.Context, backend string) (*client.ListKeysResponse, error) {
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

func (m *mockBackendsClient) ListKeyVersions(ctx context.Context, req *client.ListKeyVersionsRequest) (*client.ListKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) EnableKeyVersion(ctx context.Context, req *client.EnableKeyVersionRequest) (*client.EnableKeyVersionResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DisableKeyVersion(ctx context.Context, req *client.DisableKeyVersionRequest) (*client.DisableKeyVersionResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) EnableAllKeyVersions(ctx context.Context, req *client.EnableAllKeyVersionsRequest) (*client.EnableAllKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DisableAllKeyVersions(ctx context.Context, req *client.DisableAllKeyVersionsRequest) (*client.DisableAllKeyVersionsResponse, error) {
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

func (m *mockBackendsClient) ListCertificates(ctx context.Context, backend string) (*client.ListCertificatesResponse, error) {
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
func (m *mockBackendsClient) ListUsers(ctx context.Context) (*client.ListUsersResponse, error) {
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
			Capabilities: map[string]interface{}{
				"keys":         true,
				"signing":      true,
				"decryption":   true,
				"key_rotation": true,
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
					Capabilities: map[string]interface{}{
						"keys":    true,
						"signing": true,
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
