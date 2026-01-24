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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	client "github.com/jeremyhahn/go-keychain/sdk/go"
)

// mockKeyClient is a mock client for testing key operations
type mockKeyClient struct {
	mockBackendsClient
	generateKeyResp     *client.GenerateKeyResponse
	generateKeyErr      error
	listKeysResp        *client.ListKeysResponse
	listKeysErr         error
	getKeyResp          *client.GetKeyResponse
	getKeyErr           error
	deleteKeyResp       *client.DeleteKeyResponse
	deleteKeyErr        error
	signResp            *client.SignResponse
	signErr             error
	verifyResp          *client.VerifyResponse
	verifyErr           error
	encryptResp         *client.EncryptResponse
	encryptErr          error
	decryptResp         *client.DecryptResponse
	decryptErr          error
	encryptAsymResp     *client.EncryptAsymResponse
	encryptAsymErr      error
	rotateKeyResp       *client.RotateKeyResponse
	rotateKeyErr        error
	importKeyResp       *client.ImportKeyResponse
	importKeyErr        error
	exportKeyResp       *client.ExportKeyResponse
	exportKeyErr        error
	copyKeyResp         *client.CopyKeyResponse
	copyKeyErr          error
	getImportParamsResp *client.GetImportParametersResponse
	getImportParamsErr  error
	wrapKeyResp         *client.WrapKeyResponse
	wrapKeyErr          error
	unwrapKeyResp       *client.UnwrapKeyResponse
	unwrapKeyErr        error
}

func (m *mockKeyClient) GenerateKey(_ context.Context, req *client.GenerateKeyRequest) (*client.GenerateKeyResponse, error) {
	return m.generateKeyResp, m.generateKeyErr
}

func (m *mockKeyClient) ListKeys(_ context.Context, _ string) (*client.ListKeysResponse, error) {
	return m.listKeysResp, m.listKeysErr
}

func (m *mockKeyClient) GetKey(_ context.Context, _, _ string) (*client.GetKeyResponse, error) {
	return m.getKeyResp, m.getKeyErr
}

func (m *mockKeyClient) DeleteKey(_ context.Context, _, _ string) (*client.DeleteKeyResponse, error) {
	return m.deleteKeyResp, m.deleteKeyErr
}

func (m *mockKeyClient) Sign(_ context.Context, req *client.SignRequest) (*client.SignResponse, error) {
	return m.signResp, m.signErr
}

func (m *mockKeyClient) Verify(_ context.Context, req *client.VerifyRequest) (*client.VerifyResponse, error) {
	return m.verifyResp, m.verifyErr
}

func (m *mockKeyClient) Encrypt(_ context.Context, req *client.EncryptRequest) (*client.EncryptResponse, error) {
	return m.encryptResp, m.encryptErr
}

func (m *mockKeyClient) Decrypt(_ context.Context, req *client.DecryptRequest) (*client.DecryptResponse, error) {
	return m.decryptResp, m.decryptErr
}

func (m *mockKeyClient) EncryptAsym(_ context.Context, req *client.EncryptAsymRequest) (*client.EncryptAsymResponse, error) {
	return m.encryptAsymResp, m.encryptAsymErr
}

func (m *mockKeyClient) RotateKey(_ context.Context, req *client.RotateKeyRequest) (*client.RotateKeyResponse, error) {
	return m.rotateKeyResp, m.rotateKeyErr
}

func (m *mockKeyClient) ImportKey(_ context.Context, req *client.ImportKeyRequest) (*client.ImportKeyResponse, error) {
	return m.importKeyResp, m.importKeyErr
}

func (m *mockKeyClient) ExportKey(_ context.Context, req *client.ExportKeyRequest) (*client.ExportKeyResponse, error) {
	return m.exportKeyResp, m.exportKeyErr
}

func (m *mockKeyClient) CopyKey(_ context.Context, req *client.CopyKeyRequest) (*client.CopyKeyResponse, error) {
	return m.copyKeyResp, m.copyKeyErr
}

func (m *mockKeyClient) GetImportParameters(_ context.Context, req *client.GetImportParametersRequest) (*client.GetImportParametersResponse, error) {
	return m.getImportParamsResp, m.getImportParamsErr
}

func (m *mockKeyClient) WrapKey(_ context.Context, req *client.WrapKeyRequest) (*client.WrapKeyResponse, error) {
	return m.wrapKeyResp, m.wrapKeyErr
}

func (m *mockKeyClient) UnwrapKey(_ context.Context, req *client.UnwrapKeyRequest) (*client.UnwrapKeyResponse, error) {
	return m.unwrapKeyResp, m.unwrapKeyErr
}

func TestKeyCmd_Exists(t *testing.T) {
	if keyCmd == nil {
		t.Fatal("keyCmd should not be nil")
	}
}

func TestKeyCmd_Properties(t *testing.T) {
	if keyCmd.Use != "key" {
		t.Errorf("keyCmd.Use = %v, want key", keyCmd.Use)
	}

	if keyCmd.Short == "" {
		t.Error("keyCmd.Short should not be empty")
	}
}

func TestKeyCmd_HasSubcommands(t *testing.T) {
	subcommands := keyCmd.Commands()

	expectedCmds := []string{
		"generate",
		"list",
		"get",
		"delete",
		"sign",
		"rotate",
		"encrypt",
		"decrypt",
		"import",
		"export",
		"copy",
		"verify",
		"encrypt-asym",
		"get-import-params",
		"wrap",
		"unwrap",
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

func TestKeyGenerateCmd_Exists(t *testing.T) {
	if keyGenerateCmd == nil {
		t.Fatal("keyGenerateCmd should not be nil")
	}
}

func TestKeyGenerateCmd_Properties(t *testing.T) {
	if keyGenerateCmd.Use != "generate <key-id>" {
		t.Errorf("keyGenerateCmd.Use = %v, want 'generate <key-id>'", keyGenerateCmd.Use)
	}
}

func TestKeyListCmd_Exists(t *testing.T) {
	if keyListCmd == nil {
		t.Fatal("keyListCmd should not be nil")
	}
}

func TestKeyGetCmd_Exists(t *testing.T) {
	if keyGetCmd == nil {
		t.Fatal("keyGetCmd should not be nil")
	}
}

func TestKeyDeleteCmd_Exists(t *testing.T) {
	if keyDeleteCmd == nil {
		t.Fatal("keyDeleteCmd should not be nil")
	}
}

func TestKeySignCmd_Exists(t *testing.T) {
	if keySignCmd == nil {
		t.Fatal("keySignCmd should not be nil")
	}
}

func TestKeyRotateCmd_Exists(t *testing.T) {
	if keyRotateCmd == nil {
		t.Fatal("keyRotateCmd should not be nil")
	}
}

func TestKeyEncryptCmd_Exists(t *testing.T) {
	if keyEncryptCmd == nil {
		t.Fatal("keyEncryptCmd should not be nil")
	}
}

func TestKeyDecryptCmd_Exists(t *testing.T) {
	if keyDecryptCmd == nil {
		t.Fatal("keyDecryptCmd should not be nil")
	}
}

func TestKeyImportCmd_Exists(t *testing.T) {
	if keyImportCmd == nil {
		t.Fatal("keyImportCmd should not be nil")
	}
}

func TestKeyExportCmd_Exists(t *testing.T) {
	if keyExportCmd == nil {
		t.Fatal("keyExportCmd should not be nil")
	}
}

func TestKeyCopyCmd_Exists(t *testing.T) {
	if keyCopyCmd == nil {
		t.Fatal("keyCopyCmd should not be nil")
	}
}

func TestKeyVerifyCmd_Exists(t *testing.T) {
	if keyVerifyCmd == nil {
		t.Fatal("keyVerifyCmd should not be nil")
	}
}

func TestKeyEncryptAsymCmd_Exists(t *testing.T) {
	if keyEncryptAsymCmd == nil {
		t.Fatal("keyEncryptAsymCmd should not be nil")
	}
}

func TestKeyGetImportParamsCmd_Exists(t *testing.T) {
	if keyGetImportParamsCmd == nil {
		t.Fatal("keyGetImportParamsCmd should not be nil")
	}
}

func TestKeyWrapCmd_Exists(t *testing.T) {
	if keyWrapCmd == nil {
		t.Fatal("keyWrapCmd should not be nil")
	}
}

func TestKeyUnwrapCmd_Exists(t *testing.T) {
	if keyUnwrapCmd == nil {
		t.Fatal("keyUnwrapCmd should not be nil")
	}
}

// Test generateKey function
func TestGenerateKey_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		generateKeyResp: &client.GenerateKeyResponse{
			KeyID:   "test-key",
			KeyType: "rsa",
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	generateKey(cfg, printer, "test-key", "tls", "", "rsa", 2048, "", false)

	output := buf.String()
	if !strings.Contains(output, "Successfully generated") {
		t.Errorf("generateKey output should contain success message, got: %s", output)
	}
}

func TestGenerateKey_SymmetricKey(t *testing.T) {
	mockClient := &mockKeyClient{
		generateKeyResp: &client.GenerateKeyResponse{
			KeyID:   "sym-key",
			KeyType: "symmetric",
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	generateKey(cfg, printer, "sym-key", "symmetric", "aes-256-gcm", "", 256, "", false)

	output := buf.String()
	if !strings.Contains(output, "Successfully generated") {
		t.Errorf("generateKey output should contain success message, got: %s", output)
	}
}

func TestGenerateKey_ClientCreateError(t *testing.T) {
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

	generateKey(cfg, printer, "test-key", "tls", "", "rsa", 2048, "", false)
}

func TestGenerateKey_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	generateKey(cfg, printer, "test-key", "tls", "", "rsa", 2048, "", false)
}

func TestGenerateKey_GenerateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		generateKeyErr: errors.New("generate failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	generateKey(cfg, printer, "test-key", "tls", "", "rsa", 2048, "", false)
}

// Test listKeys function
func TestListKeys_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		listKeysResp: &client.ListKeysResponse{
			Keys: []client.KeyInfo{
				{KeyID: "key1", KeyType: "tls"},
				{KeyID: "key2", KeyType: "signing"},
			},
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	listKeys(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "key1") {
		t.Errorf("listKeys output should contain 'key1', got: %s", output)
	}
}

func TestListKeys_ClientCreateError(t *testing.T) {
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

	listKeys(cfg, printer)
}

func TestListKeys_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	listKeys(cfg, printer)
}

func TestListKeys_ListError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		listKeysErr: errors.New("list failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	listKeys(cfg, printer)
}

func TestListKeys_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockKeyClient{
				listKeysResp: &client.ListKeysResponse{
					Keys: []client.KeyInfo{
						{KeyID: "key1", KeyType: "tls"},
					},
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				Backend: "software",
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			listKeys(cfg, printer)

			if buf.Len() == 0 {
				t.Errorf("listKeys with %s format should produce output", format)
			}
		})
	}
}

// Test getKey function
func TestGetKey_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		getKeyResp: &client.GetKeyResponse{
			KeyInfo: client.KeyInfo{
				KeyID:   "test-key",
				KeyType: "tls",
			},
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	getKey(cfg, printer, "test-key")

	output := buf.String()
	if !strings.Contains(output, "test-key") {
		t.Errorf("getKey output should contain 'test-key', got: %s", output)
	}
}

func TestGetKey_ClientCreateError(t *testing.T) {
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

	getKey(cfg, printer, "test-key")
}

func TestGetKey_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	getKey(cfg, printer, "test-key")
}

func TestGetKey_GetError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		getKeyErr: errors.New("get failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	getKey(cfg, printer, "test-key")
}

func TestGetKey_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockKeyClient{
				getKeyResp: &client.GetKeyResponse{
					KeyInfo: client.KeyInfo{
						KeyID:   "test-key",
						KeyType: "tls",
					},
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				Backend: "software",
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			getKey(cfg, printer, "test-key")

			if buf.Len() == 0 {
				t.Errorf("getKey with %s format should produce output", format)
			}
		})
	}
}

// Test deleteKey function
func TestDeleteKey_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		deleteKeyResp: &client.DeleteKeyResponse{
			Success: true,
			Message: "Key deleted",
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	deleteKey(cfg, printer, "test-key")

	output := buf.String()
	if !strings.Contains(output, "Successfully deleted") {
		t.Errorf("deleteKey output should contain success message, got: %s", output)
	}
}

func TestDeleteKey_SuccessFalse(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		deleteKeyResp: &client.DeleteKeyResponse{
			Success: false,
			Message: "Key not found",
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	deleteKey(cfg, printer, "test-key")
}

func TestDeleteKey_ClientCreateError(t *testing.T) {
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

	deleteKey(cfg, printer, "test-key")
}

func TestDeleteKey_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	deleteKey(cfg, printer, "test-key")
}

func TestDeleteKey_DeleteError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		deleteKeyErr: errors.New("delete failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	deleteKey(cfg, printer, "test-key")
}

// Test sign function
func TestSign_Success(t *testing.T) {
	signature := []byte("test-signature")
	mockClient := &mockKeyClient{
		signResp: &client.SignResponse{
			Signature: signature,
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	sign(cfg, printer, "test-key", "test data", "sha256")

	output := buf.String()
	expectedSig := base64.StdEncoding.EncodeToString(signature)
	if !strings.Contains(output, expectedSig) {
		t.Errorf("sign output should contain base64 signature, got: %s", output)
	}
}

func TestSign_ClientCreateError(t *testing.T) {
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

	sign(cfg, printer, "test-key", "test data", "sha256")
}

func TestSign_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	sign(cfg, printer, "test-key", "test data", "sha256")
}

func TestSign_SignError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		signErr: errors.New("sign failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	sign(cfg, printer, "test-key", "test data", "sha256")
}

// Test verify function
func TestVerify_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		verifyResp: &client.VerifyResponse{
			Valid:   true,
			Message: "Signature valid",
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	sigBase64 := base64.StdEncoding.EncodeToString([]byte("test-signature"))
	verify(cfg, printer, "test-key", "test data", sigBase64, "sha256")

	output := buf.String()
	if !strings.Contains(output, "valid") {
		t.Errorf("verify output should contain valid message, got: %s", output)
	}
}

func TestVerify_Invalid(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		verifyResp: &client.VerifyResponse{
			Valid:   false,
			Message: "Signature invalid",
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	sigBase64 := base64.StdEncoding.EncodeToString([]byte("bad-signature"))
	verify(cfg, printer, "test-key", "test data", sigBase64, "sha256")
}

func TestVerify_DecodeError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	verify(cfg, printer, "test-key", "test data", "invalid-base64!!!", "sha256")
}

func TestVerify_ClientCreateError(t *testing.T) {
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

	sigBase64 := base64.StdEncoding.EncodeToString([]byte("test-signature"))
	verify(cfg, printer, "test-key", "test data", sigBase64, "sha256")
}

func TestVerify_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	sigBase64 := base64.StdEncoding.EncodeToString([]byte("test-signature"))
	verify(cfg, printer, "test-key", "test data", sigBase64, "sha256")
}

func TestVerify_VerifyError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		verifyErr: errors.New("verify failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	sigBase64 := base64.StdEncoding.EncodeToString([]byte("test-signature"))
	verify(cfg, printer, "test-key", "test data", sigBase64, "sha256")
}

// Test encrypt function
func TestEncrypt_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		encryptResp: &client.EncryptResponse{
			Ciphertext: []byte("encrypted-data"),
			Nonce:      []byte("nonce-data"),
			Tag:        []byte("tag-data"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	encrypt(cfg, printer, "test-key", "plaintext", "")

	output := buf.String()
	if buf.Len() == 0 {
		t.Error("encrypt should produce output")
	}
	// JSON output should contain ciphertext
	if !strings.Contains(output, "ciphertext") && !strings.Contains(output, "Ciphertext") {
		t.Errorf("encrypt output should contain ciphertext, got: %s", output)
	}
}

func TestEncrypt_WithAAD(t *testing.T) {
	mockClient := &mockKeyClient{
		encryptResp: &client.EncryptResponse{
			Ciphertext: []byte("encrypted-data"),
			Nonce:      []byte("nonce-data"),
			Tag:        []byte("tag-data"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	encrypt(cfg, printer, "test-key", "plaintext", "additional-data")

	if buf.Len() == 0 {
		t.Error("encrypt with AAD should produce output")
	}
}

func TestEncrypt_ClientCreateError(t *testing.T) {
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

	encrypt(cfg, printer, "test-key", "plaintext", "")
}

func TestEncrypt_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	encrypt(cfg, printer, "test-key", "plaintext", "")
}

func TestEncrypt_EncryptError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		encryptErr: errors.New("encrypt failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	encrypt(cfg, printer, "test-key", "plaintext", "")
}

// Test decrypt function
func TestDecrypt_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		decryptResp: &client.DecryptResponse{
			Plaintext: []byte("decrypted-data"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	ciphertextBase64 := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	decrypt(cfg, printer, "test-key", ciphertextBase64, "", "", "")

	if buf.Len() == 0 {
		t.Error("decrypt should produce output")
	}
}

func TestDecrypt_WithAADNonceTag(t *testing.T) {
	mockClient := &mockKeyClient{
		decryptResp: &client.DecryptResponse{
			Plaintext: []byte("decrypted-data"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	ciphertextBase64 := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	nonceBase64 := base64.StdEncoding.EncodeToString([]byte("nonce"))
	tagBase64 := base64.StdEncoding.EncodeToString([]byte("tag"))
	decrypt(cfg, printer, "test-key", ciphertextBase64, "aad", nonceBase64, tagBase64)

	if buf.Len() == 0 {
		t.Error("decrypt with AAD/nonce/tag should produce output")
	}
}

func TestDecrypt_CiphertextDecodeError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	decrypt(cfg, printer, "test-key", "invalid-base64!!!", "", "", "")
}

func TestDecrypt_NonceDecodeError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	ciphertextBase64 := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	decrypt(cfg, printer, "test-key", ciphertextBase64, "", "invalid-base64!!!", "")
}

func TestDecrypt_TagDecodeError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	ciphertextBase64 := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	nonceBase64 := base64.StdEncoding.EncodeToString([]byte("nonce"))
	decrypt(cfg, printer, "test-key", ciphertextBase64, "", nonceBase64, "invalid-base64!!!")
}

func TestDecrypt_ClientCreateError(t *testing.T) {
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

	ciphertextBase64 := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	decrypt(cfg, printer, "test-key", ciphertextBase64, "", "", "")
}

func TestDecrypt_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	ciphertextBase64 := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	decrypt(cfg, printer, "test-key", ciphertextBase64, "", "", "")
}

func TestDecrypt_DecryptError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		decryptErr: errors.New("decrypt failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	ciphertextBase64 := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	decrypt(cfg, printer, "test-key", ciphertextBase64, "", "", "")
}

// Test encryptAsym function
func TestEncryptAsym_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		encryptAsymResp: &client.EncryptAsymResponse{
			Ciphertext: []byte("encrypted-data"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	encryptAsym(cfg, printer, "test-key", "plaintext", "sha256")

	if buf.Len() == 0 {
		t.Error("encryptAsym should produce output")
	}
}

func TestEncryptAsym_ClientCreateError(t *testing.T) {
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

	encryptAsym(cfg, printer, "test-key", "plaintext", "sha256")
}

func TestEncryptAsym_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	encryptAsym(cfg, printer, "test-key", "plaintext", "sha256")
}

func TestEncryptAsym_EncryptError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		encryptAsymErr: errors.New("encrypt asym failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	encryptAsym(cfg, printer, "test-key", "plaintext", "sha256")
}

// Test rotateKey function
func TestRotateKey_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		rotateKeyResp: &client.RotateKeyResponse{
			KeyID:   "test-key",
			Success: true,
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	rotateKey(cfg, printer, "test-key")

	output := buf.String()
	if !strings.Contains(output, "Successfully rotated") {
		t.Errorf("rotateKey output should contain success message, got: %s", output)
	}
}

func TestRotateKey_ClientCreateError(t *testing.T) {
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

	rotateKey(cfg, printer, "test-key")
}

func TestRotateKey_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	rotateKey(cfg, printer, "test-key")
}

func TestRotateKey_RotateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		rotateKeyErr: errors.New("rotate failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	rotateKey(cfg, printer, "test-key")
}

// Test importKey function
func TestImportKey_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		importKeyResp: &client.ImportKeyResponse{
			KeyID:   "test-key",
			Success: true,
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	importKey(cfg, printer, "test-key", wrapped)

	output := buf.String()
	if !strings.Contains(output, "Successfully imported") {
		t.Errorf("importKey output should contain success message, got: %s", output)
	}
}

func TestImportKey_ClientCreateError(t *testing.T) {
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

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	importKey(cfg, printer, "test-key", wrapped)
}

func TestImportKey_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	importKey(cfg, printer, "test-key", wrapped)
}

func TestImportKey_ImportError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		importKeyErr: errors.New("import failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	importKey(cfg, printer, "test-key", wrapped)
}

// Test exportKey function
func TestExportKey_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		exportKeyResp: &client.ExportKeyResponse{
			WrappedKeyMaterial: []byte("wrapped-key-data"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Create temp file for output
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "exported-key.json")

	exportKey(cfg, printer, "test-key", outputFile, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("export key should create output file")
	}

	output := buf.String()
	if !strings.Contains(output, "Successfully exported") {
		t.Errorf("exportKey output should contain success message, got: %s", output)
	}
}

func TestExportKey_ClientCreateError(t *testing.T) {
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

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "exported-key.json")

	exportKey(cfg, printer, "test-key", outputFile, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
}

func TestExportKey_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "exported-key.json")

	exportKey(cfg, printer, "test-key", outputFile, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
}

func TestExportKey_ExportError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		exportKeyErr: errors.New("export failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "exported-key.json")

	exportKey(cfg, printer, "test-key", outputFile, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
}

func TestExportKey_WriteFileError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		exportKeyResp: &client.ExportKeyResponse{
			WrappedKeyMaterial: []byte("wrapped-key-data"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Use invalid path
	exportKey(cfg, printer, "test-key", "/nonexistent/path/file.json", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
}

// Test copyKey function
func TestCopyKey_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		copyKeyResp: &client.CopyKeyResponse{
			KeyID:   "test-key-copy",
			Success: true,
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	copyKey(cfg, printer, "test-key", "test-key-copy", "pkcs11", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	output := buf.String()
	if !strings.Contains(output, "Successfully copied") {
		t.Errorf("copyKey output should contain success message, got: %s", output)
	}
}

func TestCopyKey_WithKeyAlgorithm(t *testing.T) {
	mockClient := &mockKeyClient{
		copyKeyResp: &client.CopyKeyResponse{
			KeyID:   "test-key-copy",
			Success: true,
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Test with key algorithm (should take precedence)
	copyKey(cfg, printer, "test-key", "test-key-copy", "pkcs11", "", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	output := buf.String()
	if !strings.Contains(output, "Successfully copied") {
		t.Errorf("copyKey output should contain success message, got: %s", output)
	}
}

func TestCopyKey_ClientCreateError(t *testing.T) {
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

	copyKey(cfg, printer, "test-key", "test-key-copy", "pkcs11", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
}

func TestCopyKey_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	copyKey(cfg, printer, "test-key", "test-key-copy", "pkcs11", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
}

func TestCopyKey_CopyError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		copyKeyErr: errors.New("copy failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	copyKey(cfg, printer, "test-key", "test-key-copy", "pkcs11", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
}

// Test getImportParams function
func TestGetImportParams_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		getImportParamsResp: &client.GetImportParametersResponse{
			WrappingPublicKey: []byte("public-key-data"),
			ExpiresAt:         "2025-12-31T23:59:59Z",
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	getImportParams(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")

	if buf.Len() == 0 {
		t.Error("getImportParams should produce output")
	}
}

func TestGetImportParams_WithOutputFile(t *testing.T) {
	mockClient := &mockKeyClient{
		getImportParamsResp: &client.GetImportParametersResponse{
			WrappingPublicKey: []byte("public-key-data"),
			ExpiresAt:         "2025-12-31T23:59:59Z",
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "import-params.json")

	getImportParams(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, outputFile)

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("getImportParams should create output file")
	}

	output := buf.String()
	if !strings.Contains(output, "Import parameters saved") {
		t.Errorf("getImportParams with file output should contain saved message, got: %s", output)
	}
}

func TestGetImportParams_WithKeyAlgorithm(t *testing.T) {
	mockClient := &mockKeyClient{
		getImportParamsResp: &client.GetImportParametersResponse{
			WrappingPublicKey: []byte("public-key-data"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Test with key algorithm (should take precedence)
	getImportParams(cfg, printer, "test-key", "", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")

	if buf.Len() == 0 {
		t.Error("getImportParams should produce output")
	}
}

func TestGetImportParams_ClientCreateError(t *testing.T) {
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

	getImportParams(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
}

func TestGetImportParams_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	getImportParams(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
}

func TestGetImportParams_GetError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		getImportParamsErr: errors.New("get params failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	getImportParams(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
}

func TestGetImportParams_WriteFileError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		getImportParamsResp: &client.GetImportParametersResponse{
			WrappingPublicKey: []byte("public-key-data"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Use invalid path
	getImportParams(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "/nonexistent/path/file.json")
}

// Test wrapKey function
func TestWrapKey_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		wrapKeyResp: &client.WrapKeyResponse{
			WrappedKeyMaterial: []byte("wrapped-key"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "wrapped-key.json")

	params := &backend.ImportParameters{
		WrappingPublicKey: []byte("public-key"),
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	wrapKey(cfg, printer, []byte("key-material"), params, outputFile)

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("wrapKey should create output file")
	}

	output := buf.String()
	if !strings.Contains(output, "Successfully wrapped") {
		t.Errorf("wrapKey output should contain success message, got: %s", output)
	}
}

func TestWrapKey_InvalidPubKeyType(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "wrapped-key.json")

	params := &backend.ImportParameters{
		WrappingPublicKey: "not-bytes", // Invalid type
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	wrapKey(cfg, printer, []byte("key-material"), params, outputFile)
}

func TestWrapKey_ClientCreateError(t *testing.T) {
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

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "wrapped-key.json")

	params := &backend.ImportParameters{
		WrappingPublicKey: []byte("public-key"),
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	wrapKey(cfg, printer, []byte("key-material"), params, outputFile)
}

func TestWrapKey_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "wrapped-key.json")

	params := &backend.ImportParameters{
		WrappingPublicKey: []byte("public-key"),
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	wrapKey(cfg, printer, []byte("key-material"), params, outputFile)
}

func TestWrapKey_WrapError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		wrapKeyErr: errors.New("wrap failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "wrapped-key.json")

	params := &backend.ImportParameters{
		WrappingPublicKey: []byte("public-key"),
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	wrapKey(cfg, printer, []byte("key-material"), params, outputFile)
}

func TestWrapKey_WriteFileError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		wrapKeyResp: &client.WrapKeyResponse{
			WrappedKeyMaterial: []byte("wrapped-key"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: []byte("public-key"),
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	// Use invalid path
	wrapKey(cfg, printer, []byte("key-material"), params, "/nonexistent/path/file.json")
}

// Test unwrapKey function
func TestUnwrapKey_Success(t *testing.T) {
	mockClient := &mockKeyClient{
		unwrapKeyResp: &client.UnwrapKeyResponse{
			KeyMaterial: []byte("unwrapped-key"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "unwrapped-key.bin")

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	unwrapKey(cfg, printer, wrapped, params, outputFile)

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("unwrapKey should create output file")
	}

	output := buf.String()
	if !strings.Contains(output, "Successfully unwrapped") {
		t.Errorf("unwrapKey output should contain success message, got: %s", output)
	}
}

func TestUnwrapKey_ClientCreateError(t *testing.T) {
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

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "unwrapped-key.bin")

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	unwrapKey(cfg, printer, wrapped, params, outputFile)
}

func TestUnwrapKey_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		mockBackendsClient: mockBackendsClient{
			connectErr: errors.New("connect failed"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "unwrapped-key.bin")

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	unwrapKey(cfg, printer, wrapped, params, outputFile)
}

func TestUnwrapKey_UnwrapError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		unwrapKeyErr: errors.New("unwrap failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "unwrapped-key.bin")

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	unwrapKey(cfg, printer, wrapped, params, outputFile)
}

func TestUnwrapKey_WriteFileError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockKeyClient{
		unwrapKeyResp: &client.UnwrapKeyResponse{
			KeyMaterial: []byte("unwrapped-key"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "software",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	// Use invalid path
	unwrapKey(cfg, printer, wrapped, params, "/nonexistent/path/file.bin")
}

// Test buildKeyAttributesFromFlags helper
func TestBuildKeyAttributesFromFlags_RSA(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 2048, "", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.CN != "test-key" {
		t.Errorf("CN = %v, want test-key", attrs.CN)
	}
	if attrs.KeyAlgorithm != x509.RSA {
		t.Errorf("KeyAlgorithm = %v, want RSA", attrs.KeyAlgorithm)
	}
	if attrs.RSAAttributes == nil {
		t.Error("RSAAttributes should not be nil for RSA key")
	}
	if attrs.RSAAttributes.KeySize != 2048 {
		t.Errorf("RSAAttributes.KeySize = %v, want 2048", attrs.RSAAttributes.KeySize)
	}
	if attrs.Exportable {
		t.Error("Exportable should be false when not specified")
	}
}

func TestBuildKeyAttributesFromFlags_RSA_Exportable(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 2048, "", true)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if !attrs.Exportable {
		t.Error("Exportable should be true when specified")
	}
}

func TestBuildKeyAttributesFromFlags_ECDSA(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "signing", "ecdsa", 0, "P-256", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.KeyAlgorithm != x509.ECDSA {
		t.Errorf("KeyAlgorithm = %v, want ECDSA", attrs.KeyAlgorithm)
	}
	if attrs.ECCAttributes == nil {
		t.Error("ECCAttributes should not be nil for ECDSA key")
	}
	if attrs.KeyType != types.KeyTypeSigning {
		t.Errorf("KeyType = %v, want KeyTypeSigning", attrs.KeyType)
	}
}

func TestBuildKeyAttributesFromFlags_ECDSA_P384(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "signing", "ecdsa", 0, "P-384", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.ECCAttributes == nil {
		t.Error("ECCAttributes should not be nil for ECDSA key")
	}
}

func TestBuildKeyAttributesFromFlags_ECDSA_P521(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "signing", "ecdsa", 0, "P-521", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.ECCAttributes == nil {
		t.Error("ECCAttributes should not be nil for ECDSA key")
	}
}

func TestBuildKeyAttributesFromFlags_Ed25519(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "signing", "ed25519", 0, "", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.KeyAlgorithm != x509.Ed25519 {
		t.Errorf("KeyAlgorithm = %v, want Ed25519", attrs.KeyAlgorithm)
	}
}

func TestBuildKeyAttributesFromFlags_InvalidKeyType(t *testing.T) {
	_, err := buildKeyAttributesFromFlags("test-key", "invalid-type", "rsa", 2048, "", false)
	if err == nil {
		t.Error("buildKeyAttributesFromFlags should return error for invalid key type")
	}
}

func TestBuildKeyAttributesFromFlags_InvalidAlgorithm(t *testing.T) {
	_, err := buildKeyAttributesFromFlags("test-key", "tls", "invalid-alg", 2048, "", false)
	if err == nil {
		t.Error("buildKeyAttributesFromFlags should return error for invalid algorithm")
	}
}

func TestBuildKeyAttributesFromFlags_RSA_SmallKeySize(t *testing.T) {
	_, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 1024, "", false)
	if err == nil {
		t.Error("buildKeyAttributesFromFlags should return error for RSA key size < 2048")
	}
}

func TestBuildKeyAttributesFromFlags_InvalidCurve(t *testing.T) {
	_, err := buildKeyAttributesFromFlags("test-key", "signing", "ecdsa", 0, "invalid-curve", false)
	if err == nil {
		t.Error("buildKeyAttributesFromFlags should return error for invalid curve")
	}
}

func TestBuildKeyAttributesFromFlags_AllKeyTypes(t *testing.T) {
	keyTypes := []string{"tls", "signing", "encryption", "ca"}

	for _, kt := range keyTypes {
		t.Run(kt, func(t *testing.T) {
			attrs, err := buildKeyAttributesFromFlags("test-key", kt, "rsa", 2048, "", false)
			if err != nil {
				t.Errorf("buildKeyAttributesFromFlags(%s) returned error: %v", kt, err)
			}
			if attrs == nil {
				t.Errorf("buildKeyAttributesFromFlags(%s) returned nil attrs", kt)
			}
		})
	}
}

func TestBuildKeyAttributesFromFlags_RSA_4096(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 4096, "", false)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if attrs.RSAAttributes.KeySize != 4096 {
		t.Errorf("RSAAttributes.KeySize = %v, want 4096", attrs.RSAAttributes.KeySize)
	}
}

// Test buildSymmetricKeyAttributes helper
func TestBuildSymmetricKeyAttributes_AES128(t *testing.T) {
	attrs, err := buildSymmetricKeyAttributes("test-key", "", 128)
	if err != nil {
		t.Fatalf("buildSymmetricKeyAttributes returned error: %v", err)
	}

	if attrs.CN != "test-key" {
		t.Errorf("CN = %v, want test-key", attrs.CN)
	}
	if attrs.KeyType != types.KeyTypeSecret {
		t.Errorf("KeyType = %v, want KeyTypeSecret", attrs.KeyType)
	}
	if attrs.SymmetricAlgorithm != types.SymmetricAES128GCM {
		t.Errorf("SymmetricAlgorithm = %v, want AES-128-GCM", attrs.SymmetricAlgorithm)
	}
}

func TestBuildSymmetricKeyAttributes_AES192(t *testing.T) {
	attrs, err := buildSymmetricKeyAttributes("test-key", "", 192)
	if err != nil {
		t.Fatalf("buildSymmetricKeyAttributes returned error: %v", err)
	}

	if attrs.SymmetricAlgorithm != types.SymmetricAES192GCM {
		t.Errorf("SymmetricAlgorithm = %v, want AES-192-GCM", attrs.SymmetricAlgorithm)
	}
}

func TestBuildSymmetricKeyAttributes_AES256(t *testing.T) {
	attrs, err := buildSymmetricKeyAttributes("test-key", "", 256)
	if err != nil {
		t.Fatalf("buildSymmetricKeyAttributes returned error: %v", err)
	}

	if attrs.SymmetricAlgorithm != types.SymmetricAES256GCM {
		t.Errorf("SymmetricAlgorithm = %v, want AES-256-GCM", attrs.SymmetricAlgorithm)
	}
}

func TestBuildSymmetricKeyAttributes_InvalidKeySize(t *testing.T) {
	_, err := buildSymmetricKeyAttributes("test-key", "", 64)
	if err == nil {
		t.Error("buildSymmetricKeyAttributes should return error for invalid key size")
	}
}

func TestBuildSymmetricKeyAttributes_WithAlgorithm(t *testing.T) {
	attrs, err := buildSymmetricKeyAttributes("test-key", string(types.SymmetricAES256GCM), 0)
	if err != nil {
		t.Fatalf("buildSymmetricKeyAttributes returned error: %v", err)
	}

	if attrs.SymmetricAlgorithm != types.SymmetricAES256GCM {
		t.Errorf("SymmetricAlgorithm = %v, want AES-256-GCM", attrs.SymmetricAlgorithm)
	}
}

func TestBuildSymmetricKeyAttributes_InvalidAlgorithm(t *testing.T) {
	_, err := buildSymmetricKeyAttributes("test-key", "invalid-algorithm", 0)
	if err == nil {
		t.Error("buildSymmetricKeyAttributes should return error for invalid algorithm")
	}
}

// Test isSymmetricAlgorithm helper
func TestIsSymmetricAlgorithm_Valid(t *testing.T) {
	validAlgorithms := []string{
		string(types.SymmetricAES128GCM),
		string(types.SymmetricAES192GCM),
		string(types.SymmetricAES256GCM),
	}

	for _, alg := range validAlgorithms {
		t.Run(alg, func(t *testing.T) {
			if !isSymmetricAlgorithm(alg) {
				t.Errorf("isSymmetricAlgorithm(%s) = false, want true", alg)
			}
		})
	}
}

func TestIsSymmetricAlgorithm_Invalid(t *testing.T) {
	invalidAlgorithms := []string{
		"rsa",
		"ecdsa",
		"ed25519",
		"invalid",
		"",
	}

	for _, alg := range invalidAlgorithms {
		t.Run(alg, func(t *testing.T) {
			if isSymmetricAlgorithm(alg) {
				t.Errorf("isSymmetricAlgorithm(%s) = true, want false", alg)
			}
		})
	}
}

// Test command flags
func TestKeyGenerateCmd_HasFlags(t *testing.T) {
	flags := keyGenerateCmd.Flags()

	expectedFlags := []string{
		"key-type",
		"algorithm",
		"key-algorithm",
		"key-size",
		"curve",
		"exportable",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyGenerateCmd", flag)
		}
	}
}

func TestKeySignCmd_HasFlags(t *testing.T) {
	flags := keySignCmd.Flags()

	expectedFlags := []string{
		"hash",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keySignCmd", flag)
		}
	}
}

func TestKeyVerifyCmd_HasFlags(t *testing.T) {
	flags := keyVerifyCmd.Flags()

	expectedFlags := []string{
		"hash",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyVerifyCmd", flag)
		}
	}
}

func TestKeyEncryptCmd_HasFlags(t *testing.T) {
	flags := keyEncryptCmd.Flags()

	expectedFlags := []string{
		"aad",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyEncryptCmd", flag)
		}
	}
}

func TestKeyDecryptCmd_HasFlags(t *testing.T) {
	flags := keyDecryptCmd.Flags()

	expectedFlags := []string{
		"aad",
		"nonce",
		"tag",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyDecryptCmd", flag)
		}
	}
}

func TestKeyImportCmd_HasFlags(t *testing.T) {
	flags := keyImportCmd.Flags()

	expectedFlags := []string{
		"key-type",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyImportCmd", flag)
		}
	}
}

func TestKeyExportCmd_HasFlags(t *testing.T) {
	flags := keyExportCmd.Flags()

	expectedFlags := []string{
		"algorithm",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyExportCmd", flag)
		}
	}
}

func TestKeyCopyCmd_HasFlags(t *testing.T) {
	flags := keyCopyCmd.Flags()

	expectedFlags := []string{
		"dest-backend",
		"dest-keydir",
		"key-type",
		"key-algorithm",
		"key-size",
		"curve",
		"algorithm",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyCopyCmd", flag)
		}
	}
}

func TestKeyGetImportParamsCmd_HasFlags(t *testing.T) {
	flags := keyGetImportParamsCmd.Flags()

	expectedFlags := []string{
		"key-type",
		"key-algorithm",
		"key-size",
		"curve",
		"algorithm",
		"output",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyGetImportParamsCmd", flag)
		}
	}
}

func TestKeyEncryptAsymCmd_HasFlags(t *testing.T) {
	flags := keyEncryptAsymCmd.Flags()

	expectedFlags := []string{
		"hash",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on keyEncryptAsymCmd", flag)
		}
	}
}

// Test keyImportCmd file reading (integration with keyImportCmd Run function)
func TestKeyImportCmd_FileReadError(t *testing.T) {
	// This tests the Run function of keyImportCmd when file doesn't exist
	// We can't easily test the full Run function without running the command
	// But we can verify the file reading logic path exists
	tmpDir := t.TempDir()
	nonExistentFile := filepath.Join(tmpDir, "nonexistent.json")

	// Try to read the file (simulating what the Run function does)
	_, err := os.ReadFile(filepath.Clean(nonExistentFile))
	if err == nil {
		t.Error("reading non-existent file should return error")
	}
}

func TestKeyImportCmd_FileUnmarshalError(t *testing.T) {
	// Test file with invalid JSON
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(invalidFile, []byte("not valid json"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(invalidFile))
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	var wrapped backend.WrappedKeyMaterial
	err = json.Unmarshal(data, &wrapped)
	if err == nil {
		t.Error("unmarshaling invalid JSON should return error")
	}
}

// Test keyWrapCmd file operations
func TestKeyWrapCmd_FileOperations(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test key material file
	keyMaterialFile := filepath.Join(tmpDir, "key.bin")
	if err := os.WriteFile(keyMaterialFile, []byte("test-key-material"), 0600); err != nil {
		t.Fatalf("failed to create key material file: %v", err)
	}

	// Create test params file
	params := backend.ImportParameters{
		WrappingPublicKey: []byte("public-key"),
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}
	paramsData, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal params: %v", err)
	}
	paramsFile := filepath.Join(tmpDir, "params.json")
	if err := os.WriteFile(paramsFile, paramsData, 0600); err != nil {
		t.Fatalf("failed to create params file: %v", err)
	}

	// Verify files can be read
	keyData, err := os.ReadFile(filepath.Clean(keyMaterialFile))
	if err != nil {
		t.Fatalf("failed to read key material: %v", err)
	}
	if string(keyData) != "test-key-material" {
		t.Errorf("key material = %v, want test-key-material", string(keyData))
	}

	paramsReadData, err := os.ReadFile(filepath.Clean(paramsFile))
	if err != nil {
		t.Fatalf("failed to read params: %v", err)
	}

	var readParams backend.ImportParameters
	if err := json.Unmarshal(paramsReadData, &readParams); err != nil {
		t.Fatalf("failed to unmarshal params: %v", err)
	}
}

// Test keyUnwrapCmd file operations
func TestKeyUnwrapCmd_FileOperations(t *testing.T) {
	tmpDir := t.TempDir()

	// Create wrapped key file
	wrapped := backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}
	wrappedData, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatalf("failed to marshal wrapped key: %v", err)
	}
	wrappedFile := filepath.Join(tmpDir, "wrapped.json")
	if err := os.WriteFile(wrappedFile, wrappedData, 0600); err != nil {
		t.Fatalf("failed to create wrapped key file: %v", err)
	}

	// Verify file can be read and unmarshaled
	readData, err := os.ReadFile(filepath.Clean(wrappedFile))
	if err != nil {
		t.Fatalf("failed to read wrapped key: %v", err)
	}

	var readWrapped backend.WrappedKeyMaterial
	if err := json.Unmarshal(readData, &readWrapped); err != nil {
		t.Fatalf("failed to unmarshal wrapped key: %v", err)
	}

	if string(readWrapped.WrappedKey) != "wrapped-key-data" {
		t.Errorf("wrapped key = %v, want wrapped-key-data", string(readWrapped.WrappedKey))
	}
}

// Test all output formats for key operations
func TestGenerateKey_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockKeyClient{
				generateKeyResp: &client.GenerateKeyResponse{
					KeyID:   "test-key",
					KeyType: "rsa",
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				Backend: "software",
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			generateKey(cfg, printer, "test-key", "tls", "", "rsa", 2048, "", false)

			if buf.Len() == 0 {
				t.Errorf("generateKey with %s format should produce output", format)
			}
		})
	}
}

func TestDeleteKey_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockKeyClient{
				deleteKeyResp: &client.DeleteKeyResponse{
					Success: true,
					Message: "deleted",
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				Backend: "software",
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			deleteKey(cfg, printer, "test-key")

			if buf.Len() == 0 {
				t.Errorf("deleteKey with %s format should produce output", format)
			}
		})
	}
}

func TestSign_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockKeyClient{
				signResp: &client.SignResponse{
					Signature: []byte("signature"),
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				Backend: "software",
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			sign(cfg, printer, "test-key", "data", "sha256")

			if buf.Len() == 0 {
				t.Errorf("sign with %s format should produce output", format)
			}
		})
	}
}

func TestVerify_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockKeyClient{
				verifyResp: &client.VerifyResponse{
					Valid:   true,
					Message: "valid",
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				Backend: "software",
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			sigBase64 := base64.StdEncoding.EncodeToString([]byte("sig"))
			verify(cfg, printer, "test-key", "data", sigBase64, "sha256")

			if buf.Len() == 0 {
				t.Errorf("verify with %s format should produce output", format)
			}
		})
	}
}

func TestEncrypt_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockKeyClient{
				encryptResp: &client.EncryptResponse{
					Ciphertext: []byte("encrypted"),
					Nonce:      []byte("nonce"),
					Tag:        []byte("tag"),
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				Backend: "software",
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			encrypt(cfg, printer, "test-key", "plaintext", "")

			if buf.Len() == 0 {
				t.Errorf("encrypt with %s format should produce output", format)
			}
		})
	}
}

func TestDecrypt_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockKeyClient{
				decryptResp: &client.DecryptResponse{
					Plaintext: []byte("decrypted"),
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				Backend: "software",
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			ciphertextBase64 := base64.StdEncoding.EncodeToString([]byte("ct"))
			decrypt(cfg, printer, "test-key", ciphertextBase64, "", "", "")

			if buf.Len() == 0 {
				t.Errorf("decrypt with %s format should produce output", format)
			}
		})
	}
}

func TestRotateKey_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockKeyClient{
				rotateKeyResp: &client.RotateKeyResponse{
					KeyID:   "test-key",
					Success: true,
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				Backend: "software",
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			rotateKey(cfg, printer, "test-key")

			if buf.Len() == 0 {
				t.Errorf("rotateKey with %s format should produce output", format)
			}
		})
	}
}
