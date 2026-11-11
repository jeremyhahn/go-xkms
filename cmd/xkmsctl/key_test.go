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
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// mockKeyClient is a mock client for testing key operations
type mockKeyClient struct {
	mockBackendsClient
	generateKeyResp     *client.GenerateKeyResponse
	generateKeyReq      *client.GenerateKeyRequest
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
	importKeyReq        *client.ImportKeyRequest
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
	m.generateKeyReq = req
	return m.generateKeyResp, m.generateKeyErr
}

func (m *mockKeyClient) ListKeys(_ context.Context, _ string, _ ...client.ListOption) (*client.ListKeysResponse, error) {
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
	// Recorded, not discarded: the algorithm, size and curve the caller supplies
	// are the whole point of the import contract -- wrapped material is opaque
	// ciphertext and the server cannot infer them -- so a test that cannot see
	// the outgoing request cannot tell a correct import from one that drops them.
	m.importKeyReq = req
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

// TestGenerateKey_SymmetricKeyDefaultAlgorithm verifies a symmetric key
// requested without an explicit --algorithm still sends a non-empty
// Algorithm ("symmetric"): the server now requires the field, so the client
// can no longer rely on an empty value falling back to key_type (owner rule
// 2026-09-22, PR 2).
func TestGenerateKey_SymmetricKeyDefaultAlgorithm(t *testing.T) {
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

	generateKey(cfg, printer, "sym-key", "symmetric", keyGenOptions{Algorithm: "", KeyAlgorithm: "", KeySize: 256, Curve: "", Exportable: false, Sensitive: false})

	if mockClient.generateKeyReq == nil || mockClient.generateKeyReq.Algorithm == "" {
		t.Fatalf("Algorithm must never be empty, got %+v", mockClient.generateKeyReq)
	}
	if mockClient.generateKeyReq.Algorithm != "symmetric" {
		t.Errorf("expected Algorithm %q, got %q", "symmetric", mockClient.generateKeyReq.Algorithm)
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

	generateKey(cfg, printer, "test-key", "tls", keyGenOptions{Algorithm: "", KeyAlgorithm: "rsa", KeySize: 2048, Curve: "", Exportable: false, Sensitive: false})
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

	generateKey(cfg, printer, "test-key", "tls", keyGenOptions{Algorithm: "", KeyAlgorithm: "rsa", KeySize: 2048, Curve: "", Exportable: false, Sensitive: false})
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

	generateKey(cfg, printer, "test-key", "tls", keyGenOptions{Algorithm: "", KeyAlgorithm: "rsa", KeySize: 2048, Curve: "", Exportable: false, Sensitive: false})
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
	verify(cfg, printer, "test-key", "test data", sigBase64, "sha256", 0)
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
	verify(cfg, printer, "test-key", "test data", sigBase64, "sha256", 0)
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
	verify(cfg, printer, "test-key", "test data", sigBase64, "sha256", 0)
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
	verify(cfg, printer, "test-key", "test data", sigBase64, "sha256", 0)
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

	decrypt(cfg, printer, "test-key", "invalid-base64!!!", "", "", "", 0)
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
	decrypt(cfg, printer, "test-key", ciphertextBase64, "", "", "", 0)
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
	decrypt(cfg, printer, "test-key", ciphertextBase64, "", "", "", 0)
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
	decrypt(cfg, printer, "test-key", ciphertextBase64, "", "", "", 0)
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

	importKey(cfg, printer, "test-key", wrapped, importKeySpec{keyType: "rsa", keySize: 2048})
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

	importKey(cfg, printer, "test-key", wrapped, importKeySpec{keyType: "rsa", keySize: 2048})
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

	importKey(cfg, printer, "test-key", wrapped, importKeySpec{keyType: "rsa", keySize: 2048})
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

	copyKey(cfg, printer, "test-key", "test-key-copy", "pkcs11", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
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

	copyKey(cfg, printer, "test-key", "test-key-copy", "pkcs11", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
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

	copyKey(cfg, printer, "test-key", "test-key-copy", "pkcs11", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
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

func TestBuildKeyAttributesFromFlags_RSA_Exportable(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 2048, "", true)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags returned error: %v", err)
	}

	if !attrs.Exportable {
		t.Error("Exportable should be true when specified")
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

// TestBuildKeyAttributesFromFlags_RSA_OversizedKeySize proves the CLI refuses
// an RSA --key-size above the documented 4096-bit ceiling before it ever
// reaches the server: go-xkms#1260 refuses this everywhere, and refusing it
// here too gives the operator a fast, local error instead of waiting on a
// round trip.
func TestBuildKeyAttributesFromFlags_RSA_OversizedKeySize(t *testing.T) {
	_, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 65536, "", false)
	if err == nil {
		t.Error("buildKeyAttributesFromFlags should return error for RSA key size > 4096")
	}
	if !errors.Is(err, ErrRSAKeySizeTooLarge) {
		t.Errorf("buildKeyAttributesFromFlags error = %v, want ErrRSAKeySizeTooLarge", err)
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

			generateKey(cfg, printer, "test-key", "tls", keyGenOptions{Algorithm: "", KeyAlgorithm: "rsa", KeySize: 2048, Curve: "", Exportable: false, Sensitive: false})

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
			verify(cfg, printer, "test-key", "data", sigBase64, "sha256", 0)

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
			decrypt(cfg, printer, "test-key", ciphertextBase64, "", "", "", 0)

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
