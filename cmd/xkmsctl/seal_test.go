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
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// mockSealClient is a mock client for testing seal operations
type mockSealClient struct {
	mockBackendsClient
	sealResp    *client.SealResponse
	sealErr     error
	unsealResp  *client.UnsealResponse
	unsealErr   error
	canSealResp *client.CanSealResponse
	canSealErr  error
	connectErr  error
	closeErr    error
	closeCalled bool
}

func (m *mockSealClient) Connect(ctx context.Context) error {
	return m.connectErr
}

func (m *mockSealClient) Close() error {
	m.closeCalled = true
	return m.closeErr
}

func (m *mockSealClient) Seal(ctx context.Context, req *client.SealRequest) (*client.SealResponse, error) {
	return m.sealResp, m.sealErr
}

func (m *mockSealClient) Unseal(ctx context.Context, req *client.UnsealRequest) (*client.UnsealResponse, error) {
	return m.unsealResp, m.unsealErr
}

func (m *mockSealClient) CanSeal(ctx context.Context, backend string) (*client.CanSealResponse, error) {
	return m.canSealResp, m.canSealErr
}

// TestSealCmd_Exists verifies the seal command exists
func TestSealCmd_Exists(t *testing.T) {
	if sealCmd == nil {
		t.Fatal("sealCmd should not be nil")
	}
}

// TestSealCmd_Properties verifies the seal command properties
func TestSealCmd_Properties(t *testing.T) {
	if sealCmd.Use != "seal <data>" {
		t.Errorf("sealCmd.Use = %v, want 'seal <data>'", sealCmd.Use)
	}

	if sealCmd.Short == "" {
		t.Error("sealCmd.Short should not be empty")
	}
}

// TestUnsealDataCmd_Exists verifies the unseal command exists
func TestUnsealDataCmd_Exists(t *testing.T) {
	if unsealDataCmd == nil {
		t.Fatal("unsealDataCmd should not be nil")
	}
}

// TestUnsealDataCmd_Properties verifies the unseal command properties
func TestUnsealDataCmd_Properties(t *testing.T) {
	if unsealDataCmd.Use != "unseal <ciphertext>" {
		t.Errorf("unsealDataCmd.Use = %v, want 'unseal <ciphertext>'", unsealDataCmd.Use)
	}

	if unsealDataCmd.Short == "" {
		t.Error("unsealDataCmd.Short should not be empty")
	}
}

// TestCanSealCmd_Exists verifies the can-seal command exists
func TestCanSealCmd_Exists(t *testing.T) {
	if canSealCmd == nil {
		t.Fatal("canSealCmd should not be nil")
	}
}

// TestCanSealCmd_Properties verifies the can-seal command properties
func TestCanSealCmd_Properties(t *testing.T) {
	if canSealCmd.Use != "can-seal" {
		t.Errorf("canSealCmd.Use = %v, want 'can-seal'", canSealCmd.Use)
	}

	if canSealCmd.Short == "" {
		t.Error("canSealCmd.Short should not be empty")
	}
}

// TestSealData_Success tests successful sealing
func TestSealData_Success(t *testing.T) {
	mockClient := &mockSealClient{
		sealResp: &client.SealResponse{
			Backend:    "software",
			Ciphertext: []byte("encrypted-data"),
			Nonce:      []byte("test-nonce"),
			Tag:        []byte("test-tag"),
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

	sealData(cfg, printer, "test-key", []byte("test data"), []byte("aad"))

	output := buf.String()
	if !strings.Contains(output, "software") {
		t.Error("sealData output should contain 'software' backend")
	}
	if !strings.Contains(output, "ciphertext") {
		t.Error("sealData output should contain 'ciphertext'")
	}
}

// TestSealData_WithNonceAndTag tests sealing with nonce and tag in output
func TestSealData_WithNonceAndTag(t *testing.T) {
	mockClient := &mockSealClient{
		sealResp: &client.SealResponse{
			Backend:    "tpm2",
			Ciphertext: []byte("encrypted-data"),
			Nonce:      []byte("nonce12345"),
			Tag:        []byte("auth-tag"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "tpm2",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	sealData(cfg, printer, "test-key-id", []byte("plaintext"), nil)

	output := buf.String()
	if !strings.Contains(output, "nonce") {
		t.Error("sealData output should contain 'nonce' when provided")
	}
	if !strings.Contains(output, "tag") {
		t.Error("sealData output should contain 'tag' when provided")
	}
}

// TestSealData_WithKeyID tests sealing with key_id in output
func TestSealData_WithKeyID(t *testing.T) {
	mockClient := &mockSealClient{
		sealResp: &client.SealResponse{
			Backend:    "software",
			Ciphertext: []byte("encrypted"),
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

	sealData(cfg, printer, "my-seal-key", []byte("data"), nil)

	output := buf.String()
	if !strings.Contains(output, "key_id") {
		t.Error("sealData output should contain 'key_id' when provided")
	}
	if !strings.Contains(output, "my-seal-key") {
		t.Error("sealData output should contain the actual key_id value")
	}
}

// TestSealData_ClientCreateError tests seal with client creation error
func TestSealData_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("client creation failed")
		},
	}

	sealData(cfg, printer, "", []byte("data"), nil)
	// Should not panic
}

// TestSealData_ConnectError tests seal with connection error
func TestSealData_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockSealClient{
		connectErr: errors.New("connection failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	sealData(cfg, printer, "", []byte("data"), nil)
	// Should not panic
}

// TestSealData_SealError tests seal with seal operation error
func TestSealData_SealError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockSealClient{
		sealErr: errors.New("seal operation failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	sealData(cfg, printer, "", []byte("data"), nil)
	// Should not panic
}

// TestSealData_AllFormats tests seal output in all formats
func TestSealData_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockSealClient{
				sealResp: &client.SealResponse{
					Backend:    "software",
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

			sealData(cfg, printer, "test-key", []byte("data"), nil)

			if buf.Len() == 0 {
				t.Errorf("sealData with %s format should produce output", format)
			}
		})
	}
}

// TestUnsealData_Success tests successful unsealing
func TestUnsealData_Success(t *testing.T) {
	mockClient := &mockSealClient{
		unsealResp: &client.UnsealResponse{
			Plaintext: []byte("decrypted plaintext"),
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

	ciphertext := []byte("encrypted-data")
	nonce := []byte("nonce")
	tag := []byte("tag")
	aad := []byte("aad")

	unsealData(cfg, printer, "test-key", ciphertext, nonce, tag, aad)

	output := buf.String()
	if !strings.Contains(output, "plaintext") {
		t.Error("unsealData output should contain 'plaintext'")
	}
	if !strings.Contains(output, "decrypted plaintext") {
		t.Error("unsealData output should contain the decrypted text")
	}
}

// TestUnsealData_ClientCreateError tests unseal with client creation error
func TestUnsealData_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("client creation failed")
		},
	}

	unsealData(cfg, printer, "", []byte("ct"), nil, nil, nil)
	// Should not panic
}

// TestUnsealData_ConnectError tests unseal with connection error
func TestUnsealData_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockSealClient{
		connectErr: errors.New("connection failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	unsealData(cfg, printer, "", []byte("ct"), nil, nil, nil)
	// Should not panic
}

// TestUnsealData_UnsealError tests unseal with unseal operation error
func TestUnsealData_UnsealError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockSealClient{
		unsealErr: errors.New("unseal operation failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	unsealData(cfg, printer, "", []byte("ct"), nil, nil, nil)
	// Should not panic
}

// TestUnsealData_AllFormats tests unseal output in all formats
func TestUnsealData_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockSealClient{
				unsealResp: &client.UnsealResponse{
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

			unsealData(cfg, printer, "", []byte("ct"), nil, nil, nil)

			if buf.Len() == 0 {
				t.Errorf("unsealData with %s format should produce output", format)
			}
		})
	}
}

// TestCanSeal_Success tests successful can-seal check
func TestCanSeal_Success(t *testing.T) {
	mockClient := &mockSealClient{
		canSealResp: &client.CanSealResponse{
			CanSeal: true,
			Backend: "software",
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

	canSeal(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "can_seal") {
		t.Error("canSeal output should contain 'can_seal'")
	}
	if !strings.Contains(output, "true") {
		t.Error("canSeal output should contain 'true'")
	}
	if !strings.Contains(output, "software") {
		t.Error("canSeal output should contain 'software' backend")
	}
}

// TestCanSeal_False tests can-seal returning false
func TestCanSeal_False(t *testing.T) {
	mockClient := &mockSealClient{
		canSealResp: &client.CanSealResponse{
			CanSeal: false,
			Backend: "pkcs11",
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "pkcs11",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	canSeal(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "false") {
		t.Error("canSeal output should contain 'false' when sealing not supported")
	}
}

// TestCanSeal_ClientCreateError tests can-seal with client creation error
func TestCanSeal_ClientCreateError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("client creation failed")
		},
	}

	canSeal(cfg, printer)
	// Should not panic
}

// TestCanSeal_ConnectError tests can-seal with connection error
func TestCanSeal_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockSealClient{
		connectErr: errors.New("connection failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	canSeal(cfg, printer)
	// Should not panic
}

// TestCanSeal_CheckError tests can-seal with check operation error
func TestCanSeal_CheckError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockSealClient{
		canSealErr: errors.New("check operation failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	canSeal(cfg, printer)
	// Should not panic
}

// TestCanSeal_AllFormats tests can-seal output in all formats
func TestCanSeal_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockSealClient{
				canSealResp: &client.CanSealResponse{
					CanSeal: true,
					Backend: "software",
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

			canSeal(cfg, printer)

			if buf.Len() == 0 {
				t.Errorf("canSeal with %s format should produce output", format)
			}
		})
	}
}

// TestSealData_EmptyData tests sealing with empty data
func TestSealData_EmptyData(t *testing.T) {
	mockClient := &mockSealClient{
		sealResp: &client.SealResponse{
			Backend:    "software",
			Ciphertext: []byte("encrypted-empty"),
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

	sealData(cfg, printer, "", []byte(""), nil)

	// Should succeed even with empty data
	if buf.Len() == 0 {
		t.Error("sealData should produce output even with empty data")
	}
}

// TestSealData_WithEmptyNonceAndTag tests sealing when nonce and tag are empty
func TestSealData_WithEmptyNonceAndTag(t *testing.T) {
	mockClient := &mockSealClient{
		sealResp: &client.SealResponse{
			Backend:    "software",
			Ciphertext: []byte("encrypted"),
			Nonce:      []byte{}, // empty
			Tag:        []byte{}, // empty
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

	sealData(cfg, printer, "", []byte("data"), nil)

	output := buf.String()
	// Empty nonce/tag should not be included in output
	if strings.Contains(output, "nonce") {
		t.Error("sealData output should not contain 'nonce' when empty")
	}
	if strings.Contains(output, "tag") {
		t.Error("sealData output should not contain 'tag' when empty")
	}
}

// TestSealData_ClientCloseIsCalled tests that client.Close() is called
func TestSealData_ClientCloseIsCalled(t *testing.T) {
	mockClient := &mockSealClient{
		sealResp: &client.SealResponse{
			Backend:    "software",
			Ciphertext: []byte("encrypted"),
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

	sealData(cfg, printer, "", []byte("data"), nil)

	if !mockClient.closeCalled {
		t.Error("sealData should call client.Close()")
	}
}

// TestUnsealData_WithAllParameters tests unseal with all parameters
func TestUnsealData_WithAllParameters(t *testing.T) {
	mockClient := &mockSealClient{
		unsealResp: &client.UnsealResponse{
			Plaintext: []byte("full-decryption"),
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "tpm2",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	unsealData(cfg, printer, "seal-key-123",
		[]byte("ciphertext"),
		[]byte("nonce-value"),
		[]byte("tag-value"),
		[]byte("additional-data"))

	output := buf.String()
	if !strings.Contains(output, "full-decryption") {
		t.Error("unsealData should return the decrypted plaintext")
	}
}

// TestSealData_Base64EncodingInOutput tests that seal output is base64 encoded
func TestSealData_Base64EncodingInOutput(t *testing.T) {
	testCiphertext := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
	testNonce := []byte{0x10, 0x20, 0x30}
	testTag := []byte{0xAA, 0xBB, 0xCC}

	mockClient := &mockSealClient{
		sealResp: &client.SealResponse{
			Backend:    "software",
			Ciphertext: testCiphertext,
			Nonce:      testNonce,
			Tag:        testTag,
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

	sealData(cfg, printer, "key", []byte("data"), nil)

	output := buf.String()

	// Verify base64 encoding
	expectedCiphertext := base64.StdEncoding.EncodeToString(testCiphertext)
	if !strings.Contains(output, expectedCiphertext) {
		t.Errorf("sealData output should contain base64-encoded ciphertext: %s", expectedCiphertext)
	}
}
