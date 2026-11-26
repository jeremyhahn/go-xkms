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

	// lastSeal and lastUnseal are the last requests received.
	lastSeal   *client.SealRequest
	lastUnseal *client.UnsealRequest

	// sealPassword and unsealPassword are the passwords as they were when the
	// request arrived. The caller wipes its request once the call returns, so
	// the request itself no longer holds them.
	sealPassword   string
	unsealPassword string
}

func (m *mockSealClient) Connect(ctx context.Context) error {
	return m.connectErr
}

func (m *mockSealClient) Close() error {
	m.closeCalled = true
	return m.closeErr
}

func (m *mockSealClient) Seal(ctx context.Context, req *client.SealRequest) (*client.SealResponse, error) {
	m.lastSeal = req
	m.sealPassword = string(req.Password)
	return m.sealResp, m.sealErr
}

func (m *mockSealClient) Unseal(ctx context.Context, req *client.UnsealRequest) (*client.UnsealResponse, error) {
	m.lastUnseal = req
	m.unsealPassword = string(req.Password)
	return m.unsealResp, m.unsealErr
}

func (m *mockSealClient) CanSeal(ctx context.Context, backend string) (*client.CanSealResponse, error) {
	return m.canSealResp, m.canSealErr
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

	sealData(cfg, printer, "", []byte("data"), nil, sealTPMParams{})
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

	sealData(cfg, printer, "", []byte("data"), nil, sealTPMParams{})
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

	sealData(cfg, printer, "", []byte("data"), nil, sealTPMParams{})
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

			sealData(cfg, printer, "test-key", []byte("data"), nil, sealTPMParams{})

			if buf.Len() == 0 {
				t.Errorf("sealData with %s format should produce output", format)
			}
		})
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

	unsealData(cfg, printer, "", []byte("ct"), nil, nil, nil, unsealTPMParams{})
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

	unsealData(cfg, printer, "", []byte("ct"), nil, nil, nil, unsealTPMParams{})
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

	unsealData(cfg, printer, "", []byte("ct"), nil, nil, nil, unsealTPMParams{})
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

			unsealData(cfg, printer, "", []byte("ct"), nil, nil, nil, unsealTPMParams{})

			if buf.Len() == 0 {
				t.Errorf("unsealData with %s format should produce output", format)
			}
		})
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

	sealData(cfg, printer, "", []byte("data"), nil, sealTPMParams{})

	if !mockClient.closeCalled {
		t.Error("sealData should call client.Close()")
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

	sealData(cfg, printer, "key", []byte("data"), nil, sealTPMParams{})

	output := buf.String()

	// Verify base64 encoding
	expectedCiphertext := base64.StdEncoding.EncodeToString(testCiphertext)
	if !strings.Contains(output, expectedCiphertext) {
		t.Errorf("sealData output should contain base64-encoded ciphertext: %s", expectedCiphertext)
	}
}
