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

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockPIVClient is a mock client for testing PIV operations.
type mockPIVClient struct {
	mockBackendsClient
	listSlotsResp   *transport.ListPIVSlotsResponse
	listSlotsErr    error
	getCertResp     *transport.GetPIVCertificateResponse
	getCertErr      error
	storeCertErr    error
	deleteCertErr   error
	generateKeyResp *transport.GeneratePIVKeyResponse
	generateKeyErr  error
	importCertErr   error
	exportCertResp  *transport.GetPIVCertificateResponse
	exportCertErr   error
	generateCSRResp *transport.GeneratePIVCSRResponse
	generateCSRErr  error
	connectErr      error
	closeCalled     bool
}

func (m *mockPIVClient) Connect(ctx context.Context) error {
	return m.connectErr
}

func (m *mockPIVClient) Close() error {
	m.closeCalled = true
	return nil
}

func (m *mockPIVClient) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return m.listSlotsResp, m.listSlotsErr
}

func (m *mockPIVClient) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return m.getCertResp, m.getCertErr
}

func (m *mockPIVClient) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return m.storeCertErr
}

func (m *mockPIVClient) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return m.deleteCertErr
}

func (m *mockPIVClient) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return m.generateKeyResp, m.generateKeyErr
}

func (m *mockPIVClient) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return m.importCertErr
}

func (m *mockPIVClient) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return m.exportCertResp, m.exportCertErr
}

func (m *mockPIVClient) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return m.generateCSRResp, m.generateCSRErr
}

// TestPIVListSlots_Error tests listing PIV slots when an error occurs.
func TestPIVListSlots_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockPIVClient{
		listSlotsErr: errors.New("list slots failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "pkcs11",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	pivListSlots(cfg, printer)
	// Should not panic
}

// TestPIVListSlots_ConnectError tests listing PIV slots when connection fails.
func TestPIVListSlots_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockPIVClient{
		connectErr: errors.New("connect failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	pivListSlots(cfg, printer)
	// Should not panic
}

// TestPIVGetCertificate_Error tests getting a PIV certificate when an error occurs.
func TestPIVGetCertificate_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockPIVClient{
		getCertErr: errors.New("get certificate failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "pkcs11",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	pivGetCertificate(cfg, printer, "9a", "pem")
	// Should not panic
}

// TestPIVStoreCertificate_Error tests storing a PIV certificate when an error occurs.
func TestPIVStoreCertificate_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockPIVClient{
		storeCertErr: errors.New("store certificate failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "pkcs11",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	certData := []byte("-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n")
	pivStoreCertificate(cfg, printer, "9a", certData, "pem")
	// Should not panic
}

// TestPIVDeleteCertificate_Error tests deleting a PIV certificate when an error occurs.
func TestPIVDeleteCertificate_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockPIVClient{
		deleteCertErr: errors.New("delete certificate failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "pkcs11",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	pivDeleteCertificate(cfg, printer, "9a")
	// Should not panic
}

// TestPIVGenerateKey_Error tests PIV key generation when an error occurs.
func TestPIVGenerateKey_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockPIVClient{
		generateKeyErr: errors.New("generate key failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "pkcs11",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	pivGenerateKey(cfg, printer, "9a", "ecdsap256", "CN=TestKey")
	// Should not panic
}

// TestPIVImportCertificate_Error tests importing a PIV certificate when an error occurs.
func TestPIVImportCertificate_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockPIVClient{
		importCertErr: errors.New("import certificate failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "pkcs11",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	certData := []byte("-----BEGIN CERTIFICATE-----\nMIIBimported\n-----END CERTIFICATE-----\n")
	pivImportCertificate(cfg, printer, "9c", certData, "pem")
	// Should not panic
}

// TestPIVExportCertificate_DERFormat tests export with DER format (base64 encoded).
func TestPIVExportCertificate_DERFormat(t *testing.T) {
	derCert := []byte{0x30, 0x82, 0x01, 0x22} // sample DER bytes

	mockClient := &mockPIVClient{
		exportCertResp: &transport.GetPIVCertificateResponse{
			Slot:        "9c",
			Certificate: derCert,
			Format:      "der",
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

	pivExportCertificate(cfg, printer, "9c", "der")

	output := buf.String()
	if !strings.Contains(output, "9c") {
		t.Error("pivExportCertificate output should contain slot '9c'")
	}
	if !strings.Contains(output, "der") {
		t.Error("pivExportCertificate output should contain format 'der'")
	}
}

// TestPIVExportCertificate_Error tests exporting a PIV certificate when an error occurs.
func TestPIVExportCertificate_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockPIVClient{
		exportCertErr: errors.New("export certificate failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "pkcs11",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	pivExportCertificate(cfg, printer, "9a", "pem")
	// Should not panic
}

// TestPIVCSR_Error tests PIV CSR generation when an error occurs.
func TestPIVCSR_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockPIVClient{
		generateCSRErr: errors.New("generate CSR failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "pkcs11",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	pivCSR(cfg, printer, "9a", "CN=TestKey")
	// Should not panic
}

// TestPIVListSlots_AllFormats tests listing PIV slots in all output formats.
func TestPIVListSlots_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockPIVClient{
				listSlotsResp: &transport.ListPIVSlotsResponse{
					Slots: []transport.PIVSlotStatus{
						{
							Slot:    "9a",
							Name:    "Authentication",
							HasCert: true,
						},
					},
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				Backend: "pkcs11",
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			pivListSlots(cfg, printer)

			if buf.Len() == 0 {
				t.Errorf("pivListSlots with %s format should produce output", format)
			}
		})
	}
}

// TestPIVGenerateKey_ClientCloseIsCalled tests that client.Close() is called.
func TestPIVGenerateKey_ClientCloseIsCalled(t *testing.T) {
	mockClient := &mockPIVClient{
		generateKeyResp: &transport.GeneratePIVKeyResponse{
			Slot:        "9a",
			Certificate: []byte("cert"),
			PublicKey:   []byte("pubkey"),
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

	pivGenerateKey(cfg, printer, "9a", "ecdsap256", "CN=Test")

	if !mockClient.closeCalled {
		t.Error("pivGenerateKey should call client.Close()")
	}
}

// TestPIVGenerateKey_ConnectError tests generate key when connection fails.
func TestPIVGenerateKey_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockPIVClient{
		connectErr: errors.New("connect failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	pivGenerateKey(cfg, printer, "9a", "ecdsap256", "CN=Test")
	// Should not panic
}

// TestPIVExportCertificate_ConnectError tests export when connection fails.
func TestPIVExportCertificate_ConnectError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockPIVClient{
		connectErr: errors.New("connect failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	pivExportCertificate(cfg, printer, "9a", "pem")
	// Should not panic
}
