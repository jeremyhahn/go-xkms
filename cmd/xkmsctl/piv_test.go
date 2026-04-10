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
	"os"
	"path/filepath"
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

// TestPIVCmd_Exists verifies the piv command exists.
func TestPIVCmd_Exists(t *testing.T) {
	if pivCmd == nil {
		t.Fatal("pivCmd should not be nil")
	}
}

// TestPIVCmd_Properties verifies the piv command properties.
func TestPIVCmd_Properties(t *testing.T) {
	if pivCmd.Use != "piv" {
		t.Errorf("pivCmd.Use = %v, want 'piv'", pivCmd.Use)
	}

	if pivCmd.Short == "" {
		t.Error("pivCmd.Short should not be empty")
	}
}

// TestPIVCmd_HasSubcommands verifies all 8 PIV subcommands are present.
func TestPIVCmd_HasSubcommands(t *testing.T) {
	expectedSubcommands := []string{
		"list", "get", "store", "delete",
		"generate", "import", "export", "csr",
	}

	subcommands := pivCmd.Commands()
	found := make(map[string]bool)
	for _, cmd := range subcommands {
		found[cmd.Name()] = true
	}

	for _, expected := range expectedSubcommands {
		if !found[expected] {
			t.Errorf("expected subcommand %q not found in pivCmd", expected)
		}
	}
}

// TestPIVListSlots_Success tests successful listing of PIV slots.
func TestPIVListSlots_Success(t *testing.T) {
	mockClient := &mockPIVClient{
		listSlotsResp: &transport.ListPIVSlotsResponse{
			Slots: []transport.PIVSlotStatus{
				{
					Slot:      "9a",
					Name:      "Authentication",
					HasCert:   true,
					Subject:   "CN=TestKey",
					Algorithm: "ecdsap256",
				},
				{
					Slot:    "9c",
					Name:    "Signing",
					HasCert: false,
				},
			},
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

	pivListSlots(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "9a") {
		t.Error("pivListSlots output should contain slot '9a'")
	}
	if !strings.Contains(output, "Authentication") {
		t.Error("pivListSlots output should contain 'Authentication'")
	}
	if !strings.Contains(output, "CN=TestKey") {
		t.Error("pivListSlots output should contain 'CN=TestKey'")
	}
	if !strings.Contains(output, "9c") {
		t.Error("pivListSlots output should contain slot '9c'")
	}
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

// TestPIVListSlots_ClientCreateError tests listing PIV slots when client creation fails.
func TestPIVListSlots_ClientCreateError(t *testing.T) {
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

// TestPIVGetCertificate_Success tests successful retrieval of a PIV certificate.
func TestPIVGetCertificate_Success(t *testing.T) {
	testCert := []byte("-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n")

	mockClient := &mockPIVClient{
		getCertResp: &transport.GetPIVCertificateResponse{
			Slot:        "9a",
			Certificate: testCert,
			Format:      "pem",
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

	pivGetCertificate(cfg, printer, "9a", "pem")

	output := buf.String()
	if !strings.Contains(output, "9a") {
		t.Error("pivGetCertificate output should contain slot '9a'")
	}
	if !strings.Contains(output, "certificate") {
		t.Error("pivGetCertificate output should contain 'certificate'")
	}
	if !strings.Contains(output, "pem") {
		t.Error("pivGetCertificate output should contain format 'pem'")
	}
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

// TestPIVStoreCertificate_Success tests successful storage of a PIV certificate.
func TestPIVStoreCertificate_Success(t *testing.T) {
	mockClient := &mockPIVClient{
		storeCertErr: nil,
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

	output := buf.String()
	if !strings.Contains(output, "stored") {
		t.Error("pivStoreCertificate output should contain 'stored'")
	}
	if !strings.Contains(output, "9a") {
		t.Error("pivStoreCertificate output should contain slot '9a'")
	}
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

// TestPIVStoreCertificate_FromFile tests storing a PIV certificate read from a temp file.
func TestPIVStoreCertificate_FromFile(t *testing.T) {
	mockClient := &mockPIVClient{
		storeCertErr: nil,
	}

	// Create a temporary certificate file
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test-cert.pem")
	certContent := []byte("-----BEGIN CERTIFICATE-----\nMIIBtempfile\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(certPath, certContent, 0600); err != nil {
		t.Fatalf("failed to write temp cert file: %v", err)
	}

	// Read the cert data back (simulating what piv.go does with os.ReadFile)
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read temp cert file: %v", err)
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "pkcs11",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	pivStoreCertificate(cfg, printer, "9a", certData, "pem")

	output := buf.String()
	if !strings.Contains(output, "stored") {
		t.Error("pivStoreCertificate output should contain 'stored'")
	}
}

// TestPIVDeleteCertificate_Success tests successful deletion of a PIV certificate.
func TestPIVDeleteCertificate_Success(t *testing.T) {
	mockClient := &mockPIVClient{
		deleteCertErr: nil,
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

	output := buf.String()
	if !strings.Contains(output, "deleted") {
		t.Error("pivDeleteCertificate output should contain 'deleted'")
	}
	if !strings.Contains(output, "9a") {
		t.Error("pivDeleteCertificate output should contain slot '9a'")
	}
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

// TestPIVGenerateKey_Success tests successful PIV key generation.
func TestPIVGenerateKey_Success(t *testing.T) {
	testCert := []byte("-----BEGIN CERTIFICATE-----\nMIIBgenerated\n-----END CERTIFICATE-----\n")
	testPubKey := []byte("-----BEGIN PUBLIC KEY-----\nMIIBpubkey\n-----END PUBLIC KEY-----\n")

	mockClient := &mockPIVClient{
		generateKeyResp: &transport.GeneratePIVKeyResponse{
			Slot:        "9a",
			Certificate: testCert,
			PublicKey:   testPubKey,
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

	pivGenerateKey(cfg, printer, "9a", "ecdsap256", "CN=TestKey")

	output := buf.String()
	if !strings.Contains(output, "9a") {
		t.Error("pivGenerateKey output should contain slot '9a'")
	}
	if !strings.Contains(output, "certificate") {
		t.Error("pivGenerateKey output should contain 'certificate'")
	}
	if !strings.Contains(output, "public_key") {
		t.Error("pivGenerateKey output should contain 'public_key'")
	}
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

// TestPIVImportCertificate_Success tests successful import of a PIV certificate.
func TestPIVImportCertificate_Success(t *testing.T) {
	mockClient := &mockPIVClient{
		importCertErr: nil,
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

	output := buf.String()
	if !strings.Contains(output, "imported") {
		t.Error("pivImportCertificate output should contain 'imported'")
	}
	if !strings.Contains(output, "9c") {
		t.Error("pivImportCertificate output should contain slot '9c'")
	}
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

// TestPIVImportCertificate_FromFile tests importing a certificate from a temp file.
func TestPIVImportCertificate_FromFile(t *testing.T) {
	mockClient := &mockPIVClient{
		importCertErr: nil,
	}

	// Create a temporary certificate file
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "import-cert.pem")
	certContent := []byte("-----BEGIN CERTIFICATE-----\nMIIBimportfile\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(certPath, certContent, 0600); err != nil {
		t.Fatalf("failed to write temp cert file: %v", err)
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read temp cert file: %v", err)
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend: "pkcs11",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	pivImportCertificate(cfg, printer, "9c", certData, "pem")

	output := buf.String()
	if !strings.Contains(output, "imported") {
		t.Error("pivImportCertificate output should contain 'imported'")
	}
}

// TestPIVExportCertificate_Success tests successful export of a PIV certificate.
func TestPIVExportCertificate_Success(t *testing.T) {
	testCert := []byte("-----BEGIN CERTIFICATE-----\nMIIBexported\n-----END CERTIFICATE-----\n")

	mockClient := &mockPIVClient{
		exportCertResp: &transport.GetPIVCertificateResponse{
			Slot:        "9a",
			Certificate: testCert,
			Format:      "pem",
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

	pivExportCertificate(cfg, printer, "9a", "pem")

	output := buf.String()
	if !strings.Contains(output, "9a") {
		t.Error("pivExportCertificate output should contain slot '9a'")
	}
	if !strings.Contains(output, "certificate") {
		t.Error("pivExportCertificate output should contain 'certificate'")
	}
	if !strings.Contains(output, "pem") {
		t.Error("pivExportCertificate output should contain format 'pem'")
	}
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

// TestPIVCSR_Success tests successful PIV CSR generation.
func TestPIVCSR_Success(t *testing.T) {
	testCSR := []byte("-----BEGIN CERTIFICATE REQUEST-----\nMIIBcsr\n-----END CERTIFICATE REQUEST-----\n")

	mockClient := &mockPIVClient{
		generateCSRResp: &transport.GeneratePIVCSRResponse{
			Slot: "9a",
			CSR:  testCSR,
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

	pivCSR(cfg, printer, "9a", "CN=TestKey,O=TestOrg")

	output := buf.String()
	if !strings.Contains(output, "9a") {
		t.Error("pivCSR output should contain slot '9a'")
	}
	if !strings.Contains(output, "csr") {
		t.Error("pivCSR output should contain 'csr'")
	}
	if !strings.Contains(output, "CERTIFICATE REQUEST") {
		t.Error("pivCSR output should contain the CSR content")
	}
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

// TestPIVDeleteCertificate_ClientCreateError tests delete when client creation fails.
func TestPIVDeleteCertificate_ClientCreateError(t *testing.T) {
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

	pivDeleteCertificate(cfg, printer, "9a")
	// Should not panic
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

// TestPIVCSR_ClientCreateError tests CSR generation when client creation fails.
func TestPIVCSR_ClientCreateError(t *testing.T) {
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

	pivCSR(cfg, printer, "9a", "CN=Test")
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

// TestPIVMockClient_MethodInvocations verifies the mock client PIV methods
// return expected results when called directly.
func TestPIVMockClient_MethodInvocations(t *testing.T) {
	ctx := context.Background()

	t.Run("ListPIVSlots", func(t *testing.T) {
		mockClient := &mockPIVClient{
			listSlotsResp: &transport.ListPIVSlotsResponse{
				Slots: []transport.PIVSlotStatus{
					{Slot: "9a", Name: "Auth", HasCert: true},
					{Slot: "9c", Name: "Sign", HasCert: false},
					{Slot: "9d", Name: "KeyMgmt", HasCert: true},
					{Slot: "9e", Name: "CardAuth", HasCert: false},
				},
			},
		}

		resp, err := mockClient.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{
			Backend: "pkcs11",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Slots) != 4 {
			t.Errorf("expected 4 slots, got %d", len(resp.Slots))
		}
		if resp.Slots[0].Slot != "9a" {
			t.Errorf("expected slot '9a', got %q", resp.Slots[0].Slot)
		}
	})

	t.Run("GetPIVCertificate", func(t *testing.T) {
		testCert := []byte("test-cert-data")
		mockClient := &mockPIVClient{
			getCertResp: &transport.GetPIVCertificateResponse{
				Slot:        "9a",
				Certificate: testCert,
				Format:      "pem",
			},
		}

		resp, err := mockClient.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
			Backend: "pkcs11",
			Slot:    "9a",
			Format:  "pem",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Slot != "9a" {
			t.Errorf("expected slot '9a', got %q", resp.Slot)
		}
		if string(resp.Certificate) != "test-cert-data" {
			t.Errorf("unexpected certificate data: %s", resp.Certificate)
		}
	})

	t.Run("StorePIVCertificate", func(t *testing.T) {
		mockClient := &mockPIVClient{storeCertErr: nil}

		err := mockClient.StorePIVCertificate(ctx, &transport.StorePIVCertificateRequest{
			Backend:     "pkcs11",
			Slot:        "9a",
			Certificate: []byte("cert-data"),
			Format:      "pem",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("StorePIVCertificate_Error", func(t *testing.T) {
		expectedErr := errors.New("store failed")
		mockClient := &mockPIVClient{storeCertErr: expectedErr}

		err := mockClient.StorePIVCertificate(ctx, &transport.StorePIVCertificateRequest{
			Backend:     "pkcs11",
			Slot:        "9a",
			Certificate: []byte("cert-data"),
			Format:      "pem",
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if err.Error() != "store failed" {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("DeletePIVCertificate", func(t *testing.T) {
		mockClient := &mockPIVClient{deleteCertErr: nil}

		err := mockClient.DeletePIVCertificate(ctx, &transport.DeletePIVCertificateRequest{
			Backend: "pkcs11",
			Slot:    "9a",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("GeneratePIVKey", func(t *testing.T) {
		mockClient := &mockPIVClient{
			generateKeyResp: &transport.GeneratePIVKeyResponse{
				Slot:        "9a",
				Certificate: []byte("self-signed-cert"),
				PublicKey:   []byte("public-key-bytes"),
			},
		}

		resp, err := mockClient.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
			Backend:   "pkcs11",
			Slot:      "9a",
			Algorithm: "ecdsap256",
			Subject:   "CN=TestKey",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Slot != "9a" {
			t.Errorf("expected slot '9a', got %q", resp.Slot)
		}
		if len(resp.Certificate) == 0 {
			t.Error("expected non-empty certificate")
		}
		if len(resp.PublicKey) == 0 {
			t.Error("expected non-empty public key")
		}
	})

	t.Run("ImportPIVCertificate", func(t *testing.T) {
		mockClient := &mockPIVClient{importCertErr: nil}

		err := mockClient.ImportPIVCertificate(ctx, &transport.StorePIVCertificateRequest{
			Backend:     "pkcs11",
			Slot:        "9c",
			Certificate: []byte("imported-cert"),
			Format:      "pem",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("ExportPIVCertificate", func(t *testing.T) {
		mockClient := &mockPIVClient{
			exportCertResp: &transport.GetPIVCertificateResponse{
				Slot:        "9c",
				Certificate: []byte("exported-cert"),
				Format:      "pem",
			},
		}

		resp, err := mockClient.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
			Backend: "pkcs11",
			Slot:    "9c",
			Format:  "pem",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Slot != "9c" {
			t.Errorf("expected slot '9c', got %q", resp.Slot)
		}
	})

	t.Run("GeneratePIVCSR", func(t *testing.T) {
		mockClient := &mockPIVClient{
			generateCSRResp: &transport.GeneratePIVCSRResponse{
				Slot: "9a",
				CSR:  []byte("csr-pem-data"),
			},
		}

		resp, err := mockClient.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{
			Backend: "pkcs11",
			Slot:    "9a",
			Subject: "CN=Test,O=Org",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Slot != "9a" {
			t.Errorf("expected slot '9a', got %q", resp.Slot)
		}
		if string(resp.CSR) != "csr-pem-data" {
			t.Errorf("unexpected CSR data: %s", resp.CSR)
		}
	})
}
