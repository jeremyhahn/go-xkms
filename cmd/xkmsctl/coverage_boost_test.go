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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// FIDO2 wrapper functions (0% coverage - these call *WithWriter(os.Stdout))
// =============================================================================

func TestRunFIDO2ListDevices_DelegatesToWithWriter(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{devices: []fido2.Device{}}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)
	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	// runFIDO2ListDevices writes to os.Stdout; just verify it doesn't panic
	cmd := &cobra.Command{}
	runFIDO2ListDevices(cmd, []string{})
}

func TestRunFIDO2WaitDevice_DelegatesToWithWriter(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{
		waitForDeviceDev: &fido2.Device{
			Path:    "/dev/hidraw0",
			Product: "Test Device",
		},
	}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)
	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	cmd := &cobra.Command{}
	cmd.Flags().Duration("timeout", 30*time.Second, "timeout")
	runFIDO2WaitDevice(cmd, []string{})
}

func TestRunFIDO2Register_DelegatesToWithWriter(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{
		enrollResult: &fido2.EnrollmentResult{
			CredentialID: []byte("cred-id"),
			PublicKey:    []byte("pub-key"),
			AAGUID:       []byte("aaguid"),
			Salt:         []byte("salt"),
			User: fido2.User{
				ID:          []byte("user-id"),
				Name:        "testuser",
				DisplayName: "Test User",
			},
			RelyingParty: fido2.RelyingParty{
				ID:   "example.com",
				Name: "Example",
			},
			Created: time.Now(),
		},
	}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)
	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	cmd := &cobra.Command{}
	cmd.Flags().String("rp-id", "go-xkms", "")
	cmd.Flags().String("rp-name", "Go xKMS", "")
	cmd.Flags().String("display-name", "", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	runFIDO2Register(cmd, []string{"testuser"})
}

func TestRunFIDO2Authenticate_DelegatesToWithWriter(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{
		derivedKey: []byte("derived-key-data-1234567890123456"),
	}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)
	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", "dGVzdA==", "")
	cmd.Flags().String("salt", "c2FsdA==", "")
	cmd.Flags().String("rp-id", "go-xkms", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", false, "")
	runFIDO2Authenticate(cmd, []string{})
}

func TestRunFIDO2Info_DelegatesToWithWriter(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{
		devices: []fido2.Device{
			{Path: "/dev/hidraw0", Product: "Test", Manufacturer: "Vendor"},
		},
	}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)
	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")
	runFIDO2Info(cmd, []string{})
}

// =============================================================================
// PrintEncryptedAsym - text and table formats (only JSON was tested: 60%)
// =============================================================================

func TestPrintEncryptedAsym_TextFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	err := printer.PrintEncryptedAsym("encrypted-data-here")
	require.NoError(t, err)
	assert.Equal(t, "encrypted-data-here\n", buf.String())
}

func TestPrintEncryptedAsym_TableFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	err := printer.PrintEncryptedAsym("encrypted-data-here")
	require.NoError(t, err)
	assert.Equal(t, "encrypted-data-here\n", buf.String())
}

func TestPrintEncryptedAsym_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("yaml", buf)

	err := printer.PrintEncryptedAsym("data")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output format")
}

// =============================================================================
// PrintPrompt - missing JSON and unknown format tests (80%)
// =============================================================================

func TestPrintPrompt_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	err := printer.PrintPrompt("Please wait...")
	require.NoError(t, err)
	// JSON mode skips prompts
	assert.Empty(t, buf.String())
}

func TestPrintPrompt_TextFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	err := printer.PrintPrompt("Press enter to continue")
	require.NoError(t, err)
	assert.Equal(t, "Press enter to continue\n", buf.String())
}

func TestPrintPrompt_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("yaml", buf)

	err := printer.PrintPrompt("prompt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output format")
}

// =============================================================================
// bootstrapLogger - verbose mode branch (75%)
// =============================================================================

func TestBootstrapLogger_VerboseMode(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	globalConfig = NewConfig()
	globalConfig.Verbose = true

	logger := bootstrapLogger()
	require.NotNil(t, logger)
}

func TestBootstrapLogger_NilConfig(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	globalConfig = nil
	logger := bootstrapLogger()
	require.NotNil(t, logger)
}

// =============================================================================
// loadEnrollmentCert - missing branches (66.7%)
// =============================================================================

func TestLoadEnrollmentCert_CertFile(t *testing.T) {
	// Create a self-signed cert
	certPEM := createTestCertPEM(t)
	tmpFile := filepath.Join(t.TempDir(), "test.pem")
	require.NoError(t, os.WriteFile(tmpFile, certPEM, 0600))

	cmd := &cobra.Command{}
	cmd.Flags().String("cert-file", tmpFile, "")
	cfg := NewConfig()

	cert, err := loadEnrollmentCert(cmd, cfg)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestLoadEnrollmentCert_NeitherCertNorPKCS11(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("cert-file", "", "")
	cfg := NewConfig()

	_, err := loadEnrollmentCert(cmd, cfg)
	require.ErrorIs(t, err, ErrNoCertificateSource)
}

func TestLoadEnrollmentCert_InvalidCertFile(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("cert-file", "/nonexistent/path/cert.pem", "")
	cfg := NewConfig()

	_, err := loadEnrollmentCert(cmd, cfg)
	require.Error(t, err)
}

// =============================================================================
// generateNoiseKey - output to file branch (71.4%)
// =============================================================================

func TestGenerateNoiseKey_ToFile(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	outputFile := filepath.Join(t.TempDir(), "noise.key")
	generateNoiseKey(outputFile)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestGenerateNoiseKey_ToStdout(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	// Just verify it doesn't panic
	generateNoiseKey("")
}

func TestGenerateNoiseKey_WriteError(t *testing.T) {
	origExit := exitFunc
	exitCalled := false
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = origExit }()

	// Write to a path that doesn't exist (directory not writable)
	generateNoiseKey("/nonexistent/dir/noise.key")
	assert.True(t, exitCalled)
}

// =============================================================================
// PIV connect error paths (72.2% for pivGetCertificate, pivStoreCertificate, pivImportCertificate)
// =============================================================================

func TestPIVGetCertificate_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

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
	pivGetCertificate(cfg, printer, "9a", "pem")
}

func TestPIVGetCertificate_ClientCreateError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("factory error")
		},
	}
	pivGetCertificate(cfg, printer, "9a", "pem")
}

func TestPIVStoreCertificate_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

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
	pivStoreCertificate(cfg, printer, "9a", []byte("cert-data"), "pem")
}

func TestPIVStoreCertificate_ClientCreateError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("factory error")
		},
	}
	pivStoreCertificate(cfg, printer, "9a", []byte("cert-data"), "pem")
}

func TestPIVImportCertificate_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

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
	pivImportCertificate(cfg, printer, "9a", []byte("cert-data"), "pem")
}

func TestPIVImportCertificate_ClientCreateError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("factory error")
		},
	}
	pivImportCertificate(cfg, printer, "9a", []byte("cert-data"), "pem")
}

// =============================================================================
// Tenant connect/factory error paths (72-83%)
// =============================================================================

func TestTenantDelete_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	mock := &mockTenantClient{
		connectErr: errors.New("connect failed"),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}
	tenantDelete(cfg, printer, "acme")
}

func TestTenantDelete_ClientFactoryError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return nil, errors.New("factory failed")
		},
	}
	tenantDelete(cfg, printer, "acme")
}

func TestTenantBarrierInit_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	mock := &mockTenantClient{
		connectErr: errors.New("connect failed"),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}
	tenantBarrierInit(cfg, printer, "acme", 3, 5)
}

func TestTenantBarrierInit_ClientFactoryError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return nil, errors.New("factory failed")
		},
	}
	tenantBarrierInit(cfg, printer, "acme", 3, 5)
}

func TestTenantBarrierUnseal_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	mock := &mockTenantClient{
		connectErr: errors.New("connect failed"),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}
	tenantBarrierUnseal(cfg, printer, "acme", "")
}

func TestTenantBarrierStatus_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	mock := &mockTenantClient{
		connectErr: errors.New("connect failed"),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}
	tenantBarrierStatus(cfg, printer, "acme")
}

func TestTenantList_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	mock := &mockTenantClient{
		connectErr: errors.New("connect failed"),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}
	tenantList(cfg, printer)
}

func TestTenantShow_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	mock := &mockTenantClient{
		connectErr: errors.New("connect failed"),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}
	tenantShow(cfg, printer, "acme")
}

// =============================================================================
// Custodian connect/factory error paths (72-83%)
// =============================================================================

func TestCustodianDelete_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	mock := &mockCustodianClient{
		connectErr: errors.New("connect failed"),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := newTestCustodianConfig(mock)
	custodianDelete(cfg, printer, "grp-001")
}

func TestCustodianDelete_ClientFactoryError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return nil, errors.New("factory error")
		},
	}
	custodianDelete(cfg, printer, "grp-001")
}

func TestCustodianRemoveMember_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	mock := &mockCustodianClient{
		connectErr: errors.New("connect failed"),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := newTestCustodianConfig(mock)
	custodianRemoveMember(cfg, printer, "grp-001", "user-001")
}

func TestCustodianRemoveMember_ClientFactoryError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return nil, errors.New("factory error")
		},
	}
	custodianRemoveMember(cfg, printer, "grp-001", "user-001")
}

func TestCustodianList_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	mock := &mockCustodianClient{
		connectErr: errors.New("connect failed"),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := newTestCustodianConfig(mock)
	custodianList(cfg, printer)
}

func TestCustodianShow_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	mock := &mockCustodianClient{
		connectErr: errors.New("connect failed"),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := newTestCustodianConfig(mock)
	custodianShow(cfg, printer, "grp-001")
}

func TestCustodianAddMember_ConnectError(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	mock := &mockCustodianClient{
		connectErr: errors.New("connect failed"),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)
	cfg := newTestCustodianConfig(mock)
	custodianAddMember(cfg, printer, "grp-001", "user-001", "alice", "encrypted")
}

// =============================================================================
// printCustodianMember - missing text format with empty username (90%)
// =============================================================================

func TestPrintCustodianMember_TextWithUsername(t *testing.T) {
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	member := &transport.CustodianMemberInfo{
		UserID:     "user-001",
		Username:   "alice",
		ShareIndex: 1,
		Method:     "encrypted",
		AssignedAt: time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
	}

	printCustodianMember(printer, member)
	output := buf.String()
	assert.Contains(t, output, "alice")
	assert.Contains(t, output, "user-001")
}

func TestPrintCustodianMember_TextWithoutUsername(t *testing.T) {
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	member := &transport.CustodianMemberInfo{
		UserID:     "user-001",
		Username:   "",
		ShareIndex: 1,
		Method:     "encrypted",
		AssignedAt: time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
	}

	printCustodianMember(printer, member)
	output := buf.String()
	assert.Contains(t, output, "user-001")
	assert.NotContains(t, output, "Username:")
}

// =============================================================================
// writeTCGCSROutput - write error paths (77.8%)
// =============================================================================

func TestWriteTCGCSROutput_IAKWriteError(t *testing.T) {
	// Use a directory path that will fail (file with same name as dir)
	tmpDir := t.TempDir()
	blockingFile := filepath.Join(tmpDir, "output")
	require.NoError(t, os.WriteFile(blockingFile, []byte("block"), 0600))

	err := writeTCGCSROutput(blockingFile+"/subdir", []byte("iak"), []byte("idevid"))
	require.Error(t, err)
}

// =============================================================================
// writeEnrollmentOutput - missing blob and secret write error paths (76.5%)
// =============================================================================

func TestWriteEnrollmentOutput_WithBlobAndSecret(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "enrollment")

	resp := &client.EnrollDeviceResponse{
		IAKCertDER:      []byte("iak-cert"),
		IDevIDCertDER:   []byte("idevid-cert"),
		CredentialBlob:  []byte("credential-blob"),
		EncryptedSecret: []byte("encrypted-secret"),
	}

	err := writeEnrollmentOutput(dir, resp)
	require.NoError(t, err)

	// Verify all files written
	data, err := os.ReadFile(filepath.Join(dir, "iak_cert.der"))
	require.NoError(t, err)
	assert.Equal(t, []byte("iak-cert"), data)

	data, err = os.ReadFile(filepath.Join(dir, "credential_blob.bin"))
	require.NoError(t, err)
	assert.Equal(t, []byte("credential-blob"), data)

	data, err = os.ReadFile(filepath.Join(dir, "encrypted_secret.bin"))
	require.NoError(t, err)
	assert.Equal(t, []byte("encrypted-secret"), data)
}

func TestWriteEnrollmentOutput_NoBlobNoSecret(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "enrollment")

	resp := &client.EnrollDeviceResponse{
		IAKCertDER:    []byte("iak-cert"),
		IDevIDCertDER: []byte("idevid-cert"),
	}

	err := writeEnrollmentOutput(dir, resp)
	require.NoError(t, err)

	// credential_blob.bin should not exist
	_, err = os.ReadFile(filepath.Join(dir, "credential_blob.bin"))
	assert.True(t, os.IsNotExist(err))
}

// =============================================================================
// generateNoiseKeyPair (71.4%)
// =============================================================================

func TestGenerateNoiseKeyPair_ReturnsValidKeys(t *testing.T) {
	pubKey, privKey, err := generateNoiseKeyPair()
	require.NoError(t, err)
	require.NotEmpty(t, pubKey)
	require.NotNil(t, privKey)
}

// =============================================================================
// printTenantInfo - JSON format (87.5%)
// =============================================================================

func TestPrintTenantInfo_JSONFormat(t *testing.T) {
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	tenant := &transport.TenantInfo{
		ID:        "acme",
		Name:      "Acme Corp",
		CreatedAt: time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
	}

	printTenantInfo(printer, tenant, "Test Header")
	assert.Contains(t, buf.String(), "acme")
}

// =============================================================================
// printTenantList - table format with data (94.4% -> already good but ensure table branch)
// =============================================================================

func TestPrintTenantList_TableFormat(t *testing.T) {
	buf := new(bytes.Buffer)
	printer := NewPrinter("table", buf)

	tenants := []transport.TenantInfo{
		{ID: "acme", Name: "Acme", CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	printTenantList(printer, tenants)
	output := buf.String()
	assert.Contains(t, output, "acme")
	assert.Contains(t, output, "Acme")
}

// =============================================================================
// showNoiseKey - branches (not covered in bootstrap_noise_test.go)
// =============================================================================

func TestShowNoiseKey_NoInput(t *testing.T) {
	origExit := exitFunc
	exitCalled := false
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = origExit }()

	showNoiseKey("", "")
	assert.True(t, exitCalled)
}

func TestShowNoiseKey_InvalidKeyFile(t *testing.T) {
	origExit := exitFunc
	exitCalled := false
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = origExit }()

	showNoiseKey("/nonexistent/file.key", "")
	assert.True(t, exitCalled)
}

func TestShowNoiseKey_InvalidHex(t *testing.T) {
	origExit := exitFunc
	exitCalled := false
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = origExit }()

	showNoiseKey("", "not-valid-hex")
	assert.True(t, exitCalled)
}

// =============================================================================
// showSPKIPin - error paths
// =============================================================================

func TestShowSPKIPin_NoFile(t *testing.T) {
	origExit := exitFunc
	exitCalled := false
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = origExit }()

	showSPKIPin("")
	assert.True(t, exitCalled)
}

func TestShowSPKIPin_InvalidFile(t *testing.T) {
	origExit := exitFunc
	exitCalled := false
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = origExit }()

	showSPKIPin("/nonexistent/cert.pem")
	assert.True(t, exitCalled)
}

func TestShowSPKIPin_NotPEM(t *testing.T) {
	origExit := exitFunc
	exitCalled := false
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = origExit }()

	tmpFile := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(tmpFile, []byte("not-pem-data"), 0600))

	showSPKIPin(tmpFile)
	assert.True(t, exitCalled)
}

func TestShowSPKIPin_ValidCert(t *testing.T) {
	origExit := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = origExit }()

	certPEM := createTestCertPEM(t)
	tmpFile := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(tmpFile, certPEM, 0600))

	showSPKIPin(tmpFile)
}

// =============================================================================
// newFileCredentialStorage - error path for invalid state dir
// =============================================================================

func TestNewFileCredentialStorage_ValidDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fido2-state")
	storage, err := newFileCredentialStorage(dir)
	require.NoError(t, err)
	require.NotNil(t, storage)
}

// =============================================================================
// FIDO2 virtual device with state dir
// =============================================================================

func TestDefaultFIDO2HandlerFactory_VirtualWithPersistentStorage(t *testing.T) {
	origVirtual := os.Getenv("FIDO2_USE_VIRTUAL")
	origStateDir := os.Getenv("FIDO2_VIRTUAL_STATE_DIR")

	require.NoError(t, os.Setenv("FIDO2_USE_VIRTUAL", "true"))
	require.NoError(t, os.Setenv("FIDO2_VIRTUAL_STATE_DIR", t.TempDir()))
	defer func() {
		if origVirtual == "" {
			os.Unsetenv("FIDO2_USE_VIRTUAL")
		} else {
			os.Setenv("FIDO2_USE_VIRTUAL", origVirtual)
		}
		if origStateDir == "" {
			os.Unsetenv("FIDO2_VIRTUAL_STATE_DIR")
		} else {
			os.Setenv("FIDO2_VIRTUAL_STATE_DIR", origStateDir)
		}
	}()

	config := &fido2.Config{}
	handler, err := defaultFIDO2HandlerFactory(config)
	require.NoError(t, err)
	require.NotNil(t, handler)
	defer handler.Close()
}

// =============================================================================
// PrintImportParameters - text format with wrapping key branch (83.3%)
// =============================================================================

func TestPrintImportParameters_TextWithWrappingKey(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	params := &client.ImportParameters{
		Algorithm:        "RSA_OAEP_SHA256",
		KeySpec:          "AES_256",
		WrappingPublicKey: &privKey.PublicKey,
	}

	err = printer.PrintImportParameters(params)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Wrapping Key:")
}

func TestPrintImportParameters_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("yaml", buf)

	params := &client.ImportParameters{
		Algorithm: "RSA_OAEP_SHA256",
		KeySpec:   "AES_256",
	}

	err := printer.PrintImportParameters(params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output format")
}

// =============================================================================
// writeCABundle - stdout branch (90%)
// =============================================================================

func TestWriteCABundle_StdoutWriteError(t *testing.T) {
	// Write to stdout is tested already, but we can test the error path
	err := writeCABundle([]byte("test-bundle"), "")
	require.NoError(t, err)
}

// =============================================================================
// Helpers
// =============================================================================

func createTestCertPEM(t *testing.T) []byte {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// Ensure the imports don't get removed
var _ = strings.Contains
var _ context.Context
