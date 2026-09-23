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
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// =============================================================================
// Command Structure Tests
// =============================================================================

func TestTLSCmd_Exists(t *testing.T) {
	if tlsCmd == nil {
		t.Fatal("tlsCmd should not be nil")
	}
}

func TestTLSCmd_Properties(t *testing.T) {
	if tlsCmd.Use != "tls" {
		t.Errorf("tlsCmd.Use = %v, want tls", tlsCmd.Use)
	}

	if tlsCmd.Short == "" {
		t.Error("tlsCmd.Short should not be empty")
	}
}

func TestTLSCmd_HasSubcommands(t *testing.T) {
	subcommands := tlsCmd.Commands()

	expectedCmds := []string{"get"}
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

func TestTLSGetCmd_Exists(t *testing.T) {
	if tlsGetCmd == nil {
		t.Fatal("tlsGetCmd should not be nil")
	}
}

func TestTLSGetCmd_Properties(t *testing.T) {
	if tlsGetCmd.Use != "get <key-id>" {
		t.Errorf("tlsGetCmd.Use = %v, want 'get <key-id>'", tlsGetCmd.Use)
	}

	if tlsGetCmd.Short == "" {
		t.Error("tlsGetCmd.Short should not be empty")
	}

	if tlsGetCmd.Long == "" {
		t.Error("tlsGetCmd.Long should not be empty")
	}
}

func TestTLSGetCmd_Arguments(t *testing.T) {
	// Verify command expects exactly one argument (key-id)
	if tlsGetCmd.Args == nil {
		t.Error("tlsGetCmd.Args should be set")
	}
}

func TestTLSCmd_CommandStructure(t *testing.T) {
	// Test that tlsCmd is properly configured
	if !tlsCmd.HasSubCommands() {
		t.Error("tlsCmd should have subcommands")
	}

	// Verify parent relationship
	for _, sub := range tlsCmd.Commands() {
		if sub.Parent() != tlsCmd {
			t.Errorf("subcommand %s should have tlsCmd as parent", sub.Use)
		}
	}
}

// =============================================================================
// getTLSCert Tests - Success Paths
// =============================================================================

func TestGetTLSCert_Success_TextOutput(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})

	mockClient := newMockCertClient()
	mockClient.certificates["get-tls-test"] = string(certPEM)

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

	getTLSCert(cfg, printer, "get-tls-test")

	if exitCalled {
		t.Error("getTLSCert should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "TLS Certificate") {
		t.Errorf("expected TLS Certificate output, got: %s", output)
	}
	if strings.Contains(output, "PRIVATE KEY") {
		t.Errorf("output must never contain private key material, got: %s", output)
	}
}

func TestGetTLSCert_Success_JSONOutput(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})

	mockClient := newMockCertClient()
	mockClient.certificates["json-tls-test"] = string(certPEM)

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

	getTLSCert(cfg, printer, "json-tls-test")

	if exitCalled {
		t.Error("getTLSCert should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "subject") {
		t.Errorf("expected JSON with subject field, got: %s", output)
	}
}

func TestGetTLSCert_Success_WithChain(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Cert.Raw})
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})

	mockClient := newMockCertClient()
	mockClient.certificates["chain-tls-test"] = string(certPEM)
	mockClient.tlsChains["chain-tls-test"] = string(chainPEM)

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

	getTLSCert(cfg, printer, "chain-tls-test")

	if exitCalled {
		t.Error("getTLSCert should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "Chain Length: 1") {
		t.Errorf("expected chain info in output, got: %s", output)
	}
}

func TestGetTLSCert_Success_NoChain(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})

	mockClient := newMockCertClient()
	mockClient.certificates["no-chain-tls-test"] = string(certPEM)

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.Verbose = true
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	getTLSCert(cfg, printer, "no-chain-tls-test")

	// Chain is optional; absence must not be an error.
	if exitCalled {
		t.Error("getTLSCert should not call exit when the chain is absent")
	}

	output := buf.String()
	if !strings.Contains(output, "TLS Certificate") {
		t.Errorf("expected TLS Certificate output even without a chain, got: %s", output)
	}
}

// =============================================================================
// getTLSCert Tests - Error Paths
// =============================================================================

func TestGetTLSCert_Error_ClientCreation(t *testing.T) {
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

	getTLSCert(cfg, printer, "test-key")

	if !exitCalled {
		t.Error("getTLSCert should call exit when client creation fails")
	}
}

func TestGetTLSCert_Error_Connect(t *testing.T) {
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

	getTLSCert(cfg, printer, "test-key")

	if !exitCalled {
		t.Error("getTLSCert should call exit when connect fails")
	}
}

func TestGetTLSCert_Error_NotFound(t *testing.T) {
	mockClient := newMockCertClient()

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
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

	getTLSCert(cfg, printer, "non-existent-key")

	if !exitCalled {
		t.Error("getTLSCert should call exit when the certificate is not found")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
}

func TestGetTLSCert_Error_ServerRejects(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.getTLSCertErr = errors.New("backend unreachable")

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

	getTLSCert(cfg, printer, "test-key")

	if !exitCalled {
		t.Error("getTLSCert should call exit when the server call fails")
	}
}

func TestGetTLSCert_Error_InvalidCertPEM(t *testing.T) {
	mockClient := newMockCertClient()
	mockClient.certificates["invalid-pem-tls"] = "not-valid-pem-data"

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

	getTLSCert(cfg, printer, "invalid-pem-tls")

	if !exitCalled {
		t.Error("getTLSCert should call exit when the certificate PEM cannot be decoded")
	}
}

func TestGetTLSCert_Error_InvalidCertDER(t *testing.T) {
	invalidPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-valid-certificate-data")})

	mockClient := newMockCertClient()
	mockClient.certificates["invalid-der-tls"] = string(invalidPEM)

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

	getTLSCert(cfg, printer, "invalid-der-tls")

	if !exitCalled {
		t.Error("getTLSCert should call exit when the certificate DER cannot be parsed")
	}
}

func TestGetTLSCert_Error_InvalidChainPEM(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})

	mockClient := newMockCertClient()
	mockClient.certificates["invalid-chain-tls"] = string(certPEM)
	mockClient.tlsChains["invalid-chain-tls"] = "not-valid-pem-data"

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

	getTLSCert(cfg, printer, "invalid-chain-tls")

	if !exitCalled {
		t.Error("getTLSCert should call exit when the chain PEM cannot be decoded")
	}
}

// =============================================================================
// tlsGetCmd.Run Tests
// =============================================================================

func TestTLSGetCmd_Run_Success(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})

	mockClient := newMockCertClient()
	mockClient.certificates["run-tls-key"] = string(certPEM)

	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}
	withGlobalConfig(t, cfg)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	captureStdout(t, func() {
		tlsGetCmd.Run(tlsGetCmd, []string{"run-tls-key"})
	})

	if exitCalled {
		t.Error("tlsGetCmd.Run should not call exit on success")
	}
}

func TestTLSGetCmd_Run_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return nil, errors.New("client creation failed")
	}
	withGlobalConfig(t, cfg)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	captureStdout(t, func() {
		tlsGetCmd.Run(tlsGetCmd, []string{"missing-key"})
	})

	if !exitCalled {
		t.Error("tlsGetCmd.Run should call exit when client creation fails")
	}
}
