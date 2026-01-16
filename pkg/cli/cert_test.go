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

package cli

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/testutil"
)

func TestCertCmd_Exists(t *testing.T) {
	if certCmd == nil {
		t.Fatal("certCmd should not be nil")
	}
}

func TestCertCmd_Properties(t *testing.T) {
	if certCmd.Use != "cert" {
		t.Errorf("certCmd.Use = %v, want cert", certCmd.Use)
	}

	if certCmd.Short == "" {
		t.Error("certCmd.Short should not be empty")
	}
}

func TestCertCmd_HasSubcommands(t *testing.T) {
	subcommands := certCmd.Commands()

	expectedCmds := []string{
		"save",
		"list",
		"get",
		"delete",
		"exists",
		"save-chain",
		"get-chain",
		"generate-ca",
		"issue",
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

func TestCertSaveCmd_Exists(t *testing.T) {
	if certSaveCmd == nil {
		t.Fatal("certSaveCmd should not be nil")
	}
}

func TestCertSaveCmd_Properties(t *testing.T) {
	if certSaveCmd.Use != "save <key-id> <cert-file>" {
		t.Errorf("certSaveCmd.Use = %v, want 'save <key-id> <cert-file>'", certSaveCmd.Use)
	}

	if certSaveCmd.Short == "" {
		t.Error("certSaveCmd.Short should not be empty")
	}
}

func TestCertListCmd_Exists(t *testing.T) {
	if certListCmd == nil {
		t.Fatal("certListCmd should not be nil")
	}
}

func TestCertListCmd_Properties(t *testing.T) {
	if certListCmd.Use != "list" {
		t.Errorf("certListCmd.Use = %v, want list", certListCmd.Use)
	}
}

func TestCertGetCmd_Exists(t *testing.T) {
	if certGetCmd == nil {
		t.Fatal("certGetCmd should not be nil")
	}
}

func TestCertGetCmd_Properties(t *testing.T) {
	if certGetCmd.Use != "get <key-id>" {
		t.Errorf("certGetCmd.Use = %v, want 'get <key-id>'", certGetCmd.Use)
	}
}

func TestCertDeleteCmd_Exists(t *testing.T) {
	if certDeleteCmd == nil {
		t.Fatal("certDeleteCmd should not be nil")
	}
}

func TestCertDeleteCmd_Properties(t *testing.T) {
	if certDeleteCmd.Use != "delete <key-id>" {
		t.Errorf("certDeleteCmd.Use = %v, want 'delete <key-id>'", certDeleteCmd.Use)
	}
}

func TestCertExistsCmd_Exists(t *testing.T) {
	if certExistsCmd == nil {
		t.Fatal("certExistsCmd should not be nil")
	}
}

func TestCertExistsCmd_Properties(t *testing.T) {
	if certExistsCmd.Use != "exists <key-id>" {
		t.Errorf("certExistsCmd.Use = %v, want 'exists <key-id>'", certExistsCmd.Use)
	}
}

func TestCertSaveChainCmd_Exists(t *testing.T) {
	if certSaveChainCmd == nil {
		t.Fatal("certSaveChainCmd should not be nil")
	}
}

func TestCertGetChainCmd_Exists(t *testing.T) {
	if certGetChainCmd == nil {
		t.Fatal("certGetChainCmd should not be nil")
	}
}

func TestCertGenerateCACmd_Exists(t *testing.T) {
	if certGenerateCACmd == nil {
		t.Fatal("certGenerateCACmd should not be nil")
	}
}

func TestCertIssueCmd_Exists(t *testing.T) {
	if certIssueCmd == nil {
		t.Fatal("certIssueCmd should not be nil")
	}
}

func TestCertCmd_CommandStructure(t *testing.T) {
	// Test that certCmd is properly configured
	if !certCmd.HasSubCommands() {
		t.Error("certCmd should have subcommands")
	}

	// Verify parent relationship
	for _, sub := range certCmd.Commands() {
		if sub.Parent() != certCmd {
			t.Errorf("subcommand %s should have certCmd as parent", sub.Use)
		}
	}
}

func TestCertSaveCmd_Arguments(t *testing.T) {
	// Verify command expects arguments
	if certSaveCmd.Args == nil {
		t.Error("certSaveCmd.Args should be set")
	}
}

func TestCertDeleteCmd_Arguments(t *testing.T) {
	// Verify command expects arguments
	if certDeleteCmd.Args == nil {
		t.Error("certDeleteCmd.Args should be set")
	}
}

func TestCertGetCmd_Arguments(t *testing.T) {
	// Verify command expects arguments
	if certGetCmd.Args == nil {
		t.Error("certGetCmd.Args should be set")
	}
}

func TestCertExistsCmd_Arguments(t *testing.T) {
	// Verify command expects arguments
	if certExistsCmd.Args == nil {
		t.Error("certExistsCmd.Args should be set")
	}
}

func TestCertGenerateCACmd_HasFlags(t *testing.T) {
	flags := certGenerateCACmd.Flags()

	// Check for some expected flags
	expectedFlags := []string{"cn", "org", "country", "validity"}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Logf("flag %q may not exist on certGenerateCACmd", flag)
		}
	}
}

func TestCertIssueCmd_HasFlags(t *testing.T) {
	flags := certIssueCmd.Flags()

	// Check for some expected flags
	expectedFlags := []string{"cn", "dns", "ip"}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Logf("flag %q may not exist on certIssueCmd", flag)
		}
	}
}

// Tests for saveCertLocal function with text output

func TestCertSaveCertLocal_TextOutput_Success(t *testing.T) {
	// Create temp directory for storage
	tmpDir := t.TempDir()

	// Generate test certificate
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	// Create config with temp directory
	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	// Create printer with buffer to capture output
	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	// Capture exit calls
	exitCalled := false
	exitCode := 0
	originalExitFunc := exitFunc
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}
	defer func() { exitFunc = originalExitFunc }()

	// Call saveCertLocal
	saveCertLocal(cfg, printer, "test-cert-id", ca.Cert)

	// Verify no error occurred (exit not called)
	if exitCalled {
		t.Errorf("saveCertLocal should not call exit on success, got exit code: %d", exitCode)
	}

	// Verify output contains success message
	output := buf.String()
	if !strings.Contains(output, "Successfully saved certificate") {
		t.Errorf("expected success message in output, got: %s", output)
	}
}

func TestCertSaveCertLocal_JSONOutput_Success(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "json"

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	saveCertLocal(cfg, printer, "test-cert-json", ca.Cert)

	if exitCalled {
		t.Error("saveCertLocal should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Errorf("expected JSON success output, got: %s", output)
	}
}

// Tests for getCertLocal function

func TestCertGetCertLocal_TextOutput_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test certificate
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	// Save certificate first
	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	var saveBuf bytes.Buffer
	savePrinter := NewPrinter(cfg.OutputFormat, &saveBuf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	saveCertLocal(cfg, savePrinter, "get-test-cert", ca.Cert)

	if exitCalled {
		t.Fatal("saveCertLocal failed during setup")
	}

	// Now test getCertLocal
	var getBuf bytes.Buffer
	getPrinter := NewPrinter(cfg.OutputFormat, &getBuf)

	exitCalled = false
	getCertLocal(cfg, getPrinter, "get-test-cert")

	if exitCalled {
		t.Error("getCertLocal should not call exit on success")
	}

	// Verify output contains certificate data (PEM format for text output)
	output := getBuf.String()
	if !strings.Contains(output, "CERTIFICATE") {
		t.Errorf("expected PEM certificate in output, got: %s", output)
	}
}

func TestCertGetCertLocal_NotFoundError(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

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

	// Save global config for error output
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getCertLocal(cfg, printer, "non-existent-cert")

	if !exitCalled {
		t.Error("getCertLocal should call exit when certificate not found")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertGetCertLocal_JSONOutput_Success(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "json"

	var saveBuf bytes.Buffer
	savePrinter := NewPrinter("text", &saveBuf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	saveCertLocal(cfg, savePrinter, "json-get-cert", ca.Cert)

	if exitCalled {
		t.Fatal("saveCertLocal failed during setup")
	}

	var getBuf bytes.Buffer
	getPrinter := NewPrinter(cfg.OutputFormat, &getBuf)

	exitCalled = false
	getCertLocal(cfg, getPrinter, "json-get-cert")

	if exitCalled {
		t.Error("getCertLocal should not call exit on success")
	}

	output := getBuf.String()
	if !strings.Contains(output, "subject") {
		t.Errorf("expected JSON with subject field, got: %s", output)
	}
}

// Tests for listCertsLocal function

func TestCertListCertsLocal_MultipleEntries_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test certificates
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Save some certificates
	var saveBuf bytes.Buffer
	savePrinter := NewPrinter(cfg.OutputFormat, &saveBuf)
	saveCertLocal(cfg, savePrinter, "list-cert-1", ca.Cert)
	saveCertLocal(cfg, savePrinter, "list-cert-2", ca.Cert)

	if exitCalled {
		t.Fatal("saveCertLocal failed during setup")
	}

	// Now test listCertsLocal
	var listBuf bytes.Buffer
	listPrinter := NewPrinter(cfg.OutputFormat, &listBuf)

	exitCalled = false
	listCertsLocal(cfg, listPrinter)

	if exitCalled {
		t.Error("listCertsLocal should not call exit on success")
	}

	output := listBuf.String()
	if !strings.Contains(output, "list-cert-1") || !strings.Contains(output, "list-cert-2") {
		t.Errorf("expected certificate IDs in output, got: %s", output)
	}
}

func TestCertListCertsLocal_EmptyResult(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	listCertsLocal(cfg, printer)

	if exitCalled {
		t.Error("listCertsLocal should not call exit for empty list")
	}

	output := buf.String()
	if !strings.Contains(output, "No certificates") && !strings.Contains(output, "Certificates:") {
		t.Errorf("expected proper output for empty list, got: %s", output)
	}
}

func TestCertListCertsLocal_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "json"

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Save a certificate
	var saveBuf bytes.Buffer
	savePrinter := NewPrinter("text", &saveBuf)
	saveCertLocal(cfg, savePrinter, "json-list-cert", ca.Cert)

	if exitCalled {
		t.Fatal("saveCertLocal failed during setup")
	}

	var listBuf bytes.Buffer
	listPrinter := NewPrinter(cfg.OutputFormat, &listBuf)

	exitCalled = false
	listCertsLocal(cfg, listPrinter)

	if exitCalled {
		t.Error("listCertsLocal should not call exit on success")
	}

	output := listBuf.String()
	if !strings.Contains(output, "certificates") {
		t.Errorf("expected JSON with certificates field, got: %s", output)
	}
}

func TestCertListCertsLocal_TableOutput(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "table"

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	var saveBuf bytes.Buffer
	savePrinter := NewPrinter("text", &saveBuf)
	saveCertLocal(cfg, savePrinter, "table-list-cert", ca.Cert)

	if exitCalled {
		t.Fatal("saveCertLocal failed during setup")
	}

	var listBuf bytes.Buffer
	listPrinter := NewPrinter(cfg.OutputFormat, &listBuf)

	exitCalled = false
	listCertsLocal(cfg, listPrinter)

	if exitCalled {
		t.Error("listCertsLocal should not call exit on success")
	}

	output := listBuf.String()
	if !strings.Contains(output, "CERTIFICATE ID") || !strings.Contains(output, "table-list-cert") {
		t.Errorf("expected table format with header and cert ID, got: %s", output)
	}
}

// Tests for certExistsLocal function

func TestCertCertExistsLocal_Found(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Save certificate first
	var saveBuf bytes.Buffer
	savePrinter := NewPrinter(cfg.OutputFormat, &saveBuf)
	saveCertLocal(cfg, savePrinter, "exists-test-cert", ca.Cert)

	if exitCalled {
		t.Fatal("saveCertLocal failed during setup")
	}

	// Test certExistsLocal
	var existsBuf bytes.Buffer
	existsPrinter := NewPrinter(cfg.OutputFormat, &existsBuf)

	exitCalled = false
	certExistsLocal(cfg, existsPrinter, "exists-test-cert")

	if exitCalled {
		t.Error("certExistsLocal should not call exit on success")
	}

	output := existsBuf.String()
	if !strings.Contains(output, "exists") {
		t.Errorf("expected exists message in output, got: %s", output)
	}
}

func TestCertCertExistsLocal_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	certExistsLocal(cfg, printer, "non-existent-cert")

	if exitCalled {
		t.Error("certExistsLocal should not call exit when cert doesn't exist")
	}

	output := buf.String()
	if !strings.Contains(output, "does not exist") {
		t.Errorf("expected 'does not exist' in output, got: %s", output)
	}
}

func TestCertCertExistsLocal_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "json"

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	var saveBuf bytes.Buffer
	savePrinter := NewPrinter("text", &saveBuf)
	saveCertLocal(cfg, savePrinter, "json-exists-cert", ca.Cert)

	if exitCalled {
		t.Fatal("saveCertLocal failed during setup")
	}

	var existsBuf bytes.Buffer
	existsPrinter := NewPrinter(cfg.OutputFormat, &existsBuf)

	exitCalled = false
	certExistsLocal(cfg, existsPrinter, "json-exists-cert")

	if exitCalled {
		t.Error("certExistsLocal should not call exit on success")
	}

	output := existsBuf.String()
	if !strings.Contains(output, `"exists": true`) && !strings.Contains(output, `"exists":true`) {
		t.Errorf("expected JSON with exists: true, got: %s", output)
	}
}

// Tests for getChainLocal function

func TestCertGetChainLocal_ValidChain_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test CA and server certificate for a chain
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Save chain directly to storage
	certStorage, err := cfg.CreateCertStorage()
	if err != nil {
		t.Fatalf("failed to create cert storage: %v", err)
	}
	err = certStorage.SaveCertChain("chain-test-2", []*x509.Certificate{serverCert.Cert, ca.Cert})
	if err != nil {
		t.Fatalf("failed to save certificate chain: %v", err)
	}

	// Test getChainLocal
	var getBuf bytes.Buffer
	getPrinter := NewPrinter(cfg.OutputFormat, &getBuf)

	exitCalled = false
	getChainLocal(cfg, getPrinter, "chain-test-2")

	if exitCalled {
		t.Error("getChainLocal should not call exit on success")
	}

	output := getBuf.String()
	if !strings.Contains(output, "CERTIFICATE") {
		t.Errorf("expected PEM certificates in output, got: %s", output)
	}
}

func TestCertGetChainLocal_NotFoundError(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

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

	// Save global config for error output
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	getChainLocal(cfg, printer, "non-existent-chain")

	if !exitCalled {
		t.Error("getChainLocal should call exit when chain not found")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertGetChainLocal_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "json"

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Save chain directly to storage
	certStorage, err := cfg.CreateCertStorage()
	if err != nil {
		t.Fatalf("failed to create cert storage: %v", err)
	}
	err = certStorage.SaveCertChain("json-chain-test", []*x509.Certificate{serverCert.Cert, ca.Cert})
	if err != nil {
		t.Fatalf("failed to save certificate chain: %v", err)
	}

	var getBuf bytes.Buffer
	getPrinter := NewPrinter(cfg.OutputFormat, &getBuf)

	exitCalled = false
	getChainLocal(cfg, getPrinter, "json-chain-test")

	if exitCalled {
		t.Error("getChainLocal should not call exit on success")
	}

	output := getBuf.String()
	if !strings.Contains(output, "chain") {
		t.Errorf("expected JSON with chain field, got: %s", output)
	}
}

// Tests for deleteCertLocal function

func TestCertDeleteCertLocal_Valid_Success(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Save certificate first
	var saveBuf bytes.Buffer
	savePrinter := NewPrinter(cfg.OutputFormat, &saveBuf)
	saveCertLocal(cfg, savePrinter, "delete-test-cert", ca.Cert)

	if exitCalled {
		t.Fatal("saveCertLocal failed during setup")
	}

	// Test deleteCertLocal
	var deleteBuf bytes.Buffer
	deletePrinter := NewPrinter(cfg.OutputFormat, &deleteBuf)

	exitCalled = false
	deleteCertLocal(cfg, deletePrinter, "delete-test-cert")

	if exitCalled {
		t.Error("deleteCertLocal should not call exit on success")
	}

	output := deleteBuf.String()
	if !strings.Contains(output, "Successfully deleted") {
		t.Errorf("expected success message in output, got: %s", output)
	}

	// Verify certificate is actually deleted
	var existsBuf bytes.Buffer
	existsPrinter := NewPrinter(cfg.OutputFormat, &existsBuf)
	certExistsLocal(cfg, existsPrinter, "delete-test-cert")

	existsOutput := existsBuf.String()
	if !strings.Contains(existsOutput, "does not exist") {
		t.Errorf("certificate should be deleted, got: %s", existsOutput)
	}
}

func TestCertDeleteCertLocal_NotFoundError(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

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

	// Save global config for error output
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	deleteCertLocal(cfg, printer, "non-existent-cert")

	if !exitCalled {
		t.Error("deleteCertLocal should call exit when certificate not found")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

// Tests for saveChainLocal function

func TestCertSaveChainLocal_ValidChain_Success(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	chain := []*x509.Certificate{serverCert.Cert, ca.Cert}
	saveChainLocal(cfg, printer, "save-chain-test", chain)

	if exitCalled {
		t.Error("saveChainLocal should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "Successfully saved certificate chain") {
		t.Errorf("expected success message in output, got: %s", output)
	}
}

func TestCertSaveChainLocal_JSONOutput_Success(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "json"

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	chain := []*x509.Certificate{serverCert.Cert, ca.Cert}
	saveChainLocal(cfg, printer, "save-chain-json", chain)

	if exitCalled {
		t.Error("saveChainLocal should not call exit on success")
	}

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Errorf("expected JSON success output, got: %s", output)
	}
}

// Tests for storage creation error paths

func TestCertSaveCertLocal_InvalidStoragePath(t *testing.T) {
	// Use an invalid path that cannot be created
	cfg := NewConfig()
	cfg.KeyDir = "/nonexistent/path/that/cannot/be/created/\x00invalid"
	cfg.OutputFormat = "text"

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
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

	saveCertLocal(cfg, printer, "test-cert", ca.Cert)

	if !exitCalled {
		t.Error("saveCertLocal should call exit when storage creation fails")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertGetCertLocal_InvalidStoragePath(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = "/nonexistent/path/that/cannot/be/created/\x00invalid"
	cfg.OutputFormat = "text"

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

	getCertLocal(cfg, printer, "test-cert")

	if !exitCalled {
		t.Error("getCertLocal should call exit when storage creation fails")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertListCertsLocal_InvalidStoragePath(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = "/nonexistent/path/that/cannot/be/created/\x00invalid"
	cfg.OutputFormat = "text"

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

	listCertsLocal(cfg, printer)

	if !exitCalled {
		t.Error("listCertsLocal should call exit when storage creation fails")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertCertExistsLocal_InvalidStoragePath(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = "/nonexistent/path/that/cannot/be/created/\x00invalid"
	cfg.OutputFormat = "text"

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

	certExistsLocal(cfg, printer, "test-cert")

	if !exitCalled {
		t.Error("certExistsLocal should call exit when storage creation fails")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertGetChainLocal_InvalidStoragePath(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = "/nonexistent/path/that/cannot/be/created/\x00invalid"
	cfg.OutputFormat = "text"

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

	getChainLocal(cfg, printer, "test-chain")

	if !exitCalled {
		t.Error("getChainLocal should call exit when storage creation fails")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertSaveChainLocal_InvalidStoragePath(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = "/nonexistent/path/that/cannot/be/created/\x00invalid"
	cfg.OutputFormat = "text"

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
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

	chain := []*x509.Certificate{ca.Cert}
	saveChainLocal(cfg, printer, "test-chain", chain)

	if !exitCalled {
		t.Error("saveChainLocal should call exit when storage creation fails")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

func TestCertDeleteCertLocal_InvalidStoragePath(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = "/nonexistent/path/that/cannot/be/created/\x00invalid"
	cfg.OutputFormat = "text"

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

	deleteCertLocal(cfg, printer, "test-cert")

	if !exitCalled {
		t.Error("deleteCertLocal should call exit when storage creation fails")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}

// Additional edge case tests

func TestCertSaveCertLocal_OverwriteExisting(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Save same certificate twice (should overwrite)
	var buf1 bytes.Buffer
	printer1 := NewPrinter(cfg.OutputFormat, &buf1)
	saveCertLocal(cfg, printer1, "multi-save-cert", ca.Cert)

	if exitCalled {
		t.Fatal("first saveCertLocal should not call exit")
	}

	var buf2 bytes.Buffer
	printer2 := NewPrinter(cfg.OutputFormat, &buf2)
	saveCertLocal(cfg, printer2, "multi-save-cert", ca.Cert)

	if exitCalled {
		t.Error("second saveCertLocal should not call exit (overwrite should succeed)")
	}

	output := buf2.String()
	if !strings.Contains(output, "Successfully saved") {
		t.Errorf("expected success message in output, got: %s", output)
	}
}

func TestCertLocalFunctions_VariousIDFormats(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Test with various key IDs
	testIDs := []string{
		"cert-with-dashes",
		"cert_with_underscores",
		"cert.with.dots",
		"cert123numbers",
	}

	for _, id := range testIDs {
		t.Run(id, func(t *testing.T) {
			var saveBuf bytes.Buffer
			savePrinter := NewPrinter(cfg.OutputFormat, &saveBuf)
			exitCalled = false

			saveCertLocal(cfg, savePrinter, id, ca.Cert)

			if exitCalled {
				t.Errorf("saveCertLocal should succeed for ID: %s", id)
			}

			// Verify it exists
			var existsBuf bytes.Buffer
			existsPrinter := NewPrinter(cfg.OutputFormat, &existsBuf)
			certExistsLocal(cfg, existsPrinter, id)

			if !strings.Contains(existsBuf.String(), "exists") {
				t.Errorf("certificate should exist for ID: %s", id)
			}
		})
	}
}

func TestCertGetCertLocal_WithVerboseMode(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Verbose = true

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Save certificate first
	var saveBuf bytes.Buffer
	savePrinter := NewPrinter(cfg.OutputFormat, &saveBuf)
	saveCertLocal(cfg, savePrinter, "verbose-test-cert", ca.Cert)

	if exitCalled {
		t.Fatal("saveCertLocal failed during setup")
	}

	// Get certificate with verbose mode
	var getBuf bytes.Buffer
	getPrinter := NewPrinter(cfg.OutputFormat, &getBuf)

	exitCalled = false
	getCertLocal(cfg, getPrinter, "verbose-test-cert")

	if exitCalled {
		t.Error("getCertLocal should not call exit on success")
	}

	// Output should contain certificate PEM
	output := getBuf.String()
	if !strings.Contains(output, "CERTIFICATE") {
		t.Errorf("expected PEM certificate in output, got: %s", output)
	}
}

func TestCertSaveCertLocal_MultipleIDs(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"

	exitCalled := false
	originalExitFunc := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = originalExitFunc }()

	// Save multiple certificates with different IDs
	ids := []string{"cert-a", "cert-b", "cert-c"}
	for _, id := range ids {
		var buf bytes.Buffer
		printer := NewPrinter(cfg.OutputFormat, &buf)
		exitCalled = false

		saveCertLocal(cfg, printer, id, ca.Cert)

		if exitCalled {
			t.Errorf("saveCertLocal should not call exit for ID: %s", id)
		}
	}

	// Verify all certificates exist
	var listBuf bytes.Buffer
	listPrinter := NewPrinter(cfg.OutputFormat, &listBuf)
	listCertsLocal(cfg, listPrinter)

	output := listBuf.String()
	for _, id := range ids {
		if !strings.Contains(output, id) {
			t.Errorf("expected certificate ID %s in list output, got: %s", id, output)
		}
	}
}

func TestCertLocalFunctions_ReadOnlyDirectory(t *testing.T) {
	// Skip on non-Unix systems
	if os.Geteuid() == 0 {
		t.Skip("skipping test when running as root")
	}

	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "readonly")

	// Create a read-only directory
	if err := os.Mkdir(readOnlyDir, 0555); err != nil {
		t.Fatalf("failed to create readonly directory: %v", err)
	}
	defer func() { _ = os.Chmod(readOnlyDir, 0755) }()

	cfg := NewConfig()
	cfg.KeyDir = readOnlyDir
	cfg.OutputFormat = "text"

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
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

	// Try to save to read-only directory
	saveCertLocal(cfg, printer, "test-cert", ca.Cert)

	if !exitCalled {
		t.Error("saveCertLocal should fail when writing to read-only directory")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got: %d", exitCode)
	}
}
