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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

func TestTLSGetCmd_HasFlags(t *testing.T) {
	flags := tlsGetCmd.Flags()

	expectedFlags := []string{
		"key-type",
		"key-algorithm",
		"key-size",
		"curve",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on tlsGetCmd", flag)
		}
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

func TestTLSGetCmd_FlagDefaults(t *testing.T) {
	flags := tlsGetCmd.Flags()

	// Check default values
	keyTypeFlag := flags.Lookup("key-type")
	if keyTypeFlag.DefValue != "tls" {
		t.Errorf("key-type default = %v, want tls", keyTypeFlag.DefValue)
	}

	keyAlgFlag := flags.Lookup("key-algorithm")
	if keyAlgFlag.DefValue != "rsa" {
		t.Errorf("key-algorithm default = %v, want rsa", keyAlgFlag.DefValue)
	}

	keySizeFlag := flags.Lookup("key-size")
	if keySizeFlag.DefValue != "2048" {
		t.Errorf("key-size default = %v, want 2048", keySizeFlag.DefValue)
	}

	curveFlag := flags.Lookup("curve")
	if curveFlag.DefValue != "P-256" {
		t.Errorf("curve default = %v, want P-256", curveFlag.DefValue)
	}
}

// =============================================================================
// getTLSCertLocal Tests - Success Paths
// =============================================================================

func TestGetTLSCertLocal_Success_RSA_TextOutput(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test CA and certificate
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	// Generate an RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create mock backend with the key
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.StoreKey("test-tls-key", rsaKey)

	// Create config with mock backend
	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	// Store the certificate using real cert storage
	storageBackend, err := file.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage backend: %v", err)
	}
	certStorage := storage.NewCertAdapter(storageBackend)
	if err := certStorage.SaveCert(context.Background(), "test-tls-key", ca.Cert); err != nil {
		t.Fatalf("failed to save certificate: %v", err)
	}

	// Set up global config for error output
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	// Create printer with buffer
	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	// Capture exit
	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "test-tls-key", "tls", "rsa", 2048, "P-256")
	})

	// Should not exit on success
	if exitCode != -1 {
		t.Errorf("expected no exit on success, got exit code %d", exitCode)
	}

	// Verify output contains TLS certificate info
	output := buf.String()
	if !strings.Contains(output, "TLS Certificate") {
		t.Errorf("expected TLS Certificate output, got: %s", output)
	}
}

func TestGetTLSCertLocal_Success_ECDSA_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test CA
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	// Generate an ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// Create mock backend with the key
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.StoreKey("test-ecdsa-tls", ecKey)

	// Create config with mock backend
	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "json"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	// Store the certificate
	storageBackend, err := file.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage backend: %v", err)
	}
	certStorage := storage.NewCertAdapter(storageBackend)
	if err := certStorage.SaveCert(context.Background(), "test-ecdsa-tls", ca.Cert); err != nil {
		t.Fatalf("failed to save certificate: %v", err)
	}

	// Set up global config
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	// Create printer
	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	// Capture exit
	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "test-ecdsa-tls", "tls", "ecdsa", 0, "P-256")
	})

	if exitCode != -1 {
		t.Errorf("expected no exit on success, got exit code %d", exitCode)
	}

	// Verify JSON output
	output := buf.String()
	if !strings.Contains(output, "subject") {
		t.Errorf("expected JSON with subject field, got: %s", output)
	}
}

func TestGetTLSCertLocal_Success_WithCertChain(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test CA and server certificate
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	// Create mock backend with the server key
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.StoreKey("test-chain-key", serverCert.Key)

	// Create config with mock backend
	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	// Store the certificate and chain
	storageBackend, err := file.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage backend: %v", err)
	}
	certStorage := storage.NewCertAdapter(storageBackend)
	if err := certStorage.SaveCert(context.Background(), "test-chain-key", serverCert.Cert); err != nil {
		t.Fatalf("failed to save certificate: %v", err)
	}
	// Save the CA as the chain
	chain := []*x509.Certificate{ca.Cert}
	if err := certStorage.SaveCertChain(context.Background(), "test-chain-key", chain); err != nil {
		t.Fatalf("failed to save certificate chain: %v", err)
	}

	// Set up global config
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	// Create printer
	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	// Capture exit
	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "test-chain-key", "tls", "ecdsa", 0, "P-256")
	})

	if exitCode != -1 {
		t.Errorf("expected no exit on success, got exit code %d", exitCode)
	}

	// Verify output mentions chain
	output := buf.String()
	if !strings.Contains(output, "Chain") {
		t.Errorf("expected Chain info in output, got: %s", output)
	}
}

// =============================================================================
// getTLSCertLocal Tests - Error Paths
// =============================================================================

func TestGetTLSCertLocal_Error_BackendCreation(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return nil, fmt.Errorf("backend creation failed")
	}

	// Set up global config
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	printer := NewPrinter(cfg.OutputFormat, io.Discard)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "P-256")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for backend creation failure, got %d", exitCode)
	}
}

func TestGetTLSCertLocal_Error_CertStorageCreation(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()

	cfg := NewConfig()
	// Use /dev/null/invalid - /dev/null is a file, not a directory, so this will fail
	cfg.KeyDir = "/dev/null/invalid/path"
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	// Set up global config
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	printer := NewPrinter(cfg.OutputFormat, io.Discard)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "P-256")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for cert storage creation failure, got %d", exitCode)
	}
}

func TestGetTLSCertLocal_Error_InvalidKeyType(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid mock backend
	mockBackend := mocks.NewExtendedMockBackend()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	// Set up global config
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	printer := NewPrinter(cfg.OutputFormat, io.Discard)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "test-key", "invalid-type", "rsa", 2048, "P-256")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid key type, got %d", exitCode)
	}
}

func TestGetTLSCertLocal_Error_InvalidKeyAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()

	mockBackend := mocks.NewExtendedMockBackend()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	printer := NewPrinter(cfg.OutputFormat, io.Discard)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "test-key", "tls", "invalid-algorithm", 2048, "P-256")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid key algorithm, got %d", exitCode)
	}
}

func TestGetTLSCertLocal_Error_KeyNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	// Create mock backend without any keys
	mockBackend := mocks.NewExtendedMockBackend()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	// Set up global config
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	printer := NewPrinter(cfg.OutputFormat, io.Discard)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "non-existent-key", "tls", "rsa", 2048, "P-256")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for key not found, got %d", exitCode)
	}
}

func TestGetTLSCertLocal_Error_CertNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create mock backend with the key but NO certificate
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.StoreKey("key-no-cert", rsaKey)

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	// Set up global config
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	printer := NewPrinter(cfg.OutputFormat, io.Discard)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "key-no-cert", "tls", "rsa", 2048, "P-256")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for certificate not found, got %d", exitCode)
	}
}

func TestGetTLSCertLocal_Error_GetKeyFails(t *testing.T) {
	tmpDir := t.TempDir()

	// Create mock backend that returns error on GetKey
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, fmt.Errorf("get key operation failed")
	}

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	// Set up global config
	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	printer := NewPrinter(cfg.OutputFormat, io.Discard)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "P-256")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for GetKey failure, got %d", exitCode)
	}
}

// =============================================================================
// getTLSCertLocal Tests - Output Format Variations
// =============================================================================

func TestGetTLSCertLocal_TableOutput(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.StoreKey("table-output-key", rsaKey)

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "table"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	// Store the certificate
	storageBackend, err := file.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage backend: %v", err)
	}
	certStorage := storage.NewCertAdapter(storageBackend)
	if err := certStorage.SaveCert(context.Background(), "table-output-key", ca.Cert); err != nil {
		t.Fatalf("failed to save certificate: %v", err)
	}

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "table-output-key", "tls", "rsa", 2048, "P-256")
	})

	if exitCode != -1 {
		t.Errorf("expected no exit on success, got exit code %d", exitCode)
	}
}

func TestGetTLSCertLocal_VerboseMode(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.StoreKey("verbose-key", rsaKey)

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Verbose = true
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	storageBackend, err := file.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage backend: %v", err)
	}
	certStorage := storage.NewCertAdapter(storageBackend)
	if err := certStorage.SaveCert(context.Background(), "verbose-key", ca.Cert); err != nil {
		t.Fatalf("failed to save certificate: %v", err)
	}

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "verbose-key", "tls", "rsa", 2048, "P-256")
	})

	if exitCode != -1 {
		t.Errorf("expected no exit on success, got exit code %d", exitCode)
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestGetTLSCertLocal_CertChainNotFound_ContinuesSuccessfully(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.StoreKey("no-chain-key", rsaKey)

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Verbose = true // Enable verbose to see chain not found message
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	// Store certificate but NOT the chain
	storageBackend, err := file.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage backend: %v", err)
	}
	certStorage := storage.NewCertAdapter(storageBackend)
	if err := certStorage.SaveCert(context.Background(), "no-chain-key", ca.Cert); err != nil {
		t.Fatalf("failed to save certificate: %v", err)
	}

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "no-chain-key", "tls", "rsa", 2048, "P-256")
	})

	// Should succeed even without chain (chain is optional)
	if exitCode != -1 {
		t.Errorf("expected no exit on success (chain optional), got exit code %d", exitCode)
	}

	// Output should still contain TLS info
	output := buf.String()
	if !strings.Contains(output, "TLS Certificate") {
		t.Errorf("expected TLS Certificate output even without chain, got: %s", output)
	}
}

func TestGetTLSCertLocal_JSONOutput_WithChain(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.StoreKey("json-chain-key", serverCert.Key)

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "json"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	storageBackend, err := file.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage backend: %v", err)
	}
	certStorage := storage.NewCertAdapter(storageBackend)
	if err := certStorage.SaveCert(context.Background(), "json-chain-key", serverCert.Cert); err != nil {
		t.Fatalf("failed to save certificate: %v", err)
	}
	chain := []*x509.Certificate{ca.Cert}
	if err := certStorage.SaveCertChain(context.Background(), "json-chain-key", chain); err != nil {
		t.Fatalf("failed to save certificate chain: %v", err)
	}

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "json-chain-key", "tls", "ecdsa", 0, "P-256")
	})

	if exitCode != -1 {
		t.Errorf("expected no exit on success, got exit code %d", exitCode)
	}

	output := buf.String()
	// JSON output should contain chain info when chain is present
	if !strings.Contains(output, "chain") {
		t.Errorf("expected chain in JSON output, got: %s", output)
	}
}

// =============================================================================
// Tests for Different Key Types
// =============================================================================

func TestGetTLSCertLocal_Success_SigningKeyType(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.StoreKey("signing-key", ecKey)

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	storageBackend, err := file.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage backend: %v", err)
	}
	certStorage := storage.NewCertAdapter(storageBackend)
	if err := certStorage.SaveCert(context.Background(), "signing-key", ca.Cert); err != nil {
		t.Fatalf("failed to save certificate: %v", err)
	}

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "signing-key", "signing", "ecdsa", 0, "P-384")
	})

	if exitCode != -1 {
		t.Errorf("expected no exit on success, got exit code %d", exitCode)
	}
}

func TestGetTLSCertLocal_Success_EncryptionKeyType(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.StoreKey("encryption-key", rsaKey)

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	storageBackend, err := file.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage backend: %v", err)
	}
	certStorage := storage.NewCertAdapter(storageBackend)
	if err := certStorage.SaveCert(context.Background(), "encryption-key", ca.Cert); err != nil {
		t.Fatalf("failed to save certificate: %v", err)
	}

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	var buf bytes.Buffer
	printer := NewPrinter(cfg.OutputFormat, &buf)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "encryption-key", "encryption", "rsa", 2048, "P-256")
	})

	if exitCode != -1 {
		t.Errorf("expected no exit on success, got exit code %d", exitCode)
	}
}

func TestGetTLSCertLocal_Error_InvalidCurve(t *testing.T) {
	tmpDir := t.TempDir()

	mockBackend := mocks.NewExtendedMockBackend()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	printer := NewPrinter(cfg.OutputFormat, io.Discard)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "test-key", "tls", "ecdsa", 0, "invalid-curve")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid curve, got %d", exitCode)
	}
}

func TestGetTLSCertLocal_Error_RSAKeyTooSmall(t *testing.T) {
	tmpDir := t.TempDir()

	mockBackend := mocks.NewExtendedMockBackend()

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	originalGlobalConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = originalGlobalConfig }()

	printer := NewPrinter(cfg.OutputFormat, io.Discard)

	exitCode := captureExit(t, func() {
		getTLSCertLocal(cfg, printer, "test-key", "tls", "rsa", 1024, "")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for RSA key too small, got %d", exitCode)
	}
}

// ErrMockWriter is an io.Writer that always returns an error
type ErrMockWriter struct{}

func (e *ErrMockWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("mock write error")
}
