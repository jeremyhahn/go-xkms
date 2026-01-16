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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
)

// =============================================================================
// Helper functions for import/copy/unwrap tests
// =============================================================================

func createImportTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.OutputFormat = "text"
	cfg.UseLocal = true
	return cfg
}

func createImportTestPrinter(t *testing.T) (*Printer, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	return printer, buf
}

func createImportTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Import Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		DNSNames:  []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// =============================================================================
// Test saveCertLocal - additional coverage
// =============================================================================

func TestSaveCertLocalImportSuccess(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)

	cert := createImportTestCert(t)
	keyID := "save-cert-import-test-key"

	saveCertLocal(cfg, printer, keyID, cert)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from saveCertLocal")
	}
}

func TestSaveCertLocalMultipleImport(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)

	// Save multiple certificates
	for i := 0; i < 3; i++ {
		cert := createImportTestCert(t)
		keyID := "save-cert-import-multi-" + string(rune('a'+i))
		buf.Reset()
		saveCertLocal(cfg, printer, keyID, cert)

		output := buf.String()
		if output == "" {
			t.Errorf("Expected output from saveCertLocal for key %s", keyID)
		}
	}
}

// =============================================================================
// Test deleteCertLocal - additional coverage
// =============================================================================

func TestDeleteCertLocalImportSuccess(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)

	// First save a certificate
	cert := createImportTestCert(t)
	keyID := "delete-cert-import-test-key"
	saveCertLocal(cfg, printer, keyID, cert)
	buf.Reset()

	// Now delete it
	deleteCertLocal(cfg, printer, keyID)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from deleteCertLocal")
	}
}

func TestDeleteCertLocalMultipleImport(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)

	// Save and then delete multiple certificates
	keyIDs := []string{"delete-cert-import-a", "delete-cert-import-b", "delete-cert-import-c"}
	for _, keyID := range keyIDs {
		cert := createImportTestCert(t)
		saveCertLocal(cfg, printer, keyID, cert)
	}

	// Delete them
	for _, keyID := range keyIDs {
		buf.Reset()
		deleteCertLocal(cfg, printer, keyID)

		output := buf.String()
		if output == "" {
			t.Errorf("Expected output from deleteCertLocal for key %s", keyID)
		}
	}
}

// =============================================================================
// Test saveChainLocal - additional coverage
// =============================================================================

func TestSaveChainLocalImportSuccess(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)

	cert := createImportTestCert(t)
	chain := []*x509.Certificate{cert}
	keyID := "save-chain-import-test-key"

	saveChainLocal(cfg, printer, keyID, chain)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from saveChainLocal")
	}
}

func TestSaveChainLocalMultipleCertsImport(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)

	// Create a chain with multiple certificates
	cert1 := createImportTestCert(t)
	cert2 := createImportTestCert(t)
	cert3 := createImportTestCert(t)
	chain := []*x509.Certificate{cert1, cert2, cert3}
	keyID := "save-chain-import-multi-key"

	saveChainLocal(cfg, printer, keyID, chain)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from saveChainLocal")
	}
}

// =============================================================================
// Test wrapKeyLocal - additional coverage for key wrapping
// =============================================================================

func TestWrapKeyLocalWithRSAOAEP(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "wrapped-rsa-oaep.json")

	// Create test key material
	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	// Create wrapping key
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate wrapping key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &wrappingKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	wrapKeyLocal(cfg, printer, keyMaterial, params, outputFile)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from wrapKeyLocal")
	}

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Wrapped key file was not created")
	}
}

func TestWrapKeyLocalWithRSAOAEPSHA1(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "wrapped-rsa-oaep-sha1.json")

	// Create test key material
	keyMaterial := make([]byte, 16) // Smaller key for SHA-1
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	// Create wrapping key
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate wrapping key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &wrappingKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
	}

	wrapKeyLocal(cfg, printer, keyMaterial, params, outputFile)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from wrapKeyLocal")
	}
}

func TestWrapKeyLocalJSONOutput(t *testing.T) {
	cfg := createImportTestConfig(t)
	cfg.OutputFormat = "json"
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)
	outputFile := filepath.Join(t.TempDir(), "wrapped-json.json")

	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate wrapping key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &wrappingKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	wrapKeyLocal(cfg, printer, keyMaterial, params, outputFile)

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from wrapKeyLocal")
	}
}

// =============================================================================
// Test getImportParamsLocal - additional coverage
// =============================================================================

func TestGetImportParamsLocalECDSAImport(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)

	keyID := "import-params-ecdsa-import-key"

	// Generate a key first
	generateKeyLocal(cfg, printer, keyID, "tls", "", "ecdsa", 0, "P-256", false)
	buf.Reset()

	// Get import parameters
	getImportParamsLocal(cfg, printer, keyID, "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getImportParamsLocal")
	}
}

func TestGetImportParamsLocalWithOutputFileImport(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "import-params-import.json")

	keyID := "import-params-file-import-key"

	// Generate a key first
	generateKeyLocal(cfg, printer, keyID, "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get import parameters with output file
	getImportParamsLocal(cfg, printer, keyID, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, outputFile)

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Import params file was not created")
	}
}

func TestGetImportParamsLocalRSAHybrid(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)

	keyID := "import-params-hybrid-key"

	// Generate an RSA key first
	generateKeyLocal(cfg, printer, keyID, "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get import parameters with hybrid algorithm
	getImportParamsLocal(cfg, printer, keyID, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getImportParamsLocal")
	}
}

// =============================================================================
// Test exportKeyLocal - coverage for export operations
// =============================================================================

func TestExportKeyLocalSuccess(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "exported-key.json")

	// First generate an exportable key
	keyID := "export-test-key"
	generateKeyLocal(cfg, printer, keyID, "tls", "", "ecdsa", 0, "P-256", true)
	buf.Reset()

	// Export the key
	exportKeyLocal(cfg, printer, keyID, outputFile, "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from exportKeyLocal")
	}

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Exported key file was not created")
	}
}

func TestExportKeyLocalRSA(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "exported-rsa-key.json")

	// First generate an exportable RSA key
	keyID := "export-rsa-test-key"
	generateKeyLocal(cfg, printer, keyID, "tls", "", "rsa", 2048, "", true)
	buf.Reset()

	// Export the key using hybrid algorithm for RSA
	exportKeyLocal(cfg, printer, keyID, outputFile, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from exportKeyLocal")
	}

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Exported key file was not created")
	}
}

func TestExportKeyLocalEd25519(t *testing.T) {
	cfg := createImportTestConfig(t)
	printer, buf := createImportTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "exported-ed25519-key.json")

	// First generate an exportable Ed25519 key
	keyID := "export-ed25519-test-key"
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ed25519", 0, "", true)
	buf.Reset()

	// Export the key
	exportKeyLocal(cfg, printer, keyID, outputFile, "signing", "ed25519", 0, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from exportKeyLocal")
	}

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Exported key file was not created")
	}
}

func TestExportKeyLocalJSONOutput(t *testing.T) {
	cfg := createImportTestConfig(t)
	cfg.OutputFormat = "json"
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)
	outputFile := filepath.Join(t.TempDir(), "exported-json-key.json")

	// First generate an exportable key
	keyID := "export-json-test-key"
	generateKeyLocal(cfg, printer, keyID, "tls", "", "ecdsa", 0, "P-384", true)
	buf.Reset()

	// Export the key with JSON output
	exportKeyLocal(cfg, printer, keyID, outputFile, "tls", "ecdsa", 0, "P-384", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from exportKeyLocal")
	}
}
