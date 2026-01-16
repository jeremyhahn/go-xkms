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
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
)

// =============================================================================
// Helper functions for local coverage tests
// =============================================================================

func setupLocalCoverageConfig(t *testing.T) *Config {
	t.Helper()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.OutputFormat = "text"
	cfg.UseLocal = true
	return cfg
}

func setupLocalCoveragePrinter(t *testing.T) (*Printer, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	return printer, buf
}

func createLocalCoverageTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Local Coverage Test Certificate",
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
// Test listBackendsLocal error paths
// =============================================================================

func TestCovListBackendsLocal_PrinterErrorPath(t *testing.T) {
	// Create a printer with an invalid format to trigger error path
	printer := NewPrinter("invalid-format", io.Discard)

	// This should handle the printer error from invalid format
	code := captureExit(t, func() {
		listBackendsLocal(printer)
	})

	// Should exit with code 1 when printer fails
	if code != 1 {
		t.Errorf("Expected exit code 1 for printer error, got %d", code)
	}
}

// =============================================================================
// Test backendInfoLocal error paths
// =============================================================================

func TestCovBackendInfoLocal_UnknownBackendError(t *testing.T) {
	printer, _ := setupLocalCoveragePrinter(t)

	code := captureExit(t, func() {
		backendInfoLocal(printer, "completely-unknown-backend-xyz")
	})

	// Should exit with code 1 for unknown backend
	if code != 1 {
		t.Errorf("Expected exit code 1 for unknown backend, got %d", code)
	}
}

func TestCovBackendInfoLocal_PrinterError(t *testing.T) {
	// Create a printer with an invalid format to trigger error path
	printer := NewPrinter("invalid-format", io.Discard)

	code := captureExit(t, func() {
		backendInfoLocal(printer, "software")
	})

	// Should exit with code 1 when printer fails
	if code != 1 {
		t.Errorf("Expected exit code 1 for printer error, got %d", code)
	}
}

func TestCovBackendInfoLocal_AllKnownBackends(t *testing.T) {
	backends := []string{"software", "pkcs8", "pkcs11", "tpm2", "awskms", "gcpkms", "azurekv", "vault"}

	for _, be := range backends {
		t.Run(be, func(t *testing.T) {
			printer, buf := setupLocalCoveragePrinter(t)

			code := captureExit(t, func() {
				backendInfoLocal(printer, be)
			})

			if code != -1 {
				t.Errorf("Expected no exit call for backend %s, got code %d", be, code)
			}

			output := buf.String()
			if output == "" {
				t.Errorf("Expected output for backend %s", be)
			}
		})
	}
}

// =============================================================================
// Test certExistsLocal error paths
// =============================================================================

func TestCovCertExistsLocal_StorageCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = "/dev/null/invalid/path/for/storage"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		certExistsLocal(cfg, printer, "test-cert")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for storage creation error, got %d", code)
	}
}

func TestCovCertExistsLocal_CertExistsSuccess(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer, buf := setupLocalCoveragePrinter(t)

	// Save a cert first
	cert := createLocalCoverageTestCert(t)
	saveCertLocal(cfg, printer, "cov-exists-test-cert", cert)
	buf.Reset()

	// Check if it exists
	code := captureExit(t, func() {
		certExistsLocal(cfg, printer, "cov-exists-test-cert")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output for cert exists check")
	}
}

func TestCovCertExistsLocal_CertNotExists(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer, buf := setupLocalCoveragePrinter(t)

	// Check non-existent cert
	code := captureExit(t, func() {
		certExistsLocal(cfg, printer, "cov-nonexistent-cert-xyz")
	})

	if code != -1 {
		t.Errorf("Expected no exit call, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output for cert not exists check")
	}
}

func TestCovCertExistsLocal_PrinterError(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	// Use invalid format to trigger error path
	printer := NewPrinter("invalid-format", io.Discard)

	code := captureExit(t, func() {
		certExistsLocal(cfg, printer, "test-cert")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for printer error, got %d", code)
	}
}

// =============================================================================
// Test listCertsLocal error paths
// =============================================================================

func TestCovListCertsLocal_StorageCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = "/dev/null/invalid/path/for/storage"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		listCertsLocal(cfg, printer)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for storage creation error, got %d", code)
	}
}

func TestCovListCertsLocal_EmptyList(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer, buf := setupLocalCoveragePrinter(t)

	code := captureExit(t, func() {
		listCertsLocal(cfg, printer)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output for empty cert list")
	}
}

func TestCovListCertsLocal_WithCerts(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer, buf := setupLocalCoveragePrinter(t)

	// Save a few certs
	cert1 := createLocalCoverageTestCert(t)
	cert2 := createLocalCoverageTestCert(t)
	saveCertLocal(cfg, printer, "cov-list-cert-1", cert1)
	saveCertLocal(cfg, printer, "cov-list-cert-2", cert2)
	buf.Reset()

	code := captureExit(t, func() {
		listCertsLocal(cfg, printer)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output for cert list with certs")
	}
}

func TestCovListCertsLocal_PrinterError(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	// Use invalid format to trigger error path
	printer := NewPrinter("invalid-format", io.Discard)

	code := captureExit(t, func() {
		listCertsLocal(cfg, printer)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for printer error, got %d", code)
	}
}

// =============================================================================
// Test openUserStore error paths
// =============================================================================

func TestCovOpenUserStore_FileStorageError(t *testing.T) {
	// Use an invalid path that will fail to create
	invalidPath := "/dev/null/invalid/user/store/path"

	_, err := openUserStore(invalidPath)
	if err == nil {
		t.Error("Expected error for invalid storage path")
	}
}

func TestCovOpenUserStore_Success(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := openUserStore(tmpDir)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if store == nil {
		t.Error("Expected store to be non-nil")
	}
	if store != nil {
		_ = store.Close()
	}
}

// =============================================================================
// Test createSoftwareBackend error paths
// =============================================================================

func TestCovCreateSoftwareBackend_StorageError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = "/dev/null/invalid/path/for/keys"

	_, err := cfg.createSoftwareBackend()
	if err == nil {
		t.Error("Expected error for invalid key directory")
	}
}

func TestCovCreateSoftwareBackend_Success(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()

	be, err := cfg.createSoftwareBackend()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if be == nil {
		t.Error("Expected backend to be non-nil")
	}
	if be != nil {
		_ = be.Close()
	}
}

// =============================================================================
// Test exportKeyLocal error paths
// =============================================================================

func TestCovExportKeyLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)
	outputFile := filepath.Join(t.TempDir(), "exported.json")

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "test-key", outputFile, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestCovExportKeyLocal_InvalidKeyType(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)
	outputFile := filepath.Join(t.TempDir(), "exported.json")

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "test-key", outputFile, "invalid-key-type", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key type, got %d", code)
	}
}

func TestCovExportKeyLocal_KeyMissing(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)
	outputFile := filepath.Join(t.TempDir(), "exported.json")

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "cov-nonexistent-key-xyz", outputFile, "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for key not found, got %d", code)
	}
}

func TestCovExportKeyLocal_WriteFileError(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer, buf := setupLocalCoveragePrinter(t)

	// First generate an exportable key
	keyID := "cov-export-write-error-key"
	generateKeyLocal(cfg, printer, keyID, "tls", "", "ecdsa", 0, "P-256", true)
	buf.Reset()

	// Try to export to a directory that doesn't exist
	invalidOutputFile := "/dev/null/invalid/path/exported.json"

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, keyID, invalidOutputFile, "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for write file error, got %d", code)
	}
}

// =============================================================================
// Test importKeyLocal error paths
// =============================================================================

func TestCovImportKeyLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("test-data"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestCovImportKeyLocal_BadKeyType(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("test-data"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "test-key", "invalid-key-type", "rsa", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key type, got %d", code)
	}
}

func TestCovImportKeyLocal_InvalidWrappedData(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	// Invalid wrapped key data that will fail import
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("invalid-wrapped-data"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "cov-import-invalid-key", "tls", "ecdsa", 0, "P-256", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid wrapped data, got %d", code)
	}
}

// =============================================================================
// Test copyKeyLocal error paths
// =============================================================================

func TestCovCopyKeyLocal_SourceBackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "software", "", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for source backend creation error, got %d", code)
	}
}

func TestCovCopyKeyLocal_InvalidSourceKeyType(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "software", "", "invalid-key-type", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid source key type, got %d", code)
	}
}

func TestCovCopyKeyLocal_SourceKeyMissing(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "cov-nonexistent-source-key-xyz", "dest-key", "software", "", "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for source key not found, got %d", code)
	}
}

func TestCovCopyKeyLocal_DestBackendCreationError(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer, buf := setupLocalCoveragePrinter(t)

	// First generate an exportable key
	keyID := "cov-copy-dest-error-source-key"
	generateKeyLocal(cfg, printer, keyID, "tls", "", "ecdsa", 0, "P-256", true)
	buf.Reset()

	// Try to copy to an invalid destination backend
	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, keyID, "dest-key", "unknown-dest-backend", "", "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for dest backend creation error, got %d", code)
	}
}

func TestCovCopyKeyLocal_ImportError(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer, buf := setupLocalCoveragePrinter(t)

	// First generate an exportable key
	keyID := "cov-copy-dest-import-error-source"
	generateKeyLocal(cfg, printer, keyID, "tls", "", "ecdsa", 0, "P-256", true)
	buf.Reset()

	// The dest key params are derived from source, so we cannot easily test invalid dest key type
	// However, we can test with invalid algorithm that will fail buildKeyAttributesFromFlags
	// for destination. This test will fail at import step with invalid wrapped data.
	destDir := t.TempDir()

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, keyID, "dest-key", "software", destDir, "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	// Expect error because the import will fail (import token mismatch)
	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}
}

// =============================================================================
// Test getImportParamsLocal error paths
// =============================================================================

func TestCovGetImportParamsLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestCovGetImportParamsLocal_InvalidKeyType(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "test-key", "invalid-key-type", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key type, got %d", code)
	}
}

func TestCovGetImportParamsLocal_SuccessPath(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer, buf := setupLocalCoveragePrinter(t)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "cov-import-params-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getImportParamsLocal")
	}
}

func TestCovGetImportParamsLocal_WriteToFile(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer, _ := setupLocalCoveragePrinter(t)
	outputFile := filepath.Join(t.TempDir(), "import-params.json")

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "cov-import-params-file-key", "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, outputFile)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	// Check file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Expected output file to be created")
	}
}

func TestCovGetImportParamsLocal_WriteFileError(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	// Try to write to an invalid path
	invalidOutputFile := "/dev/null/invalid/path/params.json"

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "cov-import-params-write-error-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, invalidOutputFile)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for write file error, got %d", code)
	}
}

func TestCovGetImportParamsLocal_PrinterError(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	// Use invalid format to trigger error path
	printer := NewPrinter("invalid-format", io.Discard)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "cov-import-params-printer-error-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for printer error, got %d", code)
	}
}

// =============================================================================
// Test JSON output format for various functions
// =============================================================================

func TestCovListCertsLocal_JSONFormat(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	cfg.OutputFormat = "json"
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	// Save a cert
	cert := createLocalCoverageTestCert(t)
	saveCertLocal(cfg, printer, "cov-json-list-cert", cert)
	buf.Reset()

	code := captureExit(t, func() {
		listCertsLocal(cfg, printer)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output for cert list")
	}
}

func TestCovCertExistsLocal_JSONFormat(t *testing.T) {
	cfg := setupLocalCoverageConfig(t)
	cfg.OutputFormat = "json"
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	// Save a cert
	cert := createLocalCoverageTestCert(t)
	saveCertLocal(cfg, printer, "cov-json-exists-cert", cert)
	buf.Reset()

	code := captureExit(t, func() {
		certExistsLocal(cfg, printer, "cov-json-exists-cert")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output for cert exists")
	}
}

// =============================================================================
// =============================================================================
// Additional edge case tests
// =============================================================================

func TestCovResolveStoragePath_EnvVar(t *testing.T) {
	// Save current env var
	oldVal := os.Getenv("KEYCHAIN_STORAGE_PATH")
	defer func() {
		if oldVal == "" {
			_ = os.Unsetenv("KEYCHAIN_STORAGE_PATH")
		} else {
			_ = os.Setenv("KEYCHAIN_STORAGE_PATH", oldVal)
		}
	}()

	// Test with empty input and env var set
	_ = os.Setenv("KEYCHAIN_STORAGE_PATH", "/custom/path")
	result := resolveStoragePath("")
	if result != "/custom/path" {
		t.Errorf("Expected /custom/path, got %s", result)
	}

	// Test with empty input and no env var
	_ = os.Unsetenv("KEYCHAIN_STORAGE_PATH")
	result = resolveStoragePath("")
	if result != "/var/lib/keychain" {
		t.Errorf("Expected /var/lib/keychain, got %s", result)
	}

	// Test with explicit path
	result = resolveStoragePath("/explicit/path")
	if result != "/explicit/path" {
		t.Errorf("Expected /explicit/path, got %s", result)
	}
}

// =============================================================================
// Test getBackendCapabilities for unknown backend
// =============================================================================

func TestCovGetBackendCapabilities_UnknownBackend(t *testing.T) {
	_, err := getBackendCapabilities("completely-invalid-backend")
	if err == nil {
		t.Error("Expected error for unknown backend")
	}
}
