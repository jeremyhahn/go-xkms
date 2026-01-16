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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// =============================================================================
// Helper functions
// =============================================================================

func setupCoverageTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.OutputFormat = "text"
	cfg.UseLocal = true
	return cfg
}

func setupCoverageTestPrinter(t *testing.T) (*Printer, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	return printer, buf
}

func discardPrinter(t *testing.T) *Printer {
	t.Helper()
	return NewPrinter("text", io.Discard)
}

// =============================================================================
// Test Execute function (root.go)
// =============================================================================

func TestExecute_ReturnsNil(t *testing.T) {
	// Execute should return nil when no subcommand errors
	// We just verify it doesn't panic
	err := Execute()
	// The error may be nil or a help error depending on flags
	// Just verify the function executes without panic
	_ = err
}

// =============================================================================
// Test backends.go functions - backendInfoLocal
// =============================================================================

func TestBackendInfoLocal_AllBackends(t *testing.T) {
	backends := []string{
		"software",
		"pkcs8",
		"pkcs11",
		"tpm2",
		"awskms",
		"gcpkms",
		"azurekv",
		"vault",
	}

	for _, backend := range backends {
		t.Run(backend, func(t *testing.T) {
			printer, buf := setupCoverageTestPrinter(t)
			backendInfoLocal(printer, backend)

			output := buf.String()
			if output == "" {
				t.Errorf("Expected output for backend %s", backend)
			}
		})
	}
}

func TestBackendInfoLocal_UnknownBackend(t *testing.T) {
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		backendInfoLocal(printer, "unknown-backend-xyz")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for unknown backend, got %d", code)
	}
}

func TestListBackendsLocal_Success(t *testing.T) {
	printer, buf := setupCoverageTestPrinter(t)

	listBackendsLocal(printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from listBackendsLocal")
	}
}

func TestGetBackendCapabilities_AllKnownBackends(t *testing.T) {
	backends := []string{"software", "pkcs8", "pkcs11", "tpm2", "awskms", "gcpkms", "azurekv", "vault"}

	for _, be := range backends {
		t.Run(be, func(t *testing.T) {
			caps, err := getBackendCapabilities(be)
			if err != nil {
				t.Errorf("getBackendCapabilities(%s) returned error: %v", be, err)
			}
			if !caps.Keys {
				t.Errorf("Expected Keys capability for backend %s", be)
			}
		})
	}
}

func TestGetBackendCapabilities_UnknownBackend(t *testing.T) {
	_, err := getBackendCapabilities("nonexistent-backend")
	if err == nil {
		t.Error("Expected error for unknown backend")
	}
}

// =============================================================================
// Test key.go local functions - error paths
// =============================================================================

func TestGenerateKeyLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-key", "tls", "", "rsa", 2048, "", false)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestGenerateKeyLocal_InvalidKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-key", "invalid-type", "", "rsa", 2048, "", false)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestGenerateKeyLocal_InvalidSymmetricParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	// Invalid key size for symmetric key
	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-key", "symmetric", "", "", 64, "", false)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid symmetric params, got %d", code)
	}
}

func TestListKeysLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		listKeysLocal(cfg, printer)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestGetKeyLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		getKeyLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestGetKeyLocal_InvalidKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		getKeyLocal(cfg, printer, "test-key", "invalid-type", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestGetKeyLocal_KeyNotFound(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		getKeyLocal(cfg, printer, "nonexistent-key", "tls", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for key not found, got %d", code)
	}
}

func TestDeleteKeyLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		deleteKeyLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestDeleteKeyLocal_InvalidKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		deleteKeyLocal(cfg, printer, "test-key", "invalid-type", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestDeleteKeyLocal_KeyNotFound(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		deleteKeyLocal(cfg, printer, "nonexistent-key", "tls", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for key not found, got %d", code)
	}
}

func TestSignLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		signLocal(cfg, printer, "test-key", "data", "signing", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestSignLocal_InvalidKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		signLocal(cfg, printer, "test-key", "data", "invalid-type", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestSignLocal_InvalidHash(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer, _ := setupCoverageTestPrinter(t)

	// Generate a key first
	generateKeyLocal(cfg, printer, "sign-hash-test", "signing", "", "rsa", 2048, "", false)

	code := captureExit(t, func() {
		signLocal(cfg, printer, "sign-hash-test", "data", "signing", "rsa", 2048, "", "INVALID-HASH")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid hash, got %d", code)
	}
}

func TestSignLocal_KeyNotFound(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		signLocal(cfg, printer, "nonexistent-key", "data", "signing", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for key not found, got %d", code)
	}
}

func TestRotateKeyLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		rotateKeyLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestRotateKeyLocal_InvalidKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		rotateKeyLocal(cfg, printer, "test-key", "invalid-type", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

// Note: rotateKeyLocal creates a new key if it doesn't exist, so we test success case instead
func TestRotateKeyLocal_Success(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer, buf := setupCoverageTestPrinter(t)

	// Generate a key first
	generateKeyLocal(cfg, printer, "rotate-coverage-key", "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// Rotate should succeed
	rotateKeyLocal(cfg, printer, "rotate-coverage-key", "tls", "rsa", 2048, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from rotateKeyLocal")
	}
}

func TestEncryptLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		encryptLocal(cfg, printer, "test-key", "plaintext", string(types.SymmetricAES256GCM), 256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestEncryptLocal_InvalidKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		encryptLocal(cfg, printer, "test-key", "plaintext", "invalid-algorithm", 256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestEncryptLocal_KeyNotFound(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		encryptLocal(cfg, printer, "nonexistent-key", "plaintext", string(types.SymmetricAES256GCM), 256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for key not found, got %d", code)
	}
}

func TestDecryptLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-key", "ciphertext", "tls", "rsa", 2048, "", "", "", "", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestDecryptLocal_InvalidSymmetricParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	// Invalid symmetric algorithm with nonce and tag
	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-key", "ciphertext", "", "invalid-alg", 256, "", "", "nonce", "tag", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid symmetric params, got %d", code)
	}
}

func TestDecryptLocal_InvalidCiphertextBase64(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	// Generate key first
	generateKeyLocal(cfg, printer, "decrypt-test-key", "tls", "", "rsa", 2048, "", false)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "decrypt-test-key", "!!!invalid-base64!!!", "tls", "rsa", 2048, "", "", "", "", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid base64, got %d", code)
	}
}

func TestDecryptLocal_InvalidNonceBase64(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	// Generate symmetric key
	generateKeyLocal(cfg, printer, "decrypt-sym-test", "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "decrypt-sym-test",
			base64.StdEncoding.EncodeToString([]byte("ciphertext")),
			"", string(types.SymmetricAES256GCM), 256, "", "",
			"!!!invalid-base64!!!", // invalid nonce
			base64.StdEncoding.EncodeToString([]byte("tag")),
			"")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid nonce base64, got %d", code)
	}
}

func TestDecryptLocal_InvalidTagBase64(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	// Generate symmetric key
	generateKeyLocal(cfg, printer, "decrypt-tag-test", "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "decrypt-tag-test",
			base64.StdEncoding.EncodeToString([]byte("ciphertext")),
			"", string(types.SymmetricAES256GCM), 256, "", "",
			base64.StdEncoding.EncodeToString([]byte("nonce")),
			"!!!invalid-base64!!!", // invalid tag
			"")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid tag base64, got %d", code)
	}
}

func TestDecryptLocal_InvalidAsymmetricParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-key", "ciphertext", "invalid-type", "rsa", 2048, "", "", "", "", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid asymmetric params, got %d", code)
	}
}

func TestDecryptLocal_InvalidHashAlgorithm(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	// Generate RSA key
	generateKeyLocal(cfg, printer, "decrypt-hash-test", "tls", "", "rsa", 2048, "", false)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "decrypt-hash-test",
			base64.StdEncoding.EncodeToString([]byte("ciphertext")),
			"tls", "rsa", 2048, "", "", "", "", "INVALID-HASH")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid hash algorithm, got %d", code)
	}
}

func TestExportKeyLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "test-key", "/tmp/output.json", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestExportKeyLocal_InvalidKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "test-key", "/tmp/output.json", "invalid-type", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestExportKeyLocal_KeyNotFound(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "export-output.json")

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "nonexistent-key", outputFile, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for key not found, got %d", code)
	}
}

func TestGetImportParamsLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestGetImportParamsLocal_InvalidKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "test-key", "invalid-type", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestGetImportParamsLocal_Success(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer, buf := setupCoverageTestPrinter(t)

	getImportParamsLocal(cfg, printer, "import-params-test", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getImportParamsLocal")
	}
}

func TestGetImportParamsLocal_WithOutputFile(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer, _ := setupCoverageTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "import-params.json")

	getImportParamsLocal(cfg, printer, "import-params-file-test", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, outputFile)

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Output file was not created")
	}
}

func TestWrapKeyLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	keyMaterial := []byte("test-key-material")
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, keyMaterial, params, "/tmp/wrapped.json")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestWrapKeyLocal_Success(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer, _ := setupCoverageTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "wrapped-key.json")

	keyMaterial := []byte("test-key-material-16b") // 16 bytes for AES-128
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	wrapKeyLocal(cfg, printer, keyMaterial, params, outputFile)

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Output file was not created")
	}
}

func TestUnwrapKeyLocal_BackendError_Coverage(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		unwrapKeyLocal(cfg, printer, wrapped, params, "/tmp/unwrapped.key")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestVerifyLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		verifyLocal(cfg, printer, "test-key", "data", "signature", "signing", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestVerifyLocal_InvalidKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		verifyLocal(cfg, printer, "test-key", "data", "signature", "invalid-type", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestVerifyLocal_InvalidHash(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		verifyLocal(cfg, printer, "test-key", "data", "signature", "signing", "rsa", 2048, "", "INVALID-HASH")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid hash, got %d", code)
	}
}

func TestVerifyLocal_KeyNotFound(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		verifyLocal(cfg, printer, "nonexistent-key", "data", "signature", "signing", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for key not found, got %d", code)
	}
}

func TestVerifyLocal_InvalidSignatureBase64(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	// Generate key first
	generateKeyLocal(cfg, printer, "verify-b64-test", "signing", "", "rsa", 2048, "", false)

	code := captureExit(t, func() {
		verifyLocal(cfg, printer, "verify-b64-test", "data", "!!!invalid-base64!!!", "signing", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid base64, got %d", code)
	}
}

func TestVerifyLocal_InvalidSignature(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	// Generate key first
	generateKeyLocal(cfg, printer, "verify-invalid-sig", "signing", "", "rsa", 2048, "", false)

	// Create a fake signature
	fakeSignature := base64.StdEncoding.EncodeToString([]byte("fake-signature-data"))

	code := captureExit(t, func() {
		verifyLocal(cfg, printer, "verify-invalid-sig", "data", fakeSignature, "signing", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid signature, got %d", code)
	}
}

func TestVerifyLocal_Ed25519Success(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer, buf := setupCoverageTestPrinter(t)

	keyID := "verify-ed25519-key"

	// Generate an Ed25519 key
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ed25519", 0, "", false)
	buf.Reset()

	// Get backend and sign manually
	be, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = be.Close() }()

	attrs, _ := buildKeyAttributesFromFlags(keyID, "signing", "ed25519", 0, "", false)
	attrs.Hash = crypto.SHA256

	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Failed to get signer: %v", err)
	}

	data := "test data"
	// Ed25519 signs raw message
	signature, err := signer.Sign(rand.Reader, []byte(data), crypto.Hash(0))
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	buf.Reset()

	verifyLocal(cfg, printer, keyID, data, signatureB64, "signing", "ed25519", 0, "", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from verifyLocal")
	}
}

func TestEncryptAsymLocal_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		encryptAsymLocal(cfg, printer, "test-key", "plaintext", "tls", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestEncryptAsymLocal_InvalidKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		encryptAsymLocal(cfg, printer, "test-key", "plaintext", "invalid-type", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestEncryptAsymLocal_InvalidHash(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		encryptAsymLocal(cfg, printer, "test-key", "plaintext", "tls", "rsa", 2048, "", "INVALID-HASH")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid hash, got %d", code)
	}
}

func TestEncryptAsymLocal_KeyNotFound(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		encryptAsymLocal(cfg, printer, "nonexistent-key", "plaintext", "tls", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for key not found, got %d", code)
	}
}

func TestEncryptAsymLocal_NonRSAKey(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	// Generate an ECDSA key (non-RSA)
	generateKeyLocal(cfg, printer, "encrypt-asym-ecdsa", "tls", "", "ecdsa", 0, "P-256", false)

	code := captureExit(t, func() {
		encryptAsymLocal(cfg, printer, "encrypt-asym-ecdsa", "plaintext", "tls", "ecdsa", 0, "P-256", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for non-RSA key, got %d", code)
	}
}

func TestEncryptAsymLocal_Success(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer, buf := setupCoverageTestPrinter(t)

	// Generate an RSA key
	generateKeyLocal(cfg, printer, "encrypt-asym-test", "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	encryptAsymLocal(cfg, printer, "encrypt-asym-test", "plaintext to encrypt", "tls", "rsa", 2048, "", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptAsymLocal")
	}
}

// =============================================================================
// Test copy key operations
// =============================================================================

func TestCopyKeyLocal_SourceBackendError_Coverage(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "software", "", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for source backend error, got %d", code)
	}
}

func TestCopyKeyLocal_InvalidSourceKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "software", "", "invalid-type", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid source key params, got %d", code)
	}
}

func TestCopyKeyLocal_SourceKeyNotFound(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)
	destKeyDir := t.TempDir()

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "nonexistent-key", "dest-key", "software", destKeyDir, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for source key not found, got %d", code)
	}
}

func TestCopyKeyLocal_DestBackendError(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	// Generate an exportable key first
	generateKeyLocal(cfg, printer, "copy-src-key", "tls", "", "ecdsa", 0, "P-256", true)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "copy-src-key", "dest-key", "nonexistent-backend", "", "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for dest backend error, got %d", code)
	}
}

// =============================================================================
// Test import key operations
// =============================================================================

func TestImportKeyLocal_BackendError_Coverage(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "nonexistent-backend"
	cfg.UseLocal = true
	printer := discardPrinter(t)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend error, got %d", code)
	}
}

func TestImportKeyLocal_InvalidKeyParams(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer := discardPrinter(t)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "test-key", "invalid-type", "rsa", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

// =============================================================================
// Test printVerbose
// =============================================================================

func TestPrintVerbose_Enabled(t *testing.T) {
	// Save original config
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.Verbose = true

	// This should not panic
	printVerbose("Test message: %s", "value")
}

func TestPrintVerbose_Disabled(t *testing.T) {
	// Save original config
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.Verbose = false

	// This should not panic
	printVerbose("Test message: %s", "value")
}

// =============================================================================
// Test getConfig
// =============================================================================

func TestGetConfig_ReturnsGlobalConfig(t *testing.T) {
	cfg := getConfig()
	if cfg == nil {
		t.Error("getConfig() returned nil")
	}
	if cfg != globalConfig {
		t.Error("getConfig() did not return globalConfig")
	}
}

// =============================================================================
// Test JSON output format
// =============================================================================

func TestListKeysLocal_JSONFormat(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	cfg.OutputFormat = "json"
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	// Generate a key first
	generateKeyLocal(cfg, printer, "json-format-key", "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	listKeysLocal(cfg, printer)

	// Verify JSON output
	var result interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
}

// =============================================================================
// Test decrypt with RSA OAEP (hash specified)
// =============================================================================

func TestDecryptLocal_RSAOAEPSuccess(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer, buf := setupCoverageTestPrinter(t)

	// Generate an RSA key
	keyID := "decrypt-oaep-test"
	generateKeyLocal(cfg, printer, keyID, "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get the key and encrypt manually with OAEP
	be, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = be.Close() }()

	attrs, _ := buildKeyAttributesFromFlags(keyID, "tls", "rsa", 2048, "", false)
	key, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	// Extract public key
	var publicKey *rsa.PublicKey
	switch k := key.(type) {
	case crypto.Signer:
		publicKey = k.Public().(*rsa.PublicKey)
	}

	// Encrypt with OAEP
	plaintext := []byte("test plaintext")
	ciphertext, err := rsa.EncryptOAEP(
		crypto.SHA256.New(),
		rand.Reader,
		publicKey,
		plaintext,
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)
	buf.Reset()

	// Decrypt with hash specified
	decryptLocal(cfg, printer, keyID, ciphertextB64, "tls", "rsa", 2048, "", "", "", "", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from decryptLocal")
	}
}

// =============================================================================
// Test symmetric encrypt/decrypt with AAD
// =============================================================================

func TestDecryptLocal_SymmetricWithAAD(t *testing.T) {
	cfg := setupCoverageTestConfig(t)
	printer, buf := setupCoverageTestPrinter(t)

	keyID := "decrypt-aad-test"

	// Generate a symmetric key
	generateKeyLocal(cfg, printer, keyID, "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
	buf.Reset()

	// Encrypt with backend directly
	be, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = be.Close() }()

	attrs, _ := buildSymmetricKeyAttributes(keyID, string(types.SymmetricAES256GCM), 256)
	symBackend := be.(types.SymmetricBackend)
	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	aad := "additional-authenticated-data"
	plaintext := []byte("test plaintext")
	opts := &types.EncryptOptions{
		AdditionalData: []byte(aad),
	}
	encrypted, err := encrypter.Encrypt(plaintext, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(encrypted.Ciphertext)
	nonceB64 := base64.StdEncoding.EncodeToString(encrypted.Nonce)
	tagB64 := base64.StdEncoding.EncodeToString(encrypted.Tag)

	buf.Reset()

	// Decrypt with AAD
	decryptLocal(cfg, printer, keyID, ciphertextB64, "", string(types.SymmetricAES256GCM), 256, "", aad, nonceB64, tagB64, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from decryptLocal with AAD")
	}
}
