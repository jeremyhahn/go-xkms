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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// =============================================================================
// Helper functions for local functions coverage tests
// =============================================================================

func setupLocalFuncsCoverageConfig(t *testing.T) *Config {
	t.Helper()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.OutputFormat = "text"
	cfg.UseLocal = true
	return cfg
}

func setupLocalFuncsCoveragePrinter(t *testing.T) (*Printer, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	return printer, buf
}

// =============================================================================
// Test wrapKeyLocal - comprehensive coverage
// =============================================================================

func TestWrapKeyLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)
	outputFile := filepath.Join(t.TempDir(), "wrapped.json")

	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, keyMaterial, params, outputFile)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestWrapKeyLocal_WriteFileError(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)
	outputFile := "/dev/null/invalid/path/wrapped.json"

	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, keyMaterial, params, outputFile)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for write file error, got %d", code)
	}
}

func TestWrapKeyLocal_SuccessPath(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer, buf := setupLocalFuncsCoveragePrinter(t)
	outputFile := filepath.Join(t.TempDir(), "wrapped.json")

	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, keyMaterial, params, outputFile)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output from wrapKeyLocal")
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Wrapped key file was not created")
	}
}

func TestWrapKeyLocal_ECDSAPublicKey(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)
	outputFile := filepath.Join(t.TempDir(), "wrapped-ecdsa.json")

	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &ecdsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, keyMaterial, params, outputFile)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for ECDSA key (not RSA), got %d", code)
	}
}

// =============================================================================
// Test unwrapKeyLocal - comprehensive coverage
// =============================================================================

func TestUnwrapKeyLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)
	outputFile := filepath.Join(t.TempDir(), "unwrapped.bin")

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("test-wrapped-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		unwrapKeyLocal(cfg, printer, wrapped, params, outputFile)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestUnwrapKeyLocal_InvalidWrappedKey(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)
	outputFile := filepath.Join(t.TempDir(), "unwrapped.bin")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("invalid-wrapped-data"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		unwrapKeyLocal(cfg, printer, wrapped, params, outputFile)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid wrapped key, got %d", code)
	}
}

// =============================================================================
// Test decryptLocal - comprehensive coverage
// =============================================================================

func TestDecryptLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "key-id", "ciphertext", "tls", "rsa", 2048, "", "", "", "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestDecryptLocal_SymmetricInvalidBase64(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	keyID := "decrypt-sym-invalid-b64-key"
	genPrinter, _ := setupLocalFuncsCoveragePrinter(t)
	generateKeyLocal(cfg, genPrinter, keyID, "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, keyID, "!!!invalid-base64!!!", "", string(types.SymmetricAES256GCM), 256, "", "", "validnonce", "validtag", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid base64 ciphertext, got %d", code)
	}
}

func TestDecryptLocal_SymmetricWithAADSuccess(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer, buf := setupLocalFuncsCoveragePrinter(t)

	keyID := "decrypt-sym-aad-key"
	generateKeyLocal(cfg, printer, keyID, "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
	buf.Reset()

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

	plaintext := []byte("test plaintext with AAD")
	aad := "additional authenticated data"
	opts := &types.EncryptOptions{AdditionalData: []byte(aad)}
	encrypted, err := encrypter.Encrypt(plaintext, opts)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(encrypted.Ciphertext)
	nonceB64 := base64.StdEncoding.EncodeToString(encrypted.Nonce)
	tagB64 := base64.StdEncoding.EncodeToString(encrypted.Tag)

	buf.Reset()

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, keyID, ciphertextB64, "", string(types.SymmetricAES256GCM), 256, "", aad, nonceB64, tagB64, "")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output from decryptLocal")
	}
}

func TestDecryptLocal_AsymmetricOAEPSuccess(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer, buf := setupLocalFuncsCoveragePrinter(t)

	keyID := "decrypt-asym-oaep-key"
	generateKeyLocal(cfg, printer, keyID, "tls", "", "rsa", 2048, "", false)
	buf.Reset()

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

	var pubKey *rsa.PublicKey
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case crypto.Signer:
		pubKey = k.Public().(*rsa.PublicKey)
	default:
		t.Fatalf("Unexpected key type: %T", key)
	}

	plaintext := []byte("test plaintext for OAEP")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)
	buf.Reset()

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, keyID, ciphertextB64, "tls", "rsa", 2048, "", "", "", "", "SHA-256")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output from decryptLocal")
	}
}

func TestDecryptLocal_InvalidKeyAttributes(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	ciphertextB64 := base64.StdEncoding.EncodeToString([]byte("ciphertext"))

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "key-id", ciphertextB64, "tls", "invalid-algorithm", 2048, "", "", "", "", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key attributes, got %d", code)
	}
}

// =============================================================================
// Test generateKeyLocal - comprehensive coverage
// =============================================================================

func TestGenerateKeyLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "key-id", "tls", "", "rsa", 2048, "", false)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestGenerateKeyLocal_InvalidKeyAttributes(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "key-id", "tls", "", "invalid-algorithm", 2048, "", false)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key attributes, got %d", code)
	}
}

func TestGenerateKeyLocal_SymmetricAES192(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer, buf := setupLocalFuncsCoveragePrinter(t)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "aes192-key", "symmetric", string(types.SymmetricAES192GCM), "", 192, "", false)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocal_Ed25519(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer, buf := setupLocalFuncsCoveragePrinter(t)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "ed25519-key-gen", "signing", "", "ed25519", 0, "", false)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocal_PrinterError(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("invalid-format", io.Discard)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "printer-error-key", "tls", "", "rsa", 2048, "", false)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for printer error, got %d", code)
	}
}

// =============================================================================
// Test listKeysLocal - comprehensive coverage
// =============================================================================

func TestListKeysLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		listKeysLocal(cfg, printer)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestListKeysLocal_WithMultipleKeys(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer, buf := setupLocalFuncsCoveragePrinter(t)

	generateKeyLocal(cfg, printer, "list-key-1", "tls", "", "rsa", 2048, "", false)
	generateKeyLocal(cfg, printer, "list-key-2", "signing", "", "ecdsa", 0, "P-256", false)
	buf.Reset()

	code := captureExit(t, func() {
		listKeysLocal(cfg, printer)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output from listKeysLocal")
	}
}

func TestListKeysLocal_PrinterError(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	genPrinter, _ := setupLocalFuncsCoveragePrinter(t)
	generateKeyLocal(cfg, genPrinter, "list-printer-error-key", "tls", "", "rsa", 2048, "", false)

	printer := NewPrinter("invalid-format", io.Discard)

	code := captureExit(t, func() {
		listKeysLocal(cfg, printer)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for printer error, got %d", code)
	}
}

// =============================================================================
// Test importKeyLocal - comprehensive coverage
// =============================================================================

func TestImportKeyLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("test-wrapped-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "key-id", "tls", "rsa", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestImportKeyLocal_InvalidKeyAttributes(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("test-wrapped-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "key-id", "tls", "invalid-algorithm", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key attributes, got %d", code)
	}
}

// =============================================================================
// Test getImportParamsLocal - comprehensive coverage
// =============================================================================

func TestGetImportParamsLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "key-id", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestGetImportParamsLocal_InvalidKeyAttributes(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "key-id", "tls", "invalid-algorithm", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key attributes, got %d", code)
	}
}

func TestGetImportParamsLocal_SuccessNoFile(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer, buf := setupLocalFuncsCoveragePrinter(t)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "import-params-nofile-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getImportParamsLocal")
	}
}

func TestGetImportParamsLocal_WriteFileError(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)
	outputFile := "/dev/null/invalid/path/params.json"

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "import-params-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, outputFile)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for write file error, got %d", code)
	}
}

// =============================================================================
// Test encryptLocal - comprehensive coverage
// =============================================================================

func TestEncryptLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		encryptLocal(cfg, printer, "key-id", "plaintext", string(types.SymmetricAES256GCM), 256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestEncryptLocal_InvalidKeyAttributes(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		encryptLocal(cfg, printer, "key-id", "plaintext", "invalid-algo", 256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key attributes, got %d", code)
	}
}

func TestEncryptLocal_SuccessWithAAD(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer, buf := setupLocalFuncsCoveragePrinter(t)

	keyID := "encrypt-aad-key"
	generateKeyLocal(cfg, printer, keyID, "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
	buf.Reset()

	code := captureExit(t, func() {
		encryptLocal(cfg, printer, keyID, "plaintext to encrypt", string(types.SymmetricAES256GCM), 256, "additional data")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptLocal")
	}
}

func TestEncryptLocal_PrinterError(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	genPrinter, _ := setupLocalFuncsCoveragePrinter(t)

	keyID := "encrypt-printer-error-key"
	generateKeyLocal(cfg, genPrinter, keyID, "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)

	printer := NewPrinter("invalid-format", io.Discard)

	code := captureExit(t, func() {
		encryptLocal(cfg, printer, keyID, "plaintext", string(types.SymmetricAES256GCM), 256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for printer error, got %d", code)
	}
}

// =============================================================================
// Test copyKeyLocal - comprehensive coverage
// =============================================================================

func TestCopyKeyLocal_SourceBackendCreationError(t *testing.T) {
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

func TestCopyKeyLocal_InvalidSourceKeyAttributes(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "software", "", "tls", "invalid-algorithm", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid source key attributes, got %d", code)
	}
}

func TestCopyKeyLocal_SourceKeyMissing(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "nonexistent-source-key", "dest-key", "software", "", "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for source key not found, got %d", code)
	}
}

func TestCopyKeyLocal_DestBackendCreationError(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	genPrinter, _ := setupLocalFuncsCoveragePrinter(t)

	keyID := "copy-dest-error-key"
	generateKeyLocal(cfg, genPrinter, keyID, "tls", "", "ecdsa", 0, "P-256", true)

	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, keyID, "dest-key", "unknown-backend", "", "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for dest backend creation error, got %d", code)
	}
}

// =============================================================================
// Test rotateKeyLocal - comprehensive coverage
// =============================================================================

func TestRotateKeyLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		rotateKeyLocal(cfg, printer, "key-id", "tls", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestRotateKeyLocal_InvalidKeyAttributes(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		rotateKeyLocal(cfg, printer, "key-id", "tls", "invalid-algorithm", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key attributes, got %d", code)
	}
}

func TestRotateKeyLocal_SuccessECDSA(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer, buf := setupLocalFuncsCoveragePrinter(t)

	keyID := "rotate-ecdsa-key"
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ecdsa", 0, "P-256", false)
	buf.Reset()

	code := captureExit(t, func() {
		rotateKeyLocal(cfg, printer, keyID, "signing", "ecdsa", 0, "P-256")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected output from rotateKeyLocal")
	}
}

func TestRotateKeyLocal_PrinterError(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	genPrinter, _ := setupLocalFuncsCoveragePrinter(t)

	keyID := "rotate-printer-error-key"
	generateKeyLocal(cfg, genPrinter, keyID, "tls", "", "rsa", 2048, "", false)

	printer := NewPrinter("invalid-format", io.Discard)

	code := captureExit(t, func() {
		rotateKeyLocal(cfg, printer, keyID, "tls", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for printer error, got %d", code)
	}
}

// =============================================================================
// Test exportKeyLocal - comprehensive coverage
// =============================================================================

func TestExportKeyLocal_BackendCreationError(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "unknown-backend"
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)
	outputFile := filepath.Join(t.TempDir(), "exported.json")

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "key-id", outputFile, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestExportKeyLocal_InvalidKeyAttributes(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)
	outputFile := filepath.Join(t.TempDir(), "exported.json")

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "key-id", outputFile, "tls", "invalid-algorithm", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key attributes, got %d", code)
	}
}

func TestExportKeyLocal_KeyMissing(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer := NewPrinter("text", io.Discard)
	outputFile := filepath.Join(t.TempDir(), "exported.json")

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "nonexistent-key", outputFile, "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for key not found, got %d", code)
	}
}

func TestExportKeyLocal_WriteFileError(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	genPrinter, _ := setupLocalFuncsCoveragePrinter(t)

	keyID := "export-write-error-key"
	generateKeyLocal(cfg, genPrinter, keyID, "tls", "", "ecdsa", 0, "P-256", true)

	printer := NewPrinter("text", io.Discard)
	outputFile := "/dev/null/invalid/path/exported.json"

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, keyID, outputFile, "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for write file error, got %d", code)
	}
}

func TestExportKeyLocal_SuccessECDSA(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer, buf := setupLocalFuncsCoveragePrinter(t)
	outputFile := filepath.Join(t.TempDir(), "exported-ecdsa.json")

	keyID := "export-ecdsa-key"
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ecdsa", 0, "P-256", true)
	buf.Reset()

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, keyID, outputFile, "signing", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Exported key file was not created")
	}
}

func TestExportKeyLocal_RSAKeyTooLarge(t *testing.T) {
	cfg := setupLocalFuncsCoverageConfig(t)
	printer, buf := setupLocalFuncsCoveragePrinter(t)
	outputFile := filepath.Join(t.TempDir(), "exported-rsa.json")

	keyID := "export-rsa-key"
	generateKeyLocal(cfg, printer, keyID, "tls", "", "rsa", 2048, "", true)
	buf.Reset()

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, keyID, outputFile, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	// RSA private keys are too large for RSA-OAEP wrapping
	if code != 1 {
		t.Errorf("Expected exit code 1 for RSA key too large for OAEP wrapping, got %d", code)
	}
}
