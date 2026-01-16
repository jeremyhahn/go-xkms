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

	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// =============================================================================
// Helper functions for local key tests
// =============================================================================

func newMockBackendConfig(t *testing.T, mockBackend *mocks.ExtendedMockBackend) *Config {
	t.Helper()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	return cfg
}

func newTestPrinter(t *testing.T) (*Printer, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	return printer, buf
}

// =============================================================================
// Tests for generateKeyLocal
// =============================================================================

func TestLocalGenerateKey_Success_RSA(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-rsa-key", "tls", "", "rsa", 2048, "", false)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected success message output")
	}

	if len(mockBackend.GenerateKeyCalls) != 1 {
		t.Errorf("Expected 1 GenerateKey call, got %d", len(mockBackend.GenerateKeyCalls))
	}
}

func TestLocalGenerateKey_Success_ECDSA(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-ecdsa-key", "signing", "", "ecdsa", 0, "P-256", false)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected success message output")
	}
}

func TestLocalGenerateKey_Success_Ed25519(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-ed25519-key", "signing", "", "ed25519", 0, "", false)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected success message output")
	}
}

func TestLocalGenerateKey_Success_Symmetric_AES256(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-aes-key", "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected success message output")
	}

	if len(mockBackend.GenerateSymmetricKeyCalls) != 1 {
		t.Errorf("Expected 1 GenerateSymmetricKey call, got %d", len(mockBackend.GenerateSymmetricKeyCalls))
	}
}

func TestLocalGenerateKey_Error_BackendCreation(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return nil, fmt.Errorf("backend creation error")
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-key", "tls", "", "rsa", 2048, "", false)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestLocalGenerateKey_Error_InvalidKeyParams(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-key", "invalid-type", "", "rsa", 2048, "", false)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestLocalGenerateKey_Error_GenerateKeyFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.GenerateKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, fmt.Errorf("key generation failed")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-key", "tls", "", "rsa", 2048, "", false)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for generate key failure, got %d", code)
	}
}

func TestLocalGenerateKey_Error_SymmetricBackendNotSupported(t *testing.T) {
	// Use a basic MockBackend that doesn't support SymmetricBackend
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-key", "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for symmetric backend not supported, got %d", code)
	}
}

// =============================================================================
// Tests for decryptLocal
// =============================================================================

func TestLocalDecrypt_Success_Symmetric(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()

	// Store a symmetric key
	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}
	mockBackend.StoreSymmetricKey("test-decrypt-key", keyMaterial)

	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	// First encrypt some data
	encrypter := &mocks.MockSymmetricEncrypter{
		KeyMaterial: keyMaterial,
		Algorithm:   string(types.SymmetricAES256GCM),
	}
	encrypted, err := encrypter.Encrypt([]byte("test plaintext"), nil)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Base64 encode the components
	ciphertextB64 := base64.StdEncoding.EncodeToString(encrypted.Ciphertext)
	nonceB64 := base64.StdEncoding.EncodeToString(encrypted.Nonce)
	tagB64 := base64.StdEncoding.EncodeToString(encrypted.Tag)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-decrypt-key", ciphertextB64, "", string(types.SymmetricAES256GCM), 256, "", "", nonceB64, tagB64, "")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected decrypted output")
	}
}

func TestLocalDecrypt_Success_Asymmetric_RSA(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()

	// Generate and store an RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	mockBackend.StoreKey("test-rsa-decrypt-key", rsaKey)

	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	// Encrypt with the public key
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, []byte("test plaintext"))
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-rsa-decrypt-key", ciphertextB64, "tls", "rsa", 2048, "", "", "", "", "")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected decrypted output")
	}
}

func TestLocalDecrypt_Error_BackendCreation(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return nil, fmt.Errorf("backend creation error")
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-key", "Y2lwaGVydGV4dA==", "tls", "rsa", 2048, "", "", "", "", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestLocalDecrypt_Error_InvalidBase64Ciphertext(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockBackend.StoreKey("test-key", rsaKey)
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-key", "invalid-base64!!!", "tls", "rsa", 2048, "", "", "", "", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid base64, got %d", code)
	}
}

func TestLocalDecrypt_Error_KeyNotFound(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "nonexistent-key", "Y2lwaGVydGV4dA==", "tls", "rsa", 2048, "", "", "", "", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for key not found, got %d", code)
	}
}

// =============================================================================
// Tests for getImportParamsLocal
// =============================================================================

func TestLocalGetImportParams_Success(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "test-import-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected import params output")
	}

	if len(mockBackend.GetImportParametersCalls) != 1 {
		t.Errorf("Expected 1 GetImportParameters call, got %d", len(mockBackend.GetImportParametersCalls))
	}
}

func TestLocalGetImportParams_Success_WriteToFile(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, _ := newTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "import-params.json")

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "test-import-key", "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, outputFile)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Expected output file to be created")
	}
}

func TestLocalGetImportParams_Error_BackendCreation(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return nil, fmt.Errorf("backend creation error")
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestLocalGetImportParams_Error_InvalidKeyParams(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "test-key", "invalid-type", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestLocalGetImportParams_Error_GetImportParamsFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.GetImportParametersFunc = func(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
		return nil, fmt.Errorf("get import params failed")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for get import params failure, got %d", code)
	}
}

func TestLocalGetImportParams_Error_WriteFileFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "/dev/null/invalid/path.json")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for write file failure, got %d", code)
	}
}

// =============================================================================
// Tests for importKeyLocal
// =============================================================================

func TestLocalImportKey_Success(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("test-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "test-import-key", "tls", "rsa", 2048, "", wrapped)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected success message output")
	}

	if len(mockBackend.ImportKeyCalls) != 1 {
		t.Errorf("Expected 1 ImportKey call, got %d", len(mockBackend.ImportKeyCalls))
	}
}

func TestLocalImportKey_Error_BackendCreation(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return nil, fmt.Errorf("backend creation error")
	}
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("test-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestLocalImportKey_Error_BackendNotSupportsImport(t *testing.T) {
	mockBackend := mocks.NewMockBackend() // Basic mock without ImportExportBackend
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("test-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend not supporting import, got %d", code)
	}
}

func TestLocalImportKey_Error_InvalidKeyParams(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("test-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "test-key", "invalid-type", "rsa", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestLocalImportKey_Error_ImportKeyFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.ImportKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
		return fmt.Errorf("import key failed")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("test-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "test-key", "tls", "rsa", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for import key failure, got %d", code)
	}
}

// =============================================================================
// Tests for wrapKeyLocal
// =============================================================================

func TestLocalWrapKey_Success(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "wrapped-key.json")

	// Generate a test wrapping public key
	wrappingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	params := &backend.ImportParameters{
		WrappingPublicKey: &wrappingKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	keyMaterial := []byte("test-key-material-to-wrap")

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, keyMaterial, params, outputFile)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected success message output")
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Expected output file to be created")
	}

	if mockBackend.WrapKeyCalls != 1 {
		t.Errorf("Expected 1 WrapKey call, got %d", mockBackend.WrapKeyCalls)
	}
}

func TestLocalWrapKey_Error_BackendCreation(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return nil, fmt.Errorf("backend creation error")
	}
	printer := NewPrinter("text", io.Discard)

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, []byte("key-material"), params, "/tmp/output.json")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestLocalWrapKey_Error_BackendNotSupportsWrap(t *testing.T) {
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, []byte("key-material"), params, "/tmp/output.json")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend not supporting wrap, got %d", code)
	}
}

func TestLocalWrapKey_Error_WrapKeyFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.WrapKeyFunc = func(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
		return nil, fmt.Errorf("wrap key failed")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, []byte("key-material"), params, "/tmp/output.json")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for wrap key failure, got %d", code)
	}
}

func TestLocalWrapKey_Error_WriteFileFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, []byte("key-material"), params, "/dev/null/invalid/path.json")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for write file failure, got %d", code)
	}
}

// =============================================================================
// Tests for unwrapKeyLocal
// =============================================================================

func TestLocalUnwrapKey_Success(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "unwrapped-key.bin")

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		unwrapKeyLocal(cfg, printer, wrapped, params, outputFile)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected success message output")
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Expected output file to be created")
	}

	if mockBackend.UnwrapKeyCalls != 1 {
		t.Errorf("Expected 1 UnwrapKey call, got %d", mockBackend.UnwrapKeyCalls)
	}
}

func TestLocalUnwrapKey_Error_BackendCreation(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return nil, fmt.Errorf("backend creation error")
	}
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		unwrapKeyLocal(cfg, printer, wrapped, params, "/tmp/output.bin")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestLocalUnwrapKey_Error_BackendNotSupportsUnwrap(t *testing.T) {
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		unwrapKeyLocal(cfg, printer, wrapped, params, "/tmp/output.bin")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend not supporting unwrap, got %d", code)
	}
}

func TestLocalUnwrapKey_Error_UnwrapKeyFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.UnwrapKeyFunc = func(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
		return nil, fmt.Errorf("unwrap key failed")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		unwrapKeyLocal(cfg, printer, wrapped, params, "/tmp/output.bin")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for unwrap key failure, got %d", code)
	}
}

func TestLocalUnwrapKey_Error_WriteFileFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	code := captureExit(t, func() {
		unwrapKeyLocal(cfg, printer, wrapped, params, "/dev/null/invalid/path.bin")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for write file failure, got %d", code)
	}
}

// =============================================================================
// Tests for exportKeyLocal
// =============================================================================

func TestLocalExportKey_Success(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()

	// Store a key to export
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockBackend.StoreKey("test-export-key", ecdsaKey)

	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "exported-key.json")

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "test-export-key", outputFile, "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected success message output")
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Expected output file to be created")
	}

	if len(mockBackend.ExportKeyCalls) != 1 {
		t.Errorf("Expected 1 ExportKey call, got %d", len(mockBackend.ExportKeyCalls))
	}
}

func TestLocalExportKey_Error_BackendCreation(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return nil, fmt.Errorf("backend creation error")
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "test-key", "/tmp/output.json", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestLocalExportKey_Error_BackendNotSupportsExport(t *testing.T) {
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "test-key", "/tmp/output.json", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend not supporting export, got %d", code)
	}
}

func TestLocalExportKey_Error_InvalidKeyParams(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "test-key", "/tmp/output.json", "invalid-type", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid key params, got %d", code)
	}
}

func TestLocalExportKey_Error_ExportKeyFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.ExportKeyFunc = func(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
		return nil, fmt.Errorf("export key failed")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "test-key", "/tmp/output.json", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for export key failure, got %d", code)
	}
}

func TestLocalExportKey_Error_WriteFileFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockBackend.StoreKey("test-key", ecdsaKey)
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "test-key", "/dev/null/invalid/path.json", "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for write file failure, got %d", code)
	}
}

// =============================================================================
// Tests for copyKeyLocal
// =============================================================================

func TestLocalCopyKey_Success(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()

	// Store a source key
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockBackend.StoreKey("source-key", ecdsaKey)

	// Create a config that returns the same mock for both source and dest
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}

	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "software", "", "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected success message output")
	}

	if len(mockBackend.ExportKeyCalls) != 1 {
		t.Errorf("Expected 1 ExportKey call, got %d", len(mockBackend.ExportKeyCalls))
	}

	if len(mockBackend.ImportKeyCalls) != 1 {
		t.Errorf("Expected 1 ImportKey call, got %d", len(mockBackend.ImportKeyCalls))
	}
}

func TestLocalCopyKey_Error_SourceBackendCreation(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return nil, fmt.Errorf("backend creation error")
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "software", "", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for source backend creation error, got %d", code)
	}
}

func TestLocalCopyKey_Error_SourceBackendNotSupportsExport(t *testing.T) {
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "software", "", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for source backend not supporting export, got %d", code)
	}
}

func TestLocalCopyKey_Error_InvalidSourceKeyParams(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "software", "", "invalid-type", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid source key params, got %d", code)
	}
}

func TestLocalCopyKey_Error_ExportKeyFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.ExportKeyFunc = func(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
		return nil, fmt.Errorf("export key failed")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "software", "", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for export key failure, got %d", code)
	}
}

func TestLocalCopyKey_Error_DestBackendCreation(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockBackend.StoreKey("source-key", ecdsaKey)

	callCount := 0
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		callCount++
		if callCount == 1 {
			return mockBackend, nil
		}
		return nil, fmt.Errorf("dest backend creation error")
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "other-backend", "", "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for dest backend creation error, got %d", code)
	}
}

func TestLocalCopyKey_Error_ImportKeyFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockBackend.StoreKey("source-key", ecdsaKey)
	mockBackend.ImportKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
		return fmt.Errorf("import key failed")
	}

	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "source-key", "dest-key", "software", "", "tls", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for import key failure, got %d", code)
	}
}

// =============================================================================
// Tests for listKeysLocal
// =============================================================================

func TestLocalListKeys_Success(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()

	// Store some keys
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockBackend.StoreKey("rsa-key", rsaKey)
	mockBackend.StoreKey("ecdsa-key", ecdsaKey)

	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		listKeysLocal(cfg, printer)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected key list output")
	}

	if mockBackend.ListKeysCalls != 1 {
		t.Errorf("Expected 1 ListKeys call, got %d", mockBackend.ListKeysCalls)
	}
}

func TestLocalListKeys_Error_BackendCreation(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return nil, fmt.Errorf("backend creation error")
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		listKeysLocal(cfg, printer)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for backend creation error, got %d", code)
	}
}

func TestLocalListKeys_Error_ListKeysFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, fmt.Errorf("list keys failed")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		listKeysLocal(cfg, printer)
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for list keys failure, got %d", code)
	}
}

// =============================================================================
// Tests for additional edge cases
// =============================================================================

func TestLocalDecrypt_Error_SymmetricDecryptFails(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	keyMaterial := make([]byte, 32)
	_, _ = rand.Read(keyMaterial)
	mockBackend.StoreSymmetricKey("test-key", keyMaterial)

	// Return an encrypter that will fail on decrypt
	mockBackend.SymmetricEncrypterFunc = func(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
		return &mocks.MockSymmetricEncrypter{
			KeyMaterial:  keyMaterial,
			Algorithm:    string(types.SymmetricAES256GCM),
			DecryptError: fmt.Errorf("decryption failed"),
		}, nil
	}

	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	// Use valid base64 encoded values
	ciphertextB64 := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	nonceB64 := base64.StdEncoding.EncodeToString(make([]byte, 12))
	tagB64 := base64.StdEncoding.EncodeToString(make([]byte, 16))

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-key", ciphertextB64, "", string(types.SymmetricAES256GCM), 256, "", "", nonceB64, tagB64, "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for symmetric decryption failure, got %d", code)
	}
}

func TestLocalDecrypt_Error_InvalidNonceBase64(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	keyMaterial := make([]byte, 32)
	_, _ = rand.Read(keyMaterial)
	mockBackend.StoreSymmetricKey("test-key", keyMaterial)

	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	ciphertextB64 := base64.StdEncoding.EncodeToString([]byte("ciphertext"))

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-key", ciphertextB64, "", string(types.SymmetricAES256GCM), 256, "", "", "invalid-base64!!!", "dGFn", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid nonce base64, got %d", code)
	}
}

func TestLocalDecrypt_Error_InvalidTagBase64(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	keyMaterial := make([]byte, 32)
	_, _ = rand.Read(keyMaterial)
	mockBackend.StoreSymmetricKey("test-key", keyMaterial)

	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	ciphertextB64 := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	nonceB64 := base64.StdEncoding.EncodeToString(make([]byte, 12))

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-key", ciphertextB64, "", string(types.SymmetricAES256GCM), 256, "", "", nonceB64, "invalid-base64!!!", "")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid tag base64, got %d", code)
	}
}

func TestLocalGenerateKey_Success_Exportable(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		generateKeyLocal(cfg, printer, "test-exportable-key", "tls", "", "rsa", 2048, "", true)
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected success message output")
	}
}

func TestLocalDecrypt_Success_RSA_OAEP(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()

	// Generate and store an RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	mockBackend.StoreKey("test-oaep-key", rsaKey)

	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	// Encrypt with OAEP
	plaintext := []byte("test plaintext for OAEP")
	ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, &rsaKey.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt with OAEP: %v", err)
	}
	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-oaep-key", ciphertextB64, "tls", "rsa", 2048, "", "", "", "", "sha256")
	})

	if code != -1 {
		t.Errorf("Expected no exit call on success, got code %d", code)
	}

	if buf.Len() == 0 {
		t.Error("Expected decrypted output")
	}
}

func TestLocalDecrypt_Error_InvalidHashAlgorithm(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockBackend.StoreKey("test-key", rsaKey)

	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	ciphertextB64 := base64.StdEncoding.EncodeToString([]byte("ciphertext"))

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "test-key", ciphertextB64, "tls", "rsa", 2048, "", "", "", "", "invalid-hash")
	})

	if code != 1 {
		t.Errorf("Expected exit code 1 for invalid hash algorithm, got %d", code)
	}
}
