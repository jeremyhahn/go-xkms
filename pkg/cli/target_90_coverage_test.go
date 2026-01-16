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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/client"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// =============================================================================
// Target: decryptLocal (74.5%)
// =============================================================================

func TestDecryptLocal_SymmetricWithAAD_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	keyMaterial := make([]byte, 32)
	_, _ = rand.Read(keyMaterial)
	mockBackend.StoreSymmetricKey("sym-aad-key", keyMaterial)

	encrypter := &mocks.MockSymmetricEncrypter{
		KeyMaterial: keyMaterial,
		Algorithm:   string(types.SymmetricAES256GCM),
	}

	aad := "additional-auth-data"
	plaintext := []byte("secret data")
	encrypted, _ := encrypter.Encrypt(plaintext, &types.EncryptOptions{AdditionalData: []byte(aad)})

	ct := base64.StdEncoding.EncodeToString(encrypted.Ciphertext)
	nonce := base64.StdEncoding.EncodeToString(encrypted.Nonce)
	tag := base64.StdEncoding.EncodeToString(encrypted.Tag)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "sym-aad-key", ct, "symmetric",
			string(types.SymmetricAES256GCM), 256, "", aad, nonce, tag, "")
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
	if buf.Len() == 0 {
		t.Error("Expected output")
	}
}

func TestDecryptLocal_InvalidSymmetricParams_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "key", base64.StdEncoding.EncodeToString([]byte("ct")),
			"symmetric", "invalid-algo", 0, "", "",
			base64.StdEncoding.EncodeToString([]byte("nonce")),
			base64.StdEncoding.EncodeToString([]byte("tag")), "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1 for invalid params, got %d", code)
	}
}

func TestDecryptLocal_SymmetricBackendNotSupported_90(t *testing.T) {
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "key", base64.StdEncoding.EncodeToString([]byte("ct")),
			"symmetric", string(types.SymmetricAES256GCM), 256, "", "",
			base64.StdEncoding.EncodeToString([]byte("nonce")),
			base64.StdEncoding.EncodeToString([]byte("tag")), "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestDecryptLocal_SymmetricEncrypterError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.SymmetricEncrypterFunc = func(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
		return nil, fmt.Errorf("encrypter error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "key", base64.StdEncoding.EncodeToString([]byte("ct")),
			"symmetric", string(types.SymmetricAES256GCM), 256, "", "",
			base64.StdEncoding.EncodeToString([]byte("nonce")),
			base64.StdEncoding.EncodeToString([]byte("tag")), "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestDecryptLocal_SymmetricDecryptionFails_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	keyMaterial := make([]byte, 32)
	_, _ = rand.Read(keyMaterial)
	mockBackend.StoreSymmetricKey("bad-key", keyMaterial)

	mockBackend.SymmetricEncrypterFunc = func(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
		return &mocks.MockSymmetricEncrypter{
			KeyMaterial:  keyMaterial,
			DecryptError: fmt.Errorf("decryption error"),
		}, nil
	}

	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "bad-key", base64.StdEncoding.EncodeToString([]byte("ct")),
			"symmetric", string(types.SymmetricAES256GCM), 256, "", "",
			base64.StdEncoding.EncodeToString([]byte("nonce")),
			base64.StdEncoding.EncodeToString([]byte("tag")), "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestDecryptLocal_AsymmetricRSA_PKCS1v15_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockBackend.StoreKey("rsa-pkcs1-key", rsaKey)

	plaintext := []byte("test")
	ciphertext, _ := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, plaintext)
	ct := base64.StdEncoding.EncodeToString(ciphertext)

	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "rsa-pkcs1-key", ct, "tls", "rsa", 2048, "", "", "", "", "")
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
	if buf.Len() == 0 {
		t.Error("Expected output")
	}
}

func TestDecryptLocal_AsymmetricRSA_OAEP_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockBackend.StoreKey("rsa-oaep-key", rsaKey)

	plaintext := []byte("oaep test")
	ciphertext, _ := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, &rsaKey.PublicKey, plaintext, nil)
	ct := base64.StdEncoding.EncodeToString(ciphertext)

	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "rsa-oaep-key", ct, "tls", "rsa", 2048, "", "", "", "", "SHA-256")
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
	if buf.Len() == 0 {
		t.Error("Expected output")
	}
}

func TestDecryptLocal_AsymmetricInvalidHash_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockBackend.StoreKey("rsa-bad-hash", rsaKey)

	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	ct := base64.StdEncoding.EncodeToString([]byte("ct"))
	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "rsa-bad-hash", ct, "tls", "rsa", 2048, "", "", "", "", "INVALID-HASH")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestDecryptLocal_AsymmetricGetKeyError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, fmt.Errorf("key not found")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	ct := base64.StdEncoding.EncodeToString([]byte("ct"))
	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "missing-key", ct, "tls", "rsa", 2048, "", "", "", "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestDecryptLocal_AsymmetricDecrypterError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.DecrypterFunc = func(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
		return nil, fmt.Errorf("decrypter error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	ct := base64.StdEncoding.EncodeToString([]byte("ct"))
	code := captureExit(t, func() {
		decryptLocal(cfg, printer, "key", ct, "tls", "rsa", 2048, "", "", "", "", "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: certExistsLocal (80%)
// =============================================================================

func TestCertExistsLocal_CertFound_90(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true
	printer, buf := newTestPrinter(t)

	certStorage, _ := cfg.CreateCertStorage()
	cert := createSelfSignedCert(t)
	_ = certStorage.SaveCert("found-cert", cert)

	code := captureExit(t, func() {
		certExistsLocal(cfg, printer, "found-cert")
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
	if buf.Len() == 0 {
		t.Error("Expected output")
	}
}

func TestCertExistsLocal_CertNotFound_90(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		certExistsLocal(cfg, printer, "nonexistent")
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
	if buf.Len() == 0 {
		t.Error("Expected output")
	}
}

func TestCertExistsLocal_StorageCreationFails_90(t *testing.T) {
	// Create a file to block directory creation
	tmpFile := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(tmpFile, []byte("block"), 0600); err != nil {
		t.Fatalf("Failed to create blocker file: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = filepath.Join(tmpFile, "certs") // Use file as directory path (will fail)
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		certExistsLocal(cfg, printer, "key")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: listCertsLocal (81.8%)
// =============================================================================

func TestListCertsLocal_Empty_90(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true
	printer, _ := newTestPrinter(t)

	code := captureExit(t, func() {
		listCertsLocal(cfg, printer)
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
}

func TestListCertsLocal_WithCerts_90(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true
	printer, buf := newTestPrinter(t)

	certStorage, _ := cfg.CreateCertStorage()
	for i := 0; i < 3; i++ {
		cert := createSelfSignedCert(t)
		_ = certStorage.SaveCert(fmt.Sprintf("cert-%d", i), cert)
	}

	code := captureExit(t, func() {
		listCertsLocal(cfg, printer)
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
	if buf.Len() == 0 {
		t.Error("Expected output")
	}
}

func TestListCertsLocal_StorageFails_90(t *testing.T) {
	// Create a file to block directory creation
	tmpFile := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(tmpFile, []byte("block"), 0600); err != nil {
		t.Fatalf("Failed to create blocker file: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = filepath.Join(tmpFile, "certs") // Use file as directory path (will fail)
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		listCertsLocal(cfg, printer)
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: getChainRemote (82.8%)
// =============================================================================

func TestGetChainRemote_InvalidPEM_90(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getChainResp = &client.GetCertificateChainResponse{
		ChainPEM: []string{"not-valid-pem"},
	}

	cfg := NewConfig()
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getChainRemote(cfg, printer, "key")
	})

	if code != 1 {
		t.Errorf("Expected exit 1 for invalid PEM, got %d", code)
	}
}

func TestGetChainRemote_InvalidCert_90(t *testing.T) {
	invalidCertPEM := "-----BEGIN CERTIFICATE-----\naW52YWxpZA==\n-----END CERTIFICATE-----"

	mockClient := NewMockClient()
	mockClient.getChainResp = &client.GetCertificateChainResponse{
		ChainPEM: []string{invalidCertPEM},
	}

	cfg := NewConfig()
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getChainRemote(cfg, printer, "key")
	})

	if code != 1 {
		t.Errorf("Expected exit 1 for invalid cert, got %d", code)
	}
}

func TestGetChainRemote_GetChainFails_90(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getChainErr = fmt.Errorf("chain error")

	cfg := NewConfig()
	cfg.ClientFactory = func(c *Config) (client.Client, error) {
		return mockClient, nil
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getChainRemote(cfg, printer, "key")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: generateCA (85.7%)
// =============================================================================

func TestGenerateCA_AllFields_90(t *testing.T) {
	cert, key, err := generateCA("Test CA", "Test Org", "Test OU", "US", "CA", "San Francisco", 365, "rsa", 2048)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("Expected cert and key")
	}

	if cert.Subject.CommonName != "Test CA" {
		t.Error("Wrong CN")
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "Test Org" {
		t.Error("Wrong Org")
	}
}

func TestGenerateCA_ECDSAMinimal_90(t *testing.T) {
	cert, key, err := generateCA("ECDSA CA", "", "", "", "", "", 30, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}

	if cert == nil || key == nil {
		t.Error("Expected cert and key")
	}
}

// =============================================================================
// Target: encryptLocal (85.7%)
// =============================================================================

func TestEncryptLocal_SuccessWithAAD_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	keyMaterial := make([]byte, 32)
	_, _ = rand.Read(keyMaterial)
	mockBackend.StoreSymmetricKey("enc-aad-key", keyMaterial)

	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		encryptLocal(cfg, printer, "enc-aad-key", "plaintext", string(types.SymmetricAES256GCM), 256, "extra-data")
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
	if buf.Len() == 0 {
		t.Error("Expected output")
	}
}

func TestEncryptLocal_BackendNotSymmetric_90(t *testing.T) {
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		encryptLocal(cfg, printer, "key", "data", string(types.SymmetricAES256GCM), 256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestEncryptLocal_EncrypterError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.SymmetricEncrypterFunc = func(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
		return nil, fmt.Errorf("encrypter fail")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		encryptLocal(cfg, printer, "key", "data", string(types.SymmetricAES256GCM), 256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestEncryptLocal_EncryptionFails_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	keyMaterial := make([]byte, 32)
	_, _ = rand.Read(keyMaterial)
	mockBackend.SymmetricEncrypterFunc = func(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
		return &mocks.MockSymmetricEncrypter{
			KeyMaterial:  keyMaterial,
			EncryptError: fmt.Errorf("encrypt fail"),
		}, nil
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		encryptLocal(cfg, printer, "key", "data", string(types.SymmetricAES256GCM), 256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: encryptAsymLocal (86.1%)
// =============================================================================

func TestEncryptAsymLocal_RSASuccess_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockBackend.StoreKey("asym-key", rsaKey)

	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	plaintext := base64.StdEncoding.EncodeToString([]byte("test"))
	code := captureExit(t, func() {
		encryptAsymLocal(cfg, printer, "asym-key", plaintext, "tls", "rsa", 2048, "", "SHA-256")
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
	if buf.Len() == 0 {
		t.Error("Expected output")
	}
}

func TestEncryptAsymLocal_InvalidPlaintext_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		encryptAsymLocal(cfg, printer, "key", "not-base64!!!", "tls", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestEncryptAsymLocal_SignerError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
		return nil, fmt.Errorf("signer error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	pt := base64.StdEncoding.EncodeToString([]byte("test"))
	code := captureExit(t, func() {
		encryptAsymLocal(cfg, printer, "key", pt, "tls", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestEncryptAsymLocal_NonRSAKey_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockBackend.StoreKey("ecdsa-key", ecdsaKey)

	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	pt := base64.StdEncoding.EncodeToString([]byte("test"))
	code := captureExit(t, func() {
		encryptAsymLocal(cfg, printer, "ecdsa-key", pt, "signing", "ecdsa", 0, "P-256", "SHA-256")
	})

	// ECDSA doesn't support encryption, should fail
	if code != 1 {
		t.Errorf("Expected exit 1 for non-RSA, got %d", code)
	}
}

// =============================================================================
// Target: rotateKeyLocal (86.7%)
// =============================================================================

func TestRotateKeyLocal_RotateError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.RotateKeyFunc = func(attrs *types.KeyAttributes) error {
		return fmt.Errorf("rotate error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		rotateKeyLocal(cfg, printer, "key", "tls", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: openUserStore (87.5%)
// =============================================================================

func TestOpenUserStore_InvalidPath_90(t *testing.T) {
	// Create a file to block directory creation
	tmpFile := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(tmpFile, []byte("block"), 0600); err != nil {
		t.Fatalf("Failed to create blocker file: %v", err)
	}

	_, err := openUserStore(filepath.Join(tmpFile, "users"))
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}

func TestOpenUserStore_Valid_90(t *testing.T) {
	tempDir := t.TempDir()
	store, err := openUserStore(tempDir)
	if err != nil {
		t.Fatalf("openUserStore failed: %v", err)
	}
	if store == nil {
		t.Error("Expected non-nil store")
	}
}

// =============================================================================
// Target: createTPM2Backend (87.5%)
// =============================================================================

// =============================================================================
// Target: wrapKeyLocal (87.5%)
// =============================================================================

func TestWrapKeyLocal_NoWrapKeyFile_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, _ := newTestPrinter(t)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	outputFile := filepath.Join(t.TempDir(), "wrapped.json")

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, []byte("key-material"), params, outputFile)
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Output file not created")
	}
}

func TestWrapKeyLocal_BackendNotImportExport_90(t *testing.T) {
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
	}

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, []byte("key"), params, "/tmp/out.json")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestWrapKeyLocal_WrapKeyError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.WrapKeyFunc = func(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
		return nil, fmt.Errorf("wrap error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
	}

	code := captureExit(t, func() {
		wrapKeyLocal(cfg, printer, []byte("key"), params, "/tmp/out.json")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: verifyLocal (88.2%)
// =============================================================================

func TestVerifyLocal_RSASuccess_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockBackend.StoreKey("verify-key", rsaKey)

	// verifyLocal hashes the raw data parameter
	message := "test message"
	hash := crypto.SHA256.New()
	hash.Write([]byte(message))
	digest := hash.Sum(nil)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest)

	sigB64 := base64.StdEncoding.EncodeToString(signature)

	cfg := newMockBackendConfig(t, mockBackend)
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		verifyLocal(cfg, printer, "verify-key", message, sigB64, "tls", "rsa", 2048, "", "SHA-256")
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
	if buf.Len() == 0 {
		t.Error("Expected output")
	}
}

func TestVerifyLocal_InvalidMessage_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		verifyLocal(cfg, printer, "key", "not-base64!!!", "sig", "tls", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestVerifyLocal_InvalidSignatureB64_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	msgB64 := base64.StdEncoding.EncodeToString([]byte("msg"))
	code := captureExit(t, func() {
		verifyLocal(cfg, printer, "key", msgB64, "not-base64!!!", "tls", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestVerifyLocal_InvalidHashAlg_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	msgB64 := base64.StdEncoding.EncodeToString([]byte("msg"))
	sigB64 := base64.StdEncoding.EncodeToString([]byte("sig"))
	code := captureExit(t, func() {
		verifyLocal(cfg, printer, "key", msgB64, sigB64, "tls", "rsa", 2048, "", "INVALID-HASH")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestVerifyLocal_SignerError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
		return nil, fmt.Errorf("signer error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	msgB64 := base64.StdEncoding.EncodeToString([]byte("msg"))
	sigB64 := base64.StdEncoding.EncodeToString([]byte("sig"))
	code := captureExit(t, func() {
		verifyLocal(cfg, printer, "key", msgB64, sigB64, "tls", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: copyKeyLocal (88.6%)
// =============================================================================

func TestCopyKeyLocal_BackendNotImportExport_90(t *testing.T) {
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "src", "dest", "software", t.TempDir(), "tls", "rsa", 2048, "", backend.WrappingAlgorithm(""))
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestCopyKeyLocal_ExportError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.ExportKeyFunc = func(attrs *types.KeyAttributes, alg backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
		return nil, fmt.Errorf("export error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		copyKeyLocal(cfg, printer, "src", "dest", "software", t.TempDir(), "tls", "rsa", 2048, "", backend.WrappingAlgorithm(""))
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: getImportParamsLocal (84.8%)
// =============================================================================

func TestGetImportParamsLocal_BackendNotImportExport_90(t *testing.T) {
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestGetImportParamsLocal_GetParamsError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.GetImportParametersFunc = func(attrs *types.KeyAttributes, alg backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
		return nil, fmt.Errorf("params error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestGetImportParamsLocal_WithOutputFile_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer, _ := newTestPrinter(t)

	outputFile := filepath.Join(t.TempDir(), "params.json")
	code := captureExit(t, func() {
		getImportParamsLocal(cfg, printer, "key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, outputFile)
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
}

// =============================================================================
// Target: deleteCertLocal (88.9%)
// =============================================================================

func TestDeleteCertLocal_DeleteError_90(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		deleteCertLocal(cfg, printer, "nonexistent")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: saveChainLocal (88.9%)
// =============================================================================

func TestSaveChainLocal_WithCerts_90(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true
	printer, buf := newTestPrinter(t)

	code := captureExit(t, func() {
		cert := createSelfSignedCert(t)
		saveChainLocal(cfg, printer, "chain-key-90", []*x509.Certificate{cert})
	})

	if code != -1 {
		t.Errorf("Expected no exit, got %d", code)
	}
	_ = buf.String()
}

// =============================================================================
// Target: saveCertLocal (88.9%)
// =============================================================================

func TestSaveCertLocal_SaveError_90(t *testing.T) {
	// Create a file to block directory creation
	tmpFile := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(tmpFile, []byte("block"), 0600); err != nil {
		t.Fatalf("Failed to create blocker file: %v", err)
	}

	cfg := NewConfig()
	cfg.KeyDir = filepath.Join(tmpFile, "certs") // Use file as directory path (will fail)
	cfg.UseLocal = true
	printer := NewPrinter("text", io.Discard)

	cert := createSelfSignedCert(t)
	code := captureExit(t, func() {
		saveCertLocal(cfg, printer, "key", cert)
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: exportKeyLocal (89.3%)
// =============================================================================

func TestExportKeyLocal_BackendNotImportExport_90(t *testing.T) {
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "key", "/tmp/out", "tls", "rsa", 2048, "", backend.WrappingAlgorithm(""))
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestExportKeyLocal_ExportError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.ExportKeyFunc = func(attrs *types.KeyAttributes, alg backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
		return nil, fmt.Errorf("export error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		exportKeyLocal(cfg, printer, "key", "/tmp/out", "tls", "rsa", 2048, "", backend.WrappingAlgorithm(""))
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: importKeyLocal (94.7%)
// =============================================================================

func TestImportKeyLocal_BackendNotImportExport_90(t *testing.T) {
	mockBackend := mocks.NewMockBackend()
	cfg := NewConfig()
	cfg.UseLocal = true
	cfg.BackendFactory = func(c *Config) (types.Backend, error) {
		return mockBackend, nil
	}
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{WrappedKey: []byte("key")}
	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "key", "tls", "rsa", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestImportKeyLocal_ImportError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.ImportKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
		return fmt.Errorf("import error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	wrapped := &backend.WrappedKeyMaterial{WrappedKey: []byte("key")}
	code := captureExit(t, func() {
		importKeyLocal(cfg, printer, "key", "tls", "rsa", 2048, "", wrapped)
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: signLocal (91.2%)
// =============================================================================

func TestSignLocal_InvalidMessageB64_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		signLocal(cfg, printer, "key", "not-base64!!!", "tls", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestSignLocal_InvalidHash_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	msgB64 := base64.StdEncoding.EncodeToString([]byte("msg"))
	code := captureExit(t, func() {
		signLocal(cfg, printer, "key", msgB64, "tls", "rsa", 2048, "", "INVALID")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

func TestSignLocal_SignerError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
		return nil, fmt.Errorf("signer error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	msgB64 := base64.StdEncoding.EncodeToString([]byte("msg"))
	code := captureExit(t, func() {
		signLocal(cfg, printer, "key", msgB64, "tls", "rsa", 2048, "", "SHA-256")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: getKeyLocal (93.8%)
// =============================================================================

func TestGetKeyLocal_GetKeyError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, fmt.Errorf("key not found")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		getKeyLocal(cfg, printer, "missing-key", "tls", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Target: deleteKeyLocal (94.4%)
// =============================================================================

func TestDeleteKeyLocal_DeleteError_90(t *testing.T) {
	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.DeleteKeyFunc = func(attrs *types.KeyAttributes) error {
		return fmt.Errorf("delete error")
	}
	cfg := newMockBackendConfig(t, mockBackend)
	printer := NewPrinter("text", io.Discard)

	code := captureExit(t, func() {
		deleteKeyLocal(cfg, printer, "key", "tls", "rsa", 2048, "")
	})

	if code != 1 {
		t.Errorf("Expected exit 1, got %d", code)
	}
}

// =============================================================================
// Helper functions
// =============================================================================

func createSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}
