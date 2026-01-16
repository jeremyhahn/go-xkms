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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// =============================================================================
// Helper functions for testing
// =============================================================================

func createTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.OutputFormat = "text"
	cfg.UseLocal = true
	return cfg
}

func createTestPrinter(t *testing.T) (*Printer, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	return printer, buf
}

func createTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
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
// Test generateKeyLocal - Success paths only
// =============================================================================

func TestGenerateKeyLocalRSA(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-rsa-key", "tls", "", "rsa", 2048, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocalECDSA(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-ecdsa-key", "signing", "", "ecdsa", 0, "P-256", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocalEd25519(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-ed25519-key", "signing", "", "ed25519", 0, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocalSymmetricAES256(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-aes-key", "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocalSymmetricAES128(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-aes128-key", "symmetric", string(types.SymmetricAES128GCM), "", 128, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocalSymmetricAES192(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-aes192-key", "symmetric", string(types.SymmetricAES192GCM), "", 192, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocalExportable(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-exportable-key", "tls", "", "rsa", 2048, "", true)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

// =============================================================================
// Test listKeysLocal
// =============================================================================

func TestListKeysLocalEmpty(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	listKeysLocal(cfg, printer)

	// Should not error on empty key store
	_ = buf.String()
}

func TestListKeysLocalWithKeys(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a key first
	generateKeyLocal(cfg, printer, "list-test-key", "tls", "", "rsa", 2048, "", false)

	// Clear buffer
	buf.Reset()

	// List keys
	listKeysLocal(cfg, printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from listKeysLocal")
	}
}

// =============================================================================
// Test getKeyLocal
// =============================================================================

func TestGetKeyLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a key first
	generateKeyLocal(cfg, printer, "get-test-key", "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get key info
	getKeyLocal(cfg, printer, "get-test-key", "tls", "rsa", 2048, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getKeyLocal")
	}
}

// =============================================================================
// Test deleteKeyLocal
// =============================================================================

func TestDeleteKeyLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a key first
	generateKeyLocal(cfg, printer, "delete-test-key", "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// Delete the key
	deleteKeyLocal(cfg, printer, "delete-test-key", "tls", "rsa", 2048, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from deleteKeyLocal")
	}
}

func TestDeleteKeyLocalSymmetric(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a symmetric key first
	generateKeyLocal(cfg, printer, "delete-sym-key", "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
	buf.Reset()

	// Delete the symmetric key
	deleteKeyLocal(cfg, printer, "delete-sym-key", "", string(types.SymmetricAES256GCM), 256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from deleteKeyLocal")
	}
}

// =============================================================================
// Test signLocal
// =============================================================================

func TestSignLocalRSA(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a key first
	generateKeyLocal(cfg, printer, "sign-test-key", "signing", "", "rsa", 2048, "", false)
	buf.Reset()

	// Sign data
	signLocal(cfg, printer, "sign-test-key", "test data to sign", "signing", "rsa", 2048, "", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from signLocal")
	}
}

func TestSignLocalECDSA(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a key first
	generateKeyLocal(cfg, printer, "sign-ecdsa-key", "signing", "", "ecdsa", 0, "P-256", false)
	buf.Reset()

	// Sign data
	signLocal(cfg, printer, "sign-ecdsa-key", "test data to sign", "signing", "ecdsa", 0, "P-256", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from signLocal")
	}
}

func TestSignLocalEd25519(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a key first
	generateKeyLocal(cfg, printer, "sign-ed25519-key", "signing", "", "ed25519", 0, "", false)
	buf.Reset()

	// Sign data (Ed25519 signs raw message)
	signLocal(cfg, printer, "sign-ed25519-key", "test data to sign", "signing", "ed25519", 0, "", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from signLocal")
	}
}

// =============================================================================
// Test rotateKeyLocal
// =============================================================================

func TestRotateKeyLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a key first
	generateKeyLocal(cfg, printer, "rotate-test-key", "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// Rotate the key
	rotateKeyLocal(cfg, printer, "rotate-test-key", "tls", "rsa", 2048, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from rotateKeyLocal")
	}
}

// =============================================================================
// Test encryptLocal (symmetric)
// =============================================================================

func TestEncryptLocalSymmetric(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a symmetric key first
	generateKeyLocal(cfg, printer, "encrypt-test-key", "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
	buf.Reset()

	// Encrypt data
	encryptLocal(cfg, printer, "encrypt-test-key", "plaintext to encrypt", string(types.SymmetricAES256GCM), 256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptLocal")
	}
}

func TestEncryptLocalSymmetricWithAAD(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a symmetric key first
	generateKeyLocal(cfg, printer, "encrypt-aad-key", "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
	buf.Reset()

	// Encrypt data with AAD
	encryptLocal(cfg, printer, "encrypt-aad-key", "plaintext to encrypt", string(types.SymmetricAES256GCM), 256, "additional authenticated data")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptLocal with AAD")
	}
}

// =============================================================================
// Test decryptLocal (symmetric)
// =============================================================================

func TestDecryptLocalSymmetric(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "decrypt-test-key"

	// Generate a symmetric key first
	generateKeyLocal(cfg, printer, keyID, "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
	buf.Reset()

	// First encrypt some data
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

	plaintext := []byte("test plaintext data")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Encode components to base64
	ciphertextB64 := base64.StdEncoding.EncodeToString(encrypted.Ciphertext)
	nonceB64 := base64.StdEncoding.EncodeToString(encrypted.Nonce)
	tagB64 := base64.StdEncoding.EncodeToString(encrypted.Tag)

	buf.Reset()

	// Now decrypt
	decryptLocal(cfg, printer, keyID, ciphertextB64, "", string(types.SymmetricAES256GCM), 256, "", "", nonceB64, tagB64, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from decryptLocal")
	}
}

// =============================================================================
// Test verifyLocal
// =============================================================================

func TestVerifyLocalRSA(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "verify-test-key"

	// Generate a key and sign data
	generateKeyLocal(cfg, printer, keyID, "signing", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get the backend and sign manually to get signature
	be, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = be.Close() }()

	attrs, _ := buildKeyAttributesFromFlags(keyID, "signing", "rsa", 2048, "", false)
	attrs.Hash = crypto.SHA256

	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Failed to get signer: %v", err)
	}

	data := "test data to verify"
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(data))
	digest := hasher.Sum(nil)

	signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	buf.Reset()

	// Verify the signature
	verifyLocal(cfg, printer, keyID, data, signatureB64, "signing", "rsa", 2048, "", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from verifyLocal")
	}
}

func TestVerifyLocalECDSA(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "verify-ecdsa-key"

	// Generate a key
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ecdsa", 0, "P-256", false)
	buf.Reset()

	// Get the backend and sign manually
	be, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = be.Close() }()

	attrs, _ := buildKeyAttributesFromFlags(keyID, "signing", "ecdsa", 0, "P-256", false)
	attrs.Hash = crypto.SHA256

	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Failed to get signer: %v", err)
	}

	data := "test data to verify"
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(data))
	digest := hasher.Sum(nil)

	signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	buf.Reset()

	// Verify the signature
	verifyLocal(cfg, printer, keyID, data, signatureB64, "signing", "ecdsa", 0, "P-256", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from verifyLocal")
	}
}

// =============================================================================
// Test import/export operations
// =============================================================================

func TestExportKeyLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "export-test-key"
	outputFile := filepath.Join(t.TempDir(), "exported-key.json")

	// Generate an exportable key first
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ecdsa", 0, "P-256", true)
	buf.Reset()

	// Export the key
	exportKeyLocal(cfg, printer, keyID, outputFile, "signing", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	// Check output file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Export file was not created")
	}
}

// =============================================================================
// Test certificate operations
// =============================================================================

func TestSaveCertLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	cert := createTestCertificate(t)

	saveCertLocal(cfg, printer, "cert-test-key", cert)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from saveCertLocal")
	}
}

func TestGetCertLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "get-cert-key"
	cert := createTestCertificate(t)

	// Save cert first
	saveCertLocal(cfg, printer, keyID, cert)
	buf.Reset()

	// Get the cert
	getCertLocal(cfg, printer, keyID)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getCertLocal")
	}
}

func TestDeleteCertLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "delete-cert-key"
	cert := createTestCertificate(t)

	// Save cert first
	saveCertLocal(cfg, printer, keyID, cert)
	buf.Reset()

	// Delete the cert
	deleteCertLocal(cfg, printer, keyID)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from deleteCertLocal")
	}
}

func TestListCertsLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Save some certs first
	for i := 0; i < 3; i++ {
		cert := createTestCertificate(t)
		saveCertLocal(cfg, printer, "list-cert-"+string(rune('0'+i)), cert)
	}
	buf.Reset()

	// List certs
	listCertsLocal(cfg, printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from listCertsLocal")
	}
}

func TestCertExistsLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "exists-cert-key"
	cert := createTestCertificate(t)

	// Save cert first
	saveCertLocal(cfg, printer, keyID, cert)
	buf.Reset()

	// Check if cert exists
	certExistsLocal(cfg, printer, keyID)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from certExistsLocal")
	}
}

func TestCertExistsLocalNotFound(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Check nonexistent cert - certExistsLocal doesn't call handleError on not found
	certExistsLocal(cfg, printer, "nonexistent-cert")

	// Should still produce output indicating cert doesn't exist
	_ = buf.String()
}

// =============================================================================
// Test chain operations
// =============================================================================

func TestSaveChainLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	cert := createTestCertificate(t)
	chain := []*x509.Certificate{cert}

	saveChainLocal(cfg, printer, "chain-test-key", chain)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from saveChainLocal")
	}
}

func TestGetChainLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "get-chain-key"
	cert := createTestCertificate(t)
	chain := []*x509.Certificate{cert}

	// Save chain first
	saveChainLocal(cfg, printer, keyID, chain)
	buf.Reset()

	// Get chain
	getChainLocal(cfg, printer, keyID)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getChainLocal")
	}
}

// =============================================================================
// Test backend operations
// =============================================================================

func TestListBackendsLocal_LocalOps(t *testing.T) {
	printer, buf := createTestPrinter(t)

	listBackendsLocal(printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from listBackendsLocal")
	}
}

func TestBackendInfoLocal(t *testing.T) {
	printer, buf := createTestPrinter(t)

	backendInfoLocal(printer, "software")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from backendInfoLocal")
	}
}

func TestBackendInfoLocalAllBackends(t *testing.T) {
	backends := []string{"software", "pkcs8", "pkcs11", "tpm2", "awskms", "gcpkms", "azurekv", "vault"}

	for _, be := range backends {
		t.Run(be, func(t *testing.T) {
			printer, buf := createTestPrinter(t)
			backendInfoLocal(printer, be)
			output := buf.String()
			if output == "" {
				t.Errorf("Expected output from backendInfoLocal(%s)", be)
			}
		})
	}
}

// =============================================================================
// Test helper functions
// =============================================================================

func TestResolveStoragePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		envVar   string
		expected string
	}{
		{"explicit path", "/custom/path", "", "/custom/path"},
		{"default path", "", "", "/var/lib/keychain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVar != "" {
				if err := os.Setenv("KEYCHAIN_STORAGE_PATH", tt.envVar); err != nil {
					t.Fatalf("failed to set env: %v", err)
				}
				defer func() { _ = os.Unsetenv("KEYCHAIN_STORAGE_PATH") }()
			} else {
				_ = os.Unsetenv("KEYCHAIN_STORAGE_PATH")
			}

			result := resolveStoragePath(tt.path)
			if result != tt.expected {
				t.Errorf("resolveStoragePath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestResolveStoragePathWithEnvVar(t *testing.T) {
	if err := os.Setenv("KEYCHAIN_STORAGE_PATH", "/env/path"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() { _ = os.Unsetenv("KEYCHAIN_STORAGE_PATH") }()

	result := resolveStoragePath("")
	if result != "/env/path" {
		t.Errorf("resolveStoragePath() = %q, want /env/path", result)
	}
}

func TestRepeatString_LocalOps(t *testing.T) {
	tests := []struct {
		s      string
		count  int
		expect string
	}{
		{"-", 3, "---"},
		{"ab", 2, "abab"},
		{"x", 0, ""},
		{"", 5, ""},
	}

	for _, tt := range tests {
		result := repeatString(tt.s, tt.count)
		if result != tt.expect {
			t.Errorf("repeatString(%q, %d) = %q, want %q", tt.s, tt.count, result, tt.expect)
		}
	}
}

// =============================================================================
// Test copy operations
// =============================================================================

// =============================================================================
// Test wrap/unwrap operations
// =============================================================================

func TestWrapKeyLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "wrapped-key.json")

	// Create test key material
	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	// Create wrapping key for params
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

	// Check file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Wrapped key file was not created")
	}
}

func TestGetImportParamsLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "import-params-key"

	// Generate a key first
	generateKeyLocal(cfg, printer, keyID, "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get import parameters
	getImportParamsLocal(cfg, printer, keyID, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getImportParamsLocal")
	}
}

func TestGetImportParamsLocalWithOutput(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)
	outputFile := filepath.Join(t.TempDir(), "import-params.json")

	keyID := "import-params-key-file"

	// Generate a key first
	generateKeyLocal(cfg, printer, keyID, "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get import parameters with output file
	getImportParamsLocal(cfg, printer, keyID, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, outputFile)

	// Check file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Import params file was not created")
	}
}

// =============================================================================
// Test encrypt-asym operations
// =============================================================================

func TestEncryptAsymLocal(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "encrypt-asym-key"

	// Generate an RSA key first
	generateKeyLocal(cfg, printer, keyID, "encryption", "", "rsa", 2048, "", false)
	buf.Reset()

	// Test encrypt-asym function (RSA OAEP encryption)
	encryptAsymLocal(cfg, printer, keyID, "test plaintext", "encryption", "rsa", 2048, "", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptAsymLocal")
	}
}

// =============================================================================
// Test JSON output format
// =============================================================================

func TestLocalOperationsWithJSONOutput(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.OutputFormat = "json"

	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	// Generate key with JSON output
	generateKeyLocal(cfg, printer, "json-test-key", "tls", "", "rsa", 2048, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from generateKeyLocal")
	}

	// Verify it's valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
}

// =============================================================================
// Test table output format
// =============================================================================

func TestLocalOperationsWithTableOutput(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.OutputFormat = "table"

	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	// Generate key with table output
	generateKeyLocal(cfg, printer, "table-test-key", "tls", "", "rsa", 2048, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected table output from generateKeyLocal")
	}
}

// =============================================================================
// Additional tests for various key algorithms and curves
// =============================================================================

func TestGenerateKeyLocalRSA4096(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-rsa-4096-key", "tls", "", "rsa", 4096, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocalECDSAP384(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-ecdsa-p384-key", "signing", "", "ecdsa", 0, "P-384", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocalECDSAP521(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-ecdsa-p521-key", "signing", "", "ecdsa", 0, "P-521", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocalEncryptionType(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-encryption-key", "encryption", "", "rsa", 2048, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestGenerateKeyLocalCAType(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	generateKeyLocal(cfg, printer, "test-ca-key", "ca", "", "rsa", 2048, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

// =============================================================================
// Test sign with different hash algorithms
// =============================================================================

func TestSignLocalSHA384(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a key first
	generateKeyLocal(cfg, printer, "sign-sha384-key", "signing", "", "rsa", 2048, "", false)
	buf.Reset()

	// Sign data with SHA-384
	signLocal(cfg, printer, "sign-sha384-key", "test data to sign", "signing", "rsa", 2048, "", "SHA-384")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from signLocal")
	}
}

func TestSignLocalSHA512(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	// Generate a key first
	generateKeyLocal(cfg, printer, "sign-sha512-key", "signing", "", "rsa", 2048, "", false)
	buf.Reset()

	// Sign data with SHA-512
	signLocal(cfg, printer, "sign-sha512-key", "test data to sign", "signing", "rsa", 2048, "", "SHA-512")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from signLocal")
	}
}

// =============================================================================
// Test decryptLocal asymmetric RSA OAEP
// =============================================================================

func TestDecryptLocalAsymmetricRSAOAEP(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "decrypt-asym-key"

	// Generate an RSA key
	generateKeyLocal(cfg, printer, keyID, "encryption", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get the backend and encrypt some data
	be, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = be.Close() }()

	attrs, _ := buildKeyAttributesFromFlags(keyID, "encryption", "rsa", 2048, "", false)

	key, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	// Get public key and encrypt
	rsaPrivKey := key.(*rsa.PrivateKey)
	plaintext := []byte("test plaintext for RSA OAEP")

	ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, &rsaPrivKey.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)
	buf.Reset()

	// Now decrypt using the CLI function with SHA-256 hash
	decryptLocal(cfg, printer, keyID, ciphertextB64, "encryption", "rsa", 2048, "", "", "", "", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from decryptLocal")
	}
}

func TestDecryptLocalAsymmetricRSAPKCS1(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "decrypt-pkcs1-key"

	// Generate an RSA key
	generateKeyLocal(cfg, printer, keyID, "encryption", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get the backend and encrypt some data
	be, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = be.Close() }()

	attrs, _ := buildKeyAttributesFromFlags(keyID, "encryption", "rsa", 2048, "", false)

	key, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	// Get public key and encrypt with PKCS1v15
	rsaPrivKey := key.(*rsa.PrivateKey)
	plaintext := []byte("test plaintext for RSA PKCS1")

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaPrivKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)
	buf.Reset()

	// Now decrypt using the CLI function without hash (PKCS1v15 mode)
	decryptLocal(cfg, printer, keyID, ciphertextB64, "encryption", "rsa", 2048, "", "", "", "", "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from decryptLocal")
	}
}

// =============================================================================
// Test decryptLocal with symmetric AAD
// =============================================================================

func TestDecryptLocalSymmetricWithAAD_Local(t *testing.T) {
	cfg := createTestConfig(t)
	printer, buf := createTestPrinter(t)

	keyID := "decrypt-aad-key"

	// Generate a symmetric key first
	generateKeyLocal(cfg, printer, keyID, "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
	buf.Reset()

	// First encrypt some data with AAD
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
	aad := []byte("additional authenticated data")
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{AdditionalData: aad})
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Encode components to base64
	ciphertextB64 := base64.StdEncoding.EncodeToString(encrypted.Ciphertext)
	nonceB64 := base64.StdEncoding.EncodeToString(encrypted.Nonce)
	tagB64 := base64.StdEncoding.EncodeToString(encrypted.Tag)

	buf.Reset()

	// Now decrypt with AAD
	decryptLocal(cfg, printer, keyID, ciphertextB64, "", string(types.SymmetricAES256GCM), 256, "", string(aad), nonceB64, tagB64, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from decryptLocal")
	}
}

// =============================================================================
// Test more certificate helper functions
// =============================================================================

func TestGenerateCALocal(t *testing.T) {
	// Test the generateCA helper function
	cert, privKey, err := generateCA(
		"Test CA",
		"Test Organization",
		"Test Unit",
		"US",
		"California",
		"San Francisco",
		365,
		"rsa",
		2048,
	)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}
	if cert == nil {
		t.Fatal("Certificate should not be nil")
	}
	if privKey == nil {
		t.Fatal("Private key should not be nil")
	}
	if !cert.IsCA {
		t.Error("Certificate should be a CA")
	}
}

func TestGenerateCALocalECDSA(t *testing.T) {
	// Test the generateCA with ECDSA
	cert, privKey, err := generateCA(
		"Test CA",
		"Test Organization",
		"",
		"",
		"",
		"",
		365,
		"ecdsa",
		256,
	)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}
	if cert == nil {
		t.Error("Certificate should not be nil")
	}
	if privKey == nil {
		t.Error("Private key should not be nil")
	}
}

func TestGenerateCALocalEd25519(t *testing.T) {
	// Test the generateCA with Ed25519
	cert, privKey, err := generateCA(
		"Test CA",
		"",
		"",
		"",
		"",
		"",
		365,
		"ed25519",
		0,
	)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}
	if cert == nil {
		t.Error("Certificate should not be nil")
	}
	if privKey == nil {
		t.Error("Private key should not be nil")
	}
}

func TestIssueCertificateServer(t *testing.T) {
	// First generate a CA
	caCert, caKey, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "rsa", 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Issue a server certificate
	cert, privKey, err := issueCertificate(
		caCert, caKey,
		"server.example.com", "server",
		"Test Org", "", "", "", "",
		365, "rsa", 2048,
		[]string{"server.example.com", "localhost"},
		nil, nil,
	)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}
	if cert == nil {
		t.Fatal("Certificate should not be nil")
	}
	if privKey == nil {
		t.Fatal("Private key should not be nil")
	}
	if cert.IsCA {
		t.Error("Certificate should not be a CA")
	}
}

func TestIssueCertificateClient(t *testing.T) {
	// First generate a CA
	caCert, caKey, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "rsa", 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Issue a client certificate
	cert, privKey, err := issueCertificate(
		caCert, caKey,
		"user@example.com", "client",
		"Test Org", "", "", "", "",
		365, "rsa", 2048,
		nil, nil, []string{"user@example.com"},
	)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}
	if cert == nil {
		t.Error("Certificate should not be nil")
	}
	if privKey == nil {
		t.Error("Private key should not be nil")
	}
}

func TestIssueCertificateDefault(t *testing.T) {
	// First generate a CA
	caCert, caKey, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Issue a certificate with default type (both server and client)
	cert, privKey, err := issueCertificate(
		caCert, caKey,
		"test.example.com", "both",
		"Test Org", "Test Unit", "US", "CA", "SF",
		365, "ecdsa", 256,
		[]string{"test.example.com"},
		nil, nil,
	)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}
	if cert == nil {
		t.Error("Certificate should not be nil")
	}
	if privKey == nil {
		t.Error("Private key should not be nil")
	}
}

// =============================================================================
// Test generateKeyPair helper function
// =============================================================================

func TestGenerateKeyPairRSA(t *testing.T) {
	privKey, err := generateKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	if privKey == nil {
		t.Error("Private key should not be nil")
	}
	if _, ok := privKey.(*rsa.PrivateKey); !ok {
		t.Error("Expected RSA private key")
	}
}

func TestGenerateKeyPairRSASmallSize(t *testing.T) {
	// Should default to 2048 if size is too small
	privKey, err := generateKeyPair("rsa", 1024)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	if privKey == nil {
		t.Error("Private key should not be nil")
	}
}

func TestGenerateKeyPairECDSA256(t *testing.T) {
	privKey, err := generateKeyPair("ecdsa", 256)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	if privKey == nil {
		t.Error("Private key should not be nil")
	}
	if ecKey, ok := privKey.(*ecdsa.PrivateKey); ok {
		if ecKey.Curve != elliptic.P256() {
			t.Error("Expected P-256 curve")
		}
	} else {
		t.Error("Expected ECDSA private key")
	}
}

func TestGenerateKeyPairECDSA384(t *testing.T) {
	privKey, err := generateKeyPair("ecdsa", 384)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	if ecKey, ok := privKey.(*ecdsa.PrivateKey); ok {
		if ecKey.Curve != elliptic.P384() {
			t.Error("Expected P-384 curve")
		}
	} else {
		t.Error("Expected ECDSA private key")
	}
}

func TestGenerateKeyPairECDSA521(t *testing.T) {
	privKey, err := generateKeyPair("ecdsa", 521)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	if ecKey, ok := privKey.(*ecdsa.PrivateKey); ok {
		if ecKey.Curve != elliptic.P521() {
			t.Error("Expected P-521 curve")
		}
	} else {
		t.Error("Expected ECDSA private key")
	}
}

func TestGenerateKeyPairEC(t *testing.T) {
	// Test EC alias for ECDSA
	privKey, err := generateKeyPair("ec", 256)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	if privKey == nil {
		t.Error("Private key should not be nil")
	}
}

func TestGenerateKeyPairEd25519(t *testing.T) {
	privKey, err := generateKeyPair("ed25519", 0)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	if privKey == nil {
		t.Error("Private key should not be nil")
	}
}

func TestGenerateKeyPairDefault(t *testing.T) {
	// Unknown algorithm should default to ECDSA P-256
	privKey, err := generateKeyPair("unknown", 0)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	if privKey == nil {
		t.Error("Private key should not be nil")
	}
}

// =============================================================================
// Test getPublicKey helper function
// =============================================================================

func TestGetPublicKeyRSA(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := getPublicKey(privKey)
	if pubKey == nil {
		t.Error("Public key should not be nil")
	}
	if _, ok := pubKey.(*rsa.PublicKey); !ok {
		t.Error("Expected RSA public key")
	}
}

func TestGetPublicKeyECDSA(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := getPublicKey(privKey)
	if pubKey == nil {
		t.Error("Public key should not be nil")
	}
	if _, ok := pubKey.(*ecdsa.PublicKey); !ok {
		t.Error("Expected ECDSA public key")
	}
}

func TestGetPublicKeyEd25519(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKey := getPublicKey(privKey)
	if pubKey == nil {
		t.Error("Public key should not be nil")
	}
}

// =============================================================================
// Test splitAndTrim helper function
// =============================================================================

func TestSplitAndTrimLocalOps(t *testing.T) {
	tests := []struct {
		input  string
		expect []string
	}{
		{"a, b, c", []string{"a", "b", "c"}},
		{"  hello ,  world  ", []string{"hello", "world"}},
		{"single", []string{"single"}},
		{"", []string{}},
		{"  ,  ,  ", []string{}},
	}

	for _, tt := range tests {
		result := splitAndTrim(tt.input)
		if len(result) != len(tt.expect) {
			t.Errorf("splitAndTrim(%q) = %v, want %v", tt.input, result, tt.expect)
			continue
		}
		for i := range result {
			if result[i] != tt.expect[i] {
				t.Errorf("splitAndTrim(%q)[%d] = %q, want %q", tt.input, i, result[i], tt.expect[i])
			}
		}
	}
}
