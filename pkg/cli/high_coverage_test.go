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
// Helper functions for high coverage tests
// =============================================================================

func createHighCoverageTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.OutputFormat = "text"
	cfg.UseLocal = true
	return cfg
}

func createHighCoverageTestPrinter(t *testing.T, format string) (*Printer, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	printer := NewPrinter(format, buf)
	return printer, buf
}

func createHighCoverageTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "High Coverage Test Certificate",
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
// Test verifyLocal additional paths
// =============================================================================

func TestVerifyLocalEd25519Success(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "verify-ed25519-key"

	// Generate an Ed25519 signing key
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ed25519", 0, "", false)
	buf.Reset()

	// Get the backend and sign data
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

	data := "test data to verify with Ed25519"
	signature, err := signer.Sign(rand.Reader, []byte(data), crypto.Hash(0))
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	buf.Reset()

	// Verify the signature
	verifyLocal(cfg, printer, keyID, data, signatureB64, "signing", "ed25519", 0, "", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from verifyLocal")
	}
}

func TestVerifyLocalRSASuccess(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "verify-rsa-key"

	// Generate an RSA signing key
	generateKeyLocal(cfg, printer, keyID, "signing", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get the backend and sign data
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

	data := "test data to verify with RSA"
	digest := crypto.SHA256.New()
	digest.Write([]byte(data))
	signature, err := signer.Sign(rand.Reader, digest.Sum(nil), crypto.SHA256)
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

// =============================================================================
// Test encryptAsymLocal additional paths
// =============================================================================

func TestEncryptAsymLocalSuccess(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "encrypt-asym-rsa-key"

	// Generate an RSA encryption key
	generateKeyLocal(cfg, printer, keyID, "encryption", "", "rsa", 2048, "", false)
	buf.Reset()

	// Encrypt with RSA OAEP
	encryptAsymLocal(cfg, printer, keyID, "secret plaintext message", "encryption", "rsa", 2048, "", "SHA-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptAsymLocal")
	}
}

func TestEncryptAsymLocalSHA384(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "encrypt-asym-sha384-key"

	// Generate an RSA encryption key
	generateKeyLocal(cfg, printer, keyID, "encryption", "", "rsa", 2048, "", false)
	buf.Reset()

	// Encrypt with SHA-384
	encryptAsymLocal(cfg, printer, keyID, "secret message with SHA-384", "encryption", "rsa", 2048, "", "SHA-384")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptAsymLocal")
	}
}

func TestEncryptAsymLocalSHA512(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "encrypt-asym-sha512-key"

	// Generate an RSA 4096-bit key (SHA-512 OAEP needs larger key)
	generateKeyLocal(cfg, printer, keyID, "encryption", "", "rsa", 4096, "", false)
	buf.Reset()

	encryptAsymLocal(cfg, printer, keyID, "secret message with SHA-512", "encryption", "rsa", 4096, "", "SHA-512")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptAsymLocal")
	}
}

// =============================================================================
// Test getImportParamsLocal additional paths
// =============================================================================

func TestGetImportParamsLocalToFile(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "import-params-file-key"
	outputFile := filepath.Join(t.TempDir(), "import-params.json")

	// Generate a key
	generateKeyLocal(cfg, printer, keyID, "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get import parameters and write to file
	getImportParamsLocal(cfg, printer, keyID, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, outputFile)

	// Check file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Import params file was not created")
	}

	// Verify file contains valid JSON (note: crypto.PublicKey contains large integers that overflow float64)
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read import params file: %v", err)
	}

	// Use json.Decoder with UseNumber to handle large RSA modulus values
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var jsonData map[string]interface{}
	if err := dec.Decode(&jsonData); err != nil {
		t.Errorf("Import params file contains invalid JSON: %v", err)
	}

	// Verify expected fields are present
	if _, ok := jsonData["WrappingPublicKey"]; !ok {
		t.Error("Import params missing WrappingPublicKey field")
	}
}

func TestGetImportParamsLocalNoPrint(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "json")

	keyID := "import-params-json-key"

	// Generate a key
	generateKeyLocal(cfg, printer, keyID, "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// Get import parameters (no file output)
	getImportParamsLocal(cfg, printer, keyID, "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getImportParamsLocal")
	}
}

// =============================================================================
// Test wrapKeyLocal additional paths
// =============================================================================

func TestWrapKeyLocalToFile(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")
	outputFile := filepath.Join(t.TempDir(), "wrapped-key.json")

	// Create test key material
	keyMaterial := make([]byte, 32)
	if _, err := rand.Read(keyMaterial); err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	// Create wrapping key and params
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

	// Verify file contains valid JSON
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read wrapped key file: %v", err)
	}

	var wrapped backend.WrappedKeyMaterial
	if err := json.Unmarshal(data, &wrapped); err != nil {
		t.Errorf("Wrapped key file contains invalid JSON: %v", err)
	}
}

// =============================================================================
// Test rotateKeyLocal additional paths
// =============================================================================

func TestRotateKeyLocalECDSA(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "rotate-ecdsa-key"

	// Generate an ECDSA key
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ecdsa", 0, "P-256", false)
	buf.Reset()

	// Rotate the key
	rotateKeyLocal(cfg, printer, keyID, "signing", "ecdsa", 0, "P-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from rotateKeyLocal")
	}
}

func TestRotateKeyLocalEd25519(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "rotate-ed25519-key"

	// Generate an Ed25519 key
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ed25519", 0, "", false)
	buf.Reset()

	// Rotate the key
	rotateKeyLocal(cfg, printer, keyID, "signing", "ed25519", 0, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from rotateKeyLocal")
	}
}

// =============================================================================
// Test signLocal additional paths
// =============================================================================

func TestSignLocalRSASHA1(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "sign-rsa-sha1-key"

	// Generate an RSA signing key
	generateKeyLocal(cfg, printer, keyID, "signing", "", "rsa", 2048, "", false)
	buf.Reset()

	// Sign with SHA-1
	signLocal(cfg, printer, keyID, "test data to sign", "signing", "rsa", 2048, "", "SHA-1")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from signLocal")
	}
}

// =============================================================================
// Test encryptLocal additional paths
// =============================================================================

func TestEncryptLocalAES128_HighCov(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "encrypt-aes128-key"

	// Generate an AES-128 key
	generateKeyLocal(cfg, printer, keyID, "symmetric", string(types.SymmetricAES128GCM), "", 128, "", false)
	buf.Reset()

	// Encrypt with AES-128
	encryptLocal(cfg, printer, keyID, "plaintext to encrypt", string(types.SymmetricAES128GCM), 128, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptLocal")
	}
}

func TestEncryptLocalAES192(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "encrypt-aes192-key"

	// Generate an AES-192 key
	generateKeyLocal(cfg, printer, keyID, "symmetric", string(types.SymmetricAES192GCM), "", 192, "", false)
	buf.Reset()

	// Encrypt with AES-192
	encryptLocal(cfg, printer, keyID, "plaintext to encrypt with 192-bit key", string(types.SymmetricAES192GCM), 192, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptLocal")
	}
}

// =============================================================================
// Test listKeysLocal additional paths
// =============================================================================

func TestListKeysLocalWithMultipleTypes(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "json")

	// Generate multiple key types
	generateKeyLocal(cfg, printer, "list-rsa-key", "tls", "", "rsa", 2048, "", false)
	generateKeyLocal(cfg, printer, "list-ecdsa-key", "signing", "", "ecdsa", 0, "P-256", false)
	generateKeyLocal(cfg, printer, "list-aes-key", "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
	buf.Reset()

	// List all keys with JSON output
	listKeysLocal(cfg, printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from listKeysLocal")
	}

	// Verify it's valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
}

func TestListKeysLocalTableFormat(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "table")

	// Generate a key
	generateKeyLocal(cfg, printer, "list-table-key", "tls", "", "rsa", 2048, "", false)
	buf.Reset()

	// List keys with table output
	listKeysLocal(cfg, printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from listKeysLocal")
	}
}

// =============================================================================
// Test getKeyLocal additional paths
// =============================================================================

func TestGetKeyLocalECDSA(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "get-ecdsa-key"

	// Generate an ECDSA key
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ecdsa", 0, "P-384", false)
	buf.Reset()

	// Get the key info
	getKeyLocal(cfg, printer, keyID, "signing", "ecdsa", 0, "P-384")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getKeyLocal")
	}
}

func TestGetKeyLocalEd25519(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "json")

	keyID := "get-ed25519-key"

	// Generate an Ed25519 key
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ed25519", 0, "", false)
	buf.Reset()

	// Get the key info
	getKeyLocal(cfg, printer, keyID, "signing", "ed25519", 0, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getKeyLocal")
	}
}

// =============================================================================
// Test deleteKeyLocal additional paths
// =============================================================================

func TestDeleteKeyLocalECDSA(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "delete-ecdsa-key"

	// Generate an ECDSA key
	generateKeyLocal(cfg, printer, keyID, "signing", "", "ecdsa", 0, "P-256", false)
	buf.Reset()

	// Delete the key
	deleteKeyLocal(cfg, printer, keyID, "signing", "ecdsa", 0, "P-256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from deleteKeyLocal")
	}
}

// =============================================================================
// Test certificate operations additional paths
// =============================================================================

func TestListCertsLocalEmpty(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "json")

	// List certificates in empty storage
	listCertsLocal(cfg, printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from listCertsLocal")
	}
}

func TestCertExistsLocalExists(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "exists-cert-key"
	cert := createHighCoverageTestCert(t)

	// Save certificate first
	saveCertLocal(cfg, printer, keyID, cert)
	buf.Reset()

	// Check if exists
	certExistsLocal(cfg, printer, keyID)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from certExistsLocal")
	}
}

func TestCertExistsLocalNotExists(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	// Check if nonexistent cert exists - should return false not error
	certExistsLocal(cfg, printer, "nonexistent-cert-key")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from certExistsLocal")
	}
}

// =============================================================================
// Test certificate chain operations additional paths
// =============================================================================

func TestSaveChainLocalMultipleCerts(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	// Create multiple certificates for the chain
	cert1 := createHighCoverageTestCert(t)
	cert2 := createHighCoverageTestCert(t)
	chain := []*x509.Certificate{cert1, cert2}

	// Save chain
	saveChainLocal(cfg, printer, "multi-chain-key", chain)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from saveChainLocal")
	}
}

// =============================================================================
// Test backend info additional paths
// =============================================================================

func TestBackendInfoLocalAllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}
	backends := []string{"software", "pkcs8", "pkcs11", "tpm2"}

	for _, format := range formats {
		for _, be := range backends {
			t.Run(format+"-"+be, func(t *testing.T) {
				printer, buf := createHighCoverageTestPrinter(t, format)
				backendInfoLocal(printer, be)
				output := buf.String()
				if output == "" {
					t.Errorf("Expected output from backendInfoLocal(%s) with format %s", be, format)
				}
			})
		}
	}
}

// =============================================================================
// Test output format variations
// =============================================================================

func TestGenerateKeyLocalAllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			cfg := createHighCoverageTestConfig(t)
			cfg.OutputFormat = format
			printer, buf := createHighCoverageTestPrinter(t, format)

			keyID := "format-test-" + format + "-key"
			generateKeyLocal(cfg, printer, keyID, "tls", "", "rsa", 2048, "", false)

			output := buf.String()
			if output == "" {
				t.Errorf("Expected output with format %s", format)
			}
		})
	}
}

// =============================================================================
// Test symmetric key operations with AES type specifier
// =============================================================================

func TestGenerateKeyLocalAESType(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	// Generate symmetric key using "aes" type
	generateKeyLocal(cfg, printer, "test-aes-type-key", "aes", "", "", 256, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyLocal")
	}
}

func TestDeleteKeyLocalSymmetricAES(t *testing.T) {
	cfg := createHighCoverageTestConfig(t)
	printer, buf := createHighCoverageTestPrinter(t, "text")

	keyID := "delete-aes-type-key"

	// Generate symmetric key
	generateKeyLocal(cfg, printer, keyID, "aes", "", "", 256, "", false)
	buf.Reset()

	// Delete using AES algorithm specifier
	deleteKeyLocal(cfg, printer, keyID, "", string(types.SymmetricAES256GCM), 256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from deleteKeyLocal")
	}
}
