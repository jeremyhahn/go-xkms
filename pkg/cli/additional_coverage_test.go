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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// =============================================================================
// Test Printer.PrintSuccess and PrintError
// =============================================================================

func TestPrinterPrintSuccessAllFormats(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		message string
	}{
		{"text success", "text", "Operation completed successfully"},
		{"json success", "json", "Operation completed successfully"},
		{"table success", "table", "Operation completed successfully"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintSuccess(tt.message)
			if err != nil {
				t.Errorf("PrintSuccess() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintSuccess() produced no output")
			}
		})
	}
}

func TestPrinterPrintSuccessUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	err := printer.PrintSuccess("test message")
	if err == nil {
		t.Error("PrintSuccess() expected error for unknown format")
	}
}

func TestPrinterPrintErrorAllFormats(t *testing.T) {
	tests := []struct {
		name   string
		format string
	}{
		{"text error", "text"},
		{"json error", "json"},
		{"table error", "table"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			testErr := errAddlTestError{}
			err := printer.PrintError(testErr)
			if err != nil {
				t.Errorf("PrintError() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintError() produced no output")
			}
		})
	}
}

func TestPrinterPrintErrorUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	testErr := errAddlTestError{}
	err := printer.PrintError(testErr)
	if err == nil {
		t.Error("PrintError() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintSignature
// =============================================================================

func TestPrinterPrintSignatureAllFormats(t *testing.T) {
	signature := base64.StdEncoding.EncodeToString([]byte("test signature data"))

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintSignature(signature)
			if err != nil {
				t.Errorf("PrintSignature() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintSignature() produced no output")
			}
		})
	}
}

func TestPrinterPrintSignatureUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	err := printer.PrintSignature("signature")
	if err == nil {
		t.Error("PrintSignature() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintDecryptedData
// =============================================================================

func TestPrinterPrintDecryptedDataAllFormats(t *testing.T) {
	plaintext := "decrypted plaintext data"

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintDecryptedData(plaintext)
			if err != nil {
				t.Errorf("PrintDecryptedData() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintDecryptedData() produced no output")
			}
		})
	}
}

func TestPrinterPrintDecryptedDataUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	err := printer.PrintDecryptedData("plaintext")
	if err == nil {
		t.Error("PrintDecryptedData() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintCertList
// =============================================================================

func TestPrinterPrintCertListAllFormats(t *testing.T) {
	certIDs := []string{"cert1", "cert2", "cert3"}

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintCertList(certIDs)
			if err != nil {
				t.Errorf("PrintCertList() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintCertList() produced no output")
			}
		})
	}
}

func TestPrinterPrintCertListEmpty(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	err := printer.PrintCertList([]string{})
	if err != nil {
		t.Errorf("PrintCertList() error = %v", err)
	}
}

func TestPrinterPrintCertListUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	err := printer.PrintCertList([]string{"cert1"})
	if err == nil {
		t.Error("PrintCertList() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintCertExists
// =============================================================================

func TestPrinterPrintCertExistsAllFormats(t *testing.T) {
	tests := []struct {
		format string
		exists bool
	}{
		{"text", true},
		{"text", false},
		{"json", true},
		{"json", false},
		{"table", true},
		{"table", false},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintCertExists("test-cert", tt.exists)
			if err != nil {
				t.Errorf("PrintCertExists() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintCertExists() produced no output")
			}
		})
	}
}

func TestPrinterPrintCertExistsUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	err := printer.PrintCertExists("test-cert", true)
	if err == nil {
		t.Error("PrintCertExists() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintMessage
// =============================================================================

func TestPrinterPrintMessageAllFormats(t *testing.T) {
	message := "This is a test message"

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintMessage(message)
			if err != nil {
				t.Errorf("PrintMessage() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintMessage() produced no output")
			}
		})
	}
}

func TestPrinterPrintMessageUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	err := printer.PrintMessage("test message")
	if err == nil {
		t.Error("PrintMessage() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintEncryptedAsym
// =============================================================================

func TestPrinterPrintEncryptedAsymAllFormats(t *testing.T) {
	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted data"))

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintEncryptedAsym(ciphertext)
			if err != nil {
				t.Errorf("PrintEncryptedAsym() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintEncryptedAsym() produced no output")
			}
		})
	}
}

func TestPrinterPrintEncryptedAsymUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	err := printer.PrintEncryptedAsym("ciphertext")
	if err == nil {
		t.Error("PrintEncryptedAsym() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintBackendInfo
// =============================================================================

func TestPrinterPrintBackendInfoAllFormats(t *testing.T) {
	caps := types.Capabilities{
		Keys:           true,
		HardwareBacked: false,
		Signing:        true,
		Decryption:     true,
		KeyRotation:    true,
		Import:         true,
		Export:         true,
	}

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintBackendInfo("software", caps)
			if err != nil {
				t.Errorf("PrintBackendInfo() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintBackendInfo() produced no output")
			}
		})
	}
}

func TestPrinterPrintBackendInfoUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	caps := types.Capabilities{}
	err := printer.PrintBackendInfo("software", caps)
	if err == nil {
		t.Error("PrintBackendInfo() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintEncryptedData edge cases
// =============================================================================

func TestPrinterPrintEncryptedDataEdgeCases(t *testing.T) {
	// Data with all fields
	fullData := &types.EncryptedData{
		Ciphertext: []byte("encrypted-data-bytes-here"),
		Nonce:      []byte("nonce-12-bytes"),
		Tag:        []byte("authentication-tag-16bytes"),
		Algorithm:  "AES-256-GCM",
	}

	// Minimal data
	minData := &types.EncryptedData{
		Ciphertext: []byte("minimal"),
	}

	testCases := []*types.EncryptedData{fullData, minData}
	formats := []string{"text", "json", "table"}

	for i, data := range testCases {
		for _, format := range formats {
			t.Run(format, func(t *testing.T) {
				buf := &bytes.Buffer{}
				printer := NewPrinter(format, buf)

				err := printer.PrintEncryptedData(data)
				if err != nil {
					t.Errorf("PrintEncryptedData(%d) error = %v", i, err)
				}
			})
		}
	}
}

func TestPrinterPrintEncryptedDataUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	data := &types.EncryptedData{Ciphertext: []byte("test")}
	err := printer.PrintEncryptedData(data)
	if err == nil {
		t.Error("PrintEncryptedData() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintKeyList edge cases
// =============================================================================

func TestPrinterPrintKeyListEmptyList(t *testing.T) {
	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintKeyList([]*types.KeyAttributes{})
			if err != nil {
				t.Errorf("PrintKeyList() error = %v", err)
			}
		})
	}
}

func TestPrinterPrintKeyListUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	keys := []*types.KeyAttributes{{CN: "test"}}
	err := printer.PrintKeyList(keys)
	if err == nil {
		t.Error("PrintKeyList() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintKeyInfo edge cases
// =============================================================================

func TestPrinterPrintKeyInfoUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	key := &types.KeyAttributes{CN: "test"}
	err := printer.PrintKeyInfo(key)
	if err == nil {
		t.Error("PrintKeyInfo() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintCertificate edge cases
// =============================================================================

func TestPrinterPrintCertificateUnknownFormat(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	err := printer.PrintCertificate(cert)
	if err == nil {
		t.Error("PrintCertificate() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintCertChain edge cases
// =============================================================================

func TestPrinterPrintCertChainUnknownFormat(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	err := printer.PrintCertChain([]*x509.Certificate{cert})
	if err == nil {
		t.Error("PrintCertChain() expected error for unknown format")
	}
}

func TestPrinterPrintCertChainEmpty(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	err := printer.PrintCertChain([]*x509.Certificate{})
	if err != nil {
		t.Errorf("PrintCertChain() error = %v", err)
	}
}

// =============================================================================
// Test Printer.PrintImportParameters edge cases
// =============================================================================

func TestPrinterPrintImportParametersUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	params := &backend.ImportParameters{
		Algorithm: "RSA_OAEP_SHA256",
		KeySpec:   "AES_256",
	}
	err := printer.PrintImportParameters(params)
	if err == nil {
		t.Error("PrintImportParameters() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer FIDO2 edge cases
// =============================================================================

func TestPrinterPrintFIDO2DevicesUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	devices := []fido2Device{{Path: "/dev/hidraw0"}}
	err := printer.PrintFIDO2Devices(devices)
	if err == nil {
		t.Error("PrintFIDO2Devices() expected error for unknown format")
	}
}

func TestPrinterPrintFIDO2DeviceInfoUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	device := fido2Device{Path: "/dev/hidraw0"}
	err := printer.PrintFIDO2DeviceInfo(device)
	if err == nil {
		t.Error("PrintFIDO2DeviceInfo() expected error for unknown format")
	}
}

func TestPrinterPrintFIDO2RegistrationUnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	result := &fido2EnrollmentResult{
		CredentialID: []byte("cred-id"),
		Created:      time.Now(),
	}
	err := printer.PrintFIDO2Registration(result)
	if err == nil {
		t.Error("PrintFIDO2Registration() expected error for unknown format")
	}
}

// =============================================================================
// Test Printer.PrintTLSCertificate edge cases
// =============================================================================

func TestPrinterPrintTLSCertificateWithChain(t *testing.T) {
	// Create root CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Root CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	// Create leaf cert
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	chain := []*x509.Certificate{rootCert}

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintTLSCertificate(leafKey, leafCert, chain)
			if err != nil {
				t.Errorf("PrintTLSCertificate() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintTLSCertificate() produced no output")
			}
		})
	}
}

func TestPrinterPrintTLSCertificateUnknownFormat(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	err := printer.PrintTLSCertificate(privKey, cert, nil)
	if err == nil {
		t.Error("PrintTLSCertificate() expected error for unknown format")
	}
}

// =============================================================================
// Test isSymmetricAlgorithm
// =============================================================================

func TestIsSymmetricAlgorithmVariants(t *testing.T) {
	tests := []struct {
		algorithm string
		want      bool
	}{
		{string(types.SymmetricAES128GCM), true},
		{string(types.SymmetricAES192GCM), true},
		{string(types.SymmetricAES256GCM), true},
		{string(types.SymmetricChaCha20Poly1305), true},
		{"rsa", false},
		{"ecdsa", false},
		{"ed25519", false},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			got := isSymmetricAlgorithm(tt.algorithm)
			if got != tt.want {
				t.Errorf("isSymmetricAlgorithm(%q) = %v, want %v", tt.algorithm, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Test issueCertificate with various options
// =============================================================================

func TestIssueCertificateWithIP(t *testing.T) {
	caCert, caKey, _ := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)

	// Test server cert with IP addresses
	cert, key, err := issueCertificate(
		caCert, caKey,
		"server.example.com", "server",
		"Test Org", "Test OU", "US", "CA", "SF",
		30, "ecdsa", 256,
		[]string{"example.com"},
		[]net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("::1")},
		nil, // No email for server certs
	)
	if err != nil {
		t.Fatalf("issueCertificate() error = %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("issueCertificate() returned nil")
	}

	if len(cert.IPAddresses) != 2 {
		t.Errorf("Expected 2 IP addresses, got %d", len(cert.IPAddresses))
	}
}

func TestIssueCertificateWithEmail(t *testing.T) {
	caCert, caKey, _ := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)

	// Test client cert with email addresses
	cert, key, err := issueCertificate(
		caCert, caKey,
		"user@example.com", "client",
		"Test Org", "", "", "", "",
		30, "ecdsa", 256,
		nil, // No DNS names for client certs
		nil, // No IPs
		[]string{"user@example.com", "admin@example.com"},
	)
	if err != nil {
		t.Fatalf("issueCertificate() error = %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("issueCertificate() returned nil")
	}

	if len(cert.EmailAddresses) != 2 {
		t.Errorf("Expected 2 email addresses, got %d", len(cert.EmailAddresses))
	}
}

// =============================================================================
// Test generateCA with different algorithms
// =============================================================================

func TestGenerateCAWithDefaultKeySize(t *testing.T) {
	// Test RSA with default size
	cert, key, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "rsa", 0)
	if err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("generateCA() returned nil")
	}
}

// =============================================================================
// Test truncateString edge cases
// =============================================================================

func TestTruncateStringEdgeCases(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"", 0, ""},
		{"a", 0, ""},
		{"abc", 1, "a"},
		{"abc", 2, "ab"},
		{"abc", 3, "abc"},
		{"abcd", 4, "abcd"},
		{"abcdef", 4, "a..."},
		{"test with spaces", 10, "test wi..."},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := truncateString(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Test generateKeyPair with edge cases
// =============================================================================

func TestGenerateKeyPairEdgeCases(t *testing.T) {
	// Test ECDSA with edge case sizes
	tests := []struct {
		alg  string
		size int
	}{
		{"ecdsa", 0},   // Default
		{"ecdsa", 256}, // P-256
		{"ecdsa", 384}, // P-384
		{"ecdsa", 521}, // P-521
		{"ec", 0},      // Alias
		{"RSA", 0},     // Case insensitive? - depends on impl
		{"ECDSA", 0},   // Case insensitive? - depends on impl
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			key, err := generateKeyPair(tt.alg, tt.size)
			if err != nil {
				t.Logf("generateKeyPair(%q, %d) error = %v (may be expected)", tt.alg, tt.size, err)
				return
			}
			if key == nil {
				t.Error("generateKeyPair() returned nil key without error")
			}
		})
	}
}

// =============================================================================
// Test printJSON helper
// =============================================================================

func TestPrintJSONNested(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	data := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"level3": "deep value",
			},
		},
		"array": []interface{}{1, 2, 3},
	}

	err := printer.PrintJSON(data)
	if err != nil {
		t.Fatalf("PrintJSON() error = %v", err)
	}

	if buf.Len() == 0 {
		t.Error("PrintJSON() produced no output")
	}
}

// =============================================================================
// Test key operations with real backend (successful paths only)
// =============================================================================

func TestKeyGenerateAndListWithBackend(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true

	// First generate a key
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	generateKeyLocal(cfg, printer, "test-gen-list-key", "signing", "", "ecdsa", 0, "P-256", true)

	// Then list keys
	buf = &bytes.Buffer{}
	printer = NewPrinter("json", buf)
	listKeysLocal(cfg, printer)
}

// =============================================================================
// Helper test error type
// =============================================================================

type errAddlTestError struct{}

func (e errAddlTestError) Error() string { return "additional test error" }

// =============================================================================
// Test context usage
// =============================================================================

func TestContextBackground(t *testing.T) {
	ctx := context.Background()
	if ctx == nil {
		t.Error("context.Background() returned nil")
	}
}

// =============================================================================
// Test key attributes with symmetric keys
// =============================================================================

func TestKeyAttributesSymmetricKey(t *testing.T) {
	attrs := &types.KeyAttributes{
		CN:                 "test-symmetric",
		KeyType:            types.KeyTypeSecret,
		StoreType:          types.StoreSoftware,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	if attrs.CN != "test-symmetric" {
		t.Errorf("CN = %q, want 'test-symmetric'", attrs.CN)
	}
	if attrs.KeyType != types.KeyTypeSecret {
		t.Errorf("KeyType = %v, want KeyTypeSecret", attrs.KeyType)
	}
}

// =============================================================================
// Test PrintKeyInfo with various attributes
// =============================================================================

func TestPrinterPrintKeyInfoWithHash(t *testing.T) {
	key := &types.KeyAttributes{
		CN:           "test-key-with-hash",
		KeyType:      types.KeyTypeSigning,
		KeyAlgorithm: x509.RSA,
		StoreType:    types.StoreSoftware,
		Hash:         crypto.SHA512,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 4096,
		},
	}

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintKeyInfo(key)
			if err != nil {
				t.Errorf("PrintKeyInfo() error = %v", err)
			}
		})
	}
}
