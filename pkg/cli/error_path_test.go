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
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// =============================================================================
// Test error paths that don't call handleError
// =============================================================================

func TestParseHashAlgorithmValid(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected crypto.Hash
	}{
		{"sha256", "sha256", crypto.SHA256},
		{"sha384", "sha384", crypto.SHA384},
		{"sha512", "sha512", crypto.SHA512},
		{"SHA-256", "SHA-256", crypto.SHA256},
		{"SHA-384", "SHA-384", crypto.SHA384},
		{"SHA-512", "SHA-512", crypto.SHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, ok := types.AvailableHashes()[tc.input]
			if !ok {
				t.Errorf("Expected to find hash algorithm for %s", tc.input)
			}
			if result != tc.expected {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestBuildKeyAttributesValidKeyTypes(t *testing.T) {
	testCases := []struct {
		name    string
		keyType string
	}{
		{"tls", "tls"},
		{"signing", "signing"},
		{"encryption", "encryption"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// RSA
			attrs, err := buildKeyAttributesFromFlags("test-key", tc.keyType, "rsa", 2048, "", false)
			if err != nil {
				t.Errorf("Unexpected error for %s/rsa: %v", tc.keyType, err)
			}
			if attrs == nil {
				t.Errorf("Expected attributes for %s/rsa", tc.keyType)
			}
		})
	}
}

func TestBuildKeyAttributesValidCurves(t *testing.T) {
	curves := []string{"P-256", "P-384", "P-521"}

	for _, curve := range curves {
		t.Run(curve, func(t *testing.T) {
			attrs, err := buildKeyAttributesFromFlags("test-key", "signing", "ecdsa", 0, curve, false)
			if err != nil {
				t.Errorf("Unexpected error for curve %s: %v", curve, err)
			}
			if attrs == nil {
				t.Errorf("Expected attributes for curve %s", curve)
			}
		})
	}
}

func TestBuildKeyAttributesExportable(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 2048, "", true)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !attrs.Exportable {
		t.Error("Expected key to be exportable")
	}

	attrs2, err := buildKeyAttributesFromFlags("test-key", "tls", "rsa", 2048, "", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if attrs2.Exportable {
		t.Error("Expected key to not be exportable")
	}
}

func TestBuildSymmetricKeyAttributesAllSizes(t *testing.T) {
	testCases := []struct {
		name    string
		algo    string
		keySize int
	}{
		{"AES-128-GCM", string(types.SymmetricAES128GCM), 128},
		{"AES-192-GCM", string(types.SymmetricAES192GCM), 192},
		{"AES-256-GCM", string(types.SymmetricAES256GCM), 256},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := buildSymmetricKeyAttributes("test-key", tc.algo, tc.keySize)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if attrs == nil {
				t.Fatal("Expected attributes")
			}
			if attrs.KeyType != types.KeyTypeSecret {
				t.Errorf("Expected KeyTypeSymmetric type")
			}
		})
	}
}

func TestNewConfigDefaults(t *testing.T) {
	cfg := NewConfig()

	if cfg.Backend == "" {
		t.Error("Expected default backend to be set")
	}
	if cfg.OutputFormat == "" {
		t.Error("Expected default output format to be set")
	}
	if cfg.KeyDir == "" {
		t.Error("Expected default key directory to be set")
	}
}

func TestErrorPathConfigIsLocalAndIsRemote(t *testing.T) {
	cfg := NewConfig()

	// Test default state
	if cfg.IsRemote() {
		t.Error("Expected IsRemote to be false by default when no server is set")
	}

	// Set a server URL
	cfg.Server = "http://localhost:8080"
	if !cfg.IsRemote() {
		t.Error("Expected IsRemote to be true when server is set")
	}

	// Test IsLocal with UseLocal flag
	cfg.UseLocal = true
	if !cfg.IsLocal() {
		t.Error("Expected IsLocal to be true when UseLocal is set")
	}

	cfg.UseLocal = false
	if cfg.IsLocal() {
		t.Error("Expected IsLocal to be false when UseLocal is not set")
	}
}

func TestPrinterOutputFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}
	testErr := errors.New("test error")

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			// Test PrintSuccess
			err := printer.PrintSuccess("test message")
			if err != nil {
				t.Errorf("PrintSuccess failed for format %s: %v", format, err)
			}
			if buf.Len() == 0 {
				t.Errorf("Expected output for format %s", format)
			}
			buf.Reset()

			// Test PrintError
			err = printer.PrintError(testErr)
			if err != nil {
				t.Errorf("PrintError failed for format %s: %v", format, err)
			}
			if buf.Len() == 0 {
				t.Errorf("Expected output for format %s", format)
			}
			buf.Reset()

			// Test PrintMessage
			err = printer.PrintMessage("test")
			if err != nil {
				t.Errorf("PrintMessage failed for format %s: %v", format, err)
			}
			if buf.Len() == 0 {
				t.Errorf("Expected output for format %s", format)
			}
		})
	}
}

func TestPrinterInvalidFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)

	err := printer.PrintSuccess("test")
	if err == nil {
		t.Error("Expected error for invalid format")
	}
}

func TestPrinterKeyList(t *testing.T) {
	testCases := []struct {
		name   string
		format string
		keys   []*types.KeyAttributes
	}{
		{
			name:   "empty-text",
			format: "text",
			keys:   []*types.KeyAttributes{},
		},
		{
			name:   "empty-json",
			format: "json",
			keys:   []*types.KeyAttributes{},
		},
		{
			name:   "empty-table",
			format: "table",
			keys:   []*types.KeyAttributes{},
		},
		{
			name:   "with-keys-text",
			format: "text",
			keys: []*types.KeyAttributes{
				{CN: "key1", KeyType: types.KeyTypeTLS, KeyAlgorithm: x509.RSA},
				{CN: "key2", KeyType: types.KeyTypeSigning, KeyAlgorithm: x509.ECDSA},
			},
		},
		{
			name:   "with-keys-json",
			format: "json",
			keys: []*types.KeyAttributes{
				{CN: "key1", KeyType: types.KeyTypeTLS, KeyAlgorithm: x509.RSA},
			},
		},
		{
			name:   "with-keys-table",
			format: "table",
			keys: []*types.KeyAttributes{
				{CN: "key1", KeyType: types.KeyTypeTLS, KeyAlgorithm: x509.RSA},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tc.format, buf)

			err := printer.PrintKeyList(tc.keys)
			if err != nil {
				t.Errorf("PrintKeyList failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Error("Expected output")
			}
		})
	}
}

func TestPrinterKeyInfo(t *testing.T) {
	testCases := []struct {
		name   string
		format string
		key    *types.KeyAttributes
	}{
		{
			name:   "rsa-text",
			format: "text",
			key: &types.KeyAttributes{
				CN:            "test-rsa",
				KeyType:       types.KeyTypeTLS,
				KeyAlgorithm:  x509.RSA,
				Hash:          crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{KeySize: 2048},
			},
		},
		{
			name:   "ecdsa-json",
			format: "json",
			key: &types.KeyAttributes{
				CN:            "test-ecdsa",
				KeyType:       types.KeyTypeSigning,
				KeyAlgorithm:  x509.ECDSA,
				Hash:          crypto.SHA256,
				ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
				Partition:     "test-partition",
			},
		},
		{
			name:   "ed25519-table",
			format: "table",
			key: &types.KeyAttributes{
				CN:           "test-ed25519",
				KeyType:      types.KeyTypeSigning,
				KeyAlgorithm: x509.Ed25519,
				Hash:         crypto.SHA256,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tc.format, buf)

			err := printer.PrintKeyInfo(tc.key)
			if err != nil {
				t.Errorf("PrintKeyInfo failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Error("Expected output")
			}
		})
	}
}

func TestPrinterCertList(t *testing.T) {
	testCases := []struct {
		name    string
		format  string
		certIDs []string
	}{
		{"empty-text", "text", []string{}},
		{"empty-json", "json", []string{}},
		{"empty-table", "table", []string{}},
		{"with-certs-text", "text", []string{"cert1", "cert2"}},
		{"with-certs-json", "json", []string{"cert1", "cert2"}},
		{"with-certs-table", "table", []string{"cert1", "cert2"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tc.format, buf)

			err := printer.PrintCertList(tc.certIDs)
			if err != nil {
				t.Errorf("PrintCertList failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Error("Expected output")
			}
		})
	}
}

func TestPrinterCertExists(t *testing.T) {
	testCases := []struct {
		name   string
		format string
		keyID  string
		exists bool
	}{
		{"exists-text", "text", "test-key", true},
		{"not-exists-text", "text", "test-key", false},
		{"exists-json", "json", "test-key", true},
		{"not-exists-json", "json", "test-key", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tc.format, buf)

			err := printer.PrintCertExists(tc.keyID, tc.exists)
			if err != nil {
				t.Errorf("PrintCertExists failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Error("Expected output")
			}
		})
	}
}

func TestErrorPathTruncateString(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short-string", "hello", 10, "hello"},
		{"exact-length", "hello", 5, "hello"},
		{"needs-truncation", "hello world", 8, "hello..."},
		{"max-len-3", "hello", 3, "hel"},
		{"max-len-2", "hello", 2, "he"},
		{"empty-string", "", 10, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := truncateString(tc.input, tc.maxLen)
			if result != tc.expected {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tc.input, tc.maxLen, result, tc.expected)
			}
		})
	}
}

func TestPrinterBackendList(t *testing.T) {
	backends := []string{"software", "pkcs8", "pkcs11", "tpm2"}

	testCases := []struct {
		name   string
		format string
	}{
		{"text", "text"},
		{"json", "json"},
		{"table", "table"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tc.format, buf)

			err := printer.PrintBackendList(backends)
			if err != nil {
				t.Errorf("PrintBackendList failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Error("Expected output")
			}
		})
	}
}

func TestPrinterBackendInfo(t *testing.T) {
	caps := types.Capabilities{
		Keys:           true,
		HardwareBacked: true,
		Signing:        true,
		Decryption:     true,
		KeyRotation:    true,
	}

	testCases := []struct {
		name   string
		format string
	}{
		{"text", "text"},
		{"json", "json"},
		{"table", "table"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tc.format, buf)

			err := printer.PrintBackendInfo("software", caps)
			if err != nil {
				t.Errorf("PrintBackendInfo failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Error("Expected output")
			}
		})
	}
}

func TestPrinterSignature(t *testing.T) {
	signature := "dGVzdC1zaWduYXR1cmU="

	testCases := []struct {
		name   string
		format string
	}{
		{"text", "text"},
		{"json", "json"},
		{"table", "table"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tc.format, buf)

			err := printer.PrintSignature(signature)
			if err != nil {
				t.Errorf("PrintSignature failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Error("Expected output")
			}
		})
	}
}

func TestPrinterDecryptedData(t *testing.T) {
	plaintext := "decrypted data"

	testCases := []struct {
		name   string
		format string
	}{
		{"text", "text"},
		{"json", "json"},
		{"table", "table"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tc.format, buf)

			err := printer.PrintDecryptedData(plaintext)
			if err != nil {
				t.Errorf("PrintDecryptedData failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Error("Expected output")
			}
		})
	}
}

func TestPrinterEncryptedData(t *testing.T) {
	data := &types.EncryptedData{
		Ciphertext: []byte("encrypted"),
		Nonce:      []byte("nonce123456"),
		Tag:        []byte("tag12345"),
		Algorithm:  "AES-256-GCM",
	}

	testCases := []struct {
		name   string
		format string
	}{
		{"text", "text"},
		{"json", "json"},
		{"table", "table"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tc.format, buf)

			err := printer.PrintEncryptedData(data)
			if err != nil {
				t.Errorf("PrintEncryptedData failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Error("Expected output")
			}
		})
	}
}

func TestPrinterEncryptedAsym(t *testing.T) {
	ciphertext := "ZW5jcnlwdGVkLWRhdGE="

	testCases := []struct {
		name   string
		format string
	}{
		{"text", "text"},
		{"json", "json"},
		{"table", "table"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tc.format, buf)

			err := printer.PrintEncryptedAsym(ciphertext)
			if err != nil {
				t.Errorf("PrintEncryptedAsym failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Error("Expected output")
			}
		})
	}
}

func TestPrinterPrintJSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	data := map[string]interface{}{
		"key":    "value",
		"number": 42,
		"nested": map[string]interface{}{
			"inner": "data",
		},
	}

	err := printer.PrintJSON(data)
	if err != nil {
		t.Fatalf("PrintJSON failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("Expected output")
	}
}

func TestGetBackendCapabilitiesAll(t *testing.T) {
	backends := []string{"software", "pkcs8", "pkcs11", "tpm2", "awskms", "gcpkms", "azurekv", "vault"}

	for _, be := range backends {
		t.Run(be, func(t *testing.T) {
			caps, err := getBackendCapabilities(be)
			if err != nil {
				t.Errorf("getBackendCapabilities(%s) failed: %v", be, err)
				return
			}
			// Verify we got valid capabilities
			if caps == (types.Capabilities{}) {
				t.Errorf("Expected non-empty capabilities for %s", be)
			}
		})
	}
}

func TestGetBackendCapabilitiesUnknown(t *testing.T) {
	_, err := getBackendCapabilities("unknown-backend")
	if err == nil {
		t.Error("Expected error for unknown backend")
	}
}
