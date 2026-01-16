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
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/migration"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/spf13/cobra"
)

// =============================================================================
// Test config.go functions - Extended Coverage
// =============================================================================

func TestConfigIsLocalExtended(t *testing.T) {
	tests := []struct {
		name     string
		useLocal bool
		want     bool
	}{
		{"local mode on", true, true},
		{"local mode off", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.UseLocal = tt.useLocal
			if got := cfg.IsLocal(); got != tt.want {
				t.Errorf("IsLocal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigIsRemoteExtended(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{"no server URL", "", false},
		{"with http URL", "http://localhost:8080", true},
		{"with unix socket", "unix:///tmp/test.sock", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Server = tt.server
			if got := cfg.IsRemote(); got != tt.want {
				t.Errorf("IsRemote() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigCreateBackendUnsupportedExtended(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		wantErr bool
	}{
		{"pkcs11", "pkcs11", true},
		{"awskms", "awskms", true},
		{"gcpkms", "gcpkms", true},
		{"azurekv", "azurekv", true},
		{"vault", "vault", true},
		{"nonexistent", "nonexistent", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Backend = tt.backend
			_, err := cfg.CreateBackend()
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateBackend() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigCreateBackendSoftwareExtended(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()

	be, err := cfg.CreateBackend()
	if err != nil {
		t.Fatalf("CreateBackend() error = %v", err)
	}
	defer func() { _ = be.Close() }()

	if be == nil {
		t.Error("CreateBackend() returned nil")
	}
}

func TestConfigCreateCertStorageExtended(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = t.TempDir()

	storage, err := cfg.CreateCertStorage()
	if err != nil {
		t.Fatalf("CreateCertStorage() error = %v", err)
	}

	if storage == nil {
		t.Error("CreateCertStorage() returned nil")
	}
}

func TestConfigCreateCertStorageInvalidExtended(t *testing.T) {
	cfg := NewConfig()
	// Use /dev/null/invalid - /dev/null is a file, not a directory, so this will fail
	cfg.KeyDir = "/dev/null/invalid/path"

	_, err := cfg.CreateCertStorage()
	if err == nil {
		t.Error("CreateCertStorage() expected error for invalid path")
	}
}

func TestConfigCreateClientWithTLSAllProtocolsExtended(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
	}{
		{"unix", "unix:///tmp/test.sock"},
		{"http protocol", "http://localhost:8080"},
		{"https protocol", "https://localhost:8443"},
		{"grpc protocol", "grpc://localhost:9090"},
		{"grpcs protocol", "grpcs://localhost:9443"},
		{"quic protocol", "quic://localhost:4433"},
		{"bare address", "localhost:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Server = tt.serverURL
			cfg.TLSInsecure = true

			cl, err := cfg.createClientWithTLS()
			if err != nil {
				t.Errorf("createClientWithTLS() error = %v", err)
				return
			}
			if cl != nil {
				_ = cl.Close()
			}
		})
	}
}

func TestHasPrefixExtended(t *testing.T) {
	tests := []struct {
		s      string
		prefix string
		want   bool
	}{
		{"https://example.com", "https://", true},
		{"http://example.com", "https://", false},
		{"", "http://", false},
		{"http://", "http://", true},
		{"h", "http://", false},
		{"grpc://server:9090", "grpc://", true},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := hasPrefix(tt.s, tt.prefix); got != tt.want {
				t.Errorf("hasPrefix(%q, %q) = %v, want %v", tt.s, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestTrimPrefixExtended(t *testing.T) {
	tests := []struct {
		s      string
		prefix string
		want   string
	}{
		{"https://example.com", "https://", "example.com"},
		{"http://example.com", "https://", "http://example.com"},
		{"http://", "http://", ""},
		{"grpc://server:9090", "grpc://", "server:9090"},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := trimPrefix(tt.s, tt.prefix); got != tt.want {
				t.Errorf("trimPrefix(%q, %q) = %q, want %q", tt.s, tt.prefix, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Test backends.go functions - Extended Coverage
// =============================================================================

func TestGetBackendCapabilitiesExtended(t *testing.T) {
	tests := []struct {
		name        string
		backend     string
		wantErr     bool
		wantHWBased bool
	}{
		{"software backend", "software", false, false},
		{"pkcs8 backend", "pkcs8", false, false},
		{"pkcs11 backend", "pkcs11", false, true},
		{"tpm2 backend", "tpm2", false, true},
		{"awskms backend", "awskms", false, true},
		{"gcpkms backend", "gcpkms", false, true},
		{"azurekv backend", "azurekv", false, true},
		{"vault backend", "vault", false, false},
		{"bogus backend", "bogus", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps, err := getBackendCapabilities(tt.backend)
			if (err != nil) != tt.wantErr {
				t.Errorf("getBackendCapabilities() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && caps.HardwareBacked != tt.wantHWBased {
				t.Errorf("HardwareBacked = %v, want %v", caps.HardwareBacked, tt.wantHWBased)
			}
		})
	}
}

func TestListBackendsLocalExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	listBackendsLocal(printer)

	output := buf.String()
	if output == "" {
		t.Error("listBackendsLocal() produced no output")
	}
	expected := []string{"software", "pkcs11", "tpm2", "awskms", "vault"}
	for _, b := range expected {
		if !bytes.Contains(buf.Bytes(), []byte(b)) {
			t.Errorf("Expected backend %q not found in output", b)
		}
	}
}

func TestListBackendsLocalJSONExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	listBackendsLocal(printer)

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if result["backends"] == nil {
		t.Error("Expected 'backends' key in JSON output")
	}
}

func TestBackendInfoLocalExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	backendInfoLocal(printer, "software")

	output := buf.String()
	if output == "" {
		t.Error("backendInfoLocal() produced no output")
	}
}

func TestBackendInfoLocalJSONExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	backendInfoLocal(printer, "software")

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if result["backend"] != "software" {
		t.Errorf("Expected backend = 'software', got %v", result["backend"])
	}
}

// =============================================================================
// Test cert.go functions - Extended Coverage
// =============================================================================

func TestGenerateCAExtended(t *testing.T) {
	cert, key, err := generateCA("Test CA", "Test Org", "Test OU", "US", "CA", "SF", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}

	if cert == nil {
		t.Fatal("generateCA() returned nil certificate")
	}
	if key == nil {
		t.Fatal("generateCA() returned nil key")
	}
	if !cert.IsCA {
		t.Error("Certificate should be a CA")
	}
	if cert.Subject.CommonName != "Test CA" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Test CA")
	}
}

func TestGenerateCAAllAlgorithmsExtended(t *testing.T) {
	tests := []struct {
		name    string
		alg     string
		keySize int
	}{
		{"RSA 2048 key", "rsa", 2048},
		{"RSA 4096 key", "rsa", 4096},
		{"ECDSA P-256 key", "ecdsa", 256},
		{"ECDSA P-384 key", "ecdsa", 384},
		{"ECDSA P-521 key", "ecdsa", 521},
		{"Ed25519 key", "ed25519", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, err := generateCA("Test CA", "", "", "", "", "", 30, tt.alg, tt.keySize)
			if err != nil {
				t.Fatalf("generateCA() error = %v", err)
			}
			if cert == nil || key == nil {
				t.Error("generateCA() returned nil")
			}
		})
	}
}

func TestIssueCertificateExtended(t *testing.T) {
	caCert, caKey, err := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}

	tests := []struct {
		name     string
		certType string
		dnsNames []string
		ips      []net.IP
		emails   []string
	}{
		{"server certificate", "server", []string{"example.com"}, nil, nil},
		{"client certificate", "client", nil, nil, []string{"user@example.com"}},
		{"server with IP SANs", "server", nil, []net.IP{net.ParseIP("127.0.0.1")}, nil},
		{"dual purpose cert", "both", []string{"example.com"}, nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, err := issueCertificate(
				caCert, caKey,
				"test-cert", tt.certType,
				"", "", "", "", "",
				30, "ecdsa", 256,
				tt.dnsNames, tt.ips, tt.emails,
			)
			if err != nil {
				t.Fatalf("issueCertificate() error = %v", err)
			}
			if cert == nil || key == nil {
				t.Error("issueCertificate() returned nil")
			}
		})
	}
}

func TestIssueCertificateClientWithEmailInCNExtended(t *testing.T) {
	caCert, caKey, err := generateCA("Test CA", "", "", "", "", "", 30, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}

	cert, _, err := issueCertificate(
		caCert, caKey,
		"user@example.com", "client",
		"", "", "", "", "",
		30, "ecdsa", 256,
		nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("issueCertificate() error = %v", err)
	}

	if len(cert.EmailAddresses) == 0 {
		t.Error("Expected email address in certificate")
	}
}

// =============================================================================
// Test key.go functions - Extended Coverage
// =============================================================================

func TestBuildKeyAttributesFromFlagsExtended(t *testing.T) {
	tests := []struct {
		name        string
		keyType     string
		keyAlg      string
		keySize     int
		curve       string
		wantErr     bool
		wantAlgType x509.PublicKeyAlgorithm
	}{
		{"RSA signing key", "signing", "rsa", 2048, "", false, x509.RSA},
		{"RSA encryption key", "encryption", "rsa", 4096, "", false, x509.RSA},
		{"ECDSA P-256 key", "signing", "ecdsa", 0, "P-256", false, x509.ECDSA},
		{"ECDSA P-384 key", "signing", "ecdsa", 0, "P-384", false, x509.ECDSA},
		{"ECDSA P-521 key", "signing", "ecdsa", 0, "P-521", false, x509.ECDSA},
		{"Ed25519 key", "signing", "ed25519", 0, "", false, x509.Ed25519},
		{"bad key type", "bogus", "rsa", 2048, "", true, 0},
		{"bad algorithm", "signing", "bogus", 2048, "", true, 0},
		{"RSA key too small", "signing", "rsa", 1024, "", true, 0},
		{"bad curve name", "signing", "ecdsa", 0, "bogus", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := buildKeyAttributesFromFlags(
				"test-key", tt.keyType, tt.keyAlg, tt.keySize, tt.curve, true,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildKeyAttributesFromFlags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && attrs.KeyAlgorithm != tt.wantAlgType {
				t.Errorf("KeyAlgorithm = %v, want %v", attrs.KeyAlgorithm, tt.wantAlgType)
			}
		})
	}
}

func TestBuildSymmetricKeyAttributesExtended(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		keySize   int
		wantErr   bool
	}{
		// Use correct algorithm strings from types.go
		{"aes128-gcm algorithm", string(types.SymmetricAES128GCM), 0, false},
		{"aes192-gcm algorithm", string(types.SymmetricAES192GCM), 0, false},
		{"aes256-gcm algorithm", string(types.SymmetricAES256GCM), 0, false},
		{"AES-128 from size", "", 128, false},
		{"AES-192 from size", "", 192, false},
		{"AES-256 from size", "", 256, false},
		{"chacha20-poly1305 algorithm", string(types.SymmetricChaCha20Poly1305), 0, false},
		{"invalid key size", "", 512, true},
		{"invalid algorithm name", "bogus-alg", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := buildSymmetricKeyAttributes("test-key", tt.algorithm, tt.keySize)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildSymmetricKeyAttributes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && attrs == nil {
				t.Error("buildSymmetricKeyAttributes() returned nil attrs")
			}
		})
	}
}

func TestIsSymmetricAlgorithmExtended(t *testing.T) {
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
		{"unknown-algo", false},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			if got := isSymmetricAlgorithm(tt.algorithm); got != tt.want {
				t.Errorf("isSymmetricAlgorithm(%q) = %v, want %v", tt.algorithm, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Test output.go printer functions - Extended Coverage
// =============================================================================

func TestPrinterPrintBackendListTableExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	err := printer.PrintBackendList([]string{"software", "tpm2"})
	if err != nil {
		t.Fatalf("PrintBackendList() error = %v", err)
	}

	if buf.Len() == 0 {
		t.Error("PrintBackendList() produced no output")
	}
}

func TestPrinterPrintKeyListTableExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	keys := []*types.KeyAttributes{
		{CN: "key1", KeyType: types.KeyTypeSigning, KeyAlgorithm: x509.RSA, StoreType: types.StoreSoftware},
		{CN: "key2", KeyType: types.KeyTypeEncryption, KeyAlgorithm: x509.ECDSA, StoreType: types.StoreSoftware},
	}

	err := printer.PrintKeyList(keys)
	if err != nil {
		t.Fatalf("PrintKeyList() error = %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte("key1")) {
		t.Error("Expected key1 in output")
	}
}

func TestPrinterPrintKeyListJSONExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	keys := []*types.KeyAttributes{
		{CN: "key1", KeyType: types.KeyTypeSigning},
	}

	err := printer.PrintKeyList(keys)
	if err != nil {
		t.Fatalf("PrintKeyList() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if result["keys"] == nil {
		t.Error("Expected 'keys' in JSON output")
	}
}

func TestPrinterPrintKeyListTableEmptyExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	err := printer.PrintKeyList([]*types.KeyAttributes{})
	if err != nil {
		t.Fatalf("PrintKeyList() error = %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte("No keys found")) {
		t.Error("Expected 'No keys found' message")
	}
}

func TestPrinterPrintCertListJSONExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	err := printer.PrintCertList([]string{"cert1", "cert2"})
	if err != nil {
		t.Fatalf("PrintCertList() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if result["certificates"] == nil {
		t.Error("Expected 'certificates' in JSON output")
	}
}

func TestPrinterPrintCertListTableEmptyExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	err := printer.PrintCertList([]string{})
	if err != nil {
		t.Fatalf("PrintCertList() error = %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte("No certificates found")) {
		t.Error("Expected 'No certificates found' message")
	}
}

func TestPrinterPrintCertExistsAllFormatsExtended(t *testing.T) {
	tests := []struct {
		format string
		exists bool
	}{
		{"text", true},
		{"text", false},
		{"json", true},
		{"json", false},
		{"table", true},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintCertExists("test-key", tt.exists)
			if err != nil {
				t.Fatalf("PrintCertExists() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintCertExists() produced no output")
			}
		})
	}
}

func TestPrinterPrintSignatureAllFormatsExtended(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"text"},
		{"json"},
		{"table"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintSignature("dGVzdC1zaWduYXR1cmU=")
			if err != nil {
				t.Fatalf("PrintSignature() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintSignature() produced no output")
			}
		})
	}
}

func TestPrinterPrintDecryptedDataAllFormatsExtended(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"text"},
		{"json"},
		{"table"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintDecryptedData("decrypted-data")
			if err != nil {
				t.Fatalf("PrintDecryptedData() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintDecryptedData() produced no output")
			}
		})
	}
}

func TestPrinterPrintEncryptedDataAllFormatsExtended(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"text"},
		{"json"},
		{"table"},
	}

	data := &types.EncryptedData{
		Ciphertext: []byte("ciphertext"),
		Nonce:      []byte("nonce12345"),
		Tag:        []byte("tag12345678"),
		Algorithm:  "AES-256-GCM",
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintEncryptedData(data)
			if err != nil {
				t.Fatalf("PrintEncryptedData() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintEncryptedData() produced no output")
			}
		})
	}
}

func TestPrinterPrintCertificateJSONExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.com"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	err := printer.PrintCertificate(cert)
	if err != nil {
		t.Fatalf("PrintCertificate() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if result["subject"] == nil {
		t.Error("Expected 'subject' in JSON output")
	}
}

func TestPrinterPrintCertChainJSONExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	err := printer.PrintCertChain([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("PrintCertChain() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if result["chain"] == nil {
		t.Error("Expected 'chain' in JSON output")
	}
}

func TestPrinterPrintSuccessAllFormatsExtended(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"text"},
		{"json"},
		{"table"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintSuccess("operation successful")
			if err != nil {
				t.Fatalf("PrintSuccess() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintSuccess() produced no output")
			}
		})
	}
}

// Test error type for extended tests
type extTestError struct {
	msg string
}

func (e extTestError) Error() string { return e.msg }

var ErrExtTestError = extTestError{msg: "extended test error"}

func TestPrinterPrintErrorAllFormatsExtended(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"text"},
		{"json"},
		{"table"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintError(ErrExtTestError)
			if err != nil {
				t.Fatalf("PrintError() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintError() produced no output")
			}
		})
	}
}

func TestPrinterPrintMessageAllFormatsExtended(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"text"},
		{"json"},
		{"table"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintMessage("test message")
			if err != nil {
				t.Fatalf("PrintMessage() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintMessage() produced no output")
			}
		})
	}
}

func TestPrinterPrintEncryptedAsymAllFormatsExtended(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"text"},
		{"json"},
		{"table"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintEncryptedAsym("encrypted-data-base64")
			if err != nil {
				t.Fatalf("PrintEncryptedAsym() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintEncryptedAsym() produced no output")
			}
		})
	}
}

func TestPrinterPrintFIDO2DevicesTableExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	devices := []fido2Device{
		{
			Path:         "/dev/hidraw0",
			VendorID:     0x1050,
			ProductID:    0x0407,
			Manufacturer: "Yubico",
			Product:      "YubiKey 5",
		},
	}

	err := printer.PrintFIDO2Devices(devices)
	if err != nil {
		t.Fatalf("PrintFIDO2Devices() error = %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte("PATH")) {
		t.Error("Expected table header")
	}
}

func TestPrinterPrintFIDO2DevicesJSONExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	devices := []fido2Device{
		{
			Path:      "/dev/hidraw0",
			VendorID:  0x1050,
			ProductID: 0x0407,
		},
	}

	err := printer.PrintFIDO2Devices(devices)
	if err != nil {
		t.Fatalf("PrintFIDO2Devices() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if result["devices"] == nil {
		t.Error("Expected 'devices' in JSON output")
	}
}

func TestPrinterPrintFIDO2DeviceInfoJSONExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	dev := fido2Device{
		Path:         "/dev/hidraw0",
		VendorID:     0x1050,
		ProductID:    0x0407,
		Manufacturer: "Yubico",
		Product:      "YubiKey",
		SerialNumber: "12345678",
		Transport:    "hid",
	}

	err := printer.PrintFIDO2DeviceInfo(dev)
	if err != nil {
		t.Fatalf("PrintFIDO2DeviceInfo() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if result["path"] == nil {
		t.Error("Expected 'path' in JSON output")
	}
}

func TestPrinterPrintFIDO2RegistrationAllFormatsExtended(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"text"},
		{"json"},
		{"table"},
	}

	result := &fido2EnrollmentResult{
		CredentialID: []byte("credential-id"),
		PublicKey:    []byte("public-key"),
		AAGUID:       []byte("aaguid-data"),
		Salt:         []byte("salt-data"),
		User: fido2User{
			Name:        "testuser",
			DisplayName: "Test User",
		},
		RelyingParty: fido2RelyingParty{
			ID:   "example.com",
			Name: "Example",
		},
		Created: time.Now(),
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintFIDO2Registration(result)
			if err != nil {
				t.Fatalf("PrintFIDO2Registration() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintFIDO2Registration() produced no output")
			}
		})
	}
}

func TestPrinterPrintImportParametersAllFormatsExtended(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"text"},
		{"json"},
		{"table"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

			params := &backend.ImportParameters{
				Algorithm:         "RSA_OAEP_SHA256",
				KeySpec:           "AES_256",
				ImportToken:       []byte("token"),
				WrappingPublicKey: &privKey.PublicKey,
			}

			err := printer.PrintImportParameters(params)
			if err != nil {
				t.Fatalf("PrintImportParameters() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintImportParameters() produced no output")
			}
		})
	}
}

func TestPrinterPrintImportParametersJSONWithExpiryExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	expiry := time.Now().Add(1 * time.Hour)
	params := &backend.ImportParameters{
		Algorithm:   "RSA_OAEP_SHA256",
		KeySpec:     "AES_256",
		ExpiresAt:   &expiry,
		ImportToken: []byte("token"),
	}

	err := printer.PrintImportParameters(params)
	if err != nil {
		t.Fatalf("PrintImportParameters() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if result["expires_at"] == nil {
		t.Error("Expected 'expires_at' in JSON output")
	}
}

func TestTruncateStringExtended(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly ten", 11, "exactly ten"},
		{"this is a very long string", 10, "this is..."},
		{"abc", 2, "ab"},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc"},
		{"hello world", 5, "he..."},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := truncateString(tt.input, tt.maxLen); got != tt.want {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Test admin.go helper functions - Extended Coverage
// =============================================================================

func TestResolveStoragePathExtended(t *testing.T) {
	tests := []struct {
		name        string
		storagePath string
		want        string
	}{
		{"explicit path given", "/custom/path", "/custom/path"},
		{"use default path", "", "/var/lib/keychain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Unsetenv("KEYCHAIN_STORAGE_PATH")

			got := resolveStoragePath(tt.storagePath)
			if got != tt.want {
				t.Errorf("resolveStoragePath(%q) = %q, want %q", tt.storagePath, got, tt.want)
			}
		})
	}
}

func TestResolveStoragePathFromEnvExtended(t *testing.T) {
	envPath := "/env/storage/path"
	if err := os.Setenv("KEYCHAIN_STORAGE_PATH", envPath); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() { _ = os.Unsetenv("KEYCHAIN_STORAGE_PATH") }()

	got := resolveStoragePath("")
	if got != envPath {
		t.Errorf("resolveStoragePath() = %q, want %q", got, envPath)
	}
}

func TestRepeatStringExtended(t *testing.T) {
	tests := []struct {
		s     string
		count int
		want  string
	}{
		{"-", 3, "---"},
		{"ab", 2, "abab"},
		{"x", 0, ""},
		{"", 5, ""},
		{"*", 5, "*****"},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := repeatString(tt.s, tt.count); got != tt.want {
				t.Errorf("repeatString(%q, %d) = %q, want %q", tt.s, tt.count, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Test migrate.go helper functions - Extended Coverage
// =============================================================================

func TestBuildMigrationFilterAllFieldsExtended(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")

	// Set values
	_ = cmd.Flags().Set("key-types", "signing,encryption,ca,tls")
	_ = cmd.Flags().Set("store-types", "software,tpm2,pkcs11")
	_ = cmd.Flags().Set("partitions", "default,admin,users")
	_ = cmd.Flags().Set("cn-pattern", "prod-*")

	filter := buildMigrationFilter(cmd)

	if len(filter.KeyTypes) != 4 {
		t.Errorf("Expected 4 key types, got %d", len(filter.KeyTypes))
	}
	if len(filter.StoreTypes) != 3 {
		t.Errorf("Expected 3 store types, got %d", len(filter.StoreTypes))
	}
	if len(filter.Partitions) != 3 {
		t.Errorf("Expected 3 partitions, got %d", len(filter.Partitions))
	}
	if filter.CNPattern != "prod-*" {
		t.Errorf("Expected cn-pattern 'prod-*', got %q", filter.CNPattern)
	}
}

// =============================================================================
// Test root.go functions - Extended Coverage
// =============================================================================

func TestGetConfigExtended(t *testing.T) {
	cfg := getConfig()
	if cfg == nil {
		t.Error("getConfig() returned nil")
	}
}

func TestPrintVerboseNoOutputExtended(t *testing.T) {
	oldVerbose := globalConfig.Verbose
	globalConfig.Verbose = false
	printVerbose("test message %s", "arg")
	globalConfig.Verbose = oldVerbose
}

func TestPrintVerboseWithOutputExtended(t *testing.T) {
	oldVerbose := globalConfig.Verbose
	globalConfig.Verbose = true
	printVerbose("test message %s", "arg")
	globalConfig.Verbose = oldVerbose
}

// =============================================================================
// Test version.go - Extended Coverage
// =============================================================================

func TestVersionCmdExistsExtended(t *testing.T) {
	if versionCmd == nil {
		t.Error("versionCmd is nil")
	}
}

// =============================================================================
// Test local mode operations - Extended Coverage
// These tests work with successful operations, not expected failures
// =============================================================================

func TestGenerateKeyLocalSoftwareExtended(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	generateKeyLocal(cfg, printer, "test-key-local-ext", "signing", "", "ecdsa", 0, "P-256", true)
}

func TestGenerateKeyLocalSymmetricExtended(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	// Use correct algorithm string
	generateKeyLocal(cfg, printer, "test-aes-key-ext", "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
}

func TestListKeysLocalExtended(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	listKeysLocal(cfg, printer)
}

func TestSaveCertLocalExtended(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	saveCertLocal(cfg, printer, "test-cert-key-ext", cert)
}

func TestListCertsLocalExtended(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	listCertsLocal(cfg, printer)
}

// Test certExistsLocal - this works because it doesn't call handleError on success path
func TestCertExistsLocalExtended(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	// This should succeed - it returns false for non-existent key without error
	certExistsLocal(cfg, printer, "nonexistent-key-ext")
}

func TestSaveChainLocalExtended(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	chain := []*x509.Certificate{cert}

	saveChainLocal(cfg, printer, "test-chain-key-ext", chain)
}

// =============================================================================
// Test file operations - Extended Coverage
// =============================================================================

func TestCertGenerateCAWritesToFilesExtended(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "ca-ext.crt")
	keyFile := filepath.Join(tmpDir, "ca-ext.key")

	cert, key, err := generateCA("Test CA Ext", "Test Org", "", "", "", "", 30, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert: %v", err)
	}

	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key: %v", err)
	}

	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("Cert file not created: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Errorf("Key file not created: %v", err)
	}
}

// =============================================================================
// Test encoding - Extended Coverage
// =============================================================================

func TestBase64EncodingDecodingExtended(t *testing.T) {
	original := []byte("test data for encoding extended")
	encoded := base64.StdEncoding.EncodeToString(original)

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode error: %v", err)
	}

	if string(decoded) != string(original) {
		t.Errorf("base64 roundtrip failed: got %q, want %q", decoded, original)
	}
}

// =============================================================================
// Test RSA key operations - Extended Coverage
// =============================================================================

func TestGetPublicKeyRSAPointerExtended(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	pubKey := getPublicKey(privKey)
	if pubKey == nil {
		t.Error("getPublicKey() returned nil for RSA key")
	}

	_, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Errorf("Expected *rsa.PublicKey, got %T", pubKey)
	}
}

// =============================================================================
// Test ECDSA curve variations - Extended Coverage
// =============================================================================

func TestGenerateKeyPairECDSADefaultCurveExtended(t *testing.T) {
	key, err := generateKeyPair("ecdsa", 0)
	if err != nil {
		t.Fatalf("generateKeyPair() error = %v", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PrivateKey, got %T", key)
	}

	if ecKey.Curve != elliptic.P256() {
		t.Error("Expected P-256 curve as default")
	}
}

func TestGenerateKeyPairAllAlgorithmsExtended(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		size int
	}{
		{"RSA 2048", "rsa", 2048},
		{"RSA 4096", "rsa", 4096},
		{"ECDSA P-256", "ecdsa", 256},
		{"ECDSA P-384", "ecdsa", 384},
		{"ECDSA P-521", "ecdsa", 521},
		{"Ed25519", "ed25519", 0},
		{"EC alias P-256", "ec", 256},
		{"Default unknown", "unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := generateKeyPair(tt.alg, tt.size)
			if err != nil {
				t.Fatalf("generateKeyPair() error = %v", err)
			}
			if key == nil {
				t.Error("generateKeyPair() returned nil")
			}
		})
	}
}

// =============================================================================
// Test hash algorithm parsing - Extended Coverage
// =============================================================================

func TestHashAlgorithmParsingExtended(t *testing.T) {
	hashes := types.AvailableHashes()

	tests := []struct {
		name string
		want crypto.Hash
	}{
		{"sha256", crypto.SHA256},
		{"sha384", crypto.SHA384},
		{"sha512", crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if hash, ok := hashes[tt.name]; ok {
				if hash != tt.want {
					t.Errorf("Hash %s = %v, want %v", tt.name, hash, tt.want)
				}
			}
		})
	}
}

// =============================================================================
// Test PrintTLSCertificate - Extended Coverage
// =============================================================================

func TestPrintTLSCertificateRSAKeyExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	err := printer.PrintTLSCertificate(privKey, cert, nil)
	if err != nil {
		t.Fatalf("PrintTLSCertificate() error = %v", err)
	}

	output := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("*rsa.PrivateKey")) {
		t.Errorf("Expected RSA key type in output, got: %s", output)
	}
}

func TestPrintTLSCertificateECDSAKeyExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	err := printer.PrintTLSCertificate(privKey, cert, nil)
	if err != nil {
		t.Fatalf("PrintTLSCertificate() error = %v", err)
	}

	output := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("*ecdsa.PrivateKey")) {
		t.Errorf("Expected ECDSA key type in output, got: %s", output)
	}
}

func TestPrintTLSCertificateEd25519KeyExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, privKey.Public(), privKey)
	cert, _ := x509.ParseCertificate(certDER)

	err := printer.PrintTLSCertificate(privKey, cert, nil)
	if err != nil {
		t.Fatalf("PrintTLSCertificate() error = %v", err)
	}

	if buf.Len() == 0 {
		t.Error("PrintTLSCertificate() produced no output")
	}
}

// =============================================================================
// Test KeyAttributes - Extended Coverage
// =============================================================================

func TestKeyAttributeStoreTypesExtended(t *testing.T) {
	stores := []types.StoreType{
		types.StoreSoftware,
		types.StoreTPM2,
		types.StorePKCS11,
	}

	for _, store := range stores {
		attrs := &types.KeyAttributes{
			CN:        "test-key",
			KeyType:   types.KeyTypeSigning,
			StoreType: store,
		}

		if attrs.StoreType != store {
			t.Errorf("StoreType = %v, want %v", attrs.StoreType, store)
		}
	}
}

// =============================================================================
// Test migration output functions - Extended Coverage
// =============================================================================

func TestOutputMigrationPlanTextWithAllFieldsExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	plan := &migration.MigrationPlan{
		SourceBackendType: "software",
		DestBackendType:   "tpm2",
		Keys: []*types.KeyAttributes{
			{CN: "key1", KeyType: types.KeyTypeSigning},
			{CN: "key2", KeyType: types.KeyTypeEncryption},
			{CN: "key3", KeyType: types.KeyTypeCA},
		},
		EstimatedDuration: 30 * time.Second,
		Timestamp:         time.Now(),
		Warnings:          []string{"warning1", "warning2"},
		Errors:            []string{},
	}

	outputMigrationPlanText(plan, printer)
}

func TestOutputMigrationResultTextWithFailedKeysExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	failedKey := &types.KeyAttributes{CN: "failed-key"}
	failedKeys := make(map[*types.KeyAttributes]error)
	failedKeys[failedKey] = ErrExtTestError

	result := &migration.MigrationResult{
		SuccessCount:   3,
		FailureCount:   1,
		SkippedCount:   0,
		Duration:       5 * time.Second,
		SuccessfulKeys: []*types.KeyAttributes{{CN: "key1"}, {CN: "key2"}, {CN: "key3"}},
		FailedKeys:     failedKeys,
	}

	outputMigrationResultText(result, printer)
}

// =============================================================================
// Test splitAndTrim helper - Extended Coverage
// =============================================================================

func TestSplitAndTrimExtended(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b, c", []string{"a", "b", "c"}},
		{" a , b , c ", []string{"a", "b", "c"}},
		{"", []string{}},
		{"single", []string{"single"}},
		{",,,", []string{}},
		{"a,,b", []string{"a", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitAndTrim(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("splitAndTrim(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitAndTrim(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// =============================================================================
// Test getPublicKey helper - Extended Coverage
// =============================================================================

func TestGetPublicKeyAllTypesExtended(t *testing.T) {
	// Test RSA key
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPub := getPublicKey(rsaKey)
	if _, ok := rsaPub.(*rsa.PublicKey); !ok {
		t.Errorf("Expected *rsa.PublicKey, got %T", rsaPub)
	}

	// Test ECDSA key
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecPub := getPublicKey(ecKey)
	if _, ok := ecPub.(*ecdsa.PublicKey); !ok {
		t.Errorf("Expected *ecdsa.PublicKey, got %T", ecPub)
	}

	// Test Ed25519 key
	_, ed25519Key, _ := ed25519.GenerateKey(rand.Reader)
	edPub := getPublicKey(ed25519Key)
	if _, ok := edPub.(ed25519.PublicKey); !ok {
		t.Errorf("Expected ed25519.PublicKey, got %T", edPub)
	}

	// Test unknown type returns nil
	unknownPub := getPublicKey("not a key")
	if unknownPub != nil {
		t.Errorf("Expected nil for unknown key type, got %T", unknownPub)
	}
}

// =============================================================================
// Test Cobra commands exist - Extended Coverage
// =============================================================================

func TestCobraCommandsExistExtended(t *testing.T) {
	commands := []*cobra.Command{
		rootCmd,
		versionCmd,
		backendsCmd,
		keyCmd,
		certCmd,
		tlsCmd,
		fido2Cmd,
		adminCmd,
		userCmd,
	}

	for _, cmd := range commands {
		if cmd == nil {
			t.Error("Command is nil")
		}
	}
}

func TestSubcommandsExistExtended(t *testing.T) {
	// Test cert subcommands
	certSubcommands := []*cobra.Command{
		certSaveCmd,
		certGetCmd,
		certDeleteCmd,
		certListCmd,
		certExistsCmd,
		certSaveChainCmd,
		certGetChainCmd,
		certGenerateCACmd,
		certIssueCmd,
	}

	for _, cmd := range certSubcommands {
		if cmd == nil {
			t.Error("Cert subcommand is nil")
		}
	}
}

// =============================================================================
// Test PrintKeyInfo - Extended Coverage
// =============================================================================

func TestPrinterPrintKeyInfoAllFormatsExtended(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"text"},
		{"json"},
		{"table"},
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyType:      types.KeyTypeSigning,
		KeyAlgorithm: x509.ECDSA,
		StoreType:    types.StoreSoftware,
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintKeyInfo(attrs)
			if err != nil {
				t.Fatalf("PrintKeyInfo() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintKeyInfo() produced no output")
			}
		})
	}
}

// =============================================================================
// Test PrintBackendInfo - Extended Coverage
// =============================================================================

func TestPrinterPrintBackendInfoExtended(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"text"},
		{"json"},
		{"table"},
	}

	caps := types.Capabilities{
		HardwareBacked: false,
		Keys:           true,
		Signing:        true,
		Decryption:     true,
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintBackendInfo("software", caps)
			if err != nil {
				t.Fatalf("PrintBackendInfo() error = %v", err)
			}

			if buf.Len() == 0 {
				t.Error("PrintBackendInfo() produced no output")
			}
		})
	}
}

// =============================================================================
// Test PrintJSON - Extended Coverage
// =============================================================================

func TestPrinterPrintJSONExtended(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	data := map[string]interface{}{
		"key":   "value",
		"count": 42,
		"nested": map[string]interface{}{
			"inner": "data",
		},
	}

	err := printer.PrintJSON(data)
	if err != nil {
		t.Fatalf("PrintJSON() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("Expected key = 'value', got %v", result["key"])
	}
}
