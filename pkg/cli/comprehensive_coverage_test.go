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
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/migration"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/spf13/cobra"
)

// =============================================================================
// Test Printer.PrintBackendList edge cases
// =============================================================================

func TestPrinterPrintBackendListEdgeCasesComprehensive(t *testing.T) {
	// Empty list
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	err := printer.PrintBackendList([]string{})
	if err != nil {
		t.Errorf("PrintBackendList() with empty list failed: %v", err)
	}

	// Single item
	buf = &bytes.Buffer{}
	printer = NewPrinter("json", buf)
	err = printer.PrintBackendList([]string{"software"})
	if err != nil {
		t.Errorf("PrintBackendList() with single item failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Errorf("Failed to parse JSON: %v", err)
	}
	backends := result["backends"].([]interface{})
	if len(backends) != 1 {
		t.Errorf("Expected 1 backend, got %d", len(backends))
	}

	// Unknown format
	buf = &bytes.Buffer{}
	printer = NewPrinter("yaml", buf)
	err = printer.PrintBackendList([]string{"software"})
	if err == nil {
		t.Error("Expected error for unknown format")
	}
}

// =============================================================================
// Test buildKeyAttributesFromFlags comprehensive cases
// =============================================================================

func TestBuildKeyAttributesFromFlagsComprehensive(t *testing.T) {
	tests := []struct {
		name       string
		keyID      string
		keyType    string
		keyAlg     string
		keySize    int
		curve      string
		exportable bool
		wantErr    bool
	}{
		// Valid RSA keys
		{"RSA 2048 signing", "key1", "signing", "rsa", 2048, "", true, false},
		{"RSA 3072 encryption", "key2", "encryption", "rsa", 3072, "", false, false},
		{"RSA 4096 tls", "key3", "tls", "rsa", 4096, "", true, false},

		// Valid ECDSA keys
		{"ECDSA P-256", "key4", "signing", "ecdsa", 0, "P-256", true, false},
		{"ECDSA P-384", "key5", "signing", "ecdsa", 0, "P-384", true, false},
		{"ECDSA P-521", "key6", "signing", "ecdsa", 0, "P-521", true, false},

		// Valid Ed25519 keys
		{"Ed25519 signing", "key7", "signing", "ed25519", 0, "", true, false},

		// Invalid cases
		{"invalid key type", "key8", "invalid", "rsa", 2048, "", true, true},
		{"invalid algorithm", "key9", "signing", "invalid", 2048, "", true, true},
		{"RSA too small", "key10", "signing", "rsa", 1024, "", true, true},
		{"invalid curve", "key11", "signing", "ecdsa", 0, "invalid", true, true},
		{"empty key type", "key12", "", "rsa", 2048, "", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := buildKeyAttributesFromFlags(tt.keyID, tt.keyType, tt.keyAlg, tt.keySize, tt.curve, tt.exportable)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildKeyAttributesFromFlags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && attrs == nil {
				t.Error("buildKeyAttributesFromFlags() returned nil attrs")
			}
			if !tt.wantErr && attrs.CN != tt.keyID {
				t.Errorf("CN = %q, want %q", attrs.CN, tt.keyID)
			}
			if !tt.wantErr && attrs.Exportable != tt.exportable {
				t.Errorf("Exportable = %v, want %v", attrs.Exportable, tt.exportable)
			}
		})
	}
}

// =============================================================================
// Test buildSymmetricKeyAttributes comprehensive cases
// =============================================================================

func TestBuildSymmetricKeyAttributesComprehensive(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		algorithm string
		keySize   int
		wantErr   bool
	}{
		// Valid by algorithm
		{"AES-128-GCM by alg", "key1", string(types.SymmetricAES128GCM), 0, false},
		{"AES-192-GCM by alg", "key2", string(types.SymmetricAES192GCM), 0, false},
		{"AES-256-GCM by alg", "key3", string(types.SymmetricAES256GCM), 0, false},
		{"ChaCha20 by alg", "key4", string(types.SymmetricChaCha20Poly1305), 0, false},

		// Valid by key size
		{"AES-128 by size", "key5", "", 128, false},
		{"AES-192 by size", "key6", "", 192, false},
		{"AES-256 by size", "key7", "", 256, false},

		// Invalid cases
		{"invalid algorithm", "key8", "bogus", 0, true},
		{"invalid key size 64", "key9", "", 64, true},
		{"invalid key size 512", "key10", "", 512, true},
		{"invalid key size 0", "key11", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := buildSymmetricKeyAttributes(tt.keyID, tt.algorithm, tt.keySize)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildSymmetricKeyAttributes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && attrs == nil {
				t.Error("buildSymmetricKeyAttributes() returned nil attrs")
			}
			if !tt.wantErr && attrs.CN != tt.keyID {
				t.Errorf("CN = %q, want %q", attrs.CN, tt.keyID)
			}
		})
	}
}

// =============================================================================
// Test getBackendCapabilities comprehensive cases
// =============================================================================

func TestGetBackendCapabilitiesComprehensive(t *testing.T) {
	tests := []struct {
		name        string
		backend     string
		wantErr     bool
		wantHWBased bool
		wantKeys    bool
	}{
		{"software", "software", false, false, true},
		{"pkcs8", "pkcs8", false, false, true},
		{"pkcs11", "pkcs11", false, true, true},
		{"tpm2", "tpm2", false, true, true},
		{"awskms", "awskms", false, true, true},
		{"gcpkms", "gcpkms", false, true, true},
		{"azurekv", "azurekv", false, true, true},
		{"vault", "vault", false, false, true},
		{"unknown", "unknown", true, false, false},
		{"empty", "", true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps, err := getBackendCapabilities(tt.backend)
			if (err != nil) != tt.wantErr {
				t.Errorf("getBackendCapabilities() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if caps.HardwareBacked != tt.wantHWBased {
					t.Errorf("HardwareBacked = %v, want %v", caps.HardwareBacked, tt.wantHWBased)
				}
				if caps.Keys != tt.wantKeys {
					t.Errorf("Keys = %v, want %v", caps.Keys, tt.wantKeys)
				}
			}
		})
	}
}

// =============================================================================
// Test Config methods comprehensive
// =============================================================================

func TestConfigMethodsComprehensive(t *testing.T) {
	// Test IsLocal
	cfg := NewConfig()
	if cfg.IsLocal() {
		t.Error("New config should not be local by default")
	}
	cfg.UseLocal = true
	if !cfg.IsLocal() {
		t.Error("Config should be local when UseLocal is true")
	}

	// Test IsRemote
	cfg = NewConfig()
	if cfg.IsRemote() {
		t.Error("New config should not be remote by default")
	}
	cfg.Server = "http://localhost:8080"
	if !cfg.IsRemote() {
		t.Error("Config should be remote when Server is set")
	}
}

func TestConfigCreateBackendAllTypesComprehensive(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		wantErr bool
	}{
		{"software", "software", false},
		{"pkcs11", "pkcs11", true},   // Not supported in CLI
		{"awskms", "awskms", true},   // Not supported in CLI
		{"gcpkms", "gcpkms", true},   // Not supported in CLI
		{"azurekv", "azurekv", true}, // Not supported in CLI
		{"vault", "vault", true},     // Not supported in CLI
		{"unknown", "bogus", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Backend = tt.backend
			cfg.KeyDir = t.TempDir()

			be, err := cfg.CreateBackend()
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateBackend() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if be != nil {
				_ = be.Close()
			}
		})
	}
}

func TestConfigCreateCertStorageSuccessComprehensive(t *testing.T) {
	cfg := NewConfig()
	cfg.KeyDir = t.TempDir()

	storage, err := cfg.CreateCertStorage()
	if err != nil {
		t.Fatalf("CreateCertStorage() failed: %v", err)
	}
	if storage == nil {
		t.Error("CreateCertStorage() returned nil")
	}
}

// =============================================================================
// Test Printer methods with various formats and edge cases
// =============================================================================

func TestPrinterPrintKeyListComprehensive(t *testing.T) {
	keys := []*types.KeyAttributes{
		{CN: "key1", KeyType: types.KeyTypeSigning, KeyAlgorithm: x509.RSA, StoreType: types.StoreSoftware},
		{CN: "key2", KeyType: types.KeyTypeEncryption, KeyAlgorithm: x509.ECDSA, StoreType: types.StoreTPM2},
		{CN: "key3", KeyType: types.KeyTypeTLS, KeyAlgorithm: x509.Ed25519, StoreType: types.StorePKCS11},
	}

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintKeyList(keys)
			if err != nil {
				t.Errorf("PrintKeyList() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintKeyList() produced no output")
			}
		})
	}
}

func TestPrinterPrintKeyInfoComprehensive(t *testing.T) {
	// Key with RSA attributes
	rsaKey := &types.KeyAttributes{
		CN:           "rsa-key",
		KeyType:      types.KeyTypeSigning,
		KeyAlgorithm: x509.RSA,
		StoreType:    types.StoreSoftware,
		Hash:         crypto.SHA256,
		Partition:    "default",
		RSAAttributes: &types.RSAAttributes{
			KeySize: 4096,
		},
	}

	// Key with ECC attributes
	eccKey := &types.KeyAttributes{
		CN:           "ecc-key",
		KeyType:      types.KeyTypeTLS,
		KeyAlgorithm: x509.ECDSA,
		StoreType:    types.StoreTPM2,
		Hash:         crypto.SHA384,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P384(),
		},
	}

	// Key with no extra attributes
	simpleKey := &types.KeyAttributes{
		CN:           "simple-key",
		KeyType:      types.KeyTypeEncryption,
		KeyAlgorithm: x509.Ed25519,
		StoreType:    types.StorePKCS11,
	}

	keys := []*types.KeyAttributes{rsaKey, eccKey, simpleKey}
	formats := []string{"text", "json", "table"}

	for _, key := range keys {
		for _, format := range formats {
			t.Run(key.CN+"_"+format, func(t *testing.T) {
				buf := &bytes.Buffer{}
				printer := NewPrinter(format, buf)

				err := printer.PrintKeyInfo(key)
				if err != nil {
					t.Errorf("PrintKeyInfo() error = %v", err)
				}
				if buf.Len() == 0 {
					t.Error("PrintKeyInfo() produced no output")
				}
			})
		}
	}
}

func TestPrinterPrintCertificateComprehensive(t *testing.T) {
	// Create test certificates
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Cert",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		DNSNames:    []string{"example.com", "www.example.com"},
		IPAddresses: nil,
		IsCA:        false,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintCertificate(cert)
			if err != nil {
				t.Errorf("PrintCertificate() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintCertificate() produced no output")
			}
		})
	}
}

func TestPrinterPrintCertChainComprehensive(t *testing.T) {
	// Create a certificate chain
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Root CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &privKey.PublicKey, privKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		IsCA:         false,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &privKey.PublicKey, privKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	chain := []*x509.Certificate{leafCert, rootCert}

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintCertChain(chain)
			if err != nil {
				t.Errorf("PrintCertChain() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintCertChain() produced no output")
			}
		})
	}
}

func TestPrinterPrintEncryptedDataComprehensive(t *testing.T) {
	data := &types.EncryptedData{
		Ciphertext: []byte("encrypted-data-bytes"),
		Nonce:      []byte("nonce-12bytes"),
		Tag:        []byte("auth-tag-16bytes"),
		Algorithm:  "AES-256-GCM",
	}

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintEncryptedData(data)
			if err != nil {
				t.Errorf("PrintEncryptedData() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintEncryptedData() produced no output")
			}
		})
	}
}

func TestPrinterPrintImportParametersComprehensive(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	expiry := time.Now().Add(1 * time.Hour)

	// Params with all fields
	fullParams := &backend.ImportParameters{
		Algorithm:         "RSA_OAEP_SHA256",
		KeySpec:           "AES_256",
		ExpiresAt:         &expiry,
		ImportToken:       []byte("import-token-bytes"),
		WrappingPublicKey: &privKey.PublicKey,
	}

	// Minimal params
	minParams := &backend.ImportParameters{
		Algorithm: "RSA_OAEP_SHA256",
		KeySpec:   "AES_128",
	}

	params := []*backend.ImportParameters{fullParams, minParams}
	formats := []string{"text", "json", "table"}

	for i, p := range params {
		for _, format := range formats {
			t.Run(format, func(t *testing.T) {
				buf := &bytes.Buffer{}
				printer := NewPrinter(format, buf)

				err := printer.PrintImportParameters(p)
				if err != nil {
					t.Errorf("PrintImportParameters(%d) error = %v", i, err)
				}
				if buf.Len() == 0 {
					t.Error("PrintImportParameters() produced no output")
				}
			})
		}
	}
}

func TestPrinterPrintFIDO2DevicesComprehensive(t *testing.T) {
	devices := []fido2Device{
		{
			Path:         "/dev/hidraw0",
			VendorID:     0x1050,
			ProductID:    0x0407,
			Manufacturer: "Yubico",
			Product:      "YubiKey 5 NFC",
			SerialNumber: "12345678",
			Transport:    "hid",
		},
		{
			Path:         "/dev/hidraw1",
			VendorID:     0x096E,
			ProductID:    0x0858,
			Manufacturer: "Feitian",
			Product:      "ePass FIDO",
			Transport:    "hid",
		},
	}

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintFIDO2Devices(devices)
			if err != nil {
				t.Errorf("PrintFIDO2Devices() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintFIDO2Devices() produced no output")
			}
		})
	}

	// Empty list
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	err := printer.PrintFIDO2Devices([]fido2Device{})
	if err != nil {
		t.Errorf("PrintFIDO2Devices() with empty list failed: %v", err)
	}
}

func TestPrinterPrintFIDO2DeviceInfoComprehensive(t *testing.T) {
	device := fido2Device{
		Path:         "/dev/hidraw0",
		VendorID:     0x1050,
		ProductID:    0x0407,
		Manufacturer: "Yubico",
		Product:      "YubiKey 5 NFC",
		SerialNumber: "12345678",
		Transport:    "hid",
	}

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintFIDO2DeviceInfo(device)
			if err != nil {
				t.Errorf("PrintFIDO2DeviceInfo() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintFIDO2DeviceInfo() produced no output")
			}
		})
	}

	// Device without serial number
	deviceNoSerial := fido2Device{
		Path:         "/dev/hidraw0",
		VendorID:     0x1050,
		ProductID:    0x0407,
		Manufacturer: "Yubico",
		Product:      "YubiKey",
	}

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	err := printer.PrintFIDO2DeviceInfo(deviceNoSerial)
	if err != nil {
		t.Errorf("PrintFIDO2DeviceInfo() without serial failed: %v", err)
	}
}

func TestPrinterPrintFIDO2RegistrationComprehensive(t *testing.T) {
	result := &fido2EnrollmentResult{
		CredentialID: []byte("credential-id-bytes"),
		PublicKey:    []byte("public-key-bytes"),
		AAGUID:       []byte("aaguid-bytes-16b"),
		Salt:         []byte("salt-bytes"),
		SignCount:    0,
		User: fido2User{
			ID:          []byte("user-id"),
			Name:        "testuser@example.com",
			DisplayName: "Test User",
		},
		RelyingParty: fido2RelyingParty{
			ID:   "example.com",
			Name: "Example Corp",
		},
		Created: time.Now(),
	}

	formats := []string{"text", "json", "table"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(format, buf)

			err := printer.PrintFIDO2Registration(result)
			if err != nil {
				t.Errorf("PrintFIDO2Registration() error = %v", err)
			}
			if buf.Len() == 0 {
				t.Error("PrintFIDO2Registration() produced no output")
			}
		})
	}
}

// =============================================================================
// Test generateKeyPair comprehensive
// =============================================================================

func TestGenerateKeyPairComprehensive(t *testing.T) {
	tests := []struct {
		name    string
		alg     string
		size    int
		keyType interface{}
	}{
		{"rsa 2048", "rsa", 2048, (*rsa.PrivateKey)(nil)},
		{"rsa 4096", "rsa", 4096, (*rsa.PrivateKey)(nil)},
		{"rsa default size", "rsa", 0, (*rsa.PrivateKey)(nil)},
		{"ecdsa p256", "ecdsa", 256, (*ecdsa.PrivateKey)(nil)},
		{"ecdsa p384", "ecdsa", 384, (*ecdsa.PrivateKey)(nil)},
		{"ecdsa p521", "ecdsa", 521, (*ecdsa.PrivateKey)(nil)},
		{"ecdsa default", "ecdsa", 0, (*ecdsa.PrivateKey)(nil)},
		{"ec alias", "ec", 256, (*ecdsa.PrivateKey)(nil)},
		{"ed25519", "ed25519", 0, (ed25519.PrivateKey)(nil)},
		{"unknown defaults to ecdsa", "unknown", 0, (*ecdsa.PrivateKey)(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := generateKeyPair(tt.alg, tt.size)
			if err != nil {
				t.Fatalf("generateKeyPair() error = %v", err)
			}
			if key == nil {
				t.Fatal("generateKeyPair() returned nil")
			}
		})
	}
}

// =============================================================================
// Test getPublicKey comprehensive
// =============================================================================

func TestGetPublicKeyComprehensive(t *testing.T) {
	// RSA key
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPub := getPublicKey(rsaPriv)
	if _, ok := rsaPub.(*rsa.PublicKey); !ok {
		t.Error("Expected *rsa.PublicKey")
	}

	// ECDSA key
	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaPub := getPublicKey(ecdsaPriv)
	if _, ok := ecdsaPub.(*ecdsa.PublicKey); !ok {
		t.Error("Expected *ecdsa.PublicKey")
	}

	// Ed25519 key
	_, ed25519Priv, _ := ed25519.GenerateKey(rand.Reader)
	ed25519Pub := getPublicKey(ed25519Priv)
	if _, ok := ed25519Pub.(ed25519.PublicKey); !ok {
		t.Error("Expected ed25519.PublicKey")
	}

	// Unknown type
	unknownPub := getPublicKey("not a key")
	if unknownPub != nil {
		t.Error("Expected nil for unknown type")
	}

	// Nil key
	nilPub := getPublicKey(nil)
	if nilPub != nil {
		t.Error("Expected nil for nil input")
	}
}

// =============================================================================
// Test generateCA comprehensive
// =============================================================================

func TestGenerateCAComprehensive(t *testing.T) {
	tests := []struct {
		name    string
		cn      string
		org     string
		ou      string
		country string
		state   string
		city    string
		days    int
		alg     string
		keySize int
		wantErr bool
	}{
		{"full details RSA", "Test CA", "Test Org", "Test OU", "US", "CA", "SF", 365, "rsa", 2048, false},
		{"minimal RSA", "Test CA", "", "", "", "", "", 30, "rsa", 2048, false},
		{"ECDSA P-256", "Test CA", "Org", "", "", "", "", 365, "ecdsa", 256, false},
		{"ECDSA P-384", "Test CA", "", "", "", "", "", 365, "ecdsa", 384, false},
		{"Ed25519", "Test CA", "", "", "", "", "", 365, "ed25519", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, err := generateCA(tt.cn, tt.org, tt.ou, tt.country, tt.state, tt.city, tt.days, tt.alg, tt.keySize)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if cert == nil {
					t.Fatal("generateCA() returned nil cert")
				}
				if key == nil {
					t.Fatal("generateCA() returned nil key")
				}
				if !cert.IsCA {
					t.Error("Certificate should be CA")
				}
				if cert.Subject.CommonName != tt.cn {
					t.Errorf("CN = %q, want %q", cert.Subject.CommonName, tt.cn)
				}
			}
		})
	}
}

// =============================================================================
// Test issueCertificate comprehensive
// =============================================================================

func TestIssueCertificateComprehensive(t *testing.T) {
	// Create CA
	caCert, caKey, _ := generateCA("Test CA", "Test Org", "", "", "", "", 365, "ecdsa", 256)

	tests := []struct {
		name     string
		cn       string
		certType string
		dnsNames []string
		wantErr  bool
	}{
		{"server cert", "server.example.com", "server", []string{"server.example.com"}, false},
		{"client cert", "user@example.com", "client", nil, false},
		{"both type", "dual.example.com", "both", []string{"dual.example.com"}, false},
		{"with email CN", "user@example.com", "client", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, err := issueCertificate(
				caCert, caKey,
				tt.cn, tt.certType,
				"", "", "", "", "",
				30, "ecdsa", 256,
				tt.dnsNames, nil, nil,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("issueCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if cert == nil || key == nil {
					t.Fatal("issueCertificate() returned nil")
				}
				if cert.Subject.CommonName != tt.cn {
					t.Errorf("CN = %q, want %q", cert.Subject.CommonName, tt.cn)
				}
			}
		})
	}
}

// =============================================================================
// Test migration filter building comprehensive
// =============================================================================

func TestBuildMigrationFilterComprehensive(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")

	// Test with all fields set
	_ = cmd.Flags().Set("key-types", "signing,encryption,ca,tls")
	_ = cmd.Flags().Set("store-types", "software,tpm2,pkcs11")
	_ = cmd.Flags().Set("partitions", "default,admin,users")
	_ = cmd.Flags().Set("cn-pattern", "prod-*")
	now := time.Now()
	_ = cmd.Flags().Set("created-before", now.Format(time.RFC3339))
	_ = cmd.Flags().Set("created-after", now.Add(-24*time.Hour).Format(time.RFC3339))

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
	if filter.CreatedBefore == nil {
		t.Error("Expected created-before to be set")
	}
	if filter.CreatedAfter == nil {
		t.Error("Expected created-after to be set")
	}
}

// =============================================================================
// Test migration output functions comprehensive
// =============================================================================

func TestOutputMigrationPlanComprehensive(t *testing.T) {
	plan := &migration.MigrationPlan{
		SourceBackendType: "software",
		DestBackendType:   "tpm2",
		Keys: []*types.KeyAttributes{
			{CN: "key1", KeyType: types.KeyTypeSigning, KeyAlgorithm: x509.RSA},
			{CN: "key2", KeyType: types.KeyTypeEncryption, KeyAlgorithm: x509.ECDSA},
		},
		EstimatedDuration: 30 * time.Second,
		Timestamp:         time.Now(),
		Warnings:          []string{"warning1"},
		Errors:            []string{"error1"},
	}

	// Test text output
	bufText := &bytes.Buffer{}
	printerText := NewPrinter("text", bufText)
	outputMigrationPlanText(plan, printerText)

	// Test JSON output
	bufJSON := &bytes.Buffer{}
	printerJSON := NewPrinter("json", bufJSON)
	outputMigrationPlanJSON(plan, printerJSON)
}

func TestOutputMigrationResultComprehensive(t *testing.T) {
	failedKey := &types.KeyAttributes{CN: "failed-key"}
	failedKeys := make(map[*types.KeyAttributes]error)
	failedKeys[failedKey] = errCompTestError{}

	result := &migration.MigrationResult{
		SuccessCount: 5,
		FailureCount: 1,
		SkippedCount: 2,
		Duration:     10 * time.Second,
		SuccessfulKeys: []*types.KeyAttributes{
			{CN: "key1"},
			{CN: "key2"},
		},
		FailedKeys: failedKeys,
	}

	// Test text output
	bufText := &bytes.Buffer{}
	printerText := NewPrinter("text", bufText)
	outputMigrationResultText(result, printerText)

	// Test JSON output
	bufJSON := &bytes.Buffer{}
	printerJSON := NewPrinter("json", bufJSON)
	outputMigrationResultJSON(result, printerJSON)
}

// =============================================================================
// Test helper functions comprehensive
// =============================================================================

func TestTruncateStringComprehensive(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10c", 10, "exactly10c"},
		{"this is longer", 10, "this is..."},
		{"ab", 2, "ab"},
		{"abc", 2, "ab"},
		{"abcd", 3, "abc"},
		{"hello world!", 5, "he..."},
		{"", 10, ""},
		{"a", 1, "a"},
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

func TestRepeatStringComprehensive(t *testing.T) {
	tests := []struct {
		s     string
		count int
		want  string
	}{
		{"-", 5, "-----"},
		{"ab", 3, "ababab"},
		{"x", 0, ""},
		{"", 10, ""},
		{"*", 1, "*"},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			got := repeatString(tt.s, tt.count)
			if got != tt.want {
				t.Errorf("repeatString(%q, %d) = %q, want %q", tt.s, tt.count, got, tt.want)
			}
		})
	}
}

func TestSplitAndTrimComprehensive(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b , c ", []string{"a", "b", "c"}},
		{"single", []string{"single"}},
		{"", []string{}},
		{",,,", []string{}},
		{"a,,b", []string{"a", "b"}},
		{"  ,  ", []string{}},
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

func TestHasPrefixAndTrimPrefixComprehensive(t *testing.T) {
	tests := []struct {
		s      string
		prefix string
		has    bool
		trim   string
	}{
		{"https://example.com", "https://", true, "example.com"},
		{"http://example.com", "https://", false, "http://example.com"},
		{"grpc://server:9090", "grpc://", true, "server:9090"},
		{"", "http://", false, ""},
		{"http://", "http://", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := hasPrefix(tt.s, tt.prefix); got != tt.has {
				t.Errorf("hasPrefix(%q, %q) = %v, want %v", tt.s, tt.prefix, got, tt.has)
			}
			if got := trimPrefix(tt.s, tt.prefix); got != tt.trim {
				t.Errorf("trimPrefix(%q, %q) = %q, want %q", tt.s, tt.prefix, got, tt.trim)
			}
		})
	}
}

func TestResolveStoragePathComprehensive(t *testing.T) {
	// Test explicit path
	got := resolveStoragePath("/custom/path")
	if got != "/custom/path" {
		t.Errorf("resolveStoragePath() = %q, want %q", got, "/custom/path")
	}

	// Test env variable
	if err := os.Setenv("KEYCHAIN_STORAGE_PATH", "/env/path"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() { _ = os.Unsetenv("KEYCHAIN_STORAGE_PATH") }()
	got = resolveStoragePath("")
	if got != "/env/path" {
		t.Errorf("resolveStoragePath() = %q, want %q from env", got, "/env/path")
	}

	// Test default
	if err := os.Unsetenv("KEYCHAIN_STORAGE_PATH"); err != nil {
		t.Fatalf("failed to unset env: %v", err)
	}
	got = resolveStoragePath("")
	if got != "/var/lib/keychain" {
		t.Errorf("resolveStoragePath() = %q, want default", got)
	}
}

// =============================================================================
// Test local operations with real backend
// =============================================================================

func TestGenerateKeyLocalSuccessComprehensive(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	// Generate ECDSA key
	generateKeyLocal(cfg, printer, "test-key-gen-comp", "signing", "", "ecdsa", 0, "P-256", true)
}

func TestGenerateKeyLocalSymmetricComprehensive(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	// Generate symmetric key
	generateKeyLocal(cfg, printer, "test-aes-key-comp", "symmetric", string(types.SymmetricAES256GCM), "", 256, "", false)
}

func TestListKeysLocalSuccessComprehensive(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()
	cfg.UseLocal = true

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	listKeysLocal(cfg, printer)
}

func TestListCertsLocalSuccessComprehensive(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	listCertsLocal(cfg, printer)
}

func TestCertExistsLocalSuccessComprehensive(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	certExistsLocal(cfg, printer, "nonexistent-comp")
}

func TestSaveCertLocalSuccessComprehensive(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	// Create a certificate
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	saveCertLocal(cfg, printer, "test-cert-key-comp", cert)
}

func TestSaveChainLocalSuccessComprehensive(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "software"
	cfg.KeyDir = t.TempDir()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	// Create a certificate chain
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
	saveChainLocal(cfg, printer, "test-chain-key-comp", chain)
}

// =============================================================================
// Test PrintJSON
// =============================================================================

func TestPrinterPrintJSONComprehensive(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	data := map[string]interface{}{
		"key":   "value",
		"count": 42,
		"nested": map[string]interface{}{
			"inner": "data",
		},
		"list": []string{"a", "b", "c"},
	}

	err := printer.PrintJSON(data)
	if err != nil {
		t.Fatalf("PrintJSON() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("Expected key = 'value', got %v", result["key"])
	}
}

// =============================================================================
// Test base64 encoding/decoding
// =============================================================================

func TestBase64EncodingDecodingComprehensive(t *testing.T) {
	original := []byte("test data for base64 encoding")
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
// Test Cobra commands existence
// =============================================================================

func TestCobraCommandsExistComprehensive(t *testing.T) {
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
			t.Error("Expected command is nil")
		}
	}
}

func TestSubcommandsExistComprehensive(t *testing.T) {
	// Test backends subcommands
	if backendsListCmd == nil {
		t.Error("backendsListCmd is nil")
	}
	if backendsInfoCmd == nil {
		t.Error("backendsInfoCmd is nil")
	}

	// Test key subcommands
	if keyGenerateCmd == nil {
		t.Error("keyGenerateCmd is nil")
	}
	if keyListCmd == nil {
		t.Error("keyListCmd is nil")
	}

	// Test cert subcommands
	if certSaveCmd == nil {
		t.Error("certSaveCmd is nil")
	}
	if certGetCmd == nil {
		t.Error("certGetCmd is nil")
	}
	if certListCmd == nil {
		t.Error("certListCmd is nil")
	}
	if certExistsCmd == nil {
		t.Error("certExistsCmd is nil")
	}
	if certGenerateCACmd == nil {
		t.Error("certGenerateCACmd is nil")
	}
	if certIssueCmd == nil {
		t.Error("certIssueCmd is nil")
	}
}

// Test error type
type errCompTestError struct{}

func (e errCompTestError) Error() string { return "comprehensive test error" }

// =============================================================================
// Test PrintTLSCertificate with different key types
// =============================================================================

func TestPrintTLSCertificateAllKeyTypesComprehensive(t *testing.T) {
	// RSA key
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	rsaDER, _ := x509.CreateCertificate(rand.Reader, template, template, &rsaPriv.PublicKey, rsaPriv)
	rsaCert, _ := x509.ParseCertificate(rsaDER)

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	err := printer.PrintTLSCertificate(rsaPriv, rsaCert, nil)
	if err != nil {
		t.Errorf("PrintTLSCertificate(RSA) error = %v", err)
	}

	// ECDSA key
	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaDER, _ := x509.CreateCertificate(rand.Reader, template, template, &ecdsaPriv.PublicKey, ecdsaPriv)
	ecdsaCert, _ := x509.ParseCertificate(ecdsaDER)

	buf = &bytes.Buffer{}
	printer = NewPrinter("text", buf)
	err = printer.PrintTLSCertificate(ecdsaPriv, ecdsaCert, nil)
	if err != nil {
		t.Errorf("PrintTLSCertificate(ECDSA) error = %v", err)
	}

	// Ed25519 key
	_, ed25519Priv, _ := ed25519.GenerateKey(rand.Reader)
	ed25519DER, _ := x509.CreateCertificate(rand.Reader, template, template, ed25519Priv.Public(), ed25519Priv)
	ed25519Cert, _ := x509.ParseCertificate(ed25519DER)

	buf = &bytes.Buffer{}
	printer = NewPrinter("text", buf)
	err = printer.PrintTLSCertificate(ed25519Priv, ed25519Cert, nil)
	if err != nil {
		t.Errorf("PrintTLSCertificate(Ed25519) error = %v", err)
	}
}

// =============================================================================
// Test getConfig and printVerbose
// =============================================================================

func TestGetConfigComprehensive(t *testing.T) {
	cfg := getConfig()
	if cfg == nil {
		t.Error("getConfig() returned nil")
	}
}

func TestPrintVerboseComprehensive(t *testing.T) {
	// Save and restore
	oldVerbose := globalConfig.Verbose

	// Test when verbose is off
	globalConfig.Verbose = false
	printVerbose("test message %s", "arg")

	// Test when verbose is on
	globalConfig.Verbose = true
	printVerbose("test message %s", "arg")

	// Restore
	globalConfig.Verbose = oldVerbose
}

// =============================================================================
// Test NewConfig
// =============================================================================

func TestNewConfigComprehensive(t *testing.T) {
	cfg := NewConfig()

	if cfg.Backend != "software" {
		t.Errorf("Expected default backend 'software', got %q", cfg.Backend)
	}
	if cfg.OutputFormat != "text" {
		t.Errorf("Expected default output format 'text', got %q", cfg.OutputFormat)
	}
	if cfg.Verbose {
		t.Error("Expected Verbose to be false by default")
	}
	if cfg.UseLocal {
		t.Error("Expected UseLocal to be false by default")
	}
}

// =============================================================================
// Test createClientWithTLS
// =============================================================================

func TestCreateClientWithTLSProtocols(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
	}{
		{"unix socket", "unix:///tmp/test.sock"},
		{"http", "http://localhost:8080"},
		{"https", "https://localhost:8443"},
		{"grpc", "grpc://localhost:9090"},
		{"grpcs", "grpcs://localhost:9443"},
		{"quic", "quic://localhost:4433"},
		{"default http", "localhost:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Server = tt.serverURL
			cfg.TLSInsecure = true

			cl, err := cfg.createClientWithTLS()
			if err != nil {
				t.Logf("createClientWithTLS() error = %v (may be expected)", err)
			}
			if cl != nil {
				_ = cl.Close()
			}
		})
	}
}
