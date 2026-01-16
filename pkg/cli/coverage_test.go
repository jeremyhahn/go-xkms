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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/migration"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/spf13/cobra"
)

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"empty string", "", []string{}},
		{"single value", "test", []string{"test"}},
		{"comma separated", "a,b,c", []string{"a", "b", "c"}},
		{"with spaces", " a , b , c ", []string{"a", "b", "c"}},
		{"with empty parts", "a,,b", []string{"a", "b"}},
		{"only spaces", "   ,   ,   ", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("splitAndTrim(%q) length = %d, want %d", tt.input, len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("splitAndTrim(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestGenerateKeyPair_RSA(t *testing.T) {
	key, err := generateKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("generateKeyPair(rsa) failed: %v", err)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", key)
	}
}

func TestGenerateKeyPair_RSA_SmallSize(t *testing.T) {
	key, err := generateKeyPair("rsa", 1024)
	if err != nil {
		t.Fatalf("generateKeyPair(rsa, 1024) failed: %v", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", key)
	}
	if rsaKey.N.BitLen() < 2048 {
		t.Errorf("RSA key size = %d, want >= 2048", rsaKey.N.BitLen())
	}
}

func TestGenerateKeyPair_ECDSA_P256(t *testing.T) {
	key, err := generateKeyPair("ecdsa", 256)
	if err != nil {
		t.Fatalf("generateKeyPair(ecdsa, 256) failed: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", key)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve")
	}
}

func TestGenerateKeyPair_ECDSA_P384(t *testing.T) {
	key, err := generateKeyPair("ecdsa", 384)
	if err != nil {
		t.Fatalf("generateKeyPair(ecdsa, 384) failed: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", key)
	}
	if ecKey.Curve != elliptic.P384() {
		t.Errorf("expected P-384 curve")
	}
}

func TestGenerateKeyPair_ECDSA_P521(t *testing.T) {
	key, err := generateKeyPair("ecdsa", 521)
	if err != nil {
		t.Fatalf("generateKeyPair(ecdsa, 521) failed: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", key)
	}
	if ecKey.Curve != elliptic.P521() {
		t.Errorf("expected P-521 curve")
	}
}

func TestGenerateKeyPair_EC(t *testing.T) {
	key, err := generateKeyPair("ec", 256)
	if err != nil {
		t.Fatalf("generateKeyPair(ec) failed: %v", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", key)
	}
}

func TestGenerateKeyPair_Ed25519(t *testing.T) {
	key, err := generateKeyPair("ed25519", 0)
	if err != nil {
		t.Fatalf("generateKeyPair(ed25519) failed: %v", err)
	}
	if _, ok := key.(ed25519.PrivateKey); !ok {
		t.Errorf("expected ed25519.PrivateKey, got %T", key)
	}
}

func TestGenerateKeyPair_Default(t *testing.T) {
	key, err := generateKeyPair("unknown", 0)
	if err != nil {
		t.Fatalf("generateKeyPair(unknown) failed: %v", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey for default, got %T", key)
	}
}

func TestGetPublicKey_RSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubKey := getPublicKey(privKey)
	if pubKey == nil {
		t.Fatal("getPublicKey returned nil for RSA key")
	}
	if _, ok := pubKey.(*rsa.PublicKey); !ok {
		t.Errorf("expected *rsa.PublicKey, got %T", pubKey)
	}
}

func TestGetPublicKey_ECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	pubKey := getPublicKey(privKey)
	if pubKey == nil {
		t.Fatal("getPublicKey returned nil for ECDSA key")
	}
	if _, ok := pubKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected *ecdsa.PublicKey, got %T", pubKey)
	}
}

func TestGetPublicKey_Ed25519(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	pubKey := getPublicKey(privKey)
	if pubKey == nil {
		t.Fatal("getPublicKey returned nil for Ed25519 key")
	}
	if _, ok := pubKey.(ed25519.PublicKey); !ok {
		t.Errorf("expected ed25519.PublicKey, got %T", pubKey)
	}
}

func TestGetPublicKey_Unknown(t *testing.T) {
	pubKey := getPublicKey("unknown type")
	if pubKey != nil {
		t.Errorf("getPublicKey should return nil for unknown type, got %T", pubKey)
	}
}

func TestPrintDecryptedData_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintDecryptedData("test")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintCertificate_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test"}, SerialNumber: big.NewInt(1)}
	err := printer.PrintCertificate(cert)
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintCertList_Text_Empty(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	err := printer.PrintCertList([]string{})
	if err != nil {
		t.Fatalf("PrintCertList failed: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "No certificates found") {
		t.Error("expected 'No certificates found' message")
	}
}

func TestPrintCertList_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintCertList([]string{"test"})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintCertChain_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test"}, SerialNumber: big.NewInt(1)}
	err := printer.PrintCertChain([]*x509.Certificate{cert})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintTLSCertificate_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test"}, SerialNumber: big.NewInt(1)}
	err := printer.PrintTLSCertificate(nil, cert, nil)
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintEncryptedAsym_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintEncryptedAsym("test")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintMessage_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintMessage("test")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintSuccess_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintSuccess("test")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintError_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintError(nil)
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintSignature_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintSignature("test")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintBackendInfo_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintBackendInfo("test", types.Capabilities{})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintKeyList_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintKeyList([]*types.KeyAttributes{})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintKeyInfo_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintKeyInfo(&types.KeyAttributes{})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintCertExists_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintCertExists("test", true)
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintEncryptedData_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintEncryptedData(&types.EncryptedData{})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintFIDO2Devices_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintFIDO2Devices([]fido2Device{})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintFIDO2DeviceInfo_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintFIDO2DeviceInfo(fido2Device{})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintFIDO2Registration_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintFIDO2Registration(&fido2EnrollmentResult{})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintImportParameters_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintImportParameters(&backend.ImportParameters{})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestBuildMigrationFilter_Empty(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")
	filter := buildMigrationFilter(cmd)
	if filter == nil {
		t.Fatal("buildMigrationFilter should return non-nil filter")
	}
}

func TestBuildMigrationFilter_WithKeyTypes(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")
	_ = cmd.Flags().Set("key-types", "signing,encryption,ca,tls")
	filter := buildMigrationFilter(cmd)
	if len(filter.KeyTypes) != 4 {
		t.Errorf("expected 4 key types, got %d", len(filter.KeyTypes))
	}
}

func TestBuildMigrationFilter_WithDates(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")
	now := time.Now()
	_ = cmd.Flags().Set("created-before", now.Format(time.RFC3339))
	_ = cmd.Flags().Set("created-after", now.Add(-24*time.Hour).Format(time.RFC3339))
	filter := buildMigrationFilter(cmd)
	if filter.CreatedBefore == nil {
		t.Error("expected created-before to be set")
	}
	if filter.CreatedAfter == nil {
		t.Error("expected created-after to be set")
	}
}

func TestOutputMigrationPlanText(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	plan := &migration.MigrationPlan{
		SourceBackendType: "software",
		DestBackendType:   "tpm2",
		Keys:              []*types.KeyAttributes{{CN: "key1", KeyType: types.KeyTypeSigning, KeyAlgorithm: x509.RSA}},
		EstimatedDuration: 5 * time.Second,
		Timestamp:         time.Now(),
		Warnings:          []string{"warning1"},
		Errors:            []string{"error1"},
	}
	outputMigrationPlanText(plan, printer)
}

func TestOutputMigrationResultJSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)
	key := &types.KeyAttributes{CN: "key3"}
	failedKeys := make(map[*types.KeyAttributes]error)
	failedKeys[key] = errors.New("key not found")
	result := &migration.MigrationResult{
		SuccessCount:   5,
		FailureCount:   1,
		SkippedCount:   2,
		Duration:       10 * time.Second,
		SuccessfulKeys: []*types.KeyAttributes{{CN: "key1"}},
		FailedKeys:     failedKeys,
	}
	outputMigrationResultJSON(result, printer)
}

func TestPrintKeyList_Text_Empty(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	err := printer.PrintKeyList([]*types.KeyAttributes{})
	if err != nil {
		t.Fatalf("PrintKeyList failed: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "No keys found") {
		t.Error("expected 'No keys found' message")
	}
}

func TestPrintKeyInfo_Text_WithRSA(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	key := &types.KeyAttributes{
		CN:            "rsa-key",
		KeyType:       types.KeyTypeSigning,
		KeyAlgorithm:  x509.RSA,
		StoreType:     types.StoreSoftware,
		Partition:     "default",
		RSAAttributes: &types.RSAAttributes{KeySize: 4096},
	}
	err := printer.PrintKeyInfo(key)
	if err != nil {
		t.Fatalf("PrintKeyInfo failed: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "RSA Size:") {
		t.Error("expected RSA Size in output")
	}
}

func TestPrintKeyInfo_JSON_WithECC(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)
	key := &types.KeyAttributes{
		CN:            "ecc-key",
		KeyType:       types.KeyTypeSigning,
		KeyAlgorithm:  x509.ECDSA,
		StoreType:     types.StoreSoftware,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	err := printer.PrintKeyInfo(key)
	if err != nil {
		t.Fatalf("PrintKeyInfo failed: %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result["ecc_curve"] == nil {
		t.Error("expected ecc_curve in output")
	}
}

func TestIsSymmetricAlgorithm_Comprehensive(t *testing.T) {
	tests := []struct {
		alg  string
		want bool
	}{
		{string(types.SymmetricAES128GCM), true},
		{string(types.SymmetricAES256GCM), true},
		{string(types.SymmetricChaCha20Poly1305), true},
		{"", false},
		{"rsa", false},
	}
	for _, tt := range tests {
		if got := isSymmetricAlgorithm(tt.alg); got != tt.want {
			t.Errorf("isSymmetricAlgorithm(%q) = %v, want %v", tt.alg, got, tt.want)
		}
	}
}

func TestConfig_CreateTPM2Backend_NoDevice(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "tpm2"
	cfg.TPM2UseSimulator = false
	cfg.TPM2Device = ""
	cfg.KeyDir = t.TempDir()
	_, _ = cfg.CreateBackend()
}

func TestDecodeCredentialData_Base64Standard(t *testing.T) {
	original := []byte("test credential data")
	encoded := base64.StdEncoding.EncodeToString(original)
	result, err := decodeCredentialData(encoded)
	if err != nil {
		t.Fatalf("decodeCredentialData() failed: %v", err)
	}
	if string(result) != string(original) {
		t.Errorf("decodeCredentialData() = %q, want %q", result, original)
	}
}

func TestGenerateCA_RSA2048(t *testing.T) {
	cert, key, err := generateCA("Test CA", "Test Org", "Test OU", "US", "CA", "SF", 30, "rsa", 2048)
	if err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("generateCA() returned nil")
	}
	if !cert.IsCA {
		t.Error("Certificate should be CA")
	}
}

func TestGenerateCA_ECDSA256(t *testing.T) {
	cert, key, err := generateCA("Test CA", "", "", "", "", "", 30, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("generateCA() returned nil")
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("Expected ECDSA key, got %T", key)
	}
}

func TestGenerateCA_Ed25519(t *testing.T) {
	cert, key, err := generateCA("Test CA", "", "", "", "", "", 30, "ed25519", 0)
	if err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("generateCA() returned nil")
	}
	if _, ok := key.(ed25519.PrivateKey); !ok {
		t.Errorf("Expected Ed25519 key, got %T", key)
	}
}

func TestIssueCertificate_ServerCert(t *testing.T) {
	caCert, caKey, err := generateCA("Test CA", "", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}
	cert, key, err := issueCertificate(caCert, caKey, "server.example.com", "server", "", "", "", "", "", 30, "ecdsa", 256, []string{"server.example.com"}, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatalf("issueCertificate() error = %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("issueCertificate() returned nil")
	}
}

func TestIssueCertificate_ClientCert(t *testing.T) {
	caCert, caKey, err := generateCA("Test CA", "", "", "", "", "", 365, "ecdsa", 256)
	if err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}
	cert, key, err := issueCertificate(caCert, caKey, "user@example.com", "client", "", "", "", "", "", 30, "ecdsa", 256, nil, nil, []string{"user@example.com"})
	if err != nil {
		t.Fatalf("issueCertificate() error = %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("issueCertificate() returned nil")
	}
}

func TestBuildKeyAttributesFromFlags_RSASigning(t *testing.T) {
	attrs, err := buildKeyAttributesFromFlags("test-key", "signing", "rsa", 2048, "", true)
	if err != nil {
		t.Fatalf("buildKeyAttributesFromFlags() error = %v", err)
	}
	if attrs.CN != "test-key" {
		t.Errorf("CN = %q, want %q", attrs.CN, "test-key")
	}
	if attrs.KeyType != types.KeyTypeSigning {
		t.Errorf("KeyType = %v, want %v", attrs.KeyType, types.KeyTypeSigning)
	}
}

func TestBuildKeyAttributesFromFlags_RSATooSmall(t *testing.T) {
	_, err := buildKeyAttributesFromFlags("test-key", "signing", "rsa", 1024, "", true)
	if err == nil {
		t.Error("buildKeyAttributesFromFlags() should fail for RSA key < 2048 bits")
	}
}

func TestBuildSymmetricKeyAttributes_AES256GCM(t *testing.T) {
	attrs, err := buildSymmetricKeyAttributes("test-key", string(types.SymmetricAES256GCM), 0)
	if err != nil {
		t.Fatalf("buildSymmetricKeyAttributes() error = %v", err)
	}
	if attrs == nil {
		t.Fatal("buildSymmetricKeyAttributes() returned nil")
	}
	if attrs.SymmetricAlgorithm != types.SymmetricAES256GCM {
		t.Errorf("SymmetricAlgorithm = %v, want %v", attrs.SymmetricAlgorithm, types.SymmetricAES256GCM)
	}
}

func TestNewConfig_Coverage(t *testing.T) {
	cfg := NewConfig()
	if cfg == nil {
		t.Fatal("NewConfig() returned nil")
	}
}

func TestGetBackendCapabilities_AllBackends_Coverage(t *testing.T) {
	backends := []struct {
		name        string
		wantErr     bool
		wantHWBased bool
	}{
		{"software", false, false},
		{"pkcs8", false, false},
		{"pkcs11", false, true},
		{"tpm2", false, true},
		{"awskms", false, true},
		{"gcpkms", false, true},
		{"azurekv", false, true},
		{"vault", false, false},
		{"unknown", true, false},
	}
	for _, tt := range backends {
		t.Run(tt.name, func(t *testing.T) {
			caps, err := getBackendCapabilities(tt.name)
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

func TestListBackendsLocalCoverage_Text(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	listBackendsLocal(printer)
	if buf.Len() == 0 {
		t.Error("listBackendsLocal() produced no output")
	}
}

func TestListBackendsLocalCoverage_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)
	listBackendsLocal(printer)
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if result["backends"] == nil {
		t.Error("Expected 'backends' key in JSON output")
	}
}

func TestBackendInfoLocal_Coverage(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	backendInfoLocal(printer, "software")
	if buf.Len() == 0 {
		t.Error("backendInfoLocal() produced no output")
	}
}

func TestBackendInfoLocal_JSON_Coverage(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)
	backendInfoLocal(printer, "software")
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if result["backend"] != "software" {
		t.Errorf("Expected backend = 'software', got %v", result["backend"])
	}
}

func TestPrinter_PrintJSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)
	data := map[string]interface{}{"key": "value"}
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

func TestPrinter_PrintBackendList_Table(t *testing.T) {
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

func TestPrinter_PrintBackendList_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("invalid", buf)
	err := printer.PrintBackendList([]string{"software"})
	if err == nil {
		t.Error("PrintBackendList() should fail for unknown format")
	}
}

func TestPrinter_PrintKeyList_Table(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)
	keys := []*types.KeyAttributes{{CN: "key1", KeyType: types.KeyTypeSigning, KeyAlgorithm: x509.RSA}}
	err := printer.PrintKeyList(keys)
	if err != nil {
		t.Fatalf("PrintKeyList() error = %v", err)
	}
	if !strings.Contains(buf.String(), "key1") {
		t.Error("Expected key1 in output")
	}
}

func TestPrinter_PrintKeyList_Table_Empty(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)
	err := printer.PrintKeyList([]*types.KeyAttributes{})
	if err != nil {
		t.Fatalf("PrintKeyList() error = %v", err)
	}
	if !strings.Contains(buf.String(), "No keys found") {
		t.Error("Expected 'No keys found' message")
	}
}

func TestPrinter_PrintSuccess_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)
	err := printer.PrintSuccess("operation succeeded")
	if err != nil {
		t.Fatalf("PrintSuccess() error = %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if result["status"] != "success" {
		t.Errorf("Expected status = 'success', got %v", result["status"])
	}
}

func TestPrinter_PrintError_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)
	err := printer.PrintError(errors.New("test error"))
	if err != nil {
		t.Fatalf("PrintError() error = %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("Expected status = 'error', got %v", result["status"])
	}
}

func TestRootCmdExists(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("rootCmd is nil")
	}
	if rootCmd.Use != "keychain" {
		t.Errorf("rootCmd.Use = %q, want %q", rootCmd.Use, "keychain")
	}
}

func TestSubcommandsExist(t *testing.T) {
	commands := map[string]*cobra.Command{
		"version": versionCmd, "backends": backendsCmd, "key": keyCmd, "cert": certCmd,
		"tls": tlsCmd, "fido2": fido2Cmd, "admin": adminCmd, "user": userCmd,
	}
	for name, cmd := range commands {
		if cmd == nil {
			t.Errorf("Command %q is nil", name)
		}
	}
}

func TestPrintCertChain_Text_MultipleCerts(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &privKey.PublicKey, privKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &privKey.PublicKey, privKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	chain := []*x509.Certificate{leafCert, rootCert}
	err := printer.PrintCertChain(chain)
	if err != nil {
		t.Fatalf("PrintCertChain() error = %v", err)
	}
	count := strings.Count(buf.String(), "-----BEGIN CERTIFICATE-----")
	if count != 2 {
		t.Errorf("Expected 2 certificate blocks, got %d", count)
	}
}

func TestConfig_CreateClientWithTLS_gRPC_Coverage(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "grpc://localhost:9090"
	cfg.TLSInsecure = true
	cl, err := cfg.createClientWithTLS()
	if err != nil {
		t.Fatalf("createClientWithTLS() error = %v", err)
	}
	if cl != nil {
		_ = cl.Close()
	}
}

func TestConfig_CreateClientWithTLS_Unix_Coverage(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "unix:///tmp/test.sock"
	cfg.TLSInsecure = true
	cl, err := cfg.createClientWithTLS()
	if err != nil {
		t.Fatalf("createClientWithTLS() error = %v", err)
	}
	if cl != nil {
		_ = cl.Close()
	}
}

func TestConfig_CreateClientWithTLS_DefaultREST_Coverage(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "localhost:8080"
	cfg.TLSInsecure = true
	cl, err := cfg.createClientWithTLS()
	if err != nil {
		t.Fatalf("createClientWithTLS() error = %v", err)
	}
	if cl != nil {
		_ = cl.Close()
	}
}

func TestPrintBackendInfo_JSON_Coverage(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)
	caps := types.Capabilities{HardwareBacked: true, Keys: true, Signing: true}
	err := printer.PrintBackendInfo("tpm2", caps)
	if err != nil {
		t.Fatalf("PrintBackendInfo() error = %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if result["backend"] != "tpm2" {
		t.Errorf("Expected backend = 'tpm2', got %v", result["backend"])
	}
}

func TestConfig_CreateBackend_TPM2WithSimulator(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "tpm2"
	cfg.TPM2UseSimulator = true
	cfg.KeyDir = t.TempDir()
	// This will fail because simulator is not available, but it tests the code path
	_, _ = cfg.CreateBackend()
}

func TestBuildMigrationFilter_WithStoreTypes(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")
	_ = cmd.Flags().Set("store-types", "software,tpm2")
	filter := buildMigrationFilter(cmd)
	if len(filter.StoreTypes) != 2 {
		t.Errorf("expected 2 store types, got %d", len(filter.StoreTypes))
	}
}

func TestBuildMigrationFilter_WithPartitions(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")
	_ = cmd.Flags().Set("partitions", "default,production")
	filter := buildMigrationFilter(cmd)
	if len(filter.Partitions) != 2 {
		t.Errorf("expected 2 partitions, got %d", len(filter.Partitions))
	}
}

func TestBuildMigrationFilter_WithCNPattern(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")
	_ = cmd.Flags().Set("cn-pattern", "test-*")
	filter := buildMigrationFilter(cmd)
	if filter.CNPattern != "test-*" {
		t.Errorf("expected cn-pattern 'test-*', got %q", filter.CNPattern)
	}
}

func TestOutputMigrationResultText(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)
	key := &types.KeyAttributes{CN: "key3"}
	failedKeys := make(map[*types.KeyAttributes]error)
	failedKeys[key] = errors.New("key not found")
	result := &migration.MigrationResult{
		SuccessCount:   5,
		FailureCount:   1,
		SkippedCount:   2,
		Duration:       10 * time.Second,
		SuccessfulKeys: []*types.KeyAttributes{{CN: "key1"}},
		FailedKeys:     failedKeys,
	}
	outputMigrationResultText(result, printer)
}

func TestConfig_CreateBackend_UnknownBackend(t *testing.T) {
	cfg := NewConfig()
	cfg.Backend = "some-unknown-backend"
	cfg.KeyDir = t.TempDir()
	_, err := cfg.CreateBackend()
	if err == nil {
		t.Error("CreateBackend() should fail for unknown backend")
	}
}
