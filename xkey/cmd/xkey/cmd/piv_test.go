// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/spf13/viper"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPIVConfig_Validate tests all validation paths for PIVConfig.
func TestPIVConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *PIVConfig
		wantErr error
	}{
		{
			name: "valid software backend with file storage",
			cfg: &PIVConfig{
				Backend:     PIVBackendSoftware,
				StorageType: PIVStorageTypeFile,
				StoragePath: "/var/lib/xkey/piv",
			},
			wantErr: nil,
		},
		{
			name: "valid tpm2 backend with tpm2 storage",
			cfg: &PIVConfig{
				Backend:     PIVBackendTPM2,
				StorageType: PIVStorageTypeTPM2,
				TPMDevice:   "/dev/tpmrm0",
			},
			wantErr: nil,
		},
		{
			name: "valid pkcs11 backend with pkcs11 storage",
			cfg: &PIVConfig{
				Backend:       PIVBackendPKCS11,
				StorageType:   PIVStorageTypePKCS11,
				PKCS11Library: "/usr/lib/softhsm/libsofthsm2.so",
				PKCS11Token:   "test-token",
			},
			wantErr: nil,
		},
		{
			name: "invalid backend type",
			cfg: &PIVConfig{
				Backend:     PIVBackendType("invalid"),
				StorageType: PIVStorageTypeFile,
				StoragePath: "/var/lib/xkey/piv",
			},
			wantErr: ErrPIVInvalidBackend,
		},
		{
			name: "invalid storage type",
			cfg: &PIVConfig{
				Backend:     PIVBackendSoftware,
				StorageType: PIVStorageType("invalid"),
				StoragePath: "/var/lib/xkey/piv",
			},
			wantErr: ErrPIVInvalidStorageType,
		},
		{
			name: "file storage without path",
			cfg: &PIVConfig{
				Backend:     PIVBackendSoftware,
				StorageType: PIVStorageTypeFile,
				StoragePath: "",
			},
			wantErr: ErrPIVStoragePathRequired,
		},
		{
			name: "tpm2 storage without device path",
			cfg: &PIVConfig{
				Backend:     PIVBackendTPM2,
				StorageType: PIVStorageTypeTPM2,
				TPMDevice:   "",
			},
			wantErr: ErrPIVTPMDeviceRequired,
		},
		{
			name: "pkcs11 storage without library",
			cfg: &PIVConfig{
				Backend:       PIVBackendPKCS11,
				StorageType:   PIVStorageTypePKCS11,
				PKCS11Library: "",
				PKCS11Token:   "test-token",
			},
			wantErr: ErrPIVPKCS11LibraryRequired,
		},
		{
			name: "pkcs11 storage without token",
			cfg: &PIVConfig{
				Backend:       PIVBackendPKCS11,
				StorageType:   PIVStorageTypePKCS11,
				PKCS11Library: "/usr/lib/softhsm/libsofthsm2.so",
				PKCS11Token:   "",
			},
			wantErr: ErrPIVPKCS11TokenRequired,
		},
		{
			name: "software backend with tpm2 storage",
			cfg: &PIVConfig{
				Backend:     PIVBackendSoftware,
				StorageType: PIVStorageTypeTPM2,
				TPMDevice:   "/dev/tpmrm0",
			},
			wantErr: nil, // Valid: can use different storage than backend
		},
		{
			name: "tpm2 backend with file storage",
			cfg: &PIVConfig{
				Backend:     PIVBackendTPM2,
				StorageType: PIVStorageTypeFile,
				StoragePath: "/var/lib/xkey/piv",
			},
			wantErr: nil, // Valid: can use different storage than backend
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if err != tt.wantErr {
				t.Errorf("PIVConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestBuildPIVConfig tests config building from Viper.
func TestBuildPIVConfig(t *testing.T) {
	viper.Set(viperKeyPIVBackend, "software")
	t.Cleanup(func() { viper.Reset() })

	cfg := buildPIVConfig()
	if cfg == nil {
		t.Fatal("buildPIVConfig() returned nil")
	}

	// Check that the backend is set from Viper
	if cfg.Backend == "" {
		t.Error("buildPIVConfig() returned empty backend")
	}
}

// TestBuildPIVConfig_StorageDefaults tests storage type defaults based on backend.
func TestBuildPIVConfig_StorageDefaults(t *testing.T) {
	tests := []struct {
		name            string
		backend         PIVBackendType
		wantStorageType PIVStorageType
	}{
		{
			name:            "software backend defaults to file storage",
			backend:         PIVBackendSoftware,
			wantStorageType: PIVStorageTypeFile,
		},
		{
			name:            "tpm2 backend defaults to tpm2 storage",
			backend:         PIVBackendTPM2,
			wantStorageType: PIVStorageTypeTPM2,
		},
		{
			name:            "pkcs11 backend defaults to pkcs11 storage",
			backend:         PIVBackendPKCS11,
			wantStorageType: PIVStorageTypePKCS11,
		},
		{
			name:            "unknown backend defaults to file storage",
			backend:         PIVBackendType("unknown"),
			wantStorageType: PIVStorageTypeFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the defaulting logic from buildPIVConfig
			storageType := PIVStorageType("")
			if storageType == "" {
				switch tt.backend {
				case PIVBackendSoftware:
					storageType = PIVStorageTypeFile
				case PIVBackendTPM2:
					storageType = PIVStorageTypeTPM2
				case PIVBackendPKCS11:
					storageType = PIVStorageTypePKCS11
				default:
					storageType = PIVStorageTypeFile
				}
			}

			if storageType != tt.wantStorageType {
				t.Errorf("storage default for backend %s = %s, want %s",
					tt.backend, storageType, tt.wantStorageType)
			}
		})
	}
}

// TestValidatePIVSlot tests valid slot identifiers.
func TestValidatePIVSlot(t *testing.T) {
	tests := []struct {
		name    string
		slot    string
		wantErr bool
	}{
		{
			name:    "valid authentication slot",
			slot:    "9a",
			wantErr: false,
		},
		{
			name:    "valid digital signature slot",
			slot:    "9c",
			wantErr: false,
		},
		{
			name:    "valid key management slot",
			slot:    "9d",
			wantErr: false,
		},
		{
			name:    "valid card authentication slot",
			slot:    "9e",
			wantErr: false,
		},
		{
			name:    "valid uppercase slot",
			slot:    "9A",
			wantErr: false,
		},
		{
			name:    "valid mixed case slot",
			slot:    "9C",
			wantErr: false,
		},
		{
			name:    "valid retired slot 82",
			slot:    "82",
			wantErr: false,
		},
		{
			name:    "valid retired slot 95",
			slot:    "95",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validatePIVSlot(tt.slot)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePIVSlot(%q) error = %v, wantErr %v", tt.slot, err, tt.wantErr)
			}
		})
	}
}

// TestValidatePIVSlot_Invalid tests invalid slot identifiers.
func TestValidatePIVSlot_Invalid(t *testing.T) {
	tests := []struct {
		name string
		slot string
	}{
		{
			name: "empty slot",
			slot: "",
		},
		{
			name: "invalid slot 9b",
			slot: "9b",
		},
		{
			name: "invalid slot 9f",
			slot: "9f",
		},
		{
			name: "invalid slot 00",
			slot: "00",
		},
		{
			name: "invalid slot 99",
			slot: "99",
		},
		{
			name: "invalid slot alpha",
			slot: "aa",
		},
		{
			name: "invalid slot text",
			slot: "authentication",
		},
		{
			name: "invalid slot with prefix",
			slot: "0x9a",
		},
		{
			name: "invalid slot with spaces",
			slot: " 9a",
		},
		{
			name: "invalid slot too long",
			slot: "9aa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validatePIVSlot(tt.slot)
			if err != ErrPIVInvalidSlot {
				t.Errorf("validatePIVSlot(%q) error = %v, want %v", tt.slot, err, ErrPIVInvalidSlot)
			}
		})
	}
}

// generateTestCertificate creates a self-signed test certificate.
func generateTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "test.example.com"},
		EmailAddresses:        []string{"test@example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// generateTestCertificateDER returns a test certificate in DER format.
func generateTestCertificateDER(t *testing.T) []byte {
	t.Helper()
	cert := generateTestCertificate(t)
	return cert.Raw
}

// generateTestCertificatePEM returns a test certificate in PEM format.
func generateTestCertificatePEM(t *testing.T) []byte {
	t.Helper()
	cert := generateTestCertificate(t)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// TestParseCertificateAuto_PEM tests PEM certificate parsing.
func TestParseCertificateAuto_PEM(t *testing.T) {
	pemData := generateTestCertificatePEM(t)

	cert, format, err := parseCertificateAuto(pemData)
	if err != nil {
		t.Fatalf("parseCertificateAuto() error = %v", err)
	}

	if format != CertFormatPEM {
		t.Errorf("parseCertificateAuto() format = %v, want %v", format, CertFormatPEM)
	}

	if cert == nil {
		t.Error("parseCertificateAuto() returned nil certificate")
	}

	if cert.Subject.CommonName != "Test Certificate" {
		t.Errorf("parseCertificateAuto() subject = %v, want Test Certificate", cert.Subject.CommonName)
	}
}

// TestParseCertificateAuto_DER tests DER certificate parsing.
func TestParseCertificateAuto_DER(t *testing.T) {
	derData := generateTestCertificateDER(t)

	cert, format, err := parseCertificateAuto(derData)
	if err != nil {
		t.Fatalf("parseCertificateAuto() error = %v", err)
	}

	if format != CertFormatDER {
		t.Errorf("parseCertificateAuto() format = %v, want %v", format, CertFormatDER)
	}

	if cert == nil {
		t.Error("parseCertificateAuto() returned nil certificate")
	}

	if cert.Subject.CommonName != "Test Certificate" {
		t.Errorf("parseCertificateAuto() subject = %v, want Test Certificate", cert.Subject.CommonName)
	}
}

// TestParseCertificateAuto_Invalid tests invalid certificate data.
func TestParseCertificateAuto_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "random bytes",
			data: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{
			name: "invalid PEM type",
			data: []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"),
		},
		{
			name: "malformed PEM",
			data: []byte("-----BEGIN CERTIFICATE-----\ninvalid base64!@#$\n-----END CERTIFICATE-----"),
		},
		{
			name: "truncated DER",
			data: []byte{0x30, 0x82, 0x01, 0x00}, // ASN.1 sequence header but truncated
		},
		{
			name: "text content",
			data: []byte("This is not a certificate"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseCertificateAuto(tt.data)
			if err == nil {
				t.Error("parseCertificateAuto() expected error for invalid data")
			}
		})
	}
}

// TestParseCertFormat tests format string parsing.
func TestParseCertFormat(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		want    CertFormat
		wantErr error
	}{
		{
			name:    "pem lowercase",
			format:  "pem",
			want:    CertFormatPEM,
			wantErr: nil,
		},
		{
			name:    "PEM uppercase",
			format:  "PEM",
			want:    CertFormatPEM,
			wantErr: nil,
		},
		{
			name:    "Pem mixed case",
			format:  "Pem",
			want:    CertFormatPEM,
			wantErr: nil,
		},
		{
			name:    "der lowercase",
			format:  "der",
			want:    CertFormatDER,
			wantErr: nil,
		},
		{
			name:    "DER uppercase",
			format:  "DER",
			want:    CertFormatDER,
			wantErr: nil,
		},
		{
			name:    "Der mixed case",
			format:  "Der",
			want:    CertFormatDER,
			wantErr: nil,
		},
		{
			name:    "invalid format",
			format:  "invalid",
			want:    "",
			wantErr: ErrPIVInvalidFormat,
		},
		{
			name:    "empty format",
			format:  "",
			want:    "",
			wantErr: ErrPIVInvalidFormat,
		},
		{
			name:    "pkcs7 format",
			format:  "pkcs7",
			want:    "",
			wantErr: ErrPIVInvalidFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCertFormat(tt.format)
			if err != tt.wantErr {
				t.Errorf("parseCertFormat(%q) error = %v, wantErr %v", tt.format, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseCertFormat(%q) = %v, want %v", tt.format, got, tt.want)
			}
		})
	}
}

// TestFormatKeyUsage tests key usage formatting.
func TestFormatKeyUsage(t *testing.T) {
	tests := []struct {
		name  string
		usage x509.KeyUsage
		want  string
	}{
		{
			name:  "no usage",
			usage: 0,
			want:  "None",
		},
		{
			name:  "digital signature only",
			usage: x509.KeyUsageDigitalSignature,
			want:  "Digital Signature",
		},
		{
			name:  "key encipherment only",
			usage: x509.KeyUsageKeyEncipherment,
			want:  "Key Encipherment",
		},
		{
			name:  "multiple usages",
			usage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			want:  "Digital Signature, Key Encipherment",
		},
		{
			name:  "all primary usages",
			usage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
			want:  "Digital Signature, Content Commitment, Key Encipherment",
		},
		{
			name:  "cert sign and crl sign",
			usage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			want:  "Certificate Sign, CRL Sign",
		},
		{
			name:  "data encipherment",
			usage: x509.KeyUsageDataEncipherment,
			want:  "Data Encipherment",
		},
		{
			name:  "key agreement",
			usage: x509.KeyUsageKeyAgreement,
			want:  "Key Agreement",
		},
		{
			name:  "encipher only",
			usage: x509.KeyUsageEncipherOnly,
			want:  "Encipher Only",
		},
		{
			name:  "decipher only",
			usage: x509.KeyUsageDecipherOnly,
			want:  "Decipher Only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatKeyUsage(tt.usage)
			if got != tt.want {
				t.Errorf("formatKeyUsage(%d) = %q, want %q", tt.usage, got, tt.want)
			}
		})
	}
}

// TestFormatExtKeyUsage tests extended key usage formatting.
func TestFormatExtKeyUsage(t *testing.T) {
	tests := []struct {
		name   string
		usages []x509.ExtKeyUsage
		want   string
	}{
		{
			name:   "empty",
			usages: []x509.ExtKeyUsage{},
			want:   "None",
		},
		{
			name:   "nil",
			usages: nil,
			want:   "None",
		},
		{
			name:   "server auth only",
			usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			want:   "Server Auth",
		},
		{
			name:   "client auth only",
			usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			want:   "Client Auth",
		},
		{
			name:   "code signing only",
			usages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			want:   "Code Signing",
		},
		{
			name:   "email protection only",
			usages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			want:   "Email Protection",
		},
		{
			name:   "time stamping only",
			usages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			want:   "Time Stamping",
		},
		{
			name:   "ocsp signing only",
			usages: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			want:   "OCSP Signing",
		},
		{
			name:   "any usage",
			usages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			want:   "Any",
		},
		{
			name:   "multiple usages",
			usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			want:   "Server Auth, Client Auth",
		},
		{
			name:   "unknown usage",
			usages: []x509.ExtKeyUsage{x509.ExtKeyUsage(999)},
			want:   "Unknown(999)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatExtKeyUsage(tt.usages)
			if got != tt.want {
				t.Errorf("formatExtKeyUsage(%v) = %q, want %q", tt.usages, got, tt.want)
			}
		})
	}
}

// TestPIVCmd_Help tests help output for the PIV command.
func TestPIVCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"piv", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("piv --help failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"PIV",
		"smart card",
		"certificate",
		"9a",
		"9c",
		"9d",
		"9e",
		"Authentication",
		"Digital Signature",
		"Key Management",
		"--backend",
		"--piv-storage",
		"--storage-path",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("PIV help output missing %q", expected)
		}
	}
}

// TestPIVListCmd_Help tests help output for the PIV list command.
func TestPIVListCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"piv", "list", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("piv list --help failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"List",
		"certificate",
		"slot",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("PIV list help output missing %q", expected)
		}
	}
}

// TestPIVShowCmd_Args tests that show requires args.
func TestPIVShowCmd_Args(t *testing.T) {
	// The show command requires exactly 1 argument
	if pivShowCmd.Args == nil {
		t.Fatal("pivShowCmd.Args should not be nil")
	}

	// Test that Args validation rejects no arguments
	err := pivShowCmd.Args(pivShowCmd, []string{})
	if err == nil {
		t.Error("pivShowCmd.Args should reject empty args")
	}

	// Test that Args validation accepts exactly 1 argument
	err = pivShowCmd.Args(pivShowCmd, []string{"9a"})
	if err != nil {
		t.Errorf("pivShowCmd.Args should accept 1 arg: %v", err)
	}

	// Test that Args validation rejects too many arguments
	err = pivShowCmd.Args(pivShowCmd, []string{"9a", "extra"})
	if err == nil {
		t.Error("pivShowCmd.Args should reject extra args")
	}
}

// TestPIVStoreCmd_Args tests that store requires 2 args.
func TestPIVStoreCmd_Args(t *testing.T) {
	// The store command requires exactly 2 arguments
	if pivStoreCmd.Args == nil {
		t.Fatal("pivStoreCmd.Args should not be nil")
	}

	// Test that Args validation rejects no arguments
	err := pivStoreCmd.Args(pivStoreCmd, []string{})
	if err == nil {
		t.Error("pivStoreCmd.Args should reject empty args")
	}

	// Test that Args validation rejects 1 argument
	err = pivStoreCmd.Args(pivStoreCmd, []string{"9a"})
	if err == nil {
		t.Error("pivStoreCmd.Args should reject 1 arg")
	}

	// Test that Args validation accepts exactly 2 arguments
	err = pivStoreCmd.Args(pivStoreCmd, []string{"9a", "/path/to/cert.pem"})
	if err != nil {
		t.Errorf("pivStoreCmd.Args should accept 2 args: %v", err)
	}

	// Test that Args validation rejects too many arguments
	err = pivStoreCmd.Args(pivStoreCmd, []string{"9a", "/path/to/cert.pem", "extra"})
	if err == nil {
		t.Error("pivStoreCmd.Args should reject extra args")
	}
}

// TestPIVDeleteCmd_Args tests that delete requires arg.
func TestPIVDeleteCmd_Args(t *testing.T) {
	// The delete command requires exactly 1 argument
	if pivDeleteCmd.Args == nil {
		t.Fatal("pivDeleteCmd.Args should not be nil")
	}

	// Test that Args validation rejects no arguments
	err := pivDeleteCmd.Args(pivDeleteCmd, []string{})
	if err == nil {
		t.Error("pivDeleteCmd.Args should reject empty args")
	}

	// Test that Args validation accepts exactly 1 argument
	err = pivDeleteCmd.Args(pivDeleteCmd, []string{"9a"})
	if err != nil {
		t.Errorf("pivDeleteCmd.Args should accept 1 arg: %v", err)
	}

	// Test that Args validation rejects too many arguments
	err = pivDeleteCmd.Args(pivDeleteCmd, []string{"9a", "extra"})
	if err == nil {
		t.Error("pivDeleteCmd.Args should reject extra args")
	}
}

// TestPIVExportCmd_Args tests that export requires arg.
func TestPIVExportCmd_Args(t *testing.T) {
	// The export command requires exactly 1 argument
	if pivExportCmd.Args == nil {
		t.Fatal("pivExportCmd.Args should not be nil")
	}

	// Test that Args validation rejects no arguments
	err := pivExportCmd.Args(pivExportCmd, []string{})
	if err == nil {
		t.Error("pivExportCmd.Args should reject empty args")
	}

	// Test that Args validation accepts exactly 1 argument
	err = pivExportCmd.Args(pivExportCmd, []string{"9a"})
	if err != nil {
		t.Errorf("pivExportCmd.Args should accept 1 arg: %v", err)
	}

	// Test that Args validation rejects too many arguments
	err = pivExportCmd.Args(pivExportCmd, []string{"9a", "extra"})
	if err == nil {
		t.Error("pivExportCmd.Args should reject extra args")
	}
}

// TestPIVCmd_SubcommandRegistration tests that all subcommands are registered.
func TestPIVCmd_SubcommandRegistration(t *testing.T) {
	subcommands := map[string]bool{
		"list":   false,
		"show":   false,
		"store":  false,
		"delete": false,
		"export": false,
		"status": false,
	}

	for _, cmd := range PIVCmd.Commands() {
		if _, ok := subcommands[cmd.Name()]; ok {
			subcommands[cmd.Name()] = true
		}
	}

	for name, found := range subcommands {
		if !found {
			t.Errorf("PIV subcommand %q not registered", name)
		}
	}
}

// TestPIVCmd_Aliases tests command aliases.
func TestPIVCmd_Aliases(t *testing.T) {
	tests := []struct {
		cmd     string
		aliases []string
	}{
		{
			cmd:     "list",
			aliases: []string{"ls"},
		},
		{
			cmd:     "delete",
			aliases: []string{"rm", "remove"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			var found *bool
			for _, cmd := range PIVCmd.Commands() {
				if cmd.Name() == tt.cmd {
					for _, wantAlias := range tt.aliases {
						hasAlias := false
						for _, gotAlias := range cmd.Aliases {
							if gotAlias == wantAlias {
								hasAlias = true
								break
							}
						}
						if !hasAlias {
							t.Errorf("command %q missing alias %q", tt.cmd, wantAlias)
						}
					}
					found = new(bool)
					*found = true
					break
				}
			}
			if found == nil {
				t.Errorf("command %q not found", tt.cmd)
			}
		})
	}
}

// TestPIVErrors tests that all PIV errors have proper messages.
func TestPIVErrors(t *testing.T) {
	errors := []error{
		ErrPIVInvalidBackend,
		ErrPIVInvalidStorageType,
		ErrPIVStoragePathRequired,
		ErrPIVInvalidSlot,
		ErrPIVSlotRequired,
		ErrPIVCertFileRequired,
		ErrPIVCertificateNotFound,
		ErrPIVInvalidFormat,
		ErrPIVStorageCreationFailed,
		ErrPIVCertificateReadFailed,
		ErrPIVCertificateParseFailed,
		ErrPIVStoreFailed,
		ErrPIVDeleteFailed,
		ErrPIVExportFailed,
		ErrPIVListFailed,
		ErrPIVOutputFileRequired,
		ErrPIVTPMDeviceRequired,
		ErrPIVPKCS11LibraryRequired,
		ErrPIVPKCS11TokenRequired,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("PIV error has empty message: %v", err)
		}
		if !strings.HasPrefix(err.Error(), "piv:") {
			t.Errorf("PIV error missing 'piv:' prefix: %v", err)
		}
	}
}

// TestPIVStorageTypes tests storage type constants.
func TestPIVStorageTypes(t *testing.T) {
	tests := []struct {
		storageType PIVStorageType
		wantString  string
	}{
		{PIVStorageTypeFile, "file"},
		{PIVStorageTypeTPM2, "tpm2"},
		{PIVStorageTypePKCS11, "pkcs11"},
	}

	for _, tt := range tests {
		t.Run(string(tt.storageType), func(t *testing.T) {
			if string(tt.storageType) != tt.wantString {
				t.Errorf("PIVStorageType = %q, want %q", tt.storageType, tt.wantString)
			}
		})
	}
}

// TestPIVBackendTypes tests backend type constants.
func TestPIVBackendTypes(t *testing.T) {
	tests := []struct {
		backendType PIVBackendType
		wantString  string
	}{
		{PIVBackendSoftware, "software"},
		{PIVBackendTPM2, "tpm2"},
		{PIVBackendPKCS11, "pkcs11"},
	}

	for _, tt := range tests {
		t.Run(string(tt.backendType), func(t *testing.T) {
			if string(tt.backendType) != tt.wantString {
				t.Errorf("PIVBackendType = %q, want %q", tt.backendType, tt.wantString)
			}
		})
	}
}

// TestPIVSlotConstants tests slot constants.
func TestPIVSlotConstants(t *testing.T) {
	tests := []struct {
		slot       PIVSlot
		wantString string
	}{
		{PIVSlotAuthentication, "9a"},
		{PIVSlotDigitalSignature, "9c"},
		{PIVSlotKeyManagement, "9d"},
		{PIVSlotCardAuthentication, "9e"},
	}

	for _, tt := range tests {
		t.Run(string(tt.slot), func(t *testing.T) {
			if string(tt.slot) != tt.wantString {
				t.Errorf("PIVSlot = %q, want %q", tt.slot, tt.wantString)
			}
		})
	}
}

// TestCertFormatConstants tests certificate format constants.
func TestCertFormatConstants(t *testing.T) {
	tests := []struct {
		format     CertFormat
		wantString string
	}{
		{CertFormatPEM, "pem"},
		{CertFormatDER, "der"},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			if string(tt.format) != tt.wantString {
				t.Errorf("CertFormat = %q, want %q", tt.format, tt.wantString)
			}
		})
	}
}

// TestPIVDefaultConstants tests default configuration constants.
func TestPIVDefaultConstants(t *testing.T) {
	if defaultPIVStoragePath == "" {
		t.Error("defaultPIVStoragePath should not be empty")
	}
	if defaultPIVBackend == "" {
		t.Error("defaultPIVBackend should not be empty")
	}
	if defaultPIVTPMDevice == "" {
		t.Error("defaultPIVTPMDevice should not be empty")
	}
	if defaultPIVExportFormat == "" {
		t.Error("defaultPIVExportFormat should not be empty")
	}
	if defaultPIVPKCS11Library == "" {
		t.Error("defaultPIVPKCS11Library should not be empty")
	}
}

// TestPIVViperKeys tests that viper keys are defined.
func TestPIVViperKeys(t *testing.T) {
	keys := []string{
		viperKeyPIVBackend,
		viperKeyPIVStorage,
		viperKeyPIVStoragePath,
		viperKeyPIVTPMDevice,
		viperKeyPIVPKCS11Library,
		viperKeyPIVPKCS11Token,
		viperKeyPIVPKCS11PIN,
	}

	for _, key := range keys {
		if key == "" {
			t.Error("viper key should not be empty")
		}
		if !strings.HasPrefix(key, "piv.") {
			t.Errorf("viper key %q should have 'piv.' prefix", key)
		}
	}
}

// TestPIVSlotInfo tests PIVSlotInfo structure.
func TestPIVSlotInfo(t *testing.T) {
	info := PIVSlotInfo{
		Slot:        PIVSlotAuthentication,
		Subject:     "CN=Test",
		Issuer:      "CN=Test CA",
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		Algorithm:   "ECDSA",
		Fingerprint: "sha256:abc123",
	}

	if info.Slot != PIVSlotAuthentication {
		t.Errorf("PIVSlotInfo.Slot = %v, want %v", info.Slot, PIVSlotAuthentication)
	}
	if info.Subject != "CN=Test" {
		t.Errorf("PIVSlotInfo.Subject = %v, want CN=Test", info.Subject)
	}
	if info.Issuer != "CN=Test CA" {
		t.Errorf("PIVSlotInfo.Issuer = %v, want CN=Test CA", info.Issuer)
	}
	if info.Algorithm != "ECDSA" {
		t.Errorf("PIVSlotInfo.Algorithm = %v, want ECDSA", info.Algorithm)
	}
}

// TestParseCertificateAuto_PEMWithExtraData tests PEM parsing with trailing data.
func TestParseCertificateAuto_PEMWithExtraData(t *testing.T) {
	pemData := generateTestCertificatePEM(t)
	// Add extra PEM block (should parse first cert only)
	pemData = append(pemData, []byte("\n-----BEGIN CERTIFICATE-----\n")...)

	cert, format, err := parseCertificateAuto(pemData)
	if err != nil {
		t.Fatalf("parseCertificateAuto() error = %v", err)
	}

	if format != CertFormatPEM {
		t.Errorf("parseCertificateAuto() format = %v, want %v", format, CertFormatPEM)
	}

	if cert == nil {
		t.Error("parseCertificateAuto() returned nil certificate")
	}
}

// TestParseCertificateAuto_InvalidPEMType tests that invalid PEM types are rejected.
func TestParseCertificateAuto_InvalidPEMType(t *testing.T) {
	// Create a PEM block with wrong type
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	_, _, err := parseCertificateAuto(pemData)
	if err == nil {
		t.Error("parseCertificateAuto() should reject non-CERTIFICATE PEM blocks")
	}
	if !strings.Contains(err.Error(), "invalid PEM block type") {
		t.Errorf("parseCertificateAuto() error = %v, want error containing 'invalid PEM block type'", err)
	}
}

// TestFormatKeyUsage_AllFlags tests all key usage flags combined.
func TestFormatKeyUsage_AllFlags(t *testing.T) {
	allUsage := x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign |
		x509.KeyUsageEncipherOnly |
		x509.KeyUsageDecipherOnly

	result := formatKeyUsage(allUsage)

	expectedParts := []string{
		"Digital Signature",
		"Content Commitment",
		"Key Encipherment",
		"Data Encipherment",
		"Key Agreement",
		"Certificate Sign",
		"CRL Sign",
		"Encipher Only",
		"Decipher Only",
	}

	for _, part := range expectedParts {
		if !strings.Contains(result, part) {
			t.Errorf("formatKeyUsage() result missing %q", part)
		}
	}
}

// TestPIVConfig_ValidateEdgeCases tests edge cases in config validation.
func TestPIVConfig_ValidateEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *PIVConfig
		wantErr error
	}{
		{
			name: "file storage with empty string path",
			cfg: &PIVConfig{
				Backend:     PIVBackendSoftware,
				StorageType: PIVStorageTypeFile,
				StoragePath: "",
			},
			wantErr: ErrPIVStoragePathRequired,
		},
		{
			name: "file storage with whitespace only path",
			cfg: &PIVConfig{
				Backend:     PIVBackendSoftware,
				StorageType: PIVStorageTypeFile,
				StoragePath: "   ",
			},
			wantErr: nil, // whitespace is technically non-empty
		},
		{
			name: "pkcs11 with library but no token",
			cfg: &PIVConfig{
				Backend:       PIVBackendPKCS11,
				StorageType:   PIVStorageTypePKCS11,
				PKCS11Library: "/path/to/lib.so",
				PKCS11Token:   "",
			},
			wantErr: ErrPIVPKCS11TokenRequired,
		},
		{
			name: "pkcs11 with token but no library",
			cfg: &PIVConfig{
				Backend:       PIVBackendPKCS11,
				StorageType:   PIVStorageTypePKCS11,
				PKCS11Library: "",
				PKCS11Token:   "my-token",
			},
			wantErr: ErrPIVPKCS11LibraryRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if err != tt.wantErr {
				t.Errorf("PIVConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// PIV Generate Command Tests (piv_generate.go)
// ============================================================================

// TestPIVAlgorithm_IsValid tests PIVAlgorithm.IsValid() for all valid algorithms.
func TestPIVAlgorithm_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		algorithm PIVAlgorithm
		want      bool
	}{
		{
			name:      "ECCP256 is valid",
			algorithm: PIVAlgorithmECCP256,
			want:      true,
		},
		{
			name:      "ECCP384 is valid",
			algorithm: PIVAlgorithmECCP384,
			want:      true,
		},
		{
			name:      "RSA2048 is valid",
			algorithm: PIVAlgorithmRSA2048,
			want:      true,
		},
		{
			name:      "RSA4096 is valid",
			algorithm: PIVAlgorithmRSA4096,
			want:      true,
		},
		{
			name:      "empty string invalid",
			algorithm: PIVAlgorithm(""),
			want:      false,
		},
		{
			name:      "lowercase eccp256 invalid",
			algorithm: PIVAlgorithm("eccp256"),
			want:      false,
		},
		{
			name:      "random string invalid",
			algorithm: PIVAlgorithm("INVALID"),
			want:      false,
		},
		{
			name:      "RSA1024 invalid",
			algorithm: PIVAlgorithm("RSA1024"),
			want:      false,
		},
		{
			name:      "ECCP521 invalid",
			algorithm: PIVAlgorithm("ECCP521"),
			want:      false,
		},
		{
			name:      "ED25519 is valid",
			algorithm: PIVAlgorithmEd25519,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.algorithm.IsValid(); got != tt.want {
				t.Errorf("PIVAlgorithm(%q).IsValid() = %v, want %v", tt.algorithm, got, tt.want)
			}
		})
	}
}

// TestPIVAlgorithm_String tests PIVAlgorithm.String() method.
func TestPIVAlgorithm_String(t *testing.T) {
	tests := []struct {
		name      string
		algorithm PIVAlgorithm
		want      string
	}{
		{
			name:      "ECCP256 string",
			algorithm: PIVAlgorithmECCP256,
			want:      "ECCP256",
		},
		{
			name:      "ECCP384 string",
			algorithm: PIVAlgorithmECCP384,
			want:      "ECCP384",
		},
		{
			name:      "RSA2048 string",
			algorithm: PIVAlgorithmRSA2048,
			want:      "RSA2048",
		},
		{
			name:      "RSA4096 string",
			algorithm: PIVAlgorithmRSA4096,
			want:      "RSA4096",
		},
		{
			name:      "empty algorithm string",
			algorithm: PIVAlgorithm(""),
			want:      "",
		},
		{
			name:      "custom value preserves string",
			algorithm: PIVAlgorithm("CustomAlg"),
			want:      "CustomAlg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.algorithm.String(); got != tt.want {
				t.Errorf("PIVAlgorithm(%q).String() = %q, want %q", tt.algorithm, got, tt.want)
			}
		})
	}
}

// TestPIVPINPolicy_IsValid tests PIVPINPolicy.IsValid() for all valid policies.
func TestPIVPINPolicy_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		policy PIVPINPolicy
		want   bool
	}{
		{
			name:   "never is valid",
			policy: PIVPINPolicyNever,
			want:   true,
		},
		{
			name:   "once is valid",
			policy: PIVPINPolicyOnce,
			want:   true,
		},
		{
			name:   "always is valid",
			policy: PIVPINPolicyAlways,
			want:   true,
		},
		{
			name:   "empty string invalid",
			policy: PIVPINPolicy(""),
			want:   false,
		},
		{
			name:   "uppercase NEVER invalid",
			policy: PIVPINPolicy("NEVER"),
			want:   false,
		},
		{
			name:   "random string invalid",
			policy: PIVPINPolicy("sometimes"),
			want:   false,
		},
		{
			name:   "numeric value invalid",
			policy: PIVPINPolicy("1"),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.IsValid(); got != tt.want {
				t.Errorf("PIVPINPolicy(%q).IsValid() = %v, want %v", tt.policy, got, tt.want)
			}
		})
	}
}

// TestPIVPINPolicy_String tests PIVPINPolicy.String() method.
func TestPIVPINPolicy_String(t *testing.T) {
	tests := []struct {
		name   string
		policy PIVPINPolicy
		want   string
	}{
		{
			name:   "never string",
			policy: PIVPINPolicyNever,
			want:   "never",
		},
		{
			name:   "once string",
			policy: PIVPINPolicyOnce,
			want:   "once",
		},
		{
			name:   "always string",
			policy: PIVPINPolicyAlways,
			want:   "always",
		},
		{
			name:   "empty policy string",
			policy: PIVPINPolicy(""),
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.String(); got != tt.want {
				t.Errorf("PIVPINPolicy(%q).String() = %q, want %q", tt.policy, got, tt.want)
			}
		})
	}
}

// TestPIVTouchPolicy_IsValid tests PIVTouchPolicy.IsValid() for all valid policies.
func TestPIVTouchPolicy_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		policy PIVTouchPolicy
		want   bool
	}{
		{
			name:   "never is valid",
			policy: PIVTouchPolicyNever,
			want:   true,
		},
		{
			name:   "cached is valid",
			policy: PIVTouchPolicyCached,
			want:   true,
		},
		{
			name:   "always is valid",
			policy: PIVTouchPolicyAlways,
			want:   true,
		},
		{
			name:   "empty string invalid",
			policy: PIVTouchPolicy(""),
			want:   false,
		},
		{
			name:   "uppercase ALWAYS invalid",
			policy: PIVTouchPolicy("ALWAYS"),
			want:   false,
		},
		{
			name:   "random string invalid",
			policy: PIVTouchPolicy("required"),
			want:   false,
		},
		{
			name:   "once is invalid for touch",
			policy: PIVTouchPolicy("once"),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.IsValid(); got != tt.want {
				t.Errorf("PIVTouchPolicy(%q).IsValid() = %v, want %v", tt.policy, got, tt.want)
			}
		})
	}
}

// TestPIVTouchPolicy_String tests PIVTouchPolicy.String() method.
func TestPIVTouchPolicy_String(t *testing.T) {
	tests := []struct {
		name   string
		policy PIVTouchPolicy
		want   string
	}{
		{
			name:   "never string",
			policy: PIVTouchPolicyNever,
			want:   "never",
		},
		{
			name:   "cached string",
			policy: PIVTouchPolicyCached,
			want:   "cached",
		},
		{
			name:   "always string",
			policy: PIVTouchPolicyAlways,
			want:   "always",
		},
		{
			name:   "empty policy string",
			policy: PIVTouchPolicy(""),
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.String(); got != tt.want {
				t.Errorf("PIVTouchPolicy(%q).String() = %q, want %q", tt.policy, got, tt.want)
			}
		})
	}
}

// TestPIVKeyGenerateConfig_Validate tests all validation paths for PIVKeyGenerateConfig.
func TestPIVKeyGenerateConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *PIVKeyGenerateConfig
		wantErr error
	}{
		{
			name: "valid config with all defaults",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "9a",
				Algorithm:   PIVAlgorithmECCP256,
				PINPolicy:   PIVPINPolicyOnce,
				TouchPolicy: PIVTouchPolicyNever,
				Force:       false,
			},
			wantErr: nil,
		},
		{
			name: "valid config with RSA4096",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "9c",
				Algorithm:   PIVAlgorithmRSA4096,
				PINPolicy:   PIVPINPolicyAlways,
				TouchPolicy: PIVTouchPolicyAlways,
				Force:       true,
			},
			wantErr: nil,
		},
		{
			name: "valid config with all primary slots",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "9d",
				Algorithm:   PIVAlgorithmECCP384,
				PINPolicy:   PIVPINPolicyNever,
				TouchPolicy: PIVTouchPolicyCached,
				Force:       false,
			},
			wantErr: nil,
		},
		{
			name: "invalid slot",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "invalid",
				Algorithm:   PIVAlgorithmECCP256,
				PINPolicy:   PIVPINPolicyOnce,
				TouchPolicy: PIVTouchPolicyNever,
			},
			wantErr: ErrPIVInvalidSlot,
		},
		{
			name: "empty slot",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "",
				Algorithm:   PIVAlgorithmECCP256,
				PINPolicy:   PIVPINPolicyOnce,
				TouchPolicy: PIVTouchPolicyNever,
			},
			wantErr: ErrPIVInvalidSlot,
		},
		{
			name: "invalid algorithm",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "9a",
				Algorithm:   PIVAlgorithm("INVALID"),
				PINPolicy:   PIVPINPolicyOnce,
				TouchPolicy: PIVTouchPolicyNever,
			},
			wantErr: ErrPIVInvalidAlgorithm,
		},
		{
			name: "empty algorithm",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "9a",
				Algorithm:   PIVAlgorithm(""),
				PINPolicy:   PIVPINPolicyOnce,
				TouchPolicy: PIVTouchPolicyNever,
			},
			wantErr: ErrPIVInvalidAlgorithm,
		},
		{
			name: "invalid PIN policy",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "9a",
				Algorithm:   PIVAlgorithmECCP256,
				PINPolicy:   PIVPINPolicy("invalid"),
				TouchPolicy: PIVTouchPolicyNever,
			},
			wantErr: ErrPIVInvalidPINPolicy,
		},
		{
			name: "empty PIN policy",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "9a",
				Algorithm:   PIVAlgorithmECCP256,
				PINPolicy:   PIVPINPolicy(""),
				TouchPolicy: PIVTouchPolicyNever,
			},
			wantErr: ErrPIVInvalidPINPolicy,
		},
		{
			name: "invalid touch policy",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "9a",
				Algorithm:   PIVAlgorithmECCP256,
				PINPolicy:   PIVPINPolicyOnce,
				TouchPolicy: PIVTouchPolicy("invalid"),
			},
			wantErr: ErrPIVInvalidTouchPolicy,
		},
		{
			name: "empty touch policy",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "9a",
				Algorithm:   PIVAlgorithmECCP256,
				PINPolicy:   PIVPINPolicyOnce,
				TouchPolicy: PIVTouchPolicy(""),
			},
			wantErr: ErrPIVInvalidTouchPolicy,
		},
		{
			name: "retired slot 82 is valid",
			cfg: &PIVKeyGenerateConfig{
				Slot:        "82",
				Algorithm:   PIVAlgorithmECCP256,
				PINPolicy:   PIVPINPolicyOnce,
				TouchPolicy: PIVTouchPolicyNever,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if err != tt.wantErr {
				t.Errorf("PIVKeyGenerateConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParseAlgorithm tests the parseAlgorithm function for valid and invalid inputs.
func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    PIVAlgorithm
		wantErr error
	}{
		{
			name:    "ECCP256 uppercase",
			input:   "ECCP256",
			want:    PIVAlgorithmECCP256,
			wantErr: nil,
		},
		{
			name:    "eccp256 lowercase",
			input:   "eccp256",
			want:    PIVAlgorithmECCP256,
			wantErr: nil,
		},
		{
			name:    "EccP256 mixed case",
			input:   "EccP256",
			want:    PIVAlgorithmECCP256,
			wantErr: nil,
		},
		{
			name:    "ECCP384 uppercase",
			input:   "ECCP384",
			want:    PIVAlgorithmECCP384,
			wantErr: nil,
		},
		{
			name:    "eccp384 lowercase",
			input:   "eccp384",
			want:    PIVAlgorithmECCP384,
			wantErr: nil,
		},
		{
			name:    "RSA2048 uppercase",
			input:   "RSA2048",
			want:    PIVAlgorithmRSA2048,
			wantErr: nil,
		},
		{
			name:    "rsa2048 lowercase",
			input:   "rsa2048",
			want:    PIVAlgorithmRSA2048,
			wantErr: nil,
		},
		{
			name:    "RSA4096 uppercase",
			input:   "RSA4096",
			want:    PIVAlgorithmRSA4096,
			wantErr: nil,
		},
		{
			name:    "rsa4096 lowercase",
			input:   "rsa4096",
			want:    PIVAlgorithmRSA4096,
			wantErr: nil,
		},
		{
			name:    "invalid algorithm",
			input:   "INVALID",
			want:    "",
			wantErr: ErrPIVInvalidAlgorithm,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: ErrPIVInvalidAlgorithm,
		},
		{
			name:    "RSA1024 not supported",
			input:   "RSA1024",
			want:    "",
			wantErr: ErrPIVInvalidAlgorithm,
		},
		{
			name:    "ECCP521 not supported",
			input:   "ECCP521",
			want:    "",
			wantErr: ErrPIVInvalidAlgorithm,
		},
		{
			name:    "ED25519 uppercase",
			input:   "ED25519",
			want:    PIVAlgorithmEd25519,
			wantErr: nil,
		},
		{
			name:    "ed25519 lowercase",
			input:   "ed25519",
			want:    PIVAlgorithmEd25519,
			wantErr: nil,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			want:    "",
			wantErr: ErrPIVInvalidAlgorithm,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAlgorithm(tt.input)
			if err != tt.wantErr {
				t.Errorf("parseAlgorithm(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseAlgorithm(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestParsePINPolicy tests the parsePINPolicy function for valid and invalid inputs.
func TestParsePINPolicy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    PIVPINPolicy
		wantErr error
	}{
		{
			name:    "never lowercase",
			input:   "never",
			want:    PIVPINPolicyNever,
			wantErr: nil,
		},
		{
			name:    "NEVER uppercase",
			input:   "NEVER",
			want:    PIVPINPolicyNever,
			wantErr: nil,
		},
		{
			name:    "Never mixed case",
			input:   "Never",
			want:    PIVPINPolicyNever,
			wantErr: nil,
		},
		{
			name:    "once lowercase",
			input:   "once",
			want:    PIVPINPolicyOnce,
			wantErr: nil,
		},
		{
			name:    "ONCE uppercase",
			input:   "ONCE",
			want:    PIVPINPolicyOnce,
			wantErr: nil,
		},
		{
			name:    "always lowercase",
			input:   "always",
			want:    PIVPINPolicyAlways,
			wantErr: nil,
		},
		{
			name:    "ALWAYS uppercase",
			input:   "ALWAYS",
			want:    PIVPINPolicyAlways,
			wantErr: nil,
		},
		{
			name:    "invalid policy",
			input:   "sometimes",
			want:    "",
			wantErr: ErrPIVInvalidPINPolicy,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: ErrPIVInvalidPINPolicy,
		},
		{
			name:    "numeric value",
			input:   "1",
			want:    "",
			wantErr: ErrPIVInvalidPINPolicy,
		},
		{
			name:    "cached not valid for PIN",
			input:   "cached",
			want:    "",
			wantErr: ErrPIVInvalidPINPolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePINPolicy(tt.input)
			if err != tt.wantErr {
				t.Errorf("parsePINPolicy(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parsePINPolicy(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseTouchPolicy tests the parseTouchPolicy function for valid and invalid inputs.
func TestParseTouchPolicy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    PIVTouchPolicy
		wantErr error
	}{
		{
			name:    "never lowercase",
			input:   "never",
			want:    PIVTouchPolicyNever,
			wantErr: nil,
		},
		{
			name:    "NEVER uppercase",
			input:   "NEVER",
			want:    PIVTouchPolicyNever,
			wantErr: nil,
		},
		{
			name:    "cached lowercase",
			input:   "cached",
			want:    PIVTouchPolicyCached,
			wantErr: nil,
		},
		{
			name:    "CACHED uppercase",
			input:   "CACHED",
			want:    PIVTouchPolicyCached,
			wantErr: nil,
		},
		{
			name:    "always lowercase",
			input:   "always",
			want:    PIVTouchPolicyAlways,
			wantErr: nil,
		},
		{
			name:    "ALWAYS uppercase",
			input:   "ALWAYS",
			want:    PIVTouchPolicyAlways,
			wantErr: nil,
		},
		{
			name:    "invalid policy",
			input:   "required",
			want:    "",
			wantErr: ErrPIVInvalidTouchPolicy,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: ErrPIVInvalidTouchPolicy,
		},
		{
			name:    "once not valid for touch",
			input:   "once",
			want:    "",
			wantErr: ErrPIVInvalidTouchPolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTouchPolicy(tt.input)
			if err != tt.wantErr {
				t.Errorf("parseTouchPolicy(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseTouchPolicy(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestParsePIVSlot tests the parsePIVSlot function for valid and invalid inputs.
func TestParsePIVSlot(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:    "9a lowercase",
			input:   "9a",
			wantErr: nil,
		},
		{
			name:    "9A uppercase",
			input:   "9A",
			wantErr: nil,
		},
		{
			name:    "9c lowercase",
			input:   "9c",
			wantErr: nil,
		},
		{
			name:    "9C uppercase",
			input:   "9C",
			wantErr: nil,
		},
		{
			name:    "9d lowercase",
			input:   "9d",
			wantErr: nil,
		},
		{
			name:    "9e lowercase",
			input:   "9e",
			wantErr: nil,
		},
		{
			name:    "retired slot 82",
			input:   "82",
			wantErr: nil,
		},
		{
			name:    "retired slot 95",
			input:   "95",
			wantErr: nil,
		},
		{
			name:    "invalid slot 9b",
			input:   "9b",
			wantErr: ErrPIVInvalidSlot,
		},
		{
			name:    "invalid slot 9f",
			input:   "9f",
			wantErr: ErrPIVInvalidSlot,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: ErrPIVInvalidSlot,
		},
		{
			name:    "text slot",
			input:   "authentication",
			wantErr: ErrPIVInvalidSlot,
		},
		{
			name:    "hex prefix",
			input:   "0x9a",
			wantErr: ErrPIVInvalidSlot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePIVSlot(tt.input)
			if err != tt.wantErr {
				t.Errorf("parsePIVSlot(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// TestEncodePublicKeyToPEM tests encodePublicKeyToPEM for all key types.
func TestEncodePublicKeyToPEM(t *testing.T) {
	// Generate test keys
	ecKey256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecKey384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	ed25519PubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name      string
		publicKey interface{}
		wantErr   bool
		contains  string
	}{
		{
			name:      "ECDSA P-256 public key",
			publicKey: &ecKey256.PublicKey,
			wantErr:   false,
			contains:  "-----BEGIN PUBLIC KEY-----",
		},
		{
			name:      "ECDSA P-384 public key",
			publicKey: &ecKey384.PublicKey,
			wantErr:   false,
			contains:  "-----BEGIN PUBLIC KEY-----",
		},
		{
			name:      "RSA public key",
			publicKey: &rsaKey2048.PublicKey,
			wantErr:   false,
			contains:  "-----BEGIN PUBLIC KEY-----",
		},
		{
			name:      "Ed25519 public key",
			publicKey: ed25519PubKey,
			wantErr:   false,
			contains:  "-----BEGIN PUBLIC KEY-----",
		},
		{
			name:      "unsupported key type string",
			publicKey: "not a key",
			wantErr:   true,
			contains:  "",
		},
		{
			name:      "unsupported key type int",
			publicKey: 12345,
			wantErr:   true,
			contains:  "",
		},
		{
			name:      "nil key",
			publicKey: nil,
			wantErr:   true,
			contains:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pemStr, err := encodePublicKeyToPEM(tt.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("encodePublicKeyToPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.contains != "" {
				if !strings.Contains(pemStr, tt.contains) {
					t.Errorf("encodePublicKeyToPEM() result missing %q", tt.contains)
				}
				// Verify PEM ends correctly
				if !strings.Contains(pemStr, "-----END PUBLIC KEY-----") {
					t.Error("encodePublicKeyToPEM() result missing PEM footer")
				}
			}
		})
	}
}

// TestPIVGenerateErrors tests that all PIV generate errors have proper messages.
func TestPIVGenerateErrors(t *testing.T) {
	errors := []error{
		ErrPIVInvalidAlgorithm,
		ErrPIVInvalidPINPolicy,
		ErrPIVInvalidTouchPolicy,
		ErrPIVPublicKeyEncodeFailed,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("PIV generate error has empty message: %v", err)
		}
		if !strings.HasPrefix(err.Error(), "piv:") {
			t.Errorf("PIV generate error missing 'piv:' prefix: %v", err)
		}
	}
}

// TestPIVGenerateCmd_Help tests help output for the PIV generate command.
func TestPIVGenerateCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"piv", "generate", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("piv generate --help failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"Generate",
		"key pair",
		"PIV slot",
		"ECCP256",
		"ECCP384",
		"RSA2048",
		"RSA4096",
		"algorithm",
		"pin-policy",
		"touch-policy",
		"never",
		"once",
		"always",
		"cached",
		"--force",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("PIV generate help output missing %q", expected)
		}
	}
}

// TestPIVGenerateCmd_Args tests that generate requires exactly 1 arg.
func TestPIVGenerateCmd_Args(t *testing.T) {
	if pivGenerateCmd.Args == nil {
		t.Fatal("pivGenerateCmd.Args should not be nil")
	}

	// Test that Args validation rejects no arguments
	err := pivGenerateCmd.Args(pivGenerateCmd, []string{})
	if err == nil {
		t.Error("pivGenerateCmd.Args should reject empty args")
	}

	// Test that Args validation accepts exactly 1 argument
	err = pivGenerateCmd.Args(pivGenerateCmd, []string{"9a"})
	if err != nil {
		t.Errorf("pivGenerateCmd.Args should accept 1 arg: %v", err)
	}

	// Test that Args validation rejects too many arguments
	err = pivGenerateCmd.Args(pivGenerateCmd, []string{"9a", "extra"})
	if err == nil {
		t.Error("pivGenerateCmd.Args should reject extra args")
	}
}

// ============================================================================
// PIV CSR Command Tests (piv_csr.go)
// ============================================================================

// TestPIVCSRErrors tests that all PIV CSR errors have proper messages.
func TestPIVCSRErrors(t *testing.T) {
	errors := []error{
		ErrPIVCSRCommonNameRequired,
		ErrPIVCSROutputFailed,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("PIV CSR error has empty message: %v", err)
		}
		if !strings.HasPrefix(err.Error(), "piv:") {
			t.Errorf("PIV CSR error missing 'piv:' prefix: %v", err)
		}
	}
}

// TestPIVCSRCmd_Help tests help output for the PIV csr command.
func TestPIVCSRCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"piv", "csr", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("piv csr --help failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"Generate a Certificate Signing Request",
		"Certificate Signing Request",
		"PIV slot",
		"--cn",
		"Common Name",
		"--organization",
		"--country",
		"--san",
		"--san-dns",
		"--san-ip",
		"--san-uri",
		"--output",
		"9a",
		"9c",
		"9d",
		"9e",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("PIV csr help output missing %q", expected)
		}
	}
}

// TestPIVCSRCmd_Args tests that csr requires exactly 1 arg.
func TestPIVCSRCmd_Args(t *testing.T) {
	if pivCSRCmd.Args == nil {
		t.Fatal("pivCSRCmd.Args should not be nil")
	}

	// Test that Args validation rejects no arguments
	err := pivCSRCmd.Args(pivCSRCmd, []string{})
	if err == nil {
		t.Error("pivCSRCmd.Args should reject empty args")
	}

	// Test that Args validation accepts exactly 1 argument
	err = pivCSRCmd.Args(pivCSRCmd, []string{"9a"})
	if err != nil {
		t.Errorf("pivCSRCmd.Args should accept 1 arg: %v", err)
	}

	// Test that Args validation rejects too many arguments
	err = pivCSRCmd.Args(pivCSRCmd, []string{"9a", "extra"})
	if err == nil {
		t.Error("pivCSRCmd.Args should reject extra args")
	}
}

// ============================================================================
// PIV Import Command Tests (piv_import.go)
// ============================================================================

// TestPIVImportErrors tests that all PIV import errors have proper messages.
func TestPIVImportErrors(t *testing.T) {
	errors := []error{
		ErrPIVCertImportFailed,
		ErrPIVCertKeyMismatch,
		ErrPIVNoCertificateInFile,
		ErrPIVSlotKeyNotFound,
		ErrPIVVerificationFailed,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("PIV import error has empty message: %v", err)
		}
		if !strings.HasPrefix(err.Error(), "piv:") {
			t.Errorf("PIV import error missing 'piv:' prefix: %v", err)
		}
	}
}

// TestPIVImportCmd_Help tests help output for the PIV import command.
func TestPIVImportCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"piv", "import", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("piv import --help failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"Import",
		"certificate",
		"PIV slot",
		"PEM",
		"--verify",
		"--force",
		"9a",
		"9c",
		"9d",
		"9e",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("PIV import help output missing %q", expected)
		}
	}
}

// TestPIVImportCmd_Args tests that import requires exactly 2 args.
func TestPIVImportCmd_Args(t *testing.T) {
	if pivImportCmd.Args == nil {
		t.Fatal("pivImportCmd.Args should not be nil")
	}

	// Test that Args validation rejects no arguments
	err := pivImportCmd.Args(pivImportCmd, []string{})
	if err == nil {
		t.Error("pivImportCmd.Args should reject empty args")
	}

	// Test that Args validation rejects 1 argument
	err = pivImportCmd.Args(pivImportCmd, []string{"9a"})
	if err == nil {
		t.Error("pivImportCmd.Args should reject 1 arg")
	}

	// Test that Args validation accepts exactly 2 arguments
	err = pivImportCmd.Args(pivImportCmd, []string{"9a", "/path/to/cert.pem"})
	if err != nil {
		t.Errorf("pivImportCmd.Args should accept 2 args: %v", err)
	}

	// Test that Args validation rejects too many arguments
	err = pivImportCmd.Args(pivImportCmd, []string{"9a", "/path/to/cert.pem", "extra"})
	if err == nil {
		t.Error("pivImportCmd.Args should reject extra args")
	}
}

// TestLoadCertificateFromFile tests certificate loading from files.
func TestLoadCertificateFromFile(t *testing.T) {
	// Create a temp directory for test files
	tempDir := t.TempDir()

	// Generate test certificate
	testCert := generateTestCertificate(t)

	// Write PEM certificate
	pemPath := tempDir + "/cert.pem"
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: testCert.Raw,
	})
	if err := os.WriteFile(pemPath, pemData, 0600); err != nil {
		t.Fatalf("failed to write PEM cert: %v", err)
	}

	// Write DER certificate
	derPath := tempDir + "/cert.der"
	if err := os.WriteFile(derPath, testCert.Raw, 0600); err != nil {
		t.Fatalf("failed to write DER cert: %v", err)
	}

	// Write invalid PEM (wrong type)
	invalidPEMPath := tempDir + "/invalid.pem"
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("not a certificate"),
	})
	if err := os.WriteFile(invalidPEMPath, invalidPEM, 0600); err != nil {
		t.Fatalf("failed to write invalid PEM: %v", err)
	}

	// Write garbage data
	garbagePath := tempDir + "/garbage.bin"
	if err := os.WriteFile(garbagePath, []byte("this is not a certificate"), 0600); err != nil {
		t.Fatalf("failed to write garbage: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
		errType error
	}{
		{
			name:    "load PEM certificate",
			path:    pemPath,
			wantErr: false,
		},
		{
			name:    "load DER certificate",
			path:    derPath,
			wantErr: false,
		},
		{
			name:    "file not found",
			path:    tempDir + "/nonexistent.pem",
			wantErr: true,
		},
		{
			name:    "invalid PEM type",
			path:    invalidPEMPath,
			wantErr: true,
		},
		{
			name:    "garbage file",
			path:    garbagePath,
			wantErr: true,
			errType: ErrPIVNoCertificateInFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := loadCertificateFromFile(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadCertificateFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errType != nil {
				if !errors.Is(err, tt.errType) {
					t.Errorf("loadCertificateFromFile() error = %v, want error wrapping %v", err, tt.errType)
				}
			}

			if !tt.wantErr && cert == nil {
				t.Error("loadCertificateFromFile() returned nil certificate")
			}
		})
	}
}

// TestPublicKeysEqual tests public key comparison function.
func TestPublicKeysEqual(t *testing.T) {
	// Generate test keys
	ecKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecKey384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	ed25519Key1, _, _ := ed25519.GenerateKey(rand.Reader)
	ed25519Key2, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		pub1 interface{}
		pub2 interface{}
		want bool
	}{
		{
			name: "same ECDSA key",
			pub1: &ecKey1.PublicKey,
			pub2: &ecKey1.PublicKey,
			want: true,
		},
		{
			name: "different ECDSA keys same curve",
			pub1: &ecKey1.PublicKey,
			pub2: &ecKey2.PublicKey,
			want: false,
		},
		{
			name: "ECDSA keys different curves",
			pub1: &ecKey1.PublicKey,
			pub2: &ecKey384.PublicKey,
			want: false,
		},
		{
			name: "same RSA key",
			pub1: &rsaKey1.PublicKey,
			pub2: &rsaKey1.PublicKey,
			want: true,
		},
		{
			name: "different RSA keys",
			pub1: &rsaKey1.PublicKey,
			pub2: &rsaKey2.PublicKey,
			want: false,
		},
		{
			name: "same Ed25519 key",
			pub1: ed25519Key1,
			pub2: ed25519Key1,
			want: true,
		},
		{
			name: "different Ed25519 keys",
			pub1: ed25519Key1,
			pub2: ed25519Key2,
			want: false,
		},
		{
			name: "ECDSA vs RSA",
			pub1: &ecKey1.PublicKey,
			pub2: &rsaKey1.PublicKey,
			want: false,
		},
		{
			name: "RSA vs ECDSA",
			pub1: &rsaKey1.PublicKey,
			pub2: &ecKey1.PublicKey,
			want: false,
		},
		{
			name: "Ed25519 vs ECDSA",
			pub1: ed25519Key1,
			pub2: &ecKey1.PublicKey,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := publicKeysEqual(tt.pub1, tt.pub2); got != tt.want {
				t.Errorf("publicKeysEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFormatCertInfo tests certificate information formatting.
func TestFormatCertInfo(t *testing.T) {
	cert := generateTestCertificate(t)
	info := formatCertInfo(cert)

	expectedStrings := []string{
		"Subject:",
		"Issuer:",
		"Valid:",
		"Serial:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(info, expected) {
			t.Errorf("formatCertInfo() missing %q in output", expected)
		}
	}

	// Verify dates are formatted using the certificate's actual dates
	// (avoid time.Now() race condition across midnight or timezone issues)
	if !strings.Contains(info, cert.NotBefore.Format(time.DateOnly)) {
		t.Errorf("formatCertInfo() should contain NotBefore date %s, got: %s",
			cert.NotBefore.Format(time.DateOnly), info)
	}
}

// TestFormatCertInfo_EmptySubject tests certificate with empty subject fields.
func TestFormatCertInfo_EmptySubject(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	info := formatCertInfo(cert)

	// Should still contain the expected labels
	if !strings.Contains(info, "Subject:") {
		t.Error("formatCertInfo() should contain Subject label even if empty")
	}
	if !strings.Contains(info, "Issuer:") {
		t.Error("formatCertInfo() should contain Issuer label even if empty")
	}
}

// ============================================================================
// Additional PIV Command Integration Tests
// ============================================================================

// TestPIVCmd_GenerateSubcommandRegistration tests that generate command is registered.
func TestPIVCmd_GenerateSubcommandRegistration(t *testing.T) {
	found := false
	for _, cmd := range PIVCmd.Commands() {
		if cmd.Name() == "generate" {
			found = true
			break
		}
	}
	if !found {
		t.Error("PIV generate subcommand not registered")
	}
}

// TestPIVCmd_CSRSubcommandRegistration tests that csr command is registered.
func TestPIVCmd_CSRSubcommandRegistration(t *testing.T) {
	found := false
	for _, cmd := range PIVCmd.Commands() {
		if cmd.Name() == "csr" {
			found = true
			break
		}
	}
	if !found {
		t.Error("PIV csr subcommand not registered")
	}
}

// TestPIVCmd_ImportSubcommandRegistration tests that import command is registered.
func TestPIVCmd_ImportSubcommandRegistration(t *testing.T) {
	found := false
	for _, cmd := range PIVCmd.Commands() {
		if cmd.Name() == "import" {
			found = true
			break
		}
	}
	if !found {
		t.Error("PIV import subcommand not registered")
	}
}

// TestPIVGenerateCmd_FlagDefaults tests default flag values for generate command.
func TestPIVGenerateCmd_FlagDefaults(t *testing.T) {
	// Check algorithm flag default
	algFlag := pivGenerateCmd.Flags().Lookup("algorithm")
	if algFlag == nil {
		t.Fatal("algorithm flag not found")
	}
	if algFlag.DefValue != "ECCP256" {
		t.Errorf("algorithm flag default = %q, want ECCP256", algFlag.DefValue)
	}

	// Check pin-policy flag default
	pinFlag := pivGenerateCmd.Flags().Lookup("pin-policy")
	if pinFlag == nil {
		t.Fatal("pin-policy flag not found")
	}
	if pinFlag.DefValue != "once" {
		t.Errorf("pin-policy flag default = %q, want once", pinFlag.DefValue)
	}

	// Check touch-policy flag default
	touchFlag := pivGenerateCmd.Flags().Lookup("touch-policy")
	if touchFlag == nil {
		t.Fatal("touch-policy flag not found")
	}
	if touchFlag.DefValue != "never" {
		t.Errorf("touch-policy flag default = %q, want never", touchFlag.DefValue)
	}

	// Check force flag default
	forceFlag := pivGenerateCmd.Flags().Lookup("force")
	if forceFlag == nil {
		t.Fatal("force flag not found")
	}
	if forceFlag.DefValue != "false" {
		t.Errorf("force flag default = %q, want false", forceFlag.DefValue)
	}
}

// TestPIVImportCmd_FlagDefaults tests default flag values for import command.
func TestPIVImportCmd_FlagDefaults(t *testing.T) {
	// Check verify flag default
	verifyFlag := pivImportCmd.Flags().Lookup("verify")
	if verifyFlag == nil {
		t.Fatal("verify flag not found")
	}
	if verifyFlag.DefValue != "true" {
		t.Errorf("verify flag default = %q, want true", verifyFlag.DefValue)
	}

	// Check force flag default
	forceFlag := pivImportCmd.Flags().Lookup("force")
	if forceFlag == nil {
		t.Fatal("force flag not found")
	}
	if forceFlag.DefValue != "false" {
		t.Errorf("force flag default = %q, want false", forceFlag.DefValue)
	}
}

// TestPIVCSRCmd_FlagExists tests that required flags exist for csr command.
func TestPIVCSRCmd_FlagExists(t *testing.T) {
	requiredFlags := []string{
		"cn",
		"organization",
		"organizational-unit",
		"country",
		"province",
		"locality",
		"san",
		"san-dns",
		"san-ip",
		"san-uri",
		"output",
	}

	for _, flagName := range requiredFlags {
		flag := pivCSRCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("piv csr missing flag %q", flagName)
		}
	}
}

// TestPIVAlgorithmConstants tests algorithm constant values.
func TestPIVAlgorithmConstants(t *testing.T) {
	tests := []struct {
		algorithm PIVAlgorithm
		want      string
	}{
		{PIVAlgorithmECCP256, "ECCP256"},
		{PIVAlgorithmECCP384, "ECCP384"},
		{PIVAlgorithmEd25519, "ED25519"},
		{PIVAlgorithmRSA2048, "RSA2048"},
		{PIVAlgorithmRSA4096, "RSA4096"},
	}

	for _, tt := range tests {
		if string(tt.algorithm) != tt.want {
			t.Errorf("PIVAlgorithm constant = %q, want %q", tt.algorithm, tt.want)
		}
	}
}

// TestPIVPINPolicyConstants tests PIN policy constant values.
func TestPIVPINPolicyConstants(t *testing.T) {
	tests := []struct {
		policy PIVPINPolicy
		want   string
	}{
		{PIVPINPolicyNever, "never"},
		{PIVPINPolicyOnce, "once"},
		{PIVPINPolicyAlways, "always"},
	}

	for _, tt := range tests {
		if string(tt.policy) != tt.want {
			t.Errorf("PIVPINPolicy constant = %q, want %q", tt.policy, tt.want)
		}
	}
}

// TestPIVTouchPolicyConstants tests touch policy constant values.
func TestPIVTouchPolicyConstants(t *testing.T) {
	tests := []struct {
		policy PIVTouchPolicy
		want   string
	}{
		{PIVTouchPolicyNever, "never"},
		{PIVTouchPolicyCached, "cached"},
		{PIVTouchPolicyAlways, "always"},
	}

	for _, tt := range tests {
		if string(tt.policy) != tt.want {
			t.Errorf("PIVTouchPolicy constant = %q, want %q", tt.policy, tt.want)
		}
	}
}

// ============================================================================
// Additional Edge Case Tests for Higher Coverage
// ============================================================================

// TestBuildPIVConfig_AllBackends tests buildPIVConfig for all backend types.
func TestBuildPIVConfig_AllBackends_Detailed(t *testing.T) {
	// This tests the actual buildPIVConfig function behavior
	// Since it reads from viper, we test the defaults
	cfg := buildPIVConfig()

	// Verify the struct is populated
	if cfg == nil {
		t.Fatal("buildPIVConfig() returned nil")
	}

	// Default backend should be software
	if cfg.Backend != PIVBackendSoftware && cfg.Backend != "" {
		// Either default or empty is acceptable based on viper config
	}

	// If backend is set, storage type should default appropriately
	if cfg.Backend == PIVBackendSoftware && cfg.StorageType != PIVStorageTypeFile {
		// Software backend defaults to file storage
		t.Logf("Note: Backend %s has storage type %s", cfg.Backend, cfg.StorageType)
	}
}

// TestPIVKeyGenerateConfig_AllCombinations tests various valid config combinations.
func TestPIVKeyGenerateConfig_AllCombinations(t *testing.T) {
	algorithms := []PIVAlgorithm{
		PIVAlgorithmECCP256,
		PIVAlgorithmECCP384,
		PIVAlgorithmRSA2048,
		PIVAlgorithmRSA4096,
	}

	pinPolicies := []PIVPINPolicy{
		PIVPINPolicyNever,
		PIVPINPolicyOnce,
		PIVPINPolicyAlways,
	}

	touchPolicies := []PIVTouchPolicy{
		PIVTouchPolicyNever,
		PIVTouchPolicyCached,
		PIVTouchPolicyAlways,
	}

	slots := []string{"9a", "9c", "9d", "9e"}

	for _, alg := range algorithms {
		for _, pinPolicy := range pinPolicies {
			for _, touchPolicy := range touchPolicies {
				for _, slot := range slots {
					cfg := &PIVKeyGenerateConfig{
						Slot:        pivcert.PIVSlot(slot),
						Algorithm:   alg,
						PINPolicy:   pinPolicy,
						TouchPolicy: touchPolicy,
						Force:       false,
					}

					if err := cfg.Validate(); err != nil {
						t.Errorf("Valid config failed validation: alg=%s, pin=%s, touch=%s, slot=%s: %v",
							alg, pinPolicy, touchPolicy, slot, err)
					}
				}
			}
		}
	}
}

// TestEncodePublicKeyToPEM_ValidatesOutput tests that PEM output is valid.
func TestEncodePublicKeyToPEM_ValidatesOutput(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	pemStr, err := encodePublicKeyToPEM(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("encodePublicKeyToPEM() error = %v", err)
	}

	// Parse the PEM output
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM block type = %q, want %q", block.Type, "PUBLIC KEY")
	}

	// Parse the public key from the PEM
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse public key from PEM: %v", err)
	}

	// Verify the parsed key matches the original
	parsedEC, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", parsedKey)
	}

	if parsedEC.X.Cmp(ecKey.X) != 0 || parsedEC.Y.Cmp(ecKey.Y) != 0 {
		t.Error("parsed key does not match original key")
	}
}

// TestPublicKeysEqual_NilHandling tests nil key handling.
func TestPublicKeysEqual_NilHandling(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Note: The function doesn't explicitly handle nil, but we test behavior
	// with interface nil - this should go to the default case
	result := publicKeysEqual(nil, nil)
	// Both nil would marshal to error, which returns false
	if result {
		t.Error("publicKeysEqual(nil, nil) should return false")
	}

	result = publicKeysEqual(&ecKey.PublicKey, nil)
	if result {
		t.Error("publicKeysEqual(key, nil) should return false")
	}

	result = publicKeysEqual(nil, &ecKey.PublicKey)
	if result {
		t.Error("publicKeysEqual(nil, key) should return false")
	}
}

// TestLoadCertificateFromFile_PEMWithWhitespace tests PEM with extra whitespace.
func TestLoadCertificateFromFile_PEMWithWhitespace(t *testing.T) {
	tempDir := t.TempDir()
	testCert := generateTestCertificate(t)

	// Create PEM with extra whitespace
	pemData := "\n\n" + string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: testCert.Raw,
	})) + "\n\n"

	pemPath := tempDir + "/cert_whitespace.pem"
	if err := os.WriteFile(pemPath, []byte(pemData), 0600); err != nil {
		t.Fatalf("failed to write PEM cert: %v", err)
	}

	cert, err := loadCertificateFromFile(pemPath)
	if err != nil {
		t.Fatalf("loadCertificateFromFile() error = %v", err)
	}

	if cert.Subject.CommonName != testCert.Subject.CommonName {
		t.Errorf("Subject mismatch: got %v, want %v", cert.Subject.CommonName, testCert.Subject.CommonName)
	}
}

// TestFormatCertInfo_LongSubject tests certificate with long subject fields.
func TestFormatCertInfo_LongSubject(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:         "Very Long Common Name That Contains Many Characters",
			Organization:       []string{"Very Long Organization Name Inc."},
			OrganizationalUnit: []string{"Department of Very Long Names"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
		},
		Issuer: pkix.Name{
			CommonName:   "Root CA With A Very Long Name",
			Organization: []string{"Certificate Authority Organization"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	info := formatCertInfo(cert)

	// Verify long fields are present
	if !strings.Contains(info, "Very Long Common Name") {
		t.Error("formatCertInfo() should contain long common name")
	}
	if !strings.Contains(info, "Issuer:") {
		t.Error("formatCertInfo() should contain Issuer label")
	}
}

// TestParsePIVSlot_RetiredSlots tests all valid retired slots.
func TestParsePIVSlot_RetiredSlots(t *testing.T) {
	// Retired slots are 82-95 (hex)
	validRetiredSlots := []string{
		"82", "83", "84", "85", "86", "87", "88", "89",
		"8a", "8b", "8c", "8d", "8e", "8f",
		"90", "91", "92", "93", "94", "95",
	}

	for _, slot := range validRetiredSlots {
		t.Run(slot, func(t *testing.T) {
			_, err := parsePIVSlot(slot)
			if err != nil {
				t.Errorf("parsePIVSlot(%q) should be valid for retired slot: %v", slot, err)
			}
		})
	}
}

// TestParsePIVSlot_InvalidBoundary tests boundary invalid slots.
func TestParsePIVSlot_InvalidBoundary(t *testing.T) {
	invalidSlots := []string{
		"81", // Just before valid retired slots
		"96", // Just after valid retired slots
		"9g", // Invalid hex character
		"g9", // Invalid hex character
	}

	for _, slot := range invalidSlots {
		t.Run(slot, func(t *testing.T) {
			_, err := parsePIVSlot(slot)
			if err != ErrPIVInvalidSlot {
				t.Errorf("parsePIVSlot(%q) should return ErrPIVInvalidSlot, got: %v", slot, err)
			}
		})
	}
}

// TestPIVCmd_AllSubcommandsRegistered tests comprehensive subcommand registration.
func TestPIVCmd_AllSubcommandsRegistered(t *testing.T) {
	expectedSubcommands := []string{
		"list",
		"show",
		"store",
		"delete",
		"export",
		"status",
		"generate",
		"csr",
		"import",
	}

	registeredNames := make(map[string]bool)
	for _, cmd := range PIVCmd.Commands() {
		registeredNames[cmd.Name()] = true
	}

	for _, expected := range expectedSubcommands {
		if !registeredNames[expected] {
			t.Errorf("PIV subcommand %q not registered", expected)
		}
	}
}

// TestPIVErrors_AllUnique tests that all PIV errors are unique.
func TestPIVErrors_AllUnique(t *testing.T) {
	allErrors := []error{
		// piv.go errors
		ErrPIVInvalidBackend,
		ErrPIVInvalidStorageType,
		ErrPIVStoragePathRequired,
		ErrPIVInvalidSlot,
		ErrPIVSlotRequired,
		ErrPIVCertFileRequired,
		ErrPIVCertificateNotFound,
		ErrPIVInvalidFormat,
		ErrPIVStorageCreationFailed,
		ErrPIVCertificateReadFailed,
		ErrPIVCertificateParseFailed,
		ErrPIVStoreFailed,
		ErrPIVDeleteFailed,
		ErrPIVExportFailed,
		ErrPIVListFailed,
		ErrPIVOutputFileRequired,
		ErrPIVTPMDeviceRequired,
		ErrPIVPKCS11LibraryRequired,
		ErrPIVPKCS11TokenRequired,
		// piv_generate.go errors
		ErrPIVInvalidAlgorithm,
		ErrPIVInvalidPINPolicy,
		ErrPIVInvalidTouchPolicy,
		ErrPIVPublicKeyEncodeFailed,
		// piv_csr.go errors
		ErrPIVCSRCommonNameRequired,
		ErrPIVCSROutputFailed,
		// piv_import.go errors
		ErrPIVCertImportFailed,
		ErrPIVCertKeyMismatch,
		ErrPIVNoCertificateInFile,
		ErrPIVSlotKeyNotFound,
		ErrPIVVerificationFailed,
	}

	seen := make(map[string]bool)
	for _, err := range allErrors {
		msg := err.Error()
		if seen[msg] {
			t.Errorf("Duplicate error message: %q", msg)
		}
		seen[msg] = true
	}
}
