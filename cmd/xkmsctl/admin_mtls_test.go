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

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// ============================================================================
// Test Helpers
// ============================================================================

// generateTestCert creates a self-signed X.509 certificate in PEM format
// and writes it to a temporary file, returning the file path.
func generateTestCert(t *testing.T) (string, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "admin@example.com",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse created certificate: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	certPath := filepath.Join(t.TempDir(), "client.pem")
	if err := os.WriteFile(certPath, pemBlock, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}

	return certPath, cert
}

// ============================================================================
// admin create --method flag tests
// ============================================================================

func TestAdminCreateCmd_HasMethodFlag(t *testing.T) {
	flags := adminCreateCmd.Flags()
	methodFlag := flags.Lookup("method")
	if methodFlag == nil {
		t.Fatal("expected flag 'method' on adminCreateCmd")
	}
	if methodFlag.DefValue != "fido2" {
		t.Errorf("method default = %v, want fido2", methodFlag.DefValue)
	}
}

func TestAdminCreateCmd_HasCertFileFlag(t *testing.T) {
	flags := adminCreateCmd.Flags()
	certFileFlag := flags.Lookup("cert-file")
	if certFileFlag == nil {
		t.Fatal("expected flag 'cert-file' on adminCreateCmd")
	}
	if certFileFlag.DefValue != "" {
		t.Errorf("cert-file default = %v, want empty", certFileFlag.DefValue)
	}
}

func TestAdminCreateCmd_UnsupportedMethod(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	cmd := &cobra.Command{Use: "test"}
	cmd.AddCommand(adminCmd)
	cmd.SetArgs([]string{
		"admin", "create", "user@test.com",
		"--method", "invalid-method",
		"--storage-path", tmpDir,
	})

	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unsupported method")
	}
	if !errors.Is(err, ErrUnsupportedAuthMethod) {
		t.Errorf("expected ErrUnsupportedAuthMethod, got: %v", err)
	}
}

// ============================================================================
// mTLS enrollment with --cert-file (happy path)
// ============================================================================

func TestAdminCreate_MTLS_CertFile_Success_Text(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	certPath, cert := generateTestCert(t)

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	output, _ := executeAdminCommand(t, tmpDir, "create", "mtls-admin@test.com",
		"--method", "mtls",
		"--cert-file", certPath,
		"--display-name", "mTLS Admin",
	)

	// Verify output contains expected fields
	if !strings.Contains(output, "mtls-admin@test.com") {
		t.Errorf("expected username in output, got: %s", output)
	}
	if !strings.Contains(output, "mTLS") {
		t.Errorf("expected 'mTLS' auth method in output, got: %s", output)
	}
	if !strings.Contains(output, "Fingerprint:") {
		t.Errorf("expected fingerprint in output, got: %s", output)
	}

	// Verify user was persisted with correct cert binding
	ctx := context.Background()
	admin, err := store.GetByUsername(ctx, "mtls-admin@test.com")
	if err != nil {
		t.Fatalf("failed to retrieve admin: %v", err)
	}
	if admin.Role != "admin" {
		t.Errorf("expected admin role, got: %s", admin.Role)
	}
	if admin.DisplayName != "mTLS Admin" {
		t.Errorf("expected display name 'mTLS Admin', got: %s", admin.DisplayName)
	}
	if len(admin.CertBindings) != 1 {
		t.Fatalf("expected 1 cert binding, got: %d", len(admin.CertBindings))
	}

	// Verify the fingerprint matches the certificate
	expectedHash := sha256.Sum256(cert.Raw)
	expectedFingerprint := hex.EncodeToString(expectedHash[:])
	if admin.CertBindings[0].Fingerprint != expectedFingerprint {
		t.Errorf("fingerprint mismatch:\n  got:  %s\n  want: %s",
			admin.CertBindings[0].Fingerprint, expectedFingerprint)
	}
	if admin.CertBindings[0].Subject != cert.Subject.String() {
		t.Errorf("subject mismatch: got %s, want %s",
			admin.CertBindings[0].Subject, cert.Subject.String())
	}
}

func TestAdminCreate_MTLS_CertFile_Success_JSON(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	certPath, _ := generateTestCert(t)

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "create", "mtls-json@test.com",
		"--method", "mtls",
		"--cert-file", certPath,
		"--display-name", "",
	)

	if !strings.Contains(output, `"auth_method"`) || !strings.Contains(output, `"mtls"`) {
		t.Errorf("expected JSON with auth_method: mtls, got: %s", output)
	}
	if !strings.Contains(output, `"fingerprint"`) {
		t.Errorf("expected fingerprint in JSON output, got: %s", output)
	}
	if !strings.Contains(output, `"success"`) {
		t.Errorf("expected success in JSON output, got: %s", output)
	}
}

func TestAdminCreate_MTLS_DefaultDisplayName(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	certPath, _ := generateTestCert(t)

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	// Explicitly pass --display-name "" to reset any stale flag value
	// on the shared global adminCreateCmd from prior tests.
	_, _ = executeAdminCommand(t, tmpDir, "create", "defname@test.com",
		"--method", "mtls",
		"--cert-file", certPath,
		"--display-name", "",
	)

	// When --display-name is empty, username should be used as the display name
	ctx := context.Background()
	admin, err := store.GetByUsername(ctx, "defname@test.com")
	if err != nil {
		t.Fatalf("failed to retrieve admin: %v", err)
	}
	if admin.DisplayName != "defname@test.com" {
		t.Errorf("expected display name to default to username, got: %s", admin.DisplayName)
	}
}

// ============================================================================
// mTLS enrollment error cases
// ============================================================================

func TestAdminCreate_MTLS_NoCertSource(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"
	globalConfig.PKCS11Module = "" // Ensure no PKCS#11 module set

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "create", "no-cert@test.com",
			"--method", "mtls",
			"--cert-file", "",
		)
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for missing cert source, got %d", exitCode)
	}
}

func TestAdminCreate_MTLS_InvalidCertFile(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "create", "bad-cert@test.com",
			"--method", "mtls",
			"--cert-file", "/nonexistent/path/cert.pem",
		)
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid cert file, got %d", exitCode)
	}
}

func TestAdminCreate_MTLS_InvalidPEMContent(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	// Write a file with invalid PEM content
	badPemPath := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badPemPath, []byte("this is not a PEM file"), 0600); err != nil {
		t.Fatalf("failed to write bad PEM: %v", err)
	}

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "create", "bad-pem@test.com",
			"--method", "mtls",
			"--cert-file", badPemPath,
		)
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid PEM content, got %d", exitCode)
	}
}

func TestAdminCreate_MTLS_InvalidDERInPEM(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	// Write a valid PEM block with invalid DER content
	badDerPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not valid DER data"),
	})
	badDerPath := filepath.Join(t.TempDir(), "bad-der.pem")
	if err := os.WriteFile(badDerPath, badDerPEM, 0600); err != nil {
		t.Fatalf("failed to write bad DER PEM: %v", err)
	}

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "create", "bad-der@test.com",
			"--method", "mtls",
			"--cert-file", badDerPath,
		)
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid DER in PEM, got %d", exitCode)
	}
}

func TestAdminCreate_MTLS_PKCS11Error(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"
	globalConfig.PKCS11Module = "/usr/lib/libxkey11.so"
	globalConfig.PKCS11Slot = 2

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "create", "pkcs11@test.com",
			"--method", "mtls",
			"--cert-file", "",
		)
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for PKCS#11 error, got %d", exitCode)
	}
}

// ============================================================================
// loadCertFromFile unit tests
// ============================================================================

func TestLoadCertFromFile_Success(t *testing.T) {
	certPath, expectedCert := generateTestCert(t)

	cert, err := loadCertFromFile(certPath)
	if err != nil {
		t.Fatalf("loadCertFromFile failed: %v", err)
	}

	if cert.Subject.CommonName != expectedCert.Subject.CommonName {
		t.Errorf("CN mismatch: got %s, want %s",
			cert.Subject.CommonName, expectedCert.Subject.CommonName)
	}
}

func TestLoadCertFromFile_FileNotFound(t *testing.T) {
	_, err := loadCertFromFile("/nonexistent/cert.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !errors.Is(err, ErrCertFileRead) {
		t.Errorf("expected ErrCertFileRead, got: %v", err)
	}
}

func TestLoadCertFromFile_NoPEMBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(path, []byte("not pem data"), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := loadCertFromFile(path)
	if err == nil {
		t.Fatal("expected error for non-PEM data")
	}
	if !errors.Is(err, ErrCertFileParse) {
		t.Errorf("expected ErrCertFileParse, got: %v", err)
	}
}

func TestLoadCertFromFile_InvalidDER(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid DER"),
	})
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := loadCertFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
	if !errors.Is(err, ErrCertFileParse) {
		t.Errorf("expected ErrCertFileParse, got: %v", err)
	}
}

// ============================================================================
// loadEnrollmentCert unit tests
// ============================================================================

func TestLoadEnrollmentCert_CertFilePreferred(t *testing.T) {
	certPath, _ := generateTestCert(t)

	// Build a cobra command with the cert-file flag
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("cert-file", certPath, "")

	cfg := &Config{PKCS11Module: "/some/module.so"}

	cert, err := loadEnrollmentCert(cmd, cfg)
	if err != nil {
		t.Fatalf("loadEnrollmentCert failed: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestLoadEnrollmentCert_PKCS11Fallback(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("cert-file", "", "")

	cfg := &Config{PKCS11Module: "/usr/lib/test.so", PKCS11Slot: 3}

	_, err := loadEnrollmentCert(cmd, cfg)
	if err == nil {
		t.Fatal("expected error for PKCS#11 with invalid module path")
	}
	// The error should be wrapped from auth.NewPKCS11TLSConfig
	if !strings.Contains(err.Error(), "PKCS#11") {
		t.Errorf("expected PKCS#11-related error, got: %v", err)
	}
}

func TestLoadEnrollmentCert_NoCertSource(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("cert-file", "", "")

	cfg := &Config{}

	_, err := loadEnrollmentCert(cmd, cfg)
	if err == nil {
		t.Fatal("expected error for no cert source")
	}
	if !errors.Is(err, ErrNoCertificateSource) {
		t.Errorf("expected ErrNoCertificateSource, got: %v", err)
	}
}

// ============================================================================
// PKCS#11 persistent flag tests
// ============================================================================

func TestRootCmd_PKCS11Flags(t *testing.T) {
	flags := rootCmd.PersistentFlags()

	tests := []struct {
		name     string
		defValue string
	}{
		{"pkcs11-module", ""},
		{"pkcs11-slot", "0"},
		{"pkcs11-pin", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flag := flags.Lookup(tc.name)
			if flag == nil {
				t.Fatalf("expected persistent flag %q not found", tc.name)
			}
			if flag.DefValue != tc.defValue {
				t.Errorf("%s default = %v, want %v", tc.name, flag.DefValue, tc.defValue)
			}
		})
	}
}

// ============================================================================
// Config PKCS#11 field tests
// ============================================================================

func TestConfig_PKCS11Fields(t *testing.T) {
	cfg := NewConfig()
	if cfg.PKCS11Module != "" {
		t.Errorf("PKCS11Module should default to empty, got: %s", cfg.PKCS11Module)
	}
	if cfg.PKCS11Slot != 0 {
		t.Errorf("PKCS11Slot should default to 0, got: %d", cfg.PKCS11Slot)
	}
	if cfg.PKCS11PIN != "" {
		t.Errorf("PKCS11PIN should default to empty, got: %s", cfg.PKCS11PIN)
	}
	if cfg.AuthMethod != "" {
		t.Errorf("AuthMethod should default to empty, got: %s", cfg.AuthMethod)
	}
}

// ============================================================================
// Error type tests
// ============================================================================

func TestErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrUnsupportedAuthMethod,
		ErrNoCertificateSource,
		ErrCertFileRead,
		ErrCertFileParse,
	}

	for i := range errs {
		for j := range errs {
			if i != j && errors.Is(errs[i], errs[j]) {
				t.Errorf("errors should be distinct: %v and %v", errs[i], errs[j])
			}
		}
	}
}

// ============================================================================
// Map-based dispatch handler table test
// ============================================================================

func TestAdminCreateHandlers_HasExpectedMethods(t *testing.T) {
	expected := []string{"fido2", "mtls"}
	for _, method := range expected {
		if _, ok := adminCreateHandlers[method]; !ok {
			t.Errorf("expected handler for method %q in adminCreateHandlers", method)
		}
	}
}

func TestAdminCreateHandlers_UnknownMethodNotPresent(t *testing.T) {
	if _, ok := adminCreateHandlers["unknown"]; ok {
		t.Error("did not expect handler for 'unknown' method")
	}
}
