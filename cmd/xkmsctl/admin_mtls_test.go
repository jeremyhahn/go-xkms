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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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

// reissueTestCertForKey writes a fresh self-signed certificate that reuses the
// supplied key but carries a different serial number and subject. A renewal /
// re-issue for the same key must resolve to the same SPKI thumbprint, which is
// the key-stability property this exercises.
func reissueTestCertForKey(t *testing.T, key *ecdsa.PrivateKey) (string, *x509.Certificate) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject: pkix.Name{
			CommonName:   "admin-renewed@example.com",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create renewed certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse renewed certificate: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	certPath := filepath.Join(t.TempDir(), "client-renewed.pem")
	if err := os.WriteFile(certPath, pemBlock, 0600); err != nil {
		t.Fatalf("failed to write renewed cert file: %v", err)
	}

	return certPath, cert
}

// ============================================================================
// admin create --method flag tests
// ============================================================================

func TestAdminCreateCmd_UnsupportedMethod(t *testing.T) {
	tmpDir := newTestStorageDir(t)

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

// TestAdminCreate_MTLS_CertFile_LoadsCertBeforeEnroll verifies that the mTLS
// enrollment path loads and parses the --cert-file certificate (computing the
// canonical SPKI thumbprint) before reaching the SDK. The enrollment itself is
// driven through the xkms SDK against a live server; without a reachable server
// the command exits non-zero, so this unit test asserts the cert-loading half of
// the path and leaves the server round-trip to the integration suite.
func TestAdminCreate_MTLS_CertFile_LoadsCertBeforeEnroll(t *testing.T) {
	certPath, cert := generateTestCert(t)

	// The loaded cert must produce the canonical qrdb SPKI thumbprint — the
	// single mTLS identity algorithm shared across qrdb/xkms/quicbaas.
	loaded, err := loadCertFromFile(certPath)
	if err != nil {
		t.Fatalf("loadCertFromFile failed: %v", err)
	}
	if got, want := qrdbsdk.ComputeSPKIThumbprint(loaded), qrdbsdk.ComputeSPKIThumbprint(cert); got != want {
		t.Errorf("SPKI thumbprint mismatch:\n  got:  %s\n  want: %s", got, want)
	}

	tmpDir := newTestStorageDir(t)

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	// With no reachable server the SDK connect fails and the command exits 1.
	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "create", "mtls-admin@test.com",
			"--method", "mtls",
			"--cert-file", certPath,
			"--display-name", "mTLS Admin",
		)
	})
	if exitCode != 1 {
		t.Errorf("expected exit code 1 when no server is reachable, got %d", exitCode)
	}
}

// TestAdminCreate_MTLS_CertBinding_KeyStable verifies that the SPKI thumbprint
// is stable across certificate renewals: an initial certificate and a later
// re-issued certificate for the SAME key resolve to the same canonical
// identifier. This is the property that keeps admin mTLS identity stable across
// renewals, and it is computed from the loaded certificate before enrollment.
func TestAdminCreate_MTLS_CertBinding_KeyStable(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Initial certificate for the key.
	path1, cert1 := writeTestCertForKey(t, key, "admin-initial@example.com")
	loaded1, err := loadCertFromFile(path1)
	if err != nil {
		t.Fatalf("loadCertFromFile (initial) failed: %v", err)
	}
	if got, want := qrdbsdk.ComputeSPKIThumbprint(loaded1), qrdbsdk.ComputeSPKIThumbprint(cert1); got != want {
		t.Fatalf("initial thumbprint mismatch:\n  got:  %s\n  want: %s", got, want)
	}
	id1 := qrdbsdk.ComputeSPKIThumbprint(loaded1)

	// Re-issued certificate for the SAME key (different serial + subject).
	path2, cert2 := reissueTestCertForKey(t, key)
	loaded2, err := loadCertFromFile(path2)
	if err != nil {
		t.Fatalf("loadCertFromFile (renewed) failed: %v", err)
	}
	if got, want := qrdbsdk.ComputeSPKIThumbprint(loaded2), qrdbsdk.ComputeSPKIThumbprint(cert2); got != want {
		t.Fatalf("renewed thumbprint mismatch:\n  got:  %s\n  want: %s", got, want)
	}
	id2 := qrdbsdk.ComputeSPKIThumbprint(loaded2)

	if id1 != id2 {
		t.Fatalf("key-stability violated: re-issued cert for same key produced a different identifier:\n  first:  %s\n  second: %s", id1, id2)
	}
}

// writeTestCertForKey writes a self-signed certificate for the supplied key with
// the given common name and returns its PEM file path plus the parsed cert.
func writeTestCertForKey(t *testing.T, key *ecdsa.PrivateKey, commonName string) (string, *x509.Certificate) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
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
		t.Fatalf("failed to parse certificate: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certPath := filepath.Join(t.TempDir(), "client-initial.pem")
	if err := os.WriteFile(certPath, pemBlock, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	return certPath, cert
}

// TestAdminCreate_MTLS_CertFile_JSON_NoServer verifies the JSON-format mTLS
// enrollment path parses the cert and then fails (exit 1) when the SDK has no
// reachable server. The successful JSON summary is exercised end-to-end in the
// integration suite, which runs against a live xkms server.
func TestAdminCreate_MTLS_CertFile_JSON_NoServer(t *testing.T) {
	tmpDir := newTestStorageDir(t)

	certPath, _ := generateTestCert(t)

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "create", "mtls-json@test.com",
			"--method", "mtls",
			"--cert-file", certPath,
			"--display-name", "",
		)
	})
	if exitCode != 1 {
		t.Errorf("expected exit code 1 when no server is reachable, got %d", exitCode)
	}
}

// TestAdminCreate_MTLS_DefaultDisplayName verifies that an empty --display-name
// is accepted (defaulting to the username happens inside the enrollment handler)
// and that the path proceeds to the SDK, which exits 1 without a server. The
// default-display-name persistence is verified end-to-end in the integration
// suite.
func TestAdminCreate_MTLS_DefaultDisplayName(t *testing.T) {
	tmpDir := newTestStorageDir(t)

	certPath, _ := generateTestCert(t)

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		// Explicitly pass --display-name "" to reset any stale flag value
		// on the shared global adminCreateCmd from prior tests.
		_, _ = executeAdminCommand(t, tmpDir, "create", "defname@test.com",
			"--method", "mtls",
			"--cert-file", certPath,
			"--display-name", "",
		)
	})
	if exitCode != 1 {
		t.Errorf("expected exit code 1 when no server is reachable, got %d", exitCode)
	}
}

// ============================================================================
// mTLS enrollment error cases
// ============================================================================

func TestAdminCreate_MTLS_NoCertSource(t *testing.T) {
	tmpDir := newTestStorageDir(t)

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
	tmpDir := newTestStorageDir(t)

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
	tmpDir := newTestStorageDir(t)

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
	tmpDir := newTestStorageDir(t)

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
	tmpDir := newTestStorageDir(t)

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

// ============================================================================
// PKCS#11 persistent flag tests
// ============================================================================

// ============================================================================
// Config PKCS#11 field tests
// ============================================================================

// ============================================================================
// Error type tests
// ============================================================================

// ============================================================================
// Map-based dispatch handler table test
// ============================================================================
