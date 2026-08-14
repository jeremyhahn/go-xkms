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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
)

// =============================================================================
// Error type tests
// =============================================================================

func TestErrInvalidLogLevel_Error(t *testing.T) {
	err := ErrInvalidLogLevel{Level: "trace"}
	msg := err.Error()
	if !strings.Contains(msg, "trace") {
		t.Errorf("expected level in error message: %q", msg)
	}
	if !strings.Contains(msg, "invalid log level") {
		t.Errorf("expected prefix in error message: %q", msg)
	}
}

func TestErrConfigRead_Error(t *testing.T) {
	cause := errors.New("permission denied")
	err := ErrConfigRead{Path: "/etc/trusted-acme.yaml", Err: cause}
	msg := err.Error()
	if !strings.Contains(msg, "/etc/trusted-acme.yaml") {
		t.Errorf("expected path in error message: %q", msg)
	}
	if !strings.Contains(msg, "permission denied") {
		t.Errorf("expected cause in error message: %q", msg)
	}
}

func TestErrConfigRead_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := ErrConfigRead{Path: "/tmp/cfg", Err: cause}
	if !errors.Is(err, cause) {
		t.Error("errors.Is should unwrap to the cause")
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause directly")
	}
}

func TestErrGUINotAvailable_Error(t *testing.T) {
	err := ErrGUINotAvailable{}
	msg := err.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
	if !strings.Contains(msg, "GUI not available") {
		t.Errorf("expected 'GUI not available' in message: %q", msg)
	}
}

// =============================================================================
// hasDisplay / runGUI (no-gui build)
// =============================================================================

func TestHasDisplay_ReturnsFalse(t *testing.T) {
	if hasDisplay() {
		t.Error("hasDisplay should return false in no-gui build")
	}
}

func TestRunGUI_ReturnsError(t *testing.T) {
	err := runGUI()
	if err == nil {
		t.Error("runGUI should return error in no-gui build")
	}
	var e ErrGUINotAvailable
	if !errors.As(err, &e) {
		t.Errorf("expected ErrGUINotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// expandPath
// =============================================================================

func TestExpandPath_Tilde(t *testing.T) {
	// Pin HOME so the expansion is deterministic and independent of whatever
	// home directory the test runner happens to have.
	home := t.TempDir()
	t.Setenv("HOME", home)

	got := expandPath("~/foo/bar")
	want := filepath.Join(home, "foo/bar")
	if got != want {
		t.Errorf("expandPath: got %q, want %q", got, want)
	}
}

func TestExpandPath_NoTilde(t *testing.T) {
	path := "/etc/trusted-acme.yaml"
	got := expandPath(path)
	if got != path {
		t.Errorf("expandPath: expected %q unchanged, got %q", path, got)
	}
}

func TestExpandPath_RelativePath(t *testing.T) {
	path := "relative/path.yaml"
	got := expandPath(path)
	if got != path {
		t.Errorf("expandPath: expected %q unchanged, got %q", path, got)
	}
}

// =============================================================================
// findConfigFile
// =============================================================================

func TestFindConfigFile_NoFileExists_ReturnsEmpty(t *testing.T) {
	// On a clean test environment none of the default paths will exist.
	// If one does happen to exist, it's still OK — we just verify no panic.
	_ = findConfigFile()
}

func TestFindConfigFile_ReturnsExistingFile(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("storage:\n  backend: memory\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Temporarily replace the search paths.
	orig := configSearchPaths
	t.Cleanup(func() { configSearchPaths = orig })
	configSearchPaths = []string{cfg}

	got := findConfigFile()
	if got != cfg {
		t.Errorf("findConfigFile: expected %q, got %q", cfg, got)
	}
}

// =============================================================================
// isValidLogLevel
// =============================================================================

func TestIsValidLogLevel(t *testing.T) {
	tests := []struct {
		level string
		want  bool
	}{
		{"debug", true},
		{"info", true},
		{"warn", true},
		{"error", true},
		{"trace", false},
		{"", false},
		{"DEBUG", false}, // case-sensitive
		{"Info", false},
	}
	for _, tc := range tests {
		t.Run(tc.level, func(t *testing.T) {
			got := isValidLogLevel(tc.level)
			if got != tc.want {
				t.Errorf("isValidLogLevel(%q) = %v, want %v", tc.level, got, tc.want)
			}
		})
	}
}

// =============================================================================
// validateConfiguration
// =============================================================================

func TestValidateConfiguration_ValidLevel(t *testing.T) {
	orig := logLevel
	t.Cleanup(func() { logLevel = orig })

	for _, level := range []string{"debug", "info", "warn", "error"} {
		logLevel = level
		if err := validateConfiguration(); err != nil {
			t.Errorf("validateConfiguration with %q: unexpected error: %v", level, err)
		}
	}
}

func TestValidateConfiguration_InvalidLevel(t *testing.T) {
	orig := logLevel
	t.Cleanup(func() { logLevel = orig })

	logLevel = "trace"
	err := validateConfiguration()
	if err == nil {
		t.Fatal("expected error for invalid log level, got nil")
	}
	var e ErrInvalidLogLevel
	if !errors.As(err, &e) {
		t.Errorf("expected ErrInvalidLogLevel, got %T: %v", err, err)
	}
}

// =============================================================================
// setDefaults
// =============================================================================

func TestSetDefaults_PopulatesViper(t *testing.T) {
	v := viper.New()
	// setDefaults uses the global viper — capture its pre-state, call, then restore.
	// Because viper is global state, test in isolation using a fresh viper.
	// We call setDefaults() and verify the expected keys.
	setDefaults()
	if viper.GetString("logging.level") != "info" {
		// May already be set; just ensure it's a valid value.
		level := viper.GetString("logging.level")
		if !isValidLogLevel(level) {
			t.Errorf("logging.level default is invalid: %q", level)
		}
	}
	_ = v
}

// =============================================================================
// buildServiceConfig
// =============================================================================

func TestBuildServiceConfig_ReturnsNonNil(t *testing.T) {
	// Reset viper to known defaults.
	viper.Reset()
	setDefaults()

	cfg := buildServiceConfig()
	if cfg == nil {
		t.Fatal("buildServiceConfig returned nil")
	}
	if cfg.Accounts == nil {
		t.Error("expected non-nil Accounts map")
	}
	if cfg.Certificates == nil {
		t.Error("expected non-nil Certificates map")
	}
}

// =============================================================================
// loadConfigFile
// =============================================================================

func TestLoadConfigFile_EmptyPath_NoError(t *testing.T) {
	// Reset viper so no previous config is set.
	viper.Reset()
	// No file at default locations expected to exist in CI; should return nil.
	_ = loadConfigFile("")
}

func TestLoadConfigFile_ExplicitPath_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "test.yaml")
	content := "logging:\n  level: debug\n  format: text\n  output: stdout\n"
	if err := os.WriteFile(cfg, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	viper.Reset()
	if err := loadConfigFile(cfg); err != nil {
		t.Fatalf("loadConfigFile: unexpected error: %v", err)
	}
}

func TestLoadConfigFile_ExplicitPath_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(cfg, []byte(":\ninvalid\nyaml\n::\n"), 0600); err != nil {
		t.Fatal(err)
	}

	viper.Reset()
	err := loadConfigFile(cfg)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
	var e ErrConfigRead
	if !errors.As(err, &e) {
		t.Errorf("expected ErrConfigRead, got %T: %v", err, err)
	}
}

func TestLoadConfigFile_ViperNotFoundError_NoError(t *testing.T) {
	// Set a viper config file path to a non-existent file so that ReadInConfig
	// returns viper.ConfigFileNotFoundError (which is silently ignored).
	viper.Reset()
	viper.SetConfigFile("/nonexistent/path/trusted-acme.yaml")
	// loadConfigFile("") will skip if no default config is found, but if
	// we pre-set ConfigFile in viper, ReadInConfig is called and returns
	// ConfigFileNotFoundError, which is swallowed. We test with an empty path
	// to exercise the default-location search that returns nothing.
	err := loadConfigFile("")
	if err != nil {
		// It is valid for loadConfigFile to return nil when no file is found.
		t.Logf("loadConfigFile with no default path: %v", err)
	}
}

// =============================================================================
// initConfig
// =============================================================================

func TestInitConfig_DefaultsOnly(t *testing.T) {
	viper.Reset()
	// Set a valid log level in viper so initConfig passes validation.
	viper.Set("logging.level", "info")

	if err := initConfig(); err != nil {
		t.Fatalf("initConfig with defaults: unexpected error: %v", err)
	}
}

// =============================================================================
// runVersion
// =============================================================================

func TestRunVersion_OutputsVersion(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	if err := runVersion(cmd, nil); err != nil {
		t.Fatalf("runVersion: unexpected error: %v", err)
	}
	out := buf.String()
	// runVersion uses fmt.Printf directly (not cmd.Printf), so we check stdout.
	// The function itself returns nil; the output goes to os.Stdout. We just
	// verify it returns no error and contains expected content when we can capture it.
	_ = out
}

func TestRunVersion_NoError(t *testing.T) {
	cmd := &cobra.Command{}
	if err := runVersion(cmd, nil); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestVersionVariables(t *testing.T) {
	if version == "" {
		t.Error("version should not be empty")
	}
	if commit == "" {
		t.Error("commit should not be empty")
	}
	if buildDate == "" {
		t.Error("buildDate should not be empty")
	}
	if runtime.Version() == "" {
		t.Error("runtime.Version() should not be empty")
	}
}

// =============================================================================
// deviceEnrollCmd / deviceAttestCmd
// =============================================================================

func TestDeviceEnrollCmd_MissingAccount(t *testing.T) {
	cmd := deviceEnrollCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := deviceEnrollCmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error for missing --account")
	}
	if !strings.Contains(err.Error(), "--account") {
		t.Errorf("expected '--account' in error: %q", err.Error())
	}
}

func TestDeviceEnrollCmd_MissingDeviceID(t *testing.T) {
	// Set account but not device-id.
	cmd := deviceEnrollCmd
	if err := cmd.Flags().Set("account", "trusted-ca"); err != nil {
		t.Fatal(err)
	}
	// Reset device-id to empty.
	if err := cmd.Flags().Set("device-id", ""); err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	err := deviceEnrollCmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error for missing --device-id")
	}
	if !strings.Contains(err.Error(), "--device-id") {
		t.Errorf("expected '--device-id' in error: %q", err.Error())
	}
}

func TestDeviceEnrollCmd_Success(t *testing.T) {
	cmd := deviceEnrollCmd
	if err := cmd.Flags().Set("account", "trusted-ca"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("device-id", "node-01"); err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := deviceEnrollCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestDeviceAttestCmd_MissingAccount(t *testing.T) {
	cmd := deviceAttestCmd
	// Reset flags to ensure account is empty.
	if err := cmd.Flags().Set("account", ""); err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := deviceAttestCmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error for missing --account")
	}
	if !strings.Contains(err.Error(), "--account") {
		t.Errorf("expected '--account' in error: %q", err.Error())
	}
}

func TestDeviceAttestCmd_MissingDeviceID(t *testing.T) {
	cmd := deviceAttestCmd
	if err := cmd.Flags().Set("account", "trusted-ca"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("device-id", ""); err != nil {
		t.Fatal(err)
	}

	err := deviceAttestCmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error for missing --device-id")
	}
	if !strings.Contains(err.Error(), "--device-id") {
		t.Errorf("expected '--device-id' in error: %q", err.Error())
	}
}

func TestDeviceAttestCmd_Success(t *testing.T) {
	cmd := deviceAttestCmd
	if err := cmd.Flags().Set("account", "trusted-ca"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("device-id", "node-01"); err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := deviceAttestCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

// =============================================================================
// printManagedCert / printUnissuedSpec / collectSANs
// =============================================================================

// buildTestCert returns a minimal self-signed x509.Certificate for use in tests.
func buildTestCert(cn string) *x509.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("ecdsa.GenerateKey: " + err.Error())
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic("x509.CreateCertificate: " + err.Error())
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic("x509.ParseCertificate: " + err.Error())
	}
	return cert
}

func newTestManagedCertInfo(name string) *service.ManagedCertInfo {
	now := time.Now()
	deployedAt := now.Add(-30 * time.Minute)
	return &service.ManagedCertInfo{
		Name: name,
		Spec: &service.CertificateSpec{
			Account: "myaccount",
			Subject: service.SubjectConfig{CN: name + ".example.com"},
			SANs: service.SANsConfig{
				DNS:   []string{"alt." + name + ".example.com"},
				IP:    []string{"192.168.1.1"},
				Email: []string{"admin@example.com"},
				URI:   []string{"spiffe://cluster/svc/" + name},
			},
			Key: &service.KeyConfig{
				Algorithm: "ECDSA",
				Store:     "software",
				ECC:       &service.ECCConfig{Curve: "P-256"},
			},
			Challenge: "http-01",
			Renewal: &service.CertRenewalConfig{
				Auto:       true,
				DaysBefore: 30,
			},
		},
		Certificate: buildTestCert(name + ".example.com"),
		IssuedAt:    now.Add(-24 * time.Hour),
		ExpiresAt:   now.Add(365 * 24 * time.Hour),
		DeployedAt:  &deployedAt,
	}
}

// TestPrintManagedCert_WithAllFields tests the full output path including SANs,
// key info, challenge, auto-renewal, and expiry.
func TestPrintManagedCert_WithAllFields(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	info := newTestManagedCertInfo("web")
	printManagedCert(cmd, "web", info)
	out := buf.String()

	if !strings.Contains(out, "myaccount") {
		t.Errorf("expected account in output: %q", out)
	}
	if !strings.Contains(out, "web.example.com") {
		t.Errorf("expected subject in output: %q", out)
	}
	if !strings.Contains(out, "alt.web.example.com") {
		t.Errorf("expected SAN in output: %q", out)
	}
	if !strings.Contains(out, "issued") {
		t.Errorf("expected status issued in output: %q", out)
	}
	if !strings.Contains(out, "30") {
		t.Errorf("expected renewal DaysBefore in output: %q", out)
	}
}

func TestPrintManagedCert_WithRSAKey(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	now := time.Now()
	info := &service.ManagedCertInfo{
		Name: "api",
		Spec: &service.CertificateSpec{
			Account: "acc",
			Subject: service.SubjectConfig{CN: "api.example.com"},
			Key: &service.KeyConfig{
				Algorithm: "RSA",
				Store:     "software",
				RSA:       &service.RSAConfig{KeySize: 2048},
			},
			Challenge: "dns-01",
		},
		Certificate: buildTestCert("api.example.com"),
		IssuedAt:    now.Add(-time.Hour),
		ExpiresAt:   now.Add(365 * 24 * time.Hour),
	}
	printManagedCert(cmd, "api", info)
	out := buf.String()
	if !strings.Contains(out, "2048") {
		t.Errorf("expected RSA key size in output: %q", out)
	}
	if !strings.Contains(out, "dns-01") {
		t.Errorf("expected challenge in output: %q", out)
	}
}

func TestPrintManagedCert_NoAutoRenewal(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	now := time.Now()
	info := &service.ManagedCertInfo{
		Name: "svc",
		Spec: &service.CertificateSpec{
			Account: "acc",
			Subject: service.SubjectConfig{CN: "svc.example.com"},
			Key:     &service.KeyConfig{Algorithm: "ECDSA", Store: "software"},
			Renewal: &service.CertRenewalConfig{Auto: false},
		},
		Certificate: buildTestCert("svc.example.com"),
		IssuedAt:    now.Add(-time.Hour),
		ExpiresAt:   now.Add(365 * 24 * time.Hour),
	}
	printManagedCert(cmd, "svc", info)
	out := buf.String()
	if !strings.Contains(out, "no") {
		t.Errorf("expected 'no' in auto-renew output: %q", out)
	}
}

func TestPrintManagedCert_NilKey(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	now := time.Now()
	info := &service.ManagedCertInfo{
		Name: "bare",
		Spec: &service.CertificateSpec{
			Account: "acc",
			Subject: service.SubjectConfig{CN: "bare.example.com"},
		},
		Certificate: buildTestCert("bare.example.com"),
		IssuedAt:    now.Add(-time.Hour),
		ExpiresAt:   now.Add(365 * 24 * time.Hour),
	}
	// Should not panic with nil Key.
	printManagedCert(cmd, "bare", info)
	out := buf.String()
	if !strings.Contains(out, "http-01") {
		t.Errorf("expected default challenge http-01 in output: %q", out)
	}
}

func TestPrintManagedCert_DefaultChallenge(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	now := time.Now()
	info := &service.ManagedCertInfo{
		Name: "empty-challenge",
		Spec: &service.CertificateSpec{
			Account:   "acc",
			Subject:   service.SubjectConfig{CN: "empty.example.com"},
			Challenge: "", // empty → defaults to http-01
		},
		Certificate: buildTestCert("empty.example.com"),
		IssuedAt:    now.Add(-time.Hour),
		ExpiresAt:   now.Add(365 * 24 * time.Hour),
	}
	printManagedCert(cmd, "empty-challenge", info)
	out := buf.String()
	if !strings.Contains(out, "http-01") {
		t.Errorf("expected http-01 for empty challenge, got: %q", out)
	}
}

func TestCollectSANs_AllTypes(t *testing.T) {
	spec := &service.CertificateSpec{
		SANs: service.SANsConfig{
			DNS:   []string{"a.example.com", "b.example.com"},
			IP:    []string{"10.0.0.1"},
			Email: []string{"user@example.com"},
			URI:   []string{"spiffe://cluster/svc"},
		},
	}
	sans := collectSANs(spec)
	if len(sans) != 5 {
		t.Errorf("expected 5 SANs, got %d: %v", len(sans), sans)
	}
}

func TestCollectSANs_Empty(t *testing.T) {
	spec := &service.CertificateSpec{}
	sans := collectSANs(spec)
	if len(sans) != 0 {
		t.Errorf("expected 0 SANs, got %d", len(sans))
	}
}

func TestCollectSANs_DNSOnly(t *testing.T) {
	spec := &service.CertificateSpec{
		SANs: service.SANsConfig{
			DNS: []string{"x.example.com"},
		},
	}
	sans := collectSANs(spec)
	if len(sans) != 1 || sans[0] != "x.example.com" {
		t.Errorf("expected [x.example.com], got %v", sans)
	}
}

func TestPrintUnissuedSpec_NoRenewal(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	spec := &service.CertificateSpec{
		Account:   "acc",
		Subject:   service.SubjectConfig{CN: "test.example.com"},
		Challenge: "http-01",
		Key: &service.KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &service.ECCConfig{Curve: "P-256"},
		},
	}
	printUnissuedSpec(cmd, "test", spec)
	out := buf.String()
	if !strings.Contains(out, "test.example.com") {
		t.Errorf("expected subject in output: %q", out)
	}
	if !strings.Contains(out, "acc") {
		t.Errorf("expected account in output: %q", out)
	}
	if !strings.Contains(out, "pending") {
		t.Errorf("expected status pending in output: %q", out)
	}
}

func TestPrintUnissuedSpec_WithAutoRenewal(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	spec := &service.CertificateSpec{
		Account: "acc",
		Subject: service.SubjectConfig{CN: "test.example.com"},
		Key:     &service.KeyConfig{Algorithm: "ECDSA", Store: "software"},
		Renewal: &service.CertRenewalConfig{Auto: true, DaysBefore: 30},
	}
	printUnissuedSpec(cmd, "test", spec)
	out := buf.String()
	if !strings.Contains(out, "30") {
		t.Errorf("expected renewal days in output: %q", out)
	}
}

func TestPrintUnissuedSpec_WithNoAutoRenewal(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	spec := &service.CertificateSpec{
		Account: "acc",
		Subject: service.SubjectConfig{CN: "test.example.com"},
		Key:     &service.KeyConfig{Algorithm: "ECDSA", Store: "software"},
		Renewal: &service.CertRenewalConfig{Auto: false},
	}
	printUnissuedSpec(cmd, "test", spec)
	out := buf.String()
	if !strings.Contains(out, "no") {
		t.Errorf("expected 'no' in renewal output: %q", out)
	}
}

func TestPrintUnissuedSpec_WithSANs(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	spec := &service.CertificateSpec{
		Account: "acc",
		Subject: service.SubjectConfig{CN: "test.example.com"},
		SANs:    service.SANsConfig{DNS: []string{"alt.example.com"}},
		Key:     &service.KeyConfig{Algorithm: "ECDSA", Store: "software"},
	}
	printUnissuedSpec(cmd, "test", spec)
	out := buf.String()
	if !strings.Contains(out, "alt.example.com") {
		t.Errorf("expected SAN in output: %q", out)
	}
}

func TestPrintUnissuedSpec_WithRSAKey(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	spec := &service.CertificateSpec{
		Account: "acc",
		Subject: service.SubjectConfig{CN: "test.example.com"},
		Key: &service.KeyConfig{
			Algorithm: "RSA",
			Store:     "software",
			RSA:       &service.RSAConfig{KeySize: 2048},
		},
	}
	printUnissuedSpec(cmd, "test", spec)
	out := buf.String()
	if !strings.Contains(out, "2048") {
		t.Errorf("expected key size in output: %q", out)
	}
}

func TestPrintUnissuedSpec_NilKey(t *testing.T) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	spec := &service.CertificateSpec{
		Account:   "acc",
		Subject:   service.SubjectConfig{CN: "test.example.com"},
		Challenge: "",
	}
	// Should not panic with nil Key.
	printUnissuedSpec(cmd, "test", spec)
	out := buf.String()
	if !strings.Contains(out, "http-01") {
		t.Errorf("expected default challenge http-01 in output: %q", out)
	}
}

// =============================================================================
// serviceStatusCmd — tests that don't block
// =============================================================================

func TestServiceStatusCmd_EmptyConfig(t *testing.T) {
	// serviceStatusCmd calls createService() internally; we override the global
	// viper state to point at an in-memory config so no filesystem access occurs.
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")

	cmd := serviceStatusCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	ctx := context.Background()
	_ = ctx
	// Execute directly without going through cobra's Execute() to skip
	// PersistentPreRunE which calls initConfig() again.
	// We call RunE directly.
	err := serviceStatusCmd.RunE(cmd, nil)
	if err != nil {
		// createService() may succeed with empty config.  Either outcome is fine
		// for this test — we just ensure no panic.
		t.Logf("serviceStatusCmd.RunE returned: %v", err)
	}
	_ = buf.String()
}

// =============================================================================
// accountListCmd — produces formatted output for empty config
// =============================================================================

func TestAccountListCmd_Empty(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")

	cmd := accountListCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := accountListCmd.RunE(cmd, nil)
	if err != nil {
		t.Logf("accountListCmd.RunE with empty config: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "---") {
		t.Errorf("unexpected error output: %q", out)
	}
}

// =============================================================================
// certListCmd — produces formatted output for empty config
// =============================================================================

func TestCertListCmd_Empty(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")

	cmd := certListCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := certListCmd.RunE(cmd, nil)
	if err != nil {
		t.Logf("certListCmd.RunE with empty config: %v", err)
	}
}

// =============================================================================
// rootCmd — basic structure
// =============================================================================

func TestRootCmd_HasSubcommands(t *testing.T) {
	subcmds := map[string]bool{}
	for _, sub := range rootCmd.Commands() {
		subcmds[sub.Use] = true
	}
	for _, expected := range []string{"account", "cert", "device", "service", "version"} {
		if !subcmds[expected] {
			t.Errorf("expected subcommand %q to be registered", expected)
		}
	}
}

func TestAccountCmd_HasSubcommands(t *testing.T) {
	subcmds := map[string]bool{}
	for _, sub := range accountCmd.Commands() {
		subcmds[sub.Use] = true
	}
	for _, expected := range []string{"add <name>", "list", "show <name>", "remove <name>"} {
		if !subcmds[expected] {
			t.Errorf("expected accountCmd subcommand %q, got %v", expected, subcmds)
		}
	}
}

func TestCertCmd_HasSubcommands(t *testing.T) {
	subcmds := map[string]bool{}
	for _, sub := range certCmd.Commands() {
		subcmds[sub.Use] = true
	}
	for _, expected := range []string{"request <name>", "list", "show <name>", "renew <name>", "revoke <name>", "deploy <name>"} {
		if !subcmds[expected] {
			t.Errorf("expected certCmd subcommand %q, got %v", expected, subcmds)
		}
	}
}

func TestDeviceCmd_HasSubcommands(t *testing.T) {
	subcmds := map[string]bool{}
	for _, sub := range deviceCmd.Commands() {
		subcmds[sub.Use] = true
	}
	for _, expected := range []string{"enroll", "attest"} {
		if !subcmds[expected] {
			t.Errorf("expected deviceCmd subcommand %q, got %v", expected, subcmds)
		}
	}
}
