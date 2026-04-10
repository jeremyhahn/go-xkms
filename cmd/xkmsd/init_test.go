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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// generateTestCSR creates a PEM-encoded ECDSA P-256 CSR for testing.
func generateTestCSR(t *testing.T, cn string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
}

// writeTestCSR writes a PEM-encoded CSR to a temporary file.
func writeTestCSR(t *testing.T, dir, filename string, pemData []byte) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatalf("write CSR file: %v", err)
	}
	return path
}

func TestParseOfficerFlag_ValidFormat(t *testing.T) {
	username, csrPath, err := parseOfficerFlag("admin1@example.com:/path/to/admin1.csr")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "admin1@example.com" {
		t.Errorf("expected username admin1@example.com, got %q", username)
	}
	if csrPath != "/path/to/admin1.csr" {
		t.Errorf("expected CSR path /path/to/admin1.csr, got %q", csrPath)
	}
}

func TestParseOfficerFlag_MissingColon(t *testing.T) {
	_, _, err := parseOfficerFlag("admin1-no-colon")
	if err == nil {
		t.Fatal("expected error for missing colon")
	}
	if !errors.Is(err, ErrInvalidOfficerFormat) {
		t.Errorf("expected ErrInvalidOfficerFormat, got %v", err)
	}
}

func TestParseOfficerFlag_EmptyUsername(t *testing.T) {
	_, _, err := parseOfficerFlag(":/path/to/csr.pem")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
	if !errors.Is(err, ErrEmptyOfficerUsername) {
		t.Errorf("expected ErrEmptyOfficerUsername, got %v", err)
	}
}

func TestParseOfficerFlag_EmptyCSRPath(t *testing.T) {
	_, _, err := parseOfficerFlag("admin1:")
	if err == nil {
		t.Fatal("expected error for empty CSR path")
	}
	if !errors.Is(err, ErrEmptyCSRPath) {
		t.Errorf("expected ErrEmptyCSRPath, got %v", err)
	}
}

func TestParseOfficerFlag_WhitespaceHandling(t *testing.T) {
	username, csrPath, err := parseOfficerFlag("  admin1  :  /path/to/csr.pem  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "admin1" {
		t.Errorf("expected trimmed username admin1, got %q", username)
	}
	if csrPath != "/path/to/csr.pem" {
		t.Errorf("expected trimmed CSR path /path/to/csr.pem, got %q", csrPath)
	}
}

func TestReadAndValidateCSR_ValidCSR(t *testing.T) {
	dir := t.TempDir()
	csrPEM := generateTestCSR(t, "test-officer")
	csrPath := writeTestCSR(t, dir, "test.csr", csrPEM)

	result, err := readAndValidateCSR(csrPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected non-empty PEM data")
	}

	// Verify the returned PEM is parseable.
	block, _ := pem.Decode(result)
	if block == nil {
		t.Fatal("returned data is not valid PEM")
	}
	_, err = x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("returned PEM does not contain valid CSR: %v", err)
	}
}

func TestReadAndValidateCSR_FileNotFound(t *testing.T) {
	_, err := readAndValidateCSR("/nonexistent/path/to/csr.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !errors.Is(err, ErrCSRFileNotFound) {
		t.Errorf("expected ErrCSRFileNotFound, got %v", err)
	}
}

func TestReadAndValidateCSR_Directory(t *testing.T) {
	dir := t.TempDir()
	_, err := readAndValidateCSR(dir)
	if err == nil {
		t.Fatal("expected error for directory path")
	}
	if !errors.Is(err, ErrCSRReadFailed) {
		t.Errorf("expected ErrCSRReadFailed, got %v", err)
	}
}

func TestReadAndValidateCSR_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.csr")
	if err := os.WriteFile(path, []byte("not valid PEM data"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := readAndValidateCSR(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
	if !errors.Is(err, ErrCSRDecodeFailed) {
		t.Errorf("expected ErrCSRDecodeFailed, got %v", err)
	}
}

func TestReadAndValidateCSR_InvalidDER(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.csr")

	// Write valid PEM with garbage DER inside.
	fakePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: []byte("not a real DER certificate request"),
	})
	if err := os.WriteFile(path, fakePEM, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := readAndValidateCSR(path)
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
	if !errors.Is(err, ErrCSRParseFailed) {
		t.Errorf("expected ErrCSRParseFailed, got %v", err)
	}
}

func TestBuildOfficerConfigs_ValidOfficers(t *testing.T) {
	dir := t.TempDir()
	csr1 := generateTestCSR(t, "officer1")
	csr2 := generateTestCSR(t, "officer2")
	path1 := writeTestCSR(t, dir, "officer1.csr", csr1)
	path2 := writeTestCSR(t, dir, "officer2.csr", csr2)

	flags := []string{
		"officer1:" + path1,
		"officer2:" + path2,
	}

	officers, err := buildOfficerConfigs(flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(officers) != 2 {
		t.Fatalf("expected 2 officers, got %d", len(officers))
	}
	if officers[0].Username != "officer1" {
		t.Errorf("expected officer1, got %q", officers[0].Username)
	}
	if officers[1].Username != "officer2" {
		t.Errorf("expected officer2, got %q", officers[1].Username)
	}
	if len(officers[0].CSRPEM) == 0 {
		t.Error("officer1 CSRPEM should not be empty")
	}
	if len(officers[1].CSRPEM) == 0 {
		t.Error("officer2 CSRPEM should not be empty")
	}
}

func TestBuildOfficerConfigs_InvalidFormat(t *testing.T) {
	_, err := buildOfficerConfigs([]string{"no-colon-here"})
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !errors.Is(err, ErrInvalidOfficerFormat) {
		t.Errorf("expected ErrInvalidOfficerFormat, got %v", err)
	}
}

func TestBuildOfficerConfigs_CSRNotFound(t *testing.T) {
	_, err := buildOfficerConfigs([]string{"admin:/nonexistent/csr.pem"})
	if err == nil {
		t.Fatal("expected error for nonexistent CSR")
	}
	if !errors.Is(err, ErrCSRFileNotFound) {
		t.Errorf("expected ErrCSRFileNotFound, got %v", err)
	}
}

func TestValidateInitFlags_MissingSOPin(t *testing.T) {
	flags := &initFlags{
		userPin: "user-pin-value",
	}
	err := validateInitFlags(flags)
	if err == nil {
		t.Fatal("expected error for missing SO PIN")
	}
	if !errors.Is(err, ErrMissingSOPin) {
		t.Errorf("expected ErrMissingSOPin, got %v", err)
	}
}

func TestValidateInitFlags_MissingUserPin(t *testing.T) {
	flags := &initFlags{
		soPin: "so-pin-value",
	}
	err := validateInitFlags(flags)
	if err == nil {
		t.Fatal("expected error for missing User PIN")
	}
	if !errors.Is(err, ErrMissingUserPin) {
		t.Errorf("expected ErrMissingUserPin, got %v", err)
	}
}

func TestValidateInitFlags_ValidSingleAdmin(t *testing.T) {
	flags := &initFlags{
		soPin:   "so-pin-value",
		userPin: "user-pin-value",
	}
	if err := validateInitFlags(flags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateInitFlags_ThresholdWithoutOfficers(t *testing.T) {
	flags := &initFlags{
		soPin:     "so-pin-value",
		userPin:   "user-pin-value",
		threshold: 2,
	}
	err := validateInitFlags(flags)
	if err == nil {
		t.Fatal("expected error for threshold without officers")
	}
	if !errors.Is(err, ErrThresholdRequiresOfficers) {
		t.Errorf("expected ErrThresholdRequiresOfficers, got %v", err)
	}
}

func TestValidateInitFlags_ThresholdExceedsOfficers(t *testing.T) {
	flags := &initFlags{
		soPin:     "so-pin-value",
		userPin:   "user-pin-value",
		threshold: 3,
		officers:  stringSlice{"admin1:/path/csr1", "admin2:/path/csr2"},
	}
	err := validateInitFlags(flags)
	if err == nil {
		t.Fatal("expected error for threshold exceeding officers")
	}
	if !errors.Is(err, ErrThresholdExceedsOfficers) {
		t.Errorf("expected ErrThresholdExceedsOfficers, got %v", err)
	}
}

func TestValidateInitFlags_ValidMofN(t *testing.T) {
	flags := &initFlags{
		soPin:     "so-pin-value",
		userPin:   "user-pin-value",
		threshold: 2,
		officers:  stringSlice{"admin1:/path/csr1", "admin2:/path/csr2", "admin3:/path/csr3"},
	}
	if err := validateInitFlags(flags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseInitFlags_Defaults(t *testing.T) {
	flags, err := parseInitFlags([]string{
		"--so-pin", "test-so-pin",
		"--user-pin", "test-user-pin",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.soPin != "test-so-pin" {
		t.Errorf("expected so-pin test-so-pin, got %q", flags.soPin)
	}
	if flags.userPin != "test-user-pin" {
		t.Errorf("expected user-pin test-user-pin, got %q", flags.userPin)
	}
	if flags.configPath != "/etc/xkms/xkmsd.yaml" {
		t.Errorf("expected default config path, got %q", flags.configPath)
	}
	if flags.threshold != 0 {
		t.Errorf("expected default threshold 0, got %d", flags.threshold)
	}
	if flags.credentialStrategy != "" {
		t.Errorf("expected empty credential strategy, got %q", flags.credentialStrategy)
	}
}

func TestParseInitFlags_AllFlags(t *testing.T) {
	dir := t.TempDir()
	csrPEM := generateTestCSR(t, "admin1")
	csrPath := writeTestCSR(t, dir, "admin1.csr", csrPEM)

	flags, err := parseInitFlags([]string{
		"--config", "/custom/config.yaml",
		"--so-pin", "my-so-pin",
		"--user-pin", "my-user-pin",
		"--threshold", "2",
		"--so", "admin1:" + csrPath,
		"--credential-strategy", "barrier",
		"--data-dir", "/custom/data",
		"--hostname", "xkms.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.configPath != "/custom/config.yaml" {
		t.Errorf("expected config /custom/config.yaml, got %q", flags.configPath)
	}
	if flags.soPin != "my-so-pin" {
		t.Errorf("expected so-pin my-so-pin, got %q", flags.soPin)
	}
	if flags.userPin != "my-user-pin" {
		t.Errorf("expected user-pin my-user-pin, got %q", flags.userPin)
	}
	if flags.threshold != 2 {
		t.Errorf("expected threshold 2, got %d", flags.threshold)
	}
	if len(flags.officers) != 1 {
		t.Fatalf("expected 1 officer, got %d", len(flags.officers))
	}
	if flags.officers[0] != "admin1:"+csrPath {
		t.Errorf("expected officer admin1:%s, got %q", csrPath, flags.officers[0])
	}
	if flags.credentialStrategy != "barrier" {
		t.Errorf("expected credential-strategy barrier, got %q", flags.credentialStrategy)
	}
	if flags.dataDir != "/custom/data" {
		t.Errorf("expected data-dir /custom/data, got %q", flags.dataDir)
	}
	if flags.hostname != "xkms.example.com" {
		t.Errorf("expected hostname xkms.example.com, got %q", flags.hostname)
	}
}

func TestParseInitFlags_RepeatableSOFlag(t *testing.T) {
	flags, err := parseInitFlags([]string{
		"--so-pin", "pin",
		"--user-pin", "pin",
		"--so", "admin1:/path/csr1",
		"--so", "admin2:/path/csr2",
		"--so", "admin3:/path/csr3",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(flags.officers) != 3 {
		t.Fatalf("expected 3 officers, got %d", len(flags.officers))
	}
	expected := []string{"admin1:/path/csr1", "admin2:/path/csr2", "admin3:/path/csr3"}
	for i, exp := range expected {
		if flags.officers[i] != exp {
			t.Errorf("officer[%d] expected %q, got %q", i, exp, flags.officers[i])
		}
	}
}

func TestStringSlice_String(t *testing.T) {
	s := stringSlice{"a", "b", "c"}
	result := s.String()
	if result != "a,b,c" {
		t.Errorf("expected a,b,c, got %q", result)
	}
}

func TestStringSlice_StringEmpty(t *testing.T) {
	s := stringSlice{}
	result := s.String()
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestStringSlice_Set(t *testing.T) {
	var s stringSlice
	if err := s.Set("first"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.Set("second"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(s))
	}
	if s[0] != "first" || s[1] != "second" {
		t.Errorf("expected [first, second], got %v", s)
	}
}

func TestResolveCredentialStrategy_FlagOverridesConfig(t *testing.T) {
	flags := &initFlags{credentialStrategy: "tpm2"}
	result := resolveCredentialStrategy(flags, nil)
	if result != "tpm2" {
		t.Errorf("expected tpm2, got %q", result)
	}
}

func TestResolveCredentialStrategy_DefaultsToBarrier(t *testing.T) {
	flags := &initFlags{}
	result := resolveCredentialStrategy(flags, nil)
	if result != "barrier" {
		t.Errorf("expected barrier, got %q", result)
	}
}

func TestResolveDataDir_FlagOverridesDefault(t *testing.T) {
	flags := &initFlags{dataDir: "/custom/data"}
	result := resolveDataDir(flags, nil)
	if result != "/custom/data" {
		t.Errorf("expected /custom/data, got %q", result)
	}
}

func TestResolveDataDir_DefaultValue(t *testing.T) {
	flags := &initFlags{}
	result := resolveDataDir(flags, nil)
	if result != "/var/lib/xkms" {
		t.Errorf("expected /var/lib/xkms, got %q", result)
	}
}

func TestResolveHostname_FlagOverridesDefault(t *testing.T) {
	flags := &initFlags{hostname: "custom.example.com"}
	result := resolveHostname(flags, nil)
	if result != "custom.example.com" {
		t.Errorf("expected custom.example.com, got %q", result)
	}
}

func TestResolveHostname_DefaultValue(t *testing.T) {
	flags := &initFlags{}
	result := resolveHostname(flags, nil)
	if result != "localhost" {
		t.Errorf("expected localhost, got %q", result)
	}
}

func TestParseInitFlags_InvalidFlag(t *testing.T) {
	_, err := parseInitFlags([]string{"--nonexistent-flag", "value"})
	if err == nil {
		t.Fatal("expected error for invalid flag")
	}
}

func TestValidateInitFlags_ThresholdOneIsNotMofN(t *testing.T) {
	// threshold=1 should be treated as single admin (no officers required)
	flags := &initFlags{
		soPin:     "so-pin",
		userPin:   "user-pin",
		threshold: 1,
	}
	if err := validateInitFlags(flags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateInitFlags_ThresholdZeroIsValid(t *testing.T) {
	flags := &initFlags{
		soPin:   "so-pin",
		userPin: "user-pin",
	}
	if err := validateInitFlags(flags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
