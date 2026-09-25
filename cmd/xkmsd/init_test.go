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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
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
	// The rendered message (what an operator sees in the CLI's error output)
	// must name the sentinel condition, not just satisfy errors.Is.
	var detailErr *WrappedDetailError
	if !errors.As(err, &detailErr) {
		t.Fatalf("expected *WrappedDetailError, got %T", err)
	}
	if got := detailErr.Error(); !strings.Contains(got, ErrEmptyCSRPath.Error()) {
		t.Errorf("WrappedDetailError.Error() = %q, want it to contain %q", got, ErrEmptyCSRPath.Error())
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
		return
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
	// A WrappedDetailError with no underlying cause still names the path, so
	// an operator sees which CSR it rejected without an "<nil>" suffix.
	var detailErr *WrappedDetailError
	if !errors.As(err, &detailErr) {
		t.Fatalf("expected *WrappedDetailError, got %T", err)
	}
	if got := detailErr.Error(); !strings.Contains(got, dir) {
		t.Errorf("WrappedDetailError.Error() = %q, want it to name the rejected path %q", got, dir)
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
		soPin:           "so-pin-value",
		userPin:         "user-pin-value",
		barrierStrategy: "passphrase",
	}
	if err := validateInitFlags(flags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateInitFlags_ThresholdWithoutOfficers(t *testing.T) {
	// Threshold without --barrier-strategy=shamir and without officers
	// is rejected. The canonical model requires --shares >= 2 when
	// --barrier-strategy=shamir; supplying --threshold alone with the
	// default software strategy is invalid.
	flags := &initFlags{
		soPin:           "so-pin-value",
		userPin:         "user-pin-value",
		barrierStrategy: "passphrase",
		threshold:       2,
	}
	err := validateInitFlags(flags)
	if err == nil {
		t.Fatal("expected error for threshold with non-shamir strategy")
	}
}

func TestValidateInitFlags_ThresholdExceedsOfficers(t *testing.T) {
	flags := &initFlags{
		soPin:           "so-pin-value",
		userPin:         "user-pin-value",
		barrierStrategy: "shamir",
		shares:          2,
		threshold:       3,
		officers:        stringSlice{"admin1:/path/csr1", "admin2:/path/csr2"},
	}
	err := validateInitFlags(flags)
	if err == nil {
		t.Fatal("expected error for threshold exceeding shares")
	}
}

func TestValidateInitFlags_ValidMofN(t *testing.T) {
	flags := &initFlags{
		soPin:           "so-pin-value",
		userPin:         "user-pin-value",
		barrierStrategy: "shamir",
		shares:          3,
		threshold:       2,
		officers:        stringSlice{"admin1:/path/csr1", "admin2:/path/csr2", "admin3:/path/csr3"},
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

func TestResolveCredentialStrategy_ConfigUsedWhenFlagEmpty(t *testing.T) {
	flags := &initFlags{}
	cfg := &config.Config{Credentials: config.CredentialsConfig{SealStrategy: "pkcs11"}}
	result := resolveCredentialStrategy(flags, cfg)
	if result != "pkcs11" {
		t.Errorf("expected the config value pkcs11 when the flag is unset, got %q", result)
	}
}

func TestResolveDataDir_ConfigUsedWhenFlagEmpty(t *testing.T) {
	flags := &initFlags{}
	cfg := &config.Config{Storage: config.StorageConfig{Path: "/etc/configured/data"}}
	result := resolveDataDir(flags, cfg)
	if result != "/etc/configured/data" {
		t.Errorf("expected the config value when the flag is unset, got %q", result)
	}
}

func TestResolveHostname_ConfigUsedWhenFlagEmpty(t *testing.T) {
	flags := &initFlags{}
	cfg := &config.Config{Server: config.ServerConfig{Host: "configured.example.com"}}
	result := resolveHostname(flags, cfg)
	if result != "configured.example.com" {
		t.Errorf("expected the config value when the flag is unset, got %q", result)
	}
}

func TestParseInitFlags_InvalidFlag(t *testing.T) {
	_, err := parseInitFlags([]string{"--nonexistent-flag", "value"})
	if err == nil {
		t.Fatal("expected error for invalid flag")
	}
}

func TestValidateInitFlags_ThresholdOneIsNotMofN(t *testing.T) {
	// Per canonical surface, --threshold is only valid when
	// --barrier-strategy=shamir. Threshold=1 with the default
	// software strategy is rejected.
	flags := &initFlags{
		soPin:           "so-pin",
		userPin:         "user-pin",
		barrierStrategy: "passphrase",
		threshold:       1,
	}
	if err := validateInitFlags(flags); err == nil {
		t.Fatal("expected ErrSharesRequiresShamir for threshold>0 with non-shamir strategy")
	}
}

func TestValidateInitFlags_ThresholdZeroIsValid(t *testing.T) {
	flags := &initFlags{
		soPin:           "so-pin",
		userPin:         "user-pin",
		barrierStrategy: "passphrase",
	}
	if err := validateInitFlags(flags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// openTestPasskeyPIN opens a sealed PIN and returns its plaintext for
// comparison, destroying the buffer once read. A nil secret is reported as
// "no PIN configured".
func openTestPasskeyPIN(t *testing.T, secret *secure.Secret) string {
	t.Helper()

	if secret == nil {
		return ""
	}
	buf, err := secret.Open()
	if err != nil {
		t.Fatalf("open resolved passkey PIN: %v", err)
	}
	defer buf.Destroy()
	return string(buf.Bytes())
}

func TestResolvePasskeyPIN(t *testing.T) {
	t.Run("stdin is the preferred source", func(t *testing.T) {
		t.Setenv("XKMS_PASSKEY_PIN", "from-env")

		flags := &initFlags{passkeyPINStdin: true}
		pin, err := resolvePasskeyPIN(flags, strings.NewReader("123456\n"))
		if err != nil {
			t.Fatalf("resolvePasskeyPIN: %v", err)
		}
		// The trailing newline a shell adds is not part of the PIN, and an
		// authenticator that receives it reports a wrong PIN — burning a
		// retry against a counter that blocks the key after three.
		if got := openTestPasskeyPIN(t, pin); got != "123456" {
			t.Errorf("pin = %q, want 123456 with the line ending stripped", got)
		}
	})

	t.Run("environment is the fallback", func(t *testing.T) {
		t.Setenv("XKMS_PASSKEY_PIN", "654321")

		pin, err := resolvePasskeyPIN(&initFlags{}, strings.NewReader("ignored"))
		if err != nil {
			t.Fatalf("resolvePasskeyPIN: %v", err)
		}
		if got := openTestPasskeyPIN(t, pin); got != "654321" {
			t.Errorf("pin = %q, want the environment value", got)
		}
	})

	t.Run("no source is not an error", func(t *testing.T) {
		t.Setenv("XKMS_PASSKEY_PIN", "")

		// A key with no PIN configured enrolls without one; refusing here
		// would block a working ceremony.
		pin, err := resolvePasskeyPIN(&initFlags{}, strings.NewReader(""))
		if err != nil {
			t.Fatalf("resolvePasskeyPIN: %v", err)
		}
		if pin != nil {
			t.Errorf("pin = %v, want nil", pin)
		}
	})

	t.Run("unreadable stdin is reported, not silently empty", func(t *testing.T) {
		flags := &initFlags{passkeyPINStdin: true}

		_, err := resolvePasskeyPIN(flags, iotest.ErrReader(errors.New("closed")))
		if !errors.Is(err, ErrPasskeyPINReadFailed) {
			t.Fatalf("err = %v, want ErrPasskeyPINReadFailed", err)
		}
	})
}

func TestParseInitFlags_PasskeyPINHasNoFlagForm(t *testing.T) {
	// A PIN in argv is readable from /proc by every process on the host for
	// the life of the command, so --passkey-pin must not exist.
	if _, err := parseInitFlags([]string{
		"--so-pin", "pin",
		"--user-pin", "pin",
		"--passkey-pin", "123456",
	}); err == nil {
		t.Fatal("--passkey-pin was accepted; a PIN must never be passed in argv")
	}

	flags, err := parseInitFlags([]string{
		"--so-pin", "pin",
		"--user-pin", "pin",
		"--passkey-pin-stdin",
	})
	if err != nil {
		t.Fatalf("parseInitFlags: %v", err)
	}
	if !flags.passkeyPINStdin {
		t.Error("--passkey-pin-stdin did not set the flag")
	}
}

func TestResolveRelyingParty(t *testing.T) {
	t.Run("configured relying party wins", func(t *testing.T) {
		cfg := &config.Config{WebAuthn: &config.WebAuthnConfig{
			RPID:          "xkms.example.com",
			RPDisplayName: "xkms console",
		}}

		id, name := resolveRelyingParty(cfg, "host.local")
		if id != "xkms.example.com" || name != "xkms console" {
			t.Fatalf("resolveRelyingParty = (%q, %q), want the configured values", id, name)
		}
	})

	t.Run("display name falls back to the RP ID", func(t *testing.T) {
		cfg := &config.Config{WebAuthn: &config.WebAuthnConfig{RPID: "xkms.example.com"}}

		if _, name := resolveRelyingParty(cfg, "host.local"); name != "xkms.example.com" {
			t.Fatalf("name = %q, want the RP ID", name)
		}
	})

	t.Run("absent webauthn section falls back to the hostname", func(t *testing.T) {
		// webauthn is an optional config section: every config without one
		// reaches here with a nil pointer, which used to crash `xkmsd init`
		// before a single ceremony step ran.
		for _, cfg := range []*config.Config{nil, {}, {WebAuthn: &config.WebAuthnConfig{}}} {
			id, name := resolveRelyingParty(cfg, "host.local")
			if id != "host.local" || name != "host.local" {
				t.Fatalf("resolveRelyingParty(%+v) = (%q, %q), want the hostname", cfg, id, name)
			}
		}
	})
}

// =============================================================================
// closeFIDO2Handler
// =============================================================================

// TestCloseFIDO2Handler_NilHandlerIsANoOp proves the common case (no passkey
// planned, so runInit never opened a FIDO2 handler) does not panic on a nil
// field.
func TestCloseFIDO2Handler_NilHandlerIsANoOp(t *testing.T) {
	closeFIDO2Handler(&ceremonyEnv{})
}

// TestCloseFIDO2Handler_ClosesAnOpenHandler proves the handler runInit opened
// for a planned passkey is actually closed, using the same construction
// (pkgfido2.NewHandler with the default enumerator) runInit itself uses; it
// needs no attached hardware since FIDO2Handler.Close releases nothing but
// its own bookkeeping.
func TestCloseFIDO2Handler_ClosesAnOpenHandler(t *testing.T) {
	handler, err := pkgfido2.NewHandler(nil, pkgfido2.NewDefaultEnumerator())
	if err != nil {
		t.Fatalf("pkgfido2.NewHandler: %v", err)
	}
	env := &ceremonyEnv{fido2Handler: handler}

	// Must not panic; closeFIDO2Handler discards the Close error deliberately
	// (see its doc comment on why runInit's os.Exit paths cannot afford one).
	closeFIDO2Handler(env)
}

// =============================================================================
// printInitSummary
// =============================================================================

func TestPrintInitSummary_SingleAdminMode(t *testing.T) {
	out := captureStdout(t, func() {
		printInitSummary(
			&initialize.CeremonyConfig{Hostname: "node1.example.com", DataDir: "/var/lib/xkms"},
			"barrier",
			nil,
			&initFlags{barrierStrategy: "passphrase"},
		)
	})

	for _, want := range []string{"node1.example.com", "/var/lib/xkms", "passphrase", "barrier", "Single Admin", "Validation Passed"} {
		if !strings.Contains(out, want) {
			t.Errorf("printInitSummary output missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "M-of-N") {
		t.Errorf("single-admin summary must not mention M-of-N mode; got:\n%s", out)
	}
}

func TestPrintInitSummary_MofNMode(t *testing.T) {
	officers := []initialize.OfficerConfig{{Username: "officer-a"}, {Username: "officer-b"}}
	out := captureStdout(t, func() {
		printInitSummary(
			&initialize.CeremonyConfig{Hostname: "node1.example.com", DataDir: "/data", Threshold: 2},
			"barrier",
			officers,
			&initFlags{barrierStrategy: "passphrase"},
		)
	})

	for _, want := range []string{"M-of-N (2-of-2)", "officer-a", "officer-b"} {
		if !strings.Contains(out, want) {
			t.Errorf("printInitSummary output missing %q; got:\n%s", want, out)
		}
	}
}

func TestPrintInitSummary_ShamirStrategyReportsShareCounts(t *testing.T) {
	out := captureStdout(t, func() {
		printInitSummary(
			&initialize.CeremonyConfig{Hostname: "node1.example.com", DataDir: "/data"},
			"barrier",
			nil,
			&initFlags{barrierStrategy: "shamir", threshold: 3, shares: 5},
		)
	})

	if !strings.Contains(out, "Shamir Mode:          3-of-5") {
		t.Errorf("printInitSummary output missing the Shamir mode line; got:\n%s", out)
	}
	// Shamir mode has no single-admin/M-of-N administrator yet (officers
	// claim in a later step), so neither mode line applies.
	if strings.Contains(out, "Single Admin") || strings.Contains(out, "M-of-N") {
		t.Errorf("Shamir summary must not claim a Mode line before any officer has claimed; got:\n%s", out)
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it, restoring the original afterwards.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = original })

	fn()

	_ = w.Close()
	os.Stdout = original

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(got)
}
