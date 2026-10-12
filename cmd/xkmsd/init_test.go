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
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

func TestValidateInitFlags_MissingSOPin(t *testing.T) {
	err := validateInitFlags(&initFlags{barrierStrategy: "passphrase"})
	if err == nil {
		t.Fatal("expected error for missing SO PIN")
	}
	if !errors.Is(err, ErrMissingSOPin) {
		t.Errorf("expected ErrMissingSOPin, got %v", err)
	}
}

func TestValidateInitFlags_ValidSingleAdmin(t *testing.T) {
	flags := &initFlags{soPin: "so-pin-value", barrierStrategy: "passphrase"}
	if err := validateInitFlags(flags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestValidateInitFlags_RefusesStrategiesInitCannotComplete proves the
// barrier strategies init validates are the ones it can complete unattended:
// Shamir custody is run through go-qrdb's own holder quorum, so shamir -- like
// any unknown name -- is refused up front.
func TestValidateInitFlags_RefusesStrategiesInitCannotComplete(t *testing.T) {
	for _, strategy := range []string{"shamir", "bogus", ""} {
		err := validateInitFlags(&initFlags{soPin: "so-pin-value", barrierStrategy: strategy})
		if !errors.Is(err, ErrInvalidBarrierStrategy) {
			t.Errorf("strategy %q: expected ErrInvalidBarrierStrategy, got %v", strategy, err)
		}
	}
}

func TestParseInitFlags_Defaults(t *testing.T) {
	flags, err := parseInitFlags([]string{"--so-pin", "test-so-pin"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.soPin != "test-so-pin" {
		t.Errorf("expected so-pin test-so-pin, got %q", flags.soPin)
	}
	if flags.configPath != "/etc/xkms/xkmsd.yaml" {
		t.Errorf("expected default config path, got %q", flags.configPath)
	}
	if flags.barrierStrategy != "passphrase" {
		t.Errorf("expected default barrier strategy passphrase, got %q", flags.barrierStrategy)
	}
}

func TestParseInitFlags_AllFlags(t *testing.T) {
	flags, err := parseInitFlags([]string{
		"--config", "/custom/config.yaml",
		"--so-pin", "my-so-pin",
		"--barrier-strategy", "tpm2",
		"--data-dir", "/custom/data",
		"--hostname", "xkms.example.com",
		"--sans", "a.example.com,b.example.com",
		"--admin-factor", "mtls,fido2",
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
	if flags.barrierStrategy != "tpm2" {
		t.Errorf("expected barrier-strategy tpm2, got %q", flags.barrierStrategy)
	}
	if flags.dataDir != "/custom/data" {
		t.Errorf("expected data-dir /custom/data, got %q", flags.dataDir)
	}
	if flags.hostname != "xkms.example.com" {
		t.Errorf("expected hostname xkms.example.com, got %q", flags.hostname)
	}
	if flags.sans != "a.example.com,b.example.com" {
		t.Errorf("expected sans, got %q", flags.sans)
	}
	if len(flags.adminFactors) != 1 || flags.adminFactors[0] != "mtls,fido2" {
		t.Errorf("expected admin-factor [mtls,fido2], got %v", flags.adminFactors)
	}
}

// TestParseInitFlags_RefusesRemovedCeremonyFlags proves the holder-ceremony
// flags are gone: officers, thresholds, shares and the user PIN belong to
// go-qrdb's own ceremony, not to `xkmsd init`.
func TestParseInitFlags_RefusesRemovedCeremonyFlags(t *testing.T) {
	for _, flag := range []string{"--so", "--threshold", "--shares", "--user-pin", "--credential-strategy"} {
		if _, err := parseInitFlags([]string{"--so-pin", "pin", flag, "x"}); err == nil {
			t.Errorf("%s was accepted; the ceremony flags are go-qrdb's, not xkmsd init's", flag)
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

func TestResolveDataDir_ConfigUsedWhenFlagEmpty(t *testing.T) {
	flags := &initFlags{}
	cfg := &config.Config{Datastore: config.DatastoreConfig{Path: "/etc/configured/data"}}
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

// openTestPasskeyPIN opens a sealed PIN and returns its plaintext for
// comparison, destroying the buffer once read. A nil secret is reported as
// "no PIN configured".
func openTestPasskeyPIN(t *testing.T, secret *secure.Secret) string {
	t.Helper()

	if secret == nil {
		return ""
	}
	buf, err := secret.Open(t.Context())
	if err != nil {
		t.Fatalf("open resolved passkey PIN: %v", err)
	}
	defer buf.Destroy()
	pin, err := secure.CopyOut(buf)
	if err != nil {
		t.Fatalf("read resolved passkey PIN: %v", err)
	}
	defer secure.Wipe(pin)
	return string(pin)
}

func TestResolvePasskeyPIN(t *testing.T) {
	t.Run("stdin is the preferred source", func(t *testing.T) {
		t.Setenv("XKMS_PASSKEY_PIN", "from-env")

		flags := &initFlags{passkeyPINStdin: true}
		pin, err := resolvePasskeyPIN(t.Context(), flags, strings.NewReader("123456\n"))
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

		pin, err := resolvePasskeyPIN(t.Context(), &initFlags{}, strings.NewReader("ignored"))
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
		pin, err := resolvePasskeyPIN(t.Context(), &initFlags{}, strings.NewReader(""))
		if err != nil {
			t.Fatalf("resolvePasskeyPIN: %v", err)
		}
		if pin != nil {
			t.Errorf("pin = %v, want nil", pin)
		}
	})

	t.Run("unreadable stdin is reported, not silently empty", func(t *testing.T) {
		flags := &initFlags{passkeyPINStdin: true}

		_, err := resolvePasskeyPIN(t.Context(), flags, iotest.ErrReader(errors.New("closed")))
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
		"--passkey-pin", "123456",
	}); err == nil {
		t.Fatal("--passkey-pin was accepted; a PIN must never be passed in argv")
	}

	flags, err := parseInitFlags([]string{
		"--so-pin", "pin",
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

func TestPrintInitSummary_ReportsConfiguration(t *testing.T) {
	out := captureStdout(t, func() {
		printInitSummary("node1.example.com", "/var/lib/xkms", &initFlags{barrierStrategy: "passphrase"})
	})

	for _, want := range []string{"node1.example.com", "/var/lib/xkms", "passphrase", "Validation Passed"} {
		if !strings.Contains(out, want) {
			t.Errorf("printInitSummary output missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "M-of-N") || strings.Contains(out, "Shamir") {
		t.Errorf("summary must not mention the holder ceremony; got:\n%s", out)
	}
}
