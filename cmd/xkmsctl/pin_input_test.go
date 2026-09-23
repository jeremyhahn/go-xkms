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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/spf13/cobra"
)

// openTestPIN opens a sealed PIN and returns its plaintext for comparison,
// destroying the buffer once read. A nil secret reads as "no PIN supplied".
func openTestPIN(t *testing.T, secret *secure.Secret) string {
	t.Helper()

	if secret == nil {
		return ""
	}
	buf, err := secret.Open()
	if err != nil {
		t.Fatalf("open resolved PIN: %v", err)
	}
	defer buf.Destroy()
	return string(buf.Bytes())
}

// These tests cover the input half of go-xkms#309: the xkmsctl WebAuthn verbs
// take the same three PIN sources, in the same precedence order, as the xkey
// verbs go-xkms#299 gave them.

// newPINCommand builds a command carrying the PIN flags, as every WebAuthn
// verb that resolves a PIN must.
func newPINCommand(t *testing.T) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	addPINFlags(cmd)
	return cmd
}

// stubPINStdin points the shared stdin reader at fixed bytes for one test.
func stubPINStdin(t *testing.T, input string) {
	t.Helper()

	original := secretStdin
	secretStdin = strings.NewReader(input)
	t.Cleanup(func() { secretStdin = original })
}

// TestAddPINFlagsDeclaresBothSources proves the helper declares exactly the
// flags the resolver reads — the property that keeps a command from compiling
// cleanly and then failing at run time on a flag it never declared.
func TestAddPINFlagsDeclaresBothSources(t *testing.T) {
	cmd := newPINCommand(t)

	if cmd.Flags().Lookup(pinFlagValue) == nil {
		t.Fatal("--pin must be declared")
	}
	if cmd.Flags().Lookup(pinFlagStdin) == nil {
		t.Fatal("--pin-stdin must be declared")
	}

	t.Setenv(pinEnvVar, "")
	pin, err := resolvePINInput(cmd)
	if err != nil {
		t.Fatalf("resolvePINInput: %v", err)
	}
	if pin != nil {
		t.Errorf("a command with no PIN supplied resolves to none, got %q", openTestPIN(t, pin))
	}
}

func TestResolvePINInputPrecedence(t *testing.T) {
	t.Run("stdin outranks the environment and the flag", func(t *testing.T) {
		t.Setenv(pinEnvVar, "from-env")
		stubPINStdin(t, "from-stdin\n")

		cmd := newPINCommand(t)
		if err := cmd.Flags().Set(pinFlagStdin, "true"); err != nil {
			t.Fatalf("set %s: %v", pinFlagStdin, err)
		}
		if err := cmd.Flags().Set(pinFlagValue, "from-flag"); err != nil {
			t.Fatalf("set %s: %v", pinFlagValue, err)
		}

		pin, err := resolvePINInput(cmd)
		if err != nil {
			t.Fatalf("resolvePINInput: %v", err)
		}
		if got := openTestPIN(t, pin); got != "from-stdin" {
			t.Errorf("got %q, want %q (the trailing newline must be trimmed)", got, "from-stdin")
		}
	})

	t.Run("the environment outranks the flag", func(t *testing.T) {
		t.Setenv(pinEnvVar, "from-env")

		cmd := newPINCommand(t)
		if err := cmd.Flags().Set(pinFlagValue, "from-flag"); err != nil {
			t.Fatalf("set %s: %v", pinFlagValue, err)
		}

		pin, err := resolvePINInput(cmd)
		if err != nil {
			t.Fatalf("resolvePINInput: %v", err)
		}
		if got := openTestPIN(t, pin); got != "from-env" {
			t.Errorf("got %q, want %q", got, "from-env")
		}
	})

	t.Run("the flag is the last resort", func(t *testing.T) {
		t.Setenv(pinEnvVar, "")

		cmd := newPINCommand(t)
		if err := cmd.Flags().Set(pinFlagValue, "from-flag"); err != nil {
			t.Fatalf("set %s: %v", pinFlagValue, err)
		}

		pin, err := resolvePINInput(cmd)
		if err != nil {
			t.Fatalf("resolvePINInput: %v", err)
		}
		if got := openTestPIN(t, pin); got != "from-flag" {
			t.Errorf("got %q, want %q", got, "from-flag")
		}
	})
}

func TestResolvePINInputStdinErrors(t *testing.T) {
	t.Run("empty stdin is rejected, not silently defaulted", func(t *testing.T) {
		stubPINStdin(t, "\r\n")

		cmd := newPINCommand(t)
		if err := cmd.Flags().Set(pinFlagStdin, "true"); err != nil {
			t.Fatalf("set %s: %v", pinFlagStdin, err)
		}

		_, err := resolvePINInput(cmd)
		if !errors.Is(err, ErrPINInputStdinEmpty) {
			t.Fatalf("want ErrPINInputStdinEmpty, got %v", err)
		}
	})

	t.Run("a stdin read failure is reported as such", func(t *testing.T) {
		original := secretStdin
		secretStdin = failingReader{}
		t.Cleanup(func() { secretStdin = original })

		cmd := newPINCommand(t)
		if err := cmd.Flags().Set(pinFlagStdin, "true"); err != nil {
			t.Fatalf("set %s: %v", pinFlagStdin, err)
		}

		_, err := resolvePINInput(cmd)
		if !errors.Is(err, ErrPINInputStdinRead) {
			t.Fatalf("want ErrPINInputStdinRead, got %v", err)
		}
		if !errors.Is(err, errPromptBoom) {
			t.Errorf("the read failure must survive as the cause, got %v", err)
		}
	})
}

// TestResolvePINInputRejectsUndeclaredFlags proves a command that skipped
// addPINFlags is reported as a wiring defect rather than resolving no PIN:
// silence here would look to the operator exactly like an authenticator that
// needs none.
func TestResolvePINInputRejectsUndeclaredFlags(t *testing.T) {
	cmd := &cobra.Command{}

	_, err := resolvePINInput(cmd)
	if !errors.Is(err, ErrPINInputFlagsMissing) {
		t.Fatalf("want ErrPINInputFlagsMissing, got %v", err)
	}
}

// --- the missing-PIN diagnosis (issue #309 fix item 3) ---

// TestCeremonyFailureNamesTheMissingPIN is the whole point of the mapping: the
// raw CTAP2_ERR_PIN_REQUIRED reads as a device fault rather than missing
// input, and it names neither the PIN nor the flag that supplies it.
func TestCeremonyFailureNamesTheMissingPIN(t *testing.T) {
	for _, sentinel := range []error{ErrRegisterCredentialFailed, ErrAuthenticationFailed} {
		err := ceremonyFailure(sentinel, nil, fido2.ErrPINRequired)
		if err == nil {
			t.Fatal("want an error")
		}
		if !errors.Is(err, ErrWebAuthnPINRequired) {
			t.Fatalf("want ErrWebAuthnPINRequired, got %v", err)
		}
		if !errors.Is(err, fido2.ErrPINRequired) {
			t.Errorf("the CTAP cause must survive for diagnosis, got %v", err)
		}

		message := err.Error()
		if !strings.Contains(message, "requires a PIN") {
			t.Errorf("message must name the missing PIN: %q", message)
		}
		if !strings.Contains(message, "--"+pinFlagStdin) {
			t.Errorf("message must name the flag that supplies it: %q", message)
		}
		if !strings.Contains(message, pinEnvVar) {
			t.Errorf("message must name the environment variable: %q", message)
		}
	}
}

func TestCeremonyFailureClassification(t *testing.T) {
	t.Run("a PIN that was supplied is not reported as a missing one", func(t *testing.T) {
		// PIN_REQUIRED with a PIN in hand means the authenticator rejected an
		// authorization that WAS attempted. Telling the operator to supply the
		// PIN they just supplied sends them in a circle.
		err := ceremonyFailure(ErrAuthenticationFailed, testPINSecret(t, "123456"), fido2.ErrPINRequired)
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("want the original sentinel, got %v", err)
		}
		if errors.Is(err, ErrWebAuthnPINRequired) {
			t.Errorf("must not be classified as a missing PIN: %v", err)
		}
	})

	t.Run("an unrelated failure keeps its own sentinel", func(t *testing.T) {
		cause := errors.New("hid: device disconnected")
		err := ceremonyFailure(ErrRegisterCredentialFailed, nil, cause)
		if !errors.Is(err, ErrRegisterCredentialFailed) {
			t.Fatalf("want the original sentinel, got %v", err)
		}
		if !errors.Is(err, cause) {
			t.Errorf("the cause must survive, got %v", err)
		}
		if errors.Is(err, ErrWebAuthnPINRequired) {
			t.Errorf("must not be classified as a missing PIN: %v", err)
		}
	})

	t.Run("a wrong PIN keeps its attempts-remaining annotation", func(t *testing.T) {
		// A lockout must never read as anything else, so the attempt counter
		// the authenticator reported has to survive to the operator.
		cause := &fido2.PINAttemptsError{Err: fido2.ErrInvalidPIN, Retries: 2}
		err := ceremonyFailure(ErrAuthenticationFailed, testPINSecret(t, "999999"), cause)
		if !errors.Is(err, fido2.ErrInvalidPIN) {
			t.Fatalf("want ErrInvalidPIN reachable, got %v", err)
		}
		if errors.Is(err, ErrWebAuthnPINRequired) {
			t.Errorf("must not be classified as a missing PIN: %v", err)
		}
		if !strings.Contains(err.Error(), "2 attempts remaining") {
			t.Errorf("the attempt counter must survive: %q", err.Error())
		}
	})
}
