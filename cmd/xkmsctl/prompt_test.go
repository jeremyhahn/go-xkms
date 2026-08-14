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

// prompt_test.go exercises the resolveSecret / resolvePIN secret input
// helpers across the flag, stdin ("-"), piped-line, and terminal paths.
package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// withPromptInput redirects the secret input seams to the given string
// and forces the non-terminal path for the duration of the test.
func withPromptInput(t *testing.T, input string) {
	t.Helper()
	origStdin := secretStdin
	origIsTerminal := isTerminalFn
	origReadPassword := readPasswordFn
	t.Cleanup(func() {
		secretStdin = origStdin
		isTerminalFn = origIsTerminal
		readPasswordFn = origReadPassword
	})
	secretStdin = strings.NewReader(input)
	isTerminalFn = func(int) bool { return false }
}

// withTerminalPrompt redirects the secret input seams to a fake terminal
// that returns the given secret (or error) from the no-echo reader.
func withTerminalPrompt(t *testing.T, secret string, err error) {
	t.Helper()
	origIsTerminal := isTerminalFn
	origReadPassword := readPasswordFn
	t.Cleanup(func() {
		isTerminalFn = origIsTerminal
		readPasswordFn = origReadPassword
	})
	isTerminalFn = func(int) bool { return true }
	readPasswordFn = func(int) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		return []byte(secret), nil
	}
}

// resetCmdFlags restores every flag of the command to its default value
// and clears the Changed marker so tests do not leak flag state.
func resetCmdFlags(t *testing.T, cmd *cobra.Command) {
	t.Helper()
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
}

// errPromptBoom is a reusable failure for prompt error-path tests.
var errPromptBoom = errors.New("prompt boom")

// failingReader always fails, exercising the stdin error paths.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errPromptBoom }

func TestResolveSecret_FlagValue(t *testing.T) {
	got, err := resolveSecret("s3cret", "Secret")
	if err != nil {
		t.Fatalf("resolveSecret() error = %v", err)
	}
	if got != "s3cret" {
		t.Errorf("resolveSecret() = %q, want %q", got, "s3cret")
	}
}

func TestResolveSecret_StdinDash(t *testing.T) {
	withPromptInput(t, "piped-secret\n")
	got, err := resolveSecret("-", "Secret")
	if err != nil {
		t.Fatalf("resolveSecret() error = %v", err)
	}
	if got != "piped-secret" {
		t.Errorf("resolveSecret() = %q, want %q", got, "piped-secret")
	}
}

func TestResolveSecret_StdinDashError(t *testing.T) {
	withPromptInput(t, "")
	secretStdin = failingReader{}
	_, err := resolveSecret("-", "Secret")
	if !errors.Is(err, ErrReadSecretFailed) {
		t.Errorf("resolveSecret() error = %v, want ErrReadSecretFailed", err)
	}
}

func TestResolveSecret_PipedLine(t *testing.T) {
	withPromptInput(t, "line-secret\nnext-line\n")
	got, err := resolveSecret("", "Secret")
	if err != nil {
		t.Fatalf("resolveSecret() error = %v", err)
	}
	if got != "line-secret" {
		t.Errorf("resolveSecret() = %q, want %q", got, "line-secret")
	}
}

func TestResolveSecret_PipedLineError(t *testing.T) {
	withPromptInput(t, "")
	secretStdin = failingReader{}
	_, err := resolveSecret("", "Secret")
	if !errors.Is(err, ErrReadSecretFailed) {
		t.Errorf("resolveSecret() error = %v, want ErrReadSecretFailed", err)
	}
}

func TestResolveSecret_Terminal(t *testing.T) {
	withTerminalPrompt(t, "tty-secret", nil)
	got, err := resolveSecret("", "Secret")
	if err != nil {
		t.Fatalf("resolveSecret() error = %v", err)
	}
	if got != "tty-secret" {
		t.Errorf("resolveSecret() = %q, want %q", got, "tty-secret")
	}
}

func TestResolveSecret_TerminalError(t *testing.T) {
	withTerminalPrompt(t, "", errPromptBoom)
	_, err := resolveSecret("", "Secret")
	if !errors.Is(err, ErrReadSecretFailed) {
		t.Errorf("resolveSecret() error = %v, want ErrReadSecretFailed", err)
	}
	if !errors.Is(err, errPromptBoom) {
		t.Errorf("resolveSecret() error = %v, want wrapped errPromptBoom", err)
	}
}

func TestResolvePIN_Value(t *testing.T) {
	got, err := resolvePIN("1234", "PIN")
	if err != nil {
		t.Fatalf("resolvePIN() error = %v", err)
	}
	if got != "1234" {
		t.Errorf("resolvePIN() = %q, want %q", got, "1234")
	}
}

func TestResolvePIN_Empty(t *testing.T) {
	withPromptInput(t, "\n")
	_, err := resolvePIN("", "PIN")
	if !errors.Is(err, ErrPINEmpty) {
		t.Errorf("resolvePIN() error = %v, want ErrPINEmpty", err)
	}
}

func TestResolvePIN_PropagatesReadError(t *testing.T) {
	withPromptInput(t, "")
	secretStdin = failingReader{}
	_, err := resolvePIN("-", "PIN")
	if !errors.Is(err, ErrReadSecretFailed) {
		t.Errorf("resolvePIN() error = %v, want ErrReadSecretFailed", err)
	}
}
