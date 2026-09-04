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
	"errors"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// This file holds the ONE way a PIN enters the xkey CLI. Every command that
// needs one — "unlock", "auth register", "auth login" — declares the same three
// flags and resolves them in the same precedence order, so an operator learns
// the mechanism once and a second, divergent input path cannot appear.

// PIN input errors.
var (
	// ErrPINInputStdinEmpty indicates --pin-stdin was given but standard input
	// carried no PIN.
	//
	// Continuing with an empty PIN here would be a silent default: the
	// ceremony that follows fails inside the authenticator with a CTAP error
	// that names neither the PIN nor the flag that supplies it.
	ErrPINInputStdinEmpty = errors.New("pin: --pin-stdin was given but standard input carried no PIN")

	// ErrPINInputStdinRead indicates standard input could not be read.
	ErrPINInputStdinRead = errors.New("pin: failed to read the PIN from standard input")

	// ErrPINInputFlagsMissing indicates the command did not declare the PIN
	// input flags with addPINFlags. It is a wiring defect, not operator input,
	// and is reported rather than swallowed: a command that silently resolved
	// no PIN would look to the operator exactly like an authenticator that
	// needs none.
	ErrPINInputFlagsMissing = errors.New("pin: the command does not declare the PIN input flags")
)

// pinFlagStdin, pinFlagValue and pinEnvVar name the three PIN sources. They are
// constants so the flag declaration, the resolver, and the help text cannot
// drift apart.
const (
	pinFlagStdin = "pin-stdin"
	pinFlagValue = "pin"
	pinEnvVar    = "XKEY_PIN"
)

// pinUsage is the operator-facing description of the three PIN sources,
// embedded verbatim in the long help of every command that accepts one.
const pinUsage = `The PIN may be supplied three ways, in precedence order:

  --pin-stdin      read the PIN from standard input (preferred: it keeps the
                   PIN out of the process list and the shell history)
  XKEY_PIN         environment variable
  --pin            flag value (visible in 'ps'; use for local development only)`

// stdinReader reads the whole of standard input. It is a package-level
// variable so tests can drive the --pin-stdin path without a real pipe.
var stdinReader = func() ([]byte, error) { return io.ReadAll(os.Stdin) }

// addPINFlags declares the three PIN input flags resolvePINInput reads. Every
// command that takes a PIN uses it, so the flag names and their help text are
// identical everywhere.
func addPINFlags(cmd *cobra.Command) {
	cmd.Flags().String(pinFlagValue, "", "PIN (visible in the process list; prefer --pin-stdin)")
	cmd.Flags().Bool(pinFlagStdin, false, "Read the PIN from standard input")
}

// resolvePINInput returns the PIN from the highest-precedence source the
// command was given: standard input (--pin-stdin), then XKEY_PIN, then --pin.
// Reading from stdin is preferred because a PIN passed as a flag is visible to
// every process on the host via /proc.
//
// An empty return value means no source supplied a PIN. That is a legitimate
// state — an authenticator with no PIN configured needs none — so commands
// that require one reject the empty value themselves rather than having this
// resolver decide for them.
func resolvePINInput(cmd *cobra.Command) (string, error) {
	fromStdin, err := cmd.Flags().GetBool(pinFlagStdin)
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrPINInputFlagsMissing, Cause: err}
	}
	if fromStdin {
		data, readErr := stdinReader()
		if readErr != nil {
			return "", &SentinelCauseError{Sentinel: ErrPINInputStdinRead, Cause: readErr}
		}
		pin := strings.TrimRight(string(data), "\r\n")
		if pin == "" {
			return "", ErrPINInputStdinEmpty
		}
		return pin, nil
	}

	if pin := os.Getenv(pinEnvVar); pin != "" {
		return pin, nil
	}

	pin, err := cmd.Flags().GetString(pinFlagValue)
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrPINInputFlagsMissing, Cause: err}
	}
	return pin, nil
}
