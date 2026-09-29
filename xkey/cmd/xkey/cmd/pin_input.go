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
	"errors"
	"io"
	"os"

	"github.com/jeremyhahn/go-enclave"
	"github.com/spf13/cobra"
)

// This file holds the ONE way a PIN enters the xkey CLI. Every command that
// needs one — "unlock", "auth register", "auth login" — declares the same two
// sources and resolves them in the same precedence order, so an operator
// learns the mechanism once and a second, divergent input path cannot
// appear.
//
// A third source, a "--pin"/"--so-pin" VALUE flag, existed through
// v0.9.x. It was removed (go-xkms#272): a value flag is visible to every
// other process on the host via `ps`, which is a wider audience than the
// IPC socket the PIN is often headed for, and its own help text said so.
// stdin and the environment are the only two sources now; a command line
// with "--pin" or "--so-pin" on it is a cobra parse error, not a quieter
// way in.

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

// pinFlagStdin and pinEnvVar name the two PIN sources. They are constants so
// the flag declaration, the resolver, and the help text cannot drift apart.
const (
	pinFlagStdin = "pin-stdin"
	pinEnvVar    = "XKEY_PIN"
)

// soPINFlagStdin and soPINEnvVar name the two sources of the Security
// Officer PIN, which a command needs only to verify a sealed enterprise
// policy (config.LoadVerifiedPolicy, #118). They mirror the user PIN
// sources exactly so an operator learns one convention.
const (
	soPINFlagStdin = "so-pin-stdin"
	soPINEnvVar    = "XKEY_SO_PIN"
)

// ErrSOPINInputStdinEmpty indicates --so-pin-stdin was given but standard
// input carried no PIN. It is distinct from ErrPINInputStdinEmpty so the
// operator is told which of the two PINs was expected.
var ErrSOPINInputStdinEmpty = errors.New("pin: --so-pin-stdin was given but standard input carried no SO PIN")

// pinSource describes one kind of PIN and the two inputs it resolves from.
// The user PIN and the SO PIN are the two kinds; each is declared once here
// so their flag names, environment variables and resolution order cannot
// diverge.
type pinSource struct {
	// label names the PIN in flag help ("PIN", "SO PIN").
	label string
	// stdinFlag and envVar are the two inputs, in precedence order: stdin,
	// then environment.
	stdinFlag string
	envVar    string
	// stdinEmpty is returned when stdinFlag was given but stdin was empty.
	stdinEmpty error
	// stdinRead is returned when stdinFlag was given but stdin could not be
	// read.
	stdinRead error
}

var (
	userPINSource = pinSource{
		label:      "PIN",
		stdinFlag:  pinFlagStdin,
		envVar:     pinEnvVar,
		stdinEmpty: ErrPINInputStdinEmpty,
		stdinRead:  ErrPINInputStdinRead,
	}
	soPINSource = pinSource{
		label:      "SO PIN",
		stdinFlag:  soPINFlagStdin,
		envVar:     soPINEnvVar,
		stdinEmpty: ErrSOPINInputStdinEmpty,
		stdinRead:  ErrPINInputStdinRead,
	}
)

// pinUsage is the operator-facing description of the two PIN sources,
// embedded verbatim in the long help of every command that accepts one.
const pinUsage = `The PIN may be supplied two ways, in precedence order:

  --pin-stdin      read the PIN from standard input (preferred: it keeps the
                   PIN out of the process list and the shell history)
  XKEY_PIN         environment variable

There is no "--pin" value flag: a value on the command line is visible to
every other process on the host via 'ps', which is a wider audience than
the destination the PIN is usually headed for.`

// soPINUsage is the operator-facing description of the two SO PIN sources,
// embedded in the long help of every command that verifies a sealed policy.
const soPINUsage = `In an enterprise deployment the config directory is sealed (xkey_policy.hmac
is present) and the SO-controlled policy is honoured only once it has been
verified with the Security Officer PIN. The SO PIN may be supplied two ways,
in precedence order:

  --so-pin-stdin   read the SO PIN from standard input (preferred: it keeps
                   the PIN out of the process list and the shell history)
  XKEY_SO_PIN      environment variable

There is no "--so-pin" value flag, for the same reason there is no "--pin"
one: it would be visible to every other process on the host via 'ps'.

Without it the sealed policy is not consulted and the command fails closed.
A sealed policy that does not verify is refused, whatever it says.`

// stdinReader reads the whole of standard input. It is a package-level
// variable so tests can drive the --pin-stdin path without a real pipe.
var stdinReader = func() ([]byte, error) { return io.ReadAll(os.Stdin) }

// addPINFlags declares the user PIN input flags on cmd. Every command that
// calls resolvePINInput must call this in its init.
func addPINFlags(cmd *cobra.Command) {
	userPINSource.addFlags(cmd)
}

// addSOPINFlags declares the SO PIN input flags on cmd. Every command that
// calls resolveSOPINInput must call this in its init.
func addSOPINFlags(cmd *cobra.Command) {
	soPINSource.addFlags(cmd)
}

// resolvePINInput returns the user PIN from the highest-precedence source
// that carries one, or "" when none does. Not supplying a PIN is not an
// error here: whether one is needed is the ceremony's decision.
func resolvePINInput(cmd *cobra.Command) (string, error) {
	return userPINSource.resolve(cmd)
}

// resolveSOPINInput returns the SO PIN from the highest-precedence source
// that carries one, or "" when none does. An absent SO PIN is not an error:
// it means a sealed policy is not consulted and the caller fails closed.
func resolveSOPINInput(cmd *cobra.Command) (string, error) {
	return soPINSource.resolve(cmd)
}

// resolveSOPINFromEnv returns the SO PIN from XKEY_SO_PIN alone, for a caller
// with no *cobra.Command to check --so-pin-stdin against.
//
// loadPairingAttestationTrust is reached from two shapes of call site: a
// command's own RunE, which has cmd and could ask resolveSOPINInput, and deep
// re-attestation call graphs that do not thread one through --
// openDeviceSession's enforceReattestation and newLiveAttestor, reached from
// OATH sync, backup, sharing, phone enrollment and the FIDO2 phone backend,
// same as unsealDeviceLocalKey reads XKEY_BARRIER_PASSWORD directly rather
// than a --barrier-password flag for the identical reason. One resolver for
// both shapes, rather than a second policy-loading path for the deep one,
// keeps the enterprise application allow-list (#1305) reachable from every
// place a device is judged -- including an unattended reconnect, which the
// operator cannot type a PIN into -- without inventing a second mechanism:
// resolveBytesFrom(false) is the same env-only lookup #1209's fido2.go
// pattern already established for a caller without cmd.
func resolveSOPINFromEnv() (string, error) {
	secret, err := soPINSource.resolveBytesFrom(false)
	if err != nil {
		return "", err
	}
	defer enclave.Wipe(secret)
	return string(secret), nil
}

// addFlags declares the source's one flag on cmd. XKEY_PIN / XKEY_SO_PIN
// need no flag of their own: os.Getenv reads them directly.
func (p pinSource) addFlags(cmd *cobra.Command) {
	cmd.Flags().Bool(p.stdinFlag, false, "Read the "+p.label+" from standard input")
}

// addPersistentFlags declares the source's one flag on cmd's persistent flag
// set, so every descendant command inherits it (piv.go's PIVCmd is the
// current use: every "piv" subcommand shares one --pkcs11-pin-stdin rather
// than redeclaring it).
func (p pinSource) addPersistentFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().Bool(p.stdinFlag, false, "Read the "+p.label+" from standard input")
}

// resolve returns the PIN from the highest-precedence source that carries
// one, as a string. It is resolveBytes for callers whose destination takes a
// string; the intermediate bytes are wiped.
func (p pinSource) resolve(cmd *cobra.Command) (string, error) {
	secret, err := p.resolveBytes(cmd)
	if err != nil {
		return "", err
	}
	defer enclave.Wipe(secret)
	return string(secret), nil
}

// resolveBytes returns the secret from the highest-precedence source that
// carries one: stdin when the stdin flag is set, then the environment
// variable. It returns nil when neither does -- there is no third,
// flag-value source (go-xkms#272): a value on the command line is visible to
// every other process on the host via 'ps'. The caller owns the returned
// slice and wipes it with enclave.Wipe when done.
func (p pinSource) resolveBytes(cmd *cobra.Command) ([]byte, error) {
	fromStdin, err := cmd.Flags().GetBool(p.stdinFlag)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPINInputFlagsMissing, Cause: err}
	}
	return p.resolveBytesFrom(fromStdin)
}

// resolveBytesFrom is resolveBytes for a caller that has already determined
// whether its stdin source was selected without going through a
// *cobra.Command flag lookup -- buildFIDO2Config (fido2.go) reads Viper
// directly rather than a specific command's flags, since it is called from
// call sites that predate one being threaded through (go-xkms#1209). The
// resolution order is identical: stdin when fromStdin is true, then the
// environment variable, then nil when neither carries a value.
func (p pinSource) resolveBytesFrom(fromStdin bool) ([]byte, error) {
	if fromStdin {
		data, readErr := stdinReader()
		if readErr != nil {
			enclave.Wipe(data)
			return nil, &SentinelCauseError{Sentinel: p.stdinRead, Cause: readErr}
		}
		secret := bytes.TrimRight(data, "\r\n")
		if len(secret) == 0 {
			enclave.Wipe(data)
			return nil, p.stdinEmpty
		}
		return secret, nil
	}

	if p.envVar != "" {
		if value := os.Getenv(p.envVar); value != "" {
			return []byte(value), nil
		}
	}
	return nil, nil
}
