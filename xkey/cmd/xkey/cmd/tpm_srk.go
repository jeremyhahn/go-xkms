// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

var (
	// ErrTPMSRKNoPIN indicates no user PIN was supplied to `tpm srk enroll`.
	ErrTPMSRKNoPIN = errors.New("tpm srk enroll: no user PIN: use --pin-file, --pin-stdin or XKEY_PIN, or run at a terminal")

	// ErrTPMSRKBothStdin indicates both PINs were asked for on stdin.
	ErrTPMSRKBothStdin = errors.New("tpm srk enroll: --pin-stdin and --so-pin-stdin cannot both read standard input")

	// ErrTPMSRKEnrolledOtherPIN indicates the Platform SRK is already
	// enrolled under a user PIN other than the one supplied. The SRK is left
	// untouched: re-enrolling would evict it and every key under it.
	ErrTPMSRKEnrolledOtherPIN = errors.New("tpm srk enroll: the Platform SRK is already enrolled with a different user PIN")

	// ErrTPMSRKEnrollFailed wraps a failure in one enrolment step.
	ErrTPMSRKEnrollFailed = errors.New("tpm srk enroll failed")
)

// tpmSRKCmd is `xkey tpm srk`, the Platform SRK verbs.
var tpmSRKCmd = newTPMSRKCmd()

// newTPMSRKCmd builds `xkey tpm srk` with its `enroll` child. It is a
// constructor so tests get fresh flag state.
func newTPMSRKCmd() *cobra.Command {
	srk := &cobra.Command{
		Use:   "srk",
		Short: "Manage the Platform Storage Root Key",
		Long: `Manage the Platform Storage Root Key (SRK), the TPM key every platform
key (FIDO2 credentials on --backend tpm2, the LAK) is created under. Its
auth value is the user PIN.`,
	}
	enroll := &cobra.Command{
		Use:   "enroll",
		Short: "Enrol the Platform SRK under the user PIN",
		Long: `Enrol the Platform SRK under the user PIN, after 'xkey tpm install'.

The SO PIN is the owner hierarchy auth set by 'xkey tpm install --auth'; it
is empty when install ran without --auth. It may be supplied with
--so-pin-file, --so-pin-stdin or XKEY_SO_PIN; at a terminal it is prompted
for and may be left empty.

Enrolment is idempotent: if the Platform SRK is already enrolled under the
same user PIN it reports "already enrolled" and exits 0.

The user PIN may be supplied, in precedence order, with:

  --pin-stdin      read the PIN from standard input
  --pin-file PATH  read the PIN from the first line of a file (for example a
                   systemd credential)
  XKEY_PIN         environment variable

or, with none of these, at a no-echo terminal prompt. There is no "--pin"
value flag: a value on the command line is visible to every process on the
host via 'ps'.`,
		Args: cobra.NoArgs,
		RunE: runTPMSRKEnroll,
	}
	srkUserPINSource.addFlags(enroll)
	srkSOPINSource.addFlags(enroll)
	srk.AddCommand(enroll)
	return srk
}

// runTPMSRKEnroll resolves both PINs, opens the TPM and enrols the
// Platform SRK. No PIN value reaches the output or an error.
func runTPMSRKEnroll(cmd *cobra.Command, _ []string) error {
	userPIN, soPIN, err := resolveSRKEnrollPINs(cmd)
	if err != nil {
		return err
	}

	tpm, err := openTPM()
	if err != nil {
		return fmt.Errorf("%w: open TPM: %w", ErrTPMSRKEnrollFailed, err)
	}
	defer func() { _ = tpm.Close() }()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// The platform key store keeps its keys in the same persistent TPM key
	// store the TPM records the Platform SRK's enrolment policy in.
	keyBackend, err := tpmKeyBackend(logger)
	if err != nil {
		return fmt.Errorf("%w: key storage: %w", ErrTPMSRKEnrollFailed, err)
	}
	pks, err := xkms.AttachPlatformKeyStore(logger, tpm, keyBackend)
	if err != nil {
		return fmt.Errorf("%w: attach platform key store: %w", ErrTPMSRKEnrollFailed, err)
	}

	out := cmd.OutOrStdout()
	// An SRK left by an earlier process is checked, never re-created: a
	// mismatched PIN must not evict the SRK and the keys under it.
	if pks.IsInitialized() && !pks.IsAuthReady() {
		if verifyErr := pks.VerifyAuth(userPIN); verifyErr != nil {
			if errors.Is(verifyErr, xkms.ErrTPMAuthFailed) {
				return ErrTPMSRKEnrolledOtherPIN
			}
			return fmt.Errorf("%w: verify Platform SRK auth: %w", ErrTPMSRKEnrollFailed, verifyErr)
		}
		_, _ = fmt.Fprintln(out, "Platform SRK already enrolled")
		return nil
	}

	switch err := pks.EnrollPlatformSRK(soPIN, userPIN); {
	case err == nil:
		_, _ = fmt.Fprintln(out, "Platform SRK enrolled")
		return nil
	case errors.Is(err, xkms.ErrPlatformSRKAlreadyEnrolled):
		_, _ = fmt.Fprintln(out, "Platform SRK already enrolled")
		return nil
	default:
		return fmt.Errorf("%w: enrol Platform SRK: %w", ErrTPMSRKEnrollFailed, err)
	}
}

// resolveSRKEnrollPINs returns the user PIN (required) and the SO PIN (may
// be empty) from the non-interactive sources, or prompts at a terminal.
func resolveSRKEnrollPINs(cmd *cobra.Command) (string, string, error) {
	pinStdin, _ := cmd.Flags().GetBool(pinFlagStdin)
	soPINStdin, _ := cmd.Flags().GetBool(soPINFlagStdin)
	if pinStdin && soPINStdin {
		return "", "", ErrTPMSRKBothStdin
	}

	userPIN, err := srkUserPINSource.resolve(cmd)
	if err != nil {
		return "", "", err
	}
	soPIN, err := srkSOPINSource.resolve(cmd)
	if err != nil {
		return "", "", err
	}
	// Each PIN prompts only when its own source is empty and stdin is a
	// terminal: a supplied user PIN must not skip the SO PIN prompt, which
	// a TPM with owner auth needs. No terminal and no SO source means an
	// empty SO PIN.
	terminal := pinInputIsTerminal()
	prompts := cmd.ErrOrStderr()
	if userPIN == "" {
		if !terminal {
			return "", "", ErrTPMSRKNoPIN
		}
		userPIN, err = readPIN(prompts, "User PIN: ")
		if err != nil {
			return "", "", err
		}
	}
	if soPIN == "" && terminal {
		soPIN, err = readSRKOptionalPIN(prompts, "SO PIN (empty if 'tpm install' ran without --auth): ")
		if err != nil {
			return "", "", err
		}
	}
	return userPIN, soPIN, nil
}

// readSRKOptionalPIN reads the optional SO PIN at enrolment; a variable so
// tests can stand in for the terminal.
var readSRKOptionalPIN = readOptionalPIN

// readOptionalPIN prompts at the terminal with no echo and accepts an
// empty answer.
func readOptionalPIN(out io.Writer, prompt string) (string, error) {
	_, _ = fmt.Fprint(out, prompt)
	pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(out)
	if err != nil {
		return "", &PINCommandError{Operation: "read_so_pin", Err: err}
	}
	return string(pinBytes), nil
}
