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
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-xkms/pkg/pintpm2"
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

	// Two first enrolments must not both act on a probe that saw no SRK
	// (Codex review 6000753682): the whole probe-then-create sequence runs
	// under an exclusive lock beside the platform storage, and the probe is
	// taken again under it.
	unlock, err := lockSRKEnrollment()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTPMSRKEnrollFailed, err)
	}
	defer unlock()
	return enrollPlatformSRKLocked(cmd.OutOrStdout(), userPIN, soPIN)
}

// srkEnrollLockName is the enrolment lock file in the data directory, beside
// the platform storage directory (<data dir>/tpm). It is not inside it: the
// storage engine refuses a non-empty directory it did not write.
const srkEnrollLockName = "tpm-srk-enroll.lock"

// lockSRKEnrollment blocks until this caller holds the exclusive Platform SRK
// enrolment lock and returns the function that releases it. The lock is an
// OS file lock (flock) on srkEnrollLockName beside the platform storage, so
// it serializes enrolments across processes and is dropped if a holder dies.
func lockSRKEnrollment() (func(), error) {
	dataDir, err := resolveDataDir("")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("enrolment lock directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dataDir, srkEnrollLockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open enrolment lock: %w", err)
	}
	if err := lockFileExclusive(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("take enrolment lock: %w", err)
	}
	return func() {
		_ = unlockFile(f)
		_ = f.Close()
	}, nil
}

// enrollPlatformSRKLocked enrols the Platform SRK; the caller holds the
// enrolment lock. AttachPlatformKeyStore probes the SRK handle here, under
// the lock, so an SRK a concurrent enrolment created is seen and checked
// against userPIN, never re-created.
func enrollPlatformSRKLocked(out io.Writer, userPIN, soPIN string) error {
	// The PIN policy runs before the TPM is opened: an SRK bound to a PIN
	// the policy refuses would answer to a PIN nothing else accepts.
	if err := checkSRKUserPINPolicy(userPIN); err != nil {
		return fmt.Errorf("%w: %w", ErrTPMSRKEnrollFailed, err)
	}

	tpm, err := openTPM()
	if err != nil {
		return fmt.Errorf("%w: open TPM: %w", ErrTPMSRKEnrollFailed, err)
	}
	defer func() { _ = tpm.Close() }()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// The platform key store keeps its keys in the same persistent TPM key
	// store the TPM records the Platform SRK's enrolment policy in.
	storage, err := tpmStorageFactory(logger)
	if err != nil {
		return fmt.Errorf("%w: key storage: %w", ErrTPMSRKEnrollFailed, err)
	}
	defer func() { _ = storage.Close() }()
	pks, err := xkms.AttachPlatformKeyStore(logger, tpm, storage.KeyBackend())
	if err != nil {
		return fmt.Errorf("%w: attach platform key store: %w", ErrTPMSRKEnrollFailed, err)
	}

	// An SRK that exists is checked against this PIN, never re-created: a
	// mismatched PIN must not evict the SRK and the keys under it. The check
	// runs even when the store reports auth ready, since that state may come
	// from another enrolment that attached the store first.
	if pks.IsInitialized() {
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
	case errors.Is(err, xkms.ErrTPMAuthFailed):
		// The SRK appeared after the probe and answers to another PIN;
		// enrolment refuses rather than evicting it.
		return ErrTPMSRKEnrolledOtherPIN
	default:
		return fmt.Errorf("%w: enrol Platform SRK: %w", ErrTPMSRKEnrollFailed, err)
	}
}

// checkSRKUserPINPolicy applies the user PIN policy pintpm2's SetUserPIN
// applies, through SetUserPIN itself over a probe store, so the rule lives
// in one place. SetUserPIN reaches the store only once the policy passed;
// the probe records that and refuses, so nothing is verified or cached.
func checkSRKUserPINPolicy(userPIN string) error {
	probe := &srkPINPolicyProbe{}
	backend := pintpm2.NewTPM2Backend(probe)
	err := backend.SetUserPIN("", userPIN)
	if closeErr := backend.Close(); closeErr != nil {
		return closeErr
	}
	if probe.reached {
		return nil
	}
	return err
}

// errSRKPINPolicyProbe is the probe's refusal once the policy has passed.
var errSRKPINPolicyProbe = errors.New("tpm srk enroll: PIN policy probe")

// srkPINPolicyProbe is a pintpm2.PlatformAuthProvider that holds no SRK:
// it only records that SetUserPIN reached the store.
type srkPINPolicyProbe struct{ reached bool }

func (p *srkPINPolicyProbe) VerifyAuth(string) error {
	p.reached = true
	return errSRKPINPolicyProbe
}

func (p *srkPINPolicyProbe) ChangeAuth(string, string) error {
	p.reached = true
	return errSRKPINPolicyProbe
}

func (*srkPINPolicyProbe) GetLockoutInfo() (int, int, int, int, error) {
	return 0, 0, 0, 0, errSRKPINPolicyProbe
}

func (*srkPINPolicyProbe) DictionaryAttackLockoutReset([]byte) error { return errSRKPINPolicyProbe }

func (*srkPINPolicyProbe) IsProvisioned() bool { return true }

func (*srkPINPolicyProbe) IsAuthReady() bool { return false }

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
