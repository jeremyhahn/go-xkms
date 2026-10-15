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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
)

// This file is the operator-facing half of xKey's token lifecycle: the commands
// that establish and change the authenticator's Security Officer PIN.
//
// Every SO-gated capability — attestation provisioning, replacing the
// attestation key, resetting a forgotten user PIN, per-RP policy writes —
// refuses on a token that has no Security Officer. The authenticator has had
// the whole lifecycle since #306 (Authenticator.InitializeToken and ChangeSOPIN,
// PKCS#11 v3.0 §5.6's C_InitToken and C_SetPIN), but its only caller was the
// CTAP authenticatorConfig vendor dispatch, which nothing on the host could
// reach. A device therefore stayed permanently uninitialized and every SO-gated
// verb was unreachable (#233).
//
// These commands drive InitializeToken and ChangeSOPIN directly, the way
// `xkey fido2 --set-pin-stdin` drives Authenticator.SetInitialPIN for the user PIN
// (#411): the in-process counterpart of the wire ceremony, not a second
// establishment mechanism. handleVendorSetSOPIN and handleVendorChangeSOPIN
// pass straight through to the same two methods, so there remains exactly one
// path to a Security Officer credential and exactly one place its preconditions
// are enforced.
//
// The SO PIN is never written to xKey's password store. That store is unlocked
// by the *user* PIN, and the SO PIN's job is to reset a forgotten user PIN, so
// keeping one inside the other would make the recovery credential recoverable
// only by the credential it recovers (#432). It is typed by the operator and
// held nowhere else.
//
// Note the subject. `xkey pin set-so` names a different one: the qrdb PIN
// service over a file store under the data directory, which is the host's
// SO PIN and not the authenticator's. The two credentials are unrelated.

// Token lifecycle errors.
var (
	// ErrTokenVolatileStorage indicates the authenticator is configured with
	// memory storage, where a Security Officer credential would be discarded
	// when the process exits.
	ErrTokenVolatileStorage = errors.New("fido2: memory storage cannot hold a Security Officer credential; configure fido2.storage as 'file' or 'barrier'")

	// ErrTokenDeviceOpenFailed indicates the device state could not be opened.
	ErrTokenDeviceOpenFailed = errors.New("fido2: failed to open the device state")

	// ErrTokenStateReadFailed indicates the persisted device state could not be
	// read back.
	ErrTokenStateReadFailed = errors.New("fido2: failed to read the device state")

	// ErrTokenAlreadyInitialized indicates the token already has a Security
	// Officer PIN. Initialization never replaces one: after it, the SO PIN
	// changes only through `xkey fido2 change-so-pin`, which proves the current
	// PIN first.
	ErrTokenAlreadyInitialized = errors.New("init-token: this device already has a Security Officer PIN; change it with 'xkey fido2 change-so-pin'")

	// ErrTokenInitFailed indicates the device refused initialization.
	ErrTokenInitFailed = errors.New("init-token: the device refused to initialize")

	// ErrSOPINChangeUninitialized indicates the token has no Security Officer
	// PIN to change.
	ErrSOPINChangeUninitialized = errors.New("change-so-pin: this device has no Security Officer PIN; establish one with 'xkey fido2 init-token'")

	// ErrSOPINChangeFailed indicates the device refused the change. The most
	// common cause is a wrong current SO PIN, which spends one retry.
	ErrSOPINChangeFailed = errors.New("change-so-pin: the device refused to change the Security Officer PIN")
)

// fido2InitTokenCmd establishes the authenticator's Security Officer PIN.
var fido2InitTokenCmd = &cobra.Command{
	Use:   "init-token",
	Short: "Initialize this device's token by establishing its Security Officer PIN",
	Long: `Establish the Security Officer PIN that authorizes this device's administrative operations.

A device is uninitialized until this runs, and an uninitialized device refuses
every Security Officer operation: provisioning the attestation identity,
replacing the attestation key, resetting a forgotten user PIN. "No Security
Officer PIN" is a refusal, never a waiver.

This is xKey's C_InitToken (PKCS#11 v3.0 §5.6). It runs once. After it the SO
PIN changes only through "xkey fido2 change-so-pin", which proves the current
PIN first; a factory reset is the only way back to uninitialized.

The SO PIN is the recovery credential for a forgotten user PIN, so it is not
stored in the device's own password store — that store is unlocked by the user
PIN. Record it somewhere outside this device before you continue; nothing here
can show it to you again.

The FIDO2 daemon owns the device state while it runs, so stop it first
("xkey fido2 status" reports whether it is running) and start it again
afterwards.

This writes the device state fido2.storage and fido2.storage_path name, the
same state the daemon reads. "memory" is refused: a Security Officer credential
that does not survive the process is no credential at all.

Examples:
  # Initialize the token, entering the SO PIN at the prompt
  xkey fido2 init-token`,
	Args: cobra.NoArgs,
	RunE: runFIDO2InitToken,
}

// fido2ChangeSOPINCmd changes the authenticator's Security Officer PIN.
var fido2ChangeSOPINCmd = &cobra.Command{
	Use:   "change-so-pin",
	Short: "Change this device's Security Officer PIN (requires the current one)",
	Long: `Replace the Security Officer PIN, proving the current one first.

This is xKey's C_SetPIN as SO (PKCS#11 v3.0 §5.6). The current PIN is proven by
authenticated decryption of the wrapped Admin Key, so only whoever already holds
the SO PIN can change it. A wrong current PIN spends one retry from the device's
budget, and that spend is persisted — restarting does not restore it.

This command changes the authenticator's Security Officer PIN. "xkey pin set-so"
names a different credential: the host PIN service's SO PIN. Changing one does
not change the other.

The FIDO2 daemon owns the device state while it runs, so stop it first.

Examples:
  xkey fido2 change-so-pin`,
	Args: cobra.NoArgs,
	RunE: runFIDO2ChangeSOPIN,
}

func init() {
	fido2Cmd.AddCommand(fido2InitTokenCmd)
	fido2Cmd.AddCommand(fido2ChangeSOPINCmd)

}

// runFIDO2InitToken establishes the device's Security Officer PIN.
//
// The ordering is deliberate. Everything that can refuse without asking the
// operator for anything — volatile storage, a running daemon, a token that
// already has an SO PIN — is settled before the prompt, so nobody chooses and
// confirms a PIN only to be told the device could never have taken it. The
// authenticator itself is constructed after the prompt, because constructing it
// starts the post-power-up initialization window and PIN entry would otherwise
// spend it.
func runFIDO2InitToken(cmd *cobra.Command, _ []string) (err error) {
	out := cmd.OutOrStdout()

	storage, err := openTokenDevice(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	initialized, err := tokenInitialized(storage)
	if err != nil {
		return err
	}
	if initialized {
		return ErrTokenAlreadyInitialized
	}

	_, _ = fmt.Fprint(out, initTokenBanner)

	soPIN, err := readAndConfirmPIN(out, "Enter new SO PIN: ")
	if err != nil {
		return err
	}

	auth, err := newOfflineAuthenticator(cmd.InOrStdin(), out, storage)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTokenDeviceOpenFailed, Cause: err}
	}
	defer func() {
		if closeErr := auth.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// InitializeToken is the authoritative guard, not the pre-check above: it
	// re-tests under the state lock and returns ErrKeyManagerAlreadyInitialized,
	// which is the refusal that holds when two initializations race.
	if err := auth.InitializeToken(cmd.Context(), soPIN); err != nil {
		if errors.Is(err, authenticator.ErrKeyManagerAlreadyInitialized) {
			return ErrTokenAlreadyInitialized
		}
		return &SentinelCauseError{Sentinel: ErrTokenInitFailed, Cause: err}
	}

	reportTokenState(out, auth)
	return nil
}

// runFIDO2ChangeSOPIN replaces the device's Security Officer PIN.
func runFIDO2ChangeSOPIN(cmd *cobra.Command, _ []string) (err error) {
	out := cmd.OutOrStdout()

	storage, err := openTokenDevice(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	initialized, err := tokenInitialized(storage)
	if err != nil {
		return err
	}
	if !initialized {
		return ErrSOPINChangeUninitialized
	}

	currentPIN, err := readPIN(out, "Enter current SO PIN: ")
	if err != nil {
		return err
	}
	newPIN, err := readAndConfirmPIN(out, "Enter new SO PIN: ")
	if err != nil {
		return err
	}

	auth, err := newOfflineAuthenticator(cmd.InOrStdin(), out, storage)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTokenDeviceOpenFailed, Cause: err}
	}
	defer func() {
		if closeErr := auth.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if err := auth.ChangeSOPIN(cmd.Context(), currentPIN, newPIN); err != nil {
		if errors.Is(err, authenticator.ErrTokenUninitialized) {
			return ErrSOPINChangeUninitialized
		}
		return &SentinelCauseError{Sentinel: ErrSOPINChangeFailed, Cause: err}
	}

	reportTokenState(out, auth)
	return nil
}

// openTokenDevice settles the refusals that need no operator input and opens the
// device's storage.
func openTokenDevice(cmd *cobra.Command) (authenticator.StatefulCredentialStorage, error) {
	socketPath := resolvedSocketPath(cmd)

	cfg := buildFIDO2Config()

	// A memory-backed authenticator discards its state with the process, so an
	// SO PIN established here would be gone before the daemon ever read it —
	// the operator would be told the token was initialized and the device would
	// still refuse every SO-gated operation.
	if cfg.StorageType == FIDO2StorageTypeMemory {
		return nil, ErrTokenVolatileStorage
	}

	running, err := fido2DaemonRunning(socketPath)
	if err != nil {
		return nil, err
	}
	if running {
		return nil, ErrFIDO2DaemonRunning
	}

	storage, err := createFIDO2Storage(cfg, slog.Default())
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTokenDeviceOpenFailed, Cause: err}
	}
	return storage, nil
}

// tokenInitialized reports whether the persisted state already carries a
// Security Officer credential.
//
// It reads the store rather than constructing an authenticator, so the refusal
// can be given before the operator is prompted and without opening the
// initialization window.
func tokenInitialized(storage authenticator.StatefulCredentialStorage) (bool, error) {
	state, err := storage.LoadState()
	if err != nil {
		// A device that has never saved state has no Security Officer.
		if errors.Is(err, authenticator.ErrStateNotFound) {
			return false, nil
		}
		return false, &SentinelCauseError{Sentinel: ErrTokenStateReadFailed, Cause: err}
	}
	return state.SOPINManager != nil && state.SOPINManager.IsSet, nil
}

// initTokenBanner names the control that is actually enforcing here.
//
// InitializeToken bounds the trust-on-first-use window with CTAP 2.1 §6.9's two
// conditions — a short post-power-up window and user presence — and both are
// real for a device reached over a transport. Neither constrains an operator
// running this command: the command constructs the authenticator itself, so it
// opens the window, and the presence prompt asks the same person who just typed
// the PIN. The control that does apply is the file permissions on the device's
// state directory, which is the same control already protecting every
// credential in it. Saying so is the point: a bound that cannot fire must not be
// reported as one that held.
const initTokenBanner = `Initializing this device's token.

Authorization: the file permissions on this device's state directory.
               The post-power-up window and user-presence check that bound
               initialization over CTAP do not constrain a local operator.

Record the SO PIN outside this device. It is the recovery credential for a
forgotten user PIN, so it is not kept in the device's password store, and
nothing can show it to you again.

`

// reportTokenState renders the token's lifecycle state after a change, using
// the same PKCS#11 flag vocabulary a PKCS#11 application would see.
func reportTokenState(out io.Writer, auth *authenticator.Authenticator) {
	_, _ = fmt.Fprintf(out, "Token: %s\n", auth.TokenFlags())
}
