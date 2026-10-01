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
	"context"
	"errors"
	"log/slog"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// This file is the single place the CLI decides whether a secret-bearing
// store is barrier-encrypted or plain. `xkey oath`, `xkey backup`, and
// `xkey device oath-sync` all persist data the xkey GUI already keeps behind
// its barrier when one is initialized (go-xkms#134, go-xkms#148): the GUI
// (pkg/gui/app.go) and `xkey extension serve` (extension_serve.go) both wire
// oath.NewBackendStore over the same unsealed xkms.BarrierBackend, and
// nothing here invents a second encryption scheme or a separate wrapping
// key -- it only decides which backend the existing store constructors
// (oath.NewBackendStore vs oath.NewFileStore) are handed.
//
// fido2's storage selection (`--storage barrier|file|memory` in fido2.go)
// predates this file and stays an explicit opt-in rather than
// auto-detection, but createBarrierStorage shares the same low-level
// openBarrierBackend below, so there remains exactly one function in the
// CLI that knows how to unseal the barrier.

// Barrier-backed secret store errors.
var (
	// ErrBarrierStoreOpenFailed indicates a barrier is initialized but could
	// not be opened: a missing or wrong password, an unsupported strategy,
	// or a corrupt root key. This is always a typed refusal -- a barrier
	// that exists but cannot be opened never falls back to plaintext.
	ErrBarrierStoreOpenFailed = errors.New("barrier: failed to open barrier-backed store")

	// ErrBarrierBackendUnavailable indicates the barrier unsealed but did
	// not produce a usable storage backend. This should not happen in
	// practice; it exists so a future BarrierService regression fails
	// closed instead of silently returning a nil backend.
	ErrBarrierBackendUnavailable = errors.New("barrier: backend unavailable after unseal")

	// ErrBarrierStoreTPMUnavailable indicates a tpm2-strategy barrier could
	// not be unsealed because no TPM device is available on this host.
	ErrBarrierStoreTPMUnavailable = errors.New("barrier: TPM device required for tpm2-strategy barrier")
)

// ErrBarrierPasswordStdinEmpty indicates --barrier-password-stdin was given
// but standard input carried no password.
var ErrBarrierPasswordStdinEmpty = errors.New("barrier: --barrier-password-stdin was given but standard input carried no password")

// ErrBarrierPasswordStdinRead indicates standard input could not be read for
// --barrier-password-stdin.
var ErrBarrierPasswordStdinRead = errors.New("barrier: failed to read the barrier password from standard input")

// barrierPasswordSource is the one way a barrier password enters the CLI as
// a value the process itself resolves (as opposed to the interactive
// terminal prompt every caller of resolveBarrierPassword also offers as a
// last resort). It follows the PIN convention (pin_input.go): standard input
// or the environment, never a "--barrier-password" value flag -- a value on
// the command line is visible to every other process on the host via 'ps'
// (go-xkms#1209). Every CLI command that may open a barrier-backed store
// shares this one source (oath, backup, device oath-sync, fido2, extension
// serve, secret-service, the device commands) so an operator learns it once.
var barrierPasswordSource = pinSource{
	label:      "barrier password",
	stdinFlag:  "barrier-password-stdin",
	envVar:     "XKEY_BARRIER_PASSWORD",
	stdinEmpty: ErrBarrierPasswordStdinEmpty,
	stdinRead:  ErrBarrierPasswordStdinRead,
}

// addBarrierPasswordFlags registers --barrier-password-stdin and
// --barrier-password-file on cmd. Every CLI command that may open a
// barrier-backed store shares these two flag names (oath, backup, device
// oath-sync, fido2, extension serve) so XKEY_BARRIER_PASSWORD and an
// interactive prompt -- both handled by resolveBarrierPassword -- work
// identically everywhere.
func addBarrierPasswordFlags(cmd *cobra.Command) {
	barrierPasswordSource.addFlags(cmd)
	cmd.Flags().String("barrier-password-file", "", "Read barrier password from file (first line)")
}

// addBarrierPasswordPersistentFlags declares the barrier password flags on
// cmd's persistent flag set, so every subcommand of a group inherits them.
func addBarrierPasswordPersistentFlags(cmd *cobra.Command) {
	barrierPasswordSource.addPersistentFlags(cmd)
	cmd.PersistentFlags().String("barrier-password-file", "", "Read barrier password from file (first line)")
}

// openBarrierBackend unseals the xkey barrier for a one-shot or long-running
// headless CLI command and returns it as a storage.Backend. It shares the
// exact unseal mechanics the GUI and `xkey extension serve` already use: the
// strategy recorded in the barrier's own root key (readBarrierStrategy)
// selects the unseal method, and BarrierService.Unseal performs it.
//
// password must already be resolved by the caller: resolveBarrierPassword
// for oath/backup/device-sync, or the fido2.barrier_password /
// fido2.barrier_password_file viper config for fido2 (createBarrierStorage
// in fido2.go), which predates and does not use resolveBarrierPassword's
// environment-variable and interactive-prompt fallbacks. password is unused
// for the tpm2 strategy, which unseals via tpmDevice/tpmSimulator instead
// (PCR-policy auto-unseal first, then a direct TPM unseal).
func openBarrierBackend(password, dataDir, tpmDevice string, tpmSimulator bool) (xkms.StorageBackend, error) {
	home, err := xhome.Resolve()
	if err != nil {
		return nil, err
	}

	strategy, err := readBarrierStrategy(dataDir)
	if err != nil {
		return nil, err
	}

	barrierSvc := services.NewBarrierService(home.Root, slog.Default())
	barrierSvc.SetDataDir(dataDir)

	if strategy == xkms.StrategyTPM2 {
		if err := unsealTPM2BarrierService(barrierSvc, dataDir, tpmDevice, tpmSimulator); err != nil {
			return nil, err
		}
	} else if err := barrierSvc.Unseal(password, string(strategy)); err != nil {
		return nil, err
	}

	backend := barrierSvc.GetBackend()
	if backend == nil {
		return nil, ErrBarrierBackendUnavailable
	}
	return backend, nil
}

// unsealTPM2BarrierService unseals a tpm2-strategy barrier for a one-shot or
// long-running headless CLI command (oath, backup, the OIDC token store,
// fido2): TPM-policy auto-unseal first (see `xkey tpm policy
// auto-unseal`), then a direct TPM unseal. Both need the TPM transport
// to stay live for as long as the returned barrier-backed store is used, so
// unlike `xkey extension serve` (which threads the returned closer through
// to an explicit shutdown defer, since it is a daemon expected to run for a
// long time and receive a graceful stop signal), this deliberately never
// closes it: every caller here is a single process that exits when its
// command finishes, and the OS reclaims the device handle at exit.
func unsealTPM2BarrierService(barrierSvc *services.BarrierService, dataDir, tpmDevice string, tpmSimulator bool) error {
	logger := slog.Default()

	unsealed, _, autoErr := tryBarrierPolicyAutoUnseal(context.Background(), logger, barrierSvc, dataDir, xkms.StrategyTPM2, tpmDevice, tpmSimulator)
	if autoErr != nil {
		logger.Warn("barrier TPM-policy auto-unseal failed, falling back to direct TPM unseal", "error", autoErr)
	} else if unsealed {
		logger.Info("barrier auto-unsealed through the TPM auto-unseal policy")
		return nil
	}

	tpm, _ := probeTPMModule(logger, dataDir, tpmDevice, tpmSimulator)
	if tpm == nil {
		return ErrBarrierStoreTPMUnavailable
	}
	barrierSvc.SetTPMSealerFunc(func() xkms.Sealer { return tpm })
	return barrierSvc.Unseal("", string(xkms.StrategyTPM2))
}

// resolveSecretStoreBackend is the CLI's single "is the barrier initialised?
// open it, or warn" decision for a command that persists secrets outside the
// GUI process. `xkey oath`, `xkey backup`, and `xkey device oath-sync` all
// call this instead of independently deciding whether to trust a barrier, so
// none of them can drift into a silent plaintext fallback.
//
// storeName names the store in the emitted warning (e.g. "OATH") so an
// operator can tell which store it is about.
//
// Returns (backend, true, nil) when a barrier is initialized and was opened:
// the caller builds its store on backend (e.g. oath.NewBackendStore) instead
// of a plain file. Returns (nil, false, nil) when no barrier is initialized
// at all: this function has already logged the one unencrypted-storage
// warning naming storeName, and the caller falls back to its historical
// plain file store. Returns (nil, false, err) when a barrier IS initialized
// but could not be opened: a typed refusal (ErrBarrierStoreOpenFailed),
// never a silent downgrade to plaintext.
func resolveSecretStoreBackend(cmd *cobra.Command, dataDir, storeName string, log *slog.Logger) (xkms.StorageBackend, bool, error) {
	if !barrierRootKeyExists(dataDir) {
		log.Warn("store is unencrypted at rest; run \"xkey barrier init\" to encrypt it",
			"store", storeName)
		return nil, false, nil
	}

	password, err := resolveBarrierPassword(cmd)
	if err != nil {
		return nil, false, &SentinelCauseError{Sentinel: ErrBarrierStoreOpenFailed, Cause: err}
	}

	backend, err := openBarrierBackend(password, dataDir, "", false)
	if err != nil {
		return nil, false, &SentinelCauseError{Sentinel: ErrBarrierStoreOpenFailed, Cause: err}
	}

	return backend, true, nil
}
