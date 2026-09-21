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
)

// addBarrierPasswordFlags registers --barrier-password and
// --barrier-password-file on cmd. Every CLI command that may open a
// barrier-backed store shares these two flag names (oath, backup, device
// oath-sync, fido2, extension serve) so XKEY_BARRIER_PASSWORD and an
// interactive prompt -- both handled by resolveBarrierPassword -- work
// identically everywhere.
func addBarrierPasswordFlags(cmd *cobra.Command) {
	cmd.Flags().String("barrier-password", "", "Barrier password (for barrier-encrypted storage)")
	cmd.Flags().String("barrier-password-file", "", "Read barrier password from file (first line)")
}

// openBarrierBackend unseals the xkey barrier for a one-shot CLI command and
// returns it as a storage.Backend. It shares the exact unseal mechanics the
// GUI and `xkey extension serve` already use: the strategy recorded in the
// barrier's own root key (readBarrierStrategy) selects the unseal method,
// and BarrierService.Unseal performs it.
//
// password must already be resolved by the caller: resolveBarrierPassword
// for oath/backup/device-sync, or the fido2.barrier_password /
// fido2.barrier_password_file viper config for fido2 (createBarrierStorage
// in fido2.go), which predates and does not use resolveBarrierPassword's
// environment-variable and interactive-prompt fallbacks.
func openBarrierBackend(password, dataDir string) (xkms.StorageBackend, error) {
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

	if err := barrierSvc.Unseal(password, string(strategy)); err != nil {
		return nil, err
	}

	backend := barrierSvc.GetBackend()
	if backend == nil {
		return nil, ErrBarrierBackendUnavailable
	}
	return backend, nil
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

	backend, err := openBarrierBackend(password, dataDir)
	if err != nil {
		return nil, false, &SentinelCauseError{Sentinel: ErrBarrierStoreOpenFailed, Cause: err}
	}

	return backend, true, nil
}
