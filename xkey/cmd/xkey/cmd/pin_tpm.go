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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pinstrategy"
)

// openTPMModule opens the TPM — the hardware device at the resolved path,
// or the in-process simulator when useSimulator is true — as a
// xkms.TrustedPlatformModule, tolerating an unprovisioned TPM exactly as
// the barrier strategy's probeTPMSealer does: PlatformKeyStore-backed PIN
// verification only needs the Storage Root Key, not full EK/IAK/IDevID
// provisioning. It is the one TPM-opening primitive shared by the barrier
// (probeTPMSealer) and PIN (newPINTPMProvider) code paths, so the two
// never drift into different TPM configurations.
//
// Returns (nil, nil, err) when no TPM is available; the caller decides
// whether that is fatal (the persisted PIN strategy names tpm2, so
// pinstrategy.Resolve must refuse rather than silently choose a different
// backend) or expected (pinselect's fresh-install auto-selection, which
// treats an unavailable TPM as "prefer the next strategy").
func openTPMModule(logger *slog.Logger, dataDir, device string, useSimulator bool) (xkms.TrustedPlatformModule, io.Closer, error) {
	resolvedDevice := resolveTPMDevice(device)

	// The simulator has no backing device file to stat; only hardware mode
	// requires the device to be present before attempting to open it.
	if !useSimulator {
		if _, err := os.Stat(resolvedDevice); err != nil {
			return nil, nil, &WrappedError{Msg: fmt.Sprintf("tpm device %s not found", resolvedDevice), Err: err}
		}
	}

	tpmDataDir := filepath.Join(dataDir, "tpm")
	factory, err := xkms.NewTPMStorageFactory(logger, tpmDataDir)
	if err != nil {
		return nil, nil, &WrappedError{Msg: "tpm storage factory", Err: err}
	}

	cfg := xkms.DefaultTPMConfig
	cfg.Device = resolvedDevice
	cfg.UseSimulator = useSimulator

	tpm, err := xkms.NewTPM2(&xkms.TPMParams{
		Logger:    logger,
		Config:    &cfg,
		BlobStore: factory.BlobStore(),
		Backend:   factory.KeyBackend(),
	})
	if err != nil {
		// ErrTPMNotInitialized only means the EK/IDevID provisioning workflow
		// has not run; the returned tpm still has a live transport and can
		// serve its PlatformKeyStore (see TPM2.CanSeal). Sealing itself still
		// requires the Platform SRK to be enrolled -- xkms never falls back
		// to the Shared SRK -- which is what probeTPMSealer's caller checks
		// before using this TPM for the barrier strategy.
		if errors.Is(err, xkms.ErrTPMNotInitialized) && tpm != nil {
			return tpm, tpm, nil
		}
		return nil, nil, &WrappedError{Msg: "open tpm", Err: errors.Join(err, factory.Close())}
	}

	return tpm, tpm, nil
}

// newPINTPMProvider builds the pinselect.TPMProvider that `xkey pin` and
// the headless daemon use to decide whether TPM2 governs PIN verification,
// through the same rule (pinstrategy.NewTPMProvider) the xKey GUI's
// guiTPMProvider uses. Unlike the GUI's shared, mutex-serialized
// TPMAccessor, this opens its own short-lived TPM connection: these entry
// points are either a one-shot CLI command or the daemon's own single
// PIN-service init, so there is no cross-service TPM contention to
// serialize.
func newPINTPMProvider(logger *slog.Logger, dataDir, device string, useSimulator, persistedTPM2 bool) xkms.PINTPMProvider {
	return pinstrategy.NewTPMProvider(func() (pinstrategy.PlatformKeyStoreProvider, error) {
		tpm, _, err := openTPMModule(logger, dataDir, device, useSimulator)
		if err != nil {
			return nil, err
		}
		return tpm, nil
	}, persistedTPM2, logger)
}
