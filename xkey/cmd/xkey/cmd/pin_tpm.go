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
	"io"
	"log/slog"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/localtpm"
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
// xkms.ResolvePINBackend must refuse rather than silently choose a different
// backend) or expected (pinselect's fresh-install auto-selection, which
// treats an unavailable TPM as "prefer the next strategy").
func openTPMModule(logger *slog.Logger, dataDir, device string, useSimulator bool) (xkms.TrustedPlatformModule, io.Closer, error) {
	opened, err := openTPMWithKeyStore(logger, dataDir, device, useSimulator)
	if err != nil {
		return nil, nil, err
	}
	tpm := opened.TPM()
	return tpm, opened, nil
}

// openTPMWithKeyStore is openTPMModule's primitive: it opens the TPM with
// its key store at <dataDir>/tpm (localtpm.OpenDevice, the same opener
// xkmsctl uses) and returns both, for callers -- the local TPM policy
// service -- that need the store as well as the TPM.
func openTPMWithKeyStore(logger *slog.Logger, dataDir, device string, useSimulator bool) (*localtpm.Device, error) {
	return localtpm.OpenDevice(tpmDeviceParams(logger, dataDir, device, useSimulator))
}

// tpmDeviceParams are the localtpm parameters of this host's TPM: the
// device at the resolved path, or the in-process simulator.
func tpmDeviceParams(logger *slog.Logger, dataDir, device string, useSimulator bool) localtpm.DeviceParams {
	return localtpm.DeviceParams{
		DataDir:      dataDir,
		Device:       resolveTPMDevice(device),
		UseSimulator: useSimulator,
		Logger:       logger,
	}
}

// newPINTPMProvider builds the pinselect.TPMProvider that `xkey pin` and
// the headless daemon use to decide whether TPM2 governs PIN verification,
// through the same rule (xkms.NewPINTPMProvider) the xKey GUI's
// guiTPMProvider uses. Unlike the GUI's shared, mutex-serialized
// TPMAccessor, this opens its own short-lived TPM connection: these entry
// points are either a one-shot CLI command or the daemon's own single
// PIN-service init, so there is no cross-service TPM contention to
// serialize.
func newPINTPMProvider(logger *slog.Logger, dataDir, device string, useSimulator, persistedTPM2 bool) xkms.PINTPMProvider {
	return xkms.NewPINTPMProvider(func() (xkms.PINPlatformKeyStoreProvider, error) {
		tpm, _, err := openTPMModule(logger, dataDir, device, useSimulator)
		if err != nil {
			return nil, err
		}
		return tpm, nil
	}, persistedTPM2, logger)
}
