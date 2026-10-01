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

package pairing

import (
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpmdev"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TPM enrollment defaults.
const (
	// DefaultTPMEnrollerDevice is the Linux TPM resource manager node the
	// enrollment TPM is opened from when no device path is configured.
	DefaultTPMEnrollerDevice = "/dev/tpmrm0"

	// DefaultTPMEnrollerHash is the hash algorithm the enrollment TPM is
	// opened with. TCG-CSR-IDEVID binds the IDevID to the IAK and the IAK to
	// the EK over SHA-256.
	DefaultTPMEnrollerHash = "SHA-256"
)

// defaultTPMEnrollerDevice is DefaultTPMEnrollerDevice by default. It is a
// variable, rather than a direct reference to the constant, so tests can
// exercise the zero-value Device path deterministically instead of depending
// on whether the test host happens to have a real TPM node at that path.
var defaultTPMEnrollerDevice = DefaultTPMEnrollerDevice

// TPMEnrollerCloser is a TPMEnroller that owns an open TPM device handle.
// OpenTPMEnroller returns one; close it when the bridge it was opened for
// shuts down.
type TPMEnrollerCloser interface {
	TPMEnroller
	io.Closer
}

// TPMEnrollerConfig describes how the host TPM is opened for TCG/IDevID
// device enrollment.
type TPMEnrollerConfig struct {
	// Device is the TPM device path, either a character device such as
	// /dev/tpmrm0 or a Unix socket path ending in ".sock" for a software
	// TPM. Empty means DefaultTPMEnrollerDevice.
	Device string

	// Hash is the TPM hash algorithm name. Empty means
	// DefaultTPMEnrollerHash.
	Hash string

	// PlatformPCRBank names the PCR bank the platform policy digest is
	// computed over. Empty means the pkg/tpm2 default, which is correct on
	// every TPM that has its SHA-256 bank allocated — the common case.
	//
	// It is exposed because it is not derived from Hash: a fleet that has
	// disabled the SHA-256 bank fails every EK read while computing the
	// policy digest, and without this there is no way to correct it.
	PlatformPCRBank string

	// Logger receives the single startup line that says whether device
	// enrollment is available on this host and, when it is not, why. If nil,
	// slog.Default() is used.
	Logger *slog.Logger
}

// OpenTPMEnroller opens this host's TPM so a Bridge can answer the TCG/IDevID
// enrollment methods, and reports the outcome to the logger exactly once.
//
// Enrollment is optional, so the two ways it can be unavailable are reported
// as errors the caller is expected to tolerate rather than propagate. A
// laptop without a usable TPM must still pair, sync and serve every other
// remote.* method:
//
//   - ErrTPMNotConfigured: this host has no TPM. The device node does not
//     exist, so the fact is logged at INFO — it is a capability this machine
//     does not have, not a fault.
//   - ErrTPMUnavailable: a TPM is present but could not be opened. On Linux
//     this is usually a permissions problem on the device node, so the cause
//     and the path are logged at WARN and the cause travels with the returned
//     error for callers that want to relay it.
//
// In both cases the returned enroller is nil, which is what BridgeConfig.TPM
// expects when enrollment is not available.
func OpenTPMEnroller(config *TPMEnrollerConfig) (TPMEnrollerCloser, error) {
	if config == nil {
		config = &TPMEnrollerConfig{}
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	device := config.Device
	if device == "" {
		device = defaultTPMEnrollerDevice
	}
	hash := config.Hash
	if hash == "" {
		hash = DefaultTPMEnrollerHash
	}

	if _, err := os.Stat(device); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			logger.Info("no TPM on this host; TCG device enrollment is unavailable",
				slog.String("device", device))
			return nil, ErrTPMNotConfigured
		}
		return nil, unreachableTPM(logger, device, err)
	}

	// Everything except the device and the hash comes from the pkg/tpm2
	// defaults, so the enrollment TPM agrees with the rest of xkey on the EK
	// handle, the IAK and IDevID profiles and the platform PCR bank. Building
	// a bare Config instead would zero PlatformPCRBank and every EK read would
	// fail computing the platform policy digest. UseSimulator defaults to true
	// and must be cleared for the device path to be taken at all.
	tpmConfig := xkms.DefaultTPMConfig
	tpmConfig.Device = device
	tpmConfig.Hash = hash
	tpmConfig.UseSimulator = false
	if config.PlatformPCRBank != "" {
		tpmConfig.PlatformPCRBank = config.PlatformPCRBank
	}

	tpm, err := xkms.NewTPM2(&xkms.TPMParams{
		Config: &tpmConfig,
		Logger: logger,
	})
	if err != nil {
		// NewTPM2 can hand back a partially initialized TPM alongside its
		// error; leaving it open would hold the device handle for the life of
		// the process.
		if tpm != nil {
			if closeErr := tpm.Close(); closeErr != nil {
				logger.Warn("failed to close partially initialized TPM handle",
					slog.String("device", device),
					slog.String("error", closeErr.Error()))
			}
		}
		return nil, unreachableTPM(logger, device, deviceOpenCause(logger, device, err))
	}

	logger.Info("TPM opened for TCG device enrollment", slog.String("device", device))
	return tpm, nil
}

// unreachableTPM logs why a TPM that is present could not be used and returns
// the sentinel with the cause attached.
func unreachableTPM(logger *slog.Logger, device string, cause error) error {
	logger.Warn("this host has a TPM but xkey cannot reach it; TCG device enrollment is unavailable",
		slog.String("device", device),
		slog.String("error", cause.Error()))
	return &SentinelCauseError{Sentinel: ErrTPMUnavailable, Cause: cause}
}

// deviceOpenCause recovers the real reason a device node would not open.
// pkg/tpm2 collapses every open failure into ErrOpeningDevice, which does not
// tell an operator whether the problem is permissions, a busy device or a
// missing driver. Re-stat'ing the node is not enough — the node exists — so
// the open is repeated purely to read the errno, and the handle is closed
// immediately. Every other error is already specific and passes through.
func deviceOpenCause(logger *slog.Logger, device string, err error) error {
	if !errors.Is(err, xkms.ErrTPMOpeningDevice) {
		return err
	}
	probe, probeErr := tpmdev.Open(device)
	if probeErr != nil {
		return probeErr
	}
	if closeErr := probe.Close(); closeErr != nil {
		logger.Warn("failed to close TPM device probe handle",
			slog.String("device", device),
			slog.String("error", closeErr.Error()))
	}
	return err
}
