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

package localtpm

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

// DeviceParams open the host's TPM with its own key store.
type DeviceParams struct {
	// DataDir is the client's data directory. The TPM's own key store is
	// kept in "<DataDir>/tpm".
	DataDir string

	// Device is the TPM device path (e.g. /dev/tpmrm0), or a TPM reached
	// over TCP, "tcp://host:port" (a swtpm command port; its control port is
	// the next one). Ignored with UseSimulator.
	Device string

	// UseSimulator runs the in-process TPM simulator instead of a device.
	UseSimulator bool

	// Logger receives lifecycle events. Nil selects slog.Default().
	Logger *slog.Logger
}

// tcpDevicePrefix marks a DeviceParams.Device reached over TCP.
const tcpDevicePrefix = "tcp://"

// DeviceError reports a TPM device that does not exist.
type DeviceError struct {
	Device string
	Err    error
}

// Error implements the error interface.
func (e *DeviceError) Error() string {
	return "localtpm: tpm device " + e.Device + " not found: " + e.Err.Error()
}

// Unwrap returns the stat failure.
func (e *DeviceError) Unwrap() error { return e.Err }

// Device is the host's TPM and its own key store: the persistent store of
// the objects it creates under the system scope.
type Device struct {
	tpm     tpm2.TrustedPlatformModule
	factory *store.StorageFactory
}

// TPM returns the host's TPM.
func (d *Device) TPM() tpm2.TrustedPlatformModule { return d.tpm }

// Keys returns the TPM's own key store.
func (d *Device) Keys() store.KeyBackend { return d.factory.KeyBackend() }

// Close closes the TPM and then its key store.
func (d *Device) Close() error {
	return errors.Join(d.tpm.Close(), d.factory.Close())
}

// OpenDevice opens the host's TPM -- the device, a TPM over TCP, or the
// in-process simulator -- with its key store at "<DataDir>/tpm". An unprovisioned TPM
// (tpm2.ErrNotInitialized) is opened as it is: provisioning is an operator
// action (`xkmsd init`, `xkey tpm provision`).
func OpenDevice(p DeviceParams) (*Device, error) {
	if p.DataDir == "" {
		return nil, ErrNoDataDir
	}
	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}
	tcpAddress, overTCP := strings.CutPrefix(p.Device, tcpDevicePrefix)
	if !p.UseSimulator && !overTCP {
		if _, err := os.Stat(p.Device); err != nil {
			return nil, &DeviceError{Device: p.Device, Err: err}
		}
	}
	factory, err := store.NewStorageFactory(logger, filepath.Join(p.DataDir, "tpm"))
	if err != nil {
		return nil, err
	}
	cfg := tpm2.DefaultConfig
	cfg.UseSimulator = p.UseSimulator
	if overTCP && !p.UseSimulator {
		cfg.CommandAddress = tcpAddress
	} else {
		cfg.Device = p.Device
	}
	tpm, err := tpm2.NewTPM2(&tpm2.Params{
		Logger:  logger,
		Config:  &cfg,
		Backend: factory.KeyBackend(),
	})
	// ErrNotInitialized only means the EK/IDevID provisioning workflow has
	// not run; the TPM still has a live transport and serves keys under the
	// Platform SRK.
	unprovisioned := errors.Is(err, tpm2.ErrNotInitialized) && tpm != nil
	if err != nil && !unprovisioned {
		if tpm != nil {
			err = errors.Join(err, tpm.Close())
		}
		return nil, errors.Join(err, factory.Close())
	}
	return &Device{tpm: tpm, factory: factory}, nil
}

// Host is the host's TPM, its key store, and the TPM policy service over
// them. Close closes all of them.
type Host struct {
	*Policies
	*Device
}

// Close closes the policy service, then the TPM and its key store.
func (h *Host) Close() error {
	return errors.Join(h.Policies.Close(), h.Device.Close())
}

// OpenHost opens the host's TPM (OpenDevice) and the TPM policy service
// over it (Open) -- the same TPM, stores and service the xkey GUI's local
// mode runs. openStore opens the policy service's stores.
func OpenHost(p DeviceParams, openStore func(dir string) (storage.Backend, error)) (*Host, error) {
	device, err := OpenDevice(p)
	if err != nil {
		return nil, err
	}
	policies, err := Open(Params{
		TPM:       device.TPM(),
		Keys:      device.Keys(),
		DataDir:   p.DataDir,
		OpenStore: openStore,
		Logger:    p.Logger,
	})
	if err != nil {
		return nil, errors.Join(err, device.Close())
	}
	return &Host{Policies: policies, Device: device}, nil
}
