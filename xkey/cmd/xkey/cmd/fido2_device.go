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

//go:build ble

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// createFIDO2PhoneKeyBackend creates a phone-backed FIDO2 key backend.
func createFIDO2PhoneKeyBackend(cfg *FIDO2Config, logger *slog.Logger) (keybackend.FIDO2KeyBackend, error) {
	logger.Info("initializing phone key backend")

	// Load phone pairing configuration
	phoneCfg, err := loadDevicesConfig()
	if err != nil {
		return nil, errors.Join(ErrFIDO2DeviceConfigRequired, err)
	}

	// Find the device to use
	var device *PairedDevice
	deviceIndex := -1
	if cfg.PhoneDevice != "" {
		// Look for specific device by name or address
		for i := range phoneCfg.Devices {
			if phoneCfg.Devices[i].Name == cfg.PhoneDevice ||
				phoneCfg.Devices[i].Address == cfg.PhoneDevice {
				device = &phoneCfg.Devices[i]
				deviceIndex = i
				break
			}
		}
		if device == nil {
			return nil, &DetailError{Err: ErrFIDO2DeviceBackendCreationFailed, Detail: fmt.Sprintf(": device '%s' not found in paired devices", cfg.PhoneDevice)}
		}
	} else if phoneCfg.DefaultDevice != "" {
		// Use default device
		for i := range phoneCfg.Devices {
			if phoneCfg.Devices[i].Name == phoneCfg.DefaultDevice {
				device = &phoneCfg.Devices[i]
				deviceIndex = i
				break
			}
		}
	}

	if device == nil {
		if len(phoneCfg.Devices) > 0 {
			device = &phoneCfg.Devices[0]
			deviceIndex = 0
		} else {
			return nil, ErrFIDO2DeviceConfigRequired
		}
	}

	savedAddress := device.Address
	logger.Info("using paired phone device",
		slog.String("name", device.Name),
		slog.String("saved_address", savedAddress),
	)

	// Every identity check this record supports, assembled in one place:
	// the pairing keys, the stored fingerprint that binds the prologue, and
	// the #129 liveness requirement. Building the configuration here instead
	// is how four other commands ended up without the fingerprint and, later,
	// without the liveness proof (Codex, #124).
	backendCfg, err := newPairedDeviceBackendConfig(device, 60*time.Second, logger)
	if err != nil {
		return nil, errors.Join(ErrFIDO2DeviceBackendCreationFailed, err)
	}

	// FIDO2's own connection shape, layered on top rather than duplicated
	// beside it. Android rotates its BLE address (RPA), so the saved address is
	// a starting point and the backend rescans; the longer connect window is
	// this surface's, because a FIDO2 assertion is waiting on a human.
	backendCfg.DeviceAddress = savedAddress
	backendCfg.ScanTimeout = 30 * time.Second
	backendCfg.ConnectTimeout = 10 * time.Second

	backend, err := phone.NewPhoneKeyBackend(backendCfg)
	if err != nil {
		return nil, errors.Join(ErrFIDO2DeviceBackendCreationFailed, err)
	}

	// Pre-connect to the phone to:
	// 1. Fail early if the phone is not available
	// 2. Update the saved address if Android rotated its RPA
	logger.Info("connecting to phone...")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := backend.Connect(ctx); err != nil {
		_ = backend.Close()
		return nil, errors.Join(ErrFIDO2DeviceBackendCreationFailed, &WrappedError{Msg: "phone connection failed", Err: err})
	}

	// Check if the address changed (Android RPA rotation)
	connectedAddress := backend.ConnectedAddress()
	if connectedAddress != "" && connectedAddress != savedAddress {
		logger.Info("phone BLE address changed (Android RPA rotation), updating config",
			slog.String("old_address", savedAddress),
			slog.String("new_address", connectedAddress),
		)

		// Update the config with the new address
		if deviceIndex >= 0 && deviceIndex < len(phoneCfg.Devices) {
			phoneCfg.Devices[deviceIndex].Address = connectedAddress
			if err := saveDevicesConfig(phoneCfg); err != nil {
				// Non-fatal - log warning but continue
				logger.Warn("failed to save updated phone config",
					slog.String("error", err.Error()),
				)
			} else {
				logger.Info("phone config updated with new address")
			}
		}
	}

	logger.Info("phone key backend ready",
		slog.String("device_name", device.Name),
		slog.String("device_address", connectedAddress),
	)

	// Optionally wire xkmsd bridge for bidirectional key sharing.
	bridged, err := connectXKMSdBridge(backend, logger)
	if err != nil {
		_ = backend.Close()
		return nil, errors.Join(ErrFIDO2DeviceBackendCreationFailed, err)
	}
	if bridged != nil {
		return bridged, nil
	}

	return backend, nil
}
