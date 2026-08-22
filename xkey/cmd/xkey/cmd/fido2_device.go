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
	"encoding/base64"
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

	// Decode the stored Noise keys
	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		return nil, errors.Join(ErrFIDO2DeviceBackendCreationFailed, err)
	}

	localPrivateKey, err := base64.StdEncoding.DecodeString(device.LocalNoisePrivateKey)
	if err != nil {
		return nil, errors.Join(ErrFIDO2DeviceBackendCreationFailed, err)
	}

	// The decoded scalar is a plain heap slice. reconstructStaticKey copies it
	// into protected memory but cannot wipe the caller's copy, so wipe it here
	// rather than leave a private key sitting in garbage-collected memory.
	//
	// Registered immediately after the decode, before any other validation:
	// every return between the decode and this defer abandons the raw Noise
	// private scalar on the ordinary heap.
	defer phone.WipeBytes(localPrivateKey)

	// Decode device fingerprint for prologue binding (trusted device
	// verification). A stored-but-malformed value is refused rather than
	// treated as "no fingerprint configured" — see
	// phone.DecodeDeviceFingerprint.
	//
	// Validated HERE, before reconstructStaticKey, and not at its point of
	// use below: this is pure config validation with nothing to release,
	// whereas every return after reconstructStaticKey abandons protected
	// pages that only PhoneKeyBackend's ownership transfer frees.
	deviceFingerprint, err := phone.DecodeDeviceFingerprint(device.DeviceFingerprint)
	if err != nil {
		logger.Error("stored device fingerprint is invalid; refusing to build a backend without identity binding",
			slog.String("error", err.Error()),
		)
		return nil, errors.Join(ErrFIDO2DeviceBackendCreationFailed, err)
	}

	// Reconstruct the local static key from the stored private key
	localStaticKey, err := reconstructStaticKey(localPrivateKey)
	if err != nil {
		return nil, errors.Join(ErrFIDO2DeviceBackendCreationFailed, err)
	}

	// Create phone backend configuration
	// Note: DeviceAddress is the saved address, but the backend will scan for
	// the current address since Android rotates its BLE address (RPA) for privacy.
	// Device identity is verified via the Noise protocol using ExpectedRemoteStatic,
	// and the device fingerprint enables prologue binding for trusted device verification.
	backendCfg := &phone.PhoneKeyBackendConfig{
		DeviceAddress: savedAddress,
		// This helper hands the backend to its caller and keeps nothing, so
		// the backend has to own the key or it would never be released.
		LocalStaticKey:            localStaticKey,
		OwnsStaticKey:             true,
		ExpectedRemoteStatic:      remotePublicKey,
		ExpectedDeviceFingerprint: deviceFingerprint,
		ScanTimeout:               30 * time.Second,
		ConnectTimeout:            10 * time.Second,
		OperationTimeout:          60 * time.Second,
		Logger:                    logger,
	}

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

// reconstructStaticKey rebuilds a Noise static key pair from the stored
// private key bytes, in protected memory. It is a thin wrapper over
// phone.LoadStaticKey, which owns the derivation; the length check stays here
// only to keep the caller's error message specific.
//
// The returned key is the caller's, and the backend built from it reads its
// protected pages for as long as that backend is open.
func reconstructStaticKey(privateKey []byte) (*phone.StaticKey, error) {
	if len(privateKey) != phone.NoiseKeySize {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid private key length: expected %d, got %d", phone.NoiseKeySize, len(privateKey))}
	}

	key, err := phone.LoadStaticKey(privateKey)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to derive public key", Err: err}
	}
	return key, nil
}
