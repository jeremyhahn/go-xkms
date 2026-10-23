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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// c704gPairDevices writes a devices.yaml under a temporary HOME. Each
// device's record is broken in a different way, so the error that comes back
// shows which device the backend picked before it refused.
func c704gPairDevices(t *testing.T, defaultDevice string, devices ...PairedDevice) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: devices, DefaultDevice: defaultDevice}))
}

// c704gChosenDevice has an undecodable fingerprint, so picking it ends in
// phone.ErrInvalidDeviceFingerprint.
func c704gChosenDevice(t *testing.T, name, address string) PairedDevice {
	t.Helper()
	return PairedDevice{
		Name:                 name,
		Address:              address,
		NoisePublicKey:       validNoisePublicKeyForTest(t),
		LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t),
		DeviceFingerprint:    "not-hex",
	}
}

// c704gDecoyDevice has an undecodable phone key, so picking it fails without
// a fingerprint error.
func c704gDecoyDevice(t *testing.T, name, address string) PairedDevice {
	t.Helper()
	return PairedDevice{
		Name:                 name,
		Address:              address,
		NoisePublicKey:       "!!!",
		LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t),
	}
}

func TestCreateFIDO2PhoneKeyBackend_PicksTheDevice(t *testing.T) {
	tests := []struct {
		name          string
		phoneDevice   string
		defaultDevice string
		devices       func(t *testing.T) []PairedDevice
	}{
		{
			name:        "by name",
			phoneDevice: "Pixel",
			devices: func(t *testing.T) []PairedDevice {
				return []PairedDevice{c704gDecoyDevice(t, "Galaxy", "AA:00"), c704gChosenDevice(t, "Pixel", "AA:01")}
			},
		},
		{
			name:        "by address",
			phoneDevice: "AA:01",
			devices: func(t *testing.T) []PairedDevice {
				return []PairedDevice{c704gDecoyDevice(t, "Galaxy", "AA:00"), c704gChosenDevice(t, "Pixel", "AA:01")}
			},
		},
		{
			name:          "the default device",
			defaultDevice: "Pixel",
			devices: func(t *testing.T) []PairedDevice {
				return []PairedDevice{c704gDecoyDevice(t, "Galaxy", "AA:00"), c704gChosenDevice(t, "Pixel", "AA:01")}
			},
		},
		{
			name:          "the first device when the default is gone",
			defaultDevice: "Removed",
			devices: func(t *testing.T) []PairedDevice {
				return []PairedDevice{c704gChosenDevice(t, "Pixel", "AA:01"), c704gDecoyDevice(t, "Galaxy", "AA:00")}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c704gPairDevices(t, tt.defaultDevice, tt.devices(t)...)

			backend, err := createFIDO2PhoneKeyBackend(&FIDO2Config{PhoneDevice: tt.phoneDevice}, quietTestLogger())

			assert.Nil(t, backend)
			require.ErrorIs(t, err, ErrFIDO2DeviceBackendCreationFailed)
			assert.ErrorIs(t, err, phone.ErrInvalidDeviceFingerprint, "the chosen device's record was used")
		})
	}
}

func TestCreateFIDO2PhoneKeyBackend_UnknownDevice(t *testing.T) {
	c704gPairDevices(t, "", c704gChosenDevice(t, "Pixel", "AA:01"))

	backend, err := createFIDO2PhoneKeyBackend(&FIDO2Config{PhoneDevice: "Galaxy"}, quietTestLogger())

	assert.Nil(t, backend)
	require.ErrorIs(t, err, ErrFIDO2DeviceBackendCreationFailed)
	assert.ErrorContains(t, err, "device 'Galaxy' not found")
}

func TestCreateFIDO2PhoneKeyBackend_NoPairedDevices(t *testing.T) {
	c704gPairDevices(t, "")

	backend, err := createFIDO2PhoneKeyBackend(&FIDO2Config{}, quietTestLogger())

	assert.Nil(t, backend)
	assert.ErrorIs(t, err, ErrFIDO2DeviceConfigRequired)
}

func TestCreateFIDO2PhoneKeyBackend_UnreadableDevicesConfig(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv("SUDO_USER", "")

		_, err := createFIDO2PhoneKeyBackend(&FIDO2Config{}, quietTestLogger())

		assert.ErrorIs(t, err, ErrFIDO2DeviceConfigRequired)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("corrupt", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("SUDO_USER", "")
		require.NoError(t, os.MkdirAll(filepath.Join(home, ".xkey"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(home, ".xkey", "devices.yaml"), []byte("devices: [\n"), 0o600))

		_, err := createFIDO2PhoneKeyBackend(&FIDO2Config{}, quietTestLogger())

		assert.ErrorIs(t, err, ErrFIDO2DeviceConfigRequired)
	})
}
