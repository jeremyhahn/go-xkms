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

//go:build ble

package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRunDeviceAttestDevice_WithinGracePeriodSkipsReattestation covers the
// early "already attested recently" return: it must report and exit before
// unsealing any pairing key or touching Bluetooth at all.
func TestRunDeviceAttestDevice_WithinGracePeriodSkipsReattestation(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{
			Name:                      "A",
			Address:                   "11:22:33:44:55:66",
			LastDeviceAttestationTime: time.Now().Add(-time.Minute),
		}},
	}))

	err := runDeviceAttestDevice(attestDeviceCommand(t), nil)
	require.NoError(t, err)
}

// TestRunDeviceAttestDevice_DeviceNotFound covers the --device filter miss,
// short of any barrier or Bluetooth work.
func TestRunDeviceAttestDevice_DeviceNotFound(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{Name: "A", PairedAt: time.Now()}},
	}))

	cmd := attestDeviceCommand(t)
	require.NoError(t, cmd.Flags().Set("device", "Nonexistent"))

	err := runDeviceAttestDevice(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

// TestRunDeviceAttestDevice_DefaultDeviceNotFound covers the DevicesConfig
// pointing at a default device name that is no longer in the list.
func TestRunDeviceAttestDevice_DefaultDeviceNotFound(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices:       []PairedDevice{{Name: "A", PairedAt: time.Now()}},
		DefaultDevice: "Ghost",
	}))

	err := runDeviceAttestDevice(attestDeviceCommand(t), nil)
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

// TestRunDeviceAttestDevice_ForceBypassesGracePeriod covers --force reaching
// past the grace-period skip into the real unseal step, failing there
// because the stored key is not valid base64 -- short of any BLE work.
func TestRunDeviceAttestDevice_ForceBypassesGracePeriod(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{brokenNoiseKeyDevice("A")},
	}))

	cmd := attestDeviceCommand(t)
	require.NoError(t, cmd.Flags().Set("force", "true"))

	err := runDeviceAttestDevice(cmd, nil)
	require.ErrorIs(t, err, ErrAttestDeviceVerifyFailed)
}
