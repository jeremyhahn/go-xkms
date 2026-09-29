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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunDeviceListen_RefusesEmptyPinnedKey pins #1307: a paired-device
// record whose NoisePublicKey decodes to nothing usable must refuse before
// the peripheral is ever built, not silently listen with nothing pinned.
func TestRunDeviceListen_RefusesEmptyPinnedKey(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{
			Name:           "A",
			Address:        "11:22:33:44:55:66",
			NoisePublicKey: "",
		}},
	}))

	err := runDeviceListen(listenCommand(t), nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDevicePinInvalid)
}

// TestRunDeviceListen_RefusesWrongLengthPinnedKey covers a corrupt (but
// non-empty) stored key, not only the empty case.
func TestRunDeviceListen_RefusesWrongLengthPinnedKey(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{
			Name:           "A",
			Address:        "11:22:33:44:55:66",
			NoisePublicKey: "dG9vc2hvcnQ=", // base64("tooshort"), not NoiseKeySize bytes
		}},
	}))

	err := runDeviceListen(listenCommand(t), nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDevicePinInvalid)
}

// TestRunDeviceListen_RefusesAmbiguousDeviceName pins #1307: two paired
// records sharing a name must refuse the lookup rather than silently
// listening under whichever record's key happens to be first in the file.
func TestRunDeviceListen_RefusesAmbiguousDeviceName(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{
			{Name: "A", Address: "11:22:33:44:55:66", NoisePublicKey: "keyA"},
			{Name: "A", Address: "AA:BB:CC:DD:EE:FF", NoisePublicKey: "keyB"},
		},
	}))

	cmd := listenCommand(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "device", "A"))

	err := runDeviceListen(cmd, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNameAmbiguous)
}
