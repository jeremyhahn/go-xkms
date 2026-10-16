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
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func attestDeviceCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "attest-device"}
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("force", false, "")
	cmd.Flags().Duration("set-grace-period", 0, "")
	addDeviceBarrierFlags(cmd)
	return cmd
}

// TestRunDeviceAttestDevice_ProceedsWithoutABarrier is the #42 owner ruling
// on this verb: a host with no barrier initialized at all is not refused for
// that reason. It still fails here, but for the ordinary, unrelated reason
// that no devices.yaml exists in the isolated home -- proof the barrier
// check itself let the command continue past it.
func TestRunDeviceAttestDevice_ProceedsWithoutABarrier(t *testing.T) {
	isolateDeviceBarrierHome(t)

	err := runDeviceAttestDevice(attestDeviceCommand(t), nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNotPaired)
	assert.NotErrorIs(t, err, ErrDeviceBarrierNotInitialized,
		"an uninitialized barrier must never be why this command refuses")
}

// TestRunDeviceAttestDevice_RefusesWithWrongBarrierPassword covers the other
// half: a barrier that exists but cannot be unsealed with what was supplied.
func TestRunDeviceAttestDevice_RefusesWithWrongBarrierPassword(t *testing.T) {
	isolateDeviceBarrierHome(t)
	initDeviceBarrier(t, "correct-horse-battery-staple")

	cmd := attestDeviceCommand(t)
	t.Setenv("XKEY_BARRIER_PASSWORD", "wrong")

	err := runDeviceAttestDevice(cmd, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBarrierUnsealFailed)
}

// TestRunDeviceAttestDevice_RefusesAmbiguousDeviceName pins #1315: two
// paired records sharing a name must refuse `device attest-device` instead
// of silently attesting whichever record's key happens to be first in the
// file.
func TestRunDeviceAttestDevice_RefusesAmbiguousDeviceName(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{
			{Name: "A", Address: "11:22:33:44:55:66"},
			{Name: "A", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}))

	cmd := attestDeviceCommand(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "device", "A"))

	err := runDeviceAttestDevice(cmd, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNameAmbiguous)
}

// TestRunDeviceListen_ProceedsWithoutABarrier mirrors
// TestRunDeviceAttestDevice_ProceedsWithoutABarrier for `device listen`.
func TestRunDeviceListen_ProceedsWithoutABarrier(t *testing.T) {
	isolateDeviceBarrierHome(t)

	err := runDeviceListen(listenCommand(t), nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNotPaired)
	assert.NotErrorIs(t, err, ErrDeviceBarrierNotInitialized,
		"an uninitialized barrier must never be why this command refuses")
}

// TestRunDeviceListen_RefusesWithWrongBarrierPassword mirrors the
// attest-device wrong-password gate for `device listen`.
func TestRunDeviceListen_RefusesWithWrongBarrierPassword(t *testing.T) {
	isolateDeviceBarrierHome(t)
	initDeviceBarrier(t, "correct-horse-battery-staple")

	cmd := listenCommand(t)
	t.Setenv("XKEY_BARRIER_PASSWORD", "wrong")

	err := runDeviceListen(cmd, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBarrierUnsealFailed)
}
