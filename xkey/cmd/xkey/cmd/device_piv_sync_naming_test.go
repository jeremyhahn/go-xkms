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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pivDeviceListCommand returns a bare command carrying the same flags the
// real pivDeviceListCmd registers in init(), so runPIVDeviceList can be
// driven directly without touching the package-level singleton another test
// may have flags set on.
func pivDeviceListCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "phone-list"}
	cmd.Flags().String("device", "", "")
	cmd.Flags().Duration("timeout", 0, "")
	return cmd
}

// TestRunPIVDeviceList_RefusesAmbiguousDeviceName pins #1315: two paired
// records sharing a name must refuse `piv phone-list` instead of silently
// listing whichever record's slots happen to be first in the file.
func TestRunPIVDeviceList_RefusesAmbiguousDeviceName(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{
			{Name: "A", Address: "11:22:33:44:55:66"},
			{Name: "A", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}))

	cmd := pivDeviceListCommand(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "device", "A"))

	err := runPIVDeviceList(cmd, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNameAmbiguous)
}
