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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func deviceShareTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")
	cmd.Flags().String("label", "", "")
	cmd.Flags().Duration("timeout", 50*time.Millisecond, "")
	return cmd
}

func deviceImportTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("backend", "software", "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Duration("timeout", 50*time.Millisecond, "")
	return cmd
}

func TestRunDeviceShare_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	err := runDeviceShare(deviceShareTestCmd(), []string{"software", "my-key"})
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunDeviceShare_DeviceNotFound(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	cmd := deviceShareTestCmd()
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "device", "Nonexistent"))
	err := runDeviceShare(cmd, []string{"software", "my-key"})
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

func TestRunDeviceImport_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	err := runDeviceImport(deviceImportTestCmd(), []string{"my-key"})
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunDeviceImport_DeviceNotFound(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	cmd := deviceImportTestCmd()
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "device", "Nonexistent"))
	err := runDeviceImport(cmd, []string{"my-key"})
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

func TestRunDeviceImport_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	err := runDeviceImport(deviceImportTestCmd(), []string{"my-key"})
	require.ErrorIs(t, err, ErrShareConnectFailed)
}

// TestLoadSharedKeyMaterial_NoXKMSdListening exercises the real dial path
// against xkmsd's built-in default unix-socket address, which is a relative
// path that never resolves inside a test's working directory: the connect
// fails immediately, so this never touches a real xkmsd or the filesystem
// outside reading "no such file".
func TestLoadSharedKeyMaterial_NoXKMSdListening(t *testing.T) {
	deviceInfoTestHome(t)

	_, err := loadSharedKeyMaterial("software", "my-key", false, discardLogger())
	require.ErrorIs(t, err, ErrShareKeyLoadFailed)
}
