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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// phoneCommandRun is one device command that must consult the paired-devices
// file before it reaches for a phone.
type phoneCommandRun struct {
	name string
	run  func(*cobra.Command, []string) error
	args []string
}

// phoneCommandRuns lists the commands that talk to a paired phone. Each one
// refuses to run without a readable pairing record.
func phoneCommandRuns() []phoneCommandRun {
	return []phoneCommandRun{
		{"share", runDeviceShare, []string{"software", "signing-key"}},
		{"import", runDeviceImport, []string{"import-1"}},
		{"oath sync", runOATHSync, nil},
		{"oath push", runOATHPush, []string{"github"}},
		{"oath pull", runOATHPull, nil},
		{"piv list", runPIVDeviceList, nil},
		{"piv pull-cert", runPIVDevicePullCert, []string{"9a"}},
		{"piv generate-key", runPIVDeviceGenerateKey, []string{"9a"}},
		{"attest", runDeviceAttest, []string{"signing-key"}},
		{"info", runDeviceInfo, nil},
	}
}

// writeCorruptDevicesConfig leaves a devices file on disk that is not YAML.
func writeCorruptDevicesConfig(t *testing.T) {
	t.Helper()
	path, err := getDevicesConfigPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("devices: [unterminated"), 0o600))
}

func TestPhoneCommands_CorruptDevicesFileIsALoadFailure(t *testing.T) {
	for _, tc := range phoneCommandRuns() {
		t.Run(tc.name, func(t *testing.T) {
			isolateDeviceBarrierHome(t)
			writeCorruptDevicesConfig(t)
			phone := &fakeDeviceTransport{}
			useFakeTransport(t, phone)

			err := tc.run(&cobra.Command{}, tc.args)
			require.ErrorIs(t, err, ErrDeviceConfigLoadFailed)
			assert.NotErrorIs(t, err, ErrDeviceNotPaired, "an unreadable file is not the same as no pairing")
			assert.False(t, phone.connected, "no phone may be contacted without a pairing record")
		})
	}
}

func TestPhoneCommands_EmptyDevicesFileMeansNotPaired(t *testing.T) {
	for _, tc := range phoneCommandRuns() {
		t.Run(tc.name, func(t *testing.T) {
			isolateDeviceBarrierHome(t)
			require.NoError(t, saveDevicesConfig(&DevicesConfig{}))
			phone := &fakeDeviceTransport{}
			useFakeTransport(t, phone)

			err := tc.run(&cobra.Command{}, tc.args)
			require.ErrorIs(t, err, ErrDeviceNotPaired)
			assert.False(t, phone.connected, "no phone may be contacted without a pairing record")
		})
	}
}

func TestDeviceListings_EmptyDevicesFileReportsNoDevices(t *testing.T) {
	listings := map[string]func(*cobra.Command, []string) error{
		"list":   runDeviceList,
		"status": runDeviceStatus,
	}
	for name, run := range listings {
		t.Run(name, func(t *testing.T) {
			isolateDeviceBarrierHome(t)
			require.NoError(t, saveDevicesConfig(&DevicesConfig{}))

			var out bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&out)
			require.NoError(t, run(cmd, nil))
			assert.Equal(t, "No paired devices.\n", out.String())
		})
	}
}

func TestDeviceListings_CorruptDevicesFileIsALoadFailure(t *testing.T) {
	listings := map[string]func(*cobra.Command, []string) error{
		"list":   runDeviceList,
		"status": runDeviceStatus,
		"unpair": runDeviceUnpair,
	}
	for name, run := range listings {
		t.Run(name, func(t *testing.T) {
			isolateDeviceBarrierHome(t)
			writeCorruptDevicesConfig(t)

			var out bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&out)
			err := run(cmd, []string{"Test Phone"})
			require.ErrorIs(t, err, ErrDeviceConfigLoadFailed)
			assert.NotContains(t, out.String(), "No paired devices.", "a broken file must not read as an empty one")
		})
	}
}
