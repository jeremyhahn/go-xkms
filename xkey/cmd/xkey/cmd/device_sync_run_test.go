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
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
)

// syncTestCmd builds a fresh sync command carrying the production flag set,
// with the given flags applied.
func syncTestCmd(t *testing.T, register func(*cobra.Command), flags map[string]string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{Use: "sync-test"}
	register(cmd)
	require.NoError(t, cmd.Flags().Set("timeout", "5s"))
	for name, value := range flags {
		require.NoError(t, cmd.Flags().Set(name, value))
	}
	return cmd
}

// runSyncMode runs one sync command in the given mode and returns its output.
func runSyncMode(t *testing.T, mode syncMode, flags map[string]string) (string, error) {
	t.Helper()

	cmd := syncTestCmd(t, registerDeviceSyncFlags, flags)
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := runDeviceSyncMode(cmd, mode)
	return out.String(), err
}

// remoteSyncResults answers every store exchange with one new item from the
// phone, and reports what the phone did with the laptop's items.
func remoteSyncResults() map[string]any {
	return map[string]any{
		pairingproto.MethodLocalSyncTrustStore: &pairingproto.LocalSyncTrustStoreResult{Added: 1},
		pairingproto.MethodLocalSyncOATH: &pairingproto.LocalSyncOATHResult{
			Added: 1,
			Remote: []pairingproto.SyncOATHCredential{{
				ID:        "phone-oath",
				Name:      "PhoneOATH",
				Issuer:    "Example",
				Secret:    mustSecretText("GEZDGNBVGY3TQOJQ"),
				Type:      "totp",
				Algorithm: "SHA256",
				Digits:    6,
				Period:    30,
				UpdatedAt: "2026-01-02T03:04:05Z",
			}},
		},
		pairingproto.MethodLocalSyncPasswords: &pairingproto.LocalSyncPasswordsResult{
			Updated: 1,
			Remote: []pairingproto.SyncPassword{{
				ID:       "phone-password",
				Name:     "PhoneEntry",
				Username: "phone-user",
				Password: mustSecretText("phone-secret"),
			}},
		},
	}
}

func TestRunDeviceSyncMode_RequiresAScope(t *testing.T) {
	isolatedBackupHome(t)

	_, err := runSyncMode(t, syncModeBoth, map[string]string{"all": "false"})
	require.ErrorIs(t, err, ErrDeviceSyncNoScope)
}

func TestRunDeviceSyncMode_RequiresAPairedDevice(t *testing.T) {
	isolatedBackupHome(t)

	_, err := runSyncMode(t, syncModeBoth, nil)
	require.ErrorIs(t, err, ErrDeviceNotPaired)

	pairTestDevice(t, "Test Phone")
	_, err = runSyncMode(t, syncModeBoth, map[string]string{"device": "Other Phone"})
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

func TestRunDeviceSyncMode_DryRunCountsLocalItemsWithoutConnecting(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{}
	useFakeTransport(t, transport)

	tests := []struct {
		name   string
		mode   syncMode
		banner string
		counts bool
	}{
		{name: "sync", mode: syncModeBoth, banner: `Would sync with device "Test Phone"`, counts: true},
		{name: "push", mode: syncModePush, banner: `Would push to device "Test Phone"`, counts: true},
		{name: "pull", mode: syncModePull, banner: `Would pull from device "Test Phone"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := runSyncMode(t, tt.mode, map[string]string{"dry-run": "true"})
			require.NoError(t, err, output)

			assert.Contains(t, output, tt.banner)
			assert.Contains(t, output, "[dry-run] Stores: [trust-store oath passwords]")
			if tt.counts {
				assert.Contains(t, output, "trust-store: 1 certificate(s) to send")
				assert.Contains(t, output, "oath: 1 credential(s) to send")
				assert.Contains(t, output, "passwords: 1 entry(s) to send")
			} else {
				assert.NotContains(t, output, "to send", "a pull sends nothing")
			}
		})
	}

	assert.Empty(t, transport.requests, "a dry run must not reach the phone")
	assert.False(t, transport.connected)
}

// TestDeviceSyncEntryPoints_DispatchTheirMode pins that each RunE entry point
// runs its own direction: a swapped wrapper would push when the operator
// asked to pull.
func TestDeviceSyncEntryPoints_DispatchTheirMode(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")
	useFakeTransport(t, &fakeDeviceTransport{})

	tests := []struct {
		name   string
		run    func(*cobra.Command, []string) error
		banner string
	}{
		{"sync", runDeviceSync, `Would sync with device "Test Phone"`},
		{"push", runDeviceSyncPush, `Would push to device "Test Phone"`},
		{"pull", runDeviceSyncPull, `Would pull from device "Test Phone"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := syncTestCmd(t, registerDeviceSyncFlags, map[string]string{"dry-run": "true"})
			var out bytes.Buffer
			cmd.SetOut(&out)

			require.NoError(t, tt.run(cmd, nil), out.String())
			assert.Contains(t, out.String(), tt.banner)
		})
	}
}

func TestRunDeviceSyncMode_SyncExchangesEveryStore(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{results: remoteSyncResults()}
	useFakeTransport(t, transport)

	output, err := runSyncMode(t, syncModeBoth, nil)
	require.NoError(t, err, output)

	require.Len(t, transport.requests, 3)
	trust, ok := transport.requests[0].Params.(*pairingproto.LocalSyncTrustStoreParams)
	require.True(t, ok)
	assert.Len(t, trust.Certificates, 1, "the seeded certificate is sent")
	assert.Equal(t, pairingproto.MethodLocalSyncOATH, transport.requests[1].Method)
	assert.Equal(t, pairingproto.MethodLocalSyncPasswords, transport.requests[2].Method)

	assert.Contains(t, output, `Syncing with device "Test Phone"`)
	assert.Contains(t, output, "trust-store: phone applied 1 added, 0 updated, 0 skipped; locally applied 0 added")
	assert.Contains(t, output, "oath:        phone applied 1 added, 0 updated, 0 skipped; locally applied 1 added")
	assert.Contains(t, output, "passwords:   phone applied 0 added, 1 updated, 0 skipped; locally applied 1 added")
	assert.True(t, transport.closed)

	// The phone's items were merged locally: the next push carries them.
	output, err = runSyncMode(t, syncModePush, map[string]string{"dry-run": "true"})
	require.NoError(t, err, output)
	assert.Contains(t, output, "oath: 2 credential(s) to send")
	assert.Contains(t, output, "passwords: 2 entry(s) to send")

	// ... and the run was recorded for sync-status.
	statusTransport := &fakeDeviceTransport{results: map[string]any{
		pairingproto.MethodLocalSyncStatus: &pairingproto.LocalSyncStatusResult{DeviceID: "phone-1"},
	}}
	useFakeTransport(t, statusTransport)
	output, err = runSyncStatus(t, nil)
	require.NoError(t, err, output)
	assert.NotContains(t, output, "This device:\n  Last sync:  never")
}

func TestRunDeviceSyncMode_PushDiscardsThePhoneReply(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{results: remoteSyncResults()}
	useFakeTransport(t, transport)

	output, err := runSyncMode(t, syncModePush, map[string]string{"oath": "true"})
	require.NoError(t, err, output)

	require.Len(t, transport.requests, 1, "only the selected store is exchanged")
	params, ok := transport.requests[0].Params.(*pairingproto.LocalSyncOATHParams)
	require.True(t, ok)
	require.Len(t, params.Credentials, 1)
	assert.Equal(t, "oath-unit-test", params.Credentials[0].ID)

	assert.Contains(t, output, "oath:        phone applied 1 added, 0 updated, 0 skipped")
	assert.NotContains(t, output, "locally applied")

	output, err = runSyncMode(t, syncModePush, map[string]string{"oath": "true", "dry-run": "true"})
	require.NoError(t, err, output)
	assert.Contains(t, output, "oath: 1 credential(s) to send", "a push must not merge the phone's items")
}

func TestRunDeviceSyncMode_PullSendsNothing(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{results: remoteSyncResults()}
	useFakeTransport(t, transport)

	output, err := runSyncMode(t, syncModePull, map[string]string{"passwords": "true"})
	require.NoError(t, err, output)

	require.Len(t, transport.requests, 1)
	params, ok := transport.requests[0].Params.(*pairingproto.LocalSyncPasswordsParams)
	require.True(t, ok)
	assert.Empty(t, params.Passwords, "a pull must not hand local passwords to the phone")
	assert.Contains(t, output, "passwords:   locally applied 1 added, 0 updated, 0 skipped")
}

func TestRunDeviceSyncMode_ReportsEveryFailedStore(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	results := remoteSyncResults()
	results[pairingproto.MethodLocalSyncPasswords] = "not an object"
	transport := &fakeDeviceTransport{
		results: results,
		rpcErrors: map[string]*pairingproto.RPCError{
			pairingproto.MethodLocalSyncTrustStore: {Code: -32000, Message: "store locked"},
		},
	}
	useFakeTransport(t, transport)

	output, err := runSyncMode(t, syncModeBoth, nil)
	require.ErrorIs(t, err, ErrDeviceSyncFailed)
	assert.Contains(t, err.Error(), "local.syncTrustStore: [-32000] store locked")
	assert.Contains(t, err.Error(), "local.syncPasswords: failed to decode result")

	// The healthy store still synced and is reported.
	assert.Contains(t, output, "oath:        phone applied 1 added")
	assert.Len(t, transport.requests, 3, "one failed store must not stop the others")
}

func TestRunDeviceSyncMode_TransportFailures(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	t.Run("connect", func(t *testing.T) {
		transport := &fakeDeviceTransport{connectErr: errors.New("radio off")}
		useFakeTransport(t, transport)

		_, err := runSyncMode(t, syncModeBoth, nil)
		require.ErrorIs(t, err, ErrDeviceSyncFailed)
		assert.ErrorContains(t, err, "radio off")
		assert.True(t, transport.closed, "the transport is closed even when connect fails")
	})

	t.Run("send", func(t *testing.T) {
		transport := &fakeDeviceTransport{sendErr: errors.New("link dropped")}
		useFakeTransport(t, transport)

		_, err := runSyncMode(t, syncModeBoth, map[string]string{"trust-store": "true"})
		require.ErrorIs(t, err, ErrDeviceSyncFailed)
		assert.ErrorContains(t, err, "link dropped")
	})

	t.Run("dial", func(t *testing.T) {
		require.NoError(t, saveDevicesConfig(&DevicesConfig{
			Devices:       []PairedDevice{brokenNoiseKeyDevice("Broken Phone")},
			DefaultDevice: "Broken Phone",
		}))

		_, err := runSyncMode(t, syncModeBoth, nil)
		require.ErrorIs(t, err, ErrDeviceSyncFailed)
	})
}

// runSyncStatus runs sync-status with the given flags and returns its output.
func runSyncStatus(t *testing.T, flags map[string]string) (string, error) {
	t.Helper()

	cmd := syncTestCmd(t, registerDeviceSyncStatusFlags, flags)
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := runDeviceSyncStatus(cmd, nil)
	return out.String(), err
}

func TestRunDeviceSyncStatus_ReportsBothSides(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	t.Run("with checksums", func(t *testing.T) {
		useFakeTransport(t, &fakeDeviceTransport{results: map[string]any{
			pairingproto.MethodLocalSyncStatus: &pairingproto.LocalSyncStatusResult{
				DeviceID: "phone-1",
				LastSync: "2026-01-02T03:04:05Z",
				StoreChecksums: map[string]string{
					"oath":      "abc123",
					"passwords": "def456",
				},
			},
		}})

		output, err := runSyncStatus(t, nil)
		require.NoError(t, err, output)

		assert.Contains(t, output, "Device:    Test Phone")
		assert.Contains(t, output, "Address:   AA:BB:CC:DD:EE:FF")
		assert.Contains(t, output, "Device ID:  phone-1")
		assert.Contains(t, output, "Last sync:  2026-01-02T03:04:05Z")
		assert.Contains(t, output, "oath:        abc123")
		assert.Contains(t, output, "passwords:   def456")
		assert.NotContains(t, output, "trust_store:")
		assert.Contains(t, output, "This device:\n  Last sync:  never")
	})

	t.Run("without checksums", func(t *testing.T) {
		useFakeTransport(t, &fakeDeviceTransport{results: map[string]any{
			pairingproto.MethodLocalSyncStatus: &pairingproto.LocalSyncStatusResult{DeviceID: "phone-1"},
		}})

		output, err := runSyncStatus(t, nil)
		require.NoError(t, err, output)

		assert.Contains(t, output, "Phone:\n  Device ID:  phone-1\n  Last sync:  never")
		assert.Contains(t, output, "Checksums:  (none reported)")
	})
}

func TestRunDeviceSyncStatus_Failures(t *testing.T) {
	isolatedBackupHome(t)

	_, err := runSyncStatus(t, nil)
	require.ErrorIs(t, err, ErrDeviceNotPaired)

	pairTestDevice(t, "Test Phone")

	t.Run("connect", func(t *testing.T) {
		useFakeTransport(t, &fakeDeviceTransport{connectErr: errors.New("radio off")})

		_, err := runSyncStatus(t, nil)
		require.ErrorIs(t, err, ErrDeviceSyncFailed)
	})

	t.Run("phone error", func(t *testing.T) {
		useFakeTransport(t, &fakeDeviceTransport{rpcErrors: map[string]*pairingproto.RPCError{
			pairingproto.MethodLocalSyncStatus: {Code: -32000, Message: "busy"},
		}})

		output, err := runSyncStatus(t, nil)
		require.ErrorIs(t, err, ErrDeviceSyncFailed)
		assert.ErrorContains(t, err, "busy")
		assert.NotContains(t, output, "Device ID:")
	})

	t.Run("dial", func(t *testing.T) {
		require.NoError(t, saveDevicesConfig(&DevicesConfig{
			Devices:       []PairedDevice{brokenNoiseKeyDevice("Broken Phone")},
			DefaultDevice: "Broken Phone",
		}))

		_, err := runSyncStatus(t, nil)
		require.ErrorIs(t, err, ErrDeviceSyncFailed)
	})
}
