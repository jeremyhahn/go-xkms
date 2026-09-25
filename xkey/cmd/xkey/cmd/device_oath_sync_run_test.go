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
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
)

// oathSyncTestCmd builds a fresh cobra.Command carrying the same flags the
// package-level oath phone-sync commands register, so tests never mutate
// the shared global command's flag state.
func oathSyncTestCmd(t *testing.T, storePath string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")
	cmd.Flags().Duration("timeout", 50*time.Millisecond, "")
	cmd.Flags().String("store", "", "")
	if storePath != "" {
		require.NoError(t, cmd.Flags().Set("store", storePath))
	}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	return cmd
}

// brokenNoiseKeyDevice returns a paired device whose LocalNoisePrivateKey is
// not valid base64. unsealDeviceLocalKey (via newPairedDeviceBackendConfig)
// rejects it before any BLE dial is attempted, so this reaches and exercises
// the "connect to phone" failure branch of every phone-sync command without
// touching real Bluetooth hardware.
func brokenNoiseKeyDevice(name string) PairedDevice {
	return PairedDevice{
		Name:                 name,
		Address:              "11:22:33:44:55:66",
		LocalNoisePrivateKey: "not valid base64!!!",
		PairedAt:             time.Now(),
	}
}

func TestRunOATHSync_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := oathSyncTestCmd(t, "")
	err := runOATHSync(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunOATHSync_DeviceNotFound(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	cmd := oathSyncTestCmd(t, "")
	require.NoError(t, cmd.Flags().Set("device", "Nonexistent"))
	err := runOATHSync(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

func TestRunOATHSync_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	storePath := filepath.Join(t.TempDir(), "oath.json")
	cmd := oathSyncTestCmd(t, storePath)
	err := runOATHSync(cmd, nil)
	require.ErrorIs(t, err, ErrOATHSyncFailed)
}

func TestRunOATHPush_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := oathSyncTestCmd(t, "")
	err := runOATHPush(cmd, []string{"GitHub"})
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunOATHPush_CredentialNotFound(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	storePath := filepath.Join(t.TempDir(), "oath.json")
	cmd := oathSyncTestCmd(t, storePath)
	err := runOATHPush(cmd, []string{"does-not-exist"})
	require.ErrorIs(t, err, ErrOATHCredentialNotFound)
}

func TestRunOATHPush_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	storePath := filepath.Join(t.TempDir(), "oath.json")
	cmd := oathSyncTestCmd(t, storePath)

	store, err := openOATHStore(cmd, storePath)
	require.NoError(t, err)
	cred := withOATHSecret(&oath.Credential{
		ID: "gh", Name: "GitHub", Type: oath.TypeTOTP, Algorithm: oath.AlgorithmSHA1,
		Digits: 6, Period: 30, CreatedAt: time.Now(),
	}, "JBSWY3DPEHPK3PXP")
	require.NoError(t, store.Add(cred))
	require.NoError(t, store.Close())

	err = runOATHPush(cmd, []string{"GitHub"})
	require.ErrorIs(t, err, ErrOATHPushFailed)
}

func TestRunOATHPull_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := oathSyncTestCmd(t, "")
	err := runOATHPull(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunOATHPull_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	storePath := filepath.Join(t.TempDir(), "oath.json")
	cmd := oathSyncTestCmd(t, storePath)
	err := runOATHPull(cmd, nil)
	require.ErrorIs(t, err, ErrOATHPullFailed)
}
