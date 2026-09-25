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
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func pivSyncTestCmd(extraFlags func(*cobra.Command)) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")
	cmd.Flags().Duration("timeout", 50*time.Millisecond, "")
	if extraFlags != nil {
		extraFlags(cmd)
	}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	return cmd
}

func TestRunPIVDeviceList_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(nil)
	err := runPIVDeviceList(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunPIVDeviceList_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	cmd := pivSyncTestCmd(nil)
	err := runPIVDeviceList(cmd, nil)
	require.ErrorIs(t, err, ErrPIVDeviceListSlotsFailed)
}

func TestRunPIVDevicePushCert_InvalidSlot(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(nil)
	err := runPIVDevicePushCert(cmd, []string{"zz", "unused.pem"})
	require.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestRunPIVDevicePushCert_CertificateReadFailed(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(nil)
	err := runPIVDevicePushCert(cmd, []string{"9a", filepath.Join(t.TempDir(), "missing.pem")})
	require.ErrorIs(t, err, ErrPIVCertificateReadFailed)
}

func TestRunPIVDevicePushCert_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	certPath := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(certPath, generateTestCertificatePEM(t), 0600))

	cmd := pivSyncTestCmd(nil)
	err := runPIVDevicePushCert(cmd, []string{"9a", certPath})
	require.ErrorIs(t, err, ErrPIVDevicePushCertFailed)
}

func TestRunPIVDevicePullCert_InvalidSlot(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(func(c *cobra.Command) { c.Flags().String("output", "", "") })
	err := runPIVDevicePullCert(cmd, []string{"zz"})
	require.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestRunPIVDevicePullCert_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(func(c *cobra.Command) { c.Flags().String("output", "", "") })
	err := runPIVDevicePullCert(cmd, []string{"9a"})
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunPIVDeviceGenerateKey_InvalidSlot(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(func(c *cobra.Command) { c.Flags().StringP("algorithm", "a", "ECDSA-P256", "") })
	err := runPIVDeviceGenerateKey(cmd, []string{"zz"})
	require.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestRunPIVDeviceGenerateKey_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	cmd := pivSyncTestCmd(func(c *cobra.Command) { c.Flags().StringP("algorithm", "a", "ECDSA-P256", "") })
	err := runPIVDeviceGenerateKey(cmd, []string{"9a"})
	require.ErrorIs(t, err, ErrPIVDeviceGenerateKeyFailed)
}
