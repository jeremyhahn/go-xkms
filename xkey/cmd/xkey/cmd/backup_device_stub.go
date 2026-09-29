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

//go:build !ble

package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

// Device backup errors (stub).
var (
	// ErrBackupToDeviceFailed indicates sending backup to device failed.
	ErrBackupToDeviceFailed = errors.New("backup: send to device failed")

	// ErrBackupFromDeviceFailed indicates restoring from device failed.
	ErrBackupFromDeviceFailed = errors.New("backup: restore from device failed")
)

// backupToDeviceCmd sends a backup to a paired phone device.
// This is a stub implementation when built without BLE support.
var backupToDeviceCmd = &cobra.Command{
	Use:   "to-device",
	Short: "Send backup to a paired phone",
	Long: `Send an encrypted backup of xkey data to a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone backup, rebuild with the 'ble' build tag:

    go build -tags ble

When BLE is enabled, this command connects to the paired phone and sends
the encrypted backup over the secure Noise protocol channel.

Examples:
  xkey backup to-device
  xkey backup to-device --device "Pixel 8"`,
	RunE: runBackupToDeviceStub,
}

// backupFromDeviceCmd restores a backup from a paired phone device.
// This is a stub implementation when built without BLE support.
var backupFromDeviceCmd = &cobra.Command{
	Use:   "from-device",
	Short: "Restore backup from a paired phone",
	Long: `Restore xkey data from an encrypted backup stored on a paired phone.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone backup restore, rebuild with the 'ble' build tag:

    go build -tags ble

When BLE is enabled, this command connects to the paired phone and
retrieves the encrypted backup over the secure Noise protocol channel.

Examples:
  xkey backup from-device
  xkey backup from-device --device "Pixel 8"`,
	RunE: runBackupFromDeviceStub,
}

func init() {
	backupCmd.AddCommand(backupToDeviceCmd)
	backupCmd.AddCommand(backupFromDeviceCmd)

	registerBackupToDeviceFlags(backupToDeviceCmd)
	registerBackupFromDeviceFlags(backupFromDeviceCmd)
}

// runBackupToDeviceStub returns an error indicating BLE support is not available.
func runBackupToDeviceStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// runBackupFromDeviceStub returns an error indicating BLE support is not available.
func runBackupFromDeviceStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}
