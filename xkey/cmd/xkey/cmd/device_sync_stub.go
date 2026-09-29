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

// ErrDeviceSyncNoScope indicates no sync scope was specified.
//
// ErrDeviceSyncFailed is NOT re-declared here: it lives in
// device_sync_shared.go, which carries no build tag, so this stub build and
// the ble build share one declaration instead of two that can drift apart.
var ErrDeviceSyncNoScope = errors.New("device: no sync scope specified")

// deviceSyncCmd synchronizes data bidirectionally with a paired phone.
// This is a stub implementation when built without BLE support.
var deviceSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync data bidirectionally with a paired phone",
	Long: `Synchronize data between this device and a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone sync, rebuild with the 'ble' build tag:

    go build -tags ble

When BLE is enabled, this command connects to the paired phone and
synchronizes data bidirectionally across trust store, OATH credentials,
and passwords.

Examples:
  xkey device sync
  xkey device sync --oath --passwords
  xkey device sync --trust-store --device "Pixel 8"`,
	RunE: runDeviceSyncStub,
}

// deviceSyncStatusCmd shows sync status with a paired phone.
// This is a stub implementation when built without BLE support.
var deviceSyncStatusCmd = &cobra.Command{
	Use:   "sync-status",
	Short: "Show sync status with a paired phone",
	Long: `Display the synchronization status with a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone sync status, rebuild with the 'ble' build tag:

    go build -tags ble

Examples:
  xkey device sync-status
  xkey device sync-status --device "Pixel 8"`,
	RunE: runDeviceSyncStatusStub,
}

// deviceSyncPushCmd pushes local data to a paired phone.
// This is a stub implementation when built without BLE support.
var deviceSyncPushCmd = &cobra.Command{
	Use:   "sync-push",
	Short: "Push local data to a paired phone",
	Long: `Push local data to a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone sync push, rebuild with the 'ble' build tag:

    go build -tags ble

Examples:
  xkey device sync-push
  xkey device sync-push --oath --device "Pixel 8"`,
	RunE: runDeviceSyncPushStub,
}

// deviceSyncPullCmd pulls phone data to this device.
// This is a stub implementation when built without BLE support.
var deviceSyncPullCmd = &cobra.Command{
	Use:   "sync-pull",
	Short: "Pull phone data to this device",
	Long: `Pull data from a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone sync pull, rebuild with the 'ble' build tag:

    go build -tags ble

Examples:
  xkey device sync-pull
  xkey device sync-pull --passwords --device "Pixel 8"`,
	RunE: runDeviceSyncPullStub,
}

func init() {
	deviceCmd.AddCommand(deviceSyncCmd)
	deviceCmd.AddCommand(deviceSyncStatusCmd)
	deviceCmd.AddCommand(deviceSyncPushCmd)
	deviceCmd.AddCommand(deviceSyncPullCmd)

	registerDeviceSyncFlags(deviceSyncCmd)
	registerDeviceSyncStatusFlags(deviceSyncStatusCmd)
	registerDeviceSyncPushFlags(deviceSyncPushCmd)
	registerDeviceSyncPullFlags(deviceSyncPullCmd)
}

// runDeviceSyncStub returns an error indicating BLE support is not available.
func runDeviceSyncStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// runDeviceSyncStatusStub returns an error indicating BLE support is not available.
func runDeviceSyncStatusStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// runDeviceSyncPushStub returns an error indicating BLE support is not available.
func runDeviceSyncPushStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// runDeviceSyncPullStub returns an error indicating BLE support is not available.
func runDeviceSyncPullStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}
