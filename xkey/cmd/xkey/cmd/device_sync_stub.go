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
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Device sync errors (stub).
var (
	// ErrDeviceSyncFailed indicates a phone sync operation failed.
	ErrDeviceSyncFailed = errors.New("device: sync operation failed")

	// ErrDeviceSyncNoScope indicates no sync scope was specified.
	ErrDeviceSyncNoScope = errors.New("device: no sync scope specified")
)

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

	// Sync flags
	deviceSyncCmd.Flags().Bool("trust-store", false, "Sync trust store certificates")
	deviceSyncCmd.Flags().Bool("oath", false, "Sync OATH credentials")
	deviceSyncCmd.Flags().Bool("passwords", false, "Sync password entries")
	deviceSyncCmd.Flags().Bool("all", true, "Sync all stores (default)")
	deviceSyncCmd.Flags().String("device", "", "Paired device name")
	deviceSyncCmd.Flags().Bool("dry-run", false, "Show what would be synced without applying")
	deviceSyncCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Sync-status flags
	deviceSyncStatusCmd.Flags().String("device", "", "Paired device name")
	deviceSyncStatusCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Sync-push flags
	deviceSyncPushCmd.Flags().Bool("trust-store", false, "Push trust store certificates")
	deviceSyncPushCmd.Flags().Bool("oath", false, "Push OATH credentials")
	deviceSyncPushCmd.Flags().Bool("passwords", false, "Push password entries")
	deviceSyncPushCmd.Flags().Bool("all", true, "Push all stores (default)")
	deviceSyncPushCmd.Flags().String("device", "", "Paired device name")
	deviceSyncPushCmd.Flags().Bool("dry-run", false, "Show what would be pushed without applying")
	deviceSyncPushCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Sync-pull flags
	deviceSyncPullCmd.Flags().Bool("trust-store", false, "Pull trust store certificates")
	deviceSyncPullCmd.Flags().Bool("oath", false, "Pull OATH credentials")
	deviceSyncPullCmd.Flags().Bool("passwords", false, "Pull password entries")
	deviceSyncPullCmd.Flags().Bool("all", true, "Pull all stores (default)")
	deviceSyncPullCmd.Flags().String("device", "", "Paired device name")
	deviceSyncPullCmd.Flags().Bool("dry-run", false, "Show what would be pulled without applying")
	deviceSyncPullCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Bind flags to viper
	_ = viper.BindPFlag("device.sync.trust_store", deviceSyncCmd.Flags().Lookup("trust-store"))
	_ = viper.BindPFlag("device.sync.oath", deviceSyncCmd.Flags().Lookup("oath"))
	_ = viper.BindPFlag("device.sync.passwords", deviceSyncCmd.Flags().Lookup("passwords"))
	_ = viper.BindPFlag("device.sync.all", deviceSyncCmd.Flags().Lookup("all"))
	_ = viper.BindPFlag("device.sync.device", deviceSyncCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.sync.dry_run", deviceSyncCmd.Flags().Lookup("dry-run"))
	_ = viper.BindPFlag("device.sync.timeout", deviceSyncCmd.Flags().Lookup("timeout"))

	_ = viper.BindPFlag("device.sync_status.device", deviceSyncStatusCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.sync_status.timeout", deviceSyncStatusCmd.Flags().Lookup("timeout"))

	_ = viper.BindPFlag("device.sync_push.trust_store", deviceSyncPushCmd.Flags().Lookup("trust-store"))
	_ = viper.BindPFlag("device.sync_push.oath", deviceSyncPushCmd.Flags().Lookup("oath"))
	_ = viper.BindPFlag("device.sync_push.passwords", deviceSyncPushCmd.Flags().Lookup("passwords"))
	_ = viper.BindPFlag("device.sync_push.all", deviceSyncPushCmd.Flags().Lookup("all"))
	_ = viper.BindPFlag("device.sync_push.device", deviceSyncPushCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.sync_push.dry_run", deviceSyncPushCmd.Flags().Lookup("dry-run"))
	_ = viper.BindPFlag("device.sync_push.timeout", deviceSyncPushCmd.Flags().Lookup("timeout"))

	_ = viper.BindPFlag("device.sync_pull.trust_store", deviceSyncPullCmd.Flags().Lookup("trust-store"))
	_ = viper.BindPFlag("device.sync_pull.oath", deviceSyncPullCmd.Flags().Lookup("oath"))
	_ = viper.BindPFlag("device.sync_pull.passwords", deviceSyncPullCmd.Flags().Lookup("passwords"))
	_ = viper.BindPFlag("device.sync_pull.all", deviceSyncPullCmd.Flags().Lookup("all"))
	_ = viper.BindPFlag("device.sync_pull.device", deviceSyncPullCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.sync_pull.dry_run", deviceSyncPullCmd.Flags().Lookup("dry-run"))
	_ = viper.BindPFlag("device.sync_pull.timeout", deviceSyncPullCmd.Flags().Lookup("timeout"))
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
