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

package cmd

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// registerBackupToDeviceFlags registers the flags for `xkey backup to-device`.
// It is called by both the ble and !ble implementations of the command
// (backup_device.go and backup_device_stub.go) so the two flag sets cannot
// drift out of parity (go-xkms#1318).
func registerBackupToDeviceFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Paired device name to send backup to")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	backupPasswordSource.addFlags(cmd)
	addBackupStoreFlags(cmd)
	addBarrierPasswordFlags(cmd)

	_ = viper.BindPFlag("backup.to_device.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("backup.to_device.timeout", cmd.Flags().Lookup("timeout"))
}

// registerBackupFromDeviceFlags registers the flags for `xkey backup
// from-device`. It is called by both the ble and !ble implementations of the
// command so the two flag sets cannot drift out of parity (go-xkms#1318).
func registerBackupFromDeviceFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Paired device name to restore from")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	backupPasswordSource.addFlags(cmd)
	backupKeySource.addFlags(cmd)
	addBackupStoreFlags(cmd)
	addBarrierPasswordFlags(cmd)

	_ = viper.BindPFlag("backup.from_device.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("backup.from_device.timeout", cmd.Flags().Lookup("timeout"))
}
