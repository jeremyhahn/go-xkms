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

// registerOATHSyncPhoneFlags registers the flags for `xkey oath sync`. It is
// called by both the ble and !ble implementations of the command
// (device_oath_sync.go and device_oath_sync_stub.go) so the two flag sets
// cannot drift out of parity (go-xkms#1318).
func registerOATHSyncPhoneFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Paired device name")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	cmd.Flags().String("store", "", "Path to credential store (default: ~/.xkey/data/oath.json)")
	addBarrierPasswordFlags(cmd)

	_ = viper.BindPFlag("oath.sync.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("oath.sync.timeout", cmd.Flags().Lookup("timeout"))
}

// registerOATHPushPhoneFlags registers the flags for `xkey oath push`. It is
// called by both the ble and !ble implementations of the command so the two
// flag sets cannot drift out of parity (go-xkms#1318).
func registerOATHPushPhoneFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Paired device name")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	cmd.Flags().String("store", "", "Path to credential store (default: ~/.xkey/data/oath.json)")
	addBarrierPasswordFlags(cmd)

	_ = viper.BindPFlag("oath.push.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("oath.push.timeout", cmd.Flags().Lookup("timeout"))
}

// registerOATHPullPhoneFlags registers the flags for `xkey oath pull`. It is
// called by both the ble and !ble implementations of the command so the two
// flag sets cannot drift out of parity (go-xkms#1318).
func registerOATHPullPhoneFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Paired device name")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	cmd.Flags().String("store", "", "Path to credential store (default: ~/.xkey/data/oath.json)")
	addBarrierPasswordFlags(cmd)

	_ = viper.BindPFlag("oath.pull.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("oath.pull.timeout", cmd.Flags().Lookup("timeout"))
}
