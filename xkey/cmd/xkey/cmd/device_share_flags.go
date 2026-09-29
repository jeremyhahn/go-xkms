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

// registerDeviceShareFlags registers the flags for `xkey device share`. It is
// called by both the ble and !ble implementations of the command
// (device_share.go and device_share_stub.go) so the two flag sets cannot
// drift out of parity (go-xkms#1318).
func registerDeviceShareFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Paired device name to share with")
	cmd.Flags().String("label", "", "Label for the shared key on the phone")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	_ = viper.BindPFlag("device.share.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.share.label", cmd.Flags().Lookup("label"))
	_ = viper.BindPFlag("device.share.timeout", cmd.Flags().Lookup("timeout"))
}

// registerDeviceImportFlags registers the flags for `xkey device import`. It
// is called by both the ble and !ble implementations of the command so the
// two flag sets cannot drift out of parity (go-xkms#1318).
func registerDeviceImportFlags(cmd *cobra.Command) {
	cmd.Flags().String("backend", "software", "Target backend for imported key")
	cmd.Flags().String("device", "", "Paired device name to import from")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	_ = viper.BindPFlag("device.import.backend", cmd.Flags().Lookup("backend"))
	_ = viper.BindPFlag("device.import.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.import.timeout", cmd.Flags().Lookup("timeout"))
}
