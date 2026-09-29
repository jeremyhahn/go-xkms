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

// registerDeviceAttestFlags registers the flags for `xkey device attest`. It
// is called by both the ble and !ble implementations of the command
// (device_attest.go and device_attest_stub.go) so the two flag sets cannot
// drift out of parity (go-xkms#1318).
func registerDeviceAttestFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Specific paired device to use")
	cmd.Flags().Bool("no-verify", false, "Skip certificate chain verification")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout (includes biometric wait)")

	_ = viper.BindPFlag("device.attest.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.attest.no-verify", cmd.Flags().Lookup("no-verify"))
	_ = viper.BindPFlag("device.attest.timeout", cmd.Flags().Lookup("timeout"))
}
