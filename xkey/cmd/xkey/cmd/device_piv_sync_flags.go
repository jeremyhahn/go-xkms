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

// registerPIVDeviceListFlags registers the flags for `xkey piv phone-list`.
// It is called by both the ble and !ble implementations of the command
// (device_piv_sync.go and device_piv_sync_stub.go) so the two flag sets
// cannot drift out of parity (go-xkms#1318).
func registerPIVDeviceListFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Paired device name")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	_ = viper.BindPFlag("piv.phone_list.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_list.timeout", cmd.Flags().Lookup("timeout"))
}

// registerPIVDevicePushCertFlags registers the flags for `xkey piv
// phone-push-cert`. It is called by both the ble and !ble implementations of
// the command so the two flag sets cannot drift out of parity (go-xkms#1318).
func registerPIVDevicePushCertFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Paired device name")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	_ = viper.BindPFlag("piv.phone_push_cert.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_push_cert.timeout", cmd.Flags().Lookup("timeout"))
}

// registerPIVDevicePullCertFlags registers the flags for `xkey piv
// phone-pull-cert`. It is called by both the ble and !ble implementations of
// the command so the two flag sets cannot drift out of parity (go-xkms#1318).
func registerPIVDevicePullCertFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Paired device name")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	cmd.Flags().String("output", "", "Output file path (default: stdout)")

	_ = viper.BindPFlag("piv.phone_pull_cert.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_pull_cert.timeout", cmd.Flags().Lookup("timeout"))
}

// registerPIVDeviceGenerateKeyFlags registers the flags for `xkey piv
// phone-generate`. It is called by both the ble and !ble implementations of
// the command so the two flag sets cannot drift out of parity (go-xkms#1318).
func registerPIVDeviceGenerateKeyFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Paired device name")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	cmd.Flags().StringP("algorithm", "a", "ECDSA-P256",
		"Key algorithm (ECDSA-P256, ECDSA-P384, RSA-2048)")

	_ = viper.BindPFlag("piv.phone_generate.device", cmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_generate.timeout", cmd.Flags().Lookup("timeout"))
}
