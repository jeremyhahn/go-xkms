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
	"github.com/spf13/cobra"
)

// deviceScanCmd scans for nearby xKey devices.
var deviceScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for nearby xKey devices",
	Long: `Scan for xKey-enabled phones advertising the xKey BLE service.

NOTE: This build was compiled without BLE support.
Rebuild with '-tags ble' to enable Bluetooth functionality.`,
	RunE: runDeviceScan,
}

func init() {
	deviceCmd.AddCommand(deviceScanCmd)
}

// runDeviceScan returns an error since BLE is not available.
func runDeviceScan(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}
