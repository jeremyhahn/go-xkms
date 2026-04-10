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

// deviceInfoCmd displays detailed information about a paired device.
// This is a stub implementation when built without BLE support.
var deviceInfoCmd = &cobra.Command{
	Use:   "device-info [device-name]",
	Short: "Show detailed device information",
	Long: `Display detailed information about a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone device info, rebuild with the 'ble' build tag:

    go build -tags ble

Shows connection details, attestation status, and configuration settings
for the specified device. If no device is specified, shows the default device.

Examples:
  # Show info for default device
  xkey device device-info

  # Show info for specific device
  xkey device device-info "John's Pixel"`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDeviceInfoStub,
}

func init() {
	deviceCmd.AddCommand(deviceInfoCmd)
}

// runDeviceInfoStub returns an error indicating BLE support is not available.
func runDeviceInfoStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}
