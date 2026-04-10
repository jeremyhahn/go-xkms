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
	"github.com/spf13/viper"
)

// devicePairCmd handles pairing with a new phone device.
// This is a stub implementation when built without BLE support.
var devicePairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Pair with a phone key backend",
	Long: `Scan for and pair with a xKey-enabled Android phone.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone pairing, rebuild with the 'ble' build tag:

    go build -tags ble

This command performs the following steps when BLE is enabled:
  1. Enables the Bluetooth adapter
  2. Scans for devices advertising the xKey service
  3. Displays found devices and lets you select one
  4. Initiates BLE pairing at the OS level
  5. Performs Noise protocol handshake for app-layer key exchange
  6. Saves pairing information for future connections

Examples:
  # Scan and interactively select a device to pair
  xkey device pair

  # Pair with a specific device by name
  xkey device pair --device "John's Pixel"

  # Pair with extended scan timeout
  xkey device pair --timeout 60s

  # Force re-pairing if already paired
  xkey device pair --device "John's Pixel" --force`,
	RunE: runDevicePairStub,
}

func init() {
	deviceCmd.AddCommand(devicePairCmd)

	// Register flags even in stub mode for help text
	devicePairCmd.Flags().String("device", "", "Specific device name or address to pair")
	devicePairCmd.Flags().Duration("timeout", defaultDeviceScanTimeout, "Scan timeout duration")
	devicePairCmd.Flags().Bool("force", false, "Force re-pairing even if already paired")

	// Bind flags to viper
	_ = viper.BindPFlag("device.pair.device", devicePairCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.pair.timeout", devicePairCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("device.pair.force", devicePairCmd.Flags().Lookup("force"))
}

// runDevicePairStub returns an error indicating BLE support is not available.
func runDevicePairStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}
