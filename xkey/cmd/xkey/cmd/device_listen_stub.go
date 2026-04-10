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
	"github.com/spf13/viper"
)

// Device listen command errors - re-declared for stub builds.
var (
	ErrDeviceListenFailed    = errors.New("device: listen failed")
	ErrDeviceNoDefaultDevice = errors.New("device: no default device configured")
)

// deviceListenCmd starts the BLE peripheral to accept phone-initiated connections.
// This is a stub implementation when built without BLE support.
var deviceListenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listen for phone-initiated connections",
	Long: `Start the BLE peripheral to accept connections from paired phones.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone listening, rebuild with the 'ble' build tag:

    go build -tags ble

This command starts the laptop as a BLE peripheral (GATT server), allowing
the phone to initiate connections when it needs to perform operations like
re-attestation or key management.

Examples:
  # Start listening for the default paired device
  xkey device listen

  # Listen for a specific device
  xkey device listen --device "John's Pixel"

  # Listen with custom device name
  xkey device listen --name "My Laptop"`,
	RunE: runDeviceListenStub,
}

func init() {
	deviceCmd.AddCommand(deviceListenCmd)

	// Register flags even in stub mode for help text
	deviceListenCmd.Flags().String("device", "", "Specific paired device to accept connections from")
	deviceListenCmd.Flags().String("name", "", "Advertised device name (default: hostname)")
	deviceListenCmd.Flags().Duration("timeout", 0, "Listen timeout (0 for indefinite)")

	// Bind flags to viper
	_ = viper.BindPFlag("device.listen.device", deviceListenCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.listen.name", deviceListenCmd.Flags().Lookup("name"))
	_ = viper.BindPFlag("device.listen.timeout", deviceListenCmd.Flags().Lookup("timeout"))
}

// runDeviceListenStub returns an error indicating BLE support is not available.
func runDeviceListenStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}
