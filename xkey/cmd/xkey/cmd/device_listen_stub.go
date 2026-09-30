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

// Device listen command errors (ErrDeviceListenFailed, ErrDeviceNoDefaultDevice)
// live in device_listen_handler.go, which carries no build tag: this stub
// build and the ble build share one declaration instead of two that can
// drift apart.

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

	registerDeviceListenFlags(deviceListenCmd)
}

// runDeviceListenStub returns an error indicating BLE support is not available.
func runDeviceListenStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}
