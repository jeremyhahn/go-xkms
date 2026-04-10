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
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Key sharing errors (stub).
var (
	// ErrSharePolicyDenied indicates the sharing policy denies this operation.
	ErrSharePolicyDenied = errors.New("device: sharing denied by policy")

	// ErrShareConnectFailed indicates the connection to the phone failed during sharing.
	ErrShareConnectFailed = errors.New("device: share connection failed")

	// ErrShareRequestFailed indicates the sharing request to the phone failed.
	ErrShareRequestFailed = errors.New("device: share request failed")

	// ErrShareImportFailed indicates the key import from the phone failed.
	ErrShareImportFailed = errors.New("device: share import failed")

	// ErrSharePolicyStoreFailed indicates the sharing policy store could not be loaded.
	ErrSharePolicyStoreFailed = errors.New("device: sharing policy store failed")
)

// deviceShareCmd shares a key with a paired phone device.
// This is a stub implementation when built without BLE support.
var deviceShareCmd = &cobra.Command{
	Use:   "share <backend> <key-id>",
	Short: "Share a key with a paired phone",
	Long: `Share a key with a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone key sharing, rebuild with the 'ble' build tag:

    go build -tags ble

When BLE is enabled, this command connects to the paired phone, checks
sharing policy, and sends the key material over the encrypted Noise channel.

Examples:
  xkey device share software my-key
  xkey device share tpm2 ek --device "Pixel 8"`,
	Args: cobra.ExactArgs(2),
	RunE: runDeviceShareStub,
}

// deviceImportCmd imports a shared key from a paired phone device.
// This is a stub implementation when built without BLE support.
var deviceImportCmd = &cobra.Command{
	Use:   "import <key-id>",
	Short: "Import a shared key from a paired phone",
	Long: `Import a key that was shared by a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone key import, rebuild with the 'ble' build tag:

    go build -tags ble

When BLE is enabled, this command connects to the paired phone and
retrieves the shared key material over the encrypted Noise channel.

Examples:
  xkey device import my-phone-key
  xkey device import my-phone-key --backend software`,
	Args: cobra.ExactArgs(1),
	RunE: runDeviceImportStub,
}

func init() {
	deviceCmd.AddCommand(deviceShareCmd)
	deviceCmd.AddCommand(deviceImportCmd)

	// Share command flags
	deviceShareCmd.Flags().String("device", "", "Paired device name to share with")
	deviceShareCmd.Flags().String("label", "", "Label for the shared key on the phone")
	deviceShareCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Import command flags
	deviceImportCmd.Flags().String("backend", "software", "Target backend for imported key")
	deviceImportCmd.Flags().String("device", "", "Paired device name to import from")
	deviceImportCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Bind flags to viper
	_ = viper.BindPFlag("device.share.device", deviceShareCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.share.label", deviceShareCmd.Flags().Lookup("label"))
	_ = viper.BindPFlag("device.share.timeout", deviceShareCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("device.import.backend", deviceImportCmd.Flags().Lookup("backend"))
	_ = viper.BindPFlag("device.import.device", deviceImportCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.import.timeout", deviceImportCmd.Flags().Lookup("timeout"))
}

// runDeviceShareStub returns an error indicating BLE support is not available.
func runDeviceShareStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// runDeviceImportStub returns an error indicating BLE support is not available.
func runDeviceImportStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}
