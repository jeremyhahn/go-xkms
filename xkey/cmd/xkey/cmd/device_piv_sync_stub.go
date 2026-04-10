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

// PIV phone sync errors (stub).
var (
	// ErrPIVDeviceSyncFailed indicates PIV sync with phone failed.
	ErrPIVDeviceSyncFailed = errors.New("piv: phone sync failed")

	// ErrPIVDevicePushCertFailed indicates pushing certificate to phone failed.
	ErrPIVDevicePushCertFailed = errors.New("piv: push certificate to phone failed")

	// ErrPIVDevicePullCertFailed indicates pulling certificate from phone failed.
	ErrPIVDevicePullCertFailed = errors.New("piv: pull certificate from phone failed")

	// ErrPIVDeviceListSlotsFailed indicates listing phone PIV slots failed.
	ErrPIVDeviceListSlotsFailed = errors.New("piv: list phone slots failed")

	// ErrPIVDeviceGenerateKeyFailed indicates generating key on phone failed.
	ErrPIVDeviceGenerateKeyFailed = errors.New("piv: generate key on phone failed")
)

// pivDeviceListCmd lists PIV slots on a paired phone.
// This is a stub implementation when built without BLE support.
var pivDeviceListCmd = &cobra.Command{
	Use:   "phone-list",
	Short: "List PIV slots on a paired phone",
	Long: `List the PIV slot contents on a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone PIV operations, rebuild with the 'ble' build tag:

    go build -tags ble

Examples:
  xkey piv phone-list
  xkey piv phone-list --device "Pixel 8"`,
	RunE: runPIVPhoneListStub,
}

// pivDevicePushCertCmd pushes a certificate to a PIV slot on a paired phone.
// This is a stub implementation when built without BLE support.
var pivDevicePushCertCmd = &cobra.Command{
	Use:   "phone-push-cert <slot> <cert-file>",
	Short: "Push certificate to a PIV slot on a paired phone",
	Long: `Push a certificate to a PIV slot on a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone PIV operations, rebuild with the 'ble' build tag:

    go build -tags ble

Examples:
  xkey piv phone-push-cert 9a /path/to/cert.pem`,
	Args: cobra.ExactArgs(2),
	RunE: runPIVPhonePushCertStub,
}

// pivDevicePullCertCmd pulls a certificate from a PIV slot on a paired phone.
// This is a stub implementation when built without BLE support.
var pivDevicePullCertCmd = &cobra.Command{
	Use:   "phone-pull-cert <slot>",
	Short: "Pull certificate from a PIV slot on a paired phone",
	Long: `Pull a certificate from a PIV slot on a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone PIV operations, rebuild with the 'ble' build tag:

    go build -tags ble

Examples:
  xkey piv phone-pull-cert 9a --output cert.pem`,
	Args: cobra.ExactArgs(1),
	RunE: runPIVPhonePullCertStub,
}

// pivDeviceGenerateKeyCmd generates a key on a PIV slot on a paired phone.
// This is a stub implementation when built without BLE support.
var pivDeviceGenerateKeyCmd = &cobra.Command{
	Use:   "phone-generate <slot>",
	Short: "Generate key in a PIV slot on a paired phone",
	Long: `Request a paired phone to generate a key in a PIV slot.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone PIV operations, rebuild with the 'ble' build tag:

    go build -tags ble

Examples:
  xkey piv phone-generate 9a --algorithm ECDSA-P256`,
	Args: cobra.ExactArgs(1),
	RunE: runPIVPhoneGenerateKeyStub,
}

func init() {
	PIVCmd.AddCommand(pivDeviceListCmd)
	PIVCmd.AddCommand(pivDevicePushCertCmd)
	PIVCmd.AddCommand(pivDevicePullCertCmd)
	PIVCmd.AddCommand(pivDeviceGenerateKeyCmd)

	// Phone-list flags
	pivDeviceListCmd.Flags().String("device", "", "Paired device name")
	pivDeviceListCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Phone-push-cert flags
	pivDevicePushCertCmd.Flags().String("device", "", "Paired device name")
	pivDevicePushCertCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Phone-pull-cert flags
	pivDevicePullCertCmd.Flags().String("device", "", "Paired device name")
	pivDevicePullCertCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	pivDevicePullCertCmd.Flags().String("output", "", "Output file path (default: stdout)")

	// Phone-generate flags
	pivDeviceGenerateKeyCmd.Flags().String("device", "", "Paired device name")
	pivDeviceGenerateKeyCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	pivDeviceGenerateKeyCmd.Flags().StringP("algorithm", "a", "ECDSA-P256",
		"Key algorithm (ECDSA-P256, ECDSA-P384, RSA-2048)")

	// Bind flags to viper
	_ = viper.BindPFlag("piv.phone_list.device", pivDeviceListCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_list.timeout", pivDeviceListCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("piv.phone_push_cert.device", pivDevicePushCertCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_push_cert.timeout", pivDevicePushCertCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("piv.phone_pull_cert.device", pivDevicePullCertCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_pull_cert.timeout", pivDevicePullCertCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("piv.phone_generate.device", pivDeviceGenerateKeyCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("piv.phone_generate.timeout", pivDeviceGenerateKeyCmd.Flags().Lookup("timeout"))
}

// runPIVPhoneListStub returns an error indicating BLE support is not available.
func runPIVPhoneListStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// runPIVPhonePushCertStub returns an error indicating BLE support is not available.
func runPIVPhonePushCertStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// runPIVPhonePullCertStub returns an error indicating BLE support is not available.
func runPIVPhonePullCertStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// runPIVPhoneGenerateKeyStub returns an error indicating BLE support is not available.
func runPIVPhoneGenerateKeyStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// truncateSlotLabel truncates a slot label for table display.
func truncateSlotLabel(label string) string {
	if len(label) > 24 {
		return label[:21] + "..."
	}
	return label
}
