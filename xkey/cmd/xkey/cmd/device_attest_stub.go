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
)

// Device attest errors (stub).
var (
	// ErrDeviceAttestKeyRequired indicates a key ID is required for attestation.
	ErrDeviceAttestKeyRequired = errors.New("device: key ID is required for attestation")

	// ErrDeviceAttestNonceFailed indicates random nonce generation failed.
	ErrDeviceAttestNonceFailed = errors.New("device: failed to generate attestation nonce")

	// ErrDeviceAttestFailed indicates the attestation request failed.
	ErrDeviceAttestFailed = errors.New("device: attestation request failed")

	// ErrDeviceAttestVerifyFailed indicates attestation verification failed.
	ErrDeviceAttestVerifyFailed = errors.New("device: attestation verification failed")
)

// deviceAttestCmd requests key attestation from a paired phone.
// This is a stub implementation when built without BLE support.
var deviceAttestCmd = &cobra.Command{
	Use:   "attest <key-id>",
	Short: "Request key attestation from a paired phone",
	Long: `Request Android Key Attestation proof for a key stored on the phone.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone attestation, rebuild with the 'ble' build tag:

    go build -tags ble

When BLE is enabled, this command connects to the paired phone, sends a
cryptographic challenge, and verifies the X.509 attestation certificate
chain against Google's Hardware Attestation Root CAs.

Examples:
  # Attest a key by ID
  xkey device attest my-signing-key

  # Attest with a specific device
  xkey device attest my-signing-key --device "John's Pixel"`,
	Args: cobra.ExactArgs(1),
	RunE: runDeviceAttestStub,
}

func init() {
	deviceCmd.AddCommand(deviceAttestCmd)

	registerDeviceAttestFlags(deviceAttestCmd)
}

// runDeviceAttestStub returns an error indicating BLE support is not available.
func runDeviceAttestStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}
