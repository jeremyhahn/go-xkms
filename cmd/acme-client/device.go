// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// deviceEnrollCmd represents the device enroll subcommand for TPM enrollment.
var deviceEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll a TPM device",
	Long: `Enroll a TPM device using the ACME enroll-01 challenge type.

This initiates the IEEE 802.1AR device identity enrollment workflow.
Requires a configured TPM module via go-xkms.

Examples:
  trusted-acme-client device enroll --account trusted-ca --device-id 192.168.1.100`,
	RunE: func(cmd *cobra.Command, args []string) error {
		account, _ := cmd.Flags().GetString("account")
		deviceID, _ := cmd.Flags().GetString("device-id")

		if account == "" {
			return fmt.Errorf("--account is required")
		}
		if deviceID == "" {
			return fmt.Errorf("--device-id is required")
		}

		cmd.Printf("TPM device enrollment requires programmatic TPM setup.\n")
		cmd.Printf("Account: %s, Device ID: %s\n", account, deviceID)
		cmd.Printf("See documentation at docs/acme/README.md for examples.\n")
		return nil
	},
}

// deviceAttestCmd represents the device attest subcommand for TPM attestation.
var deviceAttestCmd = &cobra.Command{
	Use:   "attest",
	Short: "Attest a TPM device",
	Long: `Attest a TPM device using the ACME device-attest-01 challenge type.

This performs TPM-based device attestation with platform configuration
register (PCR) measurements.

Examples:
  trusted-acme-client device attest --account trusted-ca --device-id 192.168.1.100 --pcrs "0,1,2,3,7"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		account, _ := cmd.Flags().GetString("account")
		deviceID, _ := cmd.Flags().GetString("device-id")

		if account == "" {
			return fmt.Errorf("--account is required")
		}
		if deviceID == "" {
			return fmt.Errorf("--device-id is required")
		}

		cmd.Printf("TPM device attestation requires programmatic TPM setup.\n")
		cmd.Printf("Account: %s, Device ID: %s\n", account, deviceID)
		cmd.Printf("See documentation at docs/acme/README.md for examples.\n")
		return nil
	},
}

func init() {
	// Enroll flags
	deviceEnrollCmd.Flags().String("account", "", "ACME account name (required)")
	deviceEnrollCmd.Flags().String("device-id", "", "device identifier (required)")
	deviceEnrollCmd.Flags().String("cn", "", "common name for the certificate")
	deviceEnrollCmd.Flags().String("output-cert", "", "output certificate file")
	deviceEnrollCmd.Flags().String("output-iak", "", "output IAK certificate file")

	// Attest flags
	deviceAttestCmd.Flags().String("account", "", "ACME account name (required)")
	deviceAttestCmd.Flags().String("device-id", "", "device identifier (required)")
	deviceAttestCmd.Flags().String("cn", "", "common name for the certificate")
	deviceAttestCmd.Flags().String("pcrs", "0,1,2,3,4,5,6,7", "comma-separated PCR indices")
	deviceAttestCmd.Flags().String("output-cert", "", "output certificate file")

	deviceCmd.AddCommand(deviceEnrollCmd)
	deviceCmd.AddCommand(deviceAttestCmd)
}
