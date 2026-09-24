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

package main

import (
	"github.com/spf13/cobra"
)

// deviceEnrollCmd enrolls a TPM device for a named device spec via the
// enroll-01 ACME challenge.
var deviceEnrollCmd = &cobra.Command{
	Use:   "enroll <name>",
	Short: "Enroll a TPM device",
	Long: `Enroll a TPM device using the ACME enroll-01 challenge type.

This initiates the IEEE 802.1AR / TCG device identity enrollment workflow
for the named device spec defined in the configuration, opening the TPM the
spec configures (a real device, or the in-process simulator when the spec
leaves TPM unset) and issuing the device's IAK and IDevID certificates.

Examples:
  trusted-acme-client device enroll edge-gateway-01`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		name := args[0]
		result, err := svc.Devices().Enroll(cmd.Context(), name)
		if err != nil {
			return err
		}

		cmd.Printf("Device %q enrolled successfully\n", name)
		cmd.Printf("  IAK Subject: %s\n", result.IAKCertificate.Subject.CommonName)
		cmd.Printf("  IAK Expires: %s\n", result.IAKCertificate.NotAfter.Format("2006-01-02"))
		cmd.Printf("  IDevID Subject: %s\n", result.IDevIDCertificate.Subject.CommonName)
		cmd.Printf("  IDevID Expires: %s\n", result.IDevIDCertificate.NotAfter.Format("2006-01-02"))
		if len(result.Chain) > 0 {
			cmd.Printf("  Issuing chain: %d certificate(s)\n", len(result.Chain))
		}
		return nil
	},
}

// deviceAttestCmd attests a TPM device for a named device spec via the
// device-attest-01 ACME challenge.
var deviceAttestCmd = &cobra.Command{
	Use:   "attest <name>",
	Short: "Attest a TPM device",
	Long: `Attest a TPM device using the ACME device-attest-01 challenge type.

This performs TPM-based device attestation with platform configuration
register (PCR) measurements for the named device spec defined in the
configuration, using the PCR selection configured on that spec.

Examples:
  trusted-acme-client device attest edge-gateway-01`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		name := args[0]
		result, err := svc.Devices().Attest(cmd.Context(), name)
		if err != nil {
			return err
		}

		cmd.Printf("Device %q attested successfully\n", name)
		cmd.Printf("  Subject: %s\n", result.Certificate.Subject.CommonName)
		cmd.Printf("  Expires: %s\n", result.Certificate.NotAfter.Format("2006-01-02"))
		return nil
	},
}

func init() {
	deviceCmd.AddCommand(deviceEnrollCmd)
	deviceCmd.AddCommand(deviceAttestCmd)
}
