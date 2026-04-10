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

package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// PIV CSR command errors.
var (
	// ErrPIVCSRCommonNameRequired indicates the common name flag is required.
	ErrPIVCSRCommonNameRequired = errors.New("piv: common name (--cn) is required")

	// ErrPIVCSROutputFailed indicates the CSR could not be written to output.
	ErrPIVCSROutputFailed = errors.New("piv: failed to write CSR to output")
)

// pivCSRCmd generates a CSR for a PIV slot's key.
var pivCSRCmd = &cobra.Command{
	Use:   "csr <slot>",
	Short: "Generate a CSR for a PIV slot's key",
	Long: `Generate a Certificate Signing Request (CSR) for the key in the specified PIV slot.

The CSR can be submitted to a Certificate Authority for signing.
The private key never leaves the PIV device - only the CSR is exported.

Valid slots are:
  9a - PIV Authentication
  9c - Digital Signature
  9d - Key Management
  9e - Card Authentication

Examples:
  # Generate CSR with common name
  xkey piv csr 9a --cn "user@example.com"

  # Generate CSR with full subject information
  xkey piv csr 9c --cn "John Doe" --organization "ACME Corp" --country US

  # Generate CSR with Subject Alternative Names
  xkey piv csr 9a --cn "user@example.com" --san "user@example.com" --san-dns "user.example.com"

  # Generate CSR with IP and URI SANs
  xkey piv csr 9d --cn "server.example.com" --san-dns "server.example.com" --san-ip "192.168.1.100"

  # Export CSR to file
  xkey piv csr 9a --cn "user@example.com" --output /tmp/request.csr

  # Use PKCS#11 backend for key operations
  xkey piv --backend pkcs11 --pkcs11-library /usr/lib/libykcs11.so csr 9a --cn "user@example.com"`,
	Args: cobra.ExactArgs(1),
	RunE: runPivCSR,
}

func init() {
	// Add CSR command to PIV parent command
	PIVCmd.AddCommand(pivCSRCmd)

	// Subject distinguished name flags
	pivCSRCmd.Flags().String("cn", "", "Common Name (required)")
	pivCSRCmd.Flags().String("organization", "", "Organization name")
	pivCSRCmd.Flags().String("organizational-unit", "", "Organizational unit")
	pivCSRCmd.Flags().String("country", "", "Country code (2 letters)")
	pivCSRCmd.Flags().String("province", "", "State or province")
	pivCSRCmd.Flags().String("locality", "", "City or locality")

	// Subject Alternative Names flags
	pivCSRCmd.Flags().StringSlice("san", nil, "Email SAN (can be repeated)")
	pivCSRCmd.Flags().StringSlice("san-dns", nil, "DNS SAN (can be repeated)")
	pivCSRCmd.Flags().StringSlice("san-ip", nil, "IP SAN (can be repeated)")
	pivCSRCmd.Flags().StringSlice("san-uri", nil, "URI SAN (can be repeated)")

	// Output flags
	pivCSRCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")

	// Mark common name as required
	_ = pivCSRCmd.MarkFlagRequired("cn")
}

// runPivCSR executes the piv csr command.
func runPivCSR(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// Validate slot argument
	slot, err := validatePIVSlot(args[0])
	if err != nil {
		return err
	}

	// Get common name (required)
	cn, _ := cmd.Flags().GetString("cn")
	if cn == "" {
		return ErrPIVCSRCommonNameRequired
	}

	// Get configuration
	cfg := buildPIVConfig()

	// Ensure PIV manager is initialized with file storage.
	if err := ensurePIVInitialized(cfg, logger); err != nil {
		return err
	}

	// Generate CSR via xkms package-level function.
	ctx := cmd.Context()
	resp, err := xkms.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{
		Backend: string(cfg.Backend),
		Slot:    string(slot),
		Subject: cn,
	})
	if err != nil {
		return err
	}

	// Output CSR
	outputPath, _ := cmd.Flags().GetString("output")
	if outputPath != "" {
		if err := os.WriteFile(outputPath, resp.CSR, 0600); err != nil {
			return errors.Join(ErrPIVCSROutputFailed, err)
		}
		slotName := pivcert.SlotName(slot)
		fmt.Printf("CSR generated for slot %s (%s) and written to %s\n", slot, slotName, outputPath)
	} else {
		// Write to stdout
		if _, err := os.Stdout.Write(resp.CSR); err != nil {
			return errors.Join(ErrPIVCSROutputFailed, err)
		}
	}

	return nil
}
