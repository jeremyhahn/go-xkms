// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build pkcs11

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-keychain/pkg/backend/smartcardhsm"
	"github.com/spf13/cobra"
)

// dkekCmd represents the DKEK command
var dkekCmd = &cobra.Command{
	Use:   "dkek",
	Short: "Manage DKEK (Device Key Encryption Key) operations",
	Long: `Manage DKEK operations for SmartCard-HSM devices.

DKEK uses Shamir's Secret Sharing to split a device key into multiple shares.
These shares can be distributed to multiple administrators for secure key backup and restore.`,
}

// dkekGenerateCmd generates DKEK shares
var dkekGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate DKEK shares",
	Long: `Generate a new DKEK and split it into shares using Shamir's Secret Sharing.

The DKEK is split into N shares where any M shares can reconstruct the original key.
The shares are stored securely and can be distributed to different administrators.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		shares, _ := cmd.Flags().GetInt("shares")
		threshold, _ := cmd.Flags().GetInt("threshold")

		printVerbose("Generating DKEK with %d shares (threshold: %d)", shares, threshold)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer be.Close()

		// Check if backend supports DKEK
		scHSM, ok := be.(*smartcardhsm.Backend)
		if !ok {
			handleError(fmt.Errorf("backend does not support DKEK operations (not a SmartCard-HSM backend)"))
			return
		}

		// Generate DKEK shares
		dkekShares, err := scHSM.DKEK().Generate()
		if err != nil {
			handleError(fmt.Errorf("failed to generate DKEK shares: %w", err))
			return
		}

		// Format output
		result := map[string]interface{}{
			"shares":    len(dkekShares),
			"threshold": threshold,
			"message":   fmt.Sprintf("Successfully generated %d DKEK shares", len(dkekShares)),
		}

		if cfg.OutputFormat == "json" {
			shares := make([]map[string]interface{}, len(dkekShares))
			for i, share := range dkekShares {
				shares[i] = map[string]interface{}{
					"index": share.Index,
					// Don't expose actual share values in CLI output for security
					"stored": true,
				}
			}
			result["share_indices"] = shares
		}

		data, _ := json.Marshal(result)
		if err := printer.PrintSuccess(string(data)); err != nil {
			handleError(err)
		}
	},
}

// dkekListCmd lists DKEK shares
var dkekListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available DKEK shares",
	Long:  `List all DKEK shares stored in the backend.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Listing DKEK shares")

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer be.Close()

		// Check if backend supports DKEK
		scHSM, ok := be.(*smartcardhsm.Backend)
		if !ok {
			handleError(fmt.Errorf("backend does not support DKEK operations (not a SmartCard-HSM backend)"))
			return
		}

		// Load all shares
		shares, err := scHSM.DKEK().LoadAllShares()
		if err != nil {
			handleError(fmt.Errorf("failed to load DKEK shares: %w", err))
			return
		}

		// Format output
		result := map[string]interface{}{
			"total_shares": len(shares),
			"threshold":    scHSM.DKEK().GetThreshold(),
		}

		if cfg.OutputFormat == "json" {
			shareList := make([]map[string]interface{}, len(shares))
			for i, share := range shares {
				shareList[i] = map[string]interface{}{
					"index": share.Index,
					// Don't expose actual share values in CLI output for security
				}
			}
			result["shares"] = shareList
		}

		data, _ := json.Marshal(result)
		if err := printer.PrintSuccess(string(data)); err != nil {
			handleError(err)
		}
	},
}

// dkekVerifyCmd verifies DKEK shares
var dkekVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify DKEK shares integrity",
	Long: `Verify that DKEK shares are valid and can be used to reconstruct the DKEK.

This checks the integrity of the shares without actually reconstructing the DKEK.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Verifying DKEK shares")

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer be.Close()

		// Check if backend supports DKEK
		scHSM, ok := be.(*smartcardhsm.Backend)
		if !ok {
			handleError(fmt.Errorf("backend does not support DKEK operations (not a SmartCard-HSM backend)"))
			return
		}

		// Load all shares
		shares, err := scHSM.DKEK().LoadAllShares()
		if err != nil {
			handleError(fmt.Errorf("failed to load DKEK shares: %w", err))
			return
		}

		// Verify shares
		if err := scHSM.DKEK().VerifyShares(shares); err != nil {
			handleError(fmt.Errorf("DKEK share verification failed: %w", err))
			return
		}

		result := map[string]interface{}{
			"valid":        true,
			"shares_count": len(shares),
			"threshold":    scHSM.DKEK().GetThreshold(),
			"message":      "DKEK shares are valid and sufficient for reconstruction",
		}

		data, _ := json.Marshal(result)
		if err := printer.PrintSuccess(string(data)); err != nil {
			handleError(err)
		}
	},
}

// dkekDeleteCmd deletes DKEK shares
var dkekDeleteCmd = &cobra.Command{
	Use:   "delete [share-index]",
	Short: "Delete DKEK share(s)",
	Long: `Delete one or all DKEK shares.

If a share index is provided, only that share is deleted.
If --all flag is used, all shares are deleted.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		all, _ := cmd.Flags().GetBool("all")

		if !all && len(args) == 0 {
			handleError(fmt.Errorf("must specify either a share index or --all flag"))
			return
		}

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer be.Close()

		// Check if backend supports DKEK
		scHSM, ok := be.(*smartcardhsm.Backend)
		if !ok {
			handleError(fmt.Errorf("backend does not support DKEK operations (not a SmartCard-HSM backend)"))
			return
		}

		if all {
			printVerbose("Deleting all DKEK shares")
			if err := scHSM.DKEK().DeleteAllShares(); err != nil {
				handleError(fmt.Errorf("failed to delete DKEK shares: %w", err))
				return
			}
			if err := printer.PrintSuccess("Successfully deleted all DKEK shares"); err != nil {
				handleError(err)
			}
			return
		}

		// Parse share index
		var shareIndex byte
		_, err = fmt.Sscanf(args[0], "%d", &shareIndex)
		if err != nil {
			handleError(fmt.Errorf("invalid share index: %w", err))
			return
		}

		printVerbose("Deleting DKEK share %d", shareIndex)
		if err := scHSM.DKEK().DeleteShare(shareIndex); err != nil {
			handleError(fmt.Errorf("failed to delete DKEK share: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully deleted DKEK share %d", shareIndex)); err != nil {
			handleError(err)
		}
	},
}

func init() {
	// Add dkek command to root
	rootCmd.AddCommand(dkekCmd)

	// Add subcommands
	dkekCmd.AddCommand(dkekGenerateCmd)
	dkekCmd.AddCommand(dkekListCmd)
	dkekCmd.AddCommand(dkekVerifyCmd)
	dkekCmd.AddCommand(dkekDeleteCmd)

	// Flags for generate command
	dkekGenerateCmd.Flags().IntP("shares", "n", 5, "Total number of shares to create")
	dkekGenerateCmd.Flags().IntP("threshold", "t", 3, "Minimum shares needed to reconstruct DKEK")

	// Flags for delete command
	dkekDeleteCmd.Flags().BoolP("all", "a", false, "Delete all DKEK shares")
}
