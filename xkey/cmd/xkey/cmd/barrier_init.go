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
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// barrierInitCmd initializes the barrier for first-time setup.
var barrierInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the barrier (first-time setup)",
	Long: `Initialize the barrier by generating a new root key and sealing it.

This must be called exactly once before the barrier can be used. A root
key is generated using crypto/rand and sealed with the best available
strategy. The sealed root key blob is persisted to the data directory.

Strategies (in preference order):
  tpm2      - TPM 2.0 hardware-backed sealing
  pkcs11    - PKCS#11 HSM token sealing
  software  - Argon2id password-based (always available)

Use --strategy to force a specific strategy instead of auto-detecting.

Examples:
  # Auto-detect best strategy
  xkey barrier init

  # Force software-only strategy
  xkey barrier init --strategy software

  # Use a custom data directory
  xkey barrier init --data-dir /secure/xkey`,
	RunE: runBarrierInit,
}

func init() {
	barrierInitCmd.Flags().StringVar(&barrierStrategy, "strategy", "",
		"sealing strategy: software, tpm2, pkcs11 (default: auto-detect)")

	barrierCmd.AddCommand(barrierInitCmd)
}

func runBarrierInit(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// Validate strategy flag if provided.
	if barrierStrategy != "" {
		if !isValidStrategy(barrierStrategy) {
			return &BarrierError{
				Operation: "validate_strategy",
				Message:   fmt.Sprintf("unknown strategy %q, valid values: software, tpm2, pkcs11", barrierStrategy),
			}
		}
	}

	// Resolve data directory.
	dataDir, err := resolveBarrierDataDir()
	if err != nil {
		return err
	}

	// Check if barrier already initialized.
	if barrierRootKeyExists(dataDir) {
		return &BarrierError{
			Operation: "check_initialized",
			Message:   "barrier already initialized (root key exists)",
		}
	}

	// Read and confirm password.
	password, err := readAndConfirmBarrierPassword(out)
	if err != nil {
		return err
	}

	// Create and initialize the barrier.
	barrier, err := createBarrier(dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = barrier.Close() }()

	creds := seal.Credentials{Secret: password}
	if err := barrier.Initialize(context.Background(), creds); err != nil {
		return &BarrierError{
			Operation: "initialize",
			Err:       err,
		}
	}

	// Report success with strategy used.
	strategy := barrier.ActiveStrategy()
	fmt.Fprintf(out, "Barrier initialized successfully.\n")
	fmt.Fprintf(out, "  Strategy:        %s\n", strategy)
	fmt.Fprintf(out, "  Data directory:  %s\n", dataDir)
	fmt.Fprintf(out, "\nUse 'xkey barrier unseal' to unseal the barrier.\n")

	return nil
}

// isValidStrategy checks whether the given strategy string is recognized.
func isValidStrategy(s string) bool {
	valid := map[string]bool{
		"software": true,
		"tpm2":     true,
		"pkcs11":   true,
	}
	return valid[s]
}
