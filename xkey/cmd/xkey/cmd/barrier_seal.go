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
	"fmt"

	"github.com/spf13/cobra"
)

// barrierSealCmd seals the barrier to lock all operations.
var barrierSealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seal the barrier (lock it)",
	Long: `Seal the barrier to lock all storage operations.

This zeros the data encryption key (DEK) from memory and transitions the
barrier to the sealed state. All subsequent storage operations will fail
until 'xkey barrier unseal' is called again.

Sealing is idempotent -- calling seal on an already-sealed barrier has
no effect.

Examples:
  # Seal the barrier
  xkey barrier seal`,
	RunE: runBarrierSeal,
}

func init() {
	barrierCmd.AddCommand(barrierSealCmd)
}

func runBarrierSeal(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// Resolve data directory.
	dataDir, err := resolveBarrierDataDir()
	if err != nil {
		return err
	}

	// Check if barrier is initialized.
	if !barrierRootKeyExists(dataDir) {
		return &BarrierError{
			Operation: "check_initialized",
			Message:   "barrier not initialized, run 'xkey barrier init' first",
		}
	}

	// Create barrier instance and seal it.
	barrier, err := createBarrier(dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = barrier.Close() }()

	if err := barrier.Seal(); err != nil {
		return &BarrierError{
			Operation: "seal",
			Err:       err,
		}
	}

	fmt.Fprintln(out, "Barrier sealed successfully.")

	return nil
}
