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

// barrierUnsealCmd unseals the barrier by prompting for the password.
var barrierUnsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseal the barrier",
	Long: `Unseal the barrier by providing the password used during initialization.

This loads the sealed root key blob from the data directory, decrypts it
using the matching sealing strategy, and derives the data encryption key
(DEK). All subsequent storage operations are transparently encrypted with
AES-256-GCM.

Examples:
  # Unseal the barrier
  xkey barrier unseal

  # Unseal with custom data directory
  xkey barrier unseal --data-dir /secure/xkey

  # Unseal from piped password (for automation)
  echo "mypassword" | xkey barrier unseal`,
	RunE: runBarrierUnseal,
}

func init() {
	barrierCmd.AddCommand(barrierUnsealCmd)
}

func runBarrierUnseal(cmd *cobra.Command, args []string) error {
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

	// Read password.
	password, err := readBarrierPassword(out, "Enter barrier password: ")
	if err != nil {
		return err
	}

	// Create barrier and unseal.
	barrier, err := createBarrier(dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = barrier.Close() }()

	creds := seal.Credentials{Secret: password}
	if err := barrier.Unseal(context.Background(), creds); err != nil {
		return &BarrierError{
			Operation: "unseal",
			Err:       err,
		}
	}

	strategy := barrier.ActiveStrategy()
	fmt.Fprintf(out, "Barrier unsealed successfully.\n")
	fmt.Fprintf(out, "  Strategy: %s\n", strategy)

	return nil
}
