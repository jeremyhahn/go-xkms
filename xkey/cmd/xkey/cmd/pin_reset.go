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

// pinResetLockoutCmd resets the PIN lockout counter.
var pinResetLockoutCmd = &cobra.Command{
	Use:   "reset-lockout",
	Short: "Reset lockout counter (requires SO PIN)",
	Long: `Reset the PIN lockout counter using SO PIN authorization.

After too many failed PIN verification attempts, the account becomes
locked for a configurable duration with exponential backoff. This
command allows the Security Officer to immediately reset the lockout
counter by providing the SO PIN.

Examples:
  # Reset lockout
  xkey pin reset-lockout`,
	RunE: runPINResetLockout,
}

func init() {
	pinCmd.AddCommand(pinResetLockoutCmd)
}

func runPINResetLockout(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// Resolve data directory.
	dataDir, err := resolvePINDataDir()
	if err != nil {
		return err
	}

	// Create PIN service.
	svc, err := createPINService(dataDir)
	if err != nil {
		return err
	}

	// Prompt for SO PIN.
	soPIN, err := readPIN(out, "Enter SO PIN: ")
	if err != nil {
		return err
	}

	// Reset lockout.
	if err := svc.ResetLockout(soPIN); err != nil {
		return &PINCommandError{
			Operation: "reset_lockout",
			Err:       err,
		}
	}

	fmt.Fprintln(out, "Lockout reset successfully.")
	return nil
}
