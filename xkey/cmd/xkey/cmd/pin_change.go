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

// pinChangeSOCmd changes the Security Officer PIN.
var pinChangeSOCmd = &cobra.Command{
	Use:   "change-so",
	Short: "Change the SO PIN",
	Long: `Change the Security Officer (SO) PIN.

You will be prompted for the current SO PIN and then for the new PIN
with confirmation.

PIN requirements:
  - Minimum 6 characters

Examples:
  # Change the SO PIN
  xkey pin change-so`,
	RunE: runPINChangeSO,
}

// pinChangeUserCmd changes the User PIN.
var pinChangeUserCmd = &cobra.Command{
	Use:   "change-user",
	Short: "Change the User PIN",
	Long: `Change the User PIN.

You will be prompted for the current User PIN and then for the new PIN
with confirmation.

PIN requirements:
  - Minimum 6 characters

Examples:
  # Change the user PIN
  xkey pin change-user`,
	RunE: runPINChangeUser,
}

func init() {
	pinCmd.AddCommand(pinChangeSOCmd)
	pinCmd.AddCommand(pinChangeUserCmd)
}

func runPINChangeSO(cmd *cobra.Command, args []string) error {
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

	// Prompt for current SO PIN.
	currentPIN, err := readPIN(out, "Enter current SO PIN: ")
	if err != nil {
		return err
	}

	// Prompt for new SO PIN with confirmation.
	newPIN, err := readAndConfirmPIN(out, "Enter new SO PIN: ")
	if err != nil {
		return err
	}

	// Change the SO PIN.
	if err := svc.ChangeSOPIN(currentPIN, newPIN); err != nil {
		return &PINCommandError{
			Operation: "change_so",
			Err:       err,
		}
	}

	fmt.Fprintln(out, "SO PIN changed successfully.")
	return nil
}

func runPINChangeUser(cmd *cobra.Command, args []string) error {
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

	// Prompt for current user PIN.
	currentPIN, err := readPIN(out, "Enter current User PIN: ")
	if err != nil {
		return err
	}

	// Prompt for new user PIN with confirmation.
	newPIN, err := readAndConfirmPIN(out, "Enter new User PIN: ")
	if err != nil {
		return err
	}

	// Change the user PIN. The Service handles FIDO2 hash propagation
	// internally via SetFIDO2HashSetter when configured.
	if err := svc.ChangeUserPIN(currentPIN, newPIN); err != nil {
		return &PINCommandError{
			Operation: "change_user",
			Err:       err,
		}
	}

	fmt.Fprintln(out, "User PIN changed successfully.")
	return nil
}
