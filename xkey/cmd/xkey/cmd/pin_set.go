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

// pinSetSOCmd sets the Security Officer PIN.
var pinSetSOCmd = &cobra.Command{
	Use:   "set-so",
	Short: "Set the Security Officer PIN",
	Long: `Set the Security Officer (SO) PIN.

The SO PIN is the master credential for PIN management. It must be set
before user PINs can be configured.

If the SO PIN is already set, you will be prompted for the current SO PIN
before setting the new one.

PIN requirements:
  - Minimum 6 characters

Examples:
  # Set the SO PIN for the first time
  xkey pin set-so

  # Set with custom data directory
  xkey pin set-so --data-dir /secure/xkey`,
	RunE: runPINSetSO,
}

// pinSetUserCmd sets the User PIN.
var pinSetUserCmd = &cobra.Command{
	Use:   "set-user",
	Short: "Set the User PIN (requires SO PIN)",
	Long: `Set the User PIN for day-to-day operations.

Requires SO PIN authorization. You will be prompted for the SO PIN
before setting the new User PIN.

PIN requirements:
  - Minimum 6 characters

Examples:
  # Set the user PIN
  xkey pin set-user

  # Set with custom data directory
  xkey pin set-user --data-dir /secure/xkey`,
	RunE: runPINSetUser,
}

func init() {
	pinCmd.AddCommand(pinSetSOCmd)
	pinCmd.AddCommand(pinSetUserCmd)
}

func runPINSetSO(cmd *cobra.Command, args []string) error {
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

	// If SO PIN is already set, prompt for the current one.
	var currentSOPIN string
	if svc.SOPINSet() {
		currentSOPIN, err = readPIN(out, "Enter current SO PIN: ")
		if err != nil {
			return err
		}
	}

	// Prompt for new SO PIN with confirmation.
	newSOPIN, err := readAndConfirmPIN(out, "Enter new SO PIN: ")
	if err != nil {
		return err
	}

	// Set the SO PIN.
	if err := svc.SetSOPIN(currentSOPIN, newSOPIN); err != nil {
		return &PINCommandError{
			Operation: "set_so",
			Err:       err,
		}
	}

	fmt.Fprintln(out, "SO PIN set successfully.")
	return nil
}

func runPINSetUser(cmd *cobra.Command, args []string) error {
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

	// Check that SO PIN is set first.
	if !svc.SOPINSet() {
		return &PINCommandError{
			Operation: "set_user",
			Message:   "SO PIN must be set first, run 'xkey pin set-so'",
		}
	}

	// Prompt for SO PIN (authorization).
	soPIN, err := readPIN(out, "Enter SO PIN: ")
	if err != nil {
		return err
	}

	// Prompt for new user PIN with confirmation.
	newUserPIN, err := readAndConfirmPIN(out, "Enter new User PIN: ")
	if err != nil {
		return err
	}

	// Set the user PIN. The Service handles FIDO2 hash propagation
	// internally via SetFIDO2HashSetter when configured.
	if err := svc.SetUserPIN(soPIN, newUserPIN); err != nil {
		return &PINCommandError{
			Operation: "set_user",
			Err:       err,
		}
	}

	fmt.Fprintln(out, "User PIN set successfully.")
	return nil
}
