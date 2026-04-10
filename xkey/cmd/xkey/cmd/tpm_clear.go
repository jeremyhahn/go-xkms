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
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

// TPM clear error types
var (
	ErrTPMClearNotRoot      = errors.New("tpm: force clear requires root privileges")
	ErrTPMClearPPINotFound  = errors.New("tpm: PPI interface not found - UEFI TPM clear not supported")
	ErrTPMClearPPIFailed    = errors.New("tpm: failed to write PPI request")
	ErrTPMClearCancelled    = errors.New("tpm: clear operation cancelled")
	ErrTPMClearAuthRequired = errors.New("tpm: lockout authorization required for clear")
	ErrTPMClearHierarchy    = errors.New("tpm: invalid hierarchy - must be one of: lockout, owner, platform")
	ErrTPMClearRebootFailed = errors.New("tpm: failed to initiate reboot")
)

// tpmClearConfig holds configuration for the clear command
type tpmClearConfig struct {
	force       bool
	hierarchy   string
	yes         bool
	lockoutAuth string
}

var clearCfg = &tpmClearConfig{}

var tpmClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear TPM state",
	Long: `Clear the TPM, removing all context associated with the Owner hierarchy.

The clear operation will:
  - Flush resident objects (persistent and volatile) in Storage and Endorsement hierarchies
  - Delete NV indexes with TPMA_NV_PLATFORMCREATE == CLEAR
  - Change the storage primary seed (SPS) to a new random value
  - Change shProof and ehProof
  - SET shEnable and ehEnable
  - Set ownerAuth, endorsementAuth, and lockoutAuth to empty
  - Set ownerPolicy, endorsementPolicy, and lockoutPolicy to empty
  - Reset Clock, resetCount, restartCount to zero
  - Set Safe to YES
  - Increment pcrUpdateCounter

WARNING: This is a destructive operation that cannot be undone!
         All TPM-protected secrets, keys, and sealed data will be lost.

Modes:
  Standard clear (default):
    Requires lockout hierarchy authorization. Use --lockout-auth to provide
    the current lockout password.

  Force clear (--force):
    Uses UEFI Physical Presence Interface (PPI) to schedule a TPM clear
    at next reboot. Requires root privileges and will trigger a system reboot.
    Use this when hierarchy authorization is unknown or locked out.

Examples:
  # Standard clear with lockout authorization
  xkey tpm clear --lockout-auth "my-lockout-password"

  # Force clear via UEFI PPI (requires root, triggers reboot)
  sudo xkey tpm clear --force

  # Skip confirmation prompt
  xkey tpm clear --lockout-auth "password" --yes`,
	RunE: runTPMClear,
}

func init() {
	tpmClearCmd.Flags().BoolVar(&clearCfg.force, "force", false,
		"Force TPM clear via UEFI PPI (requires root, triggers reboot)")
	tpmClearCmd.Flags().StringVar(&clearCfg.hierarchy, "hierarchy", "lockout",
		"Authorization hierarchy for standard clear (lockout, owner, platform)")
	tpmClearCmd.Flags().BoolVarP(&clearCfg.yes, "yes", "y", false,
		"Skip confirmation prompt")
	tpmClearCmd.Flags().StringVar(&clearCfg.lockoutAuth, "lockout-auth", "",
		"Lockout hierarchy authorization password")

	// Register with tpm command
	tpmCmd.AddCommand(tpmClearCmd)
}

func runTPMClear(cmd *cobra.Command, args []string) error {
	// Confirmation prompt
	if !clearCfg.yes {
		if !confirmClear(clearCfg.force) {
			return ErrTPMClearCancelled
		}
	}

	if clearCfg.force {
		return runForceTPMClear(cmd)
	}

	return runStandardTPMClear(cmd)
}

// runForceTPMClear performs a TPM clear via UEFI Physical Presence Interface
func runForceTPMClear(cmd *cobra.Command) error {
	// Check for root privileges
	if os.Geteuid() != 0 {
		cmd.PrintErrln("Error: Force clear requires root privileges")
		cmd.PrintErrln("Hint: Run with sudo: sudo xkey tpm clear --force")
		return ErrTPMClearNotRoot
	}

	// Determine the TPM device name from the device path
	deviceName := filepath.Base(tpmCfg.device)
	// Handle /dev/tpmrm0 -> tpm0 mapping
	deviceName = strings.TrimPrefix(deviceName, "tpmrm")
	if strings.HasPrefix(deviceName, "tpmrm") {
		deviceName = "tpm" + strings.TrimPrefix(deviceName, "tpmrm")
	} else if !strings.HasPrefix(deviceName, "tpm") {
		deviceName = "tpm0" // Default
	}

	// PPI request file path
	// See: https://github.com/tpm2-software/tpm2-tools/issues/1956
	ppiRequestPath := fmt.Sprintf("/sys/class/tpm/%s/ppi/request", deviceName)

	// Check if PPI interface exists
	if _, err := os.Stat(ppiRequestPath); os.IsNotExist(err) {
		cmd.PrintErrf("Error: PPI interface not found at %s\n", ppiRequestPath)
		cmd.PrintErrln("Your system may not support UEFI TPM clear via PPI.")
		return ErrTPMClearPPINotFound
	}

	// Write PPI request "5" (TPM_CLEAR operation)
	// PPI operation codes: https://trustedcomputinggroup.org/wp-content/uploads/Physical-Presence-Interface_1-30_0-52.pdf
	// 5 = TPM2_Clear (Physical Presence)
	err := os.WriteFile(ppiRequestPath, []byte("5"), 0644)
	if err != nil {
		cmd.PrintErrf("Error: Failed to write PPI request: %v\n", err)
		return ErrTPMClearPPIFailed
	}

	cmd.Println("TPM clear scheduled via UEFI Physical Presence Interface.")
	cmd.Println("The system will now reboot to complete the TPM clear operation.")
	cmd.Println("")
	cmd.Println("After reboot, you may need to:")
	cmd.Println("  1. Confirm the TPM clear operation in UEFI/BIOS firmware")
	cmd.Println("  2. Re-run 'xkey tpm provision' to set up your TPM")
	cmd.Println("")

	if !clearCfg.yes {
		cmd.Print("Press Enter to reboot...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}

	// Initiate system reboot
	err = syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
	if err != nil {
		cmd.PrintErrf("Error: Failed to initiate reboot: %v\n", err)
		cmd.PrintErrln("Please reboot manually to complete the TPM clear operation.")
		return ErrTPMClearRebootFailed
	}

	return nil
}

// runStandardTPMClear performs a standard TPM clear using lockout authorization
func runStandardTPMClear(cmd *cobra.Command) error {
	// Open TPM for provisioning (allows unprovisioned state)
	tpm, err := openTPMForProvisioning()
	if err != nil {
		cmd.PrintErrf("Error: Failed to open TPM: %v\n", err)
		return err
	}
	defer tpm.Close()

	// Get lockout auth
	var lockoutAuth []byte
	if clearCfg.lockoutAuth != "" {
		lockoutAuth = []byte(clearCfg.lockoutAuth)
	} else if tpmCfg.hierarchyAuth != "" {
		lockoutAuth = []byte(tpmCfg.hierarchyAuth)
	}
	// Note: empty lockoutAuth is valid if the TPM hasn't been locked

	// Perform the clear
	cmd.Println("Clearing TPM...")

	err = tpm.Clear(lockoutAuth)
	if err != nil {
		cmd.PrintErrf("Error: TPM clear failed: %v\n", err)
		cmd.PrintErrln("")
		cmd.PrintErrln("If the lockout hierarchy is protected, try:")
		cmd.PrintErrln("  1. Provide the correct --lockout-auth password")
		cmd.PrintErrln("  2. Use --force to clear via UEFI PPI (requires root)")
		return err
	}

	cmd.Println("TPM successfully cleared.")
	cmd.Println("")
	cmd.Println("The TPM is now in a clean state. You may want to:")
	cmd.Println("  - Run 'xkey tpm provision' to set up your TPM")
	cmd.Println("  - Re-run the xKey setup wizard")

	return nil
}

// confirmClear prompts the user for confirmation before clearing the TPM
func confirmClear(force bool) bool {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("")
	fmt.Println("========================================")
	fmt.Println("  WARNING: TPM CLEAR OPERATION")
	fmt.Println("========================================")
	fmt.Println("")
	fmt.Println("This operation will:")
	fmt.Println("  - Erase ALL TPM-protected keys and secrets")
	fmt.Println("  - Reset ALL hierarchy authorizations to empty")
	fmt.Println("  - Delete sealed data and NV indexes")
	fmt.Println("")

	if force {
		fmt.Println("Mode: FORCE (UEFI Physical Presence Interface)")
		fmt.Println("  - System will REBOOT to complete the operation")
		fmt.Println("  - You may need to confirm in UEFI/BIOS firmware")
		fmt.Println("")
	}

	fmt.Println("This action CANNOT be undone!")
	fmt.Println("")
	fmt.Print("Type 'yes' to proceed: ")

	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes"
}
