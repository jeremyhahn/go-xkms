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
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
)

// Wipe command errors.
var (
	ErrWipeNoContainer     = &WipeError{Operation: "check_container", Message: "no container found"}
	ErrWipeAborted         = &WipeError{Operation: "confirm", Message: "operation aborted by user"}
	ErrWipeFailed          = &WipeError{Operation: "wipe", Message: "failed to wipe container"}
	ErrWipeContainerInUse  = &WipeError{Operation: "lock", Message: "container is in use and could not be locked"}
	ErrWipeInvalidStandard = &WipeError{Operation: "validate", Message: "invalid wipe standard (use: nist, dod3, dod7)"}
)

// wipeStandardMap maps CLI flag values to luks.WipeStandard constants.
var wipeStandardMap = map[string]luks.WipeStandard{
	"nist": luks.StandardNIST,
	"dod3": luks.StandardDoD3Pass,
	"dod7": luks.StandardDoD7Pass,
}

var (
	wipeStandard   string // Wipe standard: nist, dod3, dod7
	wipeForce      bool   // Skip confirmation prompt
	wipePath       string // Container path
	wipeMountPoint string // Custom mount point
)

var wipeCmd = &cobra.Command{
	Use:   "wipe",
	Short: "Securely destroy LUKS container",
	Long: `Securely destroy the LUKS2 encrypted container.

WARNING: This operation is IRREVERSIBLE. All data in the container will be
permanently destroyed and cannot be recovered.

This command:
1. Locks the container if currently mounted
2. Overwrites the container data using industry-standard wipe methods
3. Removes the container file

Wipe Standards:
  nist    NIST SP 800-88 Rev 1 - Single pass of random data (fastest)
  dod3    DoD 5220.22-M 3-pass - Zeros, ones, random (default, balanced)
  dod7    DoD 5220.22-M ECE 7-pass - Extended 7-pass variant (most thorough)

Security Options:
  --standard S    Wipe standard to use (default: dod3)
  --force         Skip confirmation prompt (DANGEROUS)

Requires root privileges for LUKS operations.

Example:
  sudo xkey luks2 wipe                    # DoD 3-pass wipe (default)
  sudo xkey luks2 wipe --standard nist    # NIST single-pass (fastest)
  sudo xkey luks2 wipe --standard dod7    # DoD 7-pass (most thorough)
  sudo xkey luks2 wipe --force            # Skip confirmation (scripting)`,
	RunE: runWipe,
}

func init() {
	wipeCmd.Flags().StringVar(&wipeStandard, "standard", "dod3", "Wipe standard: nist, dod3, dod7")
	wipeCmd.Flags().BoolVar(&wipeForce, "force", false, "Skip confirmation prompt")
	wipeCmd.Flags().StringVar(&wipePath, "path", "", "Container path (default: ~/.xkey.luks)")
	wipeCmd.Flags().StringVar(&wipeMountPoint, "mount-point", "", "Custom mount point (default: ~/.xkey)")

	luks2Cmd.AddCommand(wipeCmd)
}

func runWipe(cmd *cobra.Command, args []string) error {
	// Check for root privileges
	if os.Geteuid() != 0 {
		return luks.ErrPermissionDenied
	}

	// Validate wipe standard
	standard, ok := wipeStandardMap[wipeStandard]
	if !ok {
		return ErrWipeInvalidStandard
	}

	// Get volume
	vol, err := createWipeVolume()
	if err != nil {
		return err
	}

	// Check container exists
	if !vol.Exists() {
		return ErrWipeNoContainer
	}

	// Get container size for display
	size, _ := getFileSize(vol.LUKSPath)

	// Get pattern description for display
	patternDesc := getWipePatternDescription(standard)

	// Confirmation prompt
	if !wipeForce {
		fmt.Fprintln(cmd.OutOrStdout(), "======================================================================")
		fmt.Fprintln(cmd.OutOrStdout(), "                         WARNING")
		fmt.Fprintln(cmd.OutOrStdout(), "")
		fmt.Fprintln(cmd.OutOrStdout(), "  You are about to PERMANENTLY DESTROY the encrypted container")
		fmt.Fprintln(cmd.OutOrStdout(), "  and ALL data stored within it.")
		fmt.Fprintln(cmd.OutOrStdout(), "")
		fmt.Fprintln(cmd.OutOrStdout(), "  THIS ACTION CANNOT BE UNDONE!")
		fmt.Fprintln(cmd.OutOrStdout(), "======================================================================")
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.OutOrStdout(), "Container: %s\n", vol.LUKSPath)
		fmt.Fprintf(cmd.OutOrStdout(), "Size:      %s\n", formatSize(size))
		fmt.Fprintf(cmd.OutOrStdout(), "Standard:  %s\n", wipeStandard)
		fmt.Fprintf(cmd.OutOrStdout(), "Pattern:   %s\n", patternDesc)
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprint(cmd.OutOrStdout(), "Type 'DESTROY' to confirm: ")

		reader := bufio.NewReader(os.Stdin)
		confirmation, err := reader.ReadString('\n')
		if err != nil {
			return &WipeError{Operation: "read_confirmation", Err: err}
		}

		confirmation = strings.TrimSpace(confirmation)
		if confirmation != "DESTROY" {
			return ErrWipeAborted
		}
	}

	// Lock container if mounted
	if vol.IsMounted() || vol.IsOpen() {
		fmt.Fprintln(cmd.OutOrStdout(), "Locking container...")
		if err := vol.Lock(); err != nil {
			return &WipeError{Operation: "lock", Message: "container must be unlocked first", Err: err}
		}
	}

	// Perform wipe operation using local wipe implementation
	fmt.Fprintf(cmd.OutOrStdout(), "Wiping container (%s)...\n", wipeStandard)
	if err := wipeContainerWithStandard(vol.LUKSPath, standard); err != nil {
		return &WipeError{Operation: "wipe", Err: err}
	}

	// Remove the container file
	fmt.Fprintln(cmd.OutOrStdout(), "Removing container file...")
	if err := os.Remove(vol.LUKSPath); err != nil {
		return &WipeError{Operation: "remove_file", Err: err}
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Container securely destroyed.")
	return nil
}

// createWipeVolume creates a Volume instance based on command flags.
func createWipeVolume() (*luks.Volume, error) {
	var luksPath, mountPoint string
	if h := GetHome(); h != nil {
		luksPath = h.LUKSPath()
		mountPoint = h.MountPoint()
	} else {
		var err error
		luksPath, err = luks.GetDefaultLUKSPath()
		if err != nil {
			return nil, err
		}
		mountPoint, err = luks.GetDefaultDataDir()
		if err != nil {
			return nil, err
		}
	}

	if wipePath != "" {
		luksPath = luks.ExpandPath(wipePath)
	}
	if wipeMountPoint != "" {
		mountPoint = luks.ExpandPath(wipeMountPoint)
	}

	return luks.NewVolumeWithPaths(luksPath, mountPoint), nil
}

// wipeContainerWithStandard performs secure wiping using wipe standards.
func wipeContainerWithStandard(path string, standard luks.WipeStandard) error {
	opts := luks.WipeOptions{
		Path:     path,
		Standard: standard,
	}
	return luks.Wipe(opts)
}

// getWipePatternDescription returns a human-readable description of the wipe pattern.
func getWipePatternDescription(standard luks.WipeStandard) string {
	switch standard {
	case luks.StandardNIST:
		return "random (1 pass)"
	case luks.StandardDoD3Pass:
		return "zeros → ones → random (3 passes)"
	case luks.StandardDoD7Pass:
		return "(Z→O→R) + R + (Z→O→R) (7 passes)"
	default:
		return "custom"
	}
}

// WipeError represents a wipe operation error.
type WipeError struct {
	Operation string
	Message   string
	Err       error
}

// Error returns the error message.
func (e *WipeError) Error() string {
	if e.Err != nil {
		if e.Message != "" {
			return fmt.Sprintf("wipe: %s: %s: %v", e.Operation, e.Message, e.Err)
		}
		return fmt.Sprintf("wipe: %s: %v", e.Operation, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("wipe: %s: %s", e.Operation, e.Message)
	}
	return fmt.Sprintf("wipe: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *WipeError) Unwrap() error {
	return e.Err
}
