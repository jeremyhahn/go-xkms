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
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
)

// Unseal command errors.
var (
	ErrUnsealNoVolume       = &UnsealError{Operation: "check_volume", Message: "no encrypted volume found"}
	ErrUnsealPassphraseRead = &UnsealError{Operation: "read_passphrase", Message: "failed to read passphrase"}
	ErrUnsealUnlockFailed   = &UnsealError{Operation: "unlock", Message: "failed to unlock volume"}
)

var (
	unsealPath       string // Custom LUKS file path
	unsealMountPoint string // Custom mount point
)

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unlock encrypted LUKS storage",
	Long: `Unlock the encrypted LUKS2 volume for xKey data storage.

This command:
1. Prompts for the encryption passphrase
2. Sets up the loop device
3. Unlocks the LUKS container
4. Mounts the filesystem to ~/.xkey

Requires root privileges for LUKS operations.

Example:
  sudo xkey luks2 unseal
  sudo xkey luks2 unseal --path /secure/xkey.luks`,
	RunE: runUnseal,
}

func init() {
	unsealCmd.Flags().StringVar(&unsealPath, "path", "", "Custom LUKS file path (default: ~/.xkey.luks)")
	unsealCmd.Flags().StringVar(&unsealMountPoint, "mount-point", "", "Custom mount point (default: ~/.xkey)")

	luks2Cmd.AddCommand(unsealCmd)
}

func runUnseal(cmd *cobra.Command, args []string) error {
	// Check for root privileges
	if os.Geteuid() != 0 {
		return luks.ErrPermissionDenied
	}

	// Determine paths and create volume instance
	vol, err := createUnsealVolume()
	if err != nil {
		return err
	}

	// Check if LUKS file exists
	if !vol.Exists() {
		return ErrUnsealNoVolume
	}

	// Check if already mounted
	if vol.IsMounted() {
		fmt.Fprintf(cmd.OutOrStdout(), "Volume already unlocked and mounted at %s\n", vol.MountPoint)
		return nil
	}

	// Read passphrase
	passphrase, err := readUnsealPassphrase(cmd.OutOrStdout())
	if err != nil {
		return err
	}

	// Unlock the volume
	fmt.Fprintln(cmd.OutOrStdout(), "Unlocking encrypted storage...")
	if err := vol.Unlock(string(passphrase)); err != nil {
		return &UnsealError{Operation: "unlock", Err: err}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Encrypted storage unlocked and mounted at %s\n", vol.MountPoint)
	return nil
}

// readUnsealPassphrase reads passphrase from terminal or stdin.
func readUnsealPassphrase(out io.Writer) (string, error) {
	// Check if stdin is a terminal
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(out, "Enter passphrase: ")
		passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(out)
		if err != nil {
			return "", &UnsealError{Operation: "read_passphrase", Err: err}
		}
		return string(passphrase), nil
	}

	// Read from piped stdin (for automation/testing)
	reader := bufio.NewReader(os.Stdin)
	passphrase, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", &UnsealError{Operation: "read_passphrase", Err: err}
	}
	return strings.TrimSuffix(passphrase, "\n"), nil
}

// createUnsealVolume creates a Volume instance based on command flags.
// When no custom paths are specified, the resolved xhome.Home provides
// the LUKS and mount point paths.
func createUnsealVolume() (*luks.Volume, error) {
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

	if unsealPath != "" {
		luksPath = luks.ExpandPath(unsealPath)
	}
	if unsealMountPoint != "" {
		mountPoint = luks.ExpandPath(unsealMountPoint)
	}

	return luks.NewVolumeWithPaths(luksPath, mountPoint), nil
}

// UnsealError represents an unseal operation error.
type UnsealError struct {
	Operation string
	Message   string
	Err       error
}

// Error returns the error message.
func (e *UnsealError) Error() string {
	if e.Err != nil {
		if e.Message != "" {
			return fmt.Sprintf("unseal: %s: %s: %v", e.Operation, e.Message, e.Err)
		}
		return fmt.Sprintf("unseal: %s: %v", e.Operation, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("unseal: %s: %s", e.Operation, e.Message)
	}
	return fmt.Sprintf("unseal: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *UnsealError) Unwrap() error {
	return e.Err
}
