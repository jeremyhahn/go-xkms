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
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
)

// Lock command errors.
var (
	ErrLockNoVolume = &LockError{Operation: "check_volume", Message: "no encrypted volume mounted"}
	ErrLockFailed   = &LockError{Operation: "lock", Message: "failed to lock volume"}
)

var (
	lockPath       string // Custom LUKS file path
	lockMountPoint string // Custom mount point
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock encrypted LUKS storage",
	Long: `Lock the encrypted LUKS2 volume, unmounting and closing it.

This command:
1. Unmounts the filesystem from ~/.xkey
2. Closes the LUKS container
3. Detaches the loop device

Requires root privileges for LUKS operations.

Example:
  sudo xkey luks2 lock
  sudo xkey luks2 lock --path /secure/xkey.luks`,
	RunE: runLock,
}

func init() {
	lockCmd.Flags().StringVar(&lockPath, "path", "", "Custom LUKS file path (default: ~/.xkey.luks)")
	lockCmd.Flags().StringVar(&lockMountPoint, "mount-point", "", "Custom mount point (default: ~/.xkey)")

	luks2Cmd.AddCommand(lockCmd)
}

func runLock(cmd *cobra.Command, args []string) error {
	// Check for root privileges
	if os.Geteuid() != 0 {
		return luks.ErrPermissionDenied
	}

	// Determine paths and create volume instance
	vol, err := createLockVolume()
	if err != nil {
		return err
	}

	// Check if mounted or open
	if !vol.IsMounted() && !vol.IsOpen() {
		return ErrLockNoVolume
	}

	// Lock the volume
	fmt.Fprintln(cmd.OutOrStdout(), "Locking encrypted storage...")
	if err := vol.Lock(); err != nil {
		return &LockError{Operation: "lock", Err: err}
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Encrypted storage locked successfully.")
	return nil
}

// createLockVolume creates a Volume instance based on command flags.
// When no custom paths are specified, the resolved xhome.Home provides
// the LUKS and mount point paths.
func createLockVolume() (*luks.Volume, error) {
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

	if lockPath != "" {
		luksPath = luks.ExpandPath(lockPath)
	}
	if lockMountPoint != "" {
		mountPoint = luks.ExpandPath(lockMountPoint)
	}

	return luks.NewVolumeWithPaths(luksPath, mountPoint), nil
}

// LockError represents a lock operation error.
type LockError struct {
	Operation string
	Message   string
	Err       error
}

// Error returns the error message.
func (e *LockError) Error() string {
	if e.Err != nil {
		if e.Message != "" {
			return fmt.Sprintf("lock: %s: %s: %v", e.Operation, e.Message, e.Err)
		}
		return fmt.Sprintf("lock: %s: %v", e.Operation, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("lock: %s: %s", e.Operation, e.Message)
	}
	return fmt.Sprintf("lock: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *LockError) Unwrap() error {
	return e.Err
}
