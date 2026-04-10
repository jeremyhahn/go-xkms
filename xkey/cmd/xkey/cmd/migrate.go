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
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
)

// Migrate command errors.
var (
	ErrMigrateNoSource            = errors.New("migrate: no source container found")
	ErrMigrateSourceLocked        = errors.New("migrate: failed to unlock source container")
	ErrMigrateCreateFailed        = errors.New("migrate: failed to create new container")
	ErrMigrateDataCopyFailed      = errors.New("migrate: failed to copy data")
	ErrMigrateRenameFailed        = errors.New("migrate: failed to rename container")
	ErrMigratePassphraseRead      = errors.New("migrate: failed to read passphrase")
	ErrMigrateInvalidWipeStandard = errors.New("migrate: invalid wipe standard (use: nist, dod3, dod7)")
)

var (
	migrateSize         string // New container size (e.g., "200M", "1G")
	migratePath         string // New container path
	migrateSourcePath   string // Source container path (default: ~/.xkey.luks)
	migrateKeepOld      bool   // Keep old container after migration
	migrateWipe         bool   // Securely wipe old container after migration
	migrateWipeStandard string // Wipe standard: nist, dod3, dod7
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate to a new/larger LUKS container",
	Long: `Migrate xKey encrypted storage to a new or larger LUKS container.

This command:
1. Locks the current container if mounted
2. Renames the existing container to ~/.xkey.luks.old
3. Creates a new container (default: 2x current size)
4. Unlocks the old container
5. Copies all data to the new container
6. Locks the old container
7. Removes or securely wipes the old container

Use this command when:
- You need more storage space
- You want to change the encryption parameters
- You're migrating to a new location

Wipe Standards:
  nist    NIST SP 800-88 Rev 1 - Single pass of random data (fastest)
  dod3    DoD 5220.22-M 3-pass - Zeros, ones, random (default, balanced)
  dod7    DoD 5220.22-M ECE 7-pass - Extended 7-pass variant (most thorough)

Security Options:
  --wipe              Securely wipe old container after migration (slower but more secure)
  --wipe-standard S   Wipe standard to use (default: dod3)
  --keep-old          Keep old container as backup (no removal or wipe)

Requires root privileges for LUKS operations.

Example:
  sudo xkey luks2 migrate                             # Double the container size
  sudo xkey luks2 migrate --size 500M                 # Migrate to 500MB container
  sudo xkey luks2 migrate --keep-old                  # Keep old container after migration
  sudo xkey luks2 migrate --wipe                      # Securely wipe old container (DoD 3-pass)
  sudo xkey luks2 migrate --wipe --wipe-standard nist # NIST single-pass wipe (fastest)
  sudo xkey luks2 migrate --wipe --wipe-standard dod7 # DoD 7-pass wipe (most thorough)
  sudo xkey luks2 migrate --path /new/location.luks   # Migrate to new path`,
	RunE: runMigrate,
}

func init() {
	migrateCmd.Flags().StringVar(&migrateSize, "size", "", "New container size (default: 2x current size)")
	migrateCmd.Flags().StringVar(&migratePath, "path", "", "New container path (default: same as current)")
	migrateCmd.Flags().StringVar(&migrateSourcePath, "source-path", "", "Source container path (default: ~/.xkey.luks)")
	migrateCmd.Flags().BoolVar(&migrateKeepOld, "keep-old", false, "Keep old container after migration")
	migrateCmd.Flags().BoolVar(&migrateWipe, "wipe", false, "Securely wipe old container after migration")
	migrateCmd.Flags().StringVar(&migrateWipeStandard, "wipe-standard", "dod3", "Wipe standard: nist, dod3, dod7")

	luks2Cmd.AddCommand(migrateCmd)
}

func runMigrate(cmd *cobra.Command, args []string) error {
	// Check for root privileges
	if os.Geteuid() != 0 {
		return luks.ErrPermissionDenied
	}

	// Validate wipe standard if wipe is enabled
	var wipeStdValue luks.WipeStandard
	if migrateWipe {
		std, ok := wipeStandardMap[migrateWipeStandard]
		if !ok {
			return ErrMigrateInvalidWipeStandard
		}
		wipeStdValue = std
	}

	// Get source volume
	var sourceVol *luks.Volume
	var err error
	if migrateSourcePath != "" {
		// Use custom source path — resolve mount point from home or legacy default.
		var mountPoint string
		if h := GetHome(); h != nil {
			mountPoint = h.MountPoint()
		} else {
			mountPoint, err = luks.GetDefaultDataDir()
			if err != nil {
				return err
			}
		}
		sourceVol = luks.NewVolumeWithPaths(migrateSourcePath, mountPoint)
	} else if h := GetHome(); h != nil {
		sourceVol = luks.NewVolumeFromHome(h)
	} else {
		sourceVol, err = luks.NewVolume()
		if err != nil {
			return err
		}
	}

	// Check source exists
	if !sourceVol.Exists() {
		return ErrMigrateNoSource
	}

	// Lock source if mounted
	if sourceVol.IsMounted() || sourceVol.IsOpen() {
		fmt.Fprintln(cmd.OutOrStdout(), "Locking current container...")
		if err := sourceVol.Lock(); err != nil {
			// If lock fails, try to continue (might already be locked)
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not lock container: %v\n", err)
		}
	}

	// Get current container size
	currentSize, err := getFileSize(sourceVol.LUKSPath)
	if err != nil {
		return &MigrateError{Operation: "get_size", Err: fmt.Errorf("failed to get container size: %w", err)}
	}

	// Determine new size
	var newSize int64
	if migrateSize != "" {
		newSize, err = parseSize(migrateSize)
		if err != nil {
			return &MigrateError{Operation: "parse_size", Err: fmt.Errorf("invalid size: %w", err)}
		}
	} else {
		newSize = currentSize * 2
	}

	// Determine new path
	newPath := sourceVol.LUKSPath
	if migratePath != "" {
		newPath = luks.ExpandPath(migratePath)
	}

	// Create backup path for old container
	oldPath := sourceVol.LUKSPath + ".old"

	fmt.Fprintln(cmd.OutOrStdout(), "Migration plan:")
	fmt.Fprintf(cmd.OutOrStdout(), "  Source:    %s (%s)\n", sourceVol.LUKSPath, formatSize(currentSize))
	fmt.Fprintf(cmd.OutOrStdout(), "  New:       %s (%s)\n", newPath, formatSize(newSize))
	fmt.Fprintf(cmd.OutOrStdout(), "  Backup:    %s\n", oldPath)
	fmt.Fprintln(cmd.OutOrStdout())

	// Read passphrases
	oldPassphrase, newPassphrase, err := readMigratePassphrases(cmd.OutOrStdout())
	if err != nil {
		return err
	}

	// Rename current container to .old
	fmt.Fprintln(cmd.OutOrStdout(), "Renaming current container to backup...")
	if err := os.Rename(sourceVol.LUKSPath, oldPath); err != nil {
		return &MigrateError{Operation: "rename", Err: fmt.Errorf("%w: %v", ErrMigrateRenameFailed, err)}
	}

	// Create old volume reference for unlocking
	oldVol := luks.NewVolumeWithPaths(oldPath, sourceVol.MountPoint+".old-migrate")
	oldVol.MapperName = "xkey_old"

	// Create new volume
	newVol := luks.NewVolumeWithPaths(newPath, sourceVol.MountPoint)

	fmt.Fprintf(cmd.OutOrStdout(), "Creating new container (%s)...\n", formatSize(newSize))
	if err := newVol.Create(newSize, string(newPassphrase)); err != nil {
		// Restore old container on failure
		restoreErr := os.Rename(oldPath, sourceVol.LUKSPath)
		if restoreErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not restore original container: %v\n", restoreErr)
		}
		return &MigrateError{Operation: "create", Err: fmt.Errorf("%w: %v", ErrMigrateCreateFailed, err)}
	}

	// Unlock both containers
	fmt.Fprintln(cmd.OutOrStdout(), "Unlocking containers for data transfer...")

	// Create temp mount points
	oldMount, err := os.MkdirTemp("", "xkey-migrate-old-")
	if err != nil {
		restoreErr := os.Rename(oldPath, sourceVol.LUKSPath)
		if restoreErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not restore original container: %v\n", restoreErr)
		}
		return &MigrateError{Operation: "create_temp_mount", Err: fmt.Errorf("failed to create temp mount: %w", err)}
	}
	defer os.RemoveAll(oldMount)

	newMount, err := os.MkdirTemp("", "xkey-migrate-new-")
	if err != nil {
		restoreErr := os.Rename(oldPath, sourceVol.LUKSPath)
		if restoreErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not restore original container: %v\n", restoreErr)
		}
		return &MigrateError{Operation: "create_temp_mount", Err: fmt.Errorf("failed to create temp mount: %w", err)}
	}
	defer os.RemoveAll(newMount)

	// Update mount points
	oldVol.MountPoint = oldMount
	newVol.MountPoint = newMount

	// Unlock old container
	if err := oldVol.Unlock(string(oldPassphrase)); err != nil {
		restoreErr := os.Rename(oldPath, sourceVol.LUKSPath)
		if restoreErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not restore original container: %v\n", restoreErr)
		}
		return &MigrateError{Operation: "unlock_old", Err: fmt.Errorf("%w: %v", ErrMigrateSourceLocked, err)}
	}

	// Unlock new container
	if err := newVol.Unlock(string(newPassphrase)); err != nil {
		lockErr := oldVol.Lock()
		if lockErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not lock old container: %v\n", lockErr)
		}
		restoreErr := os.Rename(oldPath, sourceVol.LUKSPath)
		if restoreErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not restore original container: %v\n", restoreErr)
		}
		return &MigrateError{Operation: "unlock_new", Err: fmt.Errorf("failed to unlock new container: %w", err)}
	}

	// Copy data
	fmt.Fprintln(cmd.OutOrStdout(), "Copying data to new container...")
	if err := newVol.CopyDataToVolume(oldMount); err != nil {
		lockErr := oldVol.Lock()
		if lockErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not lock old container: %v\n", lockErr)
		}
		lockErr = newVol.Lock()
		if lockErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not lock new container: %v\n", lockErr)
		}
		removeErr := os.Remove(newPath)
		if removeErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not remove new container: %v\n", removeErr)
		}
		restoreErr := os.Rename(oldPath, sourceVol.LUKSPath)
		if restoreErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not restore original container: %v\n", restoreErr)
		}
		return &MigrateError{Operation: "copy_data", Err: fmt.Errorf("%w: %v", ErrMigrateDataCopyFailed, err)}
	}

	// Lock both containers
	fmt.Fprintln(cmd.OutOrStdout(), "Locking containers...")
	lockErr := oldVol.Lock()
	if lockErr != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not lock old container: %v\n", lockErr)
	}
	lockErr = newVol.Lock()
	if lockErr != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not lock new container: %v\n", lockErr)
	}

	// Handle old container based on flags
	if !migrateKeepOld {
		if migrateWipe {
			// Securely wipe the old container using go-luks2
			patternDesc := getWipePatternDescription(wipeStdValue)
			fmt.Fprintf(cmd.OutOrStdout(), "Securely wiping old container (%s: %s)...\n", migrateWipeStandard, patternDesc)
			if err := wipeContainerWithStandard(oldPath, wipeStdValue); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Warning: secure wipe failed: %v\n", err)
				fmt.Fprintln(cmd.OutOrStdout(), "Falling back to simple removal...")
			}
			// Remove the container file after wiping
			if err := os.Remove(oldPath); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not remove old container: %v\n", err)
			}
		} else {
			// Simple removal
			fmt.Fprintln(cmd.OutOrStdout(), "Removing old container...")
			if err := os.Remove(oldPath); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not remove old container: %v\n", err)
			}
		}
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Migration complete!")
	fmt.Fprintf(cmd.OutOrStdout(), "  New container: %s (%s)\n", newPath, formatSize(newSize))
	if migrateKeepOld {
		fmt.Fprintf(cmd.OutOrStdout(), "  Old container: %s (kept as backup)\n", oldPath)
	} else if migrateWipe {
		fmt.Fprintf(cmd.OutOrStdout(), "  Old container: securely wiped (%s) and removed\n", migrateWipeStandard)
	}
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Use 'xkey luks2 unseal' to unlock the new container.")

	return nil
}

// readMigratePassphrases reads old and new passphrases from terminal or stdin.
func readMigratePassphrases(out io.Writer) (string, string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return readMigratePassphrasesFromTerminal(out)
	}
	return readMigratePassphrasesFromStdin()
}

// readMigratePassphrasesFromTerminal reads passphrases securely from terminal.
func readMigratePassphrasesFromTerminal(out io.Writer) (string, string, error) {
	// Read passphrase for old container
	fmt.Fprint(out, "Enter passphrase for current container: ")
	oldPassphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", "", &MigrateError{Operation: "read_passphrase", Err: fmt.Errorf("%w: %v", ErrMigratePassphraseRead, err)}
	}

	// Read passphrase for new container
	fmt.Fprint(out, "Enter passphrase for new container (or press Enter to use same): ")
	newPassphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", "", &MigrateError{Operation: "read_passphrase", Err: fmt.Errorf("%w: %v", ErrMigratePassphraseRead, err)}
	}

	if len(newPassphrase) == 0 {
		newPassphrase = oldPassphrase
	} else {
		// Confirm new passphrase
		fmt.Fprint(out, "Confirm new passphrase: ")
		confirmPassphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(out)
		if err != nil {
			return "", "", &MigrateError{Operation: "read_passphrase", Err: fmt.Errorf("%w: %v", ErrMigratePassphraseRead, err)}
		}
		if string(newPassphrase) != string(confirmPassphrase) {
			return "", "", luks.ErrPassphraseMismatch
		}
	}

	return string(oldPassphrase), string(newPassphrase), nil
}

// readMigratePassphrasesFromStdin reads passphrases from piped stdin.
func readMigratePassphrasesFromStdin() (string, string, error) {
	reader := bufio.NewReader(os.Stdin)

	// Read old passphrase
	oldPassphrase, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", &MigrateError{Operation: "read_passphrase", Err: err}
	}
	oldPassphrase = strings.TrimSuffix(oldPassphrase, "\n")

	// For piped input, use same passphrase for new container
	return oldPassphrase, oldPassphrase, nil
}

// getFileSize returns the size of a file in bytes.
func getFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// formatSize formats bytes as human-readable size.
func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1fG", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1fM", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1fK", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}

// MigrateError represents a migration operation error.
type MigrateError struct {
	Operation string
	Err       error
}

// Error returns the error message.
func (e *MigrateError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("migrate: %s: %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("migrate: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *MigrateError) Unwrap() error {
	return e.Err
}
