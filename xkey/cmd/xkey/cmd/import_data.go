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

// ImportData command errors.
var (
	ErrImportDataNoSource = &ImportDataError{Operation: "validate", Message: "source directory does not exist or is empty"}
	ErrImportDataNoVolume = &ImportDataError{Operation: "validate", Message: "LUKS volume does not exist"}
)

var (
	importDataPath       string // LUKS file path
	importDataSource     string // Source directory to import from
	importDataMountPoint string // Final mount point for --unseal
	importDataCleanup    bool   // Remove source data after successful import
	importDataBackup     bool   // Create backup of source before cleanup
	importDataUnseal     bool   // Unlock volume at mount point after import
)

var importDataCmd = &cobra.Command{
	Use:   "import-data",
	Short: "Import data into a LUKS volume",
	Long: `Import existing data into an already-created LUKS2 encrypted volume.

This command safely copies data from a source directory into the LUKS
volume using a temporary mount point, so it works even while the
application is actively using the source directory.

The LUKS volume is temporarily unlocked, data is copied, and then
the volume is locked again.

Use --cleanup to remove the original plaintext data after a successful
import. Use --backup with --cleanup to create a backup of the original
data before removal.

Use --unseal with --mount-point to unlock the volume at its final
location after import and cleanup. This ensures the cleanup and mount
happen atomically in a single elevated command.

Requires root privileges for LUKS operations.

Example:
  sudo xkey luks2 import-data --source ~/.xkey --path ~/.xkey.luks --cleanup
  sudo xkey luks2 import-data --source ~/.xkey --path ~/.xkey.luks --cleanup --backup
  sudo xkey luks2 import-data --source ~/.xkey --path ~/.xkey.luks --cleanup --unseal --mount-point ~/.xkey`,
	RunE: runImportData,
}

func init() {
	importDataCmd.Flags().StringVar(&importDataPath, "path", "", "LUKS file path (default: ~/.xkey.luks)")
	importDataCmd.Flags().StringVar(&importDataSource, "source", "", "Source directory to import from (default: ~/.xkey)")
	importDataCmd.Flags().StringVar(&importDataMountPoint, "mount-point", "", "Final mount point for --unseal (default: ~/.xkey)")
	importDataCmd.Flags().BoolVar(&importDataCleanup, "cleanup", false, "Remove original data after successful import")
	importDataCmd.Flags().BoolVar(&importDataBackup, "backup", false, "Create backup before cleanup (use with --cleanup)")
	importDataCmd.Flags().BoolVar(&importDataUnseal, "unseal", false, "Unlock volume at mount point after import")

	luks2Cmd.AddCommand(importDataCmd)
}

func runImportData(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return luks.ErrPermissionDenied
	}

	// Resolve LUKS path, source directory, and mount point from xhome
	// or legacy defaults.
	var defaultLUKS, defaultMount string
	if h := GetHome(); h != nil {
		defaultLUKS = h.LUKSPath()
		defaultMount = h.MountPoint()
	} else {
		var pathErr error
		defaultLUKS, pathErr = luks.GetDefaultLUKSPath()
		if pathErr != nil {
			return pathErr
		}
		defaultMount, pathErr = luks.GetDefaultDataDir()
		if pathErr != nil {
			return pathErr
		}
	}

	luksPath := importDataPath
	if luksPath == "" {
		luksPath = defaultLUKS
	} else {
		luksPath = luks.ExpandPath(luksPath)
	}

	sourceDir := importDataSource
	if sourceDir == "" {
		sourceDir = defaultMount
	} else {
		sourceDir = luks.ExpandPath(sourceDir)
	}

	mountPoint := importDataMountPoint
	if mountPoint == "" {
		mountPoint = defaultMount
	} else {
		mountPoint = luks.ExpandPath(mountPoint)
	}

	// Validate source directory
	if !hasExistingData(sourceDir) {
		return ErrImportDataNoSource
	}

	// Validate LUKS volume exists
	vol := luks.NewVolumeWithPaths(luksPath, "")
	if !vol.Exists() {
		return ErrImportDataNoVolume
	}

	// Read passphrase
	passphrase, err := readImportPassphrase(cmd.OutOrStdout())
	if err != nil {
		return err
	}

	// Create a temporary mount point so we don't conflict with the
	// source directory (which may be the same as the default mount point).
	tmpMount, err := os.MkdirTemp("", "xkey-import-")
	if err != nil {
		return &ImportDataError{Operation: "create_temp_mount", Err: err}
	}
	defer os.RemoveAll(tmpMount)

	// Unlock the volume at the temp mount point
	vol.MountPoint = tmpMount
	fmt.Fprintf(cmd.OutOrStdout(), "Unlocking volume at temporary mount point...\n")
	if err := vol.Unlock(passphrase); err != nil {
		return &ImportDataError{Operation: "unlock", Err: err}
	}

	// Copy data from source to the mounted volume
	fmt.Fprintf(cmd.OutOrStdout(), "Importing data from %s...\n", sourceDir)
	if err := vol.CopyDataToVolume(sourceDir); err != nil {
		lockErr := vol.Lock()
		if lockErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not lock volume: %v\n", lockErr)
		}
		return &ImportDataError{Operation: "copy_data", Err: err}
	}

	// Lock the temporary mount
	fmt.Fprintln(cmd.OutOrStdout(), "Locking volume...")
	if err := vol.Lock(); err != nil {
		return &ImportDataError{Operation: "lock", Err: err}
	}

	// Clean up original plaintext data if requested. This must happen
	// BEFORE the final unlock to prevent the running app from recreating
	// data in the brief window between cleanup and mount.
	if importDataCleanup {
		if err := cleanupSourceDir(cmd.OutOrStdout(), sourceDir, importDataBackup); err != nil {
			return err
		}
	}

	// Optionally unlock at the final mount point so the volume is
	// immediately usable. Doing this in the same elevated command as
	// cleanup ensures no window exists for the app to recreate data.
	if importDataUnseal {
		fmt.Fprintf(cmd.OutOrStdout(), "Unlocking volume at %s...\n", mountPoint)
		finalVol := luks.NewVolumeWithPaths(luksPath, mountPoint)
		if err := finalVol.Unlock(passphrase); err != nil {
			return &ImportDataError{Operation: "final_unlock", Err: err}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "\nData imported and volume unlocked at %s\n", mountPoint)
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "\nData imported successfully!")
		fmt.Fprintln(cmd.OutOrStdout(), "Restart xKey to use the encrypted volume.")
	}

	return nil
}

// cleanupSourceDir removes plaintext data from the source directory after
// a successful import. If backup is true, the source is first renamed to
// <source>-backup. The source directory is then recreated empty so the
// LUKS volume can be mounted to it.
func cleanupSourceDir(out io.Writer, sourceDir string, backup bool) error {
	if backup {
		backupDir := sourceDir + "-backup"
		fmt.Fprintf(out, "Creating backup at %s...\n", backupDir)
		// Remove any stale backup from a previous migration.
		if _, err := os.Stat(backupDir); err == nil {
			if err := os.RemoveAll(backupDir); err != nil {
				return &ImportDataError{Operation: "remove_old_backup", Err: err}
			}
		}
		if err := os.Rename(sourceDir, backupDir); err != nil {
			return &ImportDataError{Operation: "backup_source", Err: err}
		}
	} else {
		fmt.Fprintf(out, "Removing original plaintext data from %s...\n", sourceDir)
		if err := os.RemoveAll(sourceDir); err != nil {
			return &ImportDataError{Operation: "cleanup_source", Err: err}
		}
	}

	// Recreate the empty source directory so the LUKS volume can mount to it.
	if err := os.MkdirAll(sourceDir, 0700); err != nil {
		return &ImportDataError{Operation: "recreate_source", Err: err}
	}

	// Chown the recreated directory to the calling user when running via sudo/pkexec.
	luks.ChownToCallingUser(sourceDir)

	return nil
}

// readImportPassphrase reads a passphrase from terminal or piped stdin.
func readImportPassphrase(out io.Writer) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(out, "Enter passphrase for LUKS volume: ")
		passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(out)
		if err != nil {
			return "", &ImportDataError{Operation: "read_passphrase", Err: err}
		}
		return string(passphrase), nil
	}

	reader := bufio.NewReader(os.Stdin)
	passphrase, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", &ImportDataError{Operation: "read_passphrase", Err: err}
	}
	return strings.TrimSuffix(passphrase, "\n"), nil
}

// ImportDataError represents an import-data operation error.
type ImportDataError struct {
	Operation string
	Message   string
	Err       error
}

// Error returns the error message.
func (e *ImportDataError) Error() string {
	if e.Err != nil {
		if e.Message != "" {
			return fmt.Sprintf("import-data: %s: %s: %v", e.Operation, e.Message, e.Err)
		}
		return fmt.Sprintf("import-data: %s: %v", e.Operation, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("import-data: %s: %s", e.Operation, e.Message)
	}
	return fmt.Sprintf("import-data: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *ImportDataError) Unwrap() error {
	return e.Err
}
