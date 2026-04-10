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
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
)

// Seal command errors.
var (
	ErrSealPassphraseRead = &SealError{Operation: "read_passphrase", Message: "failed to read passphrase"}
	ErrSealVolumeCreate   = &SealError{Operation: "create_volume", Message: "failed to create LUKS volume"}
	ErrSealDataMigration  = &SealError{Operation: "migrate_data", Message: "failed to migrate data"}
)

var (
	sealSize        string // Size flag (e.g., "100M", "1G")
	sealPath        string // Custom LUKS file path
	sealMountPoint  string // Custom mount point
	sealUnseal      bool   // Keep volume unlocked after creation
	sealSkipMigrate bool   // Skip automatic data migration
)

var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Create encrypted LUKS storage",
	Long: `Create an encrypted LUKS2 volume for xKey data storage.

This command:
1. Creates a new LUKS2 encrypted container
2. If existing data exists in ~/.xkey, migrates it to the encrypted volume
3. Removes the unencrypted data directory
4. Future xkey commands will auto-detect and prompt for passphrase

Requires root privileges for LUKS operations.

Example:
  sudo xkey luks2 seal                    # Create with default 100MB size
  sudo xkey luks2 seal --size 500M        # Create with 500MB size
  sudo xkey luks2 seal --path /secure/xkey.luks  # Custom location
  sudo xkey luks2 seal --unseal             # Create and unlock immediately`,
	RunE: runSeal,
}

func init() {
	sealCmd.Flags().StringVar(&sealSize, "size", "100M", "Volume size (e.g., 100M, 1G)")
	sealCmd.Flags().StringVar(&sealPath, "path", "", "Custom LUKS file path (default: ~/.xkey.luks)")
	sealCmd.Flags().StringVar(&sealMountPoint, "mount-point", "", "Custom mount point (default: ~/.xkey)")
	sealCmd.Flags().BoolVar(&sealUnseal, "unseal", false, "Keep volume unlocked and mounted after creation")
	sealCmd.Flags().BoolVar(&sealSkipMigrate, "skip-migrate", false, "Create volume without migrating existing data")

	luks2Cmd.AddCommand(sealCmd)
}

func runSeal(cmd *cobra.Command, args []string) error {
	// Check for root privileges
	if os.Geteuid() != 0 {
		return luks.ErrPermissionDenied
	}

	// Determine paths and create volume instance
	vol, err := createSealVolume()
	if err != nil {
		return err
	}

	// Check if LUKS file already exists
	if vol.Exists() {
		return luks.ErrVolumeAlreadyExists
	}

	// Check for existing data to migrate
	existingData := hasExistingData(vol.MountPoint)

	// Parse size
	sizeBytes, err := parseSize(sealSize)
	if err != nil {
		return &SealError{Operation: "parse_size", Message: "invalid size", Err: err}
	}

	// Read and confirm passphrase
	passphrase, err := readAndConfirmPassphrase(cmd.OutOrStdout())
	if err != nil {
		return err
	}

	// Create the volume
	fmt.Fprintf(cmd.OutOrStdout(), "Creating encrypted volume at %s...\n", vol.LUKSPath)
	if err := vol.Create(sizeBytes, passphrase); err != nil {
		return &SealError{Operation: "create_volume", Err: err}
	}

	// If there's existing data, migrate it (unless --skip-migrate is set)
	if existingData && !sealSkipMigrate {
		if err := migrateExistingData(cmd.OutOrStdout(), vol, passphrase); err != nil {
			return err
		}
	}

	// If --unseal is set, unlock and mount the volume so it's ready for use.
	if sealUnseal && !vol.IsMounted() {
		fmt.Fprintln(cmd.OutOrStdout(), "Unlocking volume...")
		if err := vol.Unlock(passphrase); err != nil {
			return &SealError{Operation: "unseal_after_create", Err: err}
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\nEncrypted storage created successfully!\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  LUKS file: %s\n", vol.LUKSPath)
	fmt.Fprintf(cmd.OutOrStdout(), "  Mount point: %s\n", vol.MountPoint)
	if sealUnseal {
		fmt.Fprintln(cmd.OutOrStdout(), "\nVolume is unlocked and mounted.")
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "\nUse 'xkey luks2 unseal' to unlock the encrypted storage.")
	}

	return nil
}

// createSealVolume creates a Volume instance based on command flags.
// When no custom paths are specified, the resolved xhome.Home provides
// the LUKS and mount point paths.
func createSealVolume() (*luks.Volume, error) {
	// Start from resolved home or legacy defaults.
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

	// Custom flags override resolved defaults.
	if sealPath != "" {
		luksPath = luks.ExpandPath(sealPath)
	}
	if sealMountPoint != "" {
		mountPoint = luks.ExpandPath(sealMountPoint)
	}

	return luks.NewVolumeWithPaths(luksPath, mountPoint), nil
}

// hasExistingData checks if the data directory has existing content.
func hasExistingData(dataDir string) bool {
	info, err := os.Stat(dataDir)
	if err != nil || !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return false
	}
	return len(entries) > 0
}

// readAndConfirmPassphrase reads and confirms passphrase from terminal or stdin.
func readAndConfirmPassphrase(out io.Writer) (string, error) {
	// Check if stdin is a terminal
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return readPassphraseFromTerminal(out)
	}
	// Read from piped stdin (for automation/testing)
	return readPassphraseFromStdin(out)
}

// readPassphraseFromTerminal reads passphrase securely from terminal.
func readPassphraseFromTerminal(out io.Writer) (string, error) {
	fmt.Fprint(out, "Enter passphrase for encrypted storage: ")
	passphrase1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", &SealError{Operation: "read_passphrase", Err: err}
	}

	fmt.Fprint(out, "Confirm passphrase: ")
	passphrase2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", &SealError{Operation: "read_passphrase", Err: err}
	}

	if string(passphrase1) != string(passphrase2) {
		return "", luks.ErrPassphraseMismatch
	}

	return string(passphrase1), nil
}

// readPassphraseFromStdin reads passphrase from piped stdin (for automation).
func readPassphraseFromStdin(out io.Writer) (string, error) {
	reader := bufio.NewReader(os.Stdin)

	passphrase1, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", &SealError{Operation: "read_passphrase", Err: err}
	}
	passphrase1 = strings.TrimSuffix(passphrase1, "\n")

	passphrase2, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", &SealError{Operation: "read_passphrase", Err: err}
	}
	passphrase2 = strings.TrimSuffix(passphrase2, "\n")

	if passphrase1 != passphrase2 {
		return "", luks.ErrPassphraseMismatch
	}

	if passphrase1 == "" {
		return "", &SealError{Operation: "read_passphrase", Message: "passphrase cannot be empty"}
	}

	return passphrase1, nil
}

// migrateExistingData migrates data from existing directory to encrypted volume.
func migrateExistingData(out io.Writer, vol *luks.Volume, passphrase string) error {
	fmt.Fprintln(out, "Migrating existing data to encrypted volume...")
	dataDir := vol.MountPoint

	// Create a temp dir to hold data during migration
	tmpDir, err := os.MkdirTemp("", "xkey-migrate-")
	if err != nil {
		return &SealError{Operation: "create_temp", Err: err}
	}
	defer os.RemoveAll(tmpDir)

	// Copy existing data to temp directory
	if err := copyDirContents(dataDir, tmpDir); err != nil {
		return &SealError{Operation: "copy_to_temp", Err: err}
	}

	// Remove original data directory
	if err := os.RemoveAll(dataDir); err != nil {
		return &SealError{Operation: "remove_original", Err: err}
	}

	// Unlock and mount the volume
	if err := vol.Unlock(passphrase); err != nil {
		return &SealError{Operation: "unlock_for_migration", Err: err}
	}

	// Copy from temp to mounted volume
	if err := vol.CopyDataToVolume(tmpDir); err != nil {
		vol.Lock()
		return &SealError{Operation: "migrate_data", Err: err}
	}

	// Lock the volume
	if err := vol.Lock(); err != nil {
		return &SealError{Operation: "lock_after_migration", Err: err}
	}

	fmt.Fprintln(out, "Data migration complete.")
	return nil
}

// parseSize converts size string (e.g., "100M", "1G") to bytes.
func parseSize(size string) (int64, error) {
	if len(size) < 2 {
		return 0, &SealError{Operation: "parse_size", Message: "invalid size format"}
	}

	unit := size[len(size)-1]
	valueStr := size[:len(size)-1]

	var value int64
	if _, err := fmt.Sscanf(valueStr, "%d", &value); err != nil {
		return 0, err
	}

	switch unit {
	case 'K', 'k':
		return value * 1024, nil
	case 'M', 'm':
		return value * 1024 * 1024, nil
	case 'G', 'g':
		return value * 1024 * 1024 * 1024, nil
	default:
		return 0, &SealError{Operation: "parse_size", Message: fmt.Sprintf("unknown size unit: %c", unit)}
	}
}

// copyDirContents copies the contents of a directory to another directory.
func copyDirContents(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := os.MkdirAll(dstPath, 0700); err != nil {
				return err
			}
			if err := copyDirContents(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFileSeal(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// copyFileSeal copies a single file preserving permissions.
func copyFileSeal(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.WriteFile(dst, data, srcInfo.Mode())
}

// SealError represents a seal operation error.
type SealError struct {
	Operation string
	Message   string
	Err       error
}

// Error returns the error message.
func (e *SealError) Error() string {
	if e.Err != nil {
		if e.Message != "" {
			return fmt.Sprintf("seal: %s: %s: %v", e.Operation, e.Message, e.Err)
		}
		return fmt.Sprintf("seal: %s: %v", e.Operation, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("seal: %s: %s", e.Operation, e.Message)
	}
	return fmt.Sprintf("seal: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *SealError) Unwrap() error {
	return e.Err
}
