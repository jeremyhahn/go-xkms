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
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
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
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Creating encrypted volume at %s...\n", vol.LUKSPath)
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
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Unlocking volume...")
		if err := vol.Unlock(passphrase); err != nil {
			return &SealError{Operation: "unseal_after_create", Err: err}
		}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nEncrypted storage created successfully!\n")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  LUKS file: %s\n", vol.LUKSPath)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Mount point: %s\n", vol.MountPoint)
	if sealUnseal {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nVolume is unlocked and mounted.")
	} else {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nUse 'xkey luks2 unseal' to unlock the encrypted storage.")
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
		h, err := xhome.Resolve()
		if err != nil {
			return nil, err
		}
		luksPath = h.LUKSPath()
		mountPoint = h.MountPoint()
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
	_, _ = fmt.Fprint(out, "Enter passphrase for encrypted storage: ")
	passphrase1, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(out)
	if err != nil {
		return "", &SealError{Operation: "read_passphrase", Err: err}
	}

	_, _ = fmt.Fprint(out, "Confirm passphrase: ")
	passphrase2, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(out)
	if err != nil {
		return "", &SealError{Operation: "read_passphrase", Err: err}
	}

	if !bytes.Equal(passphrase1, passphrase2) {
		return "", luks.ErrPassphraseMismatch
	}

	return string(passphrase1), nil
}

// readPassphraseFromStdin reads passphrase from piped stdin (for automation).
func readPassphraseFromStdin(out io.Writer) (string, error) {
	reader := bufio.NewReader(os.Stdin)

	passphrase1, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", &SealError{Operation: "read_passphrase", Err: err}
	}
	passphrase1 = strings.TrimSuffix(passphrase1, "\n")

	passphrase2, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
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

// migrateVolume is the subset of *luks.Volume behavior migrateExistingData
// needs to stage, unlock, copy into and lock the encrypted volume. The
// interface exists so tests can fault-inject unlock, copy and lock
// failures without a real LUKS container or loop device.
type migrateVolume interface {
	GetMountPoint() string
	Unlock(passphrase string) error
	Lock() error
	CopyDataToVolume(sourceDir string) error
}

// Compile-time check that *luks.Volume satisfies migrateVolume.
var _ migrateVolume = (*luks.Volume)(nil)

// migrateExistingData migrates data from the existing plaintext directory
// into the encrypted volume.
//
// dataDir and the volume's mount point are the same path: unlocking mounts
// the (empty) encrypted filesystem over dataDir, which hides the plaintext
// files underneath without touching them, and locking (unmounting) reveals
// them again untouched. That property is what makes the ordering below
// safe: the source is staged, copied into the unlocked volume, verified,
// and only deleted after the volume holding the verified copy has been
// locked. If any step fails, the staging copy is left on disk and its path
// is reported, and the plaintext source is never touched, so no copy of
// the data is ever lost.
func migrateExistingData(out io.Writer, vol migrateVolume, passphrase string) error {
	_, _ = fmt.Fprintln(out, "Migrating existing data to encrypted volume...")
	dataDir := vol.GetMountPoint()

	// Stage the existing data before touching the volume or the source.
	tmpDir, err := os.MkdirTemp("", "xkey-migrate-")
	if err != nil {
		return &SealError{Operation: "create_temp", Err: err}
	}
	if err := copyDirContents(dataDir, tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return &SealError{Operation: "copy_to_temp", Err: err}
	}

	// From here on, every failure preserves tmpDir: it may be the only
	// intact copy of the source data until the source is removed below.
	failMigration := func(op string, cause error) error {
		_, _ = fmt.Fprintf(out, "Migration failed: staged copy preserved at %s\n", tmpDir)
		return &SealError{Operation: op, Err: cause}
	}

	// Unlock the volume. This mounts the encrypted filesystem over
	// dataDir; the plaintext files already there are hidden, not deleted.
	if err := vol.Unlock(passphrase); err != nil {
		return failMigration("unlock_for_migration", err)
	}

	// Copy the staged data into the now-mounted volume.
	if err := vol.CopyDataToVolume(tmpDir); err != nil {
		if lockErr := vol.Lock(); lockErr != nil {
			_, _ = fmt.Fprintf(out, "Warning: could not lock volume: %v\n", lockErr)
		}
		return failMigration("migrate_data", err)
	}

	// Verify the copy landed intact before doing anything irreversible.
	if err := verifyDirCopy(tmpDir, dataDir); err != nil {
		if lockErr := vol.Lock(); lockErr != nil {
			_, _ = fmt.Fprintf(out, "Warning: could not lock volume: %v\n", lockErr)
		}
		return failMigration("verify_migration", err)
	}

	// Lock the volume. This unmounts it, which uncovers the original
	// plaintext directory again, untouched since Unlock.
	if err := vol.Lock(); err != nil {
		return failMigration("lock_after_migration", err)
	}

	// Only now, with a verified copy safely sealed inside the locked
	// volume, remove the plaintext source.
	if err := os.RemoveAll(dataDir); err != nil {
		return failMigration("remove_original", err)
	}

	// Migration is complete and verified; the staging copy is no longer
	// needed.
	if err := os.RemoveAll(tmpDir); err != nil {
		_, _ = fmt.Fprintf(out, "Warning: failed to remove staging copy at %s: %v\n", tmpDir, err)
	}

	_, _ = fmt.Fprintln(out, "Data migration complete.")
	return nil
}

// verifyDirCopy confirms that every entry present in src also exists in
// dst: directories exist as directories, and files exist with matching
// size. It is a shallow integrity check run after copying data into the
// encrypted volume and before the plaintext source is deleted.
func verifyDirCopy(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return &DataVerificationError{Path: path, Message: "failed to walk source", Err: walkErr}
		}
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return &DataVerificationError{Path: path, Message: "failed to resolve relative path", Err: relErr}
		}
		if rel == "." {
			return nil
		}
		dstPath := filepath.Join(dst, rel)

		if d.IsDir() {
			info, statErr := os.Stat(dstPath)
			if statErr != nil {
				return &DataVerificationError{Path: rel, Message: "missing directory in destination", Err: statErr}
			}
			if !info.IsDir() {
				return &DataVerificationError{Path: rel, Message: "expected a directory in destination"}
			}
			return nil
		}

		srcInfo, infoErr := d.Info()
		if infoErr != nil {
			return &DataVerificationError{Path: rel, Message: "failed to stat source entry", Err: infoErr}
		}
		dstInfo, statErr := os.Stat(dstPath)
		if statErr != nil {
			return &DataVerificationError{Path: rel, Message: "missing file in destination", Err: statErr}
		}
		if dstInfo.Size() != srcInfo.Size() {
			return &DataVerificationError{
				Path: rel,
				Message: fmt.Sprintf("size mismatch: source %d bytes, destination %d bytes",
					srcInfo.Size(), dstInfo.Size()),
			}
		}
		return nil
	})
}

// DataVerificationError indicates that the post-copy integrity check in
// verifyDirCopy found a mismatch between the staged source and its copy
// inside the encrypted volume.
type DataVerificationError struct {
	Path    string
	Message string
	Err     error
}

// Error returns the error message.
func (e *DataVerificationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("verify: %s: %s: %v", e.Path, e.Message, e.Err)
	}
	return fmt.Sprintf("verify: %s: %s", e.Path, e.Message)
}

// Unwrap returns the underlying error.
func (e *DataVerificationError) Unwrap() error {
	return e.Err
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
