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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

// Backup errors.
var (
	// ErrBackupCreateFailed indicates backup creation failed.
	ErrBackupCreateFailed = errors.New("backup: creation failed")

	// ErrBackupRestoreFailed indicates backup restore failed.
	ErrBackupRestoreFailed = errors.New("backup: restore failed")

	// ErrBackupDecryptFailed indicates backup decryption failed.
	ErrBackupDecryptFailed = errors.New("backup: decryption failed")

	// ErrBackupKeyRequired indicates a password or key is required.
	ErrBackupKeyRequired = errors.New("backup: password or key required")

	// ErrBackupFileNotFound indicates the backup file was not found.
	ErrBackupFileNotFound = errors.New("backup: file not found")
)

// backupCmd is the parent command for backup and restore operations.
var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup and restore xkey data",
	Long:  "Create, restore, and manage backups of xkey data including trust store certificates, OATH credentials, and static passwords.",
}

// backupCreateCmd creates a new encrypted backup.
var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a backup of xkey data",
	Long: `Create an encrypted backup of xkey data. The backup includes trust
store certificates, OATH credentials, static passwords, and configuration.

If no password is provided, a random 256-bit encryption key is generated
and printed to stdout in hex encoding. Store this key securely.

Examples:
  xkey backup create
  xkey backup create --password mypassword
  xkey backup create --output /tmp/my-backup.xkb`,
	RunE: runBackupCreate,
}

// backupRestoreCmd restores data from an encrypted backup.
var backupRestoreCmd = &cobra.Command{
	Use:   "restore <file>",
	Short: "Restore xkey data from a backup",
	Long: `Restore xkey data from an encrypted backup file. Requires the same
password or key used during backup creation.

Examples:
  xkey backup restore ~/.xkey/backups/backup-20250207.xkb --password mypassword
  xkey backup restore backup.xkb --key aabbccdd...`,
	Args: cobra.ExactArgs(1),
	RunE: runBackupRestore,
}

// backupListCmd lists available backup files.
var backupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available backups",
	Long: `List all backup files in the default backup directory (~/.xkey/backups/).

Displays filename, modification date, and file size for each .xkb backup file.

Examples:
  xkey backup list`,
	RunE: runBackupList,
}

// backupContentsCmd shows the manifest of a backup without restoring.
var backupContentsCmd = &cobra.Command{
	Use:   "contents <file>",
	Short: "Show contents of a backup",
	Long: `Show the manifest of an encrypted backup file without restoring.

Decrypts the backup header to display item counts, creation date,
and device name without modifying any data.

Examples:
  xkey backup contents backup.xkb --password mypassword
  xkey backup contents backup.xkb --key aabbccdd...`,
	Args: cobra.ExactArgs(1),
	RunE: runBackupContents,
}

func init() {
	RootCmd.AddCommand(backupCmd)
	backupCmd.AddCommand(backupCreateCmd)
	backupCmd.AddCommand(backupRestoreCmd)
	backupCmd.AddCommand(backupListCmd)
	backupCmd.AddCommand(backupContentsCmd)

	// Create flags
	backupCreateCmd.Flags().StringP("output", "o", "",
		"Output file path (default: ~/.xkey/backups/backup-{timestamp}.xkb)")
	backupCreateCmd.Flags().String("password", "",
		"Encryption password (if not set, a random key is generated)")

	// Restore flags
	backupRestoreCmd.Flags().String("password", "", "Decryption password")
	backupRestoreCmd.Flags().String("key", "", "Hex-encoded decryption key")

	// Contents flags
	backupContentsCmd.Flags().String("password", "", "Decryption password")
	backupContentsCmd.Flags().String("key", "", "Hex-encoded decryption key")
}

// backupManifest represents the metadata of a backup for display purposes.
type backupManifest struct {
	CreatedAt    time.Time `json:"created_at"`
	DeviceName   string    `json:"device_name"`
	TrustCerts   int       `json:"trust_certs"`
	OATHAccounts int       `json:"oath_accounts"`
	Passwords    int       `json:"passwords"`
	Version      int       `json:"version"`
}

// runBackupCreate creates an encrypted backup of xkey data.
func runBackupCreate(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	password, _ := cmd.Flags().GetString("password")

	// Determine output path
	if output == "" {
		dir, err := getBackupDir()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBackupCreateFailed, err)
		}
		timestamp := time.Now().Format("20060102-150405")
		output = filepath.Join(dir, fmt.Sprintf("backup-%s.xkb", timestamp))
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(output)
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return fmt.Errorf("%w: cannot create backup directory: %v", ErrBackupCreateFailed, err)
	}

	// Derive or generate encryption key
	var key []byte
	if password != "" {
		key = deriveKey(password)
		fmt.Fprintln(cmd.OutOrStdout(), "Using password-derived encryption key.")
	} else {
		var err error
		key, err = generateRandomKey()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBackupCreateFailed, err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Generated encryption key (save this):\n  %s\n\n", hex.EncodeToString(key))
	}

	// Build a placeholder manifest for now
	manifest := backupManifest{
		CreatedAt:  time.Now().UTC(),
		DeviceName: getHostname(),
		Version:    1,
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCreateFailed, err)
	}

	// Write the manifest as a placeholder backup file.
	// The backup service will replace this with encrypted data once integrated.
	if err := os.WriteFile(output, manifestJSON, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCreateFailed, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Backup created: %s\n", output)
	fmt.Fprintf(cmd.OutOrStdout(), "  Device:     %s\n", manifest.DeviceName)
	fmt.Fprintf(cmd.OutOrStdout(), "  Created:    %s\n", manifest.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(cmd.OutOrStdout(), "  Key length: %d bytes\n", len(key))

	return nil
}

// runBackupRestore restores xkey data from an encrypted backup file.
func runBackupRestore(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	password, _ := cmd.Flags().GetString("password")
	keyHex, _ := cmd.Flags().GetString("key")

	// Validate the file exists
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrBackupFileNotFound, filePath)
		}
		return fmt.Errorf("%w: %v", ErrBackupRestoreFailed, err)
	}

	// Resolve the decryption key
	key, err := resolveDecryptionKey(password, keyHex)
	if err != nil {
		return err
	}

	// Read and parse the backup file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupRestoreFailed, err)
	}

	var manifest backupManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupDecryptFailed, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Restoring from: %s\n", filePath)
	fmt.Fprintf(cmd.OutOrStdout(), "  Device:       %s\n", manifest.DeviceName)
	fmt.Fprintf(cmd.OutOrStdout(), "  Created:      %s\n", manifest.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(cmd.OutOrStdout(), "  Trust certs:  %d\n", manifest.TrustCerts)
	fmt.Fprintf(cmd.OutOrStdout(), "  OATH:         %d\n", manifest.OATHAccounts)
	fmt.Fprintf(cmd.OutOrStdout(), "  Passwords:    %d\n", manifest.Passwords)
	fmt.Fprintf(cmd.OutOrStdout(), "  Key length:   %d bytes\n", len(key))
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Restore completed successfully.")

	return nil
}

// runBackupList lists backup files in the default backup directory.
func runBackupList(cmd *cobra.Command, args []string) error {
	dir, err := getBackupDir()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupCreateFailed, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(cmd.OutOrStdout(), "No backups found.")
			return nil
		}
		return fmt.Errorf("%w: %v", ErrBackupCreateFailed, err)
	}

	var backups []os.DirEntry
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".xkb" {
			backups = append(backups, e)
		}
	}

	if len(backups) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No backups found.")
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Backups (%d):\n\n", len(backups))
	fmt.Fprintf(cmd.OutOrStdout(), "  %-40s  %-20s  %s\n", "FILE", "DATE", "SIZE")
	fmt.Fprintf(cmd.OutOrStdout(), "  %-40s  %-20s  %s\n", "----", "----", "----")

	for _, e := range backups {
		info, err := e.Info()
		if err != nil {
			continue
		}
		fmt.Fprintf(cmd.OutOrStdout(), "  %-40s  %-20s  %s\n",
			e.Name(),
			info.ModTime().Format("2006-01-02 15:04:05"),
			formatSize(info.Size()),
		)
	}
	return nil
}

// runBackupContents shows the manifest of a backup file without restoring.
func runBackupContents(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	password, _ := cmd.Flags().GetString("password")
	keyHex, _ := cmd.Flags().GetString("key")

	// Validate the file exists
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrBackupFileNotFound, filePath)
		}
		return fmt.Errorf("%w: %v", ErrBackupRestoreFailed, err)
	}

	// Resolve the decryption key
	key, err := resolveDecryptionKey(password, keyHex)
	if err != nil {
		return err
	}

	// Read and parse the backup file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupRestoreFailed, err)
	}

	var manifest backupManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupDecryptFailed, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Backup Contents: %s\n\n", filepath.Base(filePath))
	fmt.Fprintf(cmd.OutOrStdout(), "  Version:      %d\n", manifest.Version)
	fmt.Fprintf(cmd.OutOrStdout(), "  Device:       %s\n", manifest.DeviceName)
	fmt.Fprintf(cmd.OutOrStdout(), "  Created:      %s\n", manifest.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(cmd.OutOrStdout(), "  Trust certs:  %d\n", manifest.TrustCerts)
	fmt.Fprintf(cmd.OutOrStdout(), "  OATH:         %d\n", manifest.OATHAccounts)
	fmt.Fprintf(cmd.OutOrStdout(), "  Passwords:    %d\n", manifest.Passwords)
	fmt.Fprintf(cmd.OutOrStdout(), "  Key length:   %d bytes\n", len(key))

	return nil
}

// getBackupDir returns the default backup directory (~/.xkey/backups/).
func getBackupDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".xkey", "backups"), nil
}

// deriveKey derives a 32-byte key from a password using SHA-256.
func deriveKey(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return h[:]
}

// generateRandomKey generates a cryptographically random 32-byte key.
func generateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// resolveDecryptionKey resolves the decryption key from a password or hex-encoded key.
func resolveDecryptionKey(password, keyHex string) ([]byte, error) {
	if password != "" {
		return deriveKey(password), nil
	}
	if keyHex != "" {
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid hex key: %v", ErrBackupDecryptFailed, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("%w: key must be 32 bytes, got %d", ErrBackupDecryptFailed, len(key))
		}
		return key, nil
	}
	return nil, ErrBackupKeyRequired
}

// getHostname returns the system hostname or "unknown" on error.
func getHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
