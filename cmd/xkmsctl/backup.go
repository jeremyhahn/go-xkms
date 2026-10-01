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

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// backupCmd is the top-level command for whole-node backup and restore
// (owner ruling 2026-09-30, go-xkms#728). It captures and restores shard
// snapshots of the embedded go-qrdb node's barrier-encrypted, replicated
// state -- entirely through go-qrdb's own backup client. On a standalone
// (non-raft) node, every verb reports the node's own typed
// unsupported-operation error: shard snapshots require Raft-replicated
// state. For per-key backup, see `xkmsctl key export`/`key import`, which
// wrap individual keys for transport under an operator-supplied key.
var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Manage whole-node backups",
	Long: `Manage whole-node backups of the embedded go-qrdb node's replicated state.

A backup captures a point-in-time shard snapshot that can be listed,
inspected, verified and restored. This is a Raft-mode capability: a
standalone node reports the node's own unsupported-operation error.

For backing up or restoring an individual key, use "xkmsctl key export"
and "xkmsctl key import" instead, which wrap the key for transport under
an operator-supplied key or KEM recipient.

Subcommands:
  create   Create a new backup
  list     List all backups
  show     Show details for a backup
  delete   Delete a backup
  restore  Restore from a backup
  verify   Verify the integrity of a backup`,
}

// backupCreateCmd creates a new backup.
var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new backup",
	Long: `Create a new whole-node backup at the given destination.

Examples:
  xkmsctl backup create --destination /backups/daily
  xkmsctl backup create --destination s3://acme-backups/qrdb \
      --compression zstd --encryption aes256 --encryption-key "$BACKUP_KEY"`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		destination := fr.String("destination")
		compression := fr.String("compression")
		encryption := fr.String("encryption")
		encryptionKey := fr.String("encryption-key")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if destination == "" {
			handleError(ErrBackupDestinationRequired)
			return
		}

		backupCreate(cfg, printer, destination, compression, encryption, encryptionKey)
	},
}

// backupListCmd lists all backups.
var backupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all backups",
	Long: `List all backups, newest first.

Example:
  xkmsctl backup list`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		backupList(cfg, printer)
	},
}

// backupShowCmd shows details for a backup.
var backupShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show details for a backup",
	Long: `Display detailed information about a backup.

Example:
  xkmsctl backup show --id bkp-20260930-0300`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if id == "" {
			handleError(ErrBackupIDRequired)
			return
		}

		backupShow(cfg, printer, id)
	},
}

// backupDeleteCmd deletes a backup.
var backupDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a backup",
	Long: `Delete a backup by ID.

Example:
  xkmsctl backup delete --id bkp-20260930-0300`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if id == "" {
			handleError(ErrBackupIDRequired)
			return
		}

		backupDelete(cfg, printer, id)
	},
}

// backupRestoreCmd restores from a backup. This is the most destructive
// backup operation: it overwrites live shard state.
var backupRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore from a backup",
	Long: `Restore shard state from a backup. THIS OVERWRITES LIVE SHARD STATE.

Examples:
  xkmsctl backup restore --id bkp-20260930-0300 --validate
  xkmsctl backup restore --id bkp-20260930-0300 \
      --decryption-key "$BACKUP_KEY" --validate`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		decryptionKey := fr.String("decryption-key")
		validate := fr.Bool("validate")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if id == "" {
			handleError(ErrBackupIDRequired)
			return
		}

		backupRestore(cfg, printer, id, decryptionKey, validate)
	},
}

// backupVerifyCmd verifies the integrity of a backup.
var backupVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the integrity of a backup",
	Long: `Verify a backup's integrity by recomputing its checksum.

Example:
  xkmsctl backup verify --id bkp-20260930-0300`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if id == "" {
			handleError(ErrBackupIDRequired)
			return
		}

		backupVerify(cfg, printer, id)
	},
}

// createBackupClient creates and connects a client, returning the client and
// a cleanup function. The caller must call cleanup when done.
func createBackupClient(cfg *Config) (client.Client, func(), error) {
	cl, err := cfg.CreateClient()
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateClientFailed, Err: err}
	}

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		closeQuietly(cl)
		return nil, nil, &WrappedError{Sentinel: ErrConnectFailed, Err: err}
	}

	cleanup := func() { closeQuietly(cl) }
	return cl, cleanup, nil
}

// backupCreate creates a new backup.
func backupCreate(cfg *Config, printer *Printer, destination, compression, encryption, encryptionKey string) {
	cl, cleanup, err := createBackupClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Creating backup at %q", destination)

	req := &transport.BackupRequest{
		Destination: destination,
		Compression: transport.CompressionType(compression),
		Encryption:  transport.EncryptionType(encryption),
	}
	if encryptionKey != "" {
		req.EncryptionKey = []byte(encryptionKey)
	}

	resp, err := cl.CreateBackup(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateBackupFailed, Err: err})
		return
	}

	printBackupInfo(printer, resp)
}

// backupList lists all backups.
func backupList(cfg *Config, printer *Printer) {
	cl, cleanup, err := createBackupClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Listing backups")

	backups, err := cl.ListBackups(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrListBackupsFailed, Err: err})
		return
	}

	printBackupList(printer, backups)
}

// backupShow shows details for a backup.
func backupShow(cfg *Config, printer *Printer, id string) {
	cl, cleanup, err := createBackupClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving backup %q", id)

	resp, err := cl.GetBackup(context.Background(), id)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetBackupFailed, Err: err})
		return
	}

	printBackupInfo(printer, resp)
}

// backupDelete deletes a backup.
func backupDelete(cfg *Config, printer *Printer, id string) {
	cl, cleanup, err := createBackupClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Deleting backup %q", id)

	if err := cl.DeleteBackup(context.Background(), id); err != nil {
		handleError(&WrappedError{Sentinel: ErrDeleteBackupFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Backup %q deleted", id)); err != nil {
		handleError(err)
	}
}

// backupRestore restores from a backup.
func backupRestore(cfg *Config, printer *Printer, id, decryptionKey string, validate bool) {
	cl, cleanup, err := createBackupClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Restoring backup %q (validate=%v)", id, validate)

	req := &transport.RestoreRequest{
		BackupID:      id,
		ValidateFirst: validate,
	}
	if decryptionKey != "" {
		req.DecryptionKey = []byte(decryptionKey)
	}

	resp, err := cl.RestoreBackup(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrRestoreBackupFailed, Err: err})
		return
	}

	printRestoreResult(printer, resp)
}

// backupVerify verifies the integrity of a backup.
func backupVerify(cfg *Config, printer *Printer, id string) {
	cl, cleanup, err := createBackupClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Verifying backup %q", id)

	resp, err := cl.VerifyBackup(context.Background(), id)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrVerifyBackupFailed, Err: err})
		return
	}

	printVerifyResult(printer, id, resp)
}

// printBackupInfo prints a backup's metadata.
func printBackupInfo(printer *Printer, info *transport.BackupInfo) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(info); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Backup:\n")
		printer.printf("  ID:          %s\n", info.ID)
		printer.printf("  Timestamp:   %s\n", info.Timestamp.Format(time.RFC3339))
		printer.printf("  Status:      %s\n", info.Status)
		printer.printf("  Size:        %d bytes\n", info.Size)
		printer.printf("  Shards:      %d\n", info.ShardCount)
		printer.printf("  Checksum:    %s\n", info.Checksum)
		printer.printf("  Destination: %s\n", info.Destination)
		printer.printf("  Compression: %s\n", info.Compression)
		printer.printf("  Encryption:  %s\n", info.Encryption)
		if info.ErrorMessage != "" {
			printer.printf("  Error:       %s\n", info.ErrorMessage)
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// printBackupList prints a list of backups.
func printBackupList(printer *Printer, backups []transport.BackupInfo) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(backups); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		if len(backups) == 0 {
			printer.printf("No backups found.\n")
			break
		}
		printer.printf("%-24s %-10s %-20s %-10s\n", "ID", "STATUS", "TIMESTAMP", "SIZE")
		printer.printf("%s\n", strings.Repeat("-", 68))
		for _, b := range backups {
			printer.printf("%-24s %-10s %-20s %-10d\n",
				b.ID, b.Status, b.Timestamp.Format(time.RFC3339), b.Size)
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// printRestoreResult prints the outcome of a restore operation.
func printRestoreResult(printer *Printer, resp *transport.RestoreResult) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Restore complete:\n")
		printer.printf("  Backup:          %s\n", resp.BackupID)
		printer.printf("  Shards Restored: %d\n", resp.ShardsRestored)
		printer.printf("  Duration:        %s\n", resp.Duration)
		for _, e := range resp.Errors {
			printer.printf("  Shard %d error:  %s\n", e.ShardID, e.Message)
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// printVerifyResult prints the outcome of a backup verification.
func printVerifyResult(printer *Printer, id string, resp *transport.VerifyResult) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Verification result for %q:\n", id)
		printer.printf("  Valid:             %v\n", resp.Valid)
		printer.printf("  Checksum Match:    %v\n", resp.ChecksumMatch)
		printer.printf("  Expected Checksum: %s\n", resp.ExpectedChecksum)
		printer.printf("  Actual Checksum:   %s\n", resp.ActualChecksum)
		for _, e := range resp.Errors {
			printer.printf("  Error: %s\n", e)
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func init() {
	// backup create flags
	backupCreateCmd.Flags().String("destination", "", "storage path or URI, e.g. /backups/daily or s3://bucket/prefix (required)")
	backupCreateCmd.Flags().String("compression", "", "compression algorithm: none, zstd, snappy")
	backupCreateCmd.Flags().String("encryption", "", "encryption algorithm: none, aes256")
	backupCreateCmd.Flags().String("encryption-key", "", "encryption key material (required when --encryption is not none)")

	// backup show flags
	backupShowCmd.Flags().String("id", "", "backup ID (required)")

	// backup delete flags
	backupDeleteCmd.Flags().String("id", "", "backup ID (required)")

	// backup restore flags
	backupRestoreCmd.Flags().String("id", "", "backup ID to restore from (required)")
	backupRestoreCmd.Flags().String("decryption-key", "", "decryption key material (required for encrypted backups)")
	backupRestoreCmd.Flags().Bool("validate", false, "verify integrity before restoring")

	// backup verify flags
	backupVerifyCmd.Flags().String("id", "", "backup ID (required)")

	// Build subcommand tree
	backupCmd.AddCommand(backupCreateCmd)
	backupCmd.AddCommand(backupListCmd)
	backupCmd.AddCommand(backupShowCmd)
	backupCmd.AddCommand(backupDeleteCmd)
	backupCmd.AddCommand(backupRestoreCmd)
	backupCmd.AddCommand(backupVerifyCmd)

	// Register with root
	rootCmd.AddCommand(backupCmd)
}
