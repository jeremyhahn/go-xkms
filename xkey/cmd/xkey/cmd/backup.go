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
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	xkeysync "github.com/jeremyhahn/go-xkms/xkey/pkg/sync"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
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

	// ErrBackupListFailed indicates the backup directory could not be listed.
	ErrBackupListFailed = errors.New("backup: list failed")

	// ErrBackupNoData indicates every data store was empty or unreachable,
	// so there was nothing to write. An empty backup file is never created.
	ErrBackupNoData = errors.New("backup: no data available to back up")

	// ErrBackupStoreUnavailable indicates a data store could not be opened
	// for reading (backup) or writing (restore).
	ErrBackupStoreUnavailable = errors.New("backup: data store unavailable")

	// ErrBackupRestoreIncomplete indicates the backup held data in a
	// category the CLI cannot write back, so the restore was partial.
	ErrBackupRestoreIncomplete = errors.New("backup: restore incomplete")

	// ErrBackupBarrierEncrypted indicates the xkey data directory is sealed
	// by the barrier, which the CLI cannot unlock on its own.
	ErrBackupBarrierEncrypted = errors.New(
		"backup: xkey data directory is barrier-encrypted; unseal it in the xkey GUI, " +
			"or pass explicit --trust-store/--oath-store/--password-store paths")
)

// Default store locations beneath the xkey data directory ($XKEY_HOME/data,
// e.g. ~/.xkey/data). These are exactly the paths the xkey GUI uses when the
// barrier is not active, so a CLI backup captures what the GUI shows.
const (
	backupTrustStoreDir    = "trust"
	backupOATHStoreFile    = "oath.json"
	backupPasswordStoreDir = "passwords"
)

// backupCASkipReason explains why a CLI-created backup never carries CA
// material: the local CA lives inside the xkmsd daemon and is only reachable
// over the SDK transport, which the offline backup path does not open.
const backupCASkipReason = "no local CA store; xkey CA material is served by the xkmsd daemon"

// backupCmd is the parent command for backup and restore operations.
var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup and restore xkey data",
	Long: `Create, restore, and manage encrypted backups of xkey data including
trust store certificates, OATH credentials, and static passwords.

Backups are sealed with XChaCha20-Poly1305. The file is the JSON encoding of
the backup envelope -- magic, format version, nonce, and ciphertext -- so no
backed-up value is readable without the password or key used to create it.`,
}

// backupCreateCmd creates a new encrypted backup.
var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a backup of xkey data",
	Long: `Create an encrypted backup of xkey data. The backup includes trust
store certificates, OATH credentials, and static passwords read from the xkey
data directory ($XKEY_HOME/data, by default ~/.xkey/data).

If no password is provided, a random 256-bit encryption key is generated
and printed to stdout in hex encoding. Store this key securely: without it
the backup cannot be read.

The command fails rather than writing an empty file when every data store is
empty or unreachable.

Examples:
  xkey backup create
  xkey backup create --password mypassword
  xkey backup create --output /tmp/my-backup.xkb
  xkey backup create --password mypassword --oath-store /srv/xkey/oath.json`,
	RunE: runBackupCreate,
}

// backupRestoreCmd restores data from an encrypted backup.
var backupRestoreCmd = &cobra.Command{
	Use:   "restore <file>",
	Short: "Restore xkey data from a backup",
	Long: `Restore xkey data from an encrypted backup file. Requires the same
password or key used during backup creation; any other credential fails with
a decryption error and nothing is written.

Restored data is merged into the stores under the xkey data directory
($XKEY_HOME/data). Entries that already exist are reported as skipped.

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

Decrypts the backup to display item counts, creation date, and device name
without modifying any data. Requires the password or key used to create the
backup.

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
	addBackupStoreFlags(backupCreateCmd)

	// Restore flags
	backupRestoreCmd.Flags().String("password", "", "Decryption password")
	backupRestoreCmd.Flags().String("key", "", "Hex-encoded decryption key")
	addBackupStoreFlags(backupRestoreCmd)

	// Contents flags
	backupContentsCmd.Flags().String("password", "", "Decryption password")
	backupContentsCmd.Flags().String("key", "", "Hex-encoded decryption key")
}

// addBackupStoreFlags registers the store-location overrides shared by the
// create and restore commands.
func addBackupStoreFlags(cmd *cobra.Command) {
	cmd.Flags().String("trust-store", "",
		"Trust store directory (default: {xkey-home}/data/trust)")
	cmd.Flags().String("oath-store", "",
		"OATH credential store file (default: {xkey-home}/data/oath.json)")
	cmd.Flags().String("password-store", "",
		"Static password store directory (default: {xkey-home}/data/passwords)")
}

// ---------------------------------------------------------------------------
// Manifest display projection
// ---------------------------------------------------------------------------

// backupManifest is the flat display projection of a backup.Manifest. The
// backup service records counts as a list of typed items; the create,
// contents, and restore commands render them from this struct so all three
// print identical labels.
type backupManifest struct {
	CreatedAt    time.Time
	DeviceName   string
	TrustCerts   int
	OATHAccounts int
	Passwords    int
	CACerts      int
	Version      int
}

// backupManifestSetters maps a manifest item type to the display field it
// populates, giving O(1) dispatch per manifest item.
var backupManifestSetters = map[string]func(*backupManifest, int){
	backup.ItemTrustStore: func(v *backupManifest, n int) { v.TrustCerts = n },
	backup.ItemCAData:     func(v *backupManifest, n int) { v.CACerts = n },
	backup.ItemOATH:       func(v *backupManifest, n int) { v.OATHAccounts = n },
	backup.ItemPasswords:  func(v *backupManifest, n int) { v.Passwords = n },
}

// newBackupManifest projects a decrypted service manifest onto the flat
// display struct. Unknown item types are ignored: an older CLI must still be
// able to summarize a backup written by a newer one.
func newBackupManifest(m *backup.Manifest) backupManifest {
	view := backupManifest{
		CreatedAt:  m.Created,
		DeviceName: m.DeviceName,
		Version:    m.Version,
	}
	for _, item := range m.Contents {
		if set, ok := backupManifestSetters[item.Type]; ok {
			set(&view, item.Count)
		}
	}
	return view
}

// writeManifestSummary prints the manifest counts using the labels shared by
// every backup subcommand.
func writeManifestSummary(w io.Writer, view backupManifest) {
	_, _ = fmt.Fprintf(w, "  Version:      %d\n", view.Version)
	_, _ = fmt.Fprintf(w, "  Device:       %s\n", view.DeviceName)
	_, _ = fmt.Fprintf(w, "  Created:      %s\n", view.CreatedAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(w, "  Trust certs:  %d\n", view.TrustCerts)
	_, _ = fmt.Fprintf(w, "  OATH:         %d\n", view.OATHAccounts)
	_, _ = fmt.Fprintf(w, "  Passwords:    %d\n", view.Passwords)
	if view.CACerts > 0 {
		_, _ = fmt.Fprintf(w, "  CA data:      %d\n", view.CACerts)
	}
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

// runBackupCreate creates an encrypted backup of xkey data.
func runBackupCreate(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	password, _ := cmd.Flags().GetString("password")

	// Determine output path
	if output == "" {
		dir, err := getBackupDir()
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrBackupCreateFailed, Cause: err}
		}
		timestamp := time.Now().Format("20060102-150405")
		output = filepath.Join(dir, fmt.Sprintf("backup-%s.xkb", timestamp))
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(output)
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return &DetailError{Err: ErrBackupCreateFailed, Detail: fmt.Sprintf(": cannot create backup directory: %v", err)}
	}

	// Derive or generate encryption key
	var key []byte
	if password != "" {
		key = deriveKey(password)
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Using password-derived encryption key.")
	} else {
		var err error
		key, err = generateRandomKey()
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrBackupCreateFailed, Cause: err}
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Generated encryption key (save this):\n  %s\n\n", hex.EncodeToString(key))
	}

	sources, err := resolveBackupSources(backupStorePathsFromFlags(cmd))
	if err != nil {
		return err
	}
	defer sources.Close()

	svc, err := backup.NewService(&backup.Config{DeviceName: getHostname()}, sources.readerOptions()...)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupCreateFailed, Cause: err}
	}

	encrypted, err := svc.CreateBackup(key)
	if err != nil {
		if errors.Is(err, backup.ErrEmptyBackup) {
			return &DetailError{Err: ErrBackupNoData, Detail: ": " + sources.summary()}
		}
		return &SentinelCauseError{Sentinel: ErrBackupCreateFailed, Cause: err}
	}

	// Decrypt the freshly sealed backup before writing it. This both yields
	// the authoritative item counts for the report and proves the file about
	// to be written can be opened with the key the operator was handed.
	manifest, err := svc.GetManifest(encrypted, key)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupCreateFailed, Cause: err}
	}

	if err := writeEncryptedBackup(output, encrypted); err != nil {
		return err
	}

	size := int64(len(encrypted.Ciphertext))
	if info, statErr := os.Stat(output); statErr == nil {
		size = info.Size()
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Backup created: %s\n", output)
	writeManifestSummary(out, newBackupManifest(manifest))
	_, _ = fmt.Fprintf(out, "  Format:       %s v%d (XChaCha20-Poly1305)\n", encrypted.Magic, encrypted.Version)
	_, _ = fmt.Fprintf(out, "  Size:         %s\n", formatSize(size))
	writeSkippedSources(out, sources.skipped)

	return nil
}

// runBackupRestore restores xkey data from an encrypted backup file.
func runBackupRestore(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	password, _ := cmd.Flags().GetString("password")
	keyHex, _ := cmd.Flags().GetString("key")

	if err := requireBackupFile(filePath); err != nil {
		return err
	}

	key, err := resolveDecryptionKey(password, keyHex)
	if err != nil {
		return err
	}

	encrypted, err := readEncryptedBackup(filePath)
	if err != nil {
		return err
	}

	svc, err := backup.NewService(&backup.Config{DeviceName: getHostname()})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupRestoreFailed, Cause: err}
	}

	archive, err := svc.DecryptBackup(encrypted, key)
	if err != nil {
		return classifyBackupDecryptError(err)
	}

	sources, err := resolveBackupSources(backupStorePathsFromFlags(cmd))
	if err != nil {
		return err
	}
	defer sources.Close()

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Restoring from: %s\n", filePath)
	writeManifestSummary(out, newBackupManifest(&archive.Manifest))
	_, _ = fmt.Fprintln(out)

	results, err := restoreArchive(svc, archive, sources)
	if err != nil {
		return err
	}

	skipped := 0
	for _, result := range results {
		_, _ = fmt.Fprintf(out, "  %-18s restored %d, skipped %d\n",
			result.ItemType+":", result.Restored, result.Skipped)
		for _, msg := range result.Errors {
			_, _ = fmt.Fprintf(out, "      skipped: %s\n", msg)
		}
		skipped += result.Skipped
	}

	// Categories present in the archive that the CLI has no writer for are
	// reported as an incomplete restore rather than silently dropped.
	if archive.CAData != nil {
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintf(out, "  %s: not restored (%s)\n", backup.ItemCAData, backupCASkipReason)
		return &DetailError{
			Err:    ErrBackupRestoreIncomplete,
			Detail: fmt.Sprintf(": %s could not be restored: %s", backup.ItemCAData, backupCASkipReason),
		}
	}

	_, _ = fmt.Fprintln(out)
	if skipped > 0 {
		_, _ = fmt.Fprintf(out, "Restore completed with %d skipped item(s).\n", skipped)
		return nil
	}
	_, _ = fmt.Fprintln(out, "Restore completed successfully.")

	return nil
}

// runBackupList lists backup files in the default backup directory.
func runBackupList(cmd *cobra.Command, args []string) error {
	dir, err := getBackupDir()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupListFailed, Cause: err}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No backups found.")
			return nil
		}
		return &SentinelCauseError{Sentinel: ErrBackupListFailed, Cause: err}
	}

	var backups []os.DirEntry
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".xkb" {
			backups = append(backups, e)
		}
	}

	if len(backups) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No backups found.")
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Backups (%d):\n\n", len(backups))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %-40s  %-20s  %s\n", "FILE", "DATE", "SIZE")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %-40s  %-20s  %s\n", "----", "----", "----")

	for _, e := range backups {
		info, err := e.Info()
		if err != nil {
			continue
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %-40s  %-20s  %s\n",
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

	if err := requireBackupFile(filePath); err != nil {
		return err
	}

	key, err := resolveDecryptionKey(password, keyHex)
	if err != nil {
		return err
	}

	encrypted, err := readEncryptedBackup(filePath)
	if err != nil {
		return err
	}

	svc, err := backup.NewService(&backup.Config{DeviceName: getHostname()})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupRestoreFailed, Cause: err}
	}

	manifest, err := svc.GetManifest(encrypted, key)
	if err != nil {
		return classifyBackupDecryptError(err)
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Backup Contents: %s\n\n", filepath.Base(filePath))
	writeManifestSummary(out, newBackupManifest(manifest))
	_, _ = fmt.Fprintf(out, "  Format:       %s v%d (XChaCha20-Poly1305)\n", encrypted.Magic, encrypted.Version)
	_, _ = fmt.Fprintf(out, "  Checksum:     %s\n", manifest.Checksum)

	return nil
}

// ---------------------------------------------------------------------------
// Data sources
// ---------------------------------------------------------------------------

// backupStorePaths holds the on-disk locations of the data stores a backup
// reads from and a restore writes to. An empty field selects the default
// location beneath the xkey data directory.
type backupStorePaths struct {
	trust     string
	oath      string
	passwords string
}

// backupStorePathsFromFlags reads the store-location overrides shared by the
// create and restore commands.
func backupStorePathsFromFlags(cmd *cobra.Command) backupStorePaths {
	trust, _ := cmd.Flags().GetString("trust-store")
	oathPath, _ := cmd.Flags().GetString("oath-store")
	passwords, _ := cmd.Flags().GetString("password-store")
	return backupStorePaths{trust: trust, oath: oathPath, passwords: passwords}
}

// usesDefaults reports whether every store location is left at its default.
func (p backupStorePaths) usesDefaults() bool {
	return p.trust == "" && p.oath == "" && p.passwords == ""
}

// backupSkippedSource records a data category the CLI could not read or
// write, together with the operator-facing reason.
type backupSkippedSource struct {
	Item   string
	Reason string
}

// backupSources holds every data store backing a backup or restore run and
// the categories that had to be skipped.
type backupSources struct {
	trust     *trustStoreAdapter
	oath      *oathStoreAdapter
	passwords *passwordStoreAdapter
	skipped   []backupSkippedSource
}

// resolveBackupSources opens every data store reachable from the CLI. A store
// that cannot be opened is a hard failure: omitting it would produce a backup
// that silently misses data, or a restore that silently drops it.
func resolveBackupSources(paths backupStorePaths) (*backupSources, error) {
	dataDir, err := backupDataDir()
	if err != nil {
		return nil, err
	}

	// The GUI keeps these stores inside the barrier once it is initialized,
	// so any plaintext copy left on disk is stale. The CLI has no unseal
	// flow of its own, so refuse rather than back up stale data.
	if paths.usesDefaults() && barrierRootKeyExists(dataDir) {
		return nil, ErrBackupBarrierEncrypted
	}

	sources := &backupSources{
		skipped: []backupSkippedSource{{Item: backup.ItemCAData, Reason: backupCASkipReason}},
	}

	trustPath := paths.trust
	if trustPath == "" {
		trustPath = filepath.Join(dataDir, backupTrustStoreDir)
	}
	trustStore, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: trustPath})
	if err != nil {
		sources.Close()
		return nil, backupStoreError(backup.ItemTrustStore, trustPath, err)
	}
	sources.trust = &trustStoreAdapter{store: trustStore, path: trustPath}

	oathPath := paths.oath
	if oathPath == "" {
		oathPath = filepath.Join(dataDir, backupOATHStoreFile)
	}
	oathStore, err := oath.NewFileStore(oathPath)
	if err != nil {
		sources.Close()
		return nil, backupStoreError(backup.ItemOATH, oathPath, err)
	}
	sources.oath = &oathStoreAdapter{store: oathStore, path: oathPath}

	passwordPath := paths.passwords
	if passwordPath == "" {
		passwordPath = filepath.Join(dataDir, backupPasswordStoreDir)
	}
	passwordStore, err := openPasswordStore(passwordPath)
	if err != nil {
		sources.Close()
		return nil, backupStoreError(backup.ItemPasswords, passwordPath, err)
	}
	sources.passwords = &passwordStoreAdapter{store: passwordStore, path: passwordPath}

	return sources, nil
}

// backupStoreError reports a store that could not be opened, naming both the
// data category and the path so the operator can correct it.
func backupStoreError(item, path string, cause error) error {
	return &SentinelCauseError{
		Sentinel: ErrBackupStoreUnavailable,
		Cause:    &WrappedError{Msg: item + " (" + path + ")", Err: cause},
	}
}

// readerOptions returns the backup service options for every opened store.
func (s *backupSources) readerOptions() []backup.Option {
	opts := make([]backup.Option, 0, 3)
	if s.trust != nil {
		opts = append(opts, backup.WithTrustStore(s.trust))
	}
	if s.oath != nil {
		opts = append(opts, backup.WithOATH(s.oath))
	}
	if s.passwords != nil {
		opts = append(opts, backup.WithPasswords(s.passwords))
	}
	return opts
}

// syncOptions returns the sync service options for every opened store. The
// same adapters back both services, so a sync run reads and writes exactly the
// stores a backup would.
func (s *backupSources) syncOptions() []xkeysync.Option {
	opts := make([]xkeysync.Option, 0, 3)
	if s.trust != nil {
		opts = append(opts, xkeysync.WithTrustStore(s.trust))
	}
	if s.oath != nil {
		opts = append(opts, xkeysync.WithOATH(s.oath))
	}
	if s.passwords != nil {
		opts = append(opts, xkeysync.WithPasswords(s.passwords))
	}
	return opts
}

// summary renders every store location and skipped category on one line for
// inclusion in an error message.
func (s *backupSources) summary() string {
	parts := make([]string, 0, 4)
	if s.trust != nil {
		parts = append(parts, backup.ItemTrustStore+" ("+s.trust.path+")")
	}
	if s.oath != nil {
		parts = append(parts, backup.ItemOATH+" ("+s.oath.path+")")
	}
	if s.passwords != nil {
		parts = append(parts, backup.ItemPasswords+" ("+s.passwords.path+")")
	}
	summary := "no entries in " + strings.Join(parts, ", ")
	for _, skip := range s.skipped {
		summary += "; " + skip.Item + " skipped: " + skip.Reason
	}
	return summary
}

// Close releases every opened store.
func (s *backupSources) Close() {
	if s == nil {
		return
	}
	if s.trust != nil {
		_ = s.trust.Close()
	}
	if s.oath != nil {
		_ = s.oath.Close()
	}
	if s.passwords != nil {
		_ = s.passwords.Close()
	}
}

// writeSkippedSources prints the categories that were left out of a backup.
func writeSkippedSources(w io.Writer, skipped []backupSkippedSource) {
	if len(skipped) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "Not included:")
	for _, skip := range skipped {
		_, _ = fmt.Fprintf(w, "  %s: %s\n", skip.Item, skip.Reason)
	}
}

// backupDataDir returns the xkey data directory holding the GUI-visible
// stores. It prefers the home resolved by the root command so XKEY_HOME is
// honored, and falls back to ~/.xkey/data for direct invocations that run
// outside the cobra lifecycle.
func backupDataDir() (string, error) {
	if resolvedHome != nil {
		return resolvedHome.DataDir(), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrBackupStoreUnavailable, Cause: err}
	}
	return filepath.Join(home, ".xkey", "data"), nil
}

// ---------------------------------------------------------------------------
// Store adapters
// ---------------------------------------------------------------------------

// Compile-time proof that each adapter satisfies every service contract it is
// wired into. The sync accessors extend the backup reader/writer pairs with
// the lookups the merge step needs, so one adapter serves both services.
var (
	_ backup.TrustStoreReader = (*trustStoreAdapter)(nil)
	_ backup.TrustStoreWriter = (*trustStoreAdapter)(nil)
	_ backup.OATHReader       = (*oathStoreAdapter)(nil)
	_ backup.OATHWriter       = (*oathStoreAdapter)(nil)
	_ backup.PasswordReader   = (*passwordStoreAdapter)(nil)
	_ backup.PasswordWriter   = (*passwordStoreAdapter)(nil)

	_ xkeysync.TrustStoreAccessor = (*trustStoreAdapter)(nil)
	_ xkeysync.OATHAccessor       = (*oathStoreAdapter)(nil)
	_ xkeysync.PasswordAccessor   = (*passwordStoreAdapter)(nil)
)

// trustStoreAdapter bridges the xkey trust store to the backup service,
// translating trust-store metadata into the service's storage-neutral form.
type trustStoreAdapter struct {
	store *truststore.FileStore
	path  string
}

// Certificates returns every certificate held by the trust store.
func (a *trustStoreAdapter) Certificates() ([]*x509.Certificate, error) {
	return a.store.Certificates()
}

// Metadata returns the backup-facing metadata for one certificate.
func (a *trustStoreAdapter) Metadata(fingerprint string) (*backup.CertMetadataInfo, error) {
	meta, err := a.store.Metadata(fingerprint)
	if err != nil {
		return nil, err
	}
	return &backup.CertMetadataInfo{
		Fingerprint: meta.Fingerprint,
		Purpose:     string(meta.Purpose),
		Source:      meta.Source,
		Tags:        meta.Tags,
	}, nil
}

// AddPEM imports PEM-encoded certificates during a restore.
func (a *trustStoreAdapter) AddPEM(pemData []byte) (int, error) {
	return a.store.AddPEM(pemData)
}

// Contains reports whether a certificate with the given fingerprint is
// already held, so a sync merge can skip it instead of re-importing.
func (a *trustStoreAdapter) Contains(fingerprint string) (bool, error) {
	return a.store.Contains(fingerprint)
}

// Close releases the underlying trust store.
func (a *trustStoreAdapter) Close() error { return a.store.Close() }

// oathStoreAdapter bridges the xkey OATH credential store to the backup
// service's reader and writer contracts.
type oathStoreAdapter struct {
	store *oath.FileStore
	path  string
}

// List returns every stored OATH credential in backup form.
func (a *oathStoreAdapter) List() ([]*backup.OATHCredentialInfo, error) {
	creds, err := a.store.List()
	if err != nil {
		return nil, err
	}
	out := make([]*backup.OATHCredentialInfo, 0, len(creds))
	for _, cred := range creds {
		out = append(out, oathCredentialToInfo(cred))
	}
	return out, nil
}

// Get returns one stored OATH credential in backup form. It reports the
// store's not-found error unchanged so a sync merge can tell "absent" from
// "unreadable".
func (a *oathStoreAdapter) Get(id string) (*backup.OATHCredentialInfo, error) {
	cred, err := a.store.Get(id)
	if err != nil {
		return nil, err
	}
	return oathCredentialToInfo(cred), nil
}

// Add writes one restored OATH credential back to the store.
func (a *oathStoreAdapter) Add(info *backup.OATHCredentialInfo) error {
	cred, err := oathInfoToCredential(info, time.Now().UTC())
	if err != nil {
		return err
	}
	return a.store.Add(cred)
}

// Update replaces an existing OATH credential, preserving its creation time.
func (a *oathStoreAdapter) Update(info *backup.OATHCredentialInfo) error {
	existing, err := a.store.Get(info.ID)
	if err != nil {
		return err
	}
	cred, err := oathInfoToCredential(info, existing.CreatedAt)
	if err != nil {
		return err
	}
	return a.store.Update(cred)
}

// Close releases the underlying OATH store.
func (a *oathStoreAdapter) Close() error { return a.store.Close() }

// oathCredentialToInfo converts a stored credential to the service-facing
// form shared by the backup and sync services.
func oathCredentialToInfo(cred *oath.Credential) *backup.OATHCredentialInfo {
	return &backup.OATHCredentialInfo{
		ID:          cred.ID,
		Name:        cred.Name,
		Issuer:      cred.Issuer,
		AccountName: cred.AccountName,
		Secret:      cred.SecretString(),
		Type:        cred.Type,
		Algorithm:   cred.Algorithm,
		Digits:      cred.Digits,
		Period:      cred.Period,
		Counter:     oathCounterToInt64(cred.Counter),
	}
}

// oathInfoToCredential converts the service-facing form back to a stored
// credential, stamping the given creation time. The secret is adopted into
// protected memory; the error is oath.ErrProtectedMemory (wrapped) when that
// allocation fails.
func oathInfoToCredential(info *backup.OATHCredentialInfo, createdAt time.Time) (*oath.Credential, error) {
	cred := &oath.Credential{
		ID:          info.ID,
		Name:        info.Name,
		Issuer:      info.Issuer,
		AccountName: info.AccountName,
		Type:        info.Type,
		Algorithm:   info.Algorithm,
		Digits:      info.Digits,
		Period:      info.Period,
		Counter:     oathCounterFromInt64(info.Counter),
		CreatedAt:   createdAt,
	}
	if err := cred.SetSecret(info.Secret); err != nil {
		return nil, err
	}
	return cred, nil
}

// oathCounterToInt64 converts an HOTP counter to the backup service's signed
// representation, clamping the values above math.MaxInt64 that cannot occur
// in practice so the conversion can never wrap negative.
func oathCounterToInt64(counter uint64) int64 {
	if counter > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(counter)
}

// oathCounterFromInt64 converts a backup HOTP counter back to the store's
// unsigned representation, clamping negatives to zero.
func oathCounterFromInt64(counter int64) uint64 {
	if counter < 0 {
		return 0
	}
	return uint64(counter)
}

// passwordStoreAdapter bridges the static password store to the backup
// service's reader and writer contracts.
type passwordStoreAdapter struct {
	store *xkms.StaticPasswordBackendStore
	path  string
}

// List returns every stored static password in backup form.
func (a *passwordStoreAdapter) List() ([]*backup.PasswordInfo, error) {
	passwords, err := a.store.List()
	if err != nil {
		return nil, err
	}
	out := make([]*backup.PasswordInfo, 0, len(passwords))
	for _, pw := range passwords {
		out = append(out, passwordToInfo(pw))
	}
	return out, nil
}

// Get returns one stored password in backup form. It reports the store's
// not-found error unchanged so a sync merge can tell "absent" from
// "unreadable".
func (a *passwordStoreAdapter) Get(id string) (*backup.PasswordInfo, error) {
	pw, err := a.store.Get(id)
	if err != nil {
		return nil, err
	}
	return passwordToInfo(pw), nil
}

// Add writes one restored static password back to the store. The store
// derives the entry ID from the name and folder, so restoring preserves
// identity without carrying the stored ID across.
func (a *passwordStoreAdapter) Add(info *backup.PasswordInfo) error {
	return a.store.Add(&xkms.StaticPassword{
		Name:       info.Name,
		Title:      info.Title,
		Username:   info.Username,
		Password:   info.Password,
		URL:        info.URL,
		Notes:      info.Notes,
		FolderPath: info.FolderPath,
	})
}

// Update replaces an existing password entry. The store keys entries by an ID
// derived from name and folder, so the stored ID is resolved first rather than
// trusting the ID the remote peer supplied.
func (a *passwordStoreAdapter) Update(info *backup.PasswordInfo) error {
	existing, err := a.store.Get(info.ID)
	if err != nil {
		return err
	}
	return a.store.Update(&xkms.StaticPassword{
		ID:         existing.ID,
		Name:       info.Name,
		Title:      info.Title,
		Username:   info.Username,
		Password:   info.Password,
		URL:        info.URL,
		Notes:      info.Notes,
		FolderPath: info.FolderPath,
	})
}

// passwordToInfo converts a stored password to the service-facing form shared
// by the backup and sync services.
func passwordToInfo(pw *xkms.StaticPassword) *backup.PasswordInfo {
	return &backup.PasswordInfo{
		ID:         pw.ID,
		Name:       pw.Name,
		Title:      pw.Title,
		Username:   pw.Username,
		Password:   pw.Password,
		URL:        pw.URL,
		Notes:      pw.Notes,
		FolderPath: pw.FolderPath,
	}
}

// Close releases the underlying password store.
func (a *passwordStoreAdapter) Close() error { return a.store.Close() }

// ---------------------------------------------------------------------------
// Restore helpers
// ---------------------------------------------------------------------------

// restoreArchive writes every category the archive carries back to its store
// and returns one result per category that held data.
func restoreArchive(svc *backup.Service, archive *backup.Archive, sources *backupSources) ([]*backup.RestoreResult, error) {
	results := make([]*backup.RestoreResult, 0, 3)

	if archive.TrustStore != nil && len(archive.TrustStore.Certificates) > 0 {
		result, err := svc.RestoreTrustStore(archive, sources.trust)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrBackupRestoreFailed, Cause: err}
		}
		results = append(results, result)
	}

	if len(archive.OATHCreds) > 0 {
		result, err := svc.RestoreOATH(archive, sources.oath)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrBackupRestoreFailed, Cause: err}
		}
		results = append(results, result)
	}

	if len(archive.Passwords) > 0 {
		result, err := svc.RestorePasswords(archive, sources.passwords)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrBackupRestoreFailed, Cause: err}
		}
		results = append(results, result)
	}

	return results, nil
}

// ---------------------------------------------------------------------------
// File format
// ---------------------------------------------------------------------------

// writeEncryptedBackup serializes a sealed backup to disk. The on-disk format
// is the JSON encoding of backup.EncryptedBackup: a plaintext envelope
// carrying the magic value, format version, nonce, and the sealed archive as
// base64 ciphertext. Every backed-up value lives inside the ciphertext.
func writeEncryptedBackup(path string, encrypted *backup.EncryptedBackup) error {
	data, err := json.Marshal(encrypted)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupCreateFailed, Cause: err}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupCreateFailed, Cause: err}
	}
	return nil
}

// readEncryptedBackup loads the envelope written by writeEncryptedBackup. The
// envelope's magic value and version are validated by the backup service when
// the archive is decrypted.
func readEncryptedBackup(path string) (*backup.EncryptedBackup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrBackupRestoreFailed, Cause: err}
	}
	var encrypted backup.EncryptedBackup
	if err := json.Unmarshal(data, &encrypted); err != nil {
		return nil, &DetailError{
			Err:    ErrBackupDecryptFailed,
			Detail: ": file is not an xkey backup envelope",
		}
	}
	return &encrypted, nil
}

// requireBackupFile reports whether the given backup file is readable.
func requireBackupFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return &DetailError{Err: ErrBackupFileNotFound, Detail: fmt.Sprintf(": %s", path)}
		}
		return &SentinelCauseError{Sentinel: ErrBackupRestoreFailed, Cause: err}
	}
	return nil
}

// backupDecryptReasons maps a backup service failure to the operator-facing
// explanation the CLI prints, checked in order.
var backupDecryptReasons = []struct {
	sentinel error
	reason   string
}{
	{backup.ErrDecryptionFailed, "incorrect password or key"},
	{backup.ErrCorruptedBackup, "checksum mismatch: the backup file is corrupt"},
	{backup.ErrVersionMismatch, "unsupported backup format version"},
	{backup.ErrInvalidBackup, "file is not an xkey backup envelope"},
}

// classifyBackupDecryptError converts a backup service decryption failure
// into an ErrBackupDecryptFailed-rooted error naming the specific reason.
func classifyBackupDecryptError(err error) error {
	for _, candidate := range backupDecryptReasons {
		if errors.Is(err, candidate.sentinel) {
			return &DetailError{Err: ErrBackupDecryptFailed, Detail: ": " + candidate.reason}
		}
	}
	return &SentinelCauseError{Sentinel: ErrBackupDecryptFailed, Cause: err}
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

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
			return nil, &DetailError{Err: ErrBackupDecryptFailed, Detail: fmt.Sprintf(": invalid hex key: %v", err)}
		}
		if len(key) != 32 {
			return nil, &DetailError{Err: ErrBackupDecryptFailed, Detail: fmt.Sprintf(": key must be 32 bytes, got %d", len(key))}
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
