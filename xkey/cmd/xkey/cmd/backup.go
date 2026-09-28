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
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-enclave"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	xkeysync "github.com/jeremyhahn/go-xkms/xkey/pkg/sync"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
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
	ErrBackupKeyRequired = errors.New(
		"backup: password (--password-stdin or XKEY_BACKUP_PASSWORD) or " +
			"key (--key-stdin or XKEY_BACKUP_KEY) required")

	// ErrBackupKeyStdinEmpty indicates --key-stdin was given but standard
	// input carried no key.
	ErrBackupKeyStdinEmpty = errors.New("backup: --key-stdin was given but standard input carried no key")

	// ErrBackupKeyStdinRead indicates standard input could not be read for
	// --key-stdin.
	ErrBackupKeyStdinRead = errors.New("backup: failed to read the key from standard input")

	// ErrBackupPasswordStdinEmpty indicates --password-stdin was given but
	// standard input carried no password.
	ErrBackupPasswordStdinEmpty = errors.New("backup: --password-stdin was given but standard input carried no password")

	// ErrBackupPasswordStdinRead indicates standard input could not be read
	// for --password-stdin.
	ErrBackupPasswordStdinRead = errors.New("backup: failed to read the password from standard input")

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

	// ErrBackupSourceMissing indicates a backup source path the operator
	// named explicitly (--trust-store, --oath-store, --password-store) does
	// not exist. Reading from a store is never allowed to auto-create it:
	// that would silently turn a typo into an empty backup instead of an
	// error (go-xkms#936).
	ErrBackupSourceMissing = errors.New("backup: source does not exist")

	// ErrBackupRestoreIncomplete indicates the backup held data in a
	// category the CLI cannot write back, so the restore was partial.
	ErrBackupRestoreIncomplete = errors.New("backup: restore incomplete")

	// ErrBackupBarrierEncrypted indicates the trust store or password store
	// is barrier-encrypted at its default location. Unlike the OATH store
	// (resolveOATHBackupStore, barrier-aware since go-xkms#134/#148), these
	// two do not yet have a barrier-backed CLI path.
	ErrBackupBarrierEncrypted = errors.New(
		"backup: xkey data directory is barrier-encrypted; unseal it in the xkey GUI, " +
			"or pass explicit --trust-store/--password-store paths")
)

// The default store locations beneath the xkey data directory
// ($XKEY_HOME/data, e.g. ~/.xkey/data) resolve through the same
// feature-subdirectory constants their owning commands use:
// trustDataSubdir (trust.go), oathStoreFilename (oath.go), and
// passwordStoreFeature (password.go). A private copy of these names here
// previously drifted from the owning command's default -- this package once
// defined its own backupPasswordStoreDir as "passwords" while the static
// password store actually lives at "staticpw" (passwordStoreFeature) -- so a
// default backup silently captured no passwords (go-xkms#936). These are
// exactly the paths the xkey GUI uses when the barrier is not active, so a
// CLI backup captures what the GUI shows.

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
the backup envelope -- magic, format version, KDF record, nonce, and
ciphertext -- so no backed-up value is readable without the password or key
used to create it.

A password is stretched with Argon2id (t=3, m=64 MiB, p=4; PBKDF2-SHA256 when
the Go FIPS 140 module is enabled) under a random salt. The salt and the KDF
parameters are recorded in the envelope header, which is authenticated with
the ciphertext. Version 1 backups, keyed with an unsalted SHA-256 of the
password, are refused: re-create them with this release.

` + backupPasswordUsage,
}

// backupCreateCmd creates a new encrypted backup.
var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a backup of xkey data",
	Long: `Create an encrypted backup of xkey data. The backup includes trust
store certificates, OATH credentials, and static passwords read from the xkey
data directory ($XKEY_HOME/data, by default ~/.xkey/data).

If no password is supplied (--password-stdin or XKEY_BACKUP_PASSWORD), a
random 256-bit encryption key is generated and printed to stdout in hex
encoding. Store this key securely: without it the backup cannot be read.

The command fails rather than writing an empty file when every data store is
empty or unreachable.

Examples:
  xkey backup create
  xkey backup create --password-stdin < password.txt
  xkey backup create --output /tmp/my-backup.xkb
  XKEY_BACKUP_PASSWORD=... xkey backup create --oath-store /srv/xkey/oath.json`,
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
  xkey backup restore ~/.xkey/backups/backup-20250207.xkb --password-stdin < password.txt
  xkey backup restore backup.xkb --key-stdin < key.hex
  XKEY_BACKUP_KEY=aabbccdd... xkey backup restore backup.xkb`,
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
  xkey backup contents backup.xkb --password-stdin < password.txt
  xkey backup contents backup.xkb --key-stdin < key.hex
  XKEY_BACKUP_KEY=aabbccdd... xkey backup contents backup.xkb`,
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
	backupPasswordSource.addFlags(backupCreateCmd)
	addBackupStoreFlags(backupCreateCmd)
	addBarrierPasswordFlags(backupCreateCmd)

	// Restore flags
	backupPasswordSource.addFlags(backupRestoreCmd)
	backupKeySource.addFlags(backupRestoreCmd)
	addBackupStoreFlags(backupRestoreCmd)
	addBarrierPasswordFlags(backupRestoreCmd)

	// Contents flags
	backupPasswordSource.addFlags(backupContentsCmd)
	backupKeySource.addFlags(backupContentsCmd)
}

// addBackupStoreFlags registers the store-location overrides shared by the
// create and restore commands.
func addBackupStoreFlags(cmd *cobra.Command) {
	cmd.Flags().String("trust-store", "",
		"Trust store directory (default: {xkey-home}/data/trust)")
	cmd.Flags().String("oath-store", "",
		"OATH credential store file, bypassing the barrier "+
			"(default: the barrier-encrypted store when a barrier is initialized, "+
			"otherwise {xkey-home}/data/oath.json)")
	cmd.Flags().String("password-store", "",
		"Static password store directory (default: {xkey-home}/data/staticpw)")
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

	key, err := resolveSealingKey(cmd, ErrBackupCreateFailed)
	if err != nil {
		return err
	}
	defer key.Wipe()

	sources, err := resolveBackupSources(cmd, backupStorePathsFromFlags(cmd), true)
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

	if err := requireBackupFile(filePath); err != nil {
		return err
	}

	credential, err := resolveBackupCredential(cmd)
	if err != nil {
		return err
	}
	defer credential.wipe()

	encrypted, err := readEncryptedBackup(filePath)
	if err != nil {
		return err
	}

	key, err := credential.keyFor(encrypted)
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

	sources, err := resolveBackupSources(cmd, backupStorePathsFromFlags(cmd), false)
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

	if err := requireBackupFile(filePath); err != nil {
		return err
	}

	credential, err := resolveBackupCredential(cmd)
	if err != nil {
		return err
	}
	defer credential.wipe()

	encrypted, err := readEncryptedBackup(filePath)
	if err != nil {
		return err
	}

	key, err := credential.keyFor(encrypted)
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
//
// strict distinguishes a read (backup create, backup to-device) from a write
// (backup restore, backup from-device, device sync) run:
//
//   - strict=true: a source whose default location has never been written to
//     is reported in sources.skipped and left unopened rather than opened
//     (which would auto-create an empty store and silently report zero
//     entries, go-xkms#936); a source named explicitly with a flag that does
//     not exist is a hard ErrBackupSourceMissing failure, since the operator
//     asked to read a specific path.
//   - strict=false: every source is opened as before, auto-creating its
//     default or explicit location, because a write run always has somewhere
//     new to put its first entry.
//
// The OATH store is barrier-aware (go-xkms#134/#148): resolveOATHBackupStore
// opens it through the same --barrier-password / --barrier-password-file /
// XKEY_BARRIER_PASSWORD reach as `xkey oath` and `xkey device oath-sync`
// (resolveSecretStoreBackend, barrier_store.go), so a backup taken while the
// barrier is active reads the same ciphertext the GUI wrote instead of a
// stale or absent plaintext file. The trust store and password store do not
// have a barrier-backed CLI path yet, so they keep the original refusal:
// back up stale plaintext copies of those two, never.
func resolveBackupSources(cmd *cobra.Command, paths backupStorePaths, strict bool) (*backupSources, error) {
	dataDir, err := backupDataDir()
	if err != nil {
		return nil, err
	}

	// Trust store and password store: unchanged refusal. Back up a stale
	// plaintext copy of neither when their default location is
	// barrier-encrypted; an explicit override opts out of the barrier
	// entirely for that one store.
	if (paths.trust == "" || paths.passwords == "") && barrierRootKeyExists(dataDir) {
		return nil, ErrBackupBarrierEncrypted
	}

	sources := &backupSources{
		skipped: []backupSkippedSource{{Item: backup.ItemCAData, Reason: backupCASkipReason}},
	}

	trustPath := paths.trust
	var trustMissing bool
	if trustPath == "" {
		trustPath = filepath.Join(dataDir, trustDataSubdir)
		trustMissing, err = defaultSourceMissing(strict, backup.ItemTrustStore, trustPath)
	} else {
		err = requireExplicitSource(strict, backup.ItemTrustStore, trustPath)
	}
	if err != nil {
		sources.Close()
		return nil, err
	}
	if trustMissing {
		sources.skipped = append(sources.skipped, backupSkippedSource{
			Item: backup.ItemTrustStore, Reason: "no store found at " + trustPath,
		})
	} else {
		trustStore, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: trustPath})
		if err != nil {
			sources.Close()
			return nil, backupStoreError(backup.ItemTrustStore, trustPath, err)
		}
		sources.trust = &trustStoreAdapter{store: trustStore, path: trustPath}
	}

	oathStore, oathDisplayPath, oathMissing, err := resolveOATHBackupStore(cmd, dataDir, paths.oath, strict)
	if err != nil {
		sources.Close()
		return nil, err
	}
	if oathMissing {
		sources.skipped = append(sources.skipped, backupSkippedSource{
			Item: backup.ItemOATH, Reason: "no store found at " + oathDisplayPath,
		})
	} else {
		sources.oath = &oathStoreAdapter{store: oathStore, path: oathDisplayPath}
	}

	passwordPath := paths.passwords
	var passwordMissing bool
	if passwordPath == "" {
		passwordPath = filepath.Join(dataDir, passwordStoreFeature)
		passwordMissing, err = defaultSourceMissing(strict, backup.ItemPasswords, passwordPath)
	} else {
		err = requireExplicitSource(strict, backup.ItemPasswords, passwordPath)
	}
	if err != nil {
		sources.Close()
		return nil, err
	}
	if passwordMissing {
		sources.skipped = append(sources.skipped, backupSkippedSource{
			Item: backup.ItemPasswords, Reason: "no store found at " + passwordPath,
		})
	} else {
		passwordStore, err := openPasswordStore(passwordPath)
		if err != nil {
			sources.Close()
			return nil, backupStoreError(backup.ItemPasswords, passwordPath, err)
		}
		sources.passwords = &passwordStoreAdapter{store: passwordStore, path: passwordPath}
	}

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

// pathExists reports whether path names an existing file or directory. An
// error from the underlying stat other than "not found" (e.g. a parent
// component that is a regular file, ENOTDIR) is returned unchanged so the
// caller can report the real cause instead of treating it as "missing".
func pathExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// requireExplicitSource returns ErrBackupSourceMissing when strict (a read
// run) and the operator-supplied path for item does not exist: reading is
// never allowed to silently auto-create the store the operator explicitly
// named. In non-strict (write) mode, or when the path exists, it returns
// nil, and the caller proceeds to open (and, for a write run, possibly
// create) the store.
func requireExplicitSource(strict bool, item, path string) error {
	if !strict {
		return nil
	}
	exists, err := pathExists(path)
	if err != nil {
		return backupStoreError(item, path, err)
	}
	if !exists {
		return &DetailError{Err: ErrBackupSourceMissing, Detail: fmt.Sprintf(": %s (%s)", item, path)}
	}
	return nil
}

// defaultSourceMissing reports, in strict (read) mode, whether item's
// default location has never been written to, so the caller can skip
// opening it and report it as missing instead of auto-creating an empty
// store and silently backing up nothing from it (go-xkms#936). In
// non-strict (write) mode it always returns false: the destination is
// created on first write, which is the expected outcome for a restore into
// a fresh store.
func defaultSourceMissing(strict bool, item, path string) (bool, error) {
	if !strict {
		return false, nil
	}
	exists, err := pathExists(path)
	if err != nil {
		return false, backupStoreError(item, path, err)
	}
	return !exists, nil
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
	summary := "no data stores opened"
	if len(parts) > 0 {
		summary = "no entries in " + strings.Join(parts, ", ")
	}
	for _, skip := range s.skipped {
		summary += "; " + skip.Item + " skipped: " + skip.Reason
	}
	return summary
}

// Close releases every opened store. Its signature is func() -- every call
// site is a defer or an unconditional teardown call with no error path of
// its own to report through -- so a failure to close a store is logged
// rather than dropped silently.
func (s *backupSources) Close() {
	if s == nil {
		return
	}
	if s.trust != nil {
		if err := s.trust.Close(); err != nil {
			slog.Default().Warn("backup: failed to close trust store", "error", err)
		}
	}
	if s.oath != nil {
		if err := s.oath.Close(); err != nil {
			slog.Default().Warn("backup: failed to close oath store", "error", err)
		}
	}
	if s.passwords != nil {
		if err := s.passwords.Close(); err != nil {
			slog.Default().Warn("backup: failed to close password store", "error", err)
		}
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
// stores, resolved through the CLI's single data-dir chain (resolveDataDir)
// so XKEY_HOME, portable mode, XKEY_DATA_DIR and `data_dir` all apply —
// the same resolution the root command performs, without a private
// fallback that could drift from it.
func backupDataDir() (string, error) {
	dataDir, err := resolveDataDir("")
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrBackupStoreUnavailable, Cause: err}
	}
	return dataDir, nil
}

// resolveOATHBackupStore opens the OATH store a backup create/restore run
// reads or writes. An explicit --oath-store path always selects the plain
// file at that path: the operator asked for a specific file, so the barrier
// decision does not apply, matching how xkey oath's --store override
// behaves. The default location goes through resolveSecretStoreBackend
// (barrier_store.go), the same "is the barrier initialised? open it, or
// warn" decision xkey oath and xkey device oath-sync use, so a backup taken
// with a barrier active reads the same ciphertext the GUI wrote instead of a
// stale or absent plaintext file.
//
// strict carries the same read/write meaning as resolveBackupSources: in
// strict (read) mode an explicit --oath-store path that does not exist is a
// hard error, and a default oathStoreFilename that has never been written to
// is reported back as missing (missing=true, store=nil) instead of being
// auto-created and silently backed up as empty. The barrier-backed path never
// reports missing: whether the barrier itself is reachable is
// resolveSecretStoreBackend's decision, not an existence check on a file.
//
// Returns the opened store (nil when missing) and the path or barrier
// location to use in error, summary, and skipped-source messages.
func resolveOATHBackupStore(cmd *cobra.Command, dataDir, oathPath string, strict bool) (store oath.Store, path string, missing bool, err error) {
	if oathPath != "" {
		if err := requireExplicitSource(strict, backup.ItemOATH, oathPath); err != nil {
			return nil, oathPath, false, err
		}
		store, err := oath.NewFileStore(oathPath)
		if err != nil {
			return nil, oathPath, false, backupStoreError(backup.ItemOATH, oathPath, err)
		}
		return store, oathPath, false, nil
	}

	defaultPath := filepath.Join(dataDir, oathStoreFilename)

	backend, opened, err := resolveSecretStoreBackend(cmd, dataDir, "OATH", slog.Default())
	if err != nil {
		return nil, defaultPath, false, backupStoreError(backup.ItemOATH, defaultPath, err)
	}
	if opened {
		store, err := oath.NewBackendStore(backend, "oath/")
		if err != nil {
			return nil, "barrier:oath/", false, backupStoreError(backup.ItemOATH, "barrier:oath/", err)
		}
		return store, "barrier:oath/", false, nil
	}

	oathMissing, err := defaultSourceMissing(strict, backup.ItemOATH, defaultPath)
	if err != nil {
		return nil, defaultPath, false, err
	}
	if oathMissing {
		return nil, defaultPath, true, nil
	}

	store, err = oath.NewFileStore(defaultPath)
	if err != nil {
		return nil, defaultPath, false, backupStoreError(backup.ItemOATH, defaultPath, err)
	}
	return store, defaultPath, false, nil
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
// service's reader and writer contracts. store is the oath.Store interface
// rather than a concrete type because it may be barrier-backed
// (oath.BackendStore) or a plain file (oath.FileStore) depending on how
// resolveOATHBackupStore opened it.
type oathStoreAdapter struct {
	store oath.Store
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
		info, convErr := oathCredentialToInfo(cred)
		if convErr != nil {
			return nil, convErr
		}
		out = append(out, info)
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
	return oathCredentialToInfo(cred)
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
// form shared by the backup and sync services. The secret is adopted into
// protected memory; the returned error is backup.ErrProtectedMemory
// (wrapped) when that allocation fails.
func oathCredentialToInfo(cred *oath.Credential) (*backup.OATHCredentialInfo, error) {
	info := &backup.OATHCredentialInfo{
		ID:          cred.ID,
		Name:        cred.Name,
		Issuer:      cred.Issuer,
		AccountName: cred.AccountName,
		Type:        cred.Type,
		Algorithm:   cred.Algorithm,
		Digits:      cred.Digits,
		Period:      cred.Period,
		Counter:     oathCounterToInt64(cred.Counter),
	}
	if err := info.SetSecret(cred.SecretString()); err != nil {
		return nil, err
	}
	return info, nil
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
	if err := cred.SetSecret(info.SecretString()); err != nil {
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
		info, convErr := passwordToInfo(pw)
		if convErr != nil {
			return nil, convErr
		}
		out = append(out, info)
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
	return passwordToInfo(pw)
}

// Add writes one restored static password back to the store. The store
// derives the entry ID from the name and folder, so restoring preserves
// identity without carrying the stored ID across.
func (a *passwordStoreAdapter) Add(info *backup.PasswordInfo) error {
	return a.store.Add(&xkms.StaticPassword{
		Name:       info.Name,
		Title:      info.Title,
		Username:   info.Username,
		Password:   info.PasswordString(),
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
		Password:   info.PasswordString(),
		URL:        info.URL,
		Notes:      info.Notes,
		FolderPath: info.FolderPath,
	})
}

// passwordToInfo converts a stored password to the service-facing form
// shared by the backup and sync services. The password is adopted into
// protected memory; the returned error is backup.ErrProtectedMemory
// (wrapped) when that allocation fails.
func passwordToInfo(pw *xkms.StaticPassword) (*backup.PasswordInfo, error) {
	info := &backup.PasswordInfo{
		ID:         pw.ID,
		Name:       pw.Name,
		Title:      pw.Title,
		Username:   pw.Username,
		URL:        pw.URL,
		Notes:      pw.Notes,
		FolderPath: pw.FolderPath,
	}
	if err := info.SetPassword(pw.Password); err != nil {
		return nil, err
	}
	return info, nil
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
	{backup.ErrLegacyBackupFormat, "unsalted version 1 backup format is no longer supported; re-create the backup"},
	{backup.ErrVersionMismatch, "unsupported backup format version"},
	{backup.ErrInvalidBackup, "file is not an xkey backup envelope"},
	{backup.ErrNotPasswordSealed, "backup was sealed with a raw key; supply it with --key-stdin or XKEY_BACKUP_KEY"},
	{backup.ErrKeyDerivationFailed, "the backup's key-derivation record is invalid or has been altered"},
}

// BackupDecryptError is an ErrBackupDecryptFailed carrying the
// operator-facing reason and the backup service error it was classified
// from. errors.Is matches both ErrBackupDecryptFailed and the cause, so a
// caller can still tell, say, a refused legacy file from a wrong password.
type BackupDecryptError struct {
	Reason string
	Cause  error
}

// Error implements the error interface.
func (e *BackupDecryptError) Error() string {
	return ErrBackupDecryptFailed.Error() + ": " + e.Reason
}

// Unwrap returns ErrBackupDecryptFailed and the cause.
func (e *BackupDecryptError) Unwrap() []error {
	return []error{ErrBackupDecryptFailed, e.Cause}
}

// classifyBackupDecryptError converts a backup service decryption failure
// into an ErrBackupDecryptFailed-rooted error naming the specific reason.
func classifyBackupDecryptError(err error) error {
	for _, candidate := range backupDecryptReasons {
		if errors.Is(err, candidate.sentinel) {
			return &BackupDecryptError{Reason: candidate.reason, Cause: err}
		}
	}
	return &SentinelCauseError{Sentinel: ErrBackupDecryptFailed, Cause: err}
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

// backupsDirName is the backup directory under the xKey home.
const backupsDirName = "backups"

// getBackupDir returns the default backup directory, backups/ under the
// resolved xKey home, so a backup lands inside the home that XKEY_HOME or
// portable mode selected and not under $HOME regardless (#442). A home
// that cannot be resolved is an error, never a silent fallback.
func getBackupDir() (string, error) {
	home, err := xhome.Resolve()
	if err != nil {
		return "", err
	}
	return filepath.Join(home.Root, backupsDirName), nil
}

// backupPasswordSource is the one way a backup password enters the CLI. It
// follows the PIN convention (pin_input.go): standard input or the
// environment, never a value flag -- a "--password" value is visible to
// every other process on the host via 'ps' (go-xkms#1202).
var backupPasswordSource = pinSource{
	label:      "backup password",
	stdinFlag:  "password-stdin",
	envVar:     "XKEY_BACKUP_PASSWORD",
	stdinEmpty: ErrBackupPasswordStdinEmpty,
	stdinRead:  ErrBackupPasswordStdinRead,
}

// backupPasswordUsage is the operator-facing description of the two backup
// password sources, embedded in the backup command help.
const backupPasswordUsage = `The backup password may be supplied two ways, in precedence order:

  --password-stdin       read the password from standard input (preferred:
                         it keeps the password out of the process list and
                         the shell history)
  XKEY_BACKUP_PASSWORD   environment variable

There is no "--password" value flag: a value on the command line is visible
to every other process on the host via 'ps'.

"backup restore" and "backup contents" accept a raw key the same two ways
instead of a password:

  --key-stdin             read the hex-encoded key from standard input
  XKEY_BACKUP_KEY         environment variable

There is no "--key" value flag either, for the same reason.`

// backupKeySource is the one way a raw hex-encoded backup key enters the
// CLI, for "backup restore", "backup contents" and "backup from-device". It
// follows the PIN convention (pin_input.go): standard input or the
// environment, never a value flag -- a "--key" value is visible to every
// other process on the host via 'ps' (go-xkms#1209).
var backupKeySource = pinSource{
	label:      "backup key",
	stdinFlag:  "key-stdin",
	envVar:     "XKEY_BACKUP_KEY",
	stdinEmpty: ErrBackupKeyStdinEmpty,
	stdinRead:  ErrBackupKeyStdinRead,
}

// resolveSealingKey returns the key a new backup is sealed with: derived
// from the backup password when one is supplied, otherwise generated at
// random and printed so the operator can keep it. The password is wiped
// once the key is derived. sentinel names the operation a failure belongs
// to. The caller wipes the returned key.
func resolveSealingKey(cmd *cobra.Command, sentinel error) (*backup.Key, error) {
	out := cmd.OutOrStdout()
	password, err := backupPasswordSource.resolveBytes(cmd)
	if err != nil {
		return nil, err
	}
	defer enclave.Wipe(password)

	if len(password) > 0 {
		key, err := backup.NewPasswordKey(password)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: sentinel, Cause: err}
		}
		_, _ = fmt.Fprintln(out, "Using password-derived encryption key (Argon2id, salted).")
		return key, nil
	}

	key, err := backup.GenerateKey()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: sentinel, Cause: err}
	}
	_, _ = fmt.Fprintf(out, "Generated encryption key (save this):\n  %s\n\n", hex.EncodeToString(key.Bytes()))
	return key, nil
}

// backupCredential is what the operator supplied to open a backup: a
// password, whose key can only be derived once the envelope's KDF record has
// been read, or a raw key. Exactly one is set.
type backupCredential struct {
	password *secure.Buffer
	key      *backup.Key
}

// resolveBackupCredential resolves the credential for opening a backup,
// before the envelope is read, so a missing credential fails fast. The
// backup password takes precedence over --key. The caller calls wipe.
func resolveBackupCredential(cmd *cobra.Command) (*backupCredential, error) {
	password, err := backupPasswordSource.resolveBytes(cmd)
	if err != nil {
		return nil, err
	}
	if len(password) > 0 {
		// NewBufferFromBytes adopts password into protected memory and
		// wipes the source slice.
		protected, err := secure.NewBufferFromBytes(password)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrBackupDecryptFailed, Cause: err}
		}
		return &backupCredential{password: protected}, nil
	}

	keyHex, err := backupKeySource.resolveBytes(cmd)
	if err != nil {
		return nil, err
	}
	if len(keyHex) == 0 {
		return nil, ErrBackupKeyRequired
	}
	defer enclave.Wipe(keyHex)
	material, err := hex.DecodeString(string(keyHex))
	if err != nil {
		return nil, &DetailError{Err: ErrBackupDecryptFailed, Detail: fmt.Sprintf(": invalid hex key: %v", err)}
	}
	defer enclave.Wipe(material)
	key, err := backup.NewRawKey(material)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrBackupDecryptFailed, Cause: err}
	}
	return &backupCredential{key: key}, nil
}

// keyFor returns the key that opens encrypted. A password is stretched with
// the KDF record in the envelope header; the derived key is owned by the
// credential and wiped with it.
func (c *backupCredential) keyFor(encrypted *backup.EncryptedBackup) (*backup.Key, error) {
	if c.key != nil {
		return c.key, nil
	}
	key, err := encrypted.PasswordKey(c.password.Bytes())
	if err != nil {
		return nil, classifyBackupDecryptError(err)
	}
	c.key = key
	return key, nil
}

// wipe zeroes the password and key the credential holds.
func (c *backupCredential) wipe() {
	c.password.Destroy()
	c.key.Wipe()
}

// getHostname returns the system hostname or "unknown" on error.
func getHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
