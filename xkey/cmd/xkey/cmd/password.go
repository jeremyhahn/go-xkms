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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/spf13/cobra"
)

// passwordStoreFeature is the featureDataDir (datadir.go) subdirectory the
// static password store defaults to when --store is not set: <xkey data
// dir>/staticpw, resolved through the CLI's shared data-directory chain
// (XKEY_HOME, XKEY_DATA_DIR, config data_dir, or ~/.xkey/data) rather than a
// cwd-relative default (go-xkms#929).
const passwordStoreFeature = "staticpw"

// Valid access modes for the password store.
const (
	AccessModePINPerOperation = "pin_per_operation"
	AccessModeSessionBased    = "session_based"
)

// Password command errors.
var (
	ErrPasswordMissingName       = errors.New("password: --name is required")
	ErrPasswordMissingSource     = errors.New("password: --password or --generate is required")
	ErrPasswordMutuallyExclusive = errors.New("password: --password and --generate are mutually exclusive")
	ErrPasswordMissingRemoveArg  = errors.New("password: specify password name to remove")
	ErrPasswordMissingGetArg     = errors.New("password: specify password name to retrieve")
	ErrPasswordMissingTypeArg    = errors.New("password: specify password name to type")
	ErrPasswordStoreOpenFailed   = errors.New("password: failed to open store")
	ErrPasswordAddFailed         = errors.New("password: failed to add password")
	ErrPasswordListFailed        = errors.New("password: failed to list passwords")
	ErrPasswordGetFailed         = errors.New("password: failed to get password")
	ErrPasswordDeleteFailed      = errors.New("password: failed to delete password")
	ErrPasswordGenerateFailed    = errors.New("password: failed to generate password")
	ErrPasswordNotFound          = errors.New("password: password not found")
	ErrPasswordTypeFailed        = errors.New("password: type operation failed")
	ErrPasswordUnlockFailed      = errors.New("password: unlock operation failed")
	ErrPasswordLockFailed        = errors.New("password: lock operation failed")
	ErrPasswordStatusFailed      = errors.New("password: status operation failed")
	ErrPasswordAccessModeFailed  = errors.New("password: access-mode operation failed")
	ErrPasswordInvalidMode       = errors.New("password: --mode must be pin_per_operation or session_based")
	ErrPasswordMissingMode       = errors.New("password: --mode is required")
	ErrPasswordMissingPIN        = errors.New("password: user PIN is required")
	ErrPasswordConnectFailed     = errors.New("password: failed to connect to xkmsd")

	// ErrPasswordValuesNotOverIPC indicates --show-passwords was requested
	// against a running daemon. Password values are never returned over the
	// IPC socket: its only authentication is filesystem permission, so a
	// verb that hands out secrets there is reachable by every process
	// running as the same user.
	ErrPasswordValuesNotOverIPC = errors.New(
		"password: password values are never returned over the daemon IPC socket; " +
			"re-run with --source disk to read the on-disk store directly")
)

// PasswordStoreClientService defines the subset of the transport.PasswordService
// interface needed by the password store session management commands. This enables
// dependency injection for testing.
type PasswordStoreClientService interface {
	Connect(ctx context.Context) error
	Close() error
	PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error
	PasswordStoreLock(ctx context.Context) error
	PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error)
	PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error
}

// passwordClientFactory is the function used to create transport clients for
// password store session management commands. It is a package-level variable
// to allow tests to inject mock clients.
var passwordClientFactory = defaultPasswordClientFactory

// defaultPasswordClientFactory creates a real transport client for the
// password-store session commands, resolving the xkmsd endpoint through the
// shared helper (see xkmsd_client.go) so every xkey command group honors the
// same --xkmsd-url / XKMSD_URL / config precedence, scheme dispatch, token
// and TLS-CA handling.
func defaultPasswordClientFactory() (PasswordStoreClientService, error) {
	client, err := newXKMSdClient(PasswordCmd)
	if err != nil {
		return nil, &PasswordStoreError{Operation: "connect", Message: err.Error()}
	}
	return client, nil
}

// PasswordCmd represents the password parent command.
var PasswordCmd = &cobra.Command{
	Use:   "password",
	Short: "Static password management",
	Long: `Static password management.

Store, retrieve, and generate static passwords in a secure file-backed store.
This provides YubiKey-style static password storage for credentials that cannot
use one-time passwords or certificate-based authentication.

The store belongs to whoever holds the barrier: the running daemon when one is
running, the on-disk store directory otherwise. 'list' and 'status' consult
both in that order and report which answered.

A remote xkmsd server owns the session verbs — 'unlock', 'lock' and
'access-mode' — and the access mode they configure; those require
--xkmsd-url. It is not where the local store lives.

Examples:
  # Add a password manually
  xkey password add --name "DatabaseProd" --password "s3cretP@ss!"

  # Add a password with metadata
  xkey password add --name "DatabaseProd" --password "s3cretP@ss!" \
    --title "Production DB" --username "admin" --url "https://db.example.com"

  # Generate a random password
  xkey password add --name "ServiceAccount" --generate --length 64

  # Generate an alphanumeric password
  xkey password add --name "WiFi" --generate --charset alphanumeric

  # List all stored passwords
  xkey password list

  # Show passwords in the list output
  xkey password list --show-passwords

  # Retrieve a password by name (outputs just the password for piping)
  xkey password get "DatabaseProd"

  # Type a password via virtual keyboard
  xkey password type "DatabaseProd"

  # Remove a password
  xkey password remove "DatabaseProd"

  # Unlock the password store (session-based access mode)
  xkey password unlock --pin "1234"

  # Lock the password store
  xkey password lock

  # Show password store status
  xkey password status

  # Switch access mode
  xkey password access-mode --mode session_based`,
}

// passwordAddCmd adds a new static password.
var passwordAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new static password",
	Long: `Add a new static password to the store.

You can provide the password directly with --password, or generate a
cryptographically random password with --generate. These options are
mutually exclusive.

Generated passwords use crypto/rand for uniform distribution. The --charset
flag controls the character set: "all" includes letters, digits, and symbols;
"alphanumeric" includes only letters and digits.

Optional metadata flags --title, --username, and --url attach display and
autofill information to the entry. The --url value is used by the browser
extension for domain-based credential matching.

Examples:
  # Store an existing password
  xkey password add --name "DatabaseProd" --password "s3cretP@ss!"

  # Store with full metadata for browser autofill
  xkey password add --name "GitHubWork" --password "tok_abc123" \
    --title "GitHub (Work)" --username "jdoe" --url "https://github.com"

  # Generate a 32-character password (default length)
  xkey password add --name "ServiceAccount" --generate

  # Generate a 64-character alphanumeric password with notes
  xkey password add --name "WiFi" --generate --length 64 --charset alphanumeric --notes "Office WiFi"

  # Use a custom store path
  xkey password add --name "Backup" --password "p@ss" --store /tmp/passwords`,
	RunE: runPasswordAdd,
}

// passwordListCmd lists all stored passwords.
var passwordListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all passwords",
	Long: `List all static passwords in the store.

The store lives with whoever holds the barrier: the running daemon when one
is running, the on-disk store directory otherwise. Both are consulted in that
order and the reported source names which answered.

Password values are masked. --show-passwords reveals them, and requires
--source disk: values are never returned over the daemon IPC socket.

Examples:
  # List all passwords (daemon when running, store directory otherwise)
  xkey password list

  # Show password values from the on-disk store
  xkey password list --source disk --show-passwords

  # Use a custom store path
  xkey password list --source disk --store /tmp/passwords`,
	RunE: runPasswordList,
}

// passwordGetCmd retrieves a password by name.
var passwordGetCmd = &cobra.Command{
	Use:     "get [name]",
	Aliases: []string{"show"},
	Short:   "Get a password by name",
	Long: `Retrieve a static password by name.

Outputs only the password value to stdout, making it suitable for piping
to other commands or clipboard utilities.

Examples:
  # Get a password
  xkey password get "DatabaseProd"

  # Pipe to clipboard (Linux)
  xkey password get "DatabaseProd" | xclip -selection clipboard

  # Use in a script
  DB_PASS=$(xkey password get "DatabaseProd")`,
	RunE: runPasswordGet,
}

// passwordRemoveCmd removes one or more passwords.
var passwordRemoveCmd = &cobra.Command{
	Use:     "remove [name...]",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove a password",
	Long: `Remove one or more static passwords from the store.

By default, you will be prompted to confirm each removal.
Use --force to skip confirmation prompts.

Examples:
  # Remove a password (with confirmation)
  xkey password remove "DatabaseProd"

  # Remove without confirmation
  xkey password remove --force "DatabaseProd"

  # Remove multiple passwords
  xkey password remove "DatabaseProd" "ServiceAccount" "WiFi"`,
	RunE: runPasswordRemove,
}

// passwordTypeCmd types a stored password via the virtual USB keyboard by
// connecting to the running xkey daemon over IPC.
var passwordTypeCmd = &cobra.Command{
	Use:     "type [name]",
	Aliases: []string{"emit"},
	Short:   "Type a password via virtual keyboard",
	Long: `Type a stored password via the virtual USB keyboard.

This connects to the running xkey daemon and instructs it to type the
specified password using the virtual HID keyboard device. The keystrokes
appear as if a physical keyboard typed them.

Requires the xkey daemon to be running with FIDO2 mode active.

Examples:
  # Type a password
  xkey password type "DatabaseProd"

  # Custom socket path
  xkey password type "DatabaseProd" --socket /tmp/xkey.sock`,
	RunE: runPasswordType,
}

// passwordUnlockCmd unlocks the password store session.
var passwordUnlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock the password store",
	Long: `Unlock the password store by providing the user PIN.

In session_based access mode, unlocking the store allows subsequent
password operations without requiring the PIN for each operation.
The store remains unlocked until explicitly locked or the session expires.

In pin_per_operation mode, this command has no effect since each
operation requires its own PIN.

This acts on an xkmsd server's session and requires --xkmsd-url.

Examples:
  # Unlock with PIN flag
  xkey password unlock --pin "1234"

  # Unlock with interactive PIN prompt
  xkey password unlock`,
	RunE: runPasswordUnlock,
}

// passwordLockCmd locks the password store session.
var passwordLockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the password store",
	Long: `Lock the password store, ending the current session.

In session_based access mode, locking the store requires the PIN
to be provided again for subsequent password operations.

This acts on an xkmsd server's session and requires --xkmsd-url.

Examples:
  # Lock the password store
  xkey password lock`,
	RunE: runPasswordLock,
}

// passwordStatusCmd shows the password store status.
var passwordStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show password store status",
	Long: `Show the current status of the password store.

Displays where the store lives, whether it is readable, and how many entries
it holds. The same source order as 'xkey password list' applies: the running
daemon first, the on-disk store directory otherwise. Neither requires an
xkmsd server.

Access mode and auto-unseal are properties of an xkmsd session server, which
also owns 'password unlock', 'password lock' and 'password access-mode'.
Pass --source xkmsd to read them from a configured server.

Examples:
  # Show password store status
  xkey password status

  # Read the status from a configured xkmsd server
  xkey password status --source xkmsd --xkmsd-url https://xkms.example.com`,
	RunE: runPasswordStatus,
}

// passwordAccessModeCmd switches the password store access mode.
var passwordAccessModeCmd = &cobra.Command{
	Use:   "access-mode",
	Short: "Set password store access mode",
	Long: `Set the password store access mode.

Two modes are supported:
  pin_per_operation  Requires the user PIN for each decrypt operation.
                     This is the most secure mode.
  session_based      A single unlock provides access until the store is
                     explicitly locked. More convenient for batch operations.

This acts on an xkmsd server's session and requires --xkmsd-url.

Examples:
  # Switch to session-based mode
  xkey password access-mode --mode session_based

  # Switch to per-operation PIN mode
  xkey password access-mode --mode pin_per_operation`,
	RunE: runPasswordAccessMode,
}

// runPasswordAdd executes the password add command.
func runPasswordAdd(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	name, _ := cmd.Flags().GetString("name")
	password, _ := cmd.Flags().GetString("password")
	generate, err := commandFlagBool(cmd, "generate")
	if err != nil {
		return err
	}
	length, _ := cmd.Flags().GetInt("length")
	charset, _ := cmd.Flags().GetString("charset")
	notes, _ := cmd.Flags().GetString("notes")
	title, _ := cmd.Flags().GetString("title")
	username, _ := cmd.Flags().GetString("username")
	url, _ := cmd.Flags().GetString("url")
	storePath, err := passwordStorePath(cmd)
	if err != nil {
		return err
	}

	if name == "" {
		return ErrPasswordMissingName
	}

	hasPassword := password != ""
	if !hasPassword && !generate {
		return ErrPasswordMissingSource
	}
	if hasPassword && generate {
		return ErrPasswordMutuallyExclusive
	}

	store, err := openPasswordStore(storePath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if generate {
		password, err = xkms.GenerateStaticPassword(length, charset)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrPasswordGenerateFailed, Cause: err}
		}
	}

	pw := &xkms.StaticPassword{
		Name:     name,
		Title:    title,
		Username: username,
		Password: password,
		URL:      url,
		Notes:    notes,
	}

	if err := pw.Validate(); err != nil {
		return &SentinelCauseError{Sentinel: ErrPasswordAddFailed, Cause: err}
	}

	if err := store.Add(pw); err != nil {
		return &SentinelCauseError{Sentinel: ErrPasswordAddFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Added password: %s\n", pw.Name)
	if generate {
		_, _ = fmt.Fprintf(out, "Generated: %s\n", password)
	}

	return nil
}

// runPasswordList executes the password list command. It asks the running
// daemon first: the daemon holds the barrier, so it is the only authority
// that can see a barrier-backed store. Reading the store directory in this
// process reports it empty, which is what made `password list` claim "No
// passwords found" on a device whose store held entries.
func runPasswordList(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	showPasswords, err := commandFlagBool(cmd, "show-passwords")
	if err != nil {
		return err
	}

	selection, err := stateSourceSelection(cmd, stateSelectorsLocal)
	if err != nil {
		return err
	}

	entries, src, err := resolvePasswordList(cmd, selection, showPasswords)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		_, _ = fmt.Fprintln(out, "No passwords found.")
		_, _ = fmt.Fprintln(out)
		writeSource(out, src)
		return nil
	}

	_, _ = fmt.Fprintf(out, "Static Passwords (%d):\n\n", len(entries))

	for _, entry := range entries {
		_, _ = fmt.Fprintf(out, "  Name:       %s\n", entry.Name)
		if entry.Title != "" {
			_, _ = fmt.Fprintf(out, "  Title:      %s\n", entry.Title)
		}
		if entry.Username != "" {
			_, _ = fmt.Fprintf(out, "  Username:   %s\n", entry.Username)
		}
		if showPasswords {
			_, _ = fmt.Fprint(out, "  Password:   ")
			writePasswordValue(out, entry.Password)
			_, _ = fmt.Fprintln(out)
		} else {
			_, _ = fmt.Fprintf(out, "  Password:   ********\n")
		}
		entry.Password.Destroy()
		if entry.URL != "" {
			_, _ = fmt.Fprintf(out, "  URL:        %s\n", entry.URL)
		}
		if entry.Notes != "" {
			_, _ = fmt.Fprintf(out, "  Notes:      %s\n", entry.Notes)
		}
		if entry.CreatedAt != "" {
			_, _ = fmt.Fprintf(out, "  Created:    %s\n", entry.CreatedAt)
		}
		if entry.UpdatedAt != "" {
			_, _ = fmt.Fprintf(out, "  Updated:    %s\n", entry.UpdatedAt)
		}
		_, _ = fmt.Fprintln(out)
	}

	writeSource(out, src)

	return nil
}

// passwordListEntry is the CLI-facing view of one stored password. Password
// is populated only on the on-disk path; the daemon never sends values. A
// nil Password means no value is available for this entry.
type passwordListEntry struct {
	Name      string
	Title     string
	Username  string
	Password  *secure.Secret
	URL       string
	Notes     string
	CreatedAt string
	UpdatedAt string
}

// writePasswordValue writes secret's plaintext directly to w, borrowed from
// protected memory for the duration of the write rather than materialized
// into a Go string via a %s verb. A nil secret writes nothing. A failure to
// open or read the secret writes a bracketed marker instead of leaving the
// "Password:" label with nothing after it, which would otherwise be
// indistinguishable from a genuinely empty stored password.
func writePasswordValue(w io.Writer, secret *secure.Secret) {
	if secret == nil {
		return
	}
	buf, err := secret.Open()
	if err != nil {
		_, _ = fmt.Fprintf(w, "<error: %v>", err)
		return
	}
	defer buf.Destroy()
	if err := buf.WithBytes(func(b []byte) error {
		_, werr := w.Write(b)
		return werr
	}); err != nil {
		_, _ = fmt.Fprintf(w, "<error: %v>", err)
	}
}

// resolvePasswordList asks the daemon first and reads the on-disk store only
// when no daemon can answer, returning the labelled source alongside the
// entries.
func resolvePasswordList(cmd *cobra.Command, selection string, showPasswords bool) ([]passwordListEntry, stateSource, error) {
	list, socketPath, answered, reason, err := askDaemon(cmd, selection,
		func(client *ipc.Client) (*ipc.PasswordListResult, error) {
			return client.StatePasswordList()
		})
	if err != nil {
		return nil, stateSource{}, err
	}
	if answered {
		if showPasswords {
			return nil, stateSource{}, ErrPasswordValuesNotOverIPC
		}
		entries := make([]passwordListEntry, 0, len(list.Entries))
		for _, info := range list.Entries {
			entries = append(entries, passwordListEntry{
				Name:      info.Name,
				Title:     info.Title,
				Username:  info.Username,
				URL:       info.URL,
				CreatedAt: info.CreatedAt,
				UpdatedAt: info.UpdatedAt,
			})
		}
		return entries, daemonSource(socketPath), nil
	}

	entries, storePath, err := readPasswordListFromDisk(cmd)
	if err != nil {
		return nil, stateSource{}, err
	}
	return entries, diskSource(storePath, reason), nil
}

// readPasswordListFromDisk reads the on-disk static password store. It is
// the correct authority when no daemon holds the barrier, and the only path
// that can reveal password values.
func readPasswordListFromDisk(cmd *cobra.Command) (_ []passwordListEntry, _ string, err error) {
	storePath, err := passwordStorePath(cmd)
	if err != nil {
		return nil, "", err
	}

	store, err := openPasswordStore(storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storePath, nil
		}
		return nil, storePath, err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	passwords, err := store.List()
	if err != nil {
		return nil, storePath, &SentinelCauseError{Sentinel: ErrPasswordListFailed, Cause: err}
	}

	entries := make([]passwordListEntry, 0, len(passwords))
	for _, pw := range passwords {
		entry := passwordListEntry{
			Name:      pw.Name,
			Title:     pw.Title,
			Username:  pw.Username,
			URL:       pw.URL,
			Notes:     pw.Notes,
			CreatedAt: pw.CreatedAt.Format(passwordTimeLayout),
			UpdatedAt: pw.UpdatedAt.Format(passwordTimeLayout),
		}
		if pw.Password != "" {
			secret, secretErr := secure.NewSecret([]byte(pw.Password))
			if secretErr != nil {
				return nil, storePath, &SentinelCauseError{Sentinel: ErrPasswordListFailed, Cause: secretErr}
			}
			entry.Password = secret
		}
		entries = append(entries, entry)
	}
	return entries, storePath, nil
}

// passwordTimeLayout is the timestamp format used in password listings.
const passwordTimeLayout = "2006-01-02 15:04:05"

// passwordStorePath returns the on-disk store path a command should use: the
// --store flag when the operator set one, otherwise the resolved
// passwordStoreFeature default (see its doc comment).
func passwordStorePath(cmd *cobra.Command) (string, error) {
	if path := strings.TrimSpace(commandFlagString(cmd, "store")); path != "" {
		return path, nil
	}
	return featureDataDir(passwordStoreFeature)
}

// runPasswordGet executes the password get command.
func runPasswordGet(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	storePath, err := passwordStorePath(cmd)
	if err != nil {
		return err
	}

	if len(args) == 0 {
		return ErrPasswordMissingGetArg
	}

	store, err := openPasswordStore(storePath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	pw, err := store.Get(args[0])
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPasswordGetFailed, Cause: err}
	}

	_, _ = fmt.Fprint(out, pw.Password)
	return nil
}

// runPasswordRemove executes the password remove command.
func runPasswordRemove(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	storePath, err := passwordStorePath(cmd)
	if err != nil {
		return err
	}
	force, err := commandFlagBool(cmd, "force")
	if err != nil {
		return err
	}

	if len(args) == 0 {
		return ErrPasswordMissingRemoveArg
	}

	store, err := openPasswordStore(storePath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	reader := bufio.NewReader(os.Stdin)

	for _, name := range args {
		pw, err := store.Get(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}

		if !force {
			_, _ = fmt.Fprintf(out, "Remove password '%s'? [y/N]: ", pw.Name)
			confirm, readErr := reader.ReadString('\n')
			if readErr != nil {
				fmt.Fprintf(os.Stderr, "  %s: failed to read input\n", name)
				continue
			}
			confirm = strings.TrimSpace(strings.ToLower(confirm))
			if confirm != "y" && confirm != "yes" {
				_, _ = fmt.Fprintf(out, "Skipped %s\n", pw.Name)
				continue
			}
		}

		if err := store.Delete(pw.ID); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}

		_, _ = fmt.Fprintf(out, "Removed: %s\n", pw.Name)
	}

	return nil
}

// runPasswordType executes the password type command. It connects to the
// running xkey daemon and instructs it to type the named password via
// the virtual HID keyboard.
func runPasswordType(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	if len(args) == 0 {
		return ErrPasswordMissingTypeArg
	}

	socketPath := resolvedSocketPath(cmd)

	client := ipc.NewClient(socketPath)
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	resp, err := client.TypePassword(args[0])
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			return ErrTouchDaemonNotRunning
		}
		return &SentinelCauseError{Sentinel: ErrPasswordTypeFailed, Cause: err}
	}

	if resp.Status == ipc.StatusError {
		return &DetailError{Err: ErrPasswordTypeFailed, Detail: fmt.Sprintf(": %s", resp.Error)}
	}

	_, _ = fmt.Fprintf(out, "Typed password: %s\n", args[0])
	return nil
}

// runPasswordUnlock executes the password unlock command.
func runPasswordUnlock(cmd *cobra.Command, args []string) (err error) {
	pin, _ := cmd.Flags().GetString("pin")

	if pin == "" {
		return ErrPasswordMissingPIN
	}

	client, err := connectPasswordStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()
	req := &transport.PasswordStoreUnlockRequest{
		UserPIN: pin,
	}

	if err := client.PasswordStoreUnlock(ctx, req); err != nil {
		return &SentinelCauseError{Sentinel: ErrPasswordUnlockFailed, Cause: err}
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Password store unlocked.")
	return nil
}

// runPasswordLock executes the password lock command.
func runPasswordLock(cmd *cobra.Command, args []string) (err error) {
	client, err := connectPasswordStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()

	if err := client.PasswordStoreLock(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrPasswordLockFailed, Cause: err}
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Password store locked.")
	return nil
}

// passwordStatusInfo is the CLI-facing password store status.
type passwordStatusInfo struct {
	Available     bool
	Locked        bool
	Backend       string
	AccessMode    string
	AutoUnsealed  bool
	PasswordCount int
}

// runPasswordStatus executes the password status command.
//
// It used to demand --xkmsd-url while `password list` needed none and
// silently returned empty, so the two disagreed about where the store even
// lives. Both now follow one rule: the store belongs to whoever holds the
// barrier — the running daemon first, the on-disk store directory otherwise.
// A remote xkmsd server, which owns the session verbs (unlock, lock,
// access-mode), is consulted only when asked for with --source xkmsd.
func runPasswordStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	selection, err := stateSourceSelection(cmd, stateSelectorsWithXKMSd)
	if err != nil {
		return err
	}

	info, src, err := resolvePasswordStatus(cmd, selection)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(out, "Password Store Status:")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "  Available:       %s\n", boolToYesNo(info.Available))
	_, _ = fmt.Fprintf(out, "  Locked:          %s\n", boolToYesNo(info.Locked))
	if info.Backend != "" {
		_, _ = fmt.Fprintf(out, "  Backend:         %s\n", info.Backend)
	}
	_, _ = fmt.Fprintf(out, "  Access Mode:     %s\n", passwordAccessModeDisplay(info.AccessMode))
	_, _ = fmt.Fprintf(out, "  Auto-Unsealed:   %s\n", boolToYesNo(info.AutoUnsealed))
	_, _ = fmt.Fprintf(out, "  Password Count:  %d\n", info.PasswordCount)
	_, _ = fmt.Fprintln(out)
	writeSource(out, src)

	return nil
}

// passwordAccessModeDisplay renders the access mode, naming why it is
// unknown rather than printing a blank that reads as a real value.
func passwordAccessModeDisplay(mode string) string {
	if mode == "" {
		return "n/a (no xkmsd session server)"
	}
	return mode
}

// resolvePasswordStatus applies the store-location rule and returns the
// status alongside the labelled source that produced it.
func resolvePasswordStatus(cmd *cobra.Command, selection string) (passwordStatusInfo, stateSource, error) {
	if selection == sourceXKMSd {
		return readPasswordStatusFromXKMSd(cmd)
	}

	state, socketPath, answered, reason, err := askDaemon(cmd, selection,
		func(client *ipc.Client) (*ipc.PasswordStoreStateResult, error) {
			return client.StatePasswordStore()
		})
	if err != nil {
		return passwordStatusInfo{}, stateSource{}, err
	}
	if answered {
		return passwordStatusInfo{
			Available:     state.Available,
			Locked:        state.Locked,
			Backend:       state.Backend,
			AccessMode:    state.AccessMode,
			PasswordCount: state.Count,
		}, daemonSource(socketPath), nil
	}

	entries, storePath, err := readPasswordListFromDisk(cmd)
	if err != nil {
		return passwordStatusInfo{}, stateSource{}, err
	}
	return passwordStatusInfo{
		Available:     true,
		Backend:       passwordBackendFile,
		PasswordCount: len(entries),
	}, diskSource(storePath, reason), nil
}

// passwordBackendFile names the on-disk store backend.
const passwordBackendFile = "file"

// readPasswordStatusFromXKMSd reads the session status from a configured
// xkmsd server. This is the only source that knows the access mode.
func readPasswordStatusFromXKMSd(cmd *cobra.Command) (_ passwordStatusInfo, _ stateSource, err error) {
	client, err := connectPasswordStore()
	if err != nil {
		return passwordStatusInfo{}, stateSource{}, err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	resp, err := client.PasswordStoreStatus(context.Background())
	if err != nil {
		return passwordStatusInfo{}, stateSource{}, &SentinelCauseError{Sentinel: ErrPasswordStatusFailed, Cause: err}
	}

	return passwordStatusInfo{
		Available:     true,
		Locked:        resp.IsLocked,
		AccessMode:    resp.AccessMode,
		AutoUnsealed:  resp.AutoUnsealed,
		PasswordCount: resp.PasswordCount,
	}, xkmsdSource(resolveXKMSdURL()), nil
}

// runPasswordAccessMode executes the password access-mode command.
func runPasswordAccessMode(cmd *cobra.Command, args []string) (err error) {
	mode, _ := cmd.Flags().GetString("mode")

	if mode == "" {
		return ErrPasswordMissingMode
	}

	if mode != AccessModePINPerOperation && mode != AccessModeSessionBased {
		return ErrPasswordInvalidMode
	}

	client, err := connectPasswordStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()
	req := &transport.PasswordStoreSetAccessModeRequest{
		Mode: mode,
	}

	if err := client.PasswordStoreSetAccessMode(ctx, req); err != nil {
		return &SentinelCauseError{Sentinel: ErrPasswordAccessModeFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Access mode set to: %s\n", mode)
	return nil
}

// connectPasswordStore creates and connects a PasswordStoreClientService client.
func connectPasswordStore() (PasswordStoreClientService, error) {
	client, err := passwordClientFactory()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPasswordConnectFailed, Cause: err}
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPasswordConnectFailed, Cause: err}
	}

	return client, nil
}

// openPasswordStore creates a BackendStore backed by file storage at the
// given path. The file backend creates the directory if it does not exist.
func openPasswordStore(storePath string) (*xkms.StaticPasswordBackendStore, error) {
	backend, err := xkms.NewFileStorageBackend(storePath)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPasswordStoreOpenFailed, Cause: err}
	}
	return xkms.NewStaticPasswordStore(backend), nil
}

// PasswordStoreError represents a password store operation error.
type PasswordStoreError struct {
	Operation string
	Message   string
	Err       error
}

// Error returns the error message.
func (e *PasswordStoreError) Error() string {
	if e.Err != nil {
		if e.Message != "" {
			return fmt.Sprintf("password: %s: %s: %v", e.Operation, e.Message, e.Err)
		}
		return fmt.Sprintf("password: %s: %v", e.Operation, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("password: %s: %s", e.Operation, e.Message)
	}
	return fmt.Sprintf("password: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *PasswordStoreError) Unwrap() error {
	return e.Err
}

func init() {
	// Register password command with root.
	RootCmd.AddCommand(PasswordCmd)

	// Add subcommands to password command.
	PasswordCmd.AddCommand(passwordAddCmd)
	PasswordCmd.AddCommand(passwordListCmd)
	PasswordCmd.AddCommand(passwordGetCmd)
	PasswordCmd.AddCommand(passwordRemoveCmd)
	PasswordCmd.AddCommand(passwordTypeCmd)
	PasswordCmd.AddCommand(passwordUnlockCmd)
	PasswordCmd.AddCommand(passwordLockCmd)
	PasswordCmd.AddCommand(passwordStatusCmd)
	PasswordCmd.AddCommand(passwordAccessModeCmd)

	// password add flags.
	passwordAddCmd.Flags().String("name", "", "Password name (e.g., DatabaseProd)")
	passwordAddCmd.Flags().String("password", "", "The password to store")
	passwordAddCmd.Flags().Bool("generate", false, "Generate a random password")
	passwordAddCmd.Flags().Int("length", xkms.StaticPasswordDefaultLength, "Generated password length")
	passwordAddCmd.Flags().String("charset", "all", "Password charset: all, alphanumeric")
	passwordAddCmd.Flags().String("notes", "", "Optional notes")
	passwordAddCmd.Flags().String("title", "", "Display title for credential")
	passwordAddCmd.Flags().String("username", "", "Username or login")
	passwordAddCmd.Flags().String("url", "", "Website URL for domain matching")
	passwordAddCmd.Flags().String("store", "", "Path to password store (default: ~/.xkey/data/staticpw)")

	// password list flags.
	passwordListCmd.Flags().String("store", "", "Path to password store (default: ~/.xkey/data/staticpw)")
	passwordListCmd.Flags().Bool("show-passwords", false, "Show password values (requires --source disk)")
	addStateSourceFlags(passwordListCmd, stateSelectorsLocal)

	// password status flags.
	passwordStatusCmd.Flags().String("store", "", "Path to password store (default: ~/.xkey/data/staticpw)")
	addStateSourceFlags(passwordStatusCmd, stateSelectorsWithXKMSd)

	// password get flags.
	passwordGetCmd.Flags().String("store", "", "Path to password store (default: ~/.xkey/data/staticpw)")

	// password remove flags.
	passwordRemoveCmd.Flags().String("store", "", "Path to password store (default: ~/.xkey/data/staticpw)")
	passwordRemoveCmd.Flags().Bool("force", false, "Skip confirmation prompt")

	// password unlock flags.
	passwordUnlockCmd.Flags().String("pin", "", "User PIN for unlocking the store")

	// password access-mode flags.
	passwordAccessModeCmd.Flags().String("mode", "", "Access mode: pin_per_operation or session_based")
}
