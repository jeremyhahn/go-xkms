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
	"os"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/spf13/cobra"
)

// Default password storage path.
const defaultPasswordStorePath = "./data/staticpw"

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

// defaultPasswordClientFactory creates a real transport client from the global xkmsdURL.
func defaultPasswordClientFactory() (PasswordStoreClientService, error) {
	if xkmsdURL == "" {
		return nil, &PasswordStoreError{
			Operation: "connect",
			Message:   "xkmsd URL is required; use --xkmsd-url or set XKEY_XKMSD_URL",
		}
	}
	return nil, &PasswordStoreError{
		Operation: "connect",
		Message:   "transport client creation requires a running xkmsd server",
	}
}

// PasswordCmd represents the password parent command.
var PasswordCmd = &cobra.Command{
	Use:   "password",
	Short: "Static password management",
	Long: `Static password management.

Store, retrieve, and generate static passwords in a secure file-backed store.
This provides YubiKey-style static password storage for credentials that cannot
use one-time passwords or certificate-based authentication.

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

By default, password values are masked. Use --show-passwords to reveal them.

Examples:
  # List all passwords
  xkey password list

  # Show password values
  xkey password list --show-passwords

  # Use a custom store path
  xkey password list --store /tmp/passwords`,
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

Displays the access mode, lock state, auto-unseal status, and
the number of stored passwords.

Examples:
  # Show password store status
  xkey password status`,
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

Examples:
  # Switch to session-based mode
  xkey password access-mode --mode session_based

  # Switch to per-operation PIN mode
  xkey password access-mode --mode pin_per_operation`,
	RunE: runPasswordAccessMode,
}

// runPasswordAdd executes the password add command.
func runPasswordAdd(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	password, _ := cmd.Flags().GetString("password")
	generate, _ := cmd.Flags().GetBool("generate")
	length, _ := cmd.Flags().GetInt("length")
	charset, _ := cmd.Flags().GetString("charset")
	notes, _ := cmd.Flags().GetString("notes")
	title, _ := cmd.Flags().GetString("title")
	username, _ := cmd.Flags().GetString("username")
	url, _ := cmd.Flags().GetString("url")
	storePath, _ := cmd.Flags().GetString("store")

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
	defer func() { _ = store.Close() }()

	if generate {
		password, err = staticpw.GeneratePassword(length, charset)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrPasswordGenerateFailed, err)
		}
	}

	pw := &staticpw.StaticPassword{
		Name:     name,
		Title:    title,
		Username: username,
		Password: password,
		URL:      url,
		Notes:    notes,
	}

	if err := pw.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordAddFailed, err)
	}

	if err := store.Add(pw); err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordAddFailed, err)
	}

	fmt.Printf("Added password: %s\n", pw.Name)
	if generate {
		fmt.Printf("Generated: %s\n", password)
	}

	return nil
}

// runPasswordList executes the password list command.
func runPasswordList(cmd *cobra.Command, args []string) error {
	storePath, _ := cmd.Flags().GetString("store")
	showPasswords, _ := cmd.Flags().GetBool("show-passwords")

	store, err := openPasswordStore(storePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No passwords found.")
			return nil
		}
		return err
	}
	defer func() { _ = store.Close() }()

	passwords, err := store.List()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordListFailed, err)
	}

	if len(passwords) == 0 {
		fmt.Println("No passwords found.")
		return nil
	}

	fmt.Printf("Static Passwords (%d):\n\n", len(passwords))

	for _, pw := range passwords {
		fmt.Printf("  Name:       %s\n", pw.Name)
		if pw.Title != "" {
			fmt.Printf("  Title:      %s\n", pw.Title)
		}
		if pw.Username != "" {
			fmt.Printf("  Username:   %s\n", pw.Username)
		}
		if showPasswords {
			fmt.Printf("  Password:   %s\n", pw.Password)
		} else {
			fmt.Printf("  Password:   ********\n")
		}
		if pw.URL != "" {
			fmt.Printf("  URL:        %s\n", pw.URL)
		}
		if pw.Notes != "" {
			fmt.Printf("  Notes:      %s\n", pw.Notes)
		}
		fmt.Printf("  Created:    %s\n", pw.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Updated:    %s\n", pw.UpdatedAt.Format("2006-01-02 15:04:05"))
		fmt.Println()
	}

	return nil
}

// runPasswordGet executes the password get command.
func runPasswordGet(cmd *cobra.Command, args []string) error {
	storePath, _ := cmd.Flags().GetString("store")

	if len(args) == 0 {
		return ErrPasswordMissingGetArg
	}

	store, err := openPasswordStore(storePath)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	pw, err := store.Get(args[0])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordGetFailed, err)
	}

	fmt.Print(pw.Password)
	return nil
}

// runPasswordRemove executes the password remove command.
func runPasswordRemove(cmd *cobra.Command, args []string) error {
	storePath, _ := cmd.Flags().GetString("store")
	force, _ := cmd.Flags().GetBool("force")

	if len(args) == 0 {
		return ErrPasswordMissingRemoveArg
	}

	store, err := openPasswordStore(storePath)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	reader := bufio.NewReader(os.Stdin)

	for _, name := range args {
		pw, err := store.Get(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}

		if !force {
			fmt.Printf("Remove password '%s'? [y/N]: ", pw.Name)
			confirm, readErr := reader.ReadString('\n')
			if readErr != nil {
				fmt.Fprintf(os.Stderr, "  %s: failed to read input\n", name)
				continue
			}
			confirm = strings.TrimSpace(strings.ToLower(confirm))
			if confirm != "y" && confirm != "yes" {
				fmt.Printf("Skipped %s\n", pw.Name)
				continue
			}
		}

		if err := store.Delete(pw.ID); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}

		fmt.Printf("Removed: %s\n", pw.Name)
	}

	return nil
}

// runPasswordType executes the password type command. It connects to the
// running xkey daemon and instructs it to type the named password via
// the virtual HID keyboard.
func runPasswordType(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return ErrPasswordMissingTypeArg
	}

	socketPath, _ := cmd.Flags().GetString("socket")
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}

	client := ipc.NewClient(socketPath)
	defer func() { _ = client.Close() }()

	resp, err := client.TypePassword(args[0])
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			return ErrTouchDaemonNotRunning
		}
		return fmt.Errorf("%w: %v", ErrPasswordTypeFailed, err)
	}

	if resp.Status == ipc.StatusError {
		return fmt.Errorf("%w: %s", ErrPasswordTypeFailed, resp.Error)
	}

	fmt.Printf("Typed password: %s\n", args[0])
	return nil
}

// runPasswordUnlock executes the password unlock command.
func runPasswordUnlock(cmd *cobra.Command, args []string) error {
	pin, _ := cmd.Flags().GetString("pin")

	if pin == "" {
		return ErrPasswordMissingPIN
	}

	client, err := connectPasswordStore()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	req := &transport.PasswordStoreUnlockRequest{
		UserPIN: pin,
	}

	if err := client.PasswordStoreUnlock(ctx, req); err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordUnlockFailed, err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Password store unlocked.")
	return nil
}

// runPasswordLock executes the password lock command.
func runPasswordLock(cmd *cobra.Command, args []string) error {
	client, err := connectPasswordStore()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()

	if err := client.PasswordStoreLock(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordLockFailed, err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Password store locked.")
	return nil
}

// runPasswordStatus executes the password status command.
func runPasswordStatus(cmd *cobra.Command, args []string) error {
	client, err := connectPasswordStore()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.PasswordStoreStatus(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordStatusFailed, err)
	}

	out := cmd.OutOrStdout()

	fmt.Fprintln(out, "Password Store Status:")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  Access Mode:     %s\n", resp.AccessMode)
	fmt.Fprintf(out, "  Locked:          %v\n", resp.IsLocked)
	fmt.Fprintf(out, "  Auto-Unsealed:   %v\n", resp.AutoUnsealed)
	fmt.Fprintf(out, "  Password Count:  %d\n", resp.PasswordCount)

	return nil
}

// runPasswordAccessMode executes the password access-mode command.
func runPasswordAccessMode(cmd *cobra.Command, args []string) error {
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
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	req := &transport.PasswordStoreSetAccessModeRequest{
		Mode: mode,
	}

	if err := client.PasswordStoreSetAccessMode(ctx, req); err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordAccessModeFailed, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Access mode set to: %s\n", mode)
	return nil
}

// connectPasswordStore creates and connects a PasswordStoreClientService client.
func connectPasswordStore() (PasswordStoreClientService, error) {
	client, err := passwordClientFactory()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPasswordConnectFailed, err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPasswordConnectFailed, err)
	}

	return client, nil
}

// openPasswordStore creates a BackendStore backed by file storage at the
// given path. The file backend creates the directory if it does not exist.
func openPasswordStore(storePath string) (*staticpw.BackendStore, error) {
	backend, err := file.New(storePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPasswordStoreOpenFailed, err)
	}
	return staticpw.NewStore(backend), nil
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
	passwordAddCmd.Flags().Int("length", staticpw.DefaultLength, "Generated password length")
	passwordAddCmd.Flags().String("charset", "all", "Password charset: all, alphanumeric")
	passwordAddCmd.Flags().String("notes", "", "Optional notes")
	passwordAddCmd.Flags().String("title", "", "Display title for credential")
	passwordAddCmd.Flags().String("username", "", "Username or login")
	passwordAddCmd.Flags().String("url", "", "Website URL for domain matching")
	passwordAddCmd.Flags().String("store", defaultPasswordStorePath, "Path to password store")

	// password list flags.
	passwordListCmd.Flags().String("store", defaultPasswordStorePath, "Path to password store")
	passwordListCmd.Flags().Bool("show-passwords", false, "Show password values")

	// password get flags.
	passwordGetCmd.Flags().String("store", defaultPasswordStorePath, "Path to password store")

	// password remove flags.
	passwordRemoveCmd.Flags().String("store", defaultPasswordStorePath, "Path to password store")
	passwordRemoveCmd.Flags().Bool("force", false, "Skip confirmation prompt")

	// password type flags.
	passwordTypeCmd.Flags().String("socket", "", "IPC socket path (default: auto-detect)")

	// password unlock flags.
	passwordUnlockCmd.Flags().String("pin", "", "User PIN for unlocking the store")

	// password access-mode flags.
	passwordAccessModeCmd.Flags().String("mode", "", "Access mode: pin_per_operation or session_based")
}
