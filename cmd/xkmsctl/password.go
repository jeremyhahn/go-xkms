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

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// validPasswordAccessModes is the canonical staticpw access-mode set
// accepted by the server's access-mode endpoint.
var validPasswordAccessModes = map[string]struct{}{
	"pin_per_operation": {},
	"session_based":     {},
}

// passwordCmd is the top-level command for static password management.
var passwordCmd = &cobra.Command{
	Use:   "password",
	Short: "Manage static passwords",
	Long: `Manage the server-side static password store.

Password entries are encrypted at rest behind the cryptographic barrier.
Your personal entries are additionally sealed with a key only your own
vault factors unwrap: enroll one with "password vault enroll", then open
your session with "password unlock".

Subcommands:
  add          Add a new password entry
  get          Retrieve a password entry
  list         List password entries
  update       Update a password entry
  delete       Delete a password entry
  unlock       Open your personal session with a vault factor
  lock         Lock the password store
  vault        Manage your personal vault factors and recovery
  status       Show password store status
  access-mode  Set the store access mode
  generate     Generate a random password`,
}

// passwordAddCmd adds a new password entry.
var passwordAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a new password entry",
	Long: `Add a new static password entry.

The password value is taken from --password, from stdin when --password
is "-", or from an interactive no-echo prompt when the flag is omitted.

Examples:
  xkmsctl password add github --username alice
  echo -n "s3cret" | xkmsctl password add github --username alice --password -`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		password := fr.String("password")
		username := fr.String("username")
		url := fr.String("url")
		notes := fr.String("notes")
		folder := fr.String("folder")
		expiresAt := fr.String("expires-at")
		tenantID := fr.String("tenant-id")
		shared := fr.Bool("shared")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		secret, err := resolveSecret(password, "Password")
		if err != nil {
			handleError(err)
			return
		}
		if secret == "" {
			handleError(ErrPasswordSecretRequired)
			return
		}

		passwordAdd(cfg, printer, &client.PasswordAddRequest{
			Name:       args[0],
			Username:   username,
			Password:   secret,
			URL:        url,
			Notes:      notes,
			FolderPath: folder,
			ExpiresAt:  expiresAt,
			TenantID:   tenantID,
			Shared:     shared,
		})
	},
}

// passwordGetCmd retrieves a password entry.
var passwordGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Retrieve a password entry",
	Long: `Retrieve a password entry by ID.

The store must be unlocked first (see "password unlock"); the entry is
returned exactly as stored -- confidentiality at rest is provided by the
tenant barrier, not by a per-request decryption step.

Example:
  xkmsctl password get 4f1c...`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		tenantID := fr.String("tenant-id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		passwordGet(cfg, printer, &client.PasswordGetRequest{
			ID:       args[0],
			TenantID: tenantID,
		})
	},
}

// passwordListCmd lists password entries.
var passwordListCmd = &cobra.Command{
	Use:   "list",
	Short: "List password entries",
	Long: `List password entries, optionally filtered by folder.

Example:
  xkmsctl password list --folder /work`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		folder := fr.String("folder")
		tenantID := fr.String("tenant-id")
		scope := fr.String("scope")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		passwordList(cfg, printer, &client.PasswordListRequest{
			FolderPath: folder,
			TenantID:   tenantID,
			Scope:      scope,
		})
	},
}

// passwordUpdateCmd updates a password entry.
var passwordUpdateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update a password entry",
	Long: `Update fields of a password entry. Only the flags you pass are
changed; omitted fields keep their current values.

Passing --password with an empty value (or "-") reads the new password
from an interactive no-echo prompt (or stdin).

Example:
  xkmsctl password update 4f1c... --username bob --url https://example.com`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		req := &client.PasswordUpdateRequest{ID: args[0]}
		fr := newFlagReader(cmd)
		req.TenantID = fr.String("tenant-id")

		changed := false
		for flagName, target := range map[string]**string{
			"name":       &req.Name,
			"username":   &req.Username,
			"url":        &req.URL,
			"notes":      &req.Notes,
			"folder":     &req.FolderPath,
			"expires-at": &req.ExpiresAt,
		} {
			if cmd.Flags().Changed(flagName) {
				value := fr.String(flagName)
				*target = &value
				changed = true
			}
		}
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if cmd.Flags().Changed("password") {
			fr := newFlagReader(cmd)
			flagValue := fr.String("password")
			if err := fr.Err(); err != nil {
				handleError(err)
				return
			}
			secret, err := resolveSecret(flagValue, "New password")
			if err != nil {
				handleError(err)
				return
			}
			if secret == "" {
				handleError(ErrPasswordSecretRequired)
				return
			}
			req.Password = &secret
			changed = true
		}

		if !changed {
			handleError(ErrPasswordUpdateNoFields)
			return
		}

		passwordUpdate(cfg, printer, req)
	},
}

// passwordDeleteCmd deletes a password entry.
var passwordDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a password entry",
	Long: `Delete a password entry by ID.

Example:
  xkmsctl password delete 4f1c...`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		tenantID := fr.String("tenant-id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		passwordDelete(cfg, printer, &client.PasswordDeleteRequest{
			ID:       args[0],
			TenantID: tenantID,
		})
	},
}

// passwordUnlockCmd opens the caller's personal password session.
var passwordUnlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Open your personal password session",
	Long: `Open your personal password session with your vault passphrase, or
with --passkey with a vault passkey on your FIDO2 security key.

The passphrase is taken from --passphrase, from stdin when --passphrase is
"-", or from an interactive no-echo prompt when the flag is omitted. Enroll
a factor first with "password vault enroll"; if you have lost every factor,
use "password vault recover" with your recovery code.

With --passkey the vault's passkeys are tried on the attached security key;
touch it when asked.

` + vaultPasskeyPINUsage + `

Examples:
  xkmsctl password unlock
  printf '%s' "$PASSPHRASE" | xkmsctl password unlock --passphrase -
  printf '%s' "$PIN" | xkmsctl password unlock --passkey --pin-stdin`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		passphraseFlag := fr.String("passphrase")
		usePasskey := fr.Bool("passkey")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		source, cleanup, err := resolveVaultCredentialSource(cmd, cfg, printer, usePasskey, passphraseFlag, "", vaultUnlock)
		if err != nil {
			handleError(err)
			return
		}
		defer cleanup()

		passwordUnlock(cfg, printer, source)
	},
}

// passwordLockCmd locks the password store.
var passwordLockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the password store",
	Long: `Lock the password store, ending the current unlock session.

Example:
  xkmsctl password lock`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		passwordLock(cfg, printer)
	},
}

// passwordStatusCmd shows the password store status.
var passwordStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show password store status",
	Long: `Display the password store status including access mode, lock
state, and entry count.

Example:
  xkmsctl password status`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		passwordStatus(cfg, printer)
	},
}

// passwordAccessModeCmd sets the password store access mode.
var passwordAccessModeCmd = &cobra.Command{
	Use:   "access-mode <mode>",
	Short: "Set the password store access mode",
	Long: `Set the password store access-control strategy.

Valid modes:
  pin_per_operation  Authorize every password operation individually
  session_based      Unlock once per session ("password unlock")

Example:
  xkmsctl password access-mode session_based`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		if len(args) == 0 {
			handleError(ErrAccessModeRequired)
			return
		}
		mode := args[0]
		if _, ok := validPasswordAccessModes[mode]; !ok {
			handleError(&WrappedDetailError{Sentinel: ErrInvalidAccessMode, Detail: mode})
			return
		}

		passwordSetAccessMode(cfg, printer, mode)
	},
}

// passwordGenerateCmd generates a random password.
var passwordGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a random password",
	Long: `Generate a cryptographically random password on the server.

Example:
  xkmsctl password generate --length 32 --symbols=false`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		length := fr.Int("length")
		upper := fr.Bool("upper")
		lower := fr.Bool("lower")
		digits := fr.Bool("digits")
		symbols := fr.Bool("symbols")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		passwordGenerate(cfg, printer, &client.PasswordGenerateRequest{
			Length:  length,
			Upper:   upper,
			Lower:   lower,
			Digits:  digits,
			Symbols: symbols,
		})
	},
}

// createPasswordClient creates and connects a client, returning the client
// and a cleanup function. The caller must call cleanup when done.
func createPasswordClient(cfg *Config) (client.Client, func(), error) {
	cl, err := cfg.CreateClient()
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateClientFailed, Err: err}
	}

	if err := cl.Connect(context.Background()); err != nil {
		closeQuietly(cl)
		return nil, nil, &WrappedError{Sentinel: ErrConnectFailed, Err: err}
	}

	return cl, func() { closeQuietly(cl) }, nil
}

// passwordAdd adds a password entry via the SDK client.
func passwordAdd(cfg *Config, printer *Printer, req *client.PasswordAddRequest) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Adding password entry %q", req.Name)

	resp, err := cl.PasswordAdd(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrAddPasswordFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Password Added:\n")
		printer.printf("  ID:      %s\n", resp.ID)
		printer.printf("  Name:    %s\n", resp.Name)
		printer.printf("  Created: %s\n", resp.CreatedAt)
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// passwordGet retrieves a password entry via the SDK client.
func passwordGet(cfg *Config, printer *Printer, req *client.PasswordGetRequest) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving password entry %q", req.ID)

	resp, err := cl.PasswordGet(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetPasswordFailed, Err: err})
		return
	}

	printPasswordEntry(printer, resp)
}

// passwordList lists password entries via the SDK client.
func passwordList(cfg *Config, printer *Printer, req *client.PasswordListRequest) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Listing password entries")

	resp, err := cl.PasswordList(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrListPasswordsFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(map[string]interface{}{
			"passwords": resp.Passwords,
			"total":     len(resp.Passwords),
		}); err != nil {
			handleError(err)
		}
	case OutputFormatTable:
		if len(resp.Passwords) == 0 {
			printer.println("No passwords found")
			return
		}
		printer.printf("%-36s %-24s %-20s %-20s\n", "ID", "NAME", "USERNAME", "FOLDER")
		printer.println(repeatString("-", 102))
		for _, p := range resp.Passwords {
			printer.printf("%-36s %-24s %-20s %-20s\n",
				truncateString(p.ID, 36),
				truncateString(p.Name, 24),
				truncateString(p.Username, 20),
				truncateString(p.FolderPath, 20))
		}
		printer.printf("\nTotal: %d password(s)\n", len(resp.Passwords))
	case OutputFormatText:
		if len(resp.Passwords) == 0 {
			printer.println("No passwords found")
			return
		}
		printer.println("Passwords:")
		for _, p := range resp.Passwords {
			printer.printf("  - %s (%s)\n", p.Name, p.ID)
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// passwordUpdate updates a password entry via the SDK client.
func passwordUpdate(cfg *Config, printer *Printer, req *client.PasswordUpdateRequest) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Updating password entry %q", req.ID)

	if err := cl.PasswordUpdate(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrUpdatePasswordFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Password %q updated", req.ID)); err != nil {
		handleError(err)
	}
}

// passwordDelete deletes a password entry via the SDK client.
func passwordDelete(cfg *Config, printer *Printer, req *client.PasswordDeleteRequest) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Deleting password entry %q", req.ID)

	if err := cl.PasswordDelete(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrDeletePasswordFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Password %q deleted", req.ID)); err != nil {
		handleError(err)
	}
}

// passwordUnlock opens the caller's personal password session with the
// credential source produces.
func passwordUnlock(cfg *Config, printer *Printer, source vaultCredentialSource) {
	if err := unlockPasswordStore(cfg, source); err != nil {
		handleError(err)
		return
	}
	if err := printer.PrintSuccess("Personal password session unlocked"); err != nil {
		handleError(err)
	}
}

// unlockPasswordStore sends the unlock credential source produces.
func unlockPasswordStore(cfg *Config, source vaultCredentialSource) error {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	printVerbose("Opening personal password session")

	ctx := context.Background()
	cred, err := source(ctx, cl)
	if err != nil {
		return &WrappedError{Sentinel: ErrUnlockPasswordStoreFailed, Err: err}
	}
	defer clear(cred.Secret)

	req := &client.PasswordStoreUnlockRequest{PasswordVaultCredential: cred}
	if err := cl.PasswordStoreUnlock(ctx, req); err != nil {
		return &WrappedError{Sentinel: ErrUnlockPasswordStoreFailed, Err: err}
	}
	return nil
}

// passwordLock locks the password store via the SDK client.
func passwordLock(cfg *Config, printer *Printer) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Locking password store")

	if err := cl.PasswordStoreLock(context.Background()); err != nil {
		handleError(&WrappedError{Sentinel: ErrLockPasswordStoreFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess("Password store locked"); err != nil {
		handleError(err)
	}
}

// passwordStatus shows the password store status via the SDK client.
func passwordStatus(cfg *Config, printer *Printer) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving password store status")

	resp, err := cl.PasswordStoreStatus(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrPasswordStoreStatusFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Password Store Status:\n")
		printer.printf("  Access Mode:    %s\n", resp.AccessMode)
		printer.printf("  Locked:         %t\n", resp.IsLocked)
		printer.printf("  Barrier Sealed: %t\n", resp.BarrierSealed)
		printer.printf("  Auto Unsealed:  %t\n", resp.AutoUnsealed)
		printer.printf("  Passwords:      %d\n", resp.PasswordCount)
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// passwordSetAccessMode sets the password store access mode via the SDK client.
func passwordSetAccessMode(cfg *Config, printer *Printer, mode string) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Setting password store access mode to %q", mode)

	req := &client.PasswordStoreSetAccessModeRequest{Mode: mode}
	if err := cl.PasswordStoreSetAccessMode(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrSetPasswordAccessModeFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Password store access mode set to %q", mode)); err != nil {
		handleError(err)
	}
}

// passwordGenerate generates a random password via the SDK client.
func passwordGenerate(cfg *Config, printer *Printer, req *client.PasswordGenerateRequest) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Generating password (length=%d)", req.Length)

	resp, err := cl.PasswordGenerate(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGeneratePasswordFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.println(resp.Password)
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// printPasswordEntry prints a single password entry.
func printPasswordEntry(printer *Printer, entry *client.PasswordGetResponse) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(entry); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Password Entry:\n")
		printer.printf("  ID:       %s\n", entry.ID)
		printer.printf("  Name:     %s\n", entry.Name)
		if entry.Username != "" {
			printer.printf("  Username: %s\n", entry.Username)
		}
		if entry.Password != "" {
			printer.printf("  Password: %s\n", entry.Password)
		}
		if entry.URL != "" {
			printer.printf("  URL:      %s\n", entry.URL)
		}
		if entry.Notes != "" {
			printer.printf("  Notes:    %s\n", entry.Notes)
		}
		if entry.FolderPath != "" {
			printer.printf("  Folder:   %s\n", entry.FolderPath)
		}
		if entry.ExpiresAt != "" {
			printer.printf("  Expires:  %s\n", entry.ExpiresAt)
		}
		printer.printf("  Created:  %s\n", entry.CreatedAt)
		printer.printf("  Updated:  %s\n", entry.UpdatedAt)
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func init() {
	// password add flags
	passwordAddCmd.Flags().String("password", "", "password value ('-' reads stdin; prompted when omitted)")
	passwordAddCmd.Flags().String("username", "", "username associated with the entry")
	passwordAddCmd.Flags().String("url", "", "URL associated with the entry")
	passwordAddCmd.Flags().String("notes", "", "free-form notes")
	passwordAddCmd.Flags().String("folder", "", "folder path for organizing entries")
	passwordAddCmd.Flags().String("expires-at", "", "expiry timestamp (RFC 3339)")
	passwordAddCmd.Flags().String("tenant-id", "", "tenant scope for the entry")
	passwordAddCmd.Flags().Bool("shared", false, "share the entry with the tenant")

	// password get flags
	passwordGetCmd.Flags().String("tenant-id", "", "tenant scope for the entry")

	// password list flags
	passwordListCmd.Flags().String("folder", "", "filter by folder path")
	passwordListCmd.Flags().String("tenant-id", "", "tenant scope for the listing")
	passwordListCmd.Flags().String("scope", "", "listing scope (own | shared | all)")

	// password update flags
	passwordUpdateCmd.Flags().String("name", "", "new entry name")
	passwordUpdateCmd.Flags().String("username", "", "new username")
	passwordUpdateCmd.Flags().String("password", "", "new password value ('-' reads stdin; empty prompts)")
	passwordUpdateCmd.Flags().String("url", "", "new URL")
	passwordUpdateCmd.Flags().String("notes", "", "new notes")
	passwordUpdateCmd.Flags().String("folder", "", "new folder path")
	passwordUpdateCmd.Flags().String("expires-at", "", "new expiry timestamp (RFC 3339)")
	passwordUpdateCmd.Flags().String("tenant-id", "", "tenant scope for the entry")

	// password delete flags
	passwordDeleteCmd.Flags().String("tenant-id", "", "tenant scope for the entry")

	// password unlock flags
	passwordUnlockCmd.Flags().String("passphrase", "", "vault passphrase ('-' reads stdin; prompted when omitted)")
	passwordUnlockCmd.Flags().Bool("passkey", false, "unlock with a vault passkey on the attached FIDO2 security key")
	addPINFlags(passwordUnlockCmd)
	addPasskeyDeviceFlag(passwordUnlockCmd)
	addKeyFactorUnlockFlags(passwordUnlockCmd)

	// password generate flags
	passwordGenerateCmd.Flags().Int("length", 0, "password length (0 = server default)")
	passwordGenerateCmd.Flags().Bool("upper", true, "include uppercase letters")
	passwordGenerateCmd.Flags().Bool("lower", true, "include lowercase letters")
	passwordGenerateCmd.Flags().Bool("digits", true, "include digits")
	passwordGenerateCmd.Flags().Bool("symbols", true, "include symbols")

	// Build subcommand tree
	passwordCmd.AddCommand(passwordAddCmd)
	passwordCmd.AddCommand(passwordGetCmd)
	passwordCmd.AddCommand(passwordListCmd)
	passwordCmd.AddCommand(passwordUpdateCmd)
	passwordCmd.AddCommand(passwordDeleteCmd)
	passwordCmd.AddCommand(passwordUnlockCmd)
	passwordCmd.AddCommand(passwordLockCmd)
	passwordCmd.AddCommand(passwordStatusCmd)
	passwordCmd.AddCommand(passwordAccessModeCmd)
	passwordCmd.AddCommand(passwordGenerateCmd)

	// Register with root
	rootCmd.AddCommand(passwordCmd)
}
