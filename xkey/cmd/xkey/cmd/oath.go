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
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/qrscan"
	"github.com/spf13/cobra"
)

// Default OATH storage path.
const defaultOATHStorePath = "./data/oath.json"

// OATH command errors.
var (
	ErrOATHMissingName        = errors.New("oath: --name is required")
	ErrOATHMissingSecret      = errors.New("oath: --secret or --uri is required")
	ErrOATHMissingCredential  = errors.New("oath: specify credential name or use --all")
	ErrOATHMissingRemoveArg   = errors.New("oath: specify credential name to remove")
	ErrOATHStoreOpenFailed    = errors.New("oath: failed to open store")
	ErrOATHInvalidURI         = errors.New("oath: invalid URI")
	ErrOATHInvalidCredential  = errors.New("oath: invalid credential")
	ErrOATHAddFailed          = errors.New("oath: failed to add credential")
	ErrOATHListFailed         = errors.New("oath: failed to list credentials")
	ErrOATHGenerateFailed     = errors.New("oath: failed to generate code")
	ErrOATHDeleteFailed       = errors.New("oath: failed to delete credential")
	ErrOATHCredentialNotFound = errors.New("oath: credential not found")
	ErrOATHScanFailed         = errors.New("oath: failed to scan screen for QR code")
	ErrOATHNoQRFound          = errors.New("oath: no QR code found on screen")
	ErrOATHMultipleQRFound    = errors.New("oath: multiple QR codes found, use --index to select one")
)

// OATHCmd represents the oath parent command.
var OATHCmd = &cobra.Command{
	Use:   "oath",
	Short: "OATH TOTP/HOTP one-time password management",
	Long: `OATH TOTP/HOTP one-time password management.

Manage TOTP (Time-based One-Time Password) and HOTP (HMAC-based One-Time Password)
credentials for two-factor authentication.

Examples:
  # Scan screen for QR code and add credential
  xkey oath scan

  # Add credential from secret
  xkey oath add --name "GitHub" --secret JBSWY3DPEHPK3PXP --issuer "GitHub"

  # Add credential from QR code URI
  xkey oath add --uri "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"

  # List all credentials
  xkey oath list

  # Generate code for a credential
  xkey oath generate "GitHub"

  # Generate codes for all credentials
  xkey oath generate --all

  # Remove a credential
  xkey oath remove "GitHub"`,
}

// oathAddCmd adds a new OATH credential.
var oathAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new OATH credential",
	Long: `Add a new OATH TOTP or HOTP credential.

You can add a credential either by providing individual parameters or by
providing an otpauth:// URI (typically from a QR code).

Examples:
  # Add TOTP credential with secret
  xkey oath add --name "GitHub" --secret JBSWY3DPEHPK3PXP --issuer "GitHub"

  # Add TOTP credential with SHA256 and 8 digits
  xkey oath add --name "AWS" --secret JBSWY3DPEHPK3PXP --algorithm SHA256 --digits 8

  # Add HOTP credential
  xkey oath add --name "MyService" --secret JBSWY3DPEHPK3PXP --type hotp

  # Add from otpauth:// URI
  xkey oath add --uri "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"

  # Override name when using URI
  xkey oath add --uri "otpauth://totp/..." --name "My GitHub"`,
	RunE: runOATHAdd,
}

// oathListCmd lists all OATH credentials.
var oathListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all credentials",
	Long: `List all OATH TOTP/HOTP credentials in the store.

By default, secrets are hidden. Use --secrets to display them.
Use --uri to display the otpauth:// URI for each credential.

Examples:
  # List all credentials
  xkey oath list

  # Show secret keys
  xkey oath list --secrets

  # Show otpauth:// URIs
  xkey oath list --uri

  # Use custom store path
  xkey oath list --store /path/to/oath.json`,
	RunE: runOATHList,
}

// oathGenerateCmd generates OTP codes.
var oathGenerateCmd = &cobra.Command{
	Use:     "generate [name]",
	Aliases: []string{"gen", "code"},
	Short:   "Generate OTP code(s)",
	Long: `Generate one-time password codes for OATH credentials.

Specify a credential name to generate a code for a single credential,
or use --all to generate codes for all credentials.

For TOTP credentials, the remaining validity time is displayed.
For HOTP credentials, the counter is automatically incremented.

Examples:
  # Generate code for a specific credential
  xkey oath generate "GitHub"

  # Generate codes for all credentials
  xkey oath generate --all

  # Generate codes for multiple credentials
  xkey oath generate "GitHub" "AWS" "Slack"`,
	RunE: runOATHGenerate,
}

// oathRemoveCmd removes OATH credentials.
var oathRemoveCmd = &cobra.Command{
	Use:     "remove [name...]",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove a credential",
	Long: `Remove one or more OATH credentials from the store.

By default, you will be prompted to confirm each removal.
Use --force to skip confirmation prompts.

Examples:
  # Remove a credential (with confirmation)
  xkey oath remove "GitHub"

  # Remove without confirmation
  xkey oath remove --force "GitHub"

  # Remove multiple credentials
  xkey oath remove "GitHub" "AWS" "Slack"`,
	RunE: runOATHRemove,
}

// oathScanCmd scans the screen for QR codes.
var oathScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan screen for OTP QR code and add credential",
	Long: `Scan the screen for a QR code containing an otpauth:// URI and add it as a credential.

This command captures your screen(s), looks for QR codes, and if one contains
a valid otpauth:// URI (the format used by authenticator apps), it adds the
credential to your store.

By default, all displays are scanned. Use --display to scan a specific display.

Examples:
  # Scan all screens for QR code
  xkey oath scan

  # Scan specific display (0-indexed)
  xkey oath scan --display 0

  # Scan and override the credential name
  xkey oath scan --name "My GitHub"

  # Scan without confirmation prompt
  xkey oath scan --yes

  # List available displays
  xkey oath scan --list-displays`,
	RunE: runOATHScan,
}

// runOATHAdd executes the oath add command.
func runOATHAdd(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	issuer, _ := cmd.Flags().GetString("issuer")
	secret, _ := cmd.Flags().GetString("secret")
	uri, _ := cmd.Flags().GetString("uri")
	otpType, _ := cmd.Flags().GetString("type")
	algorithm, _ := cmd.Flags().GetString("algorithm")
	digits, _ := cmd.Flags().GetInt("digits")
	period, _ := cmd.Flags().GetInt("period")
	storePath, _ := cmd.Flags().GetString("store")

	store, err := oath.NewFileStore(storePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHStoreOpenFailed, err)
	}
	defer func() { _ = store.Close() }()

	var cred *oath.Credential

	if uri != "" {
		// Parse from URI
		cred, err = oath.ParseURI(uri)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrOATHInvalidURI, err)
		}
		// Allow name override
		if name != "" {
			cred.Name = name
		}
	} else {
		// Create from individual parameters
		if name == "" {
			return ErrOATHMissingName
		}
		if secret == "" {
			return ErrOATHMissingSecret
		}

		cred = &oath.Credential{
			ID:        strings.ToLower(name),
			Name:      name,
			Issuer:    issuer,
			Secret:    strings.ToUpper(secret),
			Type:      otpType,
			Algorithm: strings.ToUpper(algorithm),
			Digits:    digits,
			Period:    period,
			CreatedAt: time.Now(),
		}

		if err := cred.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrOATHInvalidCredential, err)
		}
	}

	if err := store.Add(cred); err != nil {
		return fmt.Errorf("%w: %v", ErrOATHAddFailed, err)
	}

	fmt.Printf("Added OATH credential: %s\n", cred.Name)
	return nil
}

// runOATHList executes the oath list command.
func runOATHList(cmd *cobra.Command, args []string) error {
	storePath, _ := cmd.Flags().GetString("store")
	showSecrets, _ := cmd.Flags().GetBool("secrets")
	showURI, _ := cmd.Flags().GetBool("uri")

	store, err := oath.NewFileStore(storePath)
	if err != nil {
		// If file doesn't exist, just show empty list
		if os.IsNotExist(err) {
			fmt.Println("No OATH credentials found.")
			return nil
		}
		return fmt.Errorf("%w: %v", ErrOATHStoreOpenFailed, err)
	}
	defer func() { _ = store.Close() }()

	creds, err := store.List()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHListFailed, err)
	}

	if len(creds) == 0 {
		fmt.Println("No OATH credentials found.")
		return nil
	}

	fmt.Printf("OATH Credentials (%d):\n\n", len(creds))

	for _, cred := range creds {
		fmt.Printf("  Name:      %s\n", cred.Name)
		if cred.Issuer != "" {
			fmt.Printf("  Issuer:    %s\n", cred.Issuer)
		}
		fmt.Printf("  Type:      %s\n", strings.ToUpper(cred.Type))
		fmt.Printf("  Algorithm: %s\n", cred.Algorithm)
		fmt.Printf("  Digits:    %d\n", cred.Digits)
		if cred.Type == oath.TypeTOTP {
			fmt.Printf("  Period:    %ds\n", cred.Period)
		} else {
			fmt.Printf("  Counter:   %d\n", cred.Counter)
		}
		if showSecrets {
			fmt.Printf("  Secret:    %s\n", cred.Secret)
		}
		if showURI {
			fmt.Printf("  URI:       %s\n", cred.ToURI())
		}
		fmt.Println()
	}

	return nil
}

// runOATHGenerate executes the oath generate command.
func runOATHGenerate(cmd *cobra.Command, args []string) error {
	storePath, _ := cmd.Flags().GetString("store")
	all, _ := cmd.Flags().GetBool("all")

	store, err := oath.NewFileStore(storePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHStoreOpenFailed, err)
	}
	defer func() { _ = store.Close() }()

	if all {
		// Generate for all credentials
		creds, err := store.List()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrOATHListFailed, err)
		}

		if len(creds) == 0 {
			fmt.Println("No OATH credentials found.")
			return nil
		}

		// Find max name length for alignment
		maxLen := 0
		for _, cred := range creds {
			if len(cred.Name) > maxLen {
				maxLen = len(cred.Name)
			}
		}

		for _, cred := range creds {
			gen, err := oath.NewGenerator(cred)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %-*s  ERROR: %v\n", maxLen, cred.Name, err)
				continue
			}

			code, err := gen.Generate()
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %-*s  ERROR: %v\n", maxLen, cred.Name, err)
				continue
			}

			if cred.Type == oath.TypeTOTP {
				remaining := gen.TimeRemaining()
				fmt.Printf("  %-*s  %s  (expires in %ds)\n", maxLen, cred.Name, code, remaining)
			} else {
				fmt.Printf("  %-*s  %s\n", maxLen, cred.Name, code)
				// Update counter for HOTP
				gen.IncrementCounter()
				_ = store.Update(cred)
			}
		}

		return nil
	}

	// Generate for specific credential(s)
	if len(args) == 0 {
		return ErrOATHMissingCredential
	}

	for _, name := range args {
		cred, err := store.Get(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}

		gen, err := oath.NewGenerator(cred)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}

		code, err := gen.Generate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}

		if cred.Type == oath.TypeTOTP {
			remaining := gen.TimeRemaining()
			fmt.Printf("%s  (expires in %ds)\n", code, remaining)
		} else {
			fmt.Printf("%s\n", code)
			// Update counter for HOTP
			gen.IncrementCounter()
			_ = store.Update(cred)
		}
	}

	return nil
}

// runOATHRemove executes the oath remove command.
func runOATHRemove(cmd *cobra.Command, args []string) error {
	storePath, _ := cmd.Flags().GetString("store")
	force, _ := cmd.Flags().GetBool("force")

	if len(args) == 0 {
		return ErrOATHMissingRemoveArg
	}

	store, err := oath.NewFileStore(storePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHStoreOpenFailed, err)
	}
	defer func() { _ = store.Close() }()

	reader := bufio.NewReader(os.Stdin)

	for _, name := range args {
		cred, err := store.Get(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}

		if !force {
			fmt.Printf("Remove credential '%s'? [y/N]: ", cred.Name)
			confirm, err := reader.ReadString('\n')
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %s: failed to read input\n", name)
				continue
			}
			confirm = strings.TrimSpace(strings.ToLower(confirm))
			if confirm != "y" && confirm != "yes" {
				fmt.Printf("Skipped %s\n", cred.Name)
				continue
			}
		}

		if err := store.Delete(cred.ID); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}

		fmt.Printf("Removed: %s\n", cred.Name)
	}

	return nil
}

// runOATHScan executes the oath scan command.
func runOATHScan(cmd *cobra.Command, args []string) error {
	storePath, _ := cmd.Flags().GetString("store")
	nameOverride, _ := cmd.Flags().GetString("name")
	displayIndex, _ := cmd.Flags().GetInt("display")
	listDisplays, _ := cmd.Flags().GetBool("list-displays")
	autoConfirm, _ := cmd.Flags().GetBool("yes")
	scanIndex, _ := cmd.Flags().GetInt("index")

	// List displays mode
	if listDisplays {
		n := qrscan.NumDisplays()
		if n == 0 {
			fmt.Println("No displays found.")
			return nil
		}
		fmt.Printf("Found %d display(s):\n", n)
		for i := 0; i < n; i++ {
			fmt.Printf("  Display %d\n", i)
		}
		return nil
	}

	// Check display availability
	n := qrscan.NumDisplays()
	if n == 0 {
		return ErrOATHScanFailed
	}

	fmt.Printf("Scanning %d display(s) for QR codes...\n", n)

	// Scan for QR codes
	scanner := qrscan.NewScanner()
	scanner.AllowMultiple = true // We'll handle multiple results ourselves

	results, err := scanner.ScanScreen(displayIndex)
	if err != nil {
		if errors.Is(err, qrscan.ErrNoQRCodeFound) {
			return ErrOATHNoQRFound
		}
		if errors.Is(err, qrscan.ErrInvalidQRContent) {
			fmt.Println("Found QR code(s) but none contain valid otpauth:// URIs.")
			return ErrOATHNoQRFound
		}
		return fmt.Errorf("%w: %v", ErrOATHScanFailed, err)
	}

	// Handle multiple results
	var selectedResult *qrscan.ScanResult
	if len(results) > 1 {
		if scanIndex >= 0 && scanIndex < len(results) {
			selectedResult = results[scanIndex]
		} else {
			fmt.Printf("\nFound %d QR codes with otpauth:// URIs:\n\n", len(results))
			for i, r := range results {
				// Parse to show friendly info
				cred, parseErr := oath.ParseURI(r.URI)
				if parseErr != nil {
					fmt.Printf("  [%d] (parse error: %v)\n", i, parseErr)
					continue
				}
				fmt.Printf("  [%d] %s", i, cred.Name)
				if cred.Issuer != "" {
					fmt.Printf(" (%s)", cred.Issuer)
				}
				fmt.Printf(" - %s %d-digit\n", strings.ToUpper(cred.Type), cred.Digits)
			}
			fmt.Println()
			fmt.Println("Use --index <N> to select which one to add.")
			return ErrOATHMultipleQRFound
		}
	} else {
		selectedResult = results[0]
	}

	// Parse the URI
	cred, err := oath.ParseURI(selectedResult.URI)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHInvalidURI, err)
	}

	// Apply name override if specified
	if nameOverride != "" {
		cred.Name = nameOverride
	}

	// Show what we found
	fmt.Printf("\nFound credential:\n")
	fmt.Printf("  Name:      %s\n", cred.Name)
	if cred.Issuer != "" {
		fmt.Printf("  Issuer:    %s\n", cred.Issuer)
	}
	fmt.Printf("  Type:      %s\n", strings.ToUpper(cred.Type))
	fmt.Printf("  Algorithm: %s\n", cred.Algorithm)
	fmt.Printf("  Digits:    %d\n", cred.Digits)
	if cred.Type == oath.TypeTOTP {
		fmt.Printf("  Period:    %ds\n", cred.Period)
	}
	fmt.Println()

	// Confirm unless --yes was specified
	if !autoConfirm {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Add this credential? [Y/n]: ")
		confirm, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm != "" && confirm != "y" && confirm != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	// Open store and add credential
	store, err := oath.NewFileStore(storePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHStoreOpenFailed, err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Add(cred); err != nil {
		return fmt.Errorf("%w: %v", ErrOATHAddFailed, err)
	}

	fmt.Printf("Added OATH credential: %s\n", cred.Name)
	return nil
}

func init() {
	// Register oath command with root
	RootCmd.AddCommand(OATHCmd)

	// Add subcommands to oath command
	OATHCmd.AddCommand(oathAddCmd)
	OATHCmd.AddCommand(oathListCmd)
	OATHCmd.AddCommand(oathGenerateCmd)
	OATHCmd.AddCommand(oathRemoveCmd)
	OATHCmd.AddCommand(oathScanCmd)

	// oath add flags
	oathAddCmd.Flags().String("name", "", "Credential name (e.g., GitHub)")
	oathAddCmd.Flags().String("issuer", "", "Service issuer name")
	oathAddCmd.Flags().String("secret", "", "Base32-encoded secret key")
	oathAddCmd.Flags().String("uri", "", "otpauth:// URI (from QR code)")
	oathAddCmd.Flags().String("type", "totp", "OTP type: totp or hotp")
	oathAddCmd.Flags().String("algorithm", "SHA1", "Hash algorithm: SHA1, SHA256, SHA512")
	oathAddCmd.Flags().Int("digits", 6, "Number of digits (6, 7, or 8)")
	oathAddCmd.Flags().Int("period", 30, "Time period in seconds (TOTP only)")
	oathAddCmd.Flags().String("store", defaultOATHStorePath, "Path to credential store")

	// oath list flags
	oathListCmd.Flags().String("store", defaultOATHStorePath, "Path to credential store")
	oathListCmd.Flags().Bool("secrets", false, "Show secret keys")
	oathListCmd.Flags().Bool("uri", false, "Show otpauth:// URIs")

	// oath generate flags
	oathGenerateCmd.Flags().String("store", defaultOATHStorePath, "Path to credential store")
	oathGenerateCmd.Flags().Bool("all", false, "Generate codes for all credentials")

	// oath remove flags
	oathRemoveCmd.Flags().String("store", defaultOATHStorePath, "Path to credential store")
	oathRemoveCmd.Flags().Bool("force", false, "Don't prompt for confirmation")

	// oath scan flags
	oathScanCmd.Flags().String("store", defaultOATHStorePath, "Path to credential store")
	oathScanCmd.Flags().String("name", "", "Override the credential name")
	oathScanCmd.Flags().Int("display", -1, "Display index to scan (-1 for all displays)")
	oathScanCmd.Flags().Bool("list-displays", false, "List available displays and exit")
	oathScanCmd.Flags().BoolP("yes", "y", false, "Don't prompt for confirmation")
	oathScanCmd.Flags().Int("index", -1, "Select QR code by index when multiple are found")
}
