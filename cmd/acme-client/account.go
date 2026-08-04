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
	"sort"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
)

// accountAddCmd registers a new ACME account with the configured directory.
var accountAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Register a new ACME account",
	Long: `Register a new ACME account with the specified directory URL.

The account is added to the local configuration and then registered with
the ACME server. A new account key is generated using the specified algorithm
and stored in the configured key store.

Examples:
  trusted-acme-client account add trusted-ca \
    --directory https://ca.internal:8443/directory \
    --email admin@corp.com

  trusted-acme-client account add letsencrypt \
    --directory https://acme-v02.api.letsencrypt.org/directory \
    --email admin@corp.com \
    --key-algorithm ECDSA \
    --key-curve P-384`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		name := args[0]
		directory, _ := cmd.Flags().GetString("directory")
		email, _ := cmd.Flags().GetString("email")
		algorithm, _ := cmd.Flags().GetString("key-algorithm")
		store, _ := cmd.Flags().GetString("key-store")
		curve, _ := cmd.Flags().GetString("key-curve")

		cfg := &service.AccountConfig{
			DirectoryURL: directory,
			Email:        email,
			Key: &service.KeyConfig{
				Algorithm: algorithm,
				Store:     store,
				ECC:       &service.ECCConfig{Curve: curve},
			},
		}

		if err := svc.Accounts().Add(cmd.Context(), name, cfg); err != nil {
			return err
		}

		// Trigger ACME registration by requesting a client for this account.
		if _, err := svc.Accounts().Client(cmd.Context(), name); err != nil {
			return err
		}

		cmd.Printf("Account %q added successfully\n", name)
		return nil
	},
}

// accountListCmd lists all configured ACME accounts.
var accountListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all ACME accounts",
	Long: `List all configured ACME accounts showing the account name,
directory URL, and contact email.

Examples:
  trusted-acme-client account list`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		accounts := svc.Accounts().List()
		if len(accounts) == 0 {
			cmd.Println("No accounts configured.")
			return nil
		}

		// Collect and sort account names for deterministic output.
		names := make([]string, 0, len(accounts))
		for name := range accounts {
			names = append(names, name)
		}
		sort.Strings(names)

		// Calculate column widths for aligned output.
		nameWidth := len("NAME")
		dirWidth := len("DIRECTORY")
		for _, name := range names {
			if len(name) > nameWidth {
				nameWidth = len(name)
			}
			if len(accounts[name].DirectoryURL) > dirWidth {
				dirWidth = len(accounts[name].DirectoryURL)
			}
		}

		cmd.Printf("%-*s  %-*s  %s\n", nameWidth, "NAME", dirWidth, "DIRECTORY", "EMAIL")
		for _, name := range names {
			acct := accounts[name]
			cmd.Printf("%-*s  %-*s  %s\n", nameWidth, name, dirWidth, acct.DirectoryURL, acct.Email)
		}

		return nil
	},
}

// accountShowCmd displays details for a single ACME account.
var accountShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show ACME account details",
	Long: `Display detailed information about a configured ACME account including
directory URL, email, key algorithm, key store, transport, and server address.

Examples:
  trusted-acme-client account show trusted-ca`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		name := args[0]
		acct, err := svc.Accounts().Get(name)
		if err != nil {
			return err
		}

		cmd.Printf("Account: %s\n", name)
		cmd.Printf("  Directory: %s\n", acct.DirectoryURL)
		cmd.Printf("  Email: %s\n", acct.Email)

		if acct.Key != nil {
			cmd.Printf("  Key Algorithm: %s\n", acct.Key.Algorithm)
			cmd.Printf("  Key Store: %s\n", acct.Key.Store)
		}

		if acct.Transport != "" {
			cmd.Printf("  Transport: %s\n", acct.Transport)
		}
		if acct.ServerAddr != "" {
			cmd.Printf("  Server: %s\n", acct.ServerAddr)
		}

		return nil
	},
}

// accountRemoveCmd removes an ACME account from the configuration.
var accountRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove an ACME account",
	Long: `Remove an ACME account from the local configuration. The account
must not be referenced by any certificate specs.

Examples:
  trusted-acme-client account remove letsencrypt`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		name := args[0]
		if err := svc.Accounts().Remove(cmd.Context(), name); err != nil {
			return err
		}

		cmd.Printf("Account %q removed successfully\n", name)
		return nil
	},
}

func init() {
	// Flags for account add.
	accountAddCmd.Flags().String("directory", "", "ACME directory URL (required)")
	accountAddCmd.Flags().String("email", "", "contact email address (required)")
	accountAddCmd.Flags().String("key-algorithm", "ECDSA", "key algorithm (ECDSA|RSA|ED25519)")
	accountAddCmd.Flags().String("key-store", "software", "key storage backend")
	accountAddCmd.Flags().String("key-curve", "P-256", "ECC curve for ECDSA keys (P-256|P-384|P-521)")

	accountCmd.AddCommand(accountAddCmd)
	accountCmd.AddCommand(accountListCmd)
	accountCmd.AddCommand(accountShowCmd)
	accountCmd.AddCommand(accountRemoveCmd)
}
