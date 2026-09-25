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

// acme_account.go implements "xkmsctl acme account": list/get/disable
// against the ACME admin API's account plane (sdk/go/acme/client/admin,
// AdminAccountClient), bringing xkmsctl to parity with go-trusted-ca's
// cactl "account" command group.
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	acmeadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
)

// Account command flags.
var (
	acmeAccountListPage    int
	acmeAccountListPerPage int
	acmeAccountListStatus  string
)

// acmeAccountCmd is the parent command for ACME account operations.
var acmeAccountCmd = &cobra.Command{
	Use:   "account",
	Short: "Manage ACME accounts",
	Long: `List, view, and disable ACME accounts registered with the CA.

Examples:
  xkmsctl acme account list
  xkmsctl acme account list --status valid --page 2 --per-page 50
  xkmsctl acme account get 12345
  xkmsctl acme account disable 12345`,
}

// acmeAccountListCmd lists accounts with optional filtering.
var acmeAccountListCmd = &cobra.Command{
	Use:   "list",
	Short: "List ACME accounts",
	Run: func(cmd *cobra.Command, args []string) {
		acmeAccountList(getConfig())
	},
}

// acmeAccountGetCmd retrieves an account by ID.
var acmeAccountGetCmd = &cobra.Command{
	Use:   "get [account-id]",
	Short: "Get an ACME account by ID",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		acmeAccountGet(getConfig(), args[0])
	},
}

// acmeAccountDisableCmd disables an account.
var acmeAccountDisableCmd = &cobra.Command{
	Use:   "disable [account-id]",
	Short: "Disable an ACME account",
	Long: `Disable an ACME account, preventing further certificate operations.

Disabling an account prevents it from creating new orders, finalizing
pending orders, or renewing existing certificates. Certificates already
issued remain valid until they expire.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		acmeAccountDisable(getConfig(), args[0])
	},
}

func init() {
	acmeAccountListCmd.Flags().IntVar(&acmeAccountListPage, "page", 1, "page number for pagination")
	acmeAccountListCmd.Flags().IntVar(&acmeAccountListPerPage, "per-page", 20, "number of items per page")
	acmeAccountListCmd.Flags().StringVar(&acmeAccountListStatus, "status", "",
		"filter by status (valid, deactivated, revoked)")

	acmeAccountCmd.AddCommand(acmeAccountListCmd)
	acmeAccountCmd.AddCommand(acmeAccountGetCmd)
	acmeAccountCmd.AddCommand(acmeAccountDisableCmd)
}

// parseACMEAccountID parses an account ID argument, reporting a typed
// error on malformed input rather than letting a zero value silently
// address account 0.
func parseACMEAccountID(op, raw string) (uint64, error) {
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, &WrappedDetailError{Sentinel: ErrInvalidAccountID, Detail: op + ": " + raw, Err: err}
	}
	return id, nil
}

// acmeAccountList lists ACME accounts using the admin SDK client.
func acmeAccountList(cfg *Config) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	ctx := context.Background()
	client, cleanup, err := acmeAdminClient(ctx)
	if err != nil {
		handleError(err)
		return
	}
	defer closeAdminClientQuiet(cleanup)

	resp, err := client.Account().List(ctx, &acmeadmin.ListAccountsRequest{
		Page:    acmeAccountListPage,
		PerPage: acmeAccountListPerPage,
		Status:  acmeAccountListStatus,
	})
	if err != nil {
		handleError(classifyACMEAdminError("list accounts", ErrListAccountsFailed, err))
		return
	}

	printACMEAccountList(printer, resp)
}

// acmeAccountGet retrieves a single ACME account by ID.
func acmeAccountGet(cfg *Config, rawID string) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	accountID, err := parseACMEAccountID("get", rawID)
	if err != nil {
		handleError(err)
		return
	}

	ctx := context.Background()
	client, cleanup, err := acmeAdminClient(ctx)
	if err != nil {
		handleError(err)
		return
	}
	defer closeAdminClientQuiet(cleanup)

	account, err := client.Account().Get(ctx, accountID)
	if err != nil {
		handleError(classifyACMEAdminError(fmt.Sprintf("get account %d", accountID), ErrGetACMEAccountFailed, err))
		return
	}

	printACMEAccountInfo(printer, account)
}

// acmeAccountDisable disables an ACME account.
func acmeAccountDisable(cfg *Config, rawID string) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	accountID, err := parseACMEAccountID("disable", rawID)
	if err != nil {
		handleError(err)
		return
	}

	ctx := context.Background()
	client, cleanup, err := acmeAdminClient(ctx)
	if err != nil {
		handleError(err)
		return
	}
	defer closeAdminClientQuiet(cleanup)

	if err := client.Account().Disable(ctx, accountID); err != nil {
		handleError(classifyACMEAdminError(fmt.Sprintf("disable account %d", accountID), ErrDisableACMEAccountFailed, err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Account %d disabled", accountID)); err != nil {
		handleError(err)
	}
}

// printACMEAccountList prints a page of ACME accounts.
func printACMEAccountList(printer *Printer, resp *acmeadmin.ListAccountsResponse) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"accounts": resp.Accounts,
		}
		if resp.Pagination != nil {
			result["pagination"] = resp.Pagination
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable:
		if len(resp.Accounts) == 0 {
			_, _ = fmt.Fprintln(printer.writer, "No accounts found")
			return
		}
		_, _ = fmt.Fprintf(printer.writer, "%-12s %-12s %-10s %-25s\n", "ID", "STATUS", "ORDERS", "CREATED")
		_, _ = fmt.Fprintln(printer.writer, repeatString("-", 62))
		for _, a := range resp.Accounts {
			_, _ = fmt.Fprintf(printer.writer, "%-12d %-12s %-10d %-25s\n",
				uint64(a.ID), a.Status, a.OrderCount, a.CreatedAt.Format("2006-01-02 15:04"))
		}
	case OutputFormatText:
		if len(resp.Accounts) == 0 {
			_, _ = fmt.Fprintln(printer.writer, "No accounts found")
			return
		}
		_, _ = fmt.Fprintln(printer.writer, "Accounts:")
		for _, a := range resp.Accounts {
			_, _ = fmt.Fprintf(printer.writer, "  - %d (%s, %d order(s))\n", uint64(a.ID), a.Status, a.OrderCount)
		}
	}
}

// printACMEAccountInfo prints a single ACME account.
func printACMEAccountInfo(printer *Printer, account *acmeadmin.AccountInfo) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(account); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintln(printer.writer, "Account:")
		_, _ = fmt.Fprintf(printer.writer, "  ID:         %d\n", uint64(account.ID))
		_, _ = fmt.Fprintf(printer.writer, "  Status:     %s\n", account.Status)
		_, _ = fmt.Fprintf(printer.writer, "  Contact:    %v\n", account.Contact)
		_, _ = fmt.Fprintf(printer.writer, "  TOS Agreed: %t\n", account.TermsOfServiceAgreed)
		_, _ = fmt.Fprintf(printer.writer, "  Orders:     %d\n", account.OrderCount)
		_, _ = fmt.Fprintf(printer.writer, "  Created:    %s\n", account.CreatedAt.Format("2006-01-02 15:04:05"))
	}
}
