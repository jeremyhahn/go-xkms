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

// acme_eab.go implements "xkmsctl acme eab": create/get/delete/list against
// the ACME admin API's External Account Binding plane (sdk/go/acme/client/admin,
// EABClient). go-trusted-ca's cactl has no EAB verbs — go-xkms's ACME server
// is multi-tenant and EAB is scoped to a tenant, so every verb here requires
// --tenant.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	acmeadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
)

// EAB command flags.
var (
	acmeEABTenant            string
	acmeEABPurpose           string
	acmeEABExternalAccountID string
	acmeEABContact           []string
	acmeEABExpiresInDays     int
	acmeEABListPage          int
	acmeEABListPerPage       int
	acmeEABListStatus        string
	acmeEABListPurpose       string
)

// acmeEABCmd is the parent command for EAB operations.
var acmeEABCmd = &cobra.Command{
	Use:   "eab",
	Short: "Manage ACME External Account Bindings (EAB)",
	Long: `Create, view, delete, and list External Account Bindings (EAB) for a
tenant. An EAB lets an ACME client pre-authorize account creation with a
MAC key issued out of band, per RFC 8555 section 7.3.4.

EAB is scoped to a tenant in go-xkms's ACME server, so every verb requires
--tenant.

Examples:
  xkmsctl acme eab create --tenant acme --purpose device-enrollment
  xkmsctl acme eab list --tenant acme
  xkmsctl acme eab get --tenant acme <kid>
  xkmsctl acme eab delete --tenant acme <kid>`,
}

// acmeEABCreateCmd creates a new EAB for a tenant.
var acmeEABCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new EAB",
	Run: func(cmd *cobra.Command, args []string) {
		acmeEABCreate(getConfig())
	},
}

// acmeEABGetCmd retrieves an EAB by key ID.
var acmeEABGetCmd = &cobra.Command{
	Use:   "get [kid]",
	Short: "Get an EAB by key ID",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		acmeEABGet(getConfig(), args[0])
	},
}

// acmeEABDeleteCmd deletes an EAB.
var acmeEABDeleteCmd = &cobra.Command{
	Use:   "delete [kid]",
	Short: "Delete an EAB",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		acmeEABDelete(getConfig(), args[0])
	},
}

// acmeEABListCmd lists EABs for a tenant.
var acmeEABListCmd = &cobra.Command{
	Use:   "list",
	Short: "List EABs for a tenant",
	Run: func(cmd *cobra.Command, args []string) {
		acmeEABList(getConfig())
	},
}

func init() {
	acmeEABCmd.PersistentFlags().StringVar(&acmeEABTenant, "tenant", "", "tenant ID (required)")

	acmeEABCreateCmd.Flags().StringVar(&acmeEABPurpose, "purpose", "", "purpose of the EAB (e.g. device-enrollment)")
	acmeEABCreateCmd.Flags().StringVar(&acmeEABExternalAccountID, "external-account-id", "",
		"external system's identifier for the bound account")
	acmeEABCreateCmd.Flags().StringSliceVar(&acmeEABContact, "contact", nil,
		"contact URI (repeatable, e.g. mailto:ops@example.com)")
	acmeEABCreateCmd.Flags().IntVar(&acmeEABExpiresInDays, "expires-in-days", 0,
		"EAB expiration in days from creation (0 = server default)")

	acmeEABListCmd.Flags().IntVar(&acmeEABListPage, "page", 1, "page number for pagination")
	acmeEABListCmd.Flags().IntVar(&acmeEABListPerPage, "per-page", 20, "number of items per page")
	acmeEABListCmd.Flags().StringVar(&acmeEABListStatus, "status", "", "filter by status")
	acmeEABListCmd.Flags().StringVar(&acmeEABListPurpose, "purpose", "", "filter by purpose")

	acmeEABCmd.AddCommand(acmeEABCreateCmd)
	acmeEABCmd.AddCommand(acmeEABGetCmd)
	acmeEABCmd.AddCommand(acmeEABDeleteCmd)
	acmeEABCmd.AddCommand(acmeEABListCmd)
}

// requireACMETenant validates --tenant was supplied.
func requireACMETenant() error {
	if acmeEABTenant == "" {
		return ErrACMETenantIDRequired
	}
	return nil
}

// requireACMEEABKID validates a key-ID argument is non-empty.
func requireACMEEABKID(kid string) error {
	if kid == "" {
		return ErrACMEEABKIDRequired
	}
	return nil
}

// acmeEABCreate creates a new EAB for --tenant.
func acmeEABCreate(cfg *Config) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	if err := requireACMETenant(); err != nil {
		handleError(err)
		return
	}

	ctx := context.Background()
	client, cleanup, err := acmeAdminClient(ctx)
	if err != nil {
		handleError(err)
		return
	}
	defer func() { _ = cleanup() }()

	resp, err := client.EAB().Create(ctx, acmeEABTenant, &acmeadmin.CreateEABRequest{
		Purpose:           acmeEABPurpose,
		ExternalAccountID: acmeEABExternalAccountID,
		Contact:           acmeEABContact,
		ExpiresInDays:     acmeEABExpiresInDays,
	})
	if err != nil {
		handleError(classifyACMEAdminError("create EAB for tenant "+acmeEABTenant, ErrCreateACMEEABFailed, err))
		return
	}

	printACMEEABCreateResponse(printer, resp)
}

// acmeEABGet retrieves an EAB by key ID.
func acmeEABGet(cfg *Config, kid string) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	if err := requireACMETenant(); err != nil {
		handleError(err)
		return
	}
	if err := requireACMEEABKID(kid); err != nil {
		handleError(err)
		return
	}

	ctx := context.Background()
	client, cleanup, err := acmeAdminClient(ctx)
	if err != nil {
		handleError(err)
		return
	}
	defer func() { _ = cleanup() }()

	eab, err := client.EAB().Get(ctx, acmeEABTenant, kid)
	if err != nil {
		handleError(classifyACMEAdminError("get EAB "+kid+" for tenant "+acmeEABTenant, ErrGetACMEEABFailed, err))
		return
	}

	printACMEEABInfo(printer, eab)
}

// acmeEABDelete deletes an EAB.
func acmeEABDelete(cfg *Config, kid string) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	if err := requireACMETenant(); err != nil {
		handleError(err)
		return
	}
	if err := requireACMEEABKID(kid); err != nil {
		handleError(err)
		return
	}

	ctx := context.Background()
	client, cleanup, err := acmeAdminClient(ctx)
	if err != nil {
		handleError(err)
		return
	}
	defer func() { _ = cleanup() }()

	if err := client.EAB().Delete(ctx, acmeEABTenant, kid); err != nil {
		handleError(classifyACMEAdminError("delete EAB "+kid+" for tenant "+acmeEABTenant, ErrDeleteACMEEABFailed, err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("EAB %s deleted", kid)); err != nil {
		handleError(err)
	}
}

// acmeEABList lists EABs for --tenant.
func acmeEABList(cfg *Config) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	if err := requireACMETenant(); err != nil {
		handleError(err)
		return
	}

	ctx := context.Background()
	client, cleanup, err := acmeAdminClient(ctx)
	if err != nil {
		handleError(err)
		return
	}
	defer func() { _ = cleanup() }()

	resp, err := client.EAB().List(ctx, acmeEABTenant, &acmeadmin.ListEABRequest{
		Page:    acmeEABListPage,
		PerPage: acmeEABListPerPage,
		Status:  acmeEABListStatus,
		Purpose: acmeEABListPurpose,
	})
	if err != nil {
		handleError(classifyACMEAdminError("list EABs for tenant "+acmeEABTenant, ErrListACMEEABFailed, err))
		return
	}

	printACMEEABList(printer, resp)
}

// printACMEEABCreateResponse prints the result of creating an EAB. The MAC
// key is printed exactly once, here: it is not retrievable again after this
// call returns, the same one-time-reveal contract as every other
// secret-bearing create verb in this CLI.
func printACMEEABCreateResponse(printer *Printer, resp *acmeadmin.CreateEABResponse) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintln(printer.writer, "EAB Created:")
		_, _ = fmt.Fprintf(printer.writer, "  Key ID:    %s\n", resp.ID)
		_, _ = fmt.Fprintf(printer.writer, "  MAC Key:   %s\n", resp.MACKey)
		_, _ = fmt.Fprintf(printer.writer, "  Algorithm: %s\n", resp.Algorithm)
		if resp.ExpiresAt != nil {
			_, _ = fmt.Fprintf(printer.writer, "  Expires:   %s\n", resp.ExpiresAt.Format("2006-01-02 15:04:05"))
		}
		_, _ = fmt.Fprintln(printer.writer, "\nStore the MAC key securely: it is not retrievable again.")
	}
}

// printACMEEABInfo prints a single EAB (never includes the MAC key: it is
// revealed only once, at creation).
func printACMEEABInfo(printer *Printer, eab *acmeadmin.EABInfo) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(eab); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintln(printer.writer, "EAB:")
		_, _ = fmt.Fprintf(printer.writer, "  Key ID:  %s\n", eab.ID)
		_, _ = fmt.Fprintf(printer.writer, "  Status:  %s\n", eab.Status)
		_, _ = fmt.Fprintf(printer.writer, "  Purpose: %s\n", eab.Purpose)
		if eab.AccountID != 0 {
			_, _ = fmt.Fprintf(printer.writer, "  Account: %d\n", eab.AccountID)
		}
		_, _ = fmt.Fprintf(printer.writer, "  Created: %s\n", eab.CreatedAt.Format("2006-01-02 15:04:05"))
		if eab.UsedAt != nil {
			_, _ = fmt.Fprintf(printer.writer, "  Used:    %s\n", eab.UsedAt.Format("2006-01-02 15:04:05"))
		}
		if eab.ExpiresAt != nil {
			_, _ = fmt.Fprintf(printer.writer, "  Expires: %s\n", eab.ExpiresAt.Format("2006-01-02 15:04:05"))
		}
	}
}

// printACMEEABList prints a page of EABs.
func printACMEEABList(printer *Printer, resp *acmeadmin.ListEABResponse) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"eabs": resp.EABs,
		}
		if resp.Pagination != nil {
			result["pagination"] = resp.Pagination
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable:
		if len(resp.EABs) == 0 {
			_, _ = fmt.Fprintln(printer.writer, "No EABs found")
			return
		}
		_, _ = fmt.Fprintf(printer.writer, "%-30s %-10s %-20s %-25s\n", "KEY ID", "STATUS", "PURPOSE", "CREATED")
		_, _ = fmt.Fprintln(printer.writer, repeatString("-", 88))
		for _, e := range resp.EABs {
			_, _ = fmt.Fprintf(printer.writer, "%-30s %-10s %-20s %-25s\n",
				truncateString(e.ID, 30), e.Status, truncateString(e.Purpose, 20),
				e.CreatedAt.Format("2006-01-02 15:04"))
		}
	case OutputFormatText:
		if len(resp.EABs) == 0 {
			_, _ = fmt.Fprintln(printer.writer, "No EABs found")
			return
		}
		_, _ = fmt.Fprintln(printer.writer, "EABs:")
		for _, e := range resp.EABs {
			_, _ = fmt.Fprintf(printer.writer, "  - %s (%s, %s)\n", e.ID, e.Status, e.Purpose)
		}
	}
}
