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

// acme_status.go implements "xkmsctl acme status" and "xkmsctl acme stats"
// against the ACME admin API's status plane (sdk/go/acme/client/admin,
// StatusClient), bringing xkmsctl to parity with go-trusted-ca's cactl
// "status"/"stats" commands.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	acmeadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
)

// acmeStatusCmd retrieves the ACME CA's status.
var acmeStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get ACME CA status",
	Long: `Retrieve the current status of the ACME certificate authority:
identity, version, initialization state, algorithms in use, and root/
intermediate CA information.`,
	Run: func(cmd *cobra.Command, args []string) {
		acmeStatus(getConfig())
	},
}

// acmeStatsCmd retrieves the ACME CA's statistics.
var acmeStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Get ACME CA statistics",
	Long: `Retrieve statistics about the ACME certificate authority: total,
valid, revoked, and expired certificates; total and active accounts; total,
pending, and completed orders.`,
	Run: func(cmd *cobra.Command, args []string) {
		acmeStats(getConfig())
	},
}

// acmeStatus retrieves and prints the ACME CA status.
func acmeStatus(cfg *Config) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	ctx := context.Background()
	client, cleanup, err := acmeAdminClient(ctx)
	if err != nil {
		handleError(err)
		return
	}
	defer func() { _ = cleanup() }()

	status, err := client.Status().Status(ctx)
	if err != nil {
		handleError(classifyACMEAdminError("get CA status", ErrGetACMEStatusFailed, err))
		return
	}

	printACMEStatus(printer, status)
}

// acmeStats retrieves and prints the ACME CA statistics.
func acmeStats(cfg *Config) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	ctx := context.Background()
	client, cleanup, err := acmeAdminClient(ctx)
	if err != nil {
		handleError(err)
		return
	}
	defer func() { _ = cleanup() }()

	stats, err := client.Status().Stats(ctx)
	if err != nil {
		handleError(classifyACMEAdminError("get CA stats", ErrGetACMEStatsFailed, err))
		return
	}

	printACMEStats(printer, stats)
}

// printACMEStatus prints the ACME CA status.
func printACMEStatus(printer *Printer, status *acmeadmin.CAStatus) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(status); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintln(printer.writer, "ACME CA Status:")
		_, _ = fmt.Fprintf(printer.writer, "  Identity:       %s\n", status.Identity)
		_, _ = fmt.Fprintf(printer.writer, "  Initialized:    %t\n", status.Initialized)
		_, _ = fmt.Fprintf(printer.writer, "  Version:        %s\n", status.Version)
		_, _ = fmt.Fprintf(printer.writer, "  Started At:     %s\n", status.StartedAt.Format("2006-01-02 15:04:05"))
		_, _ = fmt.Fprintf(printer.writer, "  Key Algorithm:  %s\n", status.KeyAlgorithm)
		_, _ = fmt.Fprintf(printer.writer, "  Signature Algo: %s\n", status.SignatureAlgo)
		_, _ = fmt.Fprintf(printer.writer, "  Root CA:        %s\n", status.RootCA)
		if status.IntermediateCA != "" {
			_, _ = fmt.Fprintf(printer.writer, "  Intermediate CA: %s\n", status.IntermediateCA)
		}
	}
}

// printACMEStats prints the ACME CA statistics.
func printACMEStats(printer *Printer, stats *acmeadmin.CAStats) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(stats); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintln(printer.writer, "ACME CA Statistics:")
		_, _ = fmt.Fprintf(printer.writer, "  Certificates: %d total, %d valid, %d revoked, %d expired\n",
			stats.TotalCertificates, stats.ValidCertificates, stats.RevokedCertificates, stats.ExpiredCertificates)
		_, _ = fmt.Fprintf(printer.writer, "  Accounts:     %d total, %d active\n",
			stats.TotalAccounts, stats.ActiveAccounts)
		_, _ = fmt.Fprintf(printer.writer, "  Orders:       %d total, %d pending, %d completed\n",
			stats.TotalOrders, stats.PendingOrders, stats.CompletedOrders)
	}
}
