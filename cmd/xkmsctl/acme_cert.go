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

// acme_cert.go implements "xkmsctl acme cert": list/get/revoke against the
// ACME admin API's certificate plane (sdk/go/acme/client/admin,
// CertificateClient), bringing xkmsctl to parity with go-trusted-ca's
// cactl "cert" command group.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	acmeadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
)

// Certificate command flags.
var (
	acmeCertListPage    int
	acmeCertListPerPage int
	acmeCertListStatus  string
	acmeCertRevokeRsn   string
)

// acmeCertCmd is the parent command for ACME certificate operations.
var acmeCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manage certificates issued by the ACME CA",
	Long: `List, view, and revoke certificates issued by the ACME CA.

Examples:
  xkmsctl acme cert list
  xkmsctl acme cert list --status valid --page 2 --per-page 50
  xkmsctl acme cert get 01:02:03:04:05:06:07:08
  xkmsctl acme cert revoke 01:02:03:04:05:06:07:08 --reason keyCompromise`,
}

// acmeCertListCmd lists certificates with optional filtering.
var acmeCertListCmd = &cobra.Command{
	Use:   "list",
	Short: "List certificates",
	Run: func(cmd *cobra.Command, args []string) {
		acmeCertList(getConfig())
	},
}

// acmeCertGetCmd retrieves a certificate by serial number.
var acmeCertGetCmd = &cobra.Command{
	Use:   "get [serial]",
	Short: "Get a certificate by serial number",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		acmeCertGet(getConfig(), args[0])
	},
}

// acmeCertRevokeCmd revokes a certificate.
var acmeCertRevokeCmd = &cobra.Command{
	Use:   "revoke [serial]",
	Short: "Revoke a certificate",
	Long: `Revoke a certificate by its serial number.

Valid revocation reasons (RFC 5280): unspecified (default), keyCompromise,
caCompromise, affiliationChanged, superseded, cessationOfOperation,
certificateHold, removeFromCRL, privilegeWithdrawn, aaCompromise.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		acmeCertRevoke(getConfig(), args[0])
	},
}

func init() {
	acmeCertListCmd.Flags().IntVar(&acmeCertListPage, "page", 1, "page number for pagination")
	acmeCertListCmd.Flags().IntVar(&acmeCertListPerPage, "per-page", 20, "number of items per page")
	acmeCertListCmd.Flags().StringVar(&acmeCertListStatus, "status", "",
		"filter by status (valid, revoked, expired)")

	acmeCertRevokeCmd.Flags().StringVar(&acmeCertRevokeRsn, "reason", "unspecified", "revocation reason")

	acmeCertCmd.AddCommand(acmeCertListCmd)
	acmeCertCmd.AddCommand(acmeCertGetCmd)
	acmeCertCmd.AddCommand(acmeCertRevokeCmd)
}

// requireACMESerial validates a certificate serial argument is non-empty.
func requireACMESerial(serial string) error {
	if serial == "" {
		return ErrInvalidACMESerial
	}
	return nil
}

// acmeCertList lists ACME certificates using the admin SDK client.
func acmeCertList(cfg *Config) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	ctx := context.Background()
	client, cleanup, err := acmeAdminClient(ctx)
	if err != nil {
		handleError(err)
		return
	}
	defer func() { _ = cleanup() }()

	resp, err := client.Certificate().List(ctx, &acmeadmin.ListCertificatesRequest{
		Page:    acmeCertListPage,
		PerPage: acmeCertListPerPage,
		Status:  acmeCertListStatus,
	})
	if err != nil {
		handleError(classifyACMEAdminError("list certificates", ErrListACMECertificatesFailed, err))
		return
	}

	printACMECertList(printer, resp)
}

// acmeCertGet retrieves a single certificate by serial number.
func acmeCertGet(cfg *Config, serial string) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	if err := requireACMESerial(serial); err != nil {
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

	cert, err := client.Certificate().Get(ctx, serial)
	if err != nil {
		handleError(classifyACMEAdminError("get certificate "+serial, ErrGetACMECertificateFailed, err))
		return
	}

	printACMECertInfo(printer, cert)
}

// acmeCertRevoke revokes a certificate by serial number.
func acmeCertRevoke(cfg *Config, serial string) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	if err := requireACMESerial(serial); err != nil {
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

	if err := client.Certificate().Revoke(ctx, serial, acmeCertRevokeRsn); err != nil {
		handleError(classifyACMEAdminError("revoke certificate "+serial, ErrRevokeACMECertificateFailed, err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Certificate %s revoked (reason: %s)", serial, acmeCertRevokeRsn)); err != nil {
		handleError(err)
	}
}

// printACMECertList prints a page of ACME certificates.
func printACMECertList(printer *Printer, resp *acmeadmin.ListCertificatesResponse) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"certificates": resp.Certificates,
		}
		if resp.Pagination != nil {
			result["pagination"] = resp.Pagination
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable:
		if len(resp.Certificates) == 0 {
			_, _ = fmt.Fprintln(printer.writer, "No certificates found")
			return
		}
		_, _ = fmt.Fprintf(printer.writer, "%-30s %-40s %-10s %-25s\n", "SERIAL", "SUBJECT", "STATUS", "NOT AFTER")
		_, _ = fmt.Fprintln(printer.writer, repeatString("-", 108))
		for _, c := range resp.Certificates {
			_, _ = fmt.Fprintf(printer.writer, "%-30s %-40s %-10s %-25s\n",
				truncateString(c.SerialNumber, 30), truncateString(c.Subject, 40), c.Status,
				c.NotAfter.Format("2006-01-02 15:04"))
		}
	case OutputFormatText:
		if len(resp.Certificates) == 0 {
			_, _ = fmt.Fprintln(printer.writer, "No certificates found")
			return
		}
		_, _ = fmt.Fprintln(printer.writer, "Certificates:")
		for _, c := range resp.Certificates {
			_, _ = fmt.Fprintf(printer.writer, "  - %s (%s, %s)\n", c.SerialNumber, c.Subject, c.Status)
		}
	}
}

// printACMECertInfo prints a single ACME certificate.
func printACMECertInfo(printer *Printer, cert *acmeadmin.CertificateInfo) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(cert); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintln(printer.writer, "Certificate:")
		_, _ = fmt.Fprintf(printer.writer, "  Serial:     %s\n", cert.SerialNumber)
		_, _ = fmt.Fprintf(printer.writer, "  Subject:    %s\n", cert.Subject)
		_, _ = fmt.Fprintf(printer.writer, "  Issuer:     %s\n", cert.Issuer)
		_, _ = fmt.Fprintf(printer.writer, "  Status:     %s\n", cert.Status)
		_, _ = fmt.Fprintf(printer.writer, "  Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
		_, _ = fmt.Fprintf(printer.writer, "  Not After:  %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
		_, _ = fmt.Fprintf(printer.writer, "  Issued At:  %s\n", cert.IssuedAt.Format("2006-01-02 15:04:05"))
	}
}
