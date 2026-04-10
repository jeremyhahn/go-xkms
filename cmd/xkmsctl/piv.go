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
	"encoding/base64"
	"fmt"
	"os"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// pivCmd is the parent command for PIV operations.
var pivCmd = &cobra.Command{
	Use:   "piv",
	Short: "Manage PIV smart card certificates and keys",
	Long:  `Commands for managing PIV (Personal Identity Verification) certificates and keys across backends.`,
}

// pivListCmd lists all PIV slots and their status.
var pivListCmd = &cobra.Command{
	Use:   "list",
	Short: "List PIV slots and their status",
	Long:  `List all PIV slots in the specified backend and show their current status.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		pivListSlots(cfg, printer)
	},
}

// pivGetCmd retrieves the certificate from a PIV slot.
var pivGetCmd = &cobra.Command{
	Use:   "get <slot>",
	Short: "Get certificate from a PIV slot",
	Long:  `Retrieve the certificate stored in the specified PIV slot.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		format, _ := cmd.Flags().GetString("format")
		if format == "" {
			format = "pem"
		}

		pivGetCertificate(cfg, printer, args[0], format)
	},
}

// pivStoreCmd stores a certificate in a PIV slot.
var pivStoreCmd = &cobra.Command{
	Use:   "store <slot>",
	Short: "Store a certificate in a PIV slot",
	Long:  `Store a certificate from a file into the specified PIV slot.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		certFile, _ := cmd.Flags().GetString("cert-file")
		format, _ := cmd.Flags().GetString("format")
		if format == "" {
			format = "pem"
		}

		if certFile == "" {
			handleError(fmt.Errorf("--cert-file is required"))
			return
		}

		certData, err := os.ReadFile(certFile)
		if err != nil {
			handleError(fmt.Errorf("failed to read certificate file: %w", err))
			return
		}

		pivStoreCertificate(cfg, printer, args[0], certData, format)
	},
}

// pivDeleteCmd removes the certificate from a PIV slot.
var pivDeleteCmd = &cobra.Command{
	Use:   "delete <slot>",
	Short: "Delete certificate from a PIV slot",
	Long:  `Remove the certificate stored in the specified PIV slot.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		pivDeleteCertificate(cfg, printer, args[0])
	},
}

// pivGenerateCmd generates a new key pair in a PIV slot.
var pivGenerateCmd = &cobra.Command{
	Use:   "generate <slot>",
	Short: "Generate a key pair in a PIV slot",
	Long: `Generate a new key pair in the specified PIV slot with a self-signed certificate.
The algorithm can be specified with --algorithm (default: ecdsap256).`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		algorithm, _ := cmd.Flags().GetString("algorithm")
		subject, _ := cmd.Flags().GetString("subject")

		pivGenerateKey(cfg, printer, args[0], algorithm, subject)
	},
}

// pivImportCmd imports a certificate into a PIV slot.
var pivImportCmd = &cobra.Command{
	Use:   "import <slot>",
	Short: "Import a certificate into a PIV slot",
	Long:  `Import a certificate from a file into the specified PIV slot.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		certFile, _ := cmd.Flags().GetString("cert-file")
		format, _ := cmd.Flags().GetString("format")
		if format == "" {
			format = "pem"
		}

		if certFile == "" {
			handleError(fmt.Errorf("--cert-file is required"))
			return
		}

		certData, err := os.ReadFile(certFile)
		if err != nil {
			handleError(fmt.Errorf("failed to read certificate file: %w", err))
			return
		}

		pivImportCertificate(cfg, printer, args[0], certData, format)
	},
}

// pivExportCmd exports the certificate from a PIV slot.
var pivExportCmd = &cobra.Command{
	Use:   "export <slot>",
	Short: "Export certificate from a PIV slot",
	Long:  `Export the certificate stored in the specified PIV slot.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		format, _ := cmd.Flags().GetString("format")
		if format == "" {
			format = "pem"
		}

		pivExportCertificate(cfg, printer, args[0], format)
	},
}

// pivCSRCmd generates a CSR for a PIV slot key.
var pivCSRCmd = &cobra.Command{
	Use:   "csr <slot>",
	Short: "Generate a CSR for a PIV slot key",
	Long:  `Generate a Certificate Signing Request (CSR) using the key in the specified PIV slot.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		subject, _ := cmd.Flags().GetString("subject")

		pivCSR(cfg, printer, args[0], subject)
	},
}

// pivListSlots lists all PIV slots using the SDK client.
func pivListSlots(cfg *Config, printer *Printer) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Listing PIV slots for backend: %s", cfg.Backend)

	resp, err := cl.ListPIVSlots(ctx, &client.ListPIVSlotsRequest{
		Backend: cfg.Backend,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to list PIV slots: %w", err))
		return
	}

	if err := printer.PrintJSON(resp); err != nil {
		handleError(err)
	}
}

// pivGetCertificate retrieves a certificate from a PIV slot using the SDK client.
func pivGetCertificate(cfg *Config, printer *Printer, slot, format string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Getting PIV certificate from slot: %s", slot)

	resp, err := cl.GetPIVCertificate(ctx, &client.GetPIVCertificateRequest{
		Backend: cfg.Backend,
		Slot:    slot,
		Format:  format,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to get PIV certificate: %w", err))
		return
	}

	result := map[string]interface{}{
		"slot":        resp.Slot,
		"format":      resp.Format,
		"certificate": string(resp.Certificate),
	}
	if err := printer.PrintJSON(result); err != nil {
		handleError(err)
	}
}

// pivStoreCertificate stores a certificate in a PIV slot using the SDK client.
func pivStoreCertificate(cfg *Config, printer *Printer, slot string, certData []byte, format string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Storing certificate in PIV slot: %s", slot)

	err = cl.StorePIVCertificate(ctx, &client.StorePIVCertificateRequest{
		Backend:     cfg.Backend,
		Slot:        slot,
		Certificate: certData,
		Format:      format,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to store PIV certificate: %w", err))
		return
	}

	result := map[string]interface{}{
		"status": "stored",
		"slot":   slot,
	}
	if err := printer.PrintJSON(result); err != nil {
		handleError(err)
	}
}

// pivDeleteCertificate removes a certificate from a PIV slot using the SDK client.
func pivDeleteCertificate(cfg *Config, printer *Printer, slot string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Deleting certificate from PIV slot: %s", slot)

	err = cl.DeletePIVCertificate(ctx, &client.DeletePIVCertificateRequest{
		Backend: cfg.Backend,
		Slot:    slot,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to delete PIV certificate: %w", err))
		return
	}

	result := map[string]interface{}{
		"status": "deleted",
		"slot":   slot,
	}
	if err := printer.PrintJSON(result); err != nil {
		handleError(err)
	}
}

// pivGenerateKey generates a new key pair in a PIV slot using the SDK client.
func pivGenerateKey(cfg *Config, printer *Printer, slot, algorithm, subject string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Generating PIV key in slot: %s (algorithm: %s)", slot, algorithm)

	resp, err := cl.GeneratePIVKey(ctx, &client.GeneratePIVKeyRequest{
		Backend:   cfg.Backend,
		Slot:      slot,
		Algorithm: algorithm,
		Subject:   subject,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to generate PIV key: %w", err))
		return
	}

	result := map[string]interface{}{
		"slot":        resp.Slot,
		"certificate": string(resp.Certificate),
		"public_key":  string(resp.PublicKey),
	}
	if err := printer.PrintJSON(result); err != nil {
		handleError(err)
	}
}

// pivImportCertificate imports a certificate into a PIV slot using the SDK client.
func pivImportCertificate(cfg *Config, printer *Printer, slot string, certData []byte, format string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Importing certificate into PIV slot: %s", slot)

	err = cl.ImportPIVCertificate(ctx, &client.StorePIVCertificateRequest{
		Backend:     cfg.Backend,
		Slot:        slot,
		Certificate: certData,
		Format:      format,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to import PIV certificate: %w", err))
		return
	}

	result := map[string]interface{}{
		"status": "imported",
		"slot":   slot,
	}
	if err := printer.PrintJSON(result); err != nil {
		handleError(err)
	}
}

// pivExportCertificate exports a certificate from a PIV slot using the SDK client.
func pivExportCertificate(cfg *Config, printer *Printer, slot, format string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Exporting certificate from PIV slot: %s", slot)

	resp, err := cl.ExportPIVCertificate(ctx, &client.GetPIVCertificateRequest{
		Backend: cfg.Backend,
		Slot:    slot,
		Format:  format,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to export PIV certificate: %w", err))
		return
	}

	result := map[string]interface{}{
		"slot":   resp.Slot,
		"format": resp.Format,
	}
	if format == "der" {
		result["certificate"] = base64.StdEncoding.EncodeToString(resp.Certificate)
	} else {
		result["certificate"] = string(resp.Certificate)
	}
	if err := printer.PrintJSON(result); err != nil {
		handleError(err)
	}
}

// pivCSR generates a CSR for a PIV slot key using the SDK client.
func pivCSR(cfg *Config, printer *Printer, slot, subject string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Generating CSR for PIV slot: %s", slot)

	resp, err := cl.GeneratePIVCSR(ctx, &client.GeneratePIVCSRRequest{
		Backend: cfg.Backend,
		Slot:    slot,
		Subject: subject,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to generate PIV CSR: %w", err))
		return
	}

	result := map[string]interface{}{
		"slot": resp.Slot,
		"csr":  string(resp.CSR),
	}
	if err := printer.PrintJSON(result); err != nil {
		handleError(err)
	}
}

func init() {
	// Add subcommands to piv parent
	pivCmd.AddCommand(pivListCmd)
	pivCmd.AddCommand(pivGetCmd)
	pivCmd.AddCommand(pivStoreCmd)
	pivCmd.AddCommand(pivDeleteCmd)
	pivCmd.AddCommand(pivGenerateCmd)
	pivCmd.AddCommand(pivImportCmd)
	pivCmd.AddCommand(pivExportCmd)
	pivCmd.AddCommand(pivCSRCmd)

	// piv get flags
	pivGetCmd.Flags().String("format", "pem", "certificate format (pem or der)")

	// piv store flags
	pivStoreCmd.Flags().String("cert-file", "", "path to certificate file")
	pivStoreCmd.Flags().String("format", "pem", "certificate format (pem or der)")

	// piv generate flags
	pivGenerateCmd.Flags().String("algorithm", "ecdsap256",
		"key algorithm (rsa2048, rsa4096, ecdsap256, ecdsap384, ed25519)")
	pivGenerateCmd.Flags().String("subject", "", "certificate subject (e.g., CN=MyKey)")

	// piv import flags
	pivImportCmd.Flags().String("cert-file", "", "path to certificate file")
	pivImportCmd.Flags().String("format", "pem", "certificate format (pem or der)")

	// piv export flags
	pivExportCmd.Flags().String("format", "pem", "certificate format (pem or der)")

	// piv csr flags
	pivCSRCmd.Flags().String("subject", "", "CSR subject (e.g., CN=MyKey,O=MyOrg)")
}
