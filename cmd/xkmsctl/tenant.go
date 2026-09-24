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
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// tenantCmd is the top-level command for tenant management.
var tenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Manage tenants",
	Long: `Manage tenants and their per-tenant cryptographic barriers.

Each tenant gets an isolated namespace with its own barrier, keys, and
certificates. The per-tenant barrier must be initialized and unsealed
independently of the global barrier.

Subcommands:
  create          Create a new tenant
  list            List all tenants
  show            Show details for a tenant
  delete          Delete a tenant
  barrier-init    Initialize a per-tenant barrier
  barrier-unseal  Unseal a per-tenant barrier
  barrier-status  Show per-tenant barrier status`,
}

// tenantCreateCmd creates a new tenant.
var tenantCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new tenant",
	Long: `Create a new tenant with the specified ID and name.

The tenant ID must be unique and is used to scope all operations
(keys, certificates, barrier) to this tenant.

Examples:
  xkmsctl tenant create --id acme --name "Acme Corporation"
  xkmsctl tenant create --id acme --name "Acme" --isolation barrier
  xkmsctl tenant create --id acme --name "Acme" --isolation volume --barrier-auto-unseal`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		name := fr.String("name")
		isolation := fr.String("isolation")
		autoUnseal := fr.Bool("barrier-auto-unseal")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if id == "" {
			handleError(ErrTenantIDRequired)
			return
		}
		if name == "" {
			handleError(ErrTenantNameRequired)
			return
		}

		tenantCreate(cfg, printer, id, name, isolation, autoUnseal)
	},
}

// tenantListCmd lists all tenants.
var tenantListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tenants",
	Long: `List all configured tenants.

Example:
  xkmsctl tenant list`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		tenantList(cfg, printer)
	},
}

// tenantShowCmd shows details for a tenant.
var tenantShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show details for a tenant",
	Long: `Display detailed information about a tenant.

Example:
  xkmsctl tenant show --id acme`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if id == "" {
			handleError(ErrTenantIDRequired)
			return
		}

		tenantShow(cfg, printer, id)
	},
}

// tenantDeleteCmd deletes a tenant.
var tenantDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a tenant",
	Long: `Delete a tenant and all associated resources.

WARNING: This is a destructive operation. All keys, certificates, and
barrier state associated with this tenant will be permanently removed.

Example:
  xkmsctl tenant delete --id acme`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if id == "" {
			handleError(ErrTenantIDRequired)
			return
		}

		tenantDelete(cfg, printer, id)
	},
}

// tenantBarrierInitCmd initializes a per-tenant barrier.
var tenantBarrierInitCmd = &cobra.Command{
	Use:   "barrier-init",
	Short: "Initialize a per-tenant barrier",
	Long: `Initialize the cryptographic barrier for a specific tenant.

Optionally specify Shamir threshold and shares for the tenant barrier.
If omitted, the server uses its default configuration.

Examples:
  xkmsctl tenant barrier-init --id acme --passphrase <secret>
  xkmsctl tenant barrier-init --id acme --strategy tpm2
  xkmsctl tenant barrier-init --id acme --strategy shamir --passphrase <secret> --threshold 3 --shares 5`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		threshold := fr.Int("threshold")
		shares := fr.Int("shares")
		passphrase := fr.String("passphrase")
		strategy := fr.String("strategy")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if id == "" {
			handleError(ErrTenantIDRequired)
			return
		}

		tenantBarrierInit(cfg, printer, id, passphrase, strategy, threshold, shares)
	},
}

// tenantBarrierUnsealCmd unseals a per-tenant barrier.
var tenantBarrierUnsealCmd = &cobra.Command{
	Use:   "barrier-unseal",
	Short: "Unseal a per-tenant barrier",
	Long: `Unseal the cryptographic barrier for a specific tenant.

Provide a Shamir share (base64-encoded) to contribute toward the
quorum required to unseal the tenant barrier.

Example:
  xkmsctl tenant barrier-unseal --id acme --share <base64-share>`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		share := fr.String("share")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if id == "" {
			handleError(ErrTenantIDRequired)
			return
		}

		tenantBarrierUnseal(cfg, printer, id, share)
	},
}

// tenantBarrierStatusCmd shows the per-tenant barrier status.
var tenantBarrierStatusCmd = &cobra.Command{
	Use:   "barrier-status",
	Short: "Show per-tenant barrier status",
	Long: `Display the current state of a tenant's cryptographic barrier
including whether it is sealed or unsealed.

Example:
  xkmsctl tenant barrier-status --id acme`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if id == "" {
			handleError(ErrTenantIDRequired)
			return
		}

		tenantBarrierStatus(cfg, printer, id)
	},
}

// createTenantClient creates and connects a client, returning the client
// and a cleanup function. The caller must call cleanup when done.
func createTenantClient(cfg *Config) (client.Client, func(), error) {
	cl, err := cfg.CreateClient()
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateClientFailed, Err: err}
	}

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		closeQuietly(cl)
		return nil, nil, &WrappedError{Sentinel: ErrConnectFailed, Err: err}
	}

	cleanup := func() { closeQuietly(cl) }
	return cl, cleanup, nil
}

// tenantCreate creates a new tenant.
func tenantCreate(cfg *Config, printer *Printer, id, name, isolation string, autoUnseal bool) {
	cl, cleanup, err := createTenantClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Creating tenant %q (%s) isolation=%q auto-unseal=%t", name, id, isolation, autoUnseal)

	req := &transport.CreateTenantRequest{
		ID:                id,
		Name:              name,
		IsolationType:     transport.TenantIsolationType(isolation),
		BarrierAutoUnseal: autoUnseal,
	}

	resp, err := cl.CreateTenant(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateTenantFailed, Err: err})
		return
	}

	printTenantInfo(printer, &resp.Tenant, "Tenant Created")
}

// tenantList lists all tenants.
func tenantList(cfg *Config, printer *Printer) {
	cl, cleanup, err := createTenantClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Listing tenants")

	resp, err := cl.ListTenants(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrListTenantsFailed, Err: err})
		return
	}

	printTenantList(printer, resp.Tenants)
}

// tenantShow shows details for a tenant.
func tenantShow(cfg *Config, printer *Printer, id string) {
	cl, cleanup, err := createTenantClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving tenant %q", id)

	resp, err := cl.GetTenant(context.Background(), id)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetTenantFailed, Err: err})
		return
	}

	printTenantInfo(printer, &resp.Tenant, "Tenant Details")
}

// tenantDelete deletes a tenant.
func tenantDelete(cfg *Config, printer *Printer, id string) {
	cl, cleanup, err := createTenantClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Deleting tenant %q", id)

	if err := cl.DeleteTenant(context.Background(), id); err != nil {
		handleError(&WrappedError{Sentinel: ErrDeleteTenantFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Tenant %q deleted", id)); err != nil {
		handleError(err)
	}
}

// tenantBarrierInit initializes a per-tenant barrier.
func tenantBarrierInit(cfg *Config, printer *Printer, tenantID, passphrase, strategy string, threshold, shares int) {
	cl, cleanup, err := createTenantClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Initializing barrier for tenant %q strategy=%q", tenantID, strategy)

	req := &transport.TenantBarrierInitRequest{
		TenantID:   tenantID,
		Passphrase: []byte(passphrase),
		Strategy:   strategy,
		Threshold:  threshold,
		Shares:     shares,
	}

	if err := cl.TenantBarrierInit(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrInitializeTenantBarrierFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Barrier initialized for tenant %q", tenantID)); err != nil {
		handleError(err)
	}
}

// tenantBarrierUnseal unseals a per-tenant barrier.
func tenantBarrierUnseal(cfg *Config, printer *Printer, tenantID, share string) {
	cl, cleanup, err := createTenantClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Unsealing barrier for tenant %q", tenantID)

	req := &transport.TenantBarrierUnsealRequest{
		TenantID: tenantID,
	}

	// Decode the base64 share if provided
	if share != "" {
		shareBytes, decodeErr := base64.StdEncoding.DecodeString(share)
		if decodeErr != nil {
			handleError(&WrappedError{Sentinel: ErrDecodeShareFailed, Err: decodeErr})
			return
		}
		req.Share = shareBytes
	}

	if err := cl.TenantBarrierUnseal(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrUnsealTenantBarrierFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Barrier unsealed for tenant %q", tenantID)); err != nil {
		handleError(err)
	}
}

// tenantBarrierStatus shows the per-tenant barrier status.
func tenantBarrierStatus(cfg *Config, printer *Printer, tenantID string) {
	cl, cleanup, err := createTenantClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving barrier status for tenant %q", tenantID)

	resp, err := cl.TenantBarrierStatus(context.Background(), tenantID)
	if err != nil {
		handleError(&TenantBarrierStatusError{TenantID: tenantID, Err: err})
		return
	}

	printTenantBarrierStatus(printer, resp)
}

// tenantUpdateEntitlementsCmd updates a tenant's feature entitlements.
var tenantUpdateEntitlementsCmd = &cobra.Command{
	Use:   "update-entitlements",
	Short: "Update a tenant's feature entitlements",
	Long: `Update which isolation tiers and dedicated-storage features a tenant's
plan permits.

Example:
  xkmsctl tenant update-entitlements --id acme --isolation-modes prefix,barrier,volume \
    --allow-volume --allow-system-managed`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		modes := fr.StringSlice("isolation-modes")
		allowRaft := fr.Bool("allow-raft")
		allowVolume := fr.Bool("allow-volume")
		allowSystemManaged := fr.Bool("allow-system-managed")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if id == "" {
			handleError(ErrTenantIDRequired)
			return
		}

		tenantUpdateEntitlements(cfg, printer, id, modes, allowRaft, allowVolume, allowSystemManaged)
	},
}

// tenantUpdateQuotasCmd updates a tenant's resource quotas.
var tenantUpdateQuotasCmd = &cobra.Command{
	Use:   "update-quotas",
	Short: "Update a tenant's resource quotas",
	Long: `Update a tenant's resource limits. Only the flags you pass are set;
omitted limits default to zero (the system default).

Example:
  xkmsctl tenant update-quotas --id acme --max-databases 10 --max-keys 1000`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if id == "" {
			handleError(ErrTenantIDRequired)
			return
		}
		qfr := newFlagReader(cmd)
		q := transport.TenantQuotas{
			MaxDatabases:    qfr.Int64("max-databases"),
			MaxKeys:         qfr.Int64("max-keys"),
			MaxCollections:  qfr.Int64("max-collections"),
			MaxStorageBytes: qfr.Int64("max-storage-bytes"),
			MaxUsers:        qfr.Int64("max-users"),
			MaxRoles:        qfr.Int64("max-roles"),
			MaxCertificates: qfr.Int64("max-certificates"),
		}
		if err := qfr.Err(); err != nil {
			handleError(err)
			return
		}

		tenantUpdateQuotas(cfg, printer, id, q)
	},
}

func tenantUpdateEntitlements(cfg *Config, printer *Printer, id string, modes []string, allowRaft, allowVolume, allowSystemManaged bool) {
	cl, cleanup, err := createTenantClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	resp, err := cl.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{
		TenantID: id,
		Entitlements: transport.TenantEntitlements{
			AllowedIsolationModes:     modes,
			AllowDedicatedRaft:        allowRaft,
			AllowVolumeStorage:        allowVolume,
			AllowSystemManagedBarrier: allowSystemManaged,
		},
	})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrUpdateTenantEntitlementsFailed, Err: err})
		return
	}
	printTenantInfo(printer, &resp.Tenant, "Tenant Entitlements Updated")
}

func tenantUpdateQuotas(cfg *Config, printer *Printer, id string, q transport.TenantQuotas) {
	cl, cleanup, err := createTenantClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	resp, err := cl.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{
		TenantID: id,
		Quotas:   q,
	})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrUpdateTenantQuotasFailed, Err: err})
		return
	}
	printTenantInfo(printer, &resp.Tenant, "Tenant Quotas Updated")
}

// Output helpers

// printTenantInfo prints tenant information.
func printTenantInfo(printer *Printer, tenant *transport.TenantInfo, header string) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(tenant); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("%s:\n", header)
		printer.printf("  ID:      %s\n", tenant.ID)
		printer.printf("  Name:    %s\n", tenant.Name)
		printer.printf("  Created: %s\n", tenant.CreatedAt.Format(time.RFC3339))
		printer.printf("  Updated: %s\n", tenant.UpdatedAt.Format(time.RFC3339))
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// printTenantList prints a list of tenants.
func printTenantList(printer *Printer, tenants []transport.TenantInfo) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"tenants": tenants,
			"total":   len(tenants),
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable:
		if len(tenants) == 0 {
			printer.println("No tenants found")
			return
		}
		printer.printf("%-20s %-30s %-25s\n", "ID", "NAME", "CREATED")
		printer.println(repeatString("-", 77))
		for _, t := range tenants {
			printer.printf("%-20s %-30s %-25s\n",
				truncateString(t.ID, 20),
				truncateString(t.Name, 30),
				t.CreatedAt.Format("2006-01-02 15:04"))
		}
		printer.printf("\nTotal: %d tenant(s)\n", len(tenants))
	case OutputFormatText:
		if len(tenants) == 0 {
			printer.println("No tenants found")
			return
		}
		printer.println("Tenants:")
		for _, t := range tenants {
			printer.printf("  - %s (%s)\n", t.Name, t.ID)
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// printTenantBarrierStatus prints per-tenant barrier status.
func printTenantBarrierStatus(printer *Printer, resp *transport.TenantBarrierStatusResponse) {
	if resp == nil {
		return
	}
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		sealState := "unsealed"
		if resp.Sealed {
			sealState = "sealed"
		}
		printer.printf("Tenant Barrier Status:\n")
		printer.printf("  Tenant:          %s\n", resp.TenantID)
		printer.printf("  State:           %s\n", sealState)
		printer.printf("  Initialized:     %t\n", resp.Initialized)
		printer.printf("  Strategy:        %s\n", resp.Strategy)
		printer.printf("  Hardware Backed: %t\n", resp.HardwareBacked)
		if resp.ShamirThreshold > 0 {
			printer.printf("  Shamir:          %d-of-%d\n", resp.ShamirThreshold, resp.ShamirTotal)
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func init() {
	// tenant create flags
	tenantCreateCmd.Flags().String("id", "", "tenant ID (required)")
	tenantCreateCmd.Flags().String("name", "", "tenant display name (required)")
	tenantCreateCmd.Flags().String("isolation", "", "isolation mode: prefix (default) | barrier | volume | raft")
	tenantCreateCmd.Flags().Bool("barrier-auto-unseal", false, "system-managed auto-unseal for a dedicated-isolation tenant (entitlement-gated)")

	// tenant show flags
	tenantShowCmd.Flags().String("id", "", "tenant ID (required)")

	// tenant delete flags
	tenantDeleteCmd.Flags().String("id", "", "tenant ID (required)")

	// tenant barrier-init flags
	tenantBarrierInitCmd.Flags().String("id", "", "tenant ID (required)")
	tenantBarrierInitCmd.Flags().String("passphrase", "", "tenant admin passphrase (required for passphrase/shamir strategies)")
	tenantBarrierInitCmd.Flags().String("strategy", "", "seal strategy: passphrase (default) | none | shamir | tpm2 | pkcs11 | awskms | gcpkms | azurekv | vault")
	tenantBarrierInitCmd.Flags().Int("threshold", 0, "Shamir threshold (optional)")
	tenantBarrierInitCmd.Flags().Int("shares", 0, "total Shamir shares (optional)")

	// tenant barrier-unseal flags
	tenantBarrierUnsealCmd.Flags().String("id", "", "tenant ID (required)")
	tenantBarrierUnsealCmd.Flags().String("share", "", "base64-encoded Shamir share")

	// tenant barrier-status flags
	tenantBarrierStatusCmd.Flags().String("id", "", "tenant ID (required)")

	// tenant update-entitlements flags
	tenantUpdateEntitlementsCmd.Flags().String("id", "", "tenant ID (required)")
	tenantUpdateEntitlementsCmd.Flags().StringSlice("isolation-modes", nil, "permitted isolation modes (comma-separated): prefix,barrier,volume,raft")
	tenantUpdateEntitlementsCmd.Flags().Bool("allow-raft", false, "permit dedicated-raft databases")
	tenantUpdateEntitlementsCmd.Flags().Bool("allow-volume", false, "permit dedicated-volume storage")
	tenantUpdateEntitlementsCmd.Flags().Bool("allow-system-managed", false, "permit system-managed auto-unseal")

	// tenant update-quotas flags
	tenantUpdateQuotasCmd.Flags().String("id", "", "tenant ID (required)")
	tenantUpdateQuotasCmd.Flags().Int64("max-databases", 0, "max databases (0 = system default)")
	tenantUpdateQuotasCmd.Flags().Int64("max-keys", 0, "max keys")
	tenantUpdateQuotasCmd.Flags().Int64("max-collections", 0, "max collections")
	tenantUpdateQuotasCmd.Flags().Int64("max-storage-bytes", 0, "max storage bytes")
	tenantUpdateQuotasCmd.Flags().Int64("max-users", 0, "max users")
	tenantUpdateQuotasCmd.Flags().Int64("max-roles", 0, "max roles")
	tenantUpdateQuotasCmd.Flags().Int64("max-certificates", 0, "max certificates")

	// Build subcommand tree
	tenantCmd.AddCommand(tenantCreateCmd)
	tenantCmd.AddCommand(tenantListCmd)
	tenantCmd.AddCommand(tenantShowCmd)
	tenantCmd.AddCommand(tenantDeleteCmd)
	tenantCmd.AddCommand(tenantBarrierInitCmd)
	tenantCmd.AddCommand(tenantBarrierUnsealCmd)
	tenantCmd.AddCommand(tenantBarrierStatusCmd)
	tenantCmd.AddCommand(tenantUpdateEntitlementsCmd)
	tenantCmd.AddCommand(tenantUpdateQuotasCmd)

	// Register with root
	rootCmd.AddCommand(tenantCmd)
}
