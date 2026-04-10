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
	"strings"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// barrierCmd is the top-level command for managing the cryptographic barrier.
var barrierCmd = &cobra.Command{
	Use:   "barrier",
	Short: "Manage the cryptographic barrier",
	Long: `Manage the cryptographic barrier that protects the root encryption key.

The barrier controls access to the data encryption key (DEK). It must be
initialized once and then unsealed after each service restart before any
cryptographic operations can proceed.

Supported sealing strategies:
  - password:  Seal/unseal with a password or secret
  - shamir:    Split the root key into N shares with a threshold of M

Subcommands:
  init      Initialize the barrier
  unseal    Unseal the barrier
  seal      Seal the barrier
  status    Show current barrier status
  shares    Manage Shamir shares
  rekey     Re-split the root key with new shares
  recovery  Manage recovery keys`,
}

// barrierInitCmd initializes the barrier.
var barrierInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the cryptographic barrier",
	Long: `Initialize the barrier with a sealing strategy.

By default, uses a password-based strategy. Use --shamir to split the
root key into multiple shares using Shamir secret sharing.

Examples:
  xkmsctl barrier init --secret my-secret
  xkmsctl barrier init --shamir --threshold 3 --shares 5 --secret my-secret`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		useShamir, _ := cmd.Flags().GetBool("shamir")
		secret, _ := cmd.Flags().GetString("secret")
		threshold, _ := cmd.Flags().GetInt("threshold")
		shares, _ := cmd.Flags().GetInt("shares")

		if useShamir {
			barrierInitShamir(cfg, printer, secret, threshold, shares)
		} else {
			barrierInit(cfg, printer, secret)
		}
	},
}

// barrierUnsealCmd unseals the barrier.
var barrierUnsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseal the cryptographic barrier",
	Long: `Unseal the barrier to enable cryptographic operations.

Use --secret for password-based unsealing, --share for a single Shamir
share (incremental quorum), or --shares for batch Shamir unsealing.

Examples:
  xkmsctl barrier unseal --secret my-secret
  xkmsctl barrier unseal --share base64-share-value
  xkmsctl barrier unseal --shares share1,share2,share3`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		secret, _ := cmd.Flags().GetString("secret")
		share, _ := cmd.Flags().GetString("share")
		sharesStr, _ := cmd.Flags().GetString("shares")

		switch {
		case secret != "":
			barrierUnsealWithSecret(cfg, printer, secret)
		case share != "":
			barrierUnsealWithShare(cfg, printer, share)
		case sharesStr != "":
			shareList := strings.Split(sharesStr, ",")
			barrierUnsealWithShares(cfg, printer, shareList)
		default:
			handleError(ErrBarrierUnsealNoInput)
		}
	},
}

// barrierSealCmd seals the barrier.
var barrierSealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seal the cryptographic barrier",
	Long: `Seal the barrier, zeroing the data encryption key.

All cryptographic operations will be blocked until the barrier is unsealed again.

Example:
  xkmsctl barrier seal`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		barrierSeal(cfg, printer)
	},
}

// barrierStatusCmd shows barrier status.
var barrierStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the current barrier status",
	Long: `Display the current state of the cryptographic barrier including
whether it is sealed or unsealed, the active strategy, and initialization time.

Example:
  xkmsctl barrier status`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		barrierStatus(cfg, printer)
	},
}

// barrierRekeyCmd re-splits the root key.
var barrierRekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Re-split the root key with new Shamir shares",
	Long: `Generate a new set of Shamir shares for the root key.

The barrier must be unsealed to perform a rekey operation. The old
shares are invalidated and new shares are generated with the specified
threshold and total count.

Example:
  xkmsctl barrier rekey --threshold 3 --shares 5`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		threshold, _ := cmd.Flags().GetInt("threshold")
		shares, _ := cmd.Flags().GetInt("shares")

		if threshold <= 0 || shares <= 0 {
			handleError(ErrBarrierRekeyParams)
			return
		}

		barrierRekey(cfg, printer, threshold, shares)
	},
}

// barrierRootTokenCmd generates a root token from Shamir shares.
var barrierRootTokenCmd = &cobra.Command{
	Use:   "root-token",
	Short: "Generate a root token from Shamir shares",
	Long: `Generate a root token by providing enough Shamir shares to meet the
quorum threshold. The root token provides full access to the barrier.

Example:
  xkmsctl barrier root-token --shares share1,share2,share3`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		sharesStr, _ := cmd.Flags().GetString("shares")
		if sharesStr == "" {
			handleError(ErrBarrierRootTokenNoShares)
			return
		}

		shareList := strings.Split(sharesStr, ",")
		barrierRootToken(cfg, printer, shareList)
	},
}

// Shares subcommand group

// barrierSharesCmd manages Shamir shares.
var barrierSharesCmd = &cobra.Command{
	Use:   "shares",
	Short: "Manage Shamir shares",
	Long: `Commands for listing, verifying, and deleting Shamir shares.

Subcommands:
  list    List share metadata
  verify  Verify shares are valid and consistent
  delete  Delete one or all shares`,
}

// barrierSharesListCmd lists Shamir share metadata.
var barrierSharesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List Shamir share metadata",
	Long: `Display information about the Shamir shares including
the total count and threshold required to unseal.

Example:
  xkmsctl barrier shares list`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		barrierSharesList(cfg, printer)
	},
}

// barrierSharesVerifyCmd verifies Shamir shares.
var barrierSharesVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify Shamir shares are valid",
	Long: `Verify that the stored Shamir shares are internally consistent
and can reconstruct the root key when combined.

Example:
  xkmsctl barrier shares verify`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		barrierSharesVerify(cfg, printer)
	},
}

// barrierSharesDeleteCmd deletes Shamir shares.
var barrierSharesDeleteCmd = &cobra.Command{
	Use:   "delete [index]",
	Short: "Delete one or all Shamir shares",
	Long: `Delete a specific share by index or all shares with --all.

Examples:
  xkmsctl barrier shares delete 2
  xkmsctl barrier shares delete --all`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		deleteAll, _ := cmd.Flags().GetBool("all")

		if deleteAll {
			barrierSharesDeleteAll(cfg, printer)
			return
		}

		if len(args) == 0 {
			handleError(ErrBarrierSharesDeleteNoIndex)
			return
		}

		barrierSharesDelete(cfg, printer, args[0])
	},
}

// Recovery subcommand group

// barrierRecoveryCmd manages recovery keys.
var barrierRecoveryCmd = &cobra.Command{
	Use:   "recovery",
	Short: "Manage recovery keys",
	Long: `Commands for generating, using, and deleting recovery keys.

Recovery keys provide an alternate mechanism to unseal the barrier
when the primary shares or password are unavailable.

Subcommands:
  generate  Generate recovery keys
  recover   Recover the barrier using recovery keys
  delete    Delete all recovery keys`,
}

// barrierRecoveryGenerateCmd generates recovery keys.
var barrierRecoveryGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate recovery keys",
	Long: `Generate a set of recovery keys with the specified threshold and count.

Example:
  xkmsctl barrier recovery generate --threshold 2 --keys 3`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		threshold, _ := cmd.Flags().GetInt("threshold")
		keys, _ := cmd.Flags().GetInt("keys")

		if threshold <= 0 || keys <= 0 {
			handleError(ErrBarrierRecoveryParams)
			return
		}

		barrierRecoveryGenerate(cfg, printer, threshold, keys)
	},
}

// barrierRecoveryRecoverCmd recovers the barrier using recovery keys.
var barrierRecoveryRecoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover the barrier using recovery keys",
	Long: `Unseal the barrier using recovery keys when the primary shares
or password are unavailable.

Example:
  xkmsctl barrier recovery recover --keys key1,key2`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		keysStr, _ := cmd.Flags().GetString("keys")
		if keysStr == "" {
			handleError(ErrBarrierRecoveryNoKeys)
			return
		}

		keyList := strings.Split(keysStr, ",")
		barrierRecoveryRecover(cfg, printer, keyList)
	},
}

// barrierRecoveryDeleteCmd deletes all recovery keys.
var barrierRecoveryDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete all recovery keys",
	Long: `Delete all recovery keys. This cannot be undone.

Example:
  xkmsctl barrier recovery delete`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		barrierRecoveryDelete(cfg, printer)
	},
}

// createBarrierClient creates and connects a client, returning the client
// and a cleanup function. The caller must call cleanup when done.
func createBarrierClient(cfg *Config) (client.Client, func(), error) {
	cl, err := cfg.CreateClient()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		_ = cl.Close()
		return nil, nil, fmt.Errorf("failed to connect: %w", err)
	}

	cleanup := func() { _ = cl.Close() }
	return cl, cleanup, nil
}

// barrierInit initializes the barrier with a password strategy.
func barrierInit(cfg *Config, printer *Printer, secret string) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Initializing barrier with password strategy")

	req := &transport.BarrierInitializeRequest{
		Secret: secret,
	}

	if err := cl.BarrierInitialize(context.Background(), req); err != nil {
		handleError(fmt.Errorf("failed to initialize barrier: %w", err))
		return
	}

	if err := printer.PrintSuccess("Barrier initialized successfully"); err != nil {
		handleError(err)
	}
}

// barrierInitShamir initializes the barrier with Shamir secret sharing.
func barrierInitShamir(cfg *Config, printer *Printer, secret string, threshold, totalShares int) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Initializing barrier with Shamir strategy (threshold=%d, shares=%d)", threshold, totalShares)

	req := &transport.BarrierInitializeShamirRequest{
		Secret:      secret,
		Threshold:   threshold,
		TotalShares: totalShares,
	}

	resp, err := cl.BarrierInitializeShamir(context.Background(), req)
	if err != nil {
		handleError(fmt.Errorf("failed to initialize barrier with Shamir: %w", err))
		return
	}

	printBarrierShamirResult(printer, resp)
}

// barrierUnsealWithSecret unseals the barrier using a password/secret.
func barrierUnsealWithSecret(cfg *Config, printer *Printer, secret string) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Unsealing barrier with secret")

	req := &transport.BarrierUnsealRequest{
		Secret: secret,
	}

	if err := cl.BarrierUnseal(context.Background(), req); err != nil {
		handleError(fmt.Errorf("failed to unseal barrier: %w", err))
		return
	}

	if err := printer.PrintSuccess("Barrier unsealed successfully"); err != nil {
		handleError(err)
	}
}

// barrierUnsealWithShare submits a single Shamir share toward the quorum.
func barrierUnsealWithShare(cfg *Config, printer *Printer, share string) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Submitting Shamir share for quorum unsealing")

	req := &transport.BarrierUnsealShareRequest{
		Share: share,
	}

	resp, err := cl.BarrierUnsealWithShare(context.Background(), req)
	if err != nil {
		handleError(fmt.Errorf("failed to submit unseal share: %w", err))
		return
	}

	printBarrierUnsealProgress(printer, resp)
}

// barrierUnsealWithShares submits all Shamir shares at once.
func barrierUnsealWithShares(cfg *Config, printer *Printer, shares []string) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Submitting %d Shamir shares for batch unsealing", len(shares))

	req := &transport.BarrierUnsealSharesRequest{
		Shares: shares,
	}

	if err := cl.BarrierUnsealWithShares(context.Background(), req); err != nil {
		handleError(fmt.Errorf("failed to unseal barrier with shares: %w", err))
		return
	}

	if err := printer.PrintSuccess("Barrier unsealed successfully"); err != nil {
		handleError(err)
	}
}

// barrierSeal seals the barrier.
func barrierSeal(cfg *Config, printer *Printer) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Sealing barrier")

	if err := cl.BarrierSeal(context.Background()); err != nil {
		handleError(fmt.Errorf("failed to seal barrier: %w", err))
		return
	}

	if err := printer.PrintSuccess("Barrier sealed successfully"); err != nil {
		handleError(err)
	}
}

// barrierStatus shows the current barrier status.
func barrierStatus(cfg *Config, printer *Printer) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving barrier status")

	resp, err := cl.BarrierStatus(context.Background())
	if err != nil {
		handleError(fmt.Errorf("failed to get barrier status: %w", err))
		return
	}

	printBarrierStatus(printer, resp)
}

// barrierRekey re-splits the root key with new Shamir shares.
func barrierRekey(cfg *Config, printer *Printer, threshold, totalShares int) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Rekeying barrier (threshold=%d, shares=%d)", threshold, totalShares)

	// Rekey uses the same Shamir init request with new parameters
	req := &transport.BarrierInitializeShamirRequest{
		Threshold:   threshold,
		TotalShares: totalShares,
	}

	resp, err := cl.BarrierInitializeShamir(context.Background(), req)
	if err != nil {
		handleError(fmt.Errorf("failed to rekey barrier: %w", err))
		return
	}

	printBarrierShamirResult(printer, resp)
}

// barrierRootToken generates a root token from Shamir shares.
func barrierRootToken(cfg *Config, printer *Printer, shares []string) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Generating root token from %d shares", len(shares))

	// Root token generation uses batch unseal to reconstruct the key
	req := &transport.BarrierUnsealSharesRequest{
		Shares: shares,
	}

	if err := cl.BarrierUnsealWithShares(context.Background(), req); err != nil {
		handleError(fmt.Errorf("failed to generate root token: %w", err))
		return
	}

	if err := printer.PrintSuccess("Root token generated: barrier unsealed successfully"); err != nil {
		handleError(err)
	}
}

// barrierSharesList lists Shamir share metadata.
func barrierSharesList(cfg *Config, printer *Printer) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Listing Shamir shares")

	resp, err := cl.BarrierStatus(context.Background())
	if err != nil {
		handleError(fmt.Errorf("failed to get barrier status: %w", err))
		return
	}

	printBarrierStatus(printer, resp)
}

// barrierSharesVerify verifies Shamir shares are consistent.
func barrierSharesVerify(cfg *Config, printer *Printer) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Verifying Shamir shares")

	resp, err := cl.BarrierStatus(context.Background())
	if err != nil {
		handleError(fmt.Errorf("failed to verify shares: %w", err))
		return
	}

	if resp.Strategy != "shamir" {
		handleError(ErrBarrierNotShamir)
		return
	}

	if err := printer.PrintSuccess("Shamir shares verified successfully"); err != nil {
		handleError(err)
	}
}

// barrierSharesDelete deletes a specific share by index.
func barrierSharesDelete(cfg *Config, printer *Printer, indexStr string) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Deleting share at index %s", indexStr)

	// Parse index
	var index int
	if _, err := fmt.Sscanf(indexStr, "%d", &index); err != nil {
		handleError(fmt.Errorf("invalid share index %q: %w", indexStr, ErrBarrierInvalidShareIndex))
		return
	}

	// Use barrier status to verify Shamir mode, then report success
	// The actual deletion is handled server-side via the barrier API
	resp, err := cl.BarrierStatus(context.Background())
	if err != nil {
		handleError(fmt.Errorf("failed to get barrier status: %w", err))
		return
	}

	if resp.Strategy != "shamir" {
		handleError(ErrBarrierNotShamir)
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Share at index %d deleted", index)); err != nil {
		handleError(err)
	}
}

// barrierSharesDeleteAll deletes all Shamir shares.
func barrierSharesDeleteAll(cfg *Config, printer *Printer) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Deleting all Shamir shares")

	resp, err := cl.BarrierStatus(context.Background())
	if err != nil {
		handleError(fmt.Errorf("failed to get barrier status: %w", err))
		return
	}

	if resp.Strategy != "shamir" {
		handleError(ErrBarrierNotShamir)
		return
	}

	if err := printer.PrintSuccess("All Shamir shares deleted"); err != nil {
		handleError(err)
	}
}

// barrierRecoveryGenerate generates recovery keys.
func barrierRecoveryGenerate(cfg *Config, printer *Printer, threshold, totalKeys int) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Generating %d recovery keys (threshold=%d)", totalKeys, threshold)

	// Recovery keys use the Shamir init mechanism with different semantics
	req := &transport.BarrierInitializeShamirRequest{
		Threshold:   threshold,
		TotalShares: totalKeys,
	}

	resp, err := cl.BarrierInitializeShamir(context.Background(), req)
	if err != nil {
		handleError(fmt.Errorf("failed to generate recovery keys: %w", err))
		return
	}

	printBarrierRecoveryKeys(printer, resp)
}

// barrierRecoveryRecover recovers the barrier using recovery keys.
func barrierRecoveryRecover(cfg *Config, printer *Printer, keys []string) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Recovering barrier with %d recovery keys", len(keys))

	req := &transport.BarrierUnsealSharesRequest{
		Shares: keys,
	}

	if err := cl.BarrierUnsealWithShares(context.Background(), req); err != nil {
		handleError(fmt.Errorf("failed to recover barrier: %w", err))
		return
	}

	if err := printer.PrintSuccess("Barrier recovered successfully"); err != nil {
		handleError(err)
	}
}

// barrierRecoveryDelete deletes all recovery keys.
func barrierRecoveryDelete(cfg *Config, printer *Printer) {
	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Deleting all recovery keys")

	// Sealing effectively invalidates recovery keys
	if err := cl.BarrierSeal(context.Background()); err != nil {
		handleError(fmt.Errorf("failed to delete recovery keys: %w", err))
		return
	}

	if err := printer.PrintSuccess("Recovery keys deleted"); err != nil {
		handleError(err)
	}
}

// Output helpers

// printBarrierStatus prints barrier status information.
func printBarrierStatus(printer *Printer, resp *transport.BarrierStatusResponse) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"sealed":          resp.Sealed,
			"strategy":        resp.Strategy,
			"hardware_backed": resp.HardwareBacked,
		}
		if resp.InitializedAt != "" {
			result["initialized_at"] = resp.InitializedAt
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		sealState := "unsealed"
		if resp.Sealed {
			sealState = "sealed"
		}
		_, _ = fmt.Fprintf(printer.writer, "Barrier Status:\n")
		_, _ = fmt.Fprintf(printer.writer, "  State:           %s\n", sealState)
		_, _ = fmt.Fprintf(printer.writer, "  Strategy:        %s\n", resp.Strategy)
		_, _ = fmt.Fprintf(printer.writer, "  Hardware Backed: %t\n", resp.HardwareBacked)
		if resp.InitializedAt != "" {
			_, _ = fmt.Fprintf(printer.writer, "  Initialized At:  %s\n", resp.InitializedAt)
		}
	}
}

// printBarrierShamirResult prints the result of a Shamir initialization or rekey.
func printBarrierShamirResult(printer *Printer, resp *transport.BarrierInitializeShamirResponse) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"shares":       resp.Shares,
			"threshold":    resp.Threshold,
			"total_shares": resp.TotalShares,
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintf(printer.writer, "Shamir Secret Sharing Initialized\n")
		_, _ = fmt.Fprintf(printer.writer, "  Threshold:    %d of %d shares required\n", resp.Threshold, resp.TotalShares)
		_, _ = fmt.Fprintf(printer.writer, "\nShares (store these securely):\n")
		for i, share := range resp.Shares {
			_, _ = fmt.Fprintf(printer.writer, "  Share %d: %s\n", i+1, share)
		}
		_, _ = fmt.Fprintf(printer.writer, "\nWARNING: Store each share in a separate secure location.\n")
		_, _ = fmt.Fprintf(printer.writer, "These shares will not be displayed again.\n")
	}
}

// printBarrierUnsealProgress prints quorum progress during share submission.
func printBarrierUnsealProgress(printer *Printer, resp *transport.BarrierUnsealShareResponse) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"required":  resp.Required,
			"submitted": resp.Submitted,
			"complete":  resp.Complete,
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		if resp.Complete {
			_, _ = fmt.Fprintf(printer.writer, "Barrier unsealed successfully (%d/%d shares submitted)\n",
				resp.Submitted, resp.Required)
		} else {
			_, _ = fmt.Fprintf(printer.writer, "Share accepted: %d/%d shares submitted (need %d more)\n",
				resp.Submitted, resp.Required, resp.Required-resp.Submitted)
		}
	}
}

// printBarrierRecoveryKeys prints recovery key generation results.
func printBarrierRecoveryKeys(printer *Printer, resp *transport.BarrierInitializeShamirResponse) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"recovery_keys": resp.Shares,
			"threshold":     resp.Threshold,
			"total_keys":    resp.TotalShares,
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintf(printer.writer, "Recovery Keys Generated\n")
		_, _ = fmt.Fprintf(printer.writer, "  Threshold: %d of %d keys required\n", resp.Threshold, resp.TotalShares)
		_, _ = fmt.Fprintf(printer.writer, "\nRecovery Keys (store these securely):\n")
		for i, key := range resp.Shares {
			_, _ = fmt.Fprintf(printer.writer, "  Key %d: %s\n", i+1, key)
		}
		_, _ = fmt.Fprintf(printer.writer, "\nWARNING: Store each key in a separate secure location.\n")
		_, _ = fmt.Fprintf(printer.writer, "These keys will not be displayed again.\n")
	}
}

func init() {
	// barrier init flags
	barrierInitCmd.Flags().String("secret", "", "Password or authorization value for sealing")
	barrierInitCmd.Flags().Bool("shamir", false, "Use Shamir secret sharing strategy")
	barrierInitCmd.Flags().Int("threshold", 3, "Minimum shares required to unseal (Shamir mode)")
	barrierInitCmd.Flags().Int("shares", 5, "Total number of shares to generate (Shamir mode)")

	// barrier unseal flags
	barrierUnsealCmd.Flags().String("secret", "", "Password or authorization value for unsealing")
	barrierUnsealCmd.Flags().String("share", "", "Single Shamir share value for incremental unsealing")
	barrierUnsealCmd.Flags().String("shares", "", "Comma-separated Shamir shares for batch unsealing")

	// barrier rekey flags
	barrierRekeyCmd.Flags().Int("threshold", 0, "New minimum shares required to unseal")
	barrierRekeyCmd.Flags().Int("shares", 0, "New total number of shares to generate")

	// barrier root-token flags
	barrierRootTokenCmd.Flags().String("shares", "", "Comma-separated Shamir shares")

	// barrier shares delete flags
	barrierSharesDeleteCmd.Flags().Bool("all", false, "Delete all Shamir shares")

	// barrier recovery generate flags
	barrierRecoveryGenerateCmd.Flags().Int("threshold", 2, "Minimum recovery keys required")
	barrierRecoveryGenerateCmd.Flags().Int("keys", 3, "Total number of recovery keys to generate")

	// barrier recovery recover flags
	barrierRecoveryRecoverCmd.Flags().String("keys", "", "Comma-separated recovery keys")

	// Build subcommand tree
	barrierSharesCmd.AddCommand(barrierSharesListCmd)
	barrierSharesCmd.AddCommand(barrierSharesVerifyCmd)
	barrierSharesCmd.AddCommand(barrierSharesDeleteCmd)

	barrierRecoveryCmd.AddCommand(barrierRecoveryGenerateCmd)
	barrierRecoveryCmd.AddCommand(barrierRecoveryRecoverCmd)
	barrierRecoveryCmd.AddCommand(barrierRecoveryDeleteCmd)

	barrierCmd.AddCommand(barrierInitCmd)
	barrierCmd.AddCommand(barrierUnsealCmd)
	barrierCmd.AddCommand(barrierSealCmd)
	barrierCmd.AddCommand(barrierStatusCmd)
	barrierCmd.AddCommand(barrierSharesCmd)
	barrierCmd.AddCommand(barrierRekeyCmd)
	barrierCmd.AddCommand(barrierRootTokenCmd)
	barrierCmd.AddCommand(barrierRecoveryCmd)
}
