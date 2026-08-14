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
	"sort"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// policyCmd is the top-level command for PCR policy management.
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage PCR policies",
	Long: `Manage TPM 2.0 PCR policies used for sealed-secret authorization.

A policy captures the values of a set of PCRs in a given bank. Sealed
secrets bound to a policy can only be unsealed while the platform's
PCRs match the captured values.

Subcommands:
  create   Create a new policy from current PCR values
  list     List all policies
  get      Show a policy
  delete   Delete a policy
  refresh  Re-capture a policy from current PCR values
  verify   Verify a policy against current PCR values
  export   Export a policy`,
}

// policyCreateCmd creates a new PCR policy.
var policyCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new PCR policy",
	Long: `Create a new PCR policy capturing the current values of the
selected PCRs.

Examples:
  xkmsctl policy create boot --pcrs 0,2,4,7
  xkmsctl policy create boot --bank sha384 --pcrs 0,7`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		bank, _ := cmd.Flags().GetString("bank")
		pcrs, _ := cmd.Flags().GetIntSlice("pcrs")

		if len(pcrs) == 0 {
			handleError(ErrPolicyPCRsRequired)
			return
		}

		policyCreate(cfg, printer, &client.PolicyCreateRequest{
			Name: args[0],
			Bank: bank,
			PCRs: pcrs,
		})
	},
}

// policyListCmd lists all policies.
var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all PCR policies",
	Long: `List all PCR policies.

Example:
  xkmsctl policy list`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		policyList(cfg, printer)
	},
}

// policyGetCmd shows a policy.
var policyGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Show a PCR policy",
	Long: `Display a PCR policy including its captured PCR values.

Example:
  xkmsctl policy get boot`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		policyGet(cfg, printer, args[0])
	},
}

// policyDeleteCmd deletes a policy.
var policyDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a PCR policy",
	Long: `Delete a PCR policy.

Example:
  xkmsctl policy delete boot`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		policyDelete(cfg, printer, args[0])
	},
}

// policyRefreshCmd refreshes a policy with current PCR values.
var policyRefreshCmd = &cobra.Command{
	Use:   "refresh <name>",
	Short: "Refresh a PCR policy",
	Long: `Re-capture a policy from the platform's current PCR values.
Use this after an expected platform change (for example a firmware or
kernel update) to rebind the policy to the new measurements.

Example:
  xkmsctl policy refresh boot`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		policyRefresh(cfg, printer, args[0])
	},
}

// policyVerifyCmd verifies a policy against current PCR values.
var policyVerifyCmd = &cobra.Command{
	Use:   "verify <name>",
	Short: "Verify a PCR policy",
	Long: `Verify a policy against the platform's current PCR values.
The command exits non-zero when the policy no longer matches.

Example:
  xkmsctl policy verify boot`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		policyVerify(cfg, printer, args[0])
	},
}

// policyExportCmd exports a policy.
var policyExportCmd = &cobra.Command{
	Use:   "export <name>",
	Short: "Export a PCR policy",
	Long: `Export a policy document. Without --output the document is
printed to stdout.

Example:
  xkmsctl policy export boot --output boot-policy.json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		outputFile, _ := cmd.Flags().GetString("output")

		policyExport(cfg, printer, args[0], outputFile)
	},
}

// createPolicyClient creates and connects a client, returning the client
// and a cleanup function. The caller must call cleanup when done.
func createPolicyClient(cfg *Config) (client.Client, func(), error) {
	cl, err := cfg.CreateClient()
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateClientFailed, Err: err}
	}

	if err := cl.Connect(context.Background()); err != nil {
		_ = cl.Close()
		return nil, nil, &WrappedError{Sentinel: ErrConnectFailed, Err: err}
	}

	return cl, func() { _ = cl.Close() }, nil
}

// policyCreate creates a policy via the SDK client.
func policyCreate(cfg *Config, printer *Printer, req *client.PolicyCreateRequest) {
	cl, cleanup, err := createPolicyClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Creating policy %q bank=%q pcrs=%v", req.Name, req.Bank, req.PCRs)

	resp, err := cl.PolicyCreate(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreatePolicyFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintf(printer.writer, "Policy Created:\n")
		printPolicyBody(printer, resp.Name, resp.Bank, resp.PCRs, resp.Values, resp.CreatedAt, "")
	}
}

// policyList lists policies via the SDK client.
func policyList(cfg *Config, printer *Printer) {
	cl, cleanup, err := createPolicyClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Listing policies")

	resp, err := cl.PolicyList(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrListPoliciesFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(map[string]interface{}{
			"policies": resp.Policies,
			"total":    len(resp.Policies),
		}); err != nil {
			handleError(err)
		}
	case OutputFormatTable:
		if len(resp.Policies) == 0 {
			_, _ = fmt.Fprintln(printer.writer, "No policies found")
			return
		}
		_, _ = fmt.Fprintf(printer.writer, "%-24s %-10s %-20s %-25s\n", "NAME", "BANK", "PCRS", "CREATED")
		_, _ = fmt.Fprintln(printer.writer, repeatString("-", 81))
		for _, p := range resp.Policies {
			_, _ = fmt.Fprintf(printer.writer, "%-24s %-10s %-20s %-25s\n",
				truncateString(p.Name, 24),
				truncateString(p.Bank, 10),
				truncateString(fmt.Sprint(p.PCRs), 20),
				truncateString(p.CreatedAt, 25))
		}
		_, _ = fmt.Fprintf(printer.writer, "\nTotal: %d policy(ies)\n", len(resp.Policies))
	case OutputFormatText:
		if len(resp.Policies) == 0 {
			_, _ = fmt.Fprintln(printer.writer, "No policies found")
			return
		}
		_, _ = fmt.Fprintln(printer.writer, "Policies:")
		for _, p := range resp.Policies {
			_, _ = fmt.Fprintf(printer.writer, "  - %s (%s %v)\n", p.Name, p.Bank, p.PCRs)
		}
	}
}

// policyGet shows a policy via the SDK client.
func policyGet(cfg *Config, printer *Printer, name string) {
	cl, cleanup, err := createPolicyClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving policy %q", name)

	resp, err := cl.PolicyGet(context.Background(), &client.PolicyGetRequest{Name: name})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetPolicyFailed, Err: err})
		return
	}

	printPolicy(printer, resp, "Policy")
}

// policyDelete deletes a policy via the SDK client.
func policyDelete(cfg *Config, printer *Printer, name string) {
	cl, cleanup, err := createPolicyClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Deleting policy %q", name)

	if err := cl.PolicyDelete(context.Background(), &client.PolicyDeleteRequest{Name: name}); err != nil {
		handleError(&WrappedError{Sentinel: ErrDeletePolicyFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Policy %q deleted", name)); err != nil {
		handleError(err)
	}
}

// policyRefresh refreshes a policy via the SDK client.
func policyRefresh(cfg *Config, printer *Printer, name string) {
	cl, cleanup, err := createPolicyClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Refreshing policy %q", name)

	resp, err := cl.PolicyRefresh(context.Background(), &client.PolicyRefreshRequest{Name: name})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrRefreshPolicyFailed, Err: err})
		return
	}

	printPolicy(printer, resp, "Policy Refreshed")
}

// policyVerify verifies a policy via the SDK client.
func policyVerify(cfg *Config, printer *Printer, name string) {
	cl, cleanup, err := createPolicyClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Verifying policy %q", name)

	resp, err := cl.PolicyVerify(context.Background(), &client.PolicyVerifyRequest{Name: name})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrVerifyPolicyFailed, Err: err})
		return
	}

	if !resp.Valid {
		detail := resp.Message
		if detail == "" {
			detail = name
		}
		handleError(&WrappedDetailError{Sentinel: ErrPolicyVerifyMismatch, Detail: detail})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Policy %q matches current PCR values", name)); err != nil {
		handleError(err)
	}
}

// policyExport exports a policy via the SDK client.
func policyExport(cfg *Config, printer *Printer, name, outputFile string) {
	cl, cleanup, err := createPolicyClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Exporting policy %q", name)

	resp, err := cl.PolicyExport(context.Background(), &client.PolicyExportRequest{Name: name})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrExportPolicyFailed, Err: err})
		return
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(resp.Data), 0600); err != nil {
			handleError(&WrappedError{Sentinel: ErrWritePolicyFileFailed, Err: err})
			return
		}
		if err := printer.PrintSuccess(fmt.Sprintf("Policy %q exported to %s", name, outputFile)); err != nil {
			handleError(err)
		}
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintln(printer.writer, resp.Data)
	}
}

// printPolicy prints a policy document with a heading.
func printPolicy(printer *Printer, resp *client.PolicyGetResponse, heading string) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintf(printer.writer, "%s:\n", heading)
		printPolicyBody(printer, resp.Name, resp.Bank, resp.PCRs, resp.Values, resp.CreatedAt, resp.UpdatedAt)
	}
}

// printPolicyBody prints the shared policy fields for text/table output.
func printPolicyBody(printer *Printer, name, bank string, pcrs []int, values map[int]string, createdAt, updatedAt string) {
	_, _ = fmt.Fprintf(printer.writer, "  Name:    %s\n", name)
	_, _ = fmt.Fprintf(printer.writer, "  Bank:    %s\n", bank)
	_, _ = fmt.Fprintf(printer.writer, "  PCRs:    %v\n", pcrs)
	_, _ = fmt.Fprintf(printer.writer, "  Created: %s\n", createdAt)
	if updatedAt != "" {
		_, _ = fmt.Fprintf(printer.writer, "  Updated: %s\n", updatedAt)
	}
	if len(values) > 0 {
		indexes := make([]int, 0, len(values))
		for idx := range values {
			indexes = append(indexes, idx)
		}
		sort.Ints(indexes)
		_, _ = fmt.Fprintln(printer.writer, "  Values:")
		for _, idx := range indexes {
			_, _ = fmt.Fprintf(printer.writer, "    PCR %2d: %s\n", idx, values[idx])
		}
	}
}

func init() {
	// policy create flags
	policyCreateCmd.Flags().String("bank", "sha256", "PCR bank (sha1, sha256, sha384, sha512)")
	policyCreateCmd.Flags().IntSlice("pcrs", nil, "comma-separated PCR indexes (required)")

	// policy export flags
	policyExportCmd.Flags().String("output", "", "write the exported policy to a file (mode 0600)")

	// Build subcommand tree
	policyCmd.AddCommand(policyCreateCmd)
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyGetCmd)
	policyCmd.AddCommand(policyDeleteCmd)
	policyCmd.AddCommand(policyRefreshCmd)
	policyCmd.AddCommand(policyVerifyCmd)
	policyCmd.AddCommand(policyExportCmd)

	// Register with root
	rootCmd.AddCommand(policyCmd)
}
