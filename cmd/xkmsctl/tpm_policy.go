// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"path/filepath"
	"sort"
	"strings"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// tpmCmd groups the TPM policy commands.
var tpmCmd = &cobra.Command{
	Use:   "tpm",
	Short: "Manage TPM policies and the TPM policy authority",
	Long: `Manage named TPM policies: conditions (PCR states, the object's
password, TPM localities) that many TPM keys and sealed objects share. Updating or revoking a policy re-approves or withdraws it
without re-keying the objects bound to it.

A tenant-scoped caller manages its own tenant's policies; a system caller
may address any tenant with --tenant.

Subcommands:
  policy      Create, list, update, revoke, verify and delete policies
  authority   Rotate the tenant's policy authority`,
}

// tpmPolicyCmd groups the named-policy commands.
var tpmPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage named TPM policies",
	Long: `Manage named TPM policies.

Subcommands:
  create        Create a policy over the TPM's live PCR values
  describe      Set a policy's description
  list          List policies
  get           Show a policy
  update        Re-capture a policy's PCR values and re-approve it
  revoke        Withdraw a policy's approval
  verify        Compare a policy with the live PCR values
  delete        Delete a policy no object uses
  objects       List the keys and sealed objects bound to a policy
  auto-unseal   Mark (or unmark) the policy barrier auto-unseal uses`,
}

// tpmPolicyCreateCmd creates a named TPM policy.
var tpmPolicyCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a TPM policy over the live PCR values",
	Long: `Create a named TPM policy. Its PCR values are read from the TPM, never
supplied: the policy approves the platform state at the moment of creation.

A policy is an OR of branches, each an AND of conditions. --pcrs (with
--bank) creates the common policy of one branch holding one pcr condition.
--branch, repeatable, gives each branch as conditions joined by ";":

  pcr=[BANK:]LIST   the PCRs in LIST of BANK (sha256 when omitted)
  auth_value        the object's password
  locality=LIST     the TPM localities (0-4) in LIST

LIST is comma-separated indices or ranges ("0,7" or "0-7"). Branches are
tried in order when an object is used. --pcrs and --branch are mutually
exclusive.

Examples:
  xkmsctl tpm policy create boot --pcrs 0,7 --description "firmware and Secure Boot"
  xkmsctl tpm policy create boot --bank sha384 --pcrs 0,7 --auto-unseal
  xkmsctl tpm policy create boot-or-pin --branch 'pcr=sha256:0,7' --branch 'auth_value'
  xkmsctl tpm policy create strict --branch 'pcr=sha256:0,7;auth_value;locality=0'`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		description := fr.String("description")
		bank := fr.String("bank")
		pcrs := fr.IntSlice("pcrs")
		specs := fr.StringArray("branch")
		autoUnseal := fr.Bool("auto-unseal")
		tenant := fr.String("tenant")
		ownerAuth := fr.String("owner-auth")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		selection, err := pcrIndices(pcrs)
		if err != nil {
			handleError(err)
			return
		}
		branches, err := client.TPMPolicyBranches(bank, selection, specs)
		if err != nil {
			handleError(err)
			return
		}
		auth, err := resolveOwnerAuth(ownerAuth)
		if err != nil {
			handleError(err)
			return
		}
		cfg := getConfig()
		runClientCall(cfg, "Creating TPM policy "+args[0], ErrCreateTPMPolicyFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.TPMPolicyCreate(ctx, &client.TPMPolicyCreateRequest{
				TenantID: tenant, Name: args[0], Description: description, Branches: branches,
				AutoUnseal: autoUnseal, OwnerAuth: auth,
			})
		}, printTPMPolicyResult("TPM Policy Created"))
	},
}

// tpmPolicyDescribeCmd replaces a policy's description.
var tpmPolicyDescribeCmd = &cobra.Command{
	Use:   "describe <name> <text>",
	Short: "Set a TPM policy's description",
	Long: `Replace a policy's free-text description; an empty text clears it.

Example:
  xkmsctl tpm policy describe boot "firmware and Secure Boot state"`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		tenant, ok := tenantFlag(cmd)
		if !ok {
			return
		}
		runClientCall(getConfig(), "Setting the description of TPM policy "+args[0], ErrTPMPolicyDescribeFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.TPMPolicySetDescription(ctx, &client.TPMPolicyDescriptionRequest{TenantID: tenant, Name: args[0], Description: args[1]})
		}, printTPMPolicyResult("TPM Policy"))
	},
}

// tpmPolicyListCmd lists TPM policies.
var tpmPolicyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List TPM policies",
	Long: `List the tenant's named TPM policies.

Example:
  xkmsctl tpm policy list`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		tenant, ok := tenantFlag(cmd)
		if !ok {
			return
		}
		runClientCall(getConfig(), "Listing TPM policies", ErrListTPMPoliciesFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.TPMPolicyList(ctx, &client.TPMPolicyListRequest{TenantID: tenant})
		}, printTPMPolicyList)
	},
}

// newTPMPolicyNameCmd returns a command that runs one policy-name operation.
func newTPMPolicyNameCmd(use, short, long, verbose string, failure error,
	call func(context.Context, client.Client, *client.TPMPolicyRequest) (any, error), show func(*Printer, any)) *cobra.Command {

	return &cobra.Command{
		Use:   use + " <name>",
		Short: short,
		Long:  long,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			tenant, ok := tenantFlag(cmd)
			if !ok {
				return
			}
			req := &client.TPMPolicyRequest{TenantID: tenant, Name: args[0]}
			runClientCall(getConfig(), verbose+" "+args[0], failure, func(ctx context.Context, cl client.Client) (any, error) {
				return call(ctx, cl, req)
			}, show)
		},
	}
}

var (
	// tpmPolicyGetCmd shows a TPM policy.
	tpmPolicyGetCmd = newTPMPolicyNameCmd("get", "Show a TPM policy",
		"Display a TPM policy, its captured PCR values and its approval.\n\nExample:\n  xkmsctl tpm policy get boot",
		"Retrieving TPM policy", ErrGetTPMPolicyFailed,
		func(ctx context.Context, cl client.Client, req *client.TPMPolicyRequest) (any, error) {
			return cl.TPMPolicyGet(ctx, req)
		}, printTPMPolicyResult("TPM Policy"))

	// tpmPolicyUpdateCmd re-captures and re-approves a TPM policy.
	// tpmPolicyRevokeCmd withdraws a TPM policy's approval.
	tpmPolicyRevokeCmd = newTPMPolicyNameCmd("revoke", "Withdraw a TPM policy's approval",
		"Withdraw a policy's approval. Its objects answer only to their password\nuntil the policy is updated again.\n\nExample:\n  xkmsctl tpm policy revoke boot",
		"Revoking TPM policy", ErrRevokeTPMPolicyFailed,
		func(ctx context.Context, cl client.Client, req *client.TPMPolicyRequest) (any, error) {
			return cl.TPMPolicyRevoke(ctx, req)
		}, printTPMPolicyResult("TPM Policy Revoked"))

	// tpmPolicyVerifyCmd compares a TPM policy with the live PCR values.
	tpmPolicyVerifyCmd = newTPMPolicyNameCmd("verify", "Compare a TPM policy with the live PCR values",
		"Compare a policy's captured PCR values with the live ones. The command\nexits non-zero when they differ or the policy is not approved.\n\nExample:\n  xkmsctl tpm policy verify boot",
		"Verifying TPM policy", ErrVerifyTPMPolicyFailed,
		func(ctx context.Context, cl client.Client, req *client.TPMPolicyRequest) (any, error) {
			return cl.TPMPolicyVerify(ctx, req)
		}, printTPMPolicyVerification)

	// tpmPolicyObjectsCmd lists the objects bound to a TPM policy.
	tpmPolicyObjectsCmd = newTPMPolicyNameCmd("objects", "List the objects bound to a TPM policy",
		"List the keys and sealed objects bound to a policy.\n\nExample:\n  xkmsctl tpm policy objects boot",
		"Listing the objects of TPM policy", ErrTPMPolicyObjectsFailed,
		func(ctx context.Context, cl client.Client, req *client.TPMPolicyRequest) (any, error) {
			return cl.TPMPolicyObjects(ctx, req)
		}, printTPMPolicyObjects)
)

// tpmPolicyDeleteCmd deletes a TPM policy.
// tpmPolicyUpdateCmd moves a TPM policy to its next epoch: every branch
// re-captured from the live PCRs, or one branch updated from signed
// reference values.
var tpmPolicyUpdateCmd = &cobra.Command{
	Use:   "update <name>",
	Short: "Update a TPM policy's PCR values and re-approve it",
	Long: `Re-approve a policy at its next epoch after an expected platform change,
such as a firmware or kernel update. No key is re-keyed.

Without --branch, every branch's PCR values are re-captured from the TPM,
so the update runs after the change, on the changed platform.

With --branch (counted from 0) and --reference-values, only that branch is
updated, to the PCR values the signed CoRIM predicts the platform will hold
once the images it describes are booted, so the update runs before the
change and the platform unseals unattended after it. The CoRIM must verify
under the server's configured reference signer.

Examples:
  xkmsctl tpm policy update boot
  xkmsctl tpm policy update boot --branch 0 --reference-values bootloader-v2.corim`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		tenant := fr.String("tenant")
		branch := fr.Int("branch")
		path := fr.String("reference-values")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		req := &client.TPMPolicyUpdateRequest{TenantID: tenant, Name: args[0]}
		if cmd.Flags().Changed("branch") {
			req.Branch = &branch
		}
		if path != "" {
			corim, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				handleError(&WrappedDetailError{Sentinel: ErrReadReferenceValuesFailed, Detail: path, Err: err})
				return
			}
			req.ReferenceValues = corim
		}
		runClientCall(getConfig(), "Updating TPM policy "+args[0], ErrUpdateTPMPolicyFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.TPMPolicyUpdate(ctx, req)
		}, printTPMPolicyResult("TPM Policy Updated"))
	},
}

var tpmPolicyDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a TPM policy",
	Long: `Delete a TPM policy. It is refused, listing them, while keys or sealed
objects are bound to the policy.

Example:
  xkmsctl tpm policy delete boot`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		tenant := fr.String("tenant")
		ownerAuth := fr.String("owner-auth")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		auth, err := resolveOwnerAuth(ownerAuth)
		if err != nil {
			handleError(err)
			return
		}
		name := args[0]
		runClientCall(getConfig(), "Deleting TPM policy "+name, ErrDeleteTPMPolicyFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return name, cl.TPMPolicyDelete(ctx, &client.TPMPolicyDeleteRequest{TenantID: tenant, Name: name, OwnerAuth: auth})
		}, func(p *Printer, _ any) { printCallSuccess(p, fmt.Sprintf("TPM policy %q deleted", name)) })
	},
}

// tpmPolicyAutoUnsealCmd sets or clears a policy's auto-unseal mark.
var tpmPolicyAutoUnsealCmd = &cobra.Command{
	Use:   "auto-unseal <name>",
	Short: "Mark the TPM policy barrier auto-unseal uses",
	Long: `Mark a policy as the one barrier auto-unseal uses, clearing the mark from
every other policy of the tenant; --disable clears it.

Examples:
  xkmsctl tpm policy auto-unseal boot
  xkmsctl tpm policy auto-unseal boot --disable`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		tenant := fr.String("tenant")
		disable := fr.Bool("disable")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		runClientCall(getConfig(), "Setting auto-unseal on TPM policy "+args[0], ErrTPMPolicyAutoUnsealFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.TPMPolicySetAutoUnseal(ctx, &client.TPMPolicyAutoUnsealRequest{TenantID: tenant, Name: args[0], Enabled: !disable})
		}, printTPMPolicyResult("TPM Policy"))
	},
}

// tpmAuthorityCmd groups the policy-authority commands.
var tpmAuthorityCmd = &cobra.Command{
	Use:   "authority",
	Short: "Manage the TPM policy authority",
}

// tpmAuthorityRotateCmd rotates a tenant's policy authority.
var tpmAuthorityRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the TPM policy authority",
	Long: `Replace the tenant's policy authority: every policy is re-approved by the
new authority and approvals by the old one stop authorizing anything. No key
is re-keyed.

Example:
  xkmsctl tpm authority rotate`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		tenant, ok := tenantFlag(cmd)
		if !ok {
			return
		}
		runClientCall(getConfig(), "Rotating the TPM policy authority", ErrRotateTPMAuthorityFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.TPMPolicyRotateAuthority(ctx, &client.TPMAuthorityRotateRequest{TenantID: tenant})
		}, printTPMAuthority)
	},
}

// keyPolicyCmd shows the TPM policy a key was created under.
var keyPolicyCmd = &cobra.Command{
	Use:   "policy <key-id>",
	Short: "Show the TPM policy a key is bound to",
	Long: `Show the TPM policy a TPM2 key (or, with --sealed, a sealed object) was
created under, and its authPolicy digest.

Example:
  xkmsctl key policy signer`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		tenant := fr.String("tenant")
		sealed := fr.Bool("sealed")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		kind := client.TPMObjectKindKey
		if sealed {
			kind = client.TPMObjectKindSealed
		}
		runClientCall(getConfig(), "Retrieving the TPM policy of "+args[0], ErrTPMObjectPolicyFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.TPMObjectPolicy(ctx, &client.TPMObjectPolicyRequest{TenantID: tenant, KeyID: args[0], Kind: kind})
		}, printTPMObjectPolicy)
	},
}

// tenantFlag reads the --tenant flag, reporting the flag error and false
// when it cannot be read.
func tenantFlag(cmd *cobra.Command) (string, bool) {
	fr := newFlagReader(cmd)
	tenant := fr.String("tenant")
	if err := fr.Err(); err != nil {
		handleError(err)
		return "", false
	}
	return tenant, true
}

// pcrIndices converts the --pcrs indices, refusing a negative one before any
// request is made.
func pcrIndices(pcrs []int) ([]uint, error) {
	out := make([]uint, 0, len(pcrs))
	for _, pcr := range pcrs {
		if pcr < 0 {
			return nil, &WrappedDetailError{Sentinel: ErrInvalidTPMPolicyPCR, Detail: fmt.Sprint(pcr)}
		}
		out = append(out, uint(pcr))
	}
	return out, nil
}

// resolveOwnerAuth resolves the --owner-auth value: empty for none (the
// usual case, an owner hierarchy with no authorization), "-" to read it from
// standard input, or the value itself.
func resolveOwnerAuth(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	auth, err := resolveSecret(value, "TPM owner authorization")
	if err != nil {
		return nil, err
	}
	return []byte(auth), nil
}

// runClientCall connects a client, runs call, and prints its result with
// print; a failure is reported wrapped in failure.
func runClientCall(cfg *Config, verbose string, failure error, call func(context.Context, client.Client) (any, error), show func(*Printer, any)) {
	printer := NewPrinter(cfg.OutputFormat, os.Stdout)
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}
	printVerbose("%s", verbose)

	result, err := call(ctx, cl)
	if err != nil {
		handleError(&WrappedError{Sentinel: failure, Err: err})
		return
	}
	show(printer, result)
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// printJSONResult prints result as JSON and reports whether the printer's
// format was JSON.
func printJSONResult(p *Printer, result any) bool {
	if p.format != OutputFormatJSON {
		return false
	}
	if err := p.PrintJSON(result); err != nil {
		handleError(err)
	}
	return true
}

// printCallSuccess prints a success message.
func printCallSuccess(p *Printer, message string) {
	if err := p.PrintSuccess(message); err != nil {
		handleError(err)
	}
}

// printTPMPolicyResult returns a printer of one TPM policy under title.
func printTPMPolicyResult(title string) func(*Printer, any) {
	return func(p *Printer, result any) {
		policy, ok := result.(*client.TPMPolicy)
		if !ok || printJSONResult(p, result) {
			return
		}
		p.printf("%s:\n", title)
		p.printf("  Name:        %s\n", policy.Name)
		if policy.TenantID != "" {
			p.printf("  Tenant:      %s\n", policy.TenantID)
		}
		if policy.Description != "" {
			p.printf("  Description: %s\n", policy.Description)
		}
		p.printf("  NV Index:    0x%08x\n", policy.Index)
		p.printf("  Approved:    %t", policy.Approved)
		if policy.Approved {
			p.printf(" (epoch %d, authority generation %d)", policy.Epoch, policy.AuthorityGeneration)
		}
		p.printf("\n")
		p.printf("  Auto-unseal: %t\n", policy.AutoUnseal)
		p.printf("  Created:     %s\n", policy.CreatedAt)
		if policy.UpdatedAt != "" {
			p.printf("  Updated:     %s\n", policy.UpdatedAt)
		}
		for i, branch := range policy.Branches {
			p.printf("  Branch %d:    %s (approved: %t)\n", i, branch.String(), branch.Approved)
			if branch.Reference != nil {
				p.printf("    Reference: %s\n", branch.Reference)
			}
			for _, c := range branch.Conditions {
				pcrs := make([]uint, 0, len(c.PCRValues))
				for pcr := range c.PCRValues {
					pcrs = append(pcrs, pcr)
				}
				sort.Slice(pcrs, func(i, j int) bool { return pcrs[i] < pcrs[j] })
				for _, pcr := range pcrs {
					p.printf("    PCR %-2d:    %s\n", pcr, c.PCRValues[pcr])
				}
			}
		}
	}
}

// tpmPolicyBranchSummary joins a policy's branches in spec form with " | ".
func tpmPolicyBranchSummary(branches []client.TPMPolicyBranch) string {
	parts := make([]string, len(branches))
	for i, b := range branches {
		parts[i] = b.String()
	}
	return strings.Join(parts, " | ")
}

// printTPMPolicyList prints a list of TPM policies.
func printTPMPolicyList(p *Printer, result any) {
	list, ok := result.(*client.TPMPolicyListResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	if len(list.Policies) == 0 {
		p.println("No TPM policies found")
		return
	}
	p.printf("%-24s %-32s %-9s %-11s %s\n", "NAME", "BRANCHES", "APPROVED", "AUTO-UNSEAL", "DESCRIPTION")
	p.println(repeatString("-", 96))
	for _, policy := range list.Policies {
		p.printf("%-24s %-32s %-9t %-11t %s\n",
			truncateString(policy.Name, 24), truncateString(tpmPolicyBranchSummary(policy.Branches), 32),
			policy.Approved, policy.AutoUnseal, truncateString(policy.Description, 40))
	}
	p.printf("\nTotal: %d TPM policy(ies)\n", len(list.Policies))
}

// printTPMPolicyVerification prints a verification, failing the command
// when the live PCR values of any branch differ or a branch is not
// approved.
func printTPMPolicyVerification(p *Printer, result any) {
	v, ok := result.(*client.TPMPolicyVerifyResponse)
	if !ok {
		return
	}
	if !printJSONResult(p, result) {
		for i, b := range v.Branches {
			state := "PCRs match"
			if !b.Match {
				state = fmt.Sprintf("PCRs %v differ", b.Mismatched)
			}
			p.printf("  Branch %d: %s, approved: %t\n", i, state, b.Approved)
			if b.Reference != nil {
				p.printf("    Reference: %s\n", b.Reference)
			}
		}
		if v.Match && v.Approved {
			printCallSuccess(p, fmt.Sprintf("TPM policy %q matches the live PCR values and is approved", v.Name))
		}
	}
	switch {
	case !v.Match:
		handleError(&WrappedDetailError{Sentinel: ErrTPMPolicyMismatch, Detail: v.Name})
	case !v.Approved:
		handleError(&WrappedDetailError{Sentinel: ErrTPMPolicyNotApproved, Detail: v.Name})
	}
}

// printTPMPolicyObjects prints the objects bound to a policy.
func printTPMPolicyObjects(p *Printer, result any) {
	objects, ok := result.(*client.TPMPolicyObjectsResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	if len(objects.Objects) == 0 {
		p.printf("No objects are bound to TPM policy %q\n", objects.Name)
		return
	}
	p.printf("Objects bound to TPM policy %q:\n", objects.Name)
	for _, id := range objects.Objects {
		p.printf("  - %s\n", id)
	}
}

// printTPMObjectPolicy prints the policy an object is bound to.
func printTPMObjectPolicy(p *Printer, result any) {
	obj, ok := result.(*client.TPMObjectPolicyResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	p.printf("Object:      %s\n", obj.ObjectID)
	p.printf("TPM Policy:  %s\n", obj.Policy)
	if obj.AuthPolicy != "" {
		p.printf("AuthPolicy:  %s\n", obj.AuthPolicy)
	}
	p.printf("Created:     %s\n", obj.CreatedAt)
}

// printTPMAuthority prints a rotated policy authority.
func printTPMAuthority(p *Printer, result any) {
	rotated, ok := result.(*client.TPMAuthorityRotateResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	scope := rotated.TenantID
	if scope == "" {
		scope = "system"
	}
	p.printf("TPM policy authority rotated for %s:\n", scope)
	p.printf("  Generation: %d\n", rotated.Generation)
	p.printf("  Name:       %s\n", rotated.AuthorityName)
	p.printf("  Epoch:      %d\n", rotated.Epoch)
}

// tenantTPMModeCmd shows or sets a tenant's TPM mode.
var tenantTPMModeCmd = &cobra.Command{
	Use:   "tpm-mode <tenant-id> [none|shared|vtpm]",
	Short: "Show or set a tenant's TPM mode",
	Long: `Show a tenant's TPM mode, or set it: none (no TPM objects), shared
(objects on the node's TPM under the tenant's own storage key) or vtpm (a
per-tenant virtual TPM). A mode change is refused while the tenant's TPM
holds keys, sealed objects or policies. System administrators only.

Examples:
  xkmsctl tenant tpm-mode acme
  xkmsctl tenant tpm-mode acme vtpm`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		ownerAuth := fr.String("owner-auth")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		tenantID := args[0]
		if len(args) == 1 {
			runClientCall(getConfig(), "Retrieving the TPM mode of tenant "+tenantID, ErrTenantTPMModeFailed, func(ctx context.Context, cl client.Client) (any, error) {
				return cl.GetTenantTPMMode(ctx, tenantID)
			}, printTenantTPMMode)
			return
		}
		auth, err := resolveOwnerAuth(ownerAuth)
		if err != nil {
			handleError(err)
			return
		}
		mode := strings.ToLower(args[1])
		runClientCall(getConfig(), "Setting the TPM mode of tenant "+tenantID+" to "+mode, ErrTenantTPMModeFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.SetTenantTPMMode(ctx, &client.SetTenantTPMModeRequest{TenantID: tenantID, Mode: mode, OwnerAuth: auth})
		}, printTenantTPMMode)
	},
}

// printTenantTPMMode prints a tenant's TPM mode.
func printTenantTPMMode(p *Printer, result any) {
	mode, ok := result.(*client.TenantTPMModeResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	p.printf("Tenant %s TPM mode: %s\n", mode.TenantID, mode.Mode)
}

// tenantVTPMCmd groups the tenant vTPM commands.
var tenantVTPMCmd = &cobra.Command{
	Use:   "vtpm",
	Short: "Manage a vtpm-mode tenant's virtual TPM",
	Long: `Show, start or stop the virtual TPM of a tenant in vtpm TPM mode. System
administrators only.

Subcommands:
  status   Show the tenant's vTPM
  start    Start the tenant's vTPM
  stop     Stop the tenant's vTPM, saving its state`,
}

// newTenantVTPMCmd returns a vTPM lifecycle command.
func newTenantVTPMCmd(use, short, verbose string, call func(context.Context, client.Client, string) (*client.TenantVTPMStatusResponse, error)) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <tenant-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			runClientCall(getConfig(), verbose+" "+args[0], ErrTenantVTPMFailed, func(ctx context.Context, cl client.Client) (any, error) {
				return call(ctx, cl, args[0])
			}, printTenantVTPMStatus)
		},
	}
}

var (
	tenantVTPMStatusCmd = newTenantVTPMCmd("status", "Show a tenant's vTPM", "Retrieving the vTPM of tenant",
		func(ctx context.Context, cl client.Client, tenantID string) (*client.TenantVTPMStatusResponse, error) {
			return cl.TenantVTPMStatus(ctx, tenantID)
		})
	tenantVTPMStartCmd = newTenantVTPMCmd("start", "Start a tenant's vTPM", "Starting the vTPM of tenant",
		func(ctx context.Context, cl client.Client, tenantID string) (*client.TenantVTPMStatusResponse, error) {
			return cl.TenantVTPMStart(ctx, tenantID)
		})
	tenantVTPMStopCmd = newTenantVTPMCmd("stop", "Stop a tenant's vTPM", "Stopping the vTPM of tenant",
		func(ctx context.Context, cl client.Client, tenantID string) (*client.TenantVTPMStatusResponse, error) {
			return cl.TenantVTPMStop(ctx, tenantID)
		})
)

// printTenantVTPMStatus prints a tenant's vTPM status.
func printTenantVTPMStatus(p *Printer, result any) {
	st, ok := result.(*client.TenantVTPMStatusResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	p.printf("Tenant %s vTPM:\n", st.TenantID)
	p.printf("  Running:  %t\n", st.Running)
	if st.Running {
		p.printf("  PID:      %d\n", st.PID)
		p.printf("  Socket:   %s\n", st.Socket)
	}
	p.printf("  Restarts: %d\n", st.Restarts)
}

func init() {
	const tenantUsage = "tenant whose TPM scope to address (system callers only; default: your own)"
	const ownerAuthUsage = "TPM owner-hierarchy authorization; '-' reads it from stdin (default: none)"

	tpmPolicyCreateCmd.Flags().String("description", "", "free-text description of the policy")
	tpmPolicyCreateCmd.Flags().String("bank", "", "PCR bank of --pcrs: sha1, sha256, sha384 or sha512 (default sha256)")
	tpmPolicyCreateCmd.Flags().IntSlice("pcrs", nil, "PCR indices of a one-branch policy, 0-23 (comma-separated)")
	tpmPolicyCreateCmd.Flags().StringArray("branch", nil, "a policy branch, e.g. 'pcr=sha256:0,7;auth_value;locality=0' (repeatable)")
	tpmPolicyCreateCmd.Flags().Bool("auto-unseal", false, "mark the policy barrier auto-unseal uses")
	tpmPolicyCreateCmd.Flags().String("owner-auth", "", ownerAuthUsage)
	tpmPolicyDeleteCmd.Flags().String("owner-auth", "", ownerAuthUsage)
	tpmPolicyUpdateCmd.Flags().Int("branch", 0, "update only this branch, counted from 0 (needs --reference-values)")
	tpmPolicyUpdateCmd.Flags().String("reference-values", "", "signed CoRIM file the branch's PCR values are predicted from (needs --branch)")
	tpmPolicyAutoUnsealCmd.Flags().Bool("disable", false, "clear the auto-unseal mark instead of setting it")
	tenantTPMModeCmd.Flags().String("owner-auth", "", ownerAuthUsage)
	keyPolicyCmd.Flags().Bool("sealed", false, "the ID names a sealed object, not a key")

	for _, cmd := range []*cobra.Command{
		tpmPolicyCreateCmd, tpmPolicyListCmd, tpmPolicyGetCmd, tpmPolicyUpdateCmd, tpmPolicyRevokeCmd,
		tpmPolicyVerifyCmd, tpmPolicyDeleteCmd, tpmPolicyObjectsCmd, tpmPolicyAutoUnsealCmd,
		tpmPolicyDescribeCmd, tpmAuthorityRotateCmd, keyPolicyCmd,
	} {
		cmd.Flags().String("tenant", "", tenantUsage)
	}

	tpmPolicyCmd.AddCommand(tpmPolicyCreateCmd, tpmPolicyListCmd, tpmPolicyGetCmd, tpmPolicyUpdateCmd,
		tpmPolicyRevokeCmd, tpmPolicyVerifyCmd, tpmPolicyDeleteCmd, tpmPolicyObjectsCmd, tpmPolicyAutoUnsealCmd,
		tpmPolicyDescribeCmd)
	tpmAuthorityCmd.AddCommand(tpmAuthorityRotateCmd)
	tpmCmd.AddCommand(tpmPolicyCmd, tpmAuthorityCmd)
	rootCmd.AddCommand(tpmCmd)

	keyCmd.AddCommand(keyPolicyCmd)

	tenantVTPMCmd.AddCommand(tenantVTPMStatusCmd, tenantVTPMStartCmd, tenantVTPMStopCmd)
	tenantCmd.AddCommand(tenantTPMModeCmd, tenantVTPMCmd)
}
