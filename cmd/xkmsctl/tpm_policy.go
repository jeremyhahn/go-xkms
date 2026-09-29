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
	"sort"
	"strings"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// tpmCmd groups the TPM policy commands.
var tpmCmd = &cobra.Command{
	Use:   "tpm",
	Short: "Manage TPM policies and the TPM policy authority",
	Long: `Manage named TPM policies: PCR states that many TPM keys and sealed
objects share. Updating or revoking a policy re-approves or withdraws it
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

Examples:
  xkmsctl tpm policy create boot --pcrs 0,7
  xkmsctl tpm policy create boot --bank sha384 --pcrs 0,7 --auto-unseal`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		bank := fr.String("bank")
		pcrs := fr.IntSlice("pcrs")
		autoUnseal := fr.Bool("auto-unseal")
		tenant := fr.String("tenant")
		ownerAuth := fr.String("owner-auth")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		selection, err := pcrSelection(pcrs)
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
		runTPMPolicy(cfg, "Creating TPM policy "+args[0], ErrCreateTPMPolicyFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.TPMPolicyCreate(ctx, &client.TPMPolicyCreateRequest{
				TenantID: tenant, Name: args[0], Bank: bank, PCRs: selection, AutoUnseal: autoUnseal, OwnerAuth: auth,
			})
		}, printTPMPolicyResult("TPM Policy Created"))
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
		runTPMPolicy(getConfig(), "Listing TPM policies", ErrListTPMPoliciesFailed, func(ctx context.Context, cl client.Client) (any, error) {
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
			runTPMPolicy(getConfig(), verbose+" "+args[0], failure, func(ctx context.Context, cl client.Client) (any, error) {
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
	tpmPolicyUpdateCmd = newTPMPolicyNameCmd("update", "Re-capture a TPM policy's PCR values",
		"Re-capture a policy's PCR values from the TPM and re-approve it, after an\nexpected platform change such as a firmware or kernel update. No key is\nre-keyed.\n\nExample:\n  xkmsctl tpm policy update boot",
		"Updating TPM policy", ErrUpdateTPMPolicyFailed,
		func(ctx context.Context, cl client.Client, req *client.TPMPolicyRequest) (any, error) {
			return cl.TPMPolicyUpdate(ctx, req)
		}, printTPMPolicyResult("TPM Policy Updated"))

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
		runTPMPolicy(getConfig(), "Deleting TPM policy "+name, ErrDeleteTPMPolicyFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return name, cl.TPMPolicyDelete(ctx, &client.TPMPolicyDeleteRequest{TenantID: tenant, Name: name, OwnerAuth: auth})
		}, func(p *Printer, _ any) { printTPMSuccess(p, fmt.Sprintf("TPM policy %q deleted", name)) })
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
		runTPMPolicy(getConfig(), "Setting auto-unseal on TPM policy "+args[0], ErrTPMPolicyAutoUnsealFailed, func(ctx context.Context, cl client.Client) (any, error) {
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
		runTPMPolicy(getConfig(), "Rotating the TPM policy authority", ErrRotateTPMAuthorityFailed, func(ctx context.Context, cl client.Client) (any, error) {
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
		runTPMPolicy(getConfig(), "Retrieving the TPM policy of "+args[0], ErrTPMObjectPolicyFailed, func(ctx context.Context, cl client.Client) (any, error) {
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

// pcrSelection converts the --pcrs indices, refusing an empty or negative
// selection before any request is made.
func pcrSelection(pcrs []int) ([]uint, error) {
	if len(pcrs) == 0 {
		return nil, ErrTPMPolicyPCRsRequired
	}
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

// runTPMPolicy connects a client, runs call, and prints its result with
// print; a failure is reported wrapped in failure.
func runTPMPolicy(cfg *Config, verbose string, failure error, call func(context.Context, client.Client) (any, error), show func(*Printer, any)) {
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

// printTPMSuccess prints a success message.
func printTPMSuccess(p *Printer, message string) {
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
		p.printf("  Bank:        %s\n", policy.Bank)
		p.printf("  PCRs:        %v\n", policy.PCRs)
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
		pcrs := make([]uint, 0, len(policy.PCRValues))
		for pcr := range policy.PCRValues {
			pcrs = append(pcrs, pcr)
		}
		sort.Slice(pcrs, func(i, j int) bool { return pcrs[i] < pcrs[j] })
		for _, pcr := range pcrs {
			p.printf("  PCR %-2d:      %s\n", pcr, policy.PCRValues[pcr])
		}
	}
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
	p.printf("%-24s %-8s %-16s %-9s %-11s\n", "NAME", "BANK", "PCRS", "APPROVED", "AUTO-UNSEAL")
	p.println(repeatString("-", 72))
	for _, policy := range list.Policies {
		p.printf("%-24s %-8s %-16s %-9t %-11t\n",
			truncateString(policy.Name, 24), policy.Bank,
			truncateString(fmt.Sprint(policy.PCRs), 16), policy.Approved, policy.AutoUnseal)
	}
	p.printf("\nTotal: %d TPM policy(ies)\n", len(list.Policies))
}

// printTPMPolicyVerification prints a verification, failing the command
// when the live PCR values differ or the policy is not approved.
func printTPMPolicyVerification(p *Printer, result any) {
	v, ok := result.(*client.TPMPolicyVerifyResponse)
	if !ok {
		return
	}
	if !printJSONResult(p, result) && v.Match && v.Approved {
		printTPMSuccess(p, fmt.Sprintf("TPM policy %q matches the live PCR values and is approved", v.Name))
	}
	switch {
	case !v.Match:
		handleError(&WrappedDetailError{Sentinel: ErrTPMPolicyMismatch, Detail: fmt.Sprintf("%s: PCRs %v differ", v.Name, v.Mismatched)})
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
			runTPMPolicy(getConfig(), "Retrieving the TPM mode of tenant "+tenantID, ErrTenantTPMModeFailed, func(ctx context.Context, cl client.Client) (any, error) {
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
		runTPMPolicy(getConfig(), "Setting the TPM mode of tenant "+tenantID+" to "+mode, ErrTenantTPMModeFailed, func(ctx context.Context, cl client.Client) (any, error) {
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
			runTPMPolicy(getConfig(), verbose+" "+args[0], ErrTenantVTPMFailed, func(ctx context.Context, cl client.Client) (any, error) {
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

	tpmPolicyCreateCmd.Flags().String("bank", "sha256", "PCR bank: sha1, sha256, sha384 or sha512")
	tpmPolicyCreateCmd.Flags().IntSlice("pcrs", nil, "PCR indices to select, 0-23 (required, comma-separated)")
	tpmPolicyCreateCmd.Flags().Bool("auto-unseal", false, "mark the policy barrier auto-unseal uses")
	tpmPolicyCreateCmd.Flags().String("owner-auth", "", ownerAuthUsage)
	tpmPolicyDeleteCmd.Flags().String("owner-auth", "", ownerAuthUsage)
	tpmPolicyAutoUnsealCmd.Flags().Bool("disable", false, "clear the auto-unseal mark instead of setting it")
	tenantTPMModeCmd.Flags().String("owner-auth", "", ownerAuthUsage)
	keyPolicyCmd.Flags().Bool("sealed", false, "the ID names a sealed object, not a key")

	for _, cmd := range []*cobra.Command{
		tpmPolicyCreateCmd, tpmPolicyListCmd, tpmPolicyGetCmd, tpmPolicyUpdateCmd, tpmPolicyRevokeCmd,
		tpmPolicyVerifyCmd, tpmPolicyDeleteCmd, tpmPolicyObjectsCmd, tpmPolicyAutoUnsealCmd,
		tpmAuthorityRotateCmd, keyPolicyCmd,
	} {
		cmd.Flags().String("tenant", "", tenantUsage)
	}

	tpmPolicyCmd.AddCommand(tpmPolicyCreateCmd, tpmPolicyListCmd, tpmPolicyGetCmd, tpmPolicyUpdateCmd,
		tpmPolicyRevokeCmd, tpmPolicyVerifyCmd, tpmPolicyDeleteCmd, tpmPolicyObjectsCmd, tpmPolicyAutoUnsealCmd)
	tpmAuthorityCmd.AddCommand(tpmAuthorityRotateCmd)
	tpmCmd.AddCommand(tpmPolicyCmd, tpmAuthorityCmd)
	rootCmd.AddCommand(tpmCmd)

	keyCmd.AddCommand(keyPolicyCmd)

	tenantVTPMCmd.AddCommand(tenantVTPMStatusCmd, tenantVTPMStartCmd, tenantVTPMStopCmd)
	tenantCmd.AddCommand(tenantTPMModeCmd, tenantVTPMCmd)
}
