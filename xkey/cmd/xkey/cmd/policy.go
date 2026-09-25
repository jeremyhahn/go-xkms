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

package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/spf13/cobra"

	pcrpolicy "github.com/jeremyhahn/go-xkms/xkey/pkg/pcr_policy"
)

var (
	// policyTPMDevice is the --tpm-device flag for policy commands that read
	// current PCR values from a TPM (create, verify, refresh). It mirrors
	// the `barrier` command group's --tpm-device flag.
	policyTPMDevice string

	// policyTPMSimulator is the --tpm-simulator flag for policy commands.
	// It mirrors the `barrier` command group's --tpm-simulator flag.
	policyTPMSimulator bool
)

// Valid PCR hash banks accepted by the CLI. The store normalises to
// upper-case internally; the CLI is case-insensitive for convenience.
var validPCRBanks = map[string]bool{
	"sha1":   true,
	"sha256": true,
	"sha384": true,
}

// Policy command errors.
var (
	ErrPolicyMissingName       = errors.New("policy: name argument is required")
	ErrPolicyMissingPCRs       = errors.New("policy: --pcrs flag is required")
	ErrPolicyInvalidBank       = errors.New("policy: invalid bank (valid: sha1, sha256, sha384)")
	ErrPolicyStoreOpenFailed   = errors.New("policy: failed to open store")
	ErrPolicyCreateFailed      = errors.New("policy: failed to create policy")
	ErrPolicyListFailed        = errors.New("policy: failed to list policies")
	ErrPolicyGetFailed         = errors.New("policy: failed to get policy")
	ErrPolicyDeleteFailed      = errors.New("policy: failed to delete policy")
	ErrPolicyRefreshFailed     = errors.New("policy: failed to refresh policy")
	ErrPolicyVerifyFailed      = errors.New("policy: failed to verify policy")
	ErrPolicyExportFailed      = errors.New("policy: failed to export policy")
	ErrPolicyNotFound          = errors.New("policy: policy not found")
	ErrPolicyAlreadyExists     = errors.New("policy: policy already exists")
	ErrPolicyReadCurrentFailed = errors.New("policy: failed to read current PCR values")
	ErrPolicyAutoUnsealFailed  = errors.New("policy: failed to set auto-unseal policy")
	ErrPolicyClearAutoFailed   = errors.New("policy: failed to clear auto-unseal policy")
)

// policyStoreFactory is the function used to open a PolicyStore from
// a filesystem path. It is a package-level variable so tests can
// replace it with an in-memory implementation without touching the
// filesystem or requiring real storage backends.
var policyStoreFactory = openPolicyStore

// PolicyCmd represents the policy parent command.
var PolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "PCR policy management for TPM-based sealing",
	Long: `PCR policy management for TPM-based sealing.

Create, inspect, and verify PCR policies that define which Platform
Configuration Register values are expected during TPM seal/unseal
operations. Policies capture a snapshot of selected PCR values and
can later be verified against the current platform state.

Examples:
  # Create a policy capturing PCRs 0,2,4,7 from the SHA-256 bank
  xkey policy create boot-policy --pcrs 0,2,4,7 --bank sha256

  # List all saved policies
  xkey policy list

  # Show details of a specific policy
  xkey policy get boot-policy

  # Delete a policy
  xkey policy delete boot-policy

  # Mark a policy for auto-unseal on boot
  xkey policy set-auto-unseal boot-policy

  # Clear the auto-unseal designation
  xkey policy clear-auto-unseal

  # Export policy as JSON
  xkey policy export boot-policy`,
}

// policyCreateCmd creates a new PCR policy.
var policyCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new PCR policy",
	Long: `Create a new PCR policy by reading the current values of the specified
PCR indices from the TPM. The policy is saved to the local policy store.

The --pcrs flag specifies which PCR indices to include (comma-separated).
The --bank flag selects the hash bank (default: sha256).

Examples:
  # Create a policy for secure boot PCRs
  xkey policy create boot-policy --pcrs 0,2,4,7

  # Create a policy using SHA-384 bank
  xkey policy create ha-policy --pcrs 0,7 --bank sha384`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyCreate,
}

// policyListCmd lists all saved policies.
var policyListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all PCR policies",
	Long: `List all PCR policies saved in the policy store.

Supports --page and --page-size flags for paginated output.

Examples:
  # List all policies
  xkey policy list

  # Page through results
  xkey policy list --page 1 --page-size 10`,
	RunE: runPolicyList,
}

// policyGetCmd displays details of a specific policy.
var policyGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Show details of a PCR policy",
	Long: `Show the full details of a saved PCR policy including the
recorded PCR digest values in hex.

Examples:
  # Show boot policy details
  xkey policy get boot-policy`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyGet,
}

// policyDeleteCmd removes a policy.
var policyDeleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a PCR policy",
	Long: `Delete a saved PCR policy from the policy store.

A policy that is currently designated as the auto-unseal policy cannot
be deleted. Use 'xkey policy clear-auto-unseal' first.

Examples:
  # Delete a policy
  xkey policy delete boot-policy`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyDelete,
}

// policySetAutoUnsealCmd marks a policy as the auto-unseal policy.
var policySetAutoUnsealCmd = &cobra.Command{
	Use:   "set-auto-unseal <name>",
	Short: "Mark a policy as the auto-unseal policy",
	Long: `Designate the named policy as the auto-unseal policy. On boot the
barrier will attempt to unseal using this policy's expected PCR
values. Only one policy can be designated at a time; setting a
new one clears the previous designation.

Examples:
  # Set auto-unseal policy
  xkey policy set-auto-unseal boot-policy`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicySetAutoUnseal,
}

// policyClearAutoUnsealCmd clears the auto-unseal designation.
var policyClearAutoUnsealCmd = &cobra.Command{
	Use:   "clear-auto-unseal",
	Short: "Clear the auto-unseal policy designation",
	Long: `Remove the auto-unseal designation from whichever policy currently
holds it. After this the barrier will not auto-unseal on boot.

Examples:
  # Clear auto-unseal
  xkey policy clear-auto-unseal`,
	RunE: runPolicyClearAutoUnseal,
}

// policyRefreshCmd re-reads current PCR values for a policy.
var policyRefreshCmd = &cobra.Command{
	Use:   "refresh <name>",
	Short: "Refresh policy with current PCR values",
	Long: `Re-read the current PCR values from the TPM and update the saved
policy. This is useful after a known-good platform change such as a
firmware or kernel update.

Examples:
  # Refresh boot policy after kernel update
  xkey policy refresh boot-policy`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyRefresh,
}

// policyVerifyCmd checks if current PCRs match the policy.
var policyVerifyCmd = &cobra.Command{
	Use:   "verify <name>",
	Short: "Verify current PCR values against policy",
	Long: `Read the current PCR values from the TPM and compare them against
the saved policy. Reports whether all PCR values match.

A mismatch indicates that the platform state has changed since the
policy was created or last refreshed.

Examples:
  # Verify boot policy
  xkey policy verify boot-policy`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyVerify,
}

// policyExportCmd exports a policy as JSON.
var policyExportCmd = &cobra.Command{
	Use:   "export <name>",
	Short: "Export policy as JSON",
	Long: `Export a saved PCR policy as a JSON document to stdout.
The output can be redirected to a file for backup or transfer.

Examples:
  # Export to stdout
  xkey policy export boot-policy

  # Export to a file
  xkey policy export boot-policy > boot-policy.json`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyExport,
}

func init() {
	// Register policy command with root.
	RootCmd.AddCommand(PolicyCmd)

	// Add subcommands.
	PolicyCmd.AddCommand(policyCreateCmd)
	PolicyCmd.AddCommand(policyListCmd)
	PolicyCmd.AddCommand(policyGetCmd)
	PolicyCmd.AddCommand(policyDeleteCmd)
	PolicyCmd.AddCommand(policySetAutoUnsealCmd)
	PolicyCmd.AddCommand(policyClearAutoUnsealCmd)
	PolicyCmd.AddCommand(policyRefreshCmd)
	PolicyCmd.AddCommand(policyVerifyCmd)
	PolicyCmd.AddCommand(policyExportCmd)

	// Persistent store flag for all subcommands. The default resolves
	// through resolvePolicyStorePath to <data dir>/pcr_policies -- see its
	// doc comment for why this must match the xKey GUI's own PCR policy
	// store location.
	PolicyCmd.PersistentFlags().String("store", "",
		"Path to policy store directory (default: <data dir>/pcr_policies)")
	PolicyCmd.PersistentFlags().StringVar(&policyTPMDevice, "tpm-device", "",
		"TPM device path used to read current PCR values (default: $TPM_DEVICE_PATH or /dev/tpmrm0)")
	PolicyCmd.PersistentFlags().BoolVar(&policyTPMSimulator, "tpm-simulator", false,
		"Use the in-process TPM simulator instead of a hardware device (requires a simulator build)")

	// policy create flags.
	policyCreateCmd.Flags().String("pcrs", "",
		"Comma-separated PCR indices (e.g., 0,2,4,7)")
	policyCreateCmd.Flags().String("bank", "sha256",
		"PCR hash bank (sha1, sha256, sha384)")

	// policy list pagination flags.
	policyListCmd.Flags().Int("page", 0,
		"Page number (1-based, 0 means list all)")
	policyListCmd.Flags().Int("page-size", 20,
		"Number of policies per page")
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

// runPolicyCreate executes the policy create command.
func runPolicyCreate(cmd *cobra.Command, args []string) (err error) {
	name := args[0]
	pcrsFlag, _ := cmd.Flags().GetString("pcrs")
	bank, _ := cmd.Flags().GetString("bank")
	storePath, _ := cmd.Flags().GetString("store")

	if pcrsFlag == "" {
		return ErrPolicyMissingPCRs
	}

	bank = strings.ToLower(bank)
	if !validPCRBanks[bank] {
		return ErrPolicyInvalidBank
	}

	// Parse PCR indices.
	pcrIndices, err := parsePCRIndices(pcrsFlag)
	if err != nil {
		return err
	}

	// Read current PCR values from TPM.
	values, err := readCurrentPCRValues(pcrIndices, bank, policyTPMDevice, policyTPMSimulator)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyCreateFailed, Cause: err}
	}

	// Convert hex string map to raw bytes map for the store entity.
	pcrBytes := hexMapToBytes(values)

	// Open the store.
	store, err := policyStoreFactory(storePath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyStoreOpenFailed, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()

	// Normalise bank to upper-case for the entity.
	bankUpper := strings.ToUpper(bank)

	entity, err := store.Create(ctx, name, bankUpper, pcrBytes)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyCreateFailed, Cause: err}
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Created policy: %s\n", entity.Name)
	_, _ = fmt.Fprintf(out, "  Bank:  %s\n", entity.Bank)
	_, _ = fmt.Fprintf(out, "  PCRs:  %s\n", formatPCRIndices(entity.PCRs))
	return nil
}

// runPolicyList executes the policy list command.
func runPolicyList(cmd *cobra.Command, args []string) (err error) {
	storePath, _ := cmd.Flags().GetString("store")
	page, _ := cmd.Flags().GetInt("page")
	pageSize, _ := cmd.Flags().GetInt("page-size")
	out := cmd.OutOrStdout()

	store, err := policyStoreFactory(storePath)
	if err != nil {
		_, _ = fmt.Fprintln(out, "No policies found.")
		return nil
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()

	// Paginated mode when page > 0.
	if page > 0 {
		return runPolicyListPaginated(cmd, store, ctx, page, pageSize)
	}

	// Full list mode.
	policies, err := store.List(ctx)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyListFailed, Cause: err}
	}

	if len(policies) == 0 {
		_, _ = fmt.Fprintln(out, "No policies found.")
		return nil
	}

	// Determine auto-unseal policy name for marking.
	autoName := autoUnsealName(store, ctx)

	_, _ = fmt.Fprintf(out, "PCR Policies (%d):\n\n", len(policies))
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "NAME\tBANK\tPCRS\tCREATED\tAUTO-UNSEAL\n")
	for _, p := range policies {
		autoTag := ""
		if p.Name == autoName {
			autoTag = "[auto-unseal]"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			p.Name,
			p.Bank,
			formatPCRIndices(p.PCRs),
			p.CreatedAt.Format("2006-01-02 15:04:05"),
			autoTag,
		)
	}
	_ = w.Flush()

	return nil
}

// runPolicyListPaginated outputs a single page of results.
func runPolicyListPaginated(cmd *cobra.Command, store pcrpolicy.PolicyStore, ctx context.Context, page, pageSize int) error {
	out := cmd.OutOrStdout()

	result, err := store.Page(ctx, qrdbsdk.PageQuery{
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyListFailed, Cause: err}
	}

	if len(result.Entities) == 0 {
		_, _ = fmt.Fprintln(out, "No policies found.")
		return nil
	}

	autoName := autoUnsealName(store, ctx)

	_, _ = fmt.Fprintf(out, "PCR Policies (page %d, %d total):\n\n", page, result.Total)
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "NAME\tBANK\tPCRS\tCREATED\tAUTO-UNSEAL\n")
	for _, p := range result.Entities {
		autoTag := ""
		if p.Name == autoName {
			autoTag = "[auto-unseal]"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			p.Name,
			p.Bank,
			formatPCRIndices(p.PCRs),
			p.CreatedAt.Format("2006-01-02 15:04:05"),
			autoTag,
		)
	}
	_ = w.Flush()

	if result.HasMore {
		_, _ = fmt.Fprintf(out, "\nPage %d of %d. Use --page %d for next page.\n",
			page, (result.Total+pageSize-1)/pageSize, page+1)
	}

	return nil
}

// runPolicyGet executes the policy get command.
func runPolicyGet(cmd *cobra.Command, args []string) (err error) {
	name := args[0]
	storePath, _ := cmd.Flags().GetString("store")
	out := cmd.OutOrStdout()

	store, err := policyStoreFactory(storePath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyGetFailed, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()

	entity, err := store.Get(ctx, name)
	if err != nil {
		if errors.Is(err, pcrpolicy.ErrPolicyNotFound) {
			return &DetailError{Err: ErrPolicyNotFound, Detail: fmt.Sprintf(": %s", name)}
		}
		return &SentinelCauseError{Sentinel: ErrPolicyGetFailed, Cause: err}
	}

	autoTag := ""
	if entity.AutoUnseal {
		autoTag = " [auto-unseal]"
	}

	_, _ = fmt.Fprintf(out, "Policy: %s%s\n", entity.Name, autoTag)
	_, _ = fmt.Fprintf(out, "  Bank:     %s\n", entity.Bank)
	_, _ = fmt.Fprintf(out, "  PCRs:     %s\n", formatPCRIndices(entity.PCRs))
	_, _ = fmt.Fprintf(out, "  Created:  %s\n", entity.CreatedAt.Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintf(out, "  Updated:  %s\n", entity.UpdatedAt.Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintln(out)

	// Print PCR values sorted by index.
	indices := sortedPCRIndices(entity.PCRs)

	_, _ = fmt.Fprintln(out, "  PCR Values:")
	for _, idx := range indices {
		_, _ = fmt.Fprintf(out, "    PCR[%2d]: %s\n", idx, hex.EncodeToString(entity.PCRs[idx]))
	}

	return nil
}

// runPolicyDelete executes the policy delete command.
func runPolicyDelete(cmd *cobra.Command, args []string) (err error) {
	name := args[0]
	storePath, _ := cmd.Flags().GetString("store")

	store, err := policyStoreFactory(storePath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyDeleteFailed, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()

	if err := store.Delete(ctx, name); err != nil {
		if errors.Is(err, pcrpolicy.ErrPolicyNotFound) {
			return &DetailError{Err: ErrPolicyNotFound, Detail: fmt.Sprintf(": %s", name)}
		}
		if errors.Is(err, pcrpolicy.ErrDeleteAutoUnseal) {
			return &DetailError{Err: ErrPolicyDeleteFailed, Detail: fmt.Sprintf(": %s is the active auto-unseal policy; run 'xkey policy clear-auto-unseal' first", name)}
		}
		return &SentinelCauseError{Sentinel: ErrPolicyDeleteFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted policy: %s\n", name)
	return nil
}

// runPolicySetAutoUnseal executes the policy set-auto-unseal command.
func runPolicySetAutoUnseal(cmd *cobra.Command, args []string) (err error) {
	name := args[0]
	storePath, _ := cmd.Flags().GetString("store")

	store, err := policyStoreFactory(storePath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyAutoUnsealFailed, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()

	if err := store.SetAutoUnseal(ctx, name); err != nil {
		if errors.Is(err, pcrpolicy.ErrPolicyNotFound) {
			return &DetailError{Err: ErrPolicyNotFound, Detail: fmt.Sprintf(": %s", name)}
		}
		return &SentinelCauseError{Sentinel: ErrPolicyAutoUnsealFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Auto-unseal policy set: %s\n", name)
	return nil
}

// runPolicyClearAutoUnseal executes the policy clear-auto-unseal command.
func runPolicyClearAutoUnseal(cmd *cobra.Command, args []string) (err error) {
	storePath, _ := cmd.Flags().GetString("store")

	store, err := policyStoreFactory(storePath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyClearAutoFailed, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()

	if err := store.ClearAutoUnseal(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyClearAutoFailed, Cause: err}
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Auto-unseal policy cleared.")
	return nil
}

// runPolicyRefresh executes the policy refresh command.
func runPolicyRefresh(cmd *cobra.Command, args []string) (err error) {
	name := args[0]
	storePath, _ := cmd.Flags().GetString("store")

	store, err := policyStoreFactory(storePath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyRefreshFailed, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()

	entity, err := store.Get(ctx, name)
	if err != nil {
		if errors.Is(err, pcrpolicy.ErrPolicyNotFound) {
			return &DetailError{Err: ErrPolicyNotFound, Detail: fmt.Sprintf(": %s", name)}
		}
		return &SentinelCauseError{Sentinel: ErrPolicyRefreshFailed, Cause: err}
	}

	// Build the PCR indices from the entity.
	pcrIndices := sortedPCRIndices(entity.PCRs)
	uintIndices := make([]uint, len(pcrIndices))
	copy(uintIndices, pcrIndices)

	// Read current PCR values from TPM.
	bankLower := strings.ToLower(entity.Bank)
	values, err := readCurrentPCRValues(uintIndices, bankLower, policyTPMDevice, policyTPMSimulator)

	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyRefreshFailed, Cause: err}
	}

	// Update the entity PCR values.
	entity.PCRs = hexMapToBytes(values)

	// Re-create (upsert) with the updated values.
	if _, err := store.Create(ctx, entity.Name, entity.Bank, entity.PCRs); err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyRefreshFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Refreshed policy: %s\n", name)
	return nil
}

// runPolicyVerify executes the policy verify command.
func runPolicyVerify(cmd *cobra.Command, args []string) (err error) {
	name := args[0]
	storePath, _ := cmd.Flags().GetString("store")
	out := cmd.OutOrStdout()

	store, err := policyStoreFactory(storePath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyVerifyFailed, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()

	entity, err := store.Get(ctx, name)
	if err != nil {
		if errors.Is(err, pcrpolicy.ErrPolicyNotFound) {
			return &DetailError{Err: ErrPolicyNotFound, Detail: fmt.Sprintf(": %s", name)}
		}
		return &SentinelCauseError{Sentinel: ErrPolicyVerifyFailed, Cause: err}
	}

	// Build PCR indices from the entity.
	pcrIndices := sortedPCRIndices(entity.PCRs)
	uintIndices := make([]uint, len(pcrIndices))
	copy(uintIndices, pcrIndices)

	// Read current PCR values from TPM.
	bankLower := strings.ToLower(entity.Bank)
	currentHex, err := readCurrentPCRValues(uintIndices, bankLower, policyTPMDevice, policyTPMSimulator)

	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyVerifyFailed, Cause: err}
	}

	// Compare stored entity bytes against current hex values.
	currentBytes := hexMapToBytes(currentHex)
	mismatches := comparePCRByteValues(entity.PCRs, currentBytes)

	if len(mismatches) == 0 {
		_, _ = fmt.Fprintf(out, "Policy '%s': VALID - all PCR values match\n", name)
		return nil
	}

	_, _ = fmt.Fprintf(out, "Policy '%s': MISMATCH - %d PCR(s) differ\n\n", name, len(mismatches))
	for _, m := range mismatches {
		_, _ = fmt.Fprintf(out, "  PCR[%2d]:\n", m.index)
		_, _ = fmt.Fprintf(out, "    Expected: %s\n", m.expected)
		_, _ = fmt.Fprintf(out, "    Current:  %s\n", m.current)
	}

	return &DetailError{Err: ErrPolicyVerifyFailed, Detail: fmt.Sprintf(": %d PCR value(s) do not match", len(mismatches))}
}

// runPolicyExport executes the policy export command.
func runPolicyExport(cmd *cobra.Command, args []string) (err error) {
	name := args[0]
	storePath, _ := cmd.Flags().GetString("store")

	store, err := policyStoreFactory(storePath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyExportFailed, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()

	entity, err := store.Get(ctx, name)
	if err != nil {
		if errors.Is(err, pcrpolicy.ErrPolicyNotFound) {
			return &DetailError{Err: ErrPolicyNotFound, Detail: fmt.Sprintf(": %s", name)}
		}
		return &SentinelCauseError{Sentinel: ErrPolicyExportFailed, Cause: err}
	}

	// Build an export-friendly representation with hex-encoded PCR values.
	export := policyExportJSON{
		Name:       entity.Name,
		Bank:       entity.Bank,
		PCRs:       bytesMapToHex(entity.PCRs),
		AutoUnseal: entity.AutoUnseal,
		CreatedAt:  entity.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  entity.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(export); err != nil {
		return &SentinelCauseError{Sentinel: ErrPolicyExportFailed, Cause: err}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Export JSON type
// ---------------------------------------------------------------------------

// policyExportJSON is the JSON representation used for export.
type policyExportJSON struct {
	Name       string          `json:"name"`
	Bank       string          `json:"bank"`
	PCRs       map[uint]string `json:"pcrs"`
	AutoUnseal bool            `json:"auto_unseal"`
	CreatedAt  string          `json:"created_at"`
	UpdatedAt  string          `json:"updated_at"`
}

// ---------------------------------------------------------------------------
// PCR value comparison
// ---------------------------------------------------------------------------

// pcrMismatch records a single PCR value difference.
type pcrMismatch struct {
	index    uint
	expected string
	current  string
}

// comparePCRByteValues compares expected and current PCR value maps.
// Returns a slice of mismatches sorted by PCR index.
func comparePCRByteValues(expected, current map[uint][]byte) []pcrMismatch {
	var mismatches []pcrMismatch

	for idx, exp := range expected {
		cur, ok := current[idx]
		if !ok || hex.EncodeToString(exp) != hex.EncodeToString(cur) {
			mismatches = append(mismatches, pcrMismatch{
				index:    idx,
				expected: hex.EncodeToString(exp),
				current:  hex.EncodeToString(cur),
			})
		}
	}

	sort.Slice(mismatches, func(i, j int) bool {
		return mismatches[i].index < mismatches[j].index
	})

	return mismatches
}

// ---------------------------------------------------------------------------
// TPM PCR reading
// ---------------------------------------------------------------------------

// readCurrentPCRValues reads PCR values from the TPM for the given indices
// and bank. Returns a map from PCR index to hex-encoded value. device and
// useSimulator select which TPM to open (see resolveTPMDevice for the
// flag > TPM_DEVICE_PATH env > default precedence), independent of the
// `tpm` command group's own --device/--simulator flags.
func readCurrentPCRValues(indices []uint, bank, device string, useSimulator bool) (_ map[int]string, err error) {
	tpm, err := openTPMForProvisioningWithDeviceAndPCROverrides(resolveTPMDevice(device), useSimulator, "", nil, 0)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPolicyReadCurrentFailed, Cause: err}
	}
	defer func() {
		if closeErr := tpm.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	banks, err := tpm.ReadPCRs(indices)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPolicyReadCurrentFailed, Cause: err}
	}

	values := make(map[int]string)
	for _, b := range banks {
		if !strings.EqualFold(b.Algorithm, bank) {
			continue
		}
		for _, pcr := range b.PCRs {
			values[int(pcr.ID)] = fmt.Sprintf("%x", pcr.Value)
		}
	}

	if len(values) == 0 {
		return nil, &DetailError{Err: ErrPolicyReadCurrentFailed, Detail: fmt.Sprintf(": no values returned for bank %s", bank)}
	}

	return values, nil
}

// ---------------------------------------------------------------------------
// Store factory
// ---------------------------------------------------------------------------

// openPolicyStore creates a PolicyStore backed by a file-based kvstore at
// the given directory path. This is the production implementation of the
// policyStoreFactory function.
//
// An empty storePath (the --store flag's default) resolves through
// featureDataDir to <data dir>/pcr_policies -- the exact location the xKey
// GUI's own PCR policy store uses (pkg/gui/app.go, initializeDataDir) and
// the one every headless auto-unseal caller reads
// (tryBarrierPolicyAutoUnseal, barrier_auto_unseal.go). A policy created or
// designated with `xkey policy set-auto-unseal` is therefore visible to
// the GUI, `xkey extension serve`, `xkey fido2`, and `xkey barrier unseal
// --auto` without any of them needing to agree on a path explicitly.
// --store still overrides this for advanced or test use (a second profile,
// an isolated test directory, ...).
func openPolicyStore(storePath string) (pcrpolicy.PolicyStore, error) {
	if storePath == "" {
		resolved, err := featureDataDir(pcrPolicyStoreSubdir)
		if err != nil {
			return nil, err
		}
		storePath = resolved
	}

	backend, err := newFileStorageBackend(storePath)
	if err != nil {
		return nil, err
	}

	kvStore, err := newKVAdapter(backend)
	if err != nil {
		return nil, err
	}

	return pcrpolicy.NewDAOStore(kvStore)
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

// hexMapToBytes converts a map[int]string (hex-encoded) to map[uint][]byte.
func hexMapToBytes(hexMap map[int]string) map[uint][]byte {
	result := make(map[uint][]byte, len(hexMap))
	for idx, hexStr := range hexMap {
		decoded, err := hex.DecodeString(hexStr)
		if err != nil {
			// Store the raw hex as bytes if decoding fails.
			decoded = []byte(hexStr)
		}
		result[uint(idx)] = decoded
	}
	return result
}

// bytesMapToHex converts a map[uint][]byte to map[uint]string (hex-encoded).
func bytesMapToHex(bytesMap map[uint][]byte) map[uint]string {
	result := make(map[uint]string, len(bytesMap))
	for idx, val := range bytesMap {
		result[idx] = hex.EncodeToString(val)
	}
	return result
}

// sortedPCRIndices returns the sorted PCR indices from a PCR map.
func sortedPCRIndices(pcrs map[uint][]byte) []uint {
	indices := make([]uint, 0, len(pcrs))
	for idx := range pcrs {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return indices[i] < indices[j]
	})
	return indices
}

// formatPCRIndices formats PCR indices from a map into a human-readable
// comma-separated string like "0, 2, 4, 7".
func formatPCRIndices(pcrs map[uint][]byte) string {
	indices := sortedPCRIndices(pcrs)
	parts := make([]string, len(indices))
	for i, idx := range indices {
		parts[i] = fmt.Sprintf("%d", idx)
	}
	return strings.Join(parts, ", ")
}

// autoUnsealName returns the name of the current auto-unseal policy,
// or an empty string if none is set.
func autoUnsealName(store pcrpolicy.PolicyStore, ctx context.Context) string {
	autoPolicy, err := store.GetAutoUnsealPolicy(ctx)
	if err != nil {
		return ""
	}
	return autoPolicy.Name
}

// uintSliceToIntSlice converts []uint to []int.
func uintSliceToIntSlice(u []uint) []int {
	result := make([]int, len(u))
	for i, v := range u {
		result[i] = int(v)
	}
	return result
}

// intSliceToUintSlice converts []int to []uint.
func intSliceToUintSlice(s []int) []uint {
	result := make([]uint, len(s))
	for i, v := range s {
		result[i] = uint(v)
	}
	return result
}
