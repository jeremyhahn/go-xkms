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

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// TPM policy command errors.
var (
	// ErrTPMPolicyNotSatisfied indicates `tpm policy verify` found the live
	// PCRs differ from the captured ones, or the approval is not current:
	// objects bound to the policy will not unseal through it.
	ErrTPMPolicyNotSatisfied = errors.New("tpm policy: the live platform state does not satisfy the policy")

	// ErrTPMPolicyAutoUnsealName indicates `tpm policy auto-unseal` was
	// given no policy name without --off, or a name with --off.
	ErrTPMPolicyAutoUnsealName = errors.New("tpm policy: auto-unseal takes a policy name, or --off without one")

	// ErrTPMPolicyServerConnect indicates the configured xkmsd could not be
	// reached.
	ErrTPMPolicyServerConnect = errors.New("tpm policy: failed to connect to xkmsd")
)

var (
	tpmPolicyPCRs        string
	tpmPolicyBank        string
	tpmPolicyBranchSpecs []string
	tpmPolicyDescription string
	tpmPolicyAutoUnseal  bool
	tpmPolicyOff         bool
)

// tpmPolicySession is the TPM policy service one command runs on, and what
// it holds open.
type tpmPolicySession struct {
	svc *services.TPMPolicyService

	// local is the in-process service over this host's TPM; nil when the
	// command runs on a connected xkmsd.
	local *services.LocalTPMPolicies

	closer io.Closer
}

// Close releases the connection or the local TPM.
func (s *tpmPolicySession) Close() error {
	if s.closer == nil {
		return nil
	}
	return s.closer.Close()
}

// tpmPolicySessionFactory opens the TPM policy service for a command. Tests
// replace it.
var tpmPolicySessionFactory = openTPMPolicySession

// openTPMPolicySession opens the TPM policy service a command runs on, with
// the same rule as every other xkey command: a configured xkmsd
// (--xkmsd-url, XKMSD_URL or the config) makes it server mode; otherwise it
// runs locally over this host's TPM (the tpm group's --device/--simulator),
// with the registry in the xKey data directory, shared with the GUI.
func openTPMPolicySession(cmd *cobra.Command) (*tpmPolicySession, error) {
	svc := services.NewTPMPolicyService()
	svc.SetContext(cmd.Context())
	if resolveXKMSdURL() != "" {
		client, err := connectXKMSdClient(cmd)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrTPMPolicyServerConnect, Cause: err}
		}
		svc.SetClient(client)
		return &tpmPolicySession{svc: svc, closer: client}, nil
	}
	dataDir, err := resolveDataDir("")
	if err != nil {
		return nil, err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: getLogLevel()}))
	local, err := openLocalTPMPolicies(logger, dataDir, tpmCfg.device, tpmCfg.useSimulator)
	if err != nil {
		return nil, err
	}
	svc.SetLocal(local.LocalTPMPolicies)
	return &tpmPolicySession{svc: svc, local: local.LocalTPMPolicies, closer: local}, nil
}

// withTPMPolicies runs fn on the command's TPM policy service and closes it
// afterwards.
func withTPMPolicies(cmd *cobra.Command, fn func(*tpmPolicySession) error) (err error) {
	session, err := tpmPolicySessionFactory(cmd)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, session.Close()) }()
	return fn(session)
}

// tpmPolicyCmd is `xkey tpm policy`.
var tpmPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Named TPM policies",
	Long: `Manage named TPM policies.

A named TPM policy is an OR of branches, each an AND of conditions: pcr (a
PCR bank and selection whose values are captured live from the TPM),
auth_value (the object's password) and locality (the TPM localities a
command may come from). The scope's TPM-resident policy authority approves
every branch.
Keys and sealed objects reference one policy by name; the TPM enforces it
every time they are used. The built-in "platform" policy (the platform PCR,
or the object's password) always exists and is the default.

The commands run on the xkmsd server when one is configured (--xkmsd-url,
XKMSD_URL, or the xkey config), and otherwise on this host's own TPM, with
the policy registry kept in the xKey data directory (shared with the GUI).`,
	Example: `  # Create a policy over the firmware and Secure Boot PCRs
  xkey tpm policy create boot --pcrs 0,7 --description "firmware and Secure Boot"

  # PCRs 0 and 7, or the object's password
  xkey tpm policy create boot-or-pin --branch 'pcr=sha256:0,7' --branch auth_value

  # List policies with the number of objects bound to each
  xkey tpm policy list

  # After a firmware update: check, then re-capture and re-approve
  xkey tpm policy verify boot
  xkey tpm policy update boot

  # Make the policy the barrier's auto-unseal policy
  xkey tpm policy auto-unseal boot`,
}

// tpmPolicyCreateCmd is `xkey tpm policy create`.
var tpmPolicyCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a named policy over the live PCR values",
	Long: `Create a named policy. The values of its pcr conditions are read from
the TPM, never supplied.

--pcrs (with --bank) creates the common policy of one branch holding one
pcr condition. --branch, repeatable, gives each branch as conditions joined
by ";":

  pcr=[BANK:]LIST   the PCRs in LIST of BANK (sha256 when omitted)
  auth_value        the object's password
  locality=LIST     the TPM localities (0-4) in LIST

LIST is comma-separated indices or ranges ("0,7" or "0-7"). Branches are
tried in order when an object is used. --pcrs and --branch are mutually
exclusive.

--hierarchy-auth is the TPM owner password when the owner hierarchy has one
(it authorizes the policy's NV index).`,
	Example: `  xkey tpm policy create boot --pcrs 0,7 --description "firmware and Secure Boot"
  xkey tpm policy create kernel --pcrs 0-9 --bank sha384
  xkey tpm policy create strict --branch 'pcr=sha256:0,7;auth_value;locality=0'`,
	Args: cobra.ExactArgs(1),
	RunE: runTPMPolicyCreate,
}

// tpmPolicyDescribeCmd is `xkey tpm policy describe`.
var tpmPolicyDescribeCmd = &cobra.Command{
	Use:     "describe <name> <text>",
	Short:   "Set a policy's description",
	Long:    `Replace a policy's free-text description; an empty text clears it.`,
	Example: `  xkey tpm policy describe boot "firmware and Secure Boot state"`,
	Args:    cobra.ExactArgs(2),
	RunE:    runTPMPolicyDescribe,
}

// tpmPolicyListCmd is `xkey tpm policy list`.
var tpmPolicyListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List policies with their object counts",
	Args:    cobra.NoArgs,
	RunE:    runTPMPolicyList,
}

// tpmPolicyGetCmd is `xkey tpm policy get`.
var tpmPolicyGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Show a policy and its captured PCR values",
	Args:  cobra.ExactArgs(1),
	RunE:  runTPMPolicyGet,
}

// tpmPolicyUpdateCmd is `xkey tpm policy update`.
var tpmPolicyUpdateCmd = &cobra.Command{
	Use:   "update <name>",
	Short: "Re-capture the PCR values and re-approve the policy",
	Long: `Re-capture the policy's PCR values from the TPM and re-approve it.

Use it after an intended change of platform state (a firmware or boot loader
update). No key or sealed object is re-keyed; a revoked policy is approved
again.`,
	Args: cobra.ExactArgs(1),
	RunE: runTPMPolicyUpdate,
}

// tpmPolicyRevokeCmd is `xkey tpm policy revoke`.
var tpmPolicyRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Withdraw the policy's approval",
	Long: `Withdraw the policy's approval. Its objects then answer only to their
password, if they have one, until the policy is updated.`,
	Args: cobra.ExactArgs(1),
	RunE: runTPMPolicyRevoke,
}

// tpmPolicyVerifyCmd is `xkey tpm policy verify`.
var tpmPolicyVerifyCmd = &cobra.Command{
	Use:   "verify <name>",
	Short: "Compare the live PCRs with the captured ones",
	Long: `Compare the live PCR values with those the policy captured, and report
whether its approval is current. The check is advisory -- the TPM enforces
the policy on use -- and exits non-zero when the policy is not satisfied.`,
	Args: cobra.ExactArgs(1),
	RunE: runTPMPolicyVerify,
}

// tpmPolicyDeleteCmd is `xkey tpm policy delete`.
var tpmPolicyDeleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"rm"},
	Short:   "Delete a policy no object uses",
	Long: `Delete a policy and its NV index. It is refused, listing them, while
keys or sealed objects are bound to the policy.`,
	Args: cobra.ExactArgs(1),
	RunE: runTPMPolicyDelete,
}

// tpmPolicyObjectsCmd is `xkey tpm policy objects`.
var tpmPolicyObjectsCmd = &cobra.Command{
	Use:   "objects <name>",
	Short: "List the keys and sealed objects bound to a policy",
	Example: `  xkey tpm policy objects boot
  xkey tpm policy objects platform`,
	Args: cobra.ExactArgs(1),
	RunE: runTPMPolicyObjects,
}

// tpmPolicyKeyCmd is `xkey tpm policy key`.
var tpmPolicyKeyCmd = &cobra.Command{
	Use:   "key <key-id>",
	Short: "Show the policy a TPM key is bound to",
	Args:  cobra.ExactArgs(1),
	RunE:  runTPMPolicyKey,
}

// tpmPolicyAutoUnsealCmd is `xkey tpm policy auto-unseal`.
var tpmPolicyAutoUnsealCmd = &cobra.Command{
	Use:   "auto-unseal [name]",
	Short: "Set or clear the barrier auto-unseal policy",
	Long: `Make a named policy the barrier auto-unseal policy (at most one per
scope), or clear it with --off.

Locally, this also seals the barrier password in the TPM under the policy,
so the barrier opens at boot -- without a password -- only while the PCRs
hold the values the policy approves. The password is read from the terminal,
or from stdin when it is piped. On a server it sets the policy's mark for the
server's barrier.`,
	Example: `  xkey tpm policy auto-unseal boot
  echo "$BARRIER_PASSWORD" | xkey tpm policy auto-unseal boot
  xkey tpm policy auto-unseal --off`,
	Args: cobra.RangeArgs(0, 1),
	RunE: runTPMPolicyAutoUnseal,
}

// tpmAuthorityCmd is `xkey tpm authority`.
var tpmAuthorityCmd = &cobra.Command{
	Use:   "authority",
	Short: "TPM policy authority",
}

// tpmAuthorityRotateCmd is `xkey tpm authority rotate`.
var tpmAuthorityRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Replace the policy authority",
	Long: `Replace the scope's TPM-resident policy authority. Every policy is
re-approved by the new authority and the old one stops authorizing anything.
No key or sealed object is re-keyed.`,
	Args: cobra.NoArgs,
	RunE: runTPMAuthorityRotate,
}

func init() {
	tpmPolicyCreateCmd.Flags().StringVar(&tpmPolicyPCRs, "pcrs", "", "PCR indices of a one-branch policy, e.g. 0,7 or 0-7")
	tpmPolicyCreateCmd.Flags().StringVar(&tpmPolicyBank, "bank", "", "PCR bank of --pcrs: sha1, sha256, sha384 or sha512 (default sha256)")
	tpmPolicyCreateCmd.Flags().StringArrayVar(&tpmPolicyBranchSpecs, "branch", nil,
		"A policy branch, e.g. 'pcr=sha256:0,7;auth_value;locality=0' (repeatable)")
	tpmPolicyCreateCmd.Flags().StringVar(&tpmPolicyDescription, "description", "", "Free-text description of the policy")
	tpmPolicyCreateCmd.Flags().BoolVar(&tpmPolicyAutoUnseal, "auto-unseal", false,
		"Also make it the barrier auto-unseal policy (see 'tpm policy auto-unseal')")
	tpmPolicyAutoUnsealCmd.Flags().BoolVar(&tpmPolicyOff, "off", false, "Clear the auto-unseal policy")

	tpmPolicyCmd.AddCommand(tpmPolicyCreateCmd, tpmPolicyDescribeCmd, tpmPolicyListCmd, tpmPolicyGetCmd, tpmPolicyUpdateCmd,
		tpmPolicyRevokeCmd, tpmPolicyVerifyCmd, tpmPolicyDeleteCmd, tpmPolicyObjectsCmd, tpmPolicyKeyCmd,
		tpmPolicyAutoUnsealCmd)
	tpmAuthorityCmd.AddCommand(tpmAuthorityRotateCmd)
	tpmCmd.AddCommand(tpmPolicyCmd, tpmAuthorityCmd)
}

// writeTPMPolicyOutput writes v as JSON with -o json, or with text
// otherwise.
func writeTPMPolicyOutput(out io.Writer, v any, text func(io.Writer) error) error {
	if tpmCfg.outputFormat == "json" {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(v)
	}
	return text(out)
}

func runTPMPolicyCreate(cmd *cobra.Command, args []string) error {
	var pcrs []uint
	if tpmPolicyPCRs != "" {
		var err error
		if pcrs, err = parsePCRIndicesForPCRs(tpmPolicyPCRs); err != nil {
			return err
		}
	}
	branches, err := xkms.TPMPolicyBranches(tpmPolicyBank, pcrs, tpmPolicyBranchSpecs)
	if err != nil {
		return err
	}
	return withTPMPolicies(cmd, func(s *tpmPolicySession) error {
		// Locally the auto-unseal mark comes with the sealed barrier
		// credential, so it is set by the auto-unseal flow below.
		markOnCreate := tpmPolicyAutoUnseal && s.local == nil
		p, err := s.svc.CreatePolicy(args[0], tpmPolicyDescription, branches, markOnCreate, tpmCfg.hierarchyAuth)
		if err != nil {
			return err
		}
		if tpmPolicyAutoUnseal && s.local != nil {
			if err := enableLocalAutoUnseal(cmd, s.local, p.Name); err != nil {
				return err
			}
			p.AutoUnseal = true
		}
		return writeTPMPolicyOutput(cmd.OutOrStdout(), p, func(out io.Writer) error {
			return renderTPMPolicy(out, p)
		})
	})
}

func runTPMPolicyDescribe(cmd *cobra.Command, args []string) error {
	return runTPMPolicyShow(cmd, args[0], func(svc *services.TPMPolicyService, name string) (*services.TPMPolicyInfo, error) {
		return svc.SetDescription(name, args[1])
	})
}

func runTPMPolicyList(cmd *cobra.Command, _ []string) error {
	return withTPMPolicies(cmd, func(s *tpmPolicySession) error {
		policies, err := s.svc.ListPolicies()
		if err != nil {
			return err
		}
		return writeTPMPolicyOutput(cmd.OutOrStdout(), policies, func(out io.Writer) error {
			return renderTPMPolicyList(out, s.svc.GetStatus(), policies)
		})
	})
}

func runTPMPolicyGet(cmd *cobra.Command, args []string) error {
	return runTPMPolicyShow(cmd, args[0], (*services.TPMPolicyService).GetPolicy)
}

func runTPMPolicyUpdate(cmd *cobra.Command, args []string) error {
	return runTPMPolicyShow(cmd, args[0], (*services.TPMPolicyService).UpdatePolicy)
}

func runTPMPolicyRevoke(cmd *cobra.Command, args []string) error {
	return runTPMPolicyShow(cmd, args[0], (*services.TPMPolicyService).RevokePolicy)
}

// runTPMPolicyShow runs op, an operation that returns one policy, and shows
// the policy.
func runTPMPolicyShow(cmd *cobra.Command, name string, op func(*services.TPMPolicyService, string) (*services.TPMPolicyInfo, error)) error {
	return withTPMPolicies(cmd, func(s *tpmPolicySession) error {
		p, err := op(s.svc, name)
		if err != nil {
			return err
		}
		return writeTPMPolicyOutput(cmd.OutOrStdout(), p, func(out io.Writer) error {
			return renderTPMPolicy(out, p)
		})
	})
}

func runTPMPolicyVerify(cmd *cobra.Command, args []string) error {
	return withTPMPolicies(cmd, func(s *tpmPolicySession) error {
		v, err := s.svc.VerifyPolicy(args[0])
		if err != nil {
			return err
		}
		if err := writeTPMPolicyOutput(cmd.OutOrStdout(), v, func(out io.Writer) error {
			return renderTPMPolicyVerification(out, v)
		}); err != nil {
			return err
		}
		if !v.Match || !v.Approved {
			return ErrTPMPolicyNotSatisfied
		}
		return nil
	})
}

func runTPMPolicyDelete(cmd *cobra.Command, args []string) error {
	return withTPMPolicies(cmd, func(s *tpmPolicySession) error {
		if err := s.svc.DeletePolicy(args[0], tpmCfg.hierarchyAuth); err != nil {
			return err
		}
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "Deleted TPM policy %q\n", args[0])
		return err
	})
}

func runTPMPolicyObjects(cmd *cobra.Command, args []string) error {
	return withTPMPolicies(cmd, func(s *tpmPolicySession) error {
		objects, err := s.svc.PolicyObjects(args[0])
		if err != nil {
			return err
		}
		return writeTPMPolicyOutput(cmd.OutOrStdout(), objects, func(out io.Writer) error {
			if len(objects) == 0 {
				_, err := fmt.Fprintf(out, "No objects are bound to %q\n", args[0])
				return err
			}
			for _, id := range objects {
				if _, err := fmt.Fprintln(out, id); err != nil {
					return err
				}
			}
			return nil
		})
	})
}

func runTPMPolicyKey(cmd *cobra.Command, args []string) error {
	return withTPMPolicies(cmd, func(s *tpmPolicySession) error {
		info, err := s.svc.KeyPolicy(args[0])
		if err != nil {
			return err
		}
		return writeTPMPolicyOutput(cmd.OutOrStdout(), info, func(out io.Writer) error {
			_, err := fmt.Fprintf(out, "Object:     %s\nPolicy:     %s\nCreated:    %s\n", info.ObjectID, info.Policy, info.CreatedAt)
			return err
		})
	})
}

func runTPMPolicyAutoUnseal(cmd *cobra.Command, args []string) error {
	if (len(args) == 1) == tpmPolicyOff {
		return ErrTPMPolicyAutoUnsealName
	}
	return withTPMPolicies(cmd, func(s *tpmPolicySession) error {
		out := cmd.OutOrStdout()
		switch {
		case s.local != nil && tpmPolicyOff:
			if err := services.NewBarrierAutoUnsealService(services.WithBarrierAutoUnsealLocal(s.local)).DisableAutoUnseal(); err != nil {
				return err
			}
			_, err := fmt.Fprintln(out, "Barrier auto-unseal disabled")
			return err
		case s.local != nil:
			if err := enableLocalAutoUnseal(cmd, s.local, args[0]); err != nil {
				return err
			}
			_, err := fmt.Fprintf(out, "Barrier auto-unseal enabled under TPM policy %q\n", args[0])
			return err
		case tpmPolicyOff:
			return clearServerAutoUnseal(s.svc, out)
		default:
			p, err := s.svc.SetAutoUnseal(args[0], true)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(out, "TPM policy %q is the auto-unseal policy\n", p.Name)
			return err
		}
	})
}

// enableLocalAutoUnseal reads the barrier password and seals it in the TPM
// under the named policy, making it the auto-unseal policy.
func enableLocalAutoUnseal(cmd *cobra.Command, local *services.LocalTPMPolicies, name string) error {
	password, err := readBarrierPassword(cmd.ErrOrStderr(), "Enter barrier password: ")
	if err != nil {
		return err
	}
	return services.NewBarrierAutoUnsealService(services.WithBarrierAutoUnsealLocal(local)).EnableAutoUnseal(name, password)
}

// clearServerAutoUnseal clears the auto-unseal mark of whichever of the
// server's policies carries it.
func clearServerAutoUnseal(svc *services.TPMPolicyService, out io.Writer) error {
	policies, err := svc.ListPolicies()
	if err != nil {
		return err
	}
	for _, p := range policies {
		if !p.AutoUnseal {
			continue
		}
		if _, err := svc.SetAutoUnseal(p.Name, false); err != nil {
			return err
		}
		_, err := fmt.Fprintf(out, "TPM policy %q is no longer the auto-unseal policy\n", p.Name)
		return err
	}
	_, err = fmt.Fprintln(out, "No TPM policy is the auto-unseal policy")
	return err
}

func runTPMAuthorityRotate(cmd *cobra.Command, _ []string) error {
	return withTPMPolicies(cmd, func(s *tpmPolicySession) error {
		a, err := s.svc.RotateAuthority()
		if err != nil {
			return err
		}
		return writeTPMPolicyOutput(cmd.OutOrStdout(), a, func(out io.Writer) error {
			_, err := fmt.Fprintf(out, "Policy authority rotated\n  Generation: %d\n  Name:       %s\n  Epoch:      %d\n",
				a.Generation, a.AuthorityName, a.Epoch)
			return err
		})
	})
}

// renderTPMPolicyList writes the policies as a table under a line naming
// where they live.
func renderTPMPolicyList(out io.Writer, status *services.TPMPolicyStatus, policies []services.TPMPolicyInfo) error {
	source := "local TPM (system scope)"
	if status.Mode == services.TPMPolicyModeServer {
		source = "xkmsd"
	}
	if _, err := fmt.Fprintf(out, "Source: %s\n\n", source); err != nil {
		return err
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "NAME\tBRANCHES\tAPPROVED\tAUTO-UNSEAL\tOBJECTS\tDESCRIPTION"); err != nil {
		return err
	}
	for _, p := range policies {
		branches := branchSummary(p.Branches)
		if p.Builtin {
			branches = "platform PCR or password"
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			p.Name, branches, yesNo(p.Approved), yesNo(p.AutoUnseal), p.ObjectCount, p.Description); err != nil {
			return err
		}
	}
	return w.Flush()
}

// branchSummary joins branches in spec form with " | ".
func branchSummary(branches []transport.TPMPolicyBranch) string {
	parts := make([]string, len(branches))
	for i, b := range branches {
		parts[i] = b.String()
	}
	return strings.Join(parts, " | ")
}

// renderTPMPolicy writes one policy in detail.
func renderTPMPolicy(out io.Writer, p *services.TPMPolicyInfo) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Name:         %s\n", p.Name)
	if p.Description != "" {
		fmt.Fprintf(&b, "Description:  %s\n", p.Description)
	}
	fmt.Fprintf(&b, "NV index:     0x%08x\n", p.Index)
	fmt.Fprintf(&b, "Approved:     %s\n", yesNo(p.Approved))
	if p.Approved {
		fmt.Fprintf(&b, "Epoch:        %d (authority generation %d)\n", p.Epoch, p.AuthorityGeneration)
	}
	fmt.Fprintf(&b, "Auto-unseal:  %s\n", yesNo(p.AutoUnseal))
	fmt.Fprintf(&b, "Objects:      %d\n", p.ObjectCount)
	for i, branch := range p.Branches {
		fmt.Fprintf(&b, "Branch %d:     %s (approved: %s)\n", i, branch.String(), yesNo(branch.Approved))
		for _, c := range branch.Conditions {
			pcrs := make([]uint, 0, len(c.PCRValues))
			for pcr := range c.PCRValues {
				pcrs = append(pcrs, pcr)
			}
			sort.Slice(pcrs, func(i, j int) bool { return pcrs[i] < pcrs[j] })
			for _, pcr := range pcrs {
				fmt.Fprintf(&b, "  PCR %-2d      %s\n", pcr, c.PCRValues[pcr])
			}
		}
	}
	fmt.Fprintf(&b, "Created:      %s\n", p.CreatedAt)
	if p.UpdatedAt != "" {
		fmt.Fprintf(&b, "Updated:      %s\n", p.UpdatedAt)
	}
	_, err := io.WriteString(out, b.String())
	return err
}

// renderTPMPolicyVerification writes a verification result, one line per
// branch.
func renderTPMPolicyVerification(out io.Writer, v *services.TPMPolicyVerification) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Policy:    %s\n", v.Name)
	for i, branch := range v.Branches {
		state := "PCRs match the captured values"
		if !branch.Match {
			state = "PCRs changed: " + formatPCRList(branch.Mismatched)
		}
		approval := "current"
		if !branch.Approved {
			approval = "not current (revoked or out of date)"
		}
		fmt.Fprintf(&b, "Branch %d:  %s; approval %s\n", i, state, approval)
	}
	_, err := io.WriteString(out, b.String())
	return err
}

// formatPCRList formats PCR indices as "0,7,9".
func formatPCRList(pcrs []uint) string {
	parts := make([]string, len(pcrs))
	for i, pcr := range pcrs {
		parts[i] = fmt.Sprint(pcr)
	}
	return strings.Join(parts, ",")
}

// yesNo renders a flag for a table.
func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
