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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/spf13/cobra"
)

// FIDO2 RP policy command errors.
var (
	// ErrRPPolicyRPIDRequired indicates the --rpid flag is required.
	ErrRPPolicyRPIDRequired = errors.New("fido2 policy: --rpid is required")

	// ErrRPPolicyStoreCreationFailed indicates the RP policy store could not be created.
	ErrRPPolicyStoreCreationFailed = errors.New("fido2 policy: store creation failed")

	// ErrRPPolicyListFailed indicates listing policies failed.
	ErrRPPolicyListFailed = errors.New("fido2 policy: list failed")

	// ErrRPPolicyGetFailed indicates getting a policy failed.
	ErrRPPolicyGetFailed = errors.New("fido2 policy: get failed")

	// ErrRPPolicySetFailed indicates setting a policy failed.
	ErrRPPolicySetFailed = errors.New("fido2 policy: set failed")

	// ErrRPPolicyDeleteFailed indicates deleting a policy failed.
	ErrRPPolicyDeleteFailed = errors.New("fido2 policy: delete failed")

	// ErrRPPolicyMarshalFailed indicates JSON marshaling of a policy failed.
	ErrRPPolicyMarshalFailed = errors.New("fido2 policy: JSON marshal failed")

	// ErrRPPolicyInvalidUPOverride indicates an invalid --up flag value.
	ErrRPPolicyInvalidUPOverride = errors.New("fido2 policy: --up must be 'true', 'false', or '' (empty)")

	// ErrFIDO2ProfileInvalidTransport indicates an invalid transport value.
	ErrFIDO2ProfileInvalidTransport = errors.New("fido2 profile: invalid transport (must be usb, nfc, ble, internal, or hybrid)")
)

// rpPolicyCmd is the parent command for RP policy management under fido2.
var rpPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage per-RP authentication policies",
	Long: `Manage per-relying-party authentication policies for the FIDO2 authenticator.

These policies allow Security Officers to override RP requests for specific
relying parties, enabling enterprise governance over authenticator behavior.

Policies can control:
  - User verification requirements (required, preferred, discouraged)
  - User presence requirements (force on/off)
  - Attestation mode (none, indirect, direct, enterprise)
  - Enterprise attestation trust
  - Blocking specific RPs entirely

Examples:
  # List all RP policies
  xkey fido2 policy list

  # Require user verification for a specific RP
  xkey fido2 policy set --rpid example.com --uv required

  # Block an RP from using the authenticator
  xkey fido2 policy set --rpid malicious.com --blocked

  # Get a specific policy
  xkey fido2 policy get --rpid example.com

  # Delete a policy
  xkey fido2 policy delete --rpid example.com`,
}

// rpPolicyListCmd lists all RP policies.
var rpPolicyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all RP policies",
	RunE:  runRPPolicyList,
}

// rpPolicySetCmd creates or updates an RP policy.
var rpPolicySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Create or update an RP policy",
	RunE:  runRPPolicySet,
}

// rpPolicyGetCmd retrieves a specific RP policy.
var rpPolicyGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get an RP policy by RPID",
	RunE:  runRPPolicyGet,
}

// rpPolicyDeleteCmd deletes an RP policy.
var rpPolicyDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete an RP policy",
	RunE:  runRPPolicyDelete,
}

// fido2ProfileCmd is the parent command for authenticator profile configuration.
var fido2ProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Configure authenticator profile settings",
	Long: `Configure authenticator profile settings that affect the GetInfo response.

Profile settings control how the authenticator advertises its capabilities
to relying parties and browsers.

Examples:
  # Set transports to USB and internal
  xkey fido2 profile set --transports usb,internal

  # Enable enterprise attestation
  xkey fido2 profile set --enterprise-attestation`,
}

// fido2ProfileSetCmd sets authenticator profile configuration.
var fido2ProfileSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set authenticator profile settings",
	RunE:  runFIDO2ProfileSet,
}

// fido2ValidTransports is the set of valid FIDO2 transport values.
var fido2ValidTransports = map[string]bool{
	"usb":      true,
	"nfc":      true,
	"ble":      true,
	"internal": true,
	"hybrid":   true,
}

func init() {
	// Register policy and profile as fido2 subcommands.
	fido2Cmd.AddCommand(rpPolicyCmd)
	fido2Cmd.AddCommand(fido2ProfileCmd)

	// Policy subcommands.
	rpPolicyCmd.AddCommand(rpPolicyListCmd)
	rpPolicyCmd.AddCommand(rpPolicySetCmd)
	rpPolicyCmd.AddCommand(rpPolicyGetCmd)
	rpPolicyCmd.AddCommand(rpPolicyDeleteCmd)

	// Profile subcommands.
	fido2ProfileCmd.AddCommand(fido2ProfileSetCmd)

	// Policy set command flags.
	rpPolicySetCmd.Flags().String("rpid", "", "Relying party ID (required)")
	rpPolicySetCmd.Flags().String("uv", "", "UV override: '', 'required', 'preferred', 'discouraged'")
	rpPolicySetCmd.Flags().String("up", "", "UP override: 'true', 'false', '' (empty means no override)")
	rpPolicySetCmd.Flags().String("attestation", "", "Attestation override: '', 'none', 'indirect', 'direct', 'enterprise'")
	rpPolicySetCmd.Flags().Bool("enterprise", false, "Mark as enterprise-trusted")
	rpPolicySetCmd.Flags().Bool("blocked", false, "Block all operations for this RP")

	// Policy get/delete command flags.
	rpPolicyGetCmd.Flags().String("rpid", "", "Relying party ID (required)")
	rpPolicyDeleteCmd.Flags().String("rpid", "", "Relying party ID (required)")

	// Profile set command flags.
	fido2ProfileSetCmd.Flags().String("transports", "", "Comma-separated transports: usb, nfc, ble, internal, hybrid")
	fido2ProfileSetCmd.Flags().Bool("enterprise-attestation", false, "Enable enterprise attestation")
}

// createFIDO2RPPolicyStore creates an RPPolicyStore based on the FIDO2 config.
func createFIDO2RPPolicyStore(cfg *FIDO2Config) (authenticator.RPPolicyStore, error) {
	switch cfg.StorageType {
	case FIDO2StorageTypeMemory:
		return authenticator.NewMemoryRPPolicyStore(), nil

	case FIDO2StorageTypeFile:
		backend, err := file.New(cfg.StoragePath)
		if err != nil {
			return nil, errors.Join(ErrRPPolicyStoreCreationFailed, err)
		}
		store, err := authenticator.NewBackendRPPolicyStore(backend, "xkey/rp-policies/")
		if err != nil {
			_ = backend.Close()
			return nil, errors.Join(ErrRPPolicyStoreCreationFailed, err)
		}
		return store, nil

	default:
		return nil, ErrFIDO2InvalidStorageType
	}
}

// runRPPolicyList lists all RP policies in table format.
func runRPPolicyList(cmd *cobra.Command, args []string) error {
	cfg := buildFIDO2Config()
	store, err := createFIDO2RPPolicyStore(cfg)
	if err != nil {
		return err
	}

	policies, err := store.ListPolicies()
	if err != nil {
		return errors.Join(ErrRPPolicyListFailed, err)
	}

	if len(policies) == 0 {
		fmt.Fprintln(os.Stdout, "No RP policies configured.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RPID\tUV\tUP\tAttestation\tEnterprise\tBlocked")
	fmt.Fprintln(w, "----\t--\t--\t-----------\t----------\t-------")

	for _, p := range policies {
		upStr := ""
		if p.UPOverride != nil {
			upStr = fmt.Sprintf("%t", *p.UPOverride)
		}

		uvStr := p.UVOverride
		if uvStr == "" {
			uvStr = "(default)"
		}

		attStr := p.AttestationOverride
		if attStr == "" {
			attStr = "(default)"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%t\n",
			p.RPID, uvStr, upStr, attStr, p.Enterprise, p.Blocked)
	}

	return w.Flush()
}

// runRPPolicySet creates or updates an RP policy.
func runRPPolicySet(cmd *cobra.Command, args []string) error {
	rpid, err := cmd.Flags().GetString("rpid")
	if err != nil {
		return err
	}
	if rpid == "" {
		return ErrRPPolicyRPIDRequired
	}

	policy := &authenticator.RPPolicy{
		RPID: rpid,
	}

	// UV override.
	uv, err := cmd.Flags().GetString("uv")
	if err != nil {
		return err
	}
	policy.UVOverride = uv

	// UP override.
	upStr, err := cmd.Flags().GetString("up")
	if err != nil {
		return err
	}
	if upStr != "" {
		switch strings.ToLower(upStr) {
		case "true":
			v := true
			policy.UPOverride = &v
		case "false":
			v := false
			policy.UPOverride = &v
		default:
			return ErrRPPolicyInvalidUPOverride
		}
	}

	// Attestation override.
	att, err := cmd.Flags().GetString("attestation")
	if err != nil {
		return err
	}
	policy.AttestationOverride = att

	// Enterprise flag.
	enterprise, err := cmd.Flags().GetBool("enterprise")
	if err != nil {
		return err
	}
	policy.Enterprise = enterprise

	// Blocked flag.
	blocked, err := cmd.Flags().GetBool("blocked")
	if err != nil {
		return err
	}
	policy.Blocked = blocked

	// Validate the policy using the authenticator's own validation.
	if err := policy.Validate(); err != nil {
		return err
	}

	cfg := buildFIDO2Config()
	store, err := createFIDO2RPPolicyStore(cfg)
	if err != nil {
		return err
	}

	if err := store.SetPolicy(policy); err != nil {
		return errors.Join(ErrRPPolicySetFailed, err)
	}

	fmt.Fprintf(os.Stdout, "Policy set for RP: %s\n", rpid)
	return nil
}

// runRPPolicyGet retrieves and displays a specific RP policy as JSON.
func runRPPolicyGet(cmd *cobra.Command, args []string) error {
	rpid, err := cmd.Flags().GetString("rpid")
	if err != nil {
		return err
	}
	if rpid == "" {
		return ErrRPPolicyRPIDRequired
	}

	cfg := buildFIDO2Config()
	store, err := createFIDO2RPPolicyStore(cfg)
	if err != nil {
		return err
	}

	policy, err := store.GetPolicy(rpid)
	if err != nil {
		return errors.Join(ErrRPPolicyGetFailed, err)
	}

	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return errors.Join(ErrRPPolicyMarshalFailed, err)
	}

	fmt.Fprintln(os.Stdout, string(data))
	return nil
}

// runRPPolicyDelete deletes a specific RP policy.
func runRPPolicyDelete(cmd *cobra.Command, args []string) error {
	rpid, err := cmd.Flags().GetString("rpid")
	if err != nil {
		return err
	}
	if rpid == "" {
		return ErrRPPolicyRPIDRequired
	}

	cfg := buildFIDO2Config()
	store, err := createFIDO2RPPolicyStore(cfg)
	if err != nil {
		return err
	}

	if err := store.DeletePolicy(rpid); err != nil {
		return errors.Join(ErrRPPolicyDeleteFailed, err)
	}

	fmt.Fprintf(os.Stdout, "Policy deleted for RP: %s\n", rpid)
	return nil
}

// runFIDO2ProfileSet displays the profile settings that would be applied.
func runFIDO2ProfileSet(cmd *cobra.Command, args []string) error {
	transportsStr, err := cmd.Flags().GetString("transports")
	if err != nil {
		return err
	}

	enterpriseAttestation, err := cmd.Flags().GetBool("enterprise-attestation")
	if err != nil {
		return err
	}

	// Parse and validate transports.
	var transports []string
	if transportsStr != "" {
		for _, t := range strings.Split(transportsStr, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if !fido2ValidTransports[t] {
				return fmt.Errorf("%w: %q", ErrFIDO2ProfileInvalidTransport, t)
			}
			transports = append(transports, t)
		}
	}

	// Print the profile settings that would be applied.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Setting\tValue")
	fmt.Fprintln(w, "-------\t-----")

	if len(transports) > 0 {
		fmt.Fprintf(w, "Transports\t%s\n", strings.Join(transports, ", "))
	}
	fmt.Fprintf(w, "Enterprise Attestation\t%t\n", enterpriseAttestation)

	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, "\nProfile settings displayed. Config file persistence is not yet implemented.")
	return nil
}
