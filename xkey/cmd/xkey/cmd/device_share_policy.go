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
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// Sharing policy constants.
const (
	sharingPoliciesFileName = "sharing-policies.json"
)

// Share policy errors.
var (
	// ErrSharePolicyLoadFailed indicates the sharing policy store could not be loaded.
	ErrSharePolicyLoadFailed = errors.New("device: failed to load sharing policy store")

	// ErrSharePolicySetFailed indicates the sharing policy could not be set.
	ErrSharePolicySetFailed = errors.New("device: failed to set sharing policy")

	// ErrSharePolicyRemoveFailed indicates the sharing policy could not be removed.
	ErrSharePolicyRemoveFailed = errors.New("device: failed to remove sharing policy")
)

// deviceSharePolicyCmd is the parent command for share-policy subcommands.
var deviceSharePolicyCmd = &cobra.Command{
	Use:   "share-policy",
	Short: "Manage key sharing policies",
	Long: `Manage sharing policies that control which keys can be shared
with paired phone devices.

By default, all key sharing is denied. Use 'share-policy set' to
explicitly allow sharing for specific keys.

Examples:
  xkey device share-policy list
  xkey device share-policy set software my-key --allow
  xkey device share-policy remove software my-key`,
}

// deviceSharePolicyListCmd lists all sharing policies.
var deviceSharePolicyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List key sharing policies",
	Long: `List all configured key sharing policies.

Displays each policy's backend, key ID, sharing permissions,
and allowed device restrictions.

Examples:
  xkey device share-policy list`,
	RunE: runSharePolicyList,
}

// deviceSharePolicySetCmd sets a sharing policy for a key.
var deviceSharePolicySetCmd = &cobra.Command{
	Use:   "set <backend> <key-id>",
	Short: "Set sharing policy for a key",
	Long: `Enable key sharing and configure the sharing policy for a key.

By default, all key sharing is denied. This command creates or updates
a sharing policy to allow a key to be shared with paired devices.

Use --allow to enable sharing. Without --allow, the policy is created
but sharing remains denied (useful for pre-configuring policies).

Examples:
  xkey device share-policy set software my-key --allow
  xkey device share-policy set software my-key --allow --share-public --share-symmetric
  xkey device share-policy set tpm2 ek --allow --share-public
  xkey device share-policy set software my-key --allow --devices "fp1,fp2"`,
	Args: cobra.ExactArgs(2),
	RunE: runSharePolicySet,
}

// deviceSharePolicyRemoveCmd removes a sharing policy for a key.
var deviceSharePolicyRemoveCmd = &cobra.Command{
	Use:   "remove <backend> <key-id>",
	Short: "Remove sharing policy for a key",
	Long: `Remove the sharing policy for a key.

After removal, sharing for this key reverts to the default deny behavior.

Examples:
  xkey device share-policy remove software my-key
  xkey device share-policy remove tpm2 ek`,
	Args: cobra.ExactArgs(2),
	RunE: runSharePolicyRemove,
}

func init() {
	deviceCmd.AddCommand(deviceSharePolicyCmd)
	deviceSharePolicyCmd.AddCommand(deviceSharePolicyListCmd)
	deviceSharePolicyCmd.AddCommand(deviceSharePolicySetCmd)
	deviceSharePolicyCmd.AddCommand(deviceSharePolicyRemoveCmd)

	// Share policy set flags
	deviceSharePolicySetCmd.Flags().Bool("allow", false, "Allow sharing for this key")
	deviceSharePolicySetCmd.Flags().Bool("share-public", true, "Allow sharing public key")
	deviceSharePolicySetCmd.Flags().Bool("share-symmetric", false, "Allow sharing symmetric key material")
	deviceSharePolicySetCmd.Flags().Bool("share-private", false, "Allow sharing private key (software keys only)")
	deviceSharePolicySetCmd.Flags().StringSlice("devices", nil, "Allowed device fingerprints (comma-separated)")
}

// runSharePolicyList lists all configured sharing policies.
func runSharePolicyList(cmd *cobra.Command, args []string) error {
	store, err := loadSharingPolicyStore()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSharePolicyLoadFailed, err)
	}

	policies, err := store.ListPolicies()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSharePolicyLoadFailed, err)
	}

	if len(policies) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No sharing policies configured.")
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), "Use 'xkey device share-policy set <backend> <key-id> --allow' to create one.")
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Sharing Policies (%d):\n\n", len(policies))

	// Table header
	fmt.Fprintf(cmd.OutOrStdout(), "  %-12s %-20s %-8s %-8s %-8s %-10s %s\n",
		"BACKEND", "KEY ID", "ALLOW", "PUBLIC", "SYMM", "PRIVATE", "DEVICES")
	fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", strings.Repeat("-", 80))

	for _, p := range policies {
		devicesStr := "(any)"
		if len(p.AllowedDevices) > 0 {
			devicesStr = fmt.Sprintf("%d device(s)", len(p.AllowedDevices))
		}

		fmt.Fprintf(cmd.OutOrStdout(), "  %-12s %-20s %-8v %-8v %-8v %-10v %s\n",
			p.Backend,
			truncatePolicyKeyID(p.KeyID),
			p.AllowShare,
			p.SharePublic,
			p.ShareSymmetric,
			p.SharePrivate,
			devicesStr,
		)
	}

	fmt.Fprintln(cmd.OutOrStdout())
	return nil
}

// runSharePolicySet creates or updates a sharing policy for a key.
func runSharePolicySet(cmd *cobra.Command, args []string) error {
	backend := args[0]
	keyID := args[1]

	allow, _ := cmd.Flags().GetBool("allow")
	sharePublic, _ := cmd.Flags().GetBool("share-public")
	shareSymmetric, _ := cmd.Flags().GetBool("share-symmetric")
	sharePrivate, _ := cmd.Flags().GetBool("share-private")
	devices, _ := cmd.Flags().GetStringSlice("devices")

	store, err := loadSharingPolicyStore()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSharePolicyLoadFailed, err)
	}

	policy := &phone.SharingPolicy{
		KeyID:          keyID,
		Backend:        backend,
		AllowShare:     allow,
		SharePublic:    sharePublic,
		ShareSymmetric: shareSymmetric,
		SharePrivate:   sharePrivate,
		AllowedDevices: devices,
	}

	if err := store.SetPolicy(policy); err != nil {
		return fmt.Errorf("%w: %v", ErrSharePolicySetFailed, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Sharing policy set for %s/%s:\n", backend, keyID)
	fmt.Fprintf(cmd.OutOrStdout(), "  Allow Sharing:     %v\n", allow)
	fmt.Fprintf(cmd.OutOrStdout(), "  Share Public Key:  %v\n", sharePublic)
	fmt.Fprintf(cmd.OutOrStdout(), "  Share Symmetric:   %v\n", shareSymmetric)
	fmt.Fprintf(cmd.OutOrStdout(), "  Share Private:     %v\n", sharePrivate)

	if len(devices) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "  Allowed Devices:   %s\n", strings.Join(devices, ", "))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "  Allowed Devices:   (any paired device)\n")
	}

	return nil
}

// runSharePolicyRemove removes a sharing policy for a key.
func runSharePolicyRemove(cmd *cobra.Command, args []string) error {
	backend := args[0]
	keyID := args[1]

	store, err := loadSharingPolicyStore()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSharePolicyLoadFailed, err)
	}

	if err := store.DeletePolicy(backend, keyID); err != nil {
		if errors.Is(err, phone.ErrSharePolicyNotFound) {
			return fmt.Errorf("%w: no policy found for %s/%s", ErrSharePolicyRemoveFailed, backend, keyID)
		}
		return fmt.Errorf("%w: %v", ErrSharePolicyRemoveFailed, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Sharing policy removed for %s/%s.\n", backend, keyID)
	return nil
}

// loadSharingPolicyStore creates a FileSharingPolicyStore from the
// standard sharing-policies.json path under ~/.xkey/.
func loadSharingPolicyStore() (*phone.FileSharingPolicyStore, error) {
	policyPath, err := getSharePolicyPath()
	if err != nil {
		return nil, err
	}
	return phone.NewFileSharingPolicyStore(policyPath)
}

// getSharePolicyPath returns the path to the sharing policies JSON file.
func getSharePolicyPath() (string, error) {
	configPath, err := getDevicesConfigPath()
	if err != nil {
		return "", err
	}
	// Replace phone.yaml with sharing-policies.json in the same directory
	dir := configPath[:len(configPath)-len(devicesConfigFileName)]
	return dir + sharingPoliciesFileName, nil
}

// truncatePolicyKeyID truncates a key ID for table display.
func truncatePolicyKeyID(keyID string) string {
	if len(keyID) > 20 {
		return keyID[:17] + "..."
	}
	return keyID
}
