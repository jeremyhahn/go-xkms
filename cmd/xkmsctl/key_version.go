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
	"strconv"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// keyVersionsCmd lists a key's versions.
var keyVersionsCmd = &cobra.Command{
	Use:   "versions <key-id>",
	Short: "List a key's versions",
	Long: `List every version of a key: its number, state (enabled, disabled or
retired), whether it is current, and when and by whom it was created.
Sign and encrypt use the current version; verify and decrypt accept any
enabled one.

Example:
  xkmsctl key versions my-key --backend software`,
	Args: cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		cfg := getConfig()
		runClientCall(cfg, "Listing versions of key "+args[0], ErrListKeyVersionsFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.ListKeyVersions(ctx, &client.ListKeyVersionsRequest{Backend: cfg.Backend, KeyID: args[0]})
		}, printKeyVersions)
	},
}

// keyVersionCmd groups the commands that change one key's versions.
var keyVersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Enable, disable or retire key versions",
	Long: `Change the state of a key's versions. The current version cannot be
disabled or retired: rotate the key first ('xkmsctl key rotate').

Subcommands:
  enable <key-id> <n>       Enable a disabled version
  disable <key-id> <n>      Disable a version; its key material is kept
  retire <key-id> <n>       Delete a version's key material for good
  enable-all <key-id>       Enable every disabled version
  disable-all <key-id>      Disable every version except the current one`,
}

// newKeyVersionStateCmd returns the command that runs one version state
// change.
func newKeyVersionStateCmd(use, short, long string, change func(client.Client) func(context.Context, *client.KeyVersionRequest) (*client.KeyVersionStateResponse, error)) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <key-id> <version>",
		Short: short,
		Long:  long,
		Args:  cobra.ExactArgs(2),
		Run: func(_ *cobra.Command, args []string) {
			version, err := parseKeyVersion(args[1])
			if err != nil {
				handleError(err)
				return
			}
			cfg := getConfig()
			req := &client.KeyVersionRequest{Backend: cfg.Backend, KeyID: args[0], Version: version}
			runClientCall(cfg, fmt.Sprintf("Changing version %d of key %s", version, args[0]), ErrChangeKeyVersionFailed,
				func(ctx context.Context, cl client.Client) (any, error) { return change(cl)(ctx, req) },
				printKeyVersionState)
		},
	}
}

// newAllKeyVersionsCmd returns the command that runs one bulk version state
// change.
func newAllKeyVersionsCmd(use, short, long string, change func(client.Client) func(context.Context, *client.AllKeyVersionsRequest) (*client.AllKeyVersionsResponse, error)) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <key-id>",
		Short: short,
		Long:  long,
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			cfg := getConfig()
			req := &client.AllKeyVersionsRequest{Backend: cfg.Backend, KeyID: args[0]}
			runClientCall(cfg, "Changing the versions of key "+args[0], ErrChangeKeyVersionFailed,
				func(ctx context.Context, cl client.Client) (any, error) { return change(cl)(ctx, req) },
				printAllKeyVersions)
		},
	}
}

var (
	keyVersionEnableCmd = newKeyVersionStateCmd("enable", "Enable a key version",
		"Enable a disabled version, so verify and decrypt may use it again. A retired\nversion cannot be enabled.\n\nExample:\n  xkmsctl key version enable my-key 1",
		func(cl client.Client) func(context.Context, *client.KeyVersionRequest) (*client.KeyVersionStateResponse, error) {
			return cl.EnableKeyVersion
		})
	keyVersionDisableCmd = newKeyVersionStateCmd("disable", "Disable a key version",
		"Disable a version: no operation may use it until it is enabled again. Its\nkey material is kept. The current version cannot be disabled.\n\nExample:\n  xkmsctl key version disable my-key 1",
		func(cl client.Client) func(context.Context, *client.KeyVersionRequest) (*client.KeyVersionStateResponse, error) {
			return cl.DisableKeyVersion
		})
	keyVersionRetireCmd = newKeyVersionStateCmd("retire", "Retire a key version for good",
		"Retire a version: its key material is deleted and it can never be used or\nenabled again. Signatures and ciphertext it produced can no longer be\nverified or decrypted. The current version cannot be retired.\n\nExample:\n  xkmsctl key version retire my-key 1",
		func(cl client.Client) func(context.Context, *client.KeyVersionRequest) (*client.KeyVersionStateResponse, error) {
			return cl.RetireKeyVersion
		})
	keyVersionEnableAllCmd = newAllKeyVersionsCmd("enable-all", "Enable every disabled version of a key",
		"Enable every disabled version of a key. Retired versions stay retired.\n\nExample:\n  xkmsctl key version enable-all my-key",
		func(cl client.Client) func(context.Context, *client.AllKeyVersionsRequest) (*client.AllKeyVersionsResponse, error) {
			return cl.EnableAllKeyVersions
		})
	keyVersionDisableAllCmd = newAllKeyVersionsCmd("disable-all", "Disable every non-current version of a key",
		"Disable every enabled version of a key except the current one, which sign\nand encrypt keep using.\n\nExample:\n  xkmsctl key version disable-all my-key",
		func(cl client.Client) func(context.Context, *client.AllKeyVersionsRequest) (*client.AllKeyVersionsResponse, error) {
			return cl.DisableAllKeyVersions
		})
)

// keyRotateAllCmd rotates every key of a tenant.
var keyRotateAllCmd = &cobra.Command{
	Use:   "rotate-all",
	Short: "Rotate every key of a tenant",
	Long: `Rotate every key of a tenant, in every backend: each key gets a new
version, which becomes current. A key that cannot be rotated is reported and
the rest are still rotated; the command then exits non-zero.

A tenant caller rotates its own tenant. A system caller rotates the system
tenant's keys, or the tenant --tenant names.

Examples:
  xkmsctl key rotate-all
  xkmsctl key rotate-all --tenant acme`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		tenant, ok := tenantFlag(cmd)
		if !ok {
			return
		}
		runClientCall(getConfig(), "Rotating every key of the tenant", ErrRotateScopeKeysFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.RotateScopeKeys(ctx, &client.RotateScopeKeysRequest{TenantID: tenant})
		}, printRotateScopeKeys)
	},
}

// parseKeyVersion parses a key version argument: a positive 32-bit integer.
func parseKeyVersion(arg string) (uint32, error) {
	v, err := strconv.ParseUint(arg, 10, 32)
	if err != nil || v == 0 {
		return 0, &WrappedDetailError{Sentinel: ErrInvalidKeyVersion, Detail: arg}
	}
	return uint32(v), nil
}

// printKeyVersions prints a key's versions.
func printKeyVersions(p *Printer, result any) {
	list, ok := result.(*client.ListKeyVersionsResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	p.printf("Key %s (current version %d):\n", list.KeyID, list.CurrentVersion)
	p.printf("%-8s %-9s %-8s %-21s %s\n", "VERSION", "STATE", "CURRENT", "CREATED", "CREATED BY")
	p.println(repeatString("-", 72))
	for _, v := range list.Versions {
		p.printf("%-8d %-9s %-8t %-21s %s\n", v.Version, v.State, v.Current, orDash(v.CreatedAt), orDash(v.CreatedBy))
	}
}

// orDash returns s, or "-" when it is empty.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// printKeyVersionState prints a version's state after a change.
func printKeyVersionState(p *Printer, result any) {
	state, ok := result.(*client.KeyVersionStateResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	if !state.Changed {
		printCallSuccess(p, fmt.Sprintf("Version %d of key %s was already %s", state.Version, state.KeyID, state.State))
		return
	}
	printCallSuccess(p, fmt.Sprintf("Version %d of key %s is now %s", state.Version, state.KeyID, state.State))
}

// printAllKeyVersions prints the versions a bulk change reached.
func printAllKeyVersions(p *Printer, result any) {
	all, ok := result.(*client.AllKeyVersionsResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	if all.Count == 0 {
		printCallSuccess(p, fmt.Sprintf("No version of key %s changed", all.KeyID))
		return
	}
	printCallSuccess(p, fmt.Sprintf("Key %s: versions %v are now %s", all.KeyID, all.Versions, all.State))
}

// printRotateScopeKeys prints a scope rotation's results, failing the
// command when any key failed. A skipped key is not a failure: it is left
// alone on purpose, and its reason says why.
func printRotateScopeKeys(p *Printer, result any) {
	resp, ok := result.(*client.RotateScopeKeysResponse)
	if !ok {
		return
	}
	if !printJSONResult(p, result) {
		p.printf("Tenant %s: %d rotated, %d skipped, %d failed\n", resp.TenantID, resp.Rotated, resp.Skipped, resp.Failed)
		if len(resp.Results) > 0 {
			p.printf("%-16s %-32s %-8s %-8s %s\n", "BACKEND", "KEY", "STATE", "VERSION", "DETAIL")
			p.println(repeatString("-", 80))
		}
		for _, r := range resp.Results {
			version := "-"
			if r.KeyVersion != 0 {
				version = strconv.FormatUint(uint64(r.KeyVersion), 10)
			}
			p.printf("%-16s %-32s %-8s %-8s %s\n", r.Backend, truncateString(orDash(r.KeyID), 32), r.State, version, r.Reason+r.Error)
		}
	}
	if resp.Failed > 0 {
		handleError(&WrappedDetailError{Sentinel: ErrRotateScopeKeysPartial, Detail: fmt.Sprintf("%d of %d", resp.Failed, len(resp.Results))})
	}
}

func init() {
	keyCmd.AddCommand(keyVersionsCmd)
	keyCmd.AddCommand(keyVersionCmd)
	keyCmd.AddCommand(keyRotateAllCmd)
	keyVersionCmd.AddCommand(keyVersionEnableCmd, keyVersionDisableCmd, keyVersionRetireCmd,
		keyVersionEnableAllCmd, keyVersionDisableAllCmd)

	keyRotateAllCmd.Flags().String("tenant", "", "Tenant to rotate (system callers only; default: the caller's own)")
}
