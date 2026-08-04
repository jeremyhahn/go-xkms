// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/sshlocal"
)

// sshLocalCmd groups read-only discovery of the operator's local SSH
// tooling (ssh_config(5) hosts, ssh-agent/~/.ssh identities). The same
// enumeration logic backs the GUI's SSHLocalService
// (xkey/pkg/gui/services/ssh_local_service.go) — both front ends call
// xkey/pkg/sshlocal directly so they never diverge.
var sshLocalCmd = &cobra.Command{
	Use:   "local",
	Short: "Discover local ssh_config hosts and ssh-agent/~/.ssh identities",
}

var sshLocalHostsCmd = &cobra.Command{
	Use:     "hosts",
	Aliases: []string{"ls"},
	Short:   "List Host aliases resolved from ssh_config(5)",
	Args:    cobra.NoArgs,
	RunE:    runSSHLocalHosts,
}

var sshLocalKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "List keys visible via the local ssh-agent and ~/.ssh",
	Args:  cobra.NoArgs,
	RunE:  runSSHLocalKeys,
}

func init() {
	SSHCmd.AddCommand(sshLocalCmd)
	sshLocalCmd.AddCommand(sshLocalHostsCmd)
	sshLocalCmd.AddCommand(sshLocalKeysCmd)
}

func runSSHLocalHosts(cmd *cobra.Command, _ []string) error {
	hosts, err := sshlocal.ListConfigHosts()
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No ssh_config hosts found.")
		return nil
	}
	for _, h := range hosts {
		target := h.Hostname
		if h.User != "" {
			target = h.User + "@" + h.Hostname
		}
		ids := "-"
		if len(h.IdentityFiles) > 0 {
			ids = strings.Join(h.IdentityFiles, ",")
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %-24s %s:%d\tidentities=%s\n", h.Alias, target, h.Port, ids)
	}
	return nil
}

func runSSHLocalKeys(cmd *cobra.Command, _ []string) error {
	keys, err := sshlocal.ListLocalKeys()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No local keys found (no agent, and/or no ~/.ssh identities).")
		return nil
	}
	for _, k := range keys {
		path := k.Path
		if path == "" {
			path = "-"
		}
		comment := k.Comment
		if comment == "" {
			comment = "-"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %-6s %-16s %s\t%s\t%s\n", k.Source, k.KeyType, k.Fingerprint, path, comment)
	}
	return nil
}
