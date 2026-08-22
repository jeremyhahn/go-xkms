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
	"time"

	"github.com/spf13/cobra"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

var sshSessionsCmd = &cobra.Command{
	Use:     "sessions",
	Aliases: []string{"session"},
	Short:   "Manage persistent embedded-console sessions",
	Long: `Manage the persistent embedded-console session records the xkey GUI
restores after a reload or restart. Only sessions explicitly started with
persistence enabled are recorded; a record carries the session's title and
reconnect origin — never key material or live connection state.`,
}

var sshSessionsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List persistent console sessions",
	RunE:    runSSHSessionsList,
}

var sshSessionsRemoveCmd = &cobra.Command{
	Use:     "remove [id]",
	Aliases: []string{"rm", "delete"},
	Short:   "Delete a persistent console session record",
	Args:    cobra.ExactArgs(1),
	RunE:    runSSHSessionsRemove,
}

func init() {
	SSHCmd.AddCommand(sshSessionsCmd)
	sshSessionsCmd.AddCommand(sshSessionsListCmd, sshSessionsRemoveCmd)
}

// xkeySessionStore builds the shared persistent-session store (same shared
// SSH store as profiles/host keys — see xkey/pkg/sshstore).
func xkeySessionStore() (sshsdk.ConsoleSessionStore, error) {
	backend, err := xkeySSHBackend()
	if err != nil {
		return nil, err
	}
	return sshsdk.NewConsoleSessionStore(backend)
}

// sessionOrigin renders a record's reconnect origin for display.
func sessionOrigin(s *sshsdk.ConsoleSessionRecord) string {
	switch {
	case s.ProfileID != "":
		return "profile:" + s.ProfileID
	case s.Alias != "":
		return "ssh_config:" + s.Alias
	default:
		target := s.Host
		if s.User != "" {
			target = s.User + "@" + target
		}
		if s.Port != 0 && s.Port != 22 {
			target = fmt.Sprintf("%s:%d", target, s.Port)
		}
		return target
	}
}

func runSSHSessionsList(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	store, err := xkeySessionStore()
	if err != nil {
		return err
	}
	all, err := store.List()
	if err != nil {
		return err
	}
	if len(all) == 0 {
		_, _ = fmt.Fprintln(out, "No persistent sessions found")
		return nil
	}
	for _, s := range all {
		_, _ = fmt.Fprintf(out, "%s\t%s\t%s\tlast=%s\n",
			s.ID, s.Title, sessionOrigin(s), s.LastConnectedAt.Local().Format(time.RFC3339))
	}
	return nil
}

func runSSHSessionsRemove(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	store, err := xkeySessionStore()
	if err != nil {
		return err
	}
	if derr := store.Delete(args[0]); derr != nil {
		return derr
	}
	_, _ = fmt.Fprintf(out, "Deleted persistent session %q\n", args[0])
	return nil
}
