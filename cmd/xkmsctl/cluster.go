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
	"strings"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// clusterCmd is the top-level command for read-only Raft cluster inspection.
//
// Membership mutation (add/remove replica) is intentionally absent.
//
// TODO(cluster): add/remove require a Raft replica-mutation API (qrdb
// AddReplica/RemoveReplica) not yet exposed via the xkms SDK.
var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Inspect the Raft cluster",
	Long: `Inspect the Raft cluster the xkms server participates in.

The cluster surface is read-only. A standalone (non-clustered) server reports a
single-node, non-clustered status so the commands work uniformly whether or not
clustering is enabled.

Subcommands:
  status   Show the Raft leadership status for the configured shard
  members  List the Raft replicas for the configured shard`,
}

// clusterStatusCmd shows the Raft leadership status.
var clusterStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the Raft cluster status",
	Long: `Show the Raft leadership status for the server's configured shard.

Examples:
  xkmsctl cluster status
  xkmsctl cluster status --shard 1 --output json`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		clusterStatus(cfg, printer)
	},
}

// clusterMembersCmd lists the Raft replicas.
var clusterMembersCmd = &cobra.Command{
	Use:   "members",
	Short: "List the Raft cluster members",
	Long: `List the Raft replicas for the server's configured shard.

Examples:
  xkmsctl cluster members
  xkmsctl cluster members --shard 1 --output json`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		clusterMembers(cfg, printer)
	},
}

// createClusterClient builds a connected xkms client and resolves its read-only
// cluster facade. The cluster surface is served over REST; clients connected
// via a transport that does not expose it receive ErrClusterUnsupported.
func createClusterClient(cfg *Config) (*client.ClusterClient, func(), error) {
	cl, err := cfg.CreateClient()
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateClientFailed, Err: err}
	}

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		_ = cl.Close()
		return nil, nil, &WrappedError{Sentinel: ErrConnectFailed, Err: err}
	}

	cluster, err := client.Cluster(cl)
	if err != nil {
		_ = cl.Close()
		return nil, nil, err
	}

	cleanup := func() { _ = cl.Close() }
	return cluster, cleanup, nil
}

// clusterStatus retrieves and prints the Raft leadership status.
func clusterStatus(cfg *Config, printer *Printer) {
	cluster, cleanup, err := createClusterClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving cluster status")

	resp, err := cluster.Status(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetClusterStatusFailed, Err: err})
		return
	}

	printClusterStatus(printer, &resp.Status)
}

// clusterMembers retrieves and prints the Raft membership.
func clusterMembers(cfg *Config, printer *Printer) {
	cluster, cleanup, err := createClusterClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Listing cluster members")

	resp, err := cluster.Members(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrListClusterMembersFailed, Err: err})
		return
	}

	printClusterMembers(printer, resp.Members)
}

// printClusterStatus prints the Raft leadership status.
func printClusterStatus(printer *Printer, status *client.ClusterStatusInfo) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(status); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintf(printer.writer, "Cluster Status:\n")
		_, _ = fmt.Fprintf(printer.writer, "  Shard:      %d\n", status.ShardID)
		_, _ = fmt.Fprintf(printer.writer, "  Clustered:  %t\n", status.Clustered)
		_, _ = fmt.Fprintf(printer.writer, "  Node ID:    %d\n", status.NodeID)
		_, _ = fmt.Fprintf(printer.writer, "  Has Leader: %t\n", status.HasLeader)
		_, _ = fmt.Fprintf(printer.writer, "  Leader ID:  %d\n", status.LeaderID)
	}
}

// printClusterMembers prints the Raft membership.
func printClusterMembers(printer *Printer, members []client.ClusterMemberInfo) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"members": members,
			"total":   len(members),
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable:
		if len(members) == 0 {
			_, _ = fmt.Fprintln(printer.writer, "No cluster members found")
			return
		}
		_, _ = fmt.Fprintf(printer.writer, "%-10s %-30s %-8s\n", "NODE ID", "ADDRESS", "LEADER")
		_, _ = fmt.Fprintln(printer.writer, strings.Repeat("-", 50))
		for _, m := range members {
			_, _ = fmt.Fprintf(printer.writer, "%-10d %-30s %-8s\n",
				m.NodeID, m.Address, leaderMarker(m.IsLeader))
		}
		_, _ = fmt.Fprintf(printer.writer, "\nTotal: %d member(s)\n", len(members))
	case OutputFormatText:
		if len(members) == 0 {
			_, _ = fmt.Fprintln(printer.writer, "No cluster members found")
			return
		}
		_, _ = fmt.Fprintln(printer.writer, "Cluster Members:")
		for _, m := range members {
			_, _ = fmt.Fprintf(printer.writer, "  - node %d at %s%s\n",
				m.NodeID, m.Address, leaderSuffix(m.IsLeader))
		}
	}
}

// leaderMarker returns a table cell marking the shard leader.
func leaderMarker(isLeader bool) string {
	if isLeader {
		return "*"
	}
	return ""
}

// leaderSuffix returns a text suffix marking the shard leader.
func leaderSuffix(isLeader bool) string {
	if isLeader {
		return " (leader)"
	}
	return ""
}

func init() {
	// Read-only cluster flags. --shard names the Raft shard to report on; the
	// server reports its configured shard, so this is forward-looking and kept
	// for parity with the planned multi-shard surface.
	clusterStatusCmd.Flags().Uint64("shard", 1, "Raft shard (group) identifier to report on")
	clusterMembersCmd.Flags().Uint64("shard", 1, "Raft shard (group) identifier to report on")

	// Build subcommand tree.
	clusterCmd.AddCommand(clusterStatusCmd)
	clusterCmd.AddCommand(clusterMembersCmd)

	// Register with root.
	rootCmd.AddCommand(clusterCmd)
}
