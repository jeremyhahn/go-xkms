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
	"sort"
	"strconv"
	"strings"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// clusterCmd is the top-level command for Raft cluster inspection and
// membership management.
var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Inspect and manage the Raft cluster",
	Long: `Inspect and manage the Raft cluster the xkms server participates in.

A standalone (non-clustered) server reports a single-node, non-clustered status
so the inspection commands work uniformly whether or not clustering is enabled.

Membership mutation is privileged: the server authorizes it against the
canonical cluster-membership permissions (admin:add_member, admin:remove_member)
before reconfiguring the Raft group, and refuses it outright on a standalone
node.

Subcommands:
  status   Show the Raft leadership status for the configured shard
  members  List the Raft replicas for the configured shard
  add      Add a replica to the shard
  remove   Remove a replica from the shard`,
}

// clusterAddCmd adds a replica to the shard's Raft group.
var clusterAddCmd = &cobra.Command{
	Use:   "add <replica-id> <raft-address>",
	Short: "Add a replica to the Raft cluster",
	Long: `Add a replica to the shard's Raft group.

The replica ID must be non-zero and unique within the shard. The Raft address is
the new replica's peer address in host:port form; it is the address the other
replicas will use to reach it on the consensus plane, not an API address.

Adding a replica that is already a member succeeds without changing the
configuration, so the command is safe to retry.

Examples:
  xkmsctl cluster add 2 10.0.0.2:63001
  xkmsctl cluster add 3 node3.internal:63001 --output json`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		replicaID, err := parseReplicaID(args[0])
		if err != nil {
			handleError(err)
			return
		}
		clusterAdd(cfg, printer, replicaID, args[1])
	},
}

// clusterRemoveCmd removes a replica from the shard's Raft group.
var clusterRemoveCmd = &cobra.Command{
	Use:   "remove <replica-id>",
	Short: "Remove a replica from the Raft cluster",
	Long: `Remove a replica from the shard's Raft group.

Removing a replica that is already absent succeeds, so the command is safe to
retry. Removing a replica does not stop the process running it; shut that node
down separately.

Examples:
  xkmsctl cluster remove 2
  xkmsctl cluster remove 3 --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		replicaID, err := parseReplicaID(args[0])
		if err != nil {
			handleError(err)
			return
		}
		clusterRemove(cfg, printer, replicaID)
	},
}

// parseReplicaID converts a positional replica identifier argument, rejecting
// the reserved zero value that Raft uses to mean "no replica".
func parseReplicaID(arg string) (uint64, error) {
	replicaID, err := strconv.ParseUint(arg, 10, 64)
	if err != nil {
		return 0, &WrappedError{Sentinel: ErrInvalidReplicaID, Err: err}
	}
	if replicaID == 0 {
		return 0, ErrInvalidReplicaID
	}
	return replicaID, nil
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

// clusterAdd adds a replica to the shard's Raft group and prints the result.
func clusterAdd(cfg *Config, printer *Printer, replicaID uint64, raftAddr string) {
	cluster, cleanup, err := createClusterClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose(fmt.Sprintf("Adding replica %d at %s to the cluster", replicaID, raftAddr))

	resp, err := cluster.AddReplica(context.Background(), replicaID, raftAddr)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrAddClusterReplicaFailed, Err: err})
		return
	}

	printClusterReplica(printer, "added", resp)
}

// clusterRemove removes a replica from the shard's Raft group and prints the
// result.
func clusterRemove(cfg *Config, printer *Printer, replicaID uint64) {
	cluster, cleanup, err := createClusterClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose(fmt.Sprintf("Removing replica %d from the cluster", replicaID))

	resp, err := cluster.RemoveReplica(context.Background(), replicaID)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrRemoveClusterReplicaFailed, Err: err})
		return
	}

	printClusterReplica(printer, "removed", resp)
}

// printClusterReplica reports the outcome of a membership mutation.
func printClusterReplica(printer *Printer, action string, resp *client.ClusterReplicaResponse) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"action":     action,
			"shard_id":   resp.ShardID,
			"replica_id": resp.ReplicaID,
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintf(printer.writer, "Replica %d %s (shard %d)\n",
			resp.ReplicaID, action, resp.ShardID)
	}
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
			for _, line := range formatAPIEndpoints(m.APIEndpoints) {
				_, _ = fmt.Fprintf(printer.writer, "      api: %s\n", line)
			}
		}
	}
}

// formatAPIEndpoints renders a replica's advertised API endpoints in a stable
// order. A replica that advertises nothing yields no lines, so the output is
// identical to what it was before endpoints existed.
func formatAPIEndpoints(endpoints map[string]string) []string {
	if len(endpoints) == 0 {
		return nil
	}
	protocols := make([]string, 0, len(endpoints))
	for proto := range endpoints {
		protocols = append(protocols, proto)
	}
	sort.Strings(protocols)

	lines := make([]string, 0, len(protocols))
	for _, proto := range protocols {
		lines = append(lines, fmt.Sprintf("%s=%s", proto, endpoints[proto]))
	}
	return lines
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
	clusterCmd.AddCommand(clusterAddCmd)
	clusterCmd.AddCommand(clusterRemoveCmd)

	// Register with root.
	rootCmd.AddCommand(clusterCmd)
}
