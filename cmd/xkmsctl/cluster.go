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

// cluster.go implements the "xkmsctl cluster" command group. The verbs
// drive go-qrdb's own control-plane service (QRDBService admin surface)
// that xkmsd registers on its TCP-gRPC server and unix socket alongside
// the keystore service (pkg/server/qrdb_control_plane.go). The CLI
// therefore speaks the qrdb SDK client over the qrdb unix or grpc
// transport; no xkms-authored cluster proxy is involved.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	qrdbgrpc "github.com/jeremyhahn/go-qrdb/sdk/go/transport/grpc"
	qrdbunix "github.com/jeremyhahn/go-qrdb/sdk/go/transport/unix"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// defaultShardID is the shard every cluster/rebalance verb targets when
// --shard is not given. Shard 1 is qrdb's first (and, for xkmsd's embedded
// node, only) shard.
const defaultShardID uint64 = 1

// defaultQRDBGRPCAddress mirrors the CLI's gRPC default in config.go's
// createClientFromProtocol: xkmsd's TCP gRPC port.
const defaultQRDBGRPCAddress = "localhost:9443"

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

// Sentinel errors for the cluster command group. Wrap sites pair them with
// the underlying cause via WrappedError, matching the package convention.
var (
	// ErrClusterLeaderFailed is the sentinel error "failed to query shard leader".
	ErrClusterLeaderFailed = errors.New("failed to query shard leader")

	// ErrClusterMembersFailed is the sentinel error "failed to list cluster members".
	ErrClusterMembersFailed = errors.New("failed to list cluster members")

	// ErrClusterAddReplicaFailed is the sentinel error "failed to add replica".
	ErrClusterAddReplicaFailed = errors.New("failed to add replica")

	// ErrClusterRemoveReplicaFailed is the sentinel error "failed to remove replica".
	ErrClusterRemoveReplicaFailed = errors.New("failed to remove replica")
)

// QRDBControlUnsupportedTransportError is returned when the configured
// target cannot be reached over the qrdb control-plane transports. xkmsd
// hosts qrdb's control plane on its unix socket and its TCP gRPC port
// only, so every other transport/scheme is rejected up front with a clear
// operator-facing message instead of a dial failure.
type QRDBControlUnsupportedTransportError struct {
	Target string
}

// Error returns a human-readable description.
func (e *QRDBControlUnsupportedTransportError) Error() string {
	return "cluster: the qrdb control plane is served over the unix socket or gRPC only " +
		"(use --transport unix|grpc or a unix:///, grpc:// or grpcs:// --server URL): " + e.Target
}

// QRDBControlConnectError wraps a failure to construct or connect the qrdb
// SDK client to xkmsd's control plane.
type QRDBControlConnectError struct {
	Cause error
}

// Error returns a human-readable description.
func (e *QRDBControlConnectError) Error() string {
	return "cluster: failed to connect to the qrdb control plane: " + e.Cause.Error()
}

// Unwrap returns the wrapped cause for errors.Is/As.
func (e *QRDBControlConnectError) Unwrap() error { return e.Cause }

// QRDBControlClientMissingError is returned when no control-plane client
// factory is wired (e.g., a test cleared it without installing a fake).
type QRDBControlClientMissingError struct{}

// Error returns a human-readable description.
func (e *QRDBControlClientMissingError) Error() string {
	return "cluster: qrdb control-plane client is not configured"
}

// ---------------------------------------------------------------------------
// SDK client wiring (factory seam, mirrors UserAuthFactorClientFactory)
// ---------------------------------------------------------------------------

// ClusterControlClient is the subset of qrdbsdk.ClusterClient the cluster
// verbs use. It exists as a seam so tests inject in-process fakes without
// a live server.
type ClusterControlClient interface {
	// Members returns the current membership of the given shard.
	Members(ctx context.Context, shardID uint64) ([]qrdbsdk.Member, error)

	// Leader returns the current leader replica ID for the given shard
	// and whether a leader is currently known.
	Leader(ctx context.Context, shardID uint64) (replicaID uint64, hasLeader bool, err error)

	// AddReplica adds a replica to the shard.
	AddReplica(ctx context.Context, shardID, replicaID uint64, raftAddr string) error

	// RemoveReplica removes a replica from the shard.
	RemoveReplica(ctx context.Context, shardID, replicaID uint64) error
}

// Compile-time check: the qrdb SDK cluster facade satisfies the seam.
var _ ClusterControlClient = (*qrdbsdk.ClusterClient)(nil)

// QRDBControlClient bundles the qrdb control-plane surfaces the cluster
// and rebalance command groups drive. Rebalance is nil when the active
// transport does not implement transport.RebalanceClient.
type QRDBControlClient struct {
	Cluster   ClusterControlClient
	Rebalance qrdbtransport.RebalanceClient
}

// QRDBControlClientFactory builds a QRDBControlClient plus a close
// function the caller must invoke before returning. The default factory
// dials xkmsd's qrdb control plane using the global xkmsctl config; tests
// override it via SetQRDBControlClientFactory.
type QRDBControlClientFactory func(ctx context.Context) (*QRDBControlClient, func() error, error)

// qrdbControlClientFactory is the active factory used by the cluster and
// rebalance handlers.
var qrdbControlClientFactory QRDBControlClientFactory = defaultQRDBControlClientFactory

// SetQRDBControlClientFactory replaces the active factory and returns a
// restore closure. Intended for tests; production code should not call it.
func SetQRDBControlClientFactory(f QRDBControlClientFactory) func() {
	prev := qrdbControlClientFactory
	qrdbControlClientFactory = f
	return func() { qrdbControlClientFactory = prev }
}

// qrdbControlClient resolves the active factory and opens a client.
func qrdbControlClient(ctx context.Context) (*QRDBControlClient, func() error, error) {
	if qrdbControlClientFactory == nil {
		return nil, nil, &QRDBControlClientMissingError{}
	}
	return qrdbControlClientFactory(ctx)
}

// defaultQRDBControlClientFactory derives the qrdb transport from the same
// --server/--transport/TLS flag conventions every other xkmsctl command
// uses, connects, and exposes the SDK's Cluster()/Rebalance() facades.
func defaultQRDBControlClientFactory(ctx context.Context) (*QRDBControlClient, func() error, error) {
	tr, err := newQRDBControlTransport(getConfig())
	if err != nil {
		return nil, nil, err
	}

	qc, err := qrdbsdk.NewClient(tr)
	if err != nil {
		return nil, nil, &QRDBControlConnectError{Cause: err}
	}
	if err := qc.Connect(ctx); err != nil {
		_ = qc.Close()
		return nil, nil, &QRDBControlConnectError{Cause: err}
	}

	return &QRDBControlClient{
		Cluster:   qc.Cluster(),
		Rebalance: qc.Rebalance(),
	}, qc.Close, nil
}

// newQRDBControlTransport maps the CLI's target conventions onto a qrdb
// SDK transport:
//
//   - no --server: the unix socket the CLI already defaults to
//     (client.DefaultUnixSocketPath), or gRPC when --transport grpc.
//   - unix:///path: qrdb unix transport at that socket path. xkmsd's unix
//     socket serves plaintext gRPC, so TLS is never enabled over UDS.
//   - grpc://host:port: qrdb grpc transport, plaintext.
//   - grpcs://host:port: qrdb grpc transport with the CLI's TLS material
//     flags (--tls-cert/--tls-key/--tls-ca).
//   - bare address: routed by --transport (unix socket path or gRPC host:port).
//
// Every other transport/scheme is rejected with a typed error.
func newQRDBControlTransport(cfg *Config) (qrdbtransport.Transport, error) {
	server := cfg.Server
	switch {
	case server == "":
		switch cfg.Protocol {
		case "", "unix":
			return qrdbunix.New(qrdbtransport.WithAddress(client.DefaultUnixSocketPath))
		case "grpc":
			return newQRDBControlGRPCTransport(cfg, defaultQRDBGRPCAddress, false)
		default:
			return nil, &QRDBControlUnsupportedTransportError{Target: cfg.Protocol}
		}

	case hasPrefix(server, "unix://"):
		path := trimPrefix(server, "unix://")
		if path == "" {
			path = client.DefaultUnixSocketPath
		}
		return qrdbunix.New(qrdbtransport.WithAddress(path))

	case hasPrefix(server, "grpc://"):
		return newQRDBControlGRPCTransport(cfg, trimPrefix(server, "grpc://"), false)

	case hasPrefix(server, "grpcs://"):
		return newQRDBControlGRPCTransport(cfg, trimPrefix(server, "grpcs://"), true)

	case !hasScheme(server):
		switch cfg.Protocol {
		case "", "unix":
			return qrdbunix.New(qrdbtransport.WithAddress(server))
		case "grpc":
			return newQRDBControlGRPCTransport(cfg, server, false)
		default:
			return nil, &QRDBControlUnsupportedTransportError{Target: cfg.Protocol}
		}

	default:
		return nil, &QRDBControlUnsupportedTransportError{Target: server}
	}
}

// newQRDBControlGRPCTransport builds the qrdb grpc transport for addr.
// TLS is enabled when the scheme demands it (grpcs://) or when the
// operator supplied TLS material flags, mirroring the CLI's existing
// TLS-enabled grpc convention.
func newQRDBControlGRPCTransport(cfg *Config, addr string, forceTLS bool) (qrdbtransport.Transport, error) {
	opts := []qrdbtransport.Option{qrdbtransport.WithAddress(addr)}
	if forceTLS || cfg.TLSCert != "" || cfg.TLSKey != "" || cfg.TLSCACert != "" {
		opts = append(opts, qrdbtransport.WithTLS(cfg.TLSCert, cfg.TLSKey, cfg.TLSCACert))
	}
	return qrdbgrpc.New(opts...)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

// clusterCmd is the "xkmsctl cluster" command group.
var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Cluster membership and leadership operations",
	Long: `Manage the qrdb cluster control plane hosted by xkmsd.

xkmsd registers go-qrdb's own control-plane service on its gRPC server
and unix socket; these verbs drive it through the qrdb SDK client. The
target follows the standard --server/--transport conventions: the local
unix socket by default, unix:///path, grpc://host:port, or
grpcs://host:port with --tls-cert/--tls-key/--tls-ca.`,
}

// newClusterStatusCmd implements "cluster status [--shard]".
func newClusterStatusCmd() *cobra.Command {
	var shardID uint64

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show shard leadership and membership status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctrl, closer, err := qrdbControlClient(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = closer() }()

			leaderID, hasLeader, err := ctrl.Cluster.Leader(cmd.Context(), shardID)
			if err != nil {
				return &WrappedError{Sentinel: ErrClusterLeaderFailed, Err: err}
			}
			members, err := ctrl.Cluster.Members(cmd.Context(), shardID)
			if err != nil {
				return &WrappedError{Sentinel: ErrClusterMembersFailed, Err: err}
			}

			printer := NewPrinter(getConfig().OutputFormat, cmd.OutOrStdout())
			return printer.PrintClusterStatus(shardID, leaderID, hasLeader, members)
		},
	}

	cmd.Flags().Uint64Var(&shardID, "shard", defaultShardID, "shard ID to query")
	return cmd
}

// newClusterMembersCmd implements "cluster members [--shard]".
func newClusterMembersCmd() *cobra.Command {
	var shardID uint64

	cmd := &cobra.Command{
		Use:   "members",
		Short: "List shard replicas with Raft addresses and advertised API endpoints",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctrl, closer, err := qrdbControlClient(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = closer() }()

			members, err := ctrl.Cluster.Members(cmd.Context(), shardID)
			if err != nil {
				return &WrappedError{Sentinel: ErrClusterMembersFailed, Err: err}
			}

			printer := NewPrinter(getConfig().OutputFormat, cmd.OutOrStdout())
			return printer.PrintClusterMembers(members)
		},
	}

	cmd.Flags().Uint64Var(&shardID, "shard", defaultShardID, "shard ID to query")
	return cmd
}

// newClusterAddCmd implements
// "cluster add --replica-id N --raft-address host:port [--shard]".
func newClusterAddCmd() *cobra.Command {
	var (
		shardID   uint64
		replicaID uint64
		raftAddr  string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a replica to a shard",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctrl, closer, err := qrdbControlClient(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = closer() }()

			if err := ctrl.Cluster.AddReplica(cmd.Context(), shardID, replicaID, raftAddr); err != nil {
				return &WrappedError{Sentinel: ErrClusterAddReplicaFailed, Err: err}
			}

			printer := NewPrinter(getConfig().OutputFormat, cmd.OutOrStdout())
			return printer.PrintSuccess("replica " + strconv.FormatUint(replicaID, 10) +
				" (" + raftAddr + ") added to shard " + strconv.FormatUint(shardID, 10))
		},
	}

	cmd.Flags().Uint64Var(&shardID, "shard", defaultShardID, "shard ID to modify")
	cmd.Flags().Uint64Var(&replicaID, "replica-id", 0, "replica ID to add (required)")
	cmd.Flags().StringVar(&raftAddr, "raft-address", "", "replica Raft address host:port (required)")
	_ = cmd.MarkFlagRequired("replica-id")
	_ = cmd.MarkFlagRequired("raft-address")
	return cmd
}

// newClusterRemoveCmd implements "cluster remove --replica-id N [--shard]".
func newClusterRemoveCmd() *cobra.Command {
	var (
		shardID   uint64
		replicaID uint64
	)

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a replica from a shard",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctrl, closer, err := qrdbControlClient(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = closer() }()

			if err := ctrl.Cluster.RemoveReplica(cmd.Context(), shardID, replicaID); err != nil {
				return &WrappedError{Sentinel: ErrClusterRemoveReplicaFailed, Err: err}
			}

			printer := NewPrinter(getConfig().OutputFormat, cmd.OutOrStdout())
			return printer.PrintSuccess("replica " + strconv.FormatUint(replicaID, 10) +
				" removed from shard " + strconv.FormatUint(shardID, 10))
		},
	}

	cmd.Flags().Uint64Var(&shardID, "shard", defaultShardID, "shard ID to modify")
	cmd.Flags().Uint64Var(&replicaID, "replica-id", 0, "replica ID to remove (required)")
	_ = cmd.MarkFlagRequired("replica-id")
	return cmd
}

func init() {
	clusterCmd.AddCommand(newClusterStatusCmd())
	clusterCmd.AddCommand(newClusterMembersCmd())
	clusterCmd.AddCommand(newClusterAddCmd())
	clusterCmd.AddCommand(newClusterRemoveCmd())
	rootCmd.AddCommand(clusterCmd)
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

// fprintf writes formatted output, discarding the writer's return values
// the same way the other Printer methods in output.go do.
func fprintf(w io.Writer, format string, args ...interface{}) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// clusterMemberJSON is the wire shape of one member in JSON output.
type clusterMemberJSON struct {
	ReplicaID    uint64            `json:"replica_id"`
	Address      string            `json:"address"`
	IsLeader     bool              `json:"is_leader"`
	APIEndpoints map[string]string `json:"api_endpoints,omitempty"`
}

// clusterMembersToJSON converts SDK members into the JSON output shape.
func clusterMembersToJSON(members []qrdbsdk.Member) []clusterMemberJSON {
	out := make([]clusterMemberJSON, len(members))
	for i, m := range members {
		var endpoints map[string]string
		if len(m.APIEndpoints) > 0 {
			endpoints = make(map[string]string, len(m.APIEndpoints))
			for proto, addr := range m.APIEndpoints {
				endpoints[string(proto)] = addr
			}
		}
		out[i] = clusterMemberJSON{
			ReplicaID:    m.ReplicaID,
			Address:      m.Address,
			IsLeader:     m.IsLeader,
			APIEndpoints: endpoints,
		}
	}
	return out
}

// formatAPIEndpoints renders a member's advertised endpoints as a stable
// "proto=addr" list sorted by protocol, or "-" when none are advertised.
func formatAPIEndpoints(endpoints map[qrdbsdk.APIProtocol]string) string {
	if len(endpoints) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(endpoints))
	for proto, addr := range endpoints {
		parts = append(parts, string(proto)+"="+addr)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// PrintClusterStatus prints shard leadership and membership status.
func (p *Printer) PrintClusterStatus(shardID, leaderID uint64, hasLeader bool, members []qrdbsdk.Member) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"shard_id":     shardID,
			"leader_id":    leaderID,
			"has_leader":   hasLeader,
			"member_count": len(members),
			"members":      clusterMembersToJSON(members),
		})
	case OutputFormatTable, OutputFormatText:
		fprintf(p.writer, "Shard:   %d\n", shardID)
		if hasLeader {
			leader := "replica " + strconv.FormatUint(leaderID, 10)
			for _, m := range members {
				if m.ReplicaID == leaderID {
					leader += " (" + m.Address + ")"
					break
				}
			}
			fprintf(p.writer, "Leader:  %s\n", leader)
		} else {
			fprintf(p.writer, "Leader:  none elected\n")
		}
		fprintf(p.writer, "Members: %d\n", len(members))
		return nil
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintClusterMembers prints the shard membership list.
func (p *Printer) PrintClusterMembers(members []qrdbsdk.Member) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"members": clusterMembersToJSON(members),
		})
	case OutputFormatTable:
		if len(members) == 0 {
			fprintf(p.writer, "No members found\n")
			return nil
		}
		fprintf(p.writer, "%-12s %-25s %-8s %s\n", "REPLICA ID", "RAFT ADDRESS", "LEADER", "API ENDPOINTS")
		fprintf(p.writer, "%s\n", strings.Repeat("-", 72))
		for _, m := range members {
			fprintf(p.writer, "%-12d %-25s %-8t %s\n",
				m.ReplicaID, m.Address, m.IsLeader, formatAPIEndpoints(m.APIEndpoints))
		}
		return nil
	case OutputFormatText:
		if len(members) == 0 {
			fprintf(p.writer, "No members found\n")
			return nil
		}
		fprintf(p.writer, "Members:\n")
		for _, m := range members {
			role := ""
			if m.IsLeader {
				role = " [leader]"
			}
			fprintf(p.writer, "  - replica %d at %s%s (api: %s)\n",
				m.ReplicaID, m.Address, role, formatAPIEndpoints(m.APIEndpoints))
		}
		return nil
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}
