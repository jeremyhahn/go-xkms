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

// rebalance.go implements the "xkmsctl rebalance" command group. The verbs
// map 1:1 onto go-qrdb's transport.RebalanceClient (shard stats, plan,
// execute, imbalance report), served by the qrdb control plane that xkmsd
// registers on its gRPC server and unix socket. Connection wiring is
// shared with the cluster group (see cluster.go's QRDBControlClient seam).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/spf13/cobra"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
)

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

// Sentinel errors for the rebalance command group.
var (
	// ErrShardStatsFailed is the sentinel error "failed to fetch shard statistics".
	ErrShardStatsFailed = errors.New("failed to fetch shard statistics")

	// ErrRebalancePlanFailed is the sentinel error "failed to create rebalance plan".
	ErrRebalancePlanFailed = errors.New("failed to create rebalance plan")

	// ErrRebalanceExecuteFailed is the sentinel error "failed to execute rebalance plan".
	ErrRebalanceExecuteFailed = errors.New("failed to execute rebalance plan")

	// ErrImbalanceReportFailed is the sentinel error "failed to fetch imbalance report".
	ErrImbalanceReportFailed = errors.New("failed to fetch imbalance report")
)

// RebalanceUnsupportedError is returned when the active qrdb transport
// does not implement the rebalance surface (Client.Rebalance() is nil).
type RebalanceUnsupportedError struct{}

// Error returns a human-readable description.
func (e *RebalanceUnsupportedError) Error() string {
	return "rebalance: the active transport does not support the qrdb rebalance surface " +
		"(use the unix or grpc transport against xkmsd's qrdb control plane)"
}

// RebalancePlanFileReadError wraps a failure to read a plan file passed
// to "rebalance execute --plan".
type RebalancePlanFileReadError struct {
	Path  string
	Cause error
}

// Error returns a human-readable description.
func (e *RebalancePlanFileReadError) Error() string {
	return "rebalance: failed to read plan file " + e.Path + ": " + e.Cause.Error()
}

// Unwrap returns the wrapped cause for errors.Is/As.
func (e *RebalancePlanFileReadError) Unwrap() error { return e.Cause }

// RebalancePlanFileParseError wraps a failure to parse a plan file as the
// JSON produced by "rebalance plan".
type RebalancePlanFileParseError struct {
	Path  string
	Cause error
}

// Error returns a human-readable description.
func (e *RebalancePlanFileParseError) Error() string {
	return "rebalance: failed to parse plan file " + e.Path + ": " + e.Cause.Error()
}

// Unwrap returns the wrapped cause for errors.Is/As.
func (e *RebalancePlanFileParseError) Unwrap() error { return e.Cause }

// RebalancePlanFileWriteError wraps a failure to write the plan produced
// by "rebalance plan --out".
type RebalancePlanFileWriteError struct {
	Path  string
	Cause error
}

// Error returns a human-readable description.
func (e *RebalancePlanFileWriteError) Error() string {
	return "rebalance: failed to write plan file " + e.Path + ": " + e.Cause.Error()
}

// Unwrap returns the wrapped cause for errors.Is/As.
func (e *RebalancePlanFileWriteError) Unwrap() error { return e.Cause }

// ---------------------------------------------------------------------------
// Client wiring
// ---------------------------------------------------------------------------

// rebalanceClient opens the shared qrdb control-plane client and returns
// its rebalance surface, failing with a typed error when the transport
// does not implement it. The returned close function must be invoked
// before the caller returns.
func rebalanceClient(ctx context.Context) (qrdbtransport.RebalanceClient, func() error, error) {
	ctrl, closer, err := qrdbControlClient(ctx)
	if err != nil {
		return nil, nil, err
	}
	if ctrl.Rebalance == nil {
		closeFuncQuietly(closer)
		return nil, nil, &RebalanceUnsupportedError{}
	}
	return ctrl.Rebalance, closer, nil
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

// rebalanceCmd is the "xkmsctl rebalance" command group.
var rebalanceCmd = &cobra.Command{
	Use:   "rebalance",
	Short: "Shard statistics and cluster rebalancing",
	Long: `Inspect shard load distribution and rebalance the qrdb cluster
hosted by xkmsd.

Verbs map 1:1 onto qrdb's rebalance surface:
  stats    per-shard key/byte counts, leader, and replica count
  report   cluster-wide load distribution, imbalance score, and hotspots
  plan     compute an optimal shard move plan (prints it; --out saves the
           JSON plan for later execution)
  execute  execute a plan: --plan FILE runs a saved plan verbatim,
           otherwise a fresh plan is computed server-side and executed`,
}

// newRebalanceStatsCmd implements "rebalance stats [--shard]".
func newRebalanceStatsCmd() *cobra.Command {
	var shardID uint64

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show statistics for a shard",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rc, closer, err := rebalanceClient(cmd.Context())
			if err != nil {
				return err
			}
			defer closeFuncQuietly(closer)

			stats, err := rc.GetShardStats(cmd.Context(), shardID)
			if err != nil {
				return &WrappedError{Sentinel: ErrShardStatsFailed, Err: err}
			}

			printer := NewPrinter(getConfig().OutputFormat, cmd.OutOrStdout())
			return printer.PrintShardStats(stats)
		},
	}

	cmd.Flags().Uint64Var(&shardID, "shard", defaultShardID, "shard ID to query")
	return cmd
}

// newRebalancePlanCmd implements
// "rebalance plan [--max-moves] [--dry-run] [--target-balance] [--out FILE]".
func newRebalancePlanCmd() *cobra.Command {
	var (
		maxMoves      int
		dryRun        bool
		targetBalance float64
		outFile       string
	)

	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Compute an optimal shard move plan",
		Long: `Compute an optimal shard move plan for the cluster.

The plan is printed to stdout; pass --out FILE to also save it as JSON
for later verbatim execution with "rebalance execute --plan FILE".`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rc, closer, err := rebalanceClient(cmd.Context())
			if err != nil {
				return err
			}
			defer closeFuncQuietly(closer)

			plan, err := rc.CreateRebalancePlan(cmd.Context(), &qrdbtransport.RebalancePlanRequest{
				MaxMoves:      maxMoves,
				DryRun:        dryRun,
				TargetBalance: targetBalance,
			})
			if err != nil {
				return &WrappedError{Sentinel: ErrRebalancePlanFailed, Err: err}
			}

			if outFile != "" {
				if err := writeRebalancePlanFile(outFile, plan); err != nil {
					return err
				}
			}

			printer := NewPrinter(getConfig().OutputFormat, cmd.OutOrStdout())
			return printer.PrintRebalancePlan(plan)
		},
	}

	cmd.Flags().IntVar(&maxMoves, "max-moves", 0, "maximum shard moves in the plan (0 = no limit)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "generate the plan without any server-side execution")
	cmd.Flags().Float64Var(&targetBalance, "target-balance", 0, "target balance tolerance percentage (0 = perfectly balanced)")
	cmd.Flags().StringVar(&outFile, "out", "", "write the plan as JSON to this file for later execution")
	return cmd
}

// newRebalanceExecuteCmd implements
// "rebalance execute [--plan FILE | --max-moves N --target-balance F]".
func newRebalanceExecuteCmd() *cobra.Command {
	var (
		planFile      string
		maxMoves      int
		targetBalance float64
	)

	cmd := &cobra.Command{
		Use:   "execute",
		Short: "Execute a rebalance plan",
		Long: `Execute a rebalance plan by moving shards between nodes.

With --plan FILE, the JSON plan previously saved by "rebalance plan --out"
is executed verbatim. Without --plan, a fresh plan is computed server-side
(honoring --max-moves and --target-balance) and executed immediately.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rc, closer, err := rebalanceClient(cmd.Context())
			if err != nil {
				return err
			}
			defer closeFuncQuietly(closer)

			var plan *qrdbtransport.RebalancePlan
			if planFile != "" {
				plan, err = readRebalancePlanFile(planFile)
				if err != nil {
					return err
				}
			} else {
				plan, err = rc.CreateRebalancePlan(cmd.Context(), &qrdbtransport.RebalancePlanRequest{
					MaxMoves:      maxMoves,
					TargetBalance: targetBalance,
				})
				if err != nil {
					return &WrappedError{Sentinel: ErrRebalancePlanFailed, Err: err}
				}
			}

			result, err := rc.ExecuteRebalance(cmd.Context(), plan)
			if err != nil {
				return &WrappedError{Sentinel: ErrRebalanceExecuteFailed, Err: err}
			}

			printer := NewPrinter(getConfig().OutputFormat, cmd.OutOrStdout())
			return printer.PrintRebalanceResult(result)
		},
	}

	cmd.Flags().StringVar(&planFile, "plan", "", "JSON plan file saved by 'rebalance plan --out' (executed verbatim)")
	cmd.Flags().IntVar(&maxMoves, "max-moves", 0, "maximum shard moves when planning server-side (ignored with --plan)")
	cmd.Flags().Float64Var(&targetBalance, "target-balance", 0, "target balance tolerance when planning server-side (ignored with --plan)")
	return cmd
}

// newRebalanceReportCmd implements "rebalance report".
func newRebalanceReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Show the cluster imbalance report",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rc, closer, err := rebalanceClient(cmd.Context())
			if err != nil {
				return err
			}
			defer closeFuncQuietly(closer)

			report, err := rc.GetImbalanceReport(cmd.Context())
			if err != nil {
				return &WrappedError{Sentinel: ErrImbalanceReportFailed, Err: err}
			}

			printer := NewPrinter(getConfig().OutputFormat, cmd.OutOrStdout())
			return printer.PrintImbalanceReport(report)
		},
	}
	return cmd
}

func init() {
	rebalanceCmd.AddCommand(newRebalanceStatsCmd())
	rebalanceCmd.AddCommand(newRebalancePlanCmd())
	rebalanceCmd.AddCommand(newRebalanceExecuteCmd())
	rebalanceCmd.AddCommand(newRebalanceReportCmd())
	rootCmd.AddCommand(rebalanceCmd)
}

// ---------------------------------------------------------------------------
// Plan file I/O
// ---------------------------------------------------------------------------

// writeRebalancePlanFile persists a plan as indented JSON with 0600
// permissions so it can be replayed by "rebalance execute --plan".
func writeRebalancePlanFile(path string, plan *qrdbtransport.RebalancePlan) error {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return &RebalancePlanFileWriteError{Path: path, Cause: err}
	}
	if err := fsutil.WriteFileAtomic(path, append(data, '\n'), 0o600); err != nil {
		return &RebalancePlanFileWriteError{Path: path, Cause: err}
	}
	return nil
}

// readRebalancePlanFile loads a plan previously saved by
// "rebalance plan --out".
func readRebalancePlanFile(path string) (*qrdbtransport.RebalancePlan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &RebalancePlanFileReadError{Path: path, Cause: err}
	}
	var plan qrdbtransport.RebalancePlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, &RebalancePlanFileParseError{Path: path, Cause: err}
	}
	return &plan, nil
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

// PrintShardStats prints statistics for a single shard.
func (p *Printer) PrintShardStats(stats *qrdbtransport.ShardStatsResponse) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(stats)
	case OutputFormatTable, OutputFormatText:
		fprintf(p.writer, "Shard:    %d\n", stats.ShardID)
		fprintf(p.writer, "Keys:     %d\n", stats.KeyCount)
		fprintf(p.writer, "Bytes:    %d\n", stats.ByteCount)
		if stats.LeaderID != 0 {
			fprintf(p.writer, "Leader:   replica %d\n", stats.LeaderID)
		} else {
			fprintf(p.writer, "Leader:   unknown\n")
		}
		fprintf(p.writer, "Replicas: %d\n", stats.ReplicaCount)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintRebalancePlan prints a computed rebalance plan.
func (p *Printer) PrintRebalancePlan(plan *qrdbtransport.RebalancePlan) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(plan)
	case OutputFormatTable, OutputFormatText:
		fprintf(p.writer, "Current imbalance:  %.2f\n", plan.CurrentImbalance)
		fprintf(p.writer, "Estimated duration: %s\n", plan.EstimatedDuration)
		fprintf(p.writer, "Planned moves:      %d\n", len(plan.Moves))
		if len(plan.Moves) == 0 {
			fprintf(p.writer, "Cluster is balanced; nothing to move\n")
			return p.writer.Err()
		}
		fprintf(p.writer, "%-8s %-25s %-25s %s\n", "SHARD", "FROM", "TO", "EST. BYTES")
		for _, m := range plan.Moves {
			fprintf(p.writer, "%-8d %-25s %-25s %d\n", m.ShardID, m.FromNode, m.ToNode, m.EstimatedBytes)
		}
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintRebalanceResult prints the outcome of an executed rebalance.
func (p *Printer) PrintRebalanceResult(result *qrdbtransport.RebalanceResult) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(result)
	case OutputFormatTable, OutputFormatText:
		fprintf(p.writer, "Moves completed: %d\n", result.MovesCompleted)
		fprintf(p.writer, "Moves failed:    %d\n", result.MovesFailed)
		fprintf(p.writer, "Duration:        %s\n", result.Duration)
		fprintf(p.writer, "Final imbalance: %.2f\n", result.FinalImbalance)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintImbalanceReport prints the cluster load-distribution report.
func (p *Printer) PrintImbalanceReport(report *qrdbtransport.ImbalanceReport) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(report)
	case OutputFormatTable, OutputFormatText:
		fprintf(p.writer, "Imbalance score: %.2f\n", report.ImbalanceScore)
		if len(report.Hotspots) > 0 {
			fprintf(p.writer, "Hotspots:        %v\n", report.Hotspots)
		} else {
			fprintf(p.writer, "Hotspots:        none\n")
		}
		if len(report.Nodes) == 0 {
			fprintf(p.writer, "No nodes reported\n")
			return p.writer.Err()
		}
		fprintf(p.writer, "%-20s %-25s %-8s %-12s %-12s %s\n",
			"NODE", "ADDRESS", "SHARDS", "KEYS", "BYTES", "LEADERS")
		for _, n := range report.Nodes {
			fprintf(p.writer, "%-20s %-25s %-8d %-12d %-12d %d\n",
				n.NodeID, n.Address, n.ShardCount, n.TotalKeys, n.TotalBytes, n.LeaderCount)
		}
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}
