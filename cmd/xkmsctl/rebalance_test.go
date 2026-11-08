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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// ---------------------------------------------------------------------------
// Fake
// ---------------------------------------------------------------------------

// fakeRebalanceClient is an in-process transport.RebalanceClient recording
// call arguments and returning canned results.
type fakeRebalanceClient struct {
	stats      *qrdbtransport.ShardStatsResponse
	statsErr   error
	plan       *qrdbtransport.RebalancePlan
	planErr    error
	result     *qrdbtransport.RebalanceResult
	execErr    error
	report     *qrdbtransport.ImbalanceReport
	reportErr  error
	gotShardID uint64
	gotPlanReq *qrdbtransport.RebalancePlanRequest
	gotPlan    *qrdbtransport.RebalancePlan
}

func (f *fakeRebalanceClient) GetShardStats(_ context.Context, shardID uint64) (*qrdbtransport.ShardStatsResponse, error) {
	f.gotShardID = shardID
	if f.statsErr != nil {
		return nil, f.statsErr
	}
	return f.stats, nil
}

func (f *fakeRebalanceClient) CreateRebalancePlan(_ context.Context, req *qrdbtransport.RebalancePlanRequest) (*qrdbtransport.RebalancePlan, error) {
	f.gotPlanReq = req
	if f.planErr != nil {
		return nil, f.planErr
	}
	return f.plan, nil
}

func (f *fakeRebalanceClient) ExecuteRebalance(_ context.Context, plan *qrdbtransport.RebalancePlan) (*qrdbtransport.RebalanceResult, error) {
	f.gotPlan = plan
	if f.execErr != nil {
		return nil, f.execErr
	}
	return f.result, nil
}

func (f *fakeRebalanceClient) GetImbalanceReport(_ context.Context) (*qrdbtransport.ImbalanceReport, error) {
	if f.reportErr != nil {
		return nil, f.reportErr
	}
	return f.report, nil
}

// testRebalancePlan returns a single-move plan fixture.
func testRebalancePlan() *qrdbtransport.RebalancePlan {
	return &qrdbtransport.RebalancePlan{
		Moves: []qrdbtransport.RebalanceMove{
			{ShardID: 2, FromNode: "10.0.0.1:63001", ToNode: "10.0.0.2:63001", EstimatedBytes: 4096},
		},
		EstimatedDuration: 3 * time.Second,
		CurrentImbalance:  0.42,
	}
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// TestRebalanceStats_ShardFlagDefault verifies rebalance stats carries a
// --shard flag defaulting to "1".
func TestRebalanceStats_ShardFlagDefault(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"rebalance", "stats"})
	if err != nil {
		t.Fatalf("rebalance stats not registered: %v", err)
	}
	flag := cmd.Flags().Lookup("shard")
	if flag == nil {
		t.Fatal("rebalance stats --shard flag missing")
	}
	if flag.DefValue != "1" {
		t.Errorf("--shard default = %q, want \"1\"", flag.DefValue)
	}
}

// ---------------------------------------------------------------------------
// Nil-rebalance transport guard
// ---------------------------------------------------------------------------

// TestRebalance_NilClient verifies every verb fails with the typed
// unsupported-transport error when the transport lacks the rebalance
// surface.
func TestRebalance_NilClient(t *testing.T) {
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}})

	for _, verb := range []string{"stats", "plan", "execute", "report"} {
		_, err := runClusterCmd(t, "rebalance", verb)
		var unsupported *RebalanceUnsupportedError
		if !errors.As(err, &unsupported) {
			t.Errorf("rebalance %s: expected RebalanceUnsupportedError, got %v", verb, err)
		}
	}
}

// ---------------------------------------------------------------------------
// rebalance stats
// ---------------------------------------------------------------------------

// TestRebalanceStats_Success verifies shard stats rendering and --shard
// plumbing.
func TestRebalanceStats_Success(t *testing.T) {
	fake := &fakeRebalanceClient{
		stats: &qrdbtransport.ShardStatsResponse{
			ShardID:      4,
			KeyCount:     1000,
			ByteCount:    2048,
			LeaderID:     2,
			ReplicaCount: 3,
		},
	}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	out, err := runClusterCmd(t, "rebalance", "stats", "--shard", "4")
	if err != nil {
		t.Fatalf("rebalance stats: %v", err)
	}
	if fake.gotShardID != 4 {
		t.Errorf("shard ID = %d, want 4", fake.gotShardID)
	}
	for _, want := range []string{"Shard:    4", "Keys:     1000", "Replicas: 3", "replica 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestRebalanceStats_Error verifies the typed error path.
func TestRebalanceStats_Error(t *testing.T) {
	fake := &fakeRebalanceClient{statsErr: errors.New("boom")}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	_, err := runClusterCmd(t, "rebalance", "stats")
	if !errors.Is(err, ErrShardStatsFailed) {
		t.Fatalf("expected ErrShardStatsFailed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// rebalance plan
// ---------------------------------------------------------------------------

// TestRebalancePlan_WritesOutFile verifies --out persists a JSON plan
// that execute can replay.
func TestRebalancePlan_WritesOutFile(t *testing.T) {
	fake := &fakeRebalanceClient{plan: testRebalancePlan()}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	planPath := filepath.Join(t.TempDir(), "plan.json")
	if _, err := runClusterCmd(t, "rebalance", "plan", "--out", planPath); err != nil {
		t.Fatalf("rebalance plan --out: %v", err)
	}

	data, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("read plan file: %v", err)
	}
	var plan qrdbtransport.RebalancePlan
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatalf("plan file is not valid JSON: %v", err)
	}
	if len(plan.Moves) != 1 || plan.Moves[0].ShardID != 2 {
		t.Errorf("unexpected persisted plan: %+v", plan)
	}
}

// TestRebalancePlan_Error verifies the typed error path.
func TestRebalancePlan_Error(t *testing.T) {
	fake := &fakeRebalanceClient{planErr: errors.New("boom")}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	_, err := runClusterCmd(t, "rebalance", "plan")
	if !errors.Is(err, ErrRebalancePlanFailed) {
		t.Fatalf("expected ErrRebalancePlanFailed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// rebalance execute
// ---------------------------------------------------------------------------

// TestRebalanceExecute_FromPlanFile verifies a saved plan is executed
// verbatim without a server-side re-plan.
func TestRebalanceExecute_FromPlanFile(t *testing.T) {
	fake := &fakeRebalanceClient{
		result: &qrdbtransport.RebalanceResult{
			MovesCompleted: 1,
			Duration:       2 * time.Second,
			FinalImbalance: 0.01,
		},
	}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	planPath := filepath.Join(t.TempDir(), "plan.json")
	data, err := json.Marshal(testRebalancePlan())
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(planPath, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out, err := runClusterCmd(t, "rebalance", "execute", "--plan", planPath)
	if err != nil {
		t.Fatalf("rebalance execute: %v", err)
	}
	if fake.gotPlanReq != nil {
		t.Error("execute --plan must not re-plan server-side")
	}
	if fake.gotPlan == nil || len(fake.gotPlan.Moves) != 1 || fake.gotPlan.Moves[0].ShardID != 2 {
		t.Errorf("executed plan = %+v, want the saved single-move plan", fake.gotPlan)
	}
	if !strings.Contains(out, "Moves completed: 1") {
		t.Errorf("output missing result:\n%s", out)
	}
}

// TestRebalanceExecute_ServerSidePlan verifies execute without --plan
// computes a fresh plan then executes it.
func TestRebalanceExecute_ServerSidePlan(t *testing.T) {
	fake := &fakeRebalanceClient{
		plan:   testRebalancePlan(),
		result: &qrdbtransport.RebalanceResult{MovesCompleted: 1},
	}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	_, err := runClusterCmd(t, "rebalance", "execute", "--max-moves", "2", "--target-balance", "5")
	if err != nil {
		t.Fatalf("rebalance execute: %v", err)
	}
	if fake.gotPlanReq == nil {
		t.Fatal("expected a server-side CreateRebalancePlan call")
	}
	if fake.gotPlanReq.MaxMoves != 2 || fake.gotPlanReq.TargetBalance != 5 || fake.gotPlanReq.DryRun {
		t.Errorf("plan request = %+v, want MaxMoves=2 TargetBalance=5 DryRun=false", fake.gotPlanReq)
	}
	if fake.gotPlan != fake.plan {
		t.Error("execute must run the freshly computed plan")
	}
}

// TestRebalanceExecute_PlanFileMissing verifies the typed read error.
func TestRebalanceExecute_PlanFileMissing(t *testing.T) {
	fake := &fakeRebalanceClient{}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	_, err := runClusterCmd(t, "rebalance", "execute",
		"--plan", filepath.Join(t.TempDir(), "missing.json"))
	var readErr *RebalancePlanFileReadError
	if !errors.As(err, &readErr) {
		t.Fatalf("expected RebalancePlanFileReadError, got %v", err)
	}
}

// TestRebalanceExecute_PlanFileInvalid verifies the typed parse error.
func TestRebalanceExecute_PlanFileInvalid(t *testing.T) {
	fake := &fakeRebalanceClient{}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	planPath := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(planPath, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, err := runClusterCmd(t, "rebalance", "execute", "--plan", planPath)
	var parseErr *RebalancePlanFileParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected RebalancePlanFileParseError, got %v", err)
	}
	if fake.gotPlan != nil {
		t.Error("ExecuteRebalance must not run with an unparseable plan")
	}
}

// TestRebalanceExecute_Error verifies the typed execute error path.
func TestRebalanceExecute_Error(t *testing.T) {
	fake := &fakeRebalanceClient{plan: testRebalancePlan(), execErr: errors.New("boom")}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	_, err := runClusterCmd(t, "rebalance", "execute")
	if !errors.Is(err, ErrRebalanceExecuteFailed) {
		t.Fatalf("expected ErrRebalanceExecuteFailed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// rebalance report
// ---------------------------------------------------------------------------

// TestRebalanceReport_Success verifies the report rendering.
func TestRebalanceReport_Success(t *testing.T) {
	fake := &fakeRebalanceClient{
		report: &qrdbtransport.ImbalanceReport{
			Nodes: []qrdbtransport.NodeLoad{
				{NodeID: "node-a", Address: "10.0.0.1:63001", ShardCount: 3, TotalKeys: 900, TotalBytes: 8192, LeaderCount: 2},
			},
			ImbalanceScore: 0.37,
			Hotspots:       []string{"node-a"},
		},
	}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	out, err := runClusterCmd(t, "rebalance", "report")
	if err != nil {
		t.Fatalf("rebalance report: %v", err)
	}
	for _, want := range []string{"Imbalance score: 0.37", "node-a", "10.0.0.1:63001"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestRebalanceReport_JSON verifies JSON output round-trips.
func TestRebalanceReport_JSON(t *testing.T) {
	fake := &fakeRebalanceClient{
		report: &qrdbtransport.ImbalanceReport{ImbalanceScore: 0.5, Hotspots: []string{"n1"}},
	}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	out, err := runClusterCmdFormat(t, "json", "rebalance", "report")
	if err != nil {
		t.Fatalf("rebalance report: %v", err)
	}
	var report qrdbtransport.ImbalanceReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON output %q: %v", out, err)
	}
	if report.ImbalanceScore != 0.5 || len(report.Hotspots) != 1 {
		t.Errorf("unexpected report: %+v", report)
	}
}

// TestRebalanceReport_Error verifies the typed error path.
func TestRebalanceReport_Error(t *testing.T) {
	fake := &fakeRebalanceClient{reportErr: errors.New("boom")}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: &fakeClusterControl{}, Rebalance: fake})

	_, err := runClusterCmd(t, "rebalance", "report")
	if !errors.Is(err, ErrImbalanceReportFailed) {
		t.Fatalf("expected ErrImbalanceReportFailed, got %v", err)
	}
}

// TestRebalancePrinters_EmptyResults pins the text an operator sees when the
// server has no leader, no moves or no nodes to report: each is an explicit
// line, never a blank table.
func TestRebalancePrinters_EmptyResults(t *testing.T) {
	tests := []struct {
		name  string
		print func(p *Printer) error
		want  []string
	}{
		{
			name:  "shard without leader",
			print: func(p *Printer) error { return p.PrintShardStats(&qrdbtransport.ShardStatsResponse{ShardID: 4}) },
			want:  []string{"Shard:    4", "Leader:   unknown"},
		},
		{
			name:  "balanced plan",
			print: func(p *Printer) error { return p.PrintRebalancePlan(&qrdbtransport.RebalancePlan{}) },
			want:  []string{"Planned moves:      0", "Cluster is balanced; nothing to move"},
		},
		{
			name:  "report without nodes",
			print: func(p *Printer) error { return p.PrintImbalanceReport(&qrdbtransport.ImbalanceReport{}) },
			want:  []string{"Hotspots:        none", "No nodes reported"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tt.print(NewPrinter(string(OutputFormatText), &buf)); err != nil {
				t.Fatalf("print: %v", err)
			}
			for _, want := range tt.want {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("output missing %q:\n%s", want, buf.String())
				}
			}
		})
	}
}

// TestRebalancePrinters_UnknownFormat checks every rebalance printer refuses
// an output format it does not render, and writes nothing.
func TestRebalancePrinters_UnknownFormat(t *testing.T) {
	printers := map[string]func(p *Printer) error{
		"stats":  func(p *Printer) error { return p.PrintShardStats(&qrdbtransport.ShardStatsResponse{}) },
		"plan":   func(p *Printer) error { return p.PrintRebalancePlan(&qrdbtransport.RebalancePlan{}) },
		"result": func(p *Printer) error { return p.PrintRebalanceResult(&qrdbtransport.RebalanceResult{}) },
		"report": func(p *Printer) error { return p.PrintImbalanceReport(&qrdbtransport.ImbalanceReport{}) },
	}
	for name, printFn := range printers {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			err := printFn(NewPrinter("yaml", &buf))
			if !errors.Is(err, ErrUnknownOutputFormat) {
				t.Fatalf("err = %v, want ErrUnknownOutputFormat", err)
			}
			if buf.Len() != 0 {
				t.Errorf("wrote output for a refused format: %q", buf.String())
			}
		})
	}
}
