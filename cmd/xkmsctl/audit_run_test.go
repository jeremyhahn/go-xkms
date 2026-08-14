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

// audit_run_test.go exercises the "xkmsctl audit" command tree against a
// mock AuditService, covering happy paths, flag validation, JSON/table
// rendering, and the --all cursor-following loop.
package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errAuditRunBoom = errors.New("boom")

// mockAuditClient answers QueryAudit from a queue of canned responses,
// consumed one per call (the last entry repeats once the queue is
// exhausted, which is what makes the --all safety-bound test possible: a
// single-entry queue with a non-empty Next just keeps paging).
type mockAuditClient struct {
	mockBackendsClient

	responses []*transport.AuditPage
	err       error

	calls      int
	gotFilters []transport.AuditFilter
}

func (m *mockAuditClient) QueryAudit(_ context.Context, filter *transport.AuditFilter) (*transport.AuditPage, error) {
	m.gotFilters = append(m.gotFilters, *filter)
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	if len(m.responses) == 0 {
		return &transport.AuditPage{}, nil
	}
	idx := m.calls - 1
	if idx >= len(m.responses) {
		idx = len(m.responses) - 1
	}
	return m.responses[idx], nil
}

func newAuditConfig(mock *mockAuditClient) *Config {
	return &Config{
		OutputFormat: "table",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func TestAuditQueryCmd_Success(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })

	ts := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	mock := &mockAuditClient{responses: []*transport.AuditPage{{
		Events: []transport.AuditEvent{{
			Timestamp: ts, Actor: "alice", Resource: "key/prod", Action: "sign",
			Outcome: "allow", PrevHash: "deadbeef",
		}},
		Total: 1,
	}}}
	withGlobalConfig(t, newAuditConfig(mock))
	_ = auditQueryCmd.Flags().Set("actor", "alice")
	_ = auditQueryCmd.Flags().Set("resource", "key/prod")

	out := captureStdout(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})

	if len(mock.gotFilters) != 1 || mock.gotFilters[0].Actor != "alice" || mock.gotFilters[0].Resource != "key/prod" {
		t.Fatalf("QueryAudit filter mismatch: %+v", mock.gotFilters)
	}
	if !strings.Contains(out, "alice") || !strings.Contains(out, "sign") || !strings.Contains(out, "allow") {
		t.Errorf("expected event fields in table output, got %q", out)
	}
	if strings.Contains(out, "deadbeef") {
		t.Errorf("table output must not include prev_hash (chain link is JSON-only), got %q", out)
	}
}

func TestAuditQueryCmd_EmptyResult(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })

	withGlobalConfig(t, newAuditConfig(&mockAuditClient{responses: []*transport.AuditPage{{}}}))

	out := captureStdout(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})
	if !strings.Contains(out, "No audit events found") {
		t.Errorf("expected empty-result message, got %q", out)
	}
}

func TestAuditQueryCmd_JSONIncludesPrevHash(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })

	cfg := newAuditConfig(&mockAuditClient{responses: []*transport.AuditPage{{
		Events: []transport.AuditEvent{{Actor: "bob", PrevHash: "cafef00d"}},
	}}})
	cfg.OutputFormat = "json"
	withGlobalConfig(t, cfg)

	out := captureStdout(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})
	if !strings.Contains(out, "cafef00d") {
		t.Errorf("expected prev_hash in JSON output, got %q", out)
	}
}

func TestAuditQueryCmd_InvalidFrom(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })
	withGlobalConfig(t, newAuditConfig(&mockAuditClient{}))
	_ = auditQueryCmd.Flags().Set("from", "not-a-timestamp")

	code := captureExit(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 with invalid --from, got %d", code)
	}
}

func TestAuditQueryCmd_InvalidTo(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })
	withGlobalConfig(t, newAuditConfig(&mockAuditClient{}))
	_ = auditQueryCmd.Flags().Set("to", "not-a-timestamp")

	code := captureExit(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 with invalid --to, got %d", code)
	}
}

func TestAuditQueryCmd_ValidFromTo(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })
	mock := &mockAuditClient{responses: []*transport.AuditPage{{}}}
	withGlobalConfig(t, newAuditConfig(mock))
	_ = auditQueryCmd.Flags().Set("from", "2026-08-01T00:00:00Z")
	_ = auditQueryCmd.Flags().Set("to", "2026-08-12T00:00:00Z")

	captureStdout(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})

	if len(mock.gotFilters) != 1 {
		t.Fatalf("expected one QueryAudit call, got %d", len(mock.gotFilters))
	}
	got := mock.gotFilters[0]
	if got.From.IsZero() || got.To.IsZero() {
		t.Errorf("expected From/To to be parsed, got From=%v To=%v", got.From, got.To)
	}
}

func TestAuditQueryCmd_TransportError(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })
	withGlobalConfig(t, newAuditConfig(&mockAuditClient{err: errAuditRunBoom}))

	code := captureExit(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 on transport error, got %d", code)
	}
}

func TestAuditQueryCmd_ConnectError(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })
	mock := &mockAuditClient{}
	mock.connectErr = errAuditRunBoom
	withGlobalConfig(t, newAuditConfig(mock))

	code := captureExit(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 on connect error, got %d", code)
	}
}

func TestAuditQueryCmd_All_FollowsCursorAcrossPages(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })

	mock := &mockAuditClient{responses: []*transport.AuditPage{
		{
			Events: []transport.AuditEvent{{Actor: "alice"}, {Actor: "bob"}},
			Next:   "cursor-page-2",
			Total:  4,
		},
		{
			Events: []transport.AuditEvent{{Actor: "carol"}, {Actor: "dave"}},
			Next:   "",
			Total:  4,
		},
	}}
	withGlobalConfig(t, newAuditConfig(mock))
	_ = auditQueryCmd.Flags().Set("all", "true")

	out := captureStdout(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})

	if mock.calls != 2 {
		t.Fatalf("expected 2 QueryAudit calls following the cursor chain, got %d", mock.calls)
	}
	if mock.gotFilters[0].Cursor != "" {
		t.Errorf("first page cursor = %q, want empty", mock.gotFilters[0].Cursor)
	}
	if mock.gotFilters[1].Cursor != "cursor-page-2" {
		t.Errorf("second page cursor = %q, want %q", mock.gotFilters[1].Cursor, "cursor-page-2")
	}
	for _, actor := range []string{"alice", "bob", "carol", "dave"} {
		if !strings.Contains(out, actor) {
			t.Errorf("expected combined output to include actor %q, got %q", actor, out)
		}
	}
	if !strings.Contains(out, "Total: 4 event(s)") {
		t.Errorf("expected all 4 events combined into one page, got %q", out)
	}
}

func TestAuditQueryCmd_All_StartsFromCursorFlag(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })

	mock := &mockAuditClient{responses: []*transport.AuditPage{{Events: nil, Next: ""}}}
	withGlobalConfig(t, newAuditConfig(mock))
	_ = auditQueryCmd.Flags().Set("all", "true")
	_ = auditQueryCmd.Flags().Set("cursor", "resume-here")

	captureStdout(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})

	if len(mock.gotFilters) != 1 || mock.gotFilters[0].Cursor != "resume-here" {
		t.Fatalf("expected --all to start from --cursor, got filters %+v", mock.gotFilters)
	}
}

// TestAuditQueryCmd_All_SafetyBound pins the loop-termination guarantee: a
// server (or bug) that always returns a non-empty Next must not make --all
// spin forever. It stops at auditMaxFollowPages and reports the bound.
func TestAuditQueryCmd_All_SafetyBound(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })

	mock := &mockAuditClient{responses: []*transport.AuditPage{
		{Next: "always-more"},
	}}
	withGlobalConfig(t, newAuditConfig(mock))
	_ = auditQueryCmd.Flags().Set("all", "true")

	out := captureStdout(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})

	if mock.calls != auditMaxFollowPages {
		t.Errorf("expected exactly %d QueryAudit calls at the safety bound, got %d", auditMaxFollowPages, mock.calls)
	}
	if !strings.Contains(out, "10000") {
		t.Errorf("expected the safety bound to be reported in the warning, got %q", out)
	}
}

func TestAuditQueryCmd_All_TransportError(t *testing.T) {
	resetCmdFlags(t, auditQueryCmd)
	t.Cleanup(func() { resetCmdFlags(t, auditQueryCmd) })
	withGlobalConfig(t, newAuditConfig(&mockAuditClient{err: errAuditRunBoom}))
	_ = auditQueryCmd.Flags().Set("all", "true")

	code := captureExit(t, func() {
		auditQueryCmd.Run(auditQueryCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 on transport error mid-follow, got %d", code)
	}
}

func TestAuditCmd_Registration(t *testing.T) {
	found := map[string]bool{}
	for _, c := range auditCmd.Commands() {
		found[c.Name()] = true
	}
	if !found["query"] {
		t.Errorf("expected audit subcommand %q to be registered", "query")
	}

	rootFound := false
	for _, c := range rootCmd.Commands() {
		if c.Name() == "audit" {
			rootFound = true
		}
	}
	if !rootFound {
		t.Errorf("expected \"audit\" to be registered on the root command")
	}
}
