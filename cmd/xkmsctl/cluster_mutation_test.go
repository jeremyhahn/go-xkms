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
	"errors"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// errClusterDenied stands in for the server-side authorization refusal a caller
// without the membership permission receives.
var errClusterDenied = errors.New("permission denied: admin:add_member")

// mockClusterMutatorClient extends the read-only cluster mock with the
// membership-mutation surface, so the SDK resolves a mutation-capable facade.
type mockClusterMutatorClient struct {
	mockClusterClient

	addReplicaID uint64
	addRaftAddr  string
	addCalls     int
	addErr       error

	removeReplicaID uint64
	removeCalls     int
	removeErr       error
}

func (m *mockClusterMutatorClient) AddClusterReplica(_ context.Context, replicaID uint64, raftAddr string) (*transport.ClusterReplicaResponse, error) {
	m.addCalls++
	m.addReplicaID = replicaID
	m.addRaftAddr = raftAddr
	if m.addErr != nil {
		return nil, m.addErr
	}
	return &transport.ClusterReplicaResponse{ShardID: 1, ReplicaID: replicaID}, nil
}

func (m *mockClusterMutatorClient) RemoveClusterReplica(_ context.Context, replicaID uint64) (*transport.ClusterReplicaResponse, error) {
	m.removeCalls++
	m.removeReplicaID = replicaID
	if m.removeErr != nil {
		return nil, m.removeErr
	}
	return &transport.ClusterReplicaResponse{ShardID: 1, ReplicaID: replicaID}, nil
}

func newTestClusterMutatorConfig(mock *mockClusterMutatorClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mock, nil
		},
	}
}

// --- Command registration ---

func TestClusterAddRemoveCmds_Registered(t *testing.T) {
	names := make(map[string]bool)
	for _, sub := range clusterCmd.Commands() {
		names[sub.Name()] = true
	}
	for _, want := range []string{"status", "members", "add", "remove"} {
		if !names[want] {
			t.Fatalf("cluster subcommand %q is not registered", want)
		}
	}
}

func TestClusterAddCmd_RequiresTwoArgs(t *testing.T) {
	if err := clusterAddCmd.Args(clusterAddCmd, []string{"2"}); err == nil {
		t.Fatal("cluster add should reject a single argument")
	}
	if err := clusterAddCmd.Args(clusterAddCmd, []string{"2", "10.0.0.2:63001"}); err != nil {
		t.Fatalf("cluster add should accept two arguments: %v", err)
	}
}

func TestClusterRemoveCmd_RequiresOneArg(t *testing.T) {
	if err := clusterRemoveCmd.Args(clusterRemoveCmd, []string{}); err == nil {
		t.Fatal("cluster remove should reject zero arguments")
	}
	if err := clusterRemoveCmd.Args(clusterRemoveCmd, []string{"2"}); err != nil {
		t.Fatalf("cluster remove should accept one argument: %v", err)
	}
}

// --- parseReplicaID ---

func TestParseReplicaID_Valid(t *testing.T) {
	got, err := parseReplicaID("7")
	if err != nil {
		t.Fatalf("parseReplicaID(\"7\") unexpected error: %v", err)
	}
	if got != 7 {
		t.Fatalf("parseReplicaID(\"7\") = %d, want 7", got)
	}
}

func TestParseReplicaID_Invalid(t *testing.T) {
	for _, arg := range []string{"0", "-1", "abc", "", "1.5"} {
		if _, err := parseReplicaID(arg); !errors.Is(err, ErrInvalidReplicaID) {
			t.Fatalf("parseReplicaID(%q) error = %v, want ErrInvalidReplicaID", arg, err)
		}
	}
}

// --- clusterAdd / clusterRemove ---

func TestClusterAdd_Success(t *testing.T) {
	mock := &mockClusterMutatorClient{}
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	clusterAdd(newTestClusterMutatorConfig(mock), printer, 2, "10.0.0.2:63001")

	if mock.addCalls != 1 {
		t.Fatalf("AddClusterReplica calls = %d, want 1", mock.addCalls)
	}
	if mock.addReplicaID != 2 || mock.addRaftAddr != "10.0.0.2:63001" {
		t.Fatalf("server received replica %d at %q, want 2 at 10.0.0.2:63001",
			mock.addReplicaID, mock.addRaftAddr)
	}
	if out := buf.String(); !strings.Contains(out, "added") || !strings.Contains(out, "2") {
		t.Fatalf("output %q should report replica 2 added", out)
	}
}

func TestClusterRemove_Success(t *testing.T) {
	mock := &mockClusterMutatorClient{}
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	clusterRemove(newTestClusterMutatorConfig(mock), printer, 3)

	if mock.removeCalls != 1 {
		t.Fatalf("RemoveClusterReplica calls = %d, want 1", mock.removeCalls)
	}
	if mock.removeReplicaID != 3 {
		t.Fatalf("server received replica %d, want 3", mock.removeReplicaID)
	}
	if out := buf.String(); !strings.Contains(out, "removed") {
		t.Fatalf("output %q should report the replica removed", out)
	}
}

// TestClusterAdd_Idempotent proves the CLI adds no client-side bookkeeping: a
// repeated add reaches the server again and still succeeds.
func TestClusterAdd_Idempotent(t *testing.T) {
	mock := &mockClusterMutatorClient{}
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	cfg := newTestClusterMutatorConfig(mock)

	clusterAdd(cfg, printer, 2, "10.0.0.2:63001")
	clusterAdd(cfg, printer, 2, "10.0.0.2:63001")

	if mock.addCalls != 2 {
		t.Fatalf("AddClusterReplica calls = %d, want 2", mock.addCalls)
	}
}

// TestClusterAdd_Denied covers the authorization refusal path: the caller lacks
// the membership permission, so the CLI must exit non-zero rather than report
// success. handleError terminates the process, so the exit code is the
// observable outcome.
func TestClusterAdd_Denied(t *testing.T) {
	mock := &mockClusterMutatorClient{addErr: errClusterDenied}
	cfg := newTestClusterMutatorConfig(mock)

	code := captureExit(t, func() {
		clusterAdd(cfg, NewPrinter("text", nil), 2, "10.0.0.2:63001")
	})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 when the server denies the mutation", code)
	}
	if mock.addCalls != 1 {
		t.Fatalf("AddClusterReplica calls = %d, want 1", mock.addCalls)
	}
}

func TestClusterRemove_Denied(t *testing.T) {
	mock := &mockClusterMutatorClient{removeErr: errClusterDenied}
	cfg := newTestClusterMutatorConfig(mock)

	code := captureExit(t, func() {
		clusterRemove(cfg, NewPrinter("text", nil), 2)
	})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 when the server denies the mutation", code)
	}
}

// TestClusterMutation_UnsupportedTransport covers a transport that exposes the
// read-only cluster surface but cannot mutate membership: the CLI must fail
// cleanly rather than appear to succeed.
func TestClusterMutation_UnsupportedTransport(t *testing.T) {
	cfg := newTestClusterConfig(&mockClusterClient{})

	code := captureExit(t, func() {
		clusterAdd(cfg, NewPrinter("text", nil), 2, "10.0.0.2:63001")
	})
	if code != 1 {
		t.Fatalf("add exit code = %d, want 1 on a read-only transport", code)
	}

	code = captureExit(t, func() {
		clusterRemove(cfg, NewPrinter("text", nil), 2)
	})
	if code != 1 {
		t.Fatalf("remove exit code = %d, want 1 on a read-only transport", code)
	}
}

func TestClusterAdd_ClientError(t *testing.T) {
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("dial failed")
		},
	}

	code := captureExit(t, func() {
		clusterAdd(cfg, NewPrinter("text", nil), 2, "10.0.0.2:63001")
	})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 when the client cannot be built", code)
	}
}

func TestClusterRemove_ClientError(t *testing.T) {
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("dial failed")
		},
	}

	code := captureExit(t, func() {
		clusterRemove(cfg, NewPrinter("text", nil), 2)
	})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 when the client cannot be built", code)
	}
}

// --- advertised endpoint rendering ---

func TestFormatAPIEndpoints_Sorted(t *testing.T) {
	lines := formatAPIEndpoints(map[string]string{
		"rest": "10.0.0.1:8443",
		"grpc": "10.0.0.1:9443",
		"quic": "10.0.0.1:8444",
	})

	want := []string{"grpc=10.0.0.1:9443", "quic=10.0.0.1:8444", "rest=10.0.0.1:8443"}
	if len(lines) != len(want) {
		t.Fatalf("formatAPIEndpoints() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("formatAPIEndpoints()[%d] = %q, want %q", i, lines[i], want[i])
		}
	}
}

// TestFormatAPIEndpoints_NotAdvertised covers the degrade path: a replica that
// advertises nothing renders exactly as it did before endpoints existed.
func TestFormatAPIEndpoints_NotAdvertised(t *testing.T) {
	if lines := formatAPIEndpoints(nil); lines != nil {
		t.Fatalf("formatAPIEndpoints(nil) = %v, want nil", lines)
	}
	if lines := formatAPIEndpoints(map[string]string{}); lines != nil {
		t.Fatalf("formatAPIEndpoints(empty) = %v, want nil", lines)
	}
}

// TestPrintClusterMembers_APIEndpoints verifies the members listing shows an
// advertising replica's endpoints and stays unchanged for one that advertises
// nothing.
func TestPrintClusterMembers_APIEndpoints(t *testing.T) {
	var buf bytes.Buffer
	printClusterMembers(NewPrinter("text", &buf), []client.ClusterMemberInfo{
		{
			NodeID:       1,
			Address:      "10.0.0.1:63001",
			APIEndpoints: map[string]string{"rest": "10.0.0.1:8443"},
			IsLeader:     true,
		},
		{NodeID: 2, Address: "10.0.0.2:63001"},
	})

	out := buf.String()
	if !strings.Contains(out, "api: rest=10.0.0.1:8443") {
		t.Fatalf("output %q should list the advertised REST endpoint", out)
	}
	if strings.Count(out, "api:") != 1 {
		t.Fatalf("output %q should carry exactly one api line (only one replica advertises)", out)
	}
}
