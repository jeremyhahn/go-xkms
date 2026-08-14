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
	"github.com/spf13/cobra"
)

// mockClusterClient extends the custodian mock with the read-only cluster
// surface so the SDK Cluster() accessor resolves the client.
type mockClusterClient struct {
	mockCustodianClient

	statusResp  *transport.ClusterStatusResponse
	statusErr   error
	membersResp *transport.ListClusterMembersResponse
	membersErr  error
}

func (m *mockClusterClient) ClusterStatus(_ context.Context) (*transport.ClusterStatusResponse, error) {
	return m.statusResp, m.statusErr
}

func (m *mockClusterClient) ClusterMembers(_ context.Context) (*transport.ListClusterMembersResponse, error) {
	return m.membersResp, m.membersErr
}

func newTestClusterConfig(mock *mockClusterClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mock, nil
		},
	}
}

// --- Command existence and properties ---

func TestClusterCmd_Exists(t *testing.T) {
	if clusterCmd == nil {
		t.Fatal("clusterCmd should not be nil")
	}
}

func TestClusterCmd_Properties(t *testing.T) {
	if clusterCmd.Use != "cluster" {
		t.Errorf("clusterCmd.Use = %q, want %q", clusterCmd.Use, "cluster")
	}
	if clusterCmd.Short == "" {
		t.Error("clusterCmd.Short should not be empty")
	}
}

func TestClusterCmd_Subcommands(t *testing.T) {
	subcommands := clusterCmd.Commands()

	expected := map[string]bool{
		"status":  false,
		"members": false,
		"add":     false,
		"remove":  false,
	}
	for _, cmd := range subcommands {
		if _, ok := expected[cmd.Name()]; ok {
			expected[cmd.Name()] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("expected subcommand %q not found", name)
		}
	}
	if len(subcommands) != 4 {
		t.Errorf("expected 4 subcommands, got %d", len(subcommands))
	}
}

func TestClusterCmd_RegisteredOnRoot(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "cluster" {
			found = true
			break
		}
	}
	if !found {
		t.Error("cluster command not registered on root")
	}
}

func TestClusterCmd_ShardFlag(t *testing.T) {
	cmds := map[string]*cobra.Command{
		"status":  clusterStatusCmd,
		"members": clusterMembersCmd,
	}
	for name, target := range cmds {
		flag := target.Flags().Lookup("shard")
		if flag == nil {
			t.Fatalf("%s command missing --shard flag", name)
		}
		if flag.DefValue != "1" {
			t.Errorf("%s --shard default = %q, want 1", name, flag.DefValue)
		}
	}
}

// --- createClusterClient ---

func TestCreateClusterClient_Success(t *testing.T) {
	mock := &mockClusterClient{}
	cfg := newTestClusterConfig(mock)

	cluster, cleanup, err := createClusterClient(cfg)
	if err != nil {
		t.Fatalf("createClusterClient returned unexpected error: %v", err)
	}
	if cluster == nil {
		t.Fatal("createClusterClient returned nil cluster client")
	}
	cleanup()
	if !mock.closeCalled {
		t.Error("cleanup should call client.Close()")
	}
}

func TestCreateClusterClient_FactoryError(t *testing.T) {
	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("factory failure")
		},
	}

	cluster, cleanup, err := createClusterClient(cfg)
	if err == nil {
		t.Fatal("createClusterClient should return error on factory failure")
	}
	if cluster != nil {
		t.Error("cluster client should be nil on error")
	}
	if cleanup != nil {
		t.Error("cleanup should be nil on error")
	}
}

// --- status / members rendering ---

func TestClusterStatus_Success(t *testing.T) {
	mock := &mockClusterClient{
		statusResp: &transport.ClusterStatusResponse{
			Status: transport.ClusterStatusInfo{
				ShardID:   1,
				NodeID:    1,
				LeaderID:  2,
				HasLeader: true,
				Clustered: true,
			},
		},
	}
	cfg := newTestClusterConfig(mock)

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	clusterStatus(cfg, printer)

	out := buf.String()
	if !strings.Contains(out, "Leader ID:  2") {
		t.Errorf("status output missing leader id: %q", out)
	}
	if !strings.Contains(out, "Clustered:  true") {
		t.Errorf("status output missing clustered flag: %q", out)
	}
}

func TestClusterMembers_Success(t *testing.T) {
	mock := &mockClusterClient{
		membersResp: &transport.ListClusterMembersResponse{
			Members: []transport.ClusterMemberInfo{
				{NodeID: 1, Address: "10.0.0.1:63001", IsLeader: true},
				{NodeID: 2, Address: "10.0.0.2:63001", IsLeader: false},
			},
		},
	}
	cfg := newTestClusterConfig(mock)

	var buf bytes.Buffer
	printer := NewPrinter("table", &buf)
	clusterMembers(cfg, printer)

	out := buf.String()
	if !strings.Contains(out, "10.0.0.1:63001") {
		t.Errorf("members output missing address: %q", out)
	}
	if !strings.Contains(out, "Total: 2 member(s)") {
		t.Errorf("members output missing total: %q", out)
	}
}

func TestClusterMembers_Empty(t *testing.T) {
	mock := &mockClusterClient{
		membersResp: &transport.ListClusterMembersResponse{Members: nil},
	}
	cfg := newTestClusterConfig(mock)

	var buf bytes.Buffer
	printer := NewPrinter("table", &buf)
	clusterMembers(cfg, printer)

	if !strings.Contains(buf.String(), "No cluster members found") {
		t.Errorf("expected empty members message, got: %q", buf.String())
	}
}
