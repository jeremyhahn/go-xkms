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
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeClusterControl is an in-process ClusterControlClient recording the
// arguments of every call and returning canned results.
type fakeClusterControl struct {
	members      []qrdbsdk.Member
	membersErr   error
	leaderID     uint64
	hasLeader    bool
	leaderErr    error
	addErr       error
	removeErr    error
	gotShardID   uint64
	gotReplicaID uint64
	gotRaftAddr  string
}

func (f *fakeClusterControl) Members(_ context.Context, shardID uint64) ([]qrdbsdk.Member, error) {
	f.gotShardID = shardID
	if f.membersErr != nil {
		return nil, f.membersErr
	}
	return f.members, nil
}

func (f *fakeClusterControl) Leader(_ context.Context, shardID uint64) (uint64, bool, error) {
	f.gotShardID = shardID
	if f.leaderErr != nil {
		return 0, false, f.leaderErr
	}
	return f.leaderID, f.hasLeader, nil
}

func (f *fakeClusterControl) AddReplica(_ context.Context, shardID, replicaID uint64, raftAddr string) error {
	f.gotShardID = shardID
	f.gotReplicaID = replicaID
	f.gotRaftAddr = raftAddr
	return f.addErr
}

func (f *fakeClusterControl) RemoveReplica(_ context.Context, shardID, replicaID uint64) error {
	f.gotShardID = shardID
	f.gotReplicaID = replicaID
	return f.removeErr
}

// installClusterControlFactory swaps in a factory returning the given
// control bundle for the duration of the calling test.
func installClusterControlFactory(t *testing.T, ctrl *QRDBControlClient) {
	t.Helper()
	restore := SetQRDBControlClientFactory(func(_ context.Context) (*QRDBControlClient, func() error, error) {
		return ctrl, func() error { return nil }, nil
	})
	t.Cleanup(restore)
}

// runClusterCmd executes rootCmd with args in the default text output
// format, capturing command output.
func runClusterCmd(t *testing.T, args ...string) (string, error) {
	return runClusterCmdFormat(t, "text", args...)
}

// runClusterCmdFormat executes rootCmd with args, capturing command
// output. Cobra retains parsed flag values across Execute calls on
// globally shared commands, so the cluster/rebalance subtrees are reset
// to their registered defaults before each invocation. The output format
// is applied directly to the live config (other tests in this package
// mutate or replace globalConfig, so the persistent -o flag binding is
// not a reliable carrier across the whole suite).
func runClusterCmdFormat(t *testing.T, format string, args ...string) (string, error) {
	t.Helper()
	for _, name := range []string{"cluster", "rebalance"} {
		if cmd, _, err := rootCmd.Find([]string{name}); err == nil {
			resetCmdFlagsRecursive(cmd)
		}
	}

	prevFormat := getConfig().OutputFormat
	getConfig().OutputFormat = format
	t.Cleanup(func() { getConfig().OutputFormat = prevFormat })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	defer func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs([]string{})
	}()

	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return buf.String(), err
}

// testClusterMembers returns a two-replica membership fixture.
func testClusterMembers() []qrdbsdk.Member {
	return []qrdbsdk.Member{
		{
			ReplicaID: 1,
			Address:   "10.0.0.1:63001",
			IsLeader:  true,
			APIEndpoints: map[qrdbsdk.APIProtocol]string{
				qrdbsdk.APIProtocolGRPC: "10.0.0.1:9443",
			},
		},
		{
			ReplicaID: 2,
			Address:   "10.0.0.2:63001",
			IsLeader:  false,
		},
	}
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// TestClusterCmd_Registered verifies the cluster group and all four verbs
// are attached to the root command.
func TestClusterCmd_Registered(t *testing.T) {
	for _, verb := range []string{"status", "members", "add", "remove"} {
		if _, _, err := rootCmd.Find([]string{"cluster", verb}); err != nil {
			t.Errorf("cluster %s not registered: %v", verb, err)
		}
	}
}

// TestClusterCmd_ShardFlagDefaults verifies every cluster verb carries a
// --shard flag defaulting to "1".
func TestClusterCmd_ShardFlagDefaults(t *testing.T) {
	for _, verb := range []string{"status", "members", "add", "remove"} {
		cmd, _, err := rootCmd.Find([]string{"cluster", verb})
		if err != nil {
			t.Fatalf("cluster %s not registered: %v", verb, err)
		}
		flag := cmd.Flags().Lookup("shard")
		if flag == nil {
			t.Errorf("cluster %s --shard flag missing", verb)
			continue
		}
		if flag.DefValue != "1" {
			t.Errorf("cluster %s --shard default = %q, want \"1\"", verb, flag.DefValue)
		}
	}
}

// ---------------------------------------------------------------------------
// cluster status
// ---------------------------------------------------------------------------

// TestClusterStatus_Success verifies leader and member info is rendered.
func TestClusterStatus_Success(t *testing.T) {
	fake := &fakeClusterControl{
		members:   testClusterMembers(),
		leaderID:  1,
		hasLeader: true,
	}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	out, err := runClusterCmd(t, "cluster", "status", "--shard", "7")
	if err != nil {
		t.Fatalf("cluster status: %v", err)
	}
	if fake.gotShardID != 7 {
		t.Errorf("shard ID = %d, want 7", fake.gotShardID)
	}
	for _, want := range []string{"Shard:   7", "replica 1", "10.0.0.1:63001", "Members: 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestClusterStatus_NoLeader verifies the no-leader rendering.
func TestClusterStatus_NoLeader(t *testing.T) {
	fake := &fakeClusterControl{members: testClusterMembers()}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	out, err := runClusterCmd(t, "cluster", "status")
	if err != nil {
		t.Fatalf("cluster status: %v", err)
	}
	if !strings.Contains(out, "none elected") {
		t.Errorf("output missing no-leader marker:\n%s", out)
	}
}

// TestClusterStatus_LeaderError verifies the typed error path when the
// leader query fails.
func TestClusterStatus_LeaderError(t *testing.T) {
	fake := &fakeClusterControl{leaderErr: errors.New("boom")}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	_, err := runClusterCmd(t, "cluster", "status")
	if !errors.Is(err, ErrClusterLeaderFailed) {
		t.Fatalf("expected ErrClusterLeaderFailed, got %v", err)
	}
}

// TestClusterStatus_MembersError verifies the typed error path when the
// membership query fails after a successful leader query.
func TestClusterStatus_MembersError(t *testing.T) {
	fake := &fakeClusterControl{hasLeader: true, leaderID: 1, membersErr: errors.New("boom")}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	_, err := runClusterCmd(t, "cluster", "status")
	if !errors.Is(err, ErrClusterMembersFailed) {
		t.Fatalf("expected ErrClusterMembersFailed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// cluster members
// ---------------------------------------------------------------------------

// TestClusterMembers_Table verifies the table rendering.
func TestClusterMembers_Table(t *testing.T) {
	fake := &fakeClusterControl{members: testClusterMembers()}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	out, err := runClusterCmdFormat(t, "table", "cluster", "members")
	if err != nil {
		t.Fatalf("cluster members: %v", err)
	}
	for _, want := range []string{"REPLICA ID", "RAFT ADDRESS", "10.0.0.2:63001", "grpc=10.0.0.1:9443"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if fake.gotShardID != defaultShardID {
		t.Errorf("shard ID = %d, want default %d", fake.gotShardID, defaultShardID)
	}
}

// TestClusterMembers_JSON verifies the JSON rendering round-trips.
func TestClusterMembers_JSON(t *testing.T) {
	fake := &fakeClusterControl{members: testClusterMembers()}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	out, err := runClusterCmdFormat(t, "json", "cluster", "members")
	if err != nil {
		t.Fatalf("cluster members: %v", err)
	}
	var payload struct {
		Members []struct {
			ReplicaID    uint64            `json:"replica_id"`
			Address      string            `json:"address"`
			IsLeader     bool              `json:"is_leader"`
			APIEndpoints map[string]string `json:"api_endpoints"`
		} `json:"members"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("invalid JSON output %q: %v", out, err)
	}
	if len(payload.Members) != 2 {
		t.Fatalf("members = %d, want 2", len(payload.Members))
	}
	if !payload.Members[0].IsLeader || payload.Members[0].ReplicaID != 1 {
		t.Errorf("unexpected first member: %+v", payload.Members[0])
	}
	if payload.Members[0].APIEndpoints["grpc"] != "10.0.0.1:9443" {
		t.Errorf("unexpected api endpoints: %+v", payload.Members[0].APIEndpoints)
	}
}

// TestClusterMembers_Error verifies the typed error path.
func TestClusterMembers_Error(t *testing.T) {
	fake := &fakeClusterControl{membersErr: errors.New("boom")}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	_, err := runClusterCmd(t, "cluster", "members")
	if !errors.Is(err, ErrClusterMembersFailed) {
		t.Fatalf("expected ErrClusterMembersFailed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// cluster add
// ---------------------------------------------------------------------------

// TestClusterAdd_Success verifies flag plumbing into AddReplica.
func TestClusterAdd_Success(t *testing.T) {
	fake := &fakeClusterControl{}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	out, err := runClusterCmd(t, "cluster", "add",
		"--shard", "3", "--replica-id", "9", "--raft-address", "10.0.0.9:63001")
	if err != nil {
		t.Fatalf("cluster add: %v", err)
	}
	if fake.gotShardID != 3 || fake.gotReplicaID != 9 || fake.gotRaftAddr != "10.0.0.9:63001" {
		t.Errorf("AddReplica got (%d, %d, %q), want (3, 9, 10.0.0.9:63001)",
			fake.gotShardID, fake.gotReplicaID, fake.gotRaftAddr)
	}
	if !strings.Contains(out, "replica 9") || !strings.Contains(out, "shard 3") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

// TestClusterAdd_MissingRequiredFlags verifies the required-flag guard.
func TestClusterAdd_MissingRequiredFlags(t *testing.T) {
	fake := &fakeClusterControl{}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	_, err := runClusterCmd(t, "cluster", "add", "--replica-id", "9")
	if err == nil || !strings.Contains(err.Error(), "raft-address") {
		t.Fatalf("expected missing --raft-address error, got %v", err)
	}
	if fake.gotReplicaID != 0 {
		t.Error("AddReplica must not be called when required flags are missing")
	}
}

// TestClusterAdd_Error verifies the typed error path.
func TestClusterAdd_Error(t *testing.T) {
	fake := &fakeClusterControl{addErr: errors.New("boom")}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	_, err := runClusterCmd(t, "cluster", "add",
		"--replica-id", "9", "--raft-address", "10.0.0.9:63001")
	if !errors.Is(err, ErrClusterAddReplicaFailed) {
		t.Fatalf("expected ErrClusterAddReplicaFailed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// cluster remove
// ---------------------------------------------------------------------------

// TestClusterRemove_Success verifies flag plumbing into RemoveReplica.
func TestClusterRemove_Success(t *testing.T) {
	fake := &fakeClusterControl{}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	out, err := runClusterCmd(t, "cluster", "remove", "--shard", "2", "--replica-id", "5")
	if err != nil {
		t.Fatalf("cluster remove: %v", err)
	}
	if fake.gotShardID != 2 || fake.gotReplicaID != 5 {
		t.Errorf("RemoveReplica got (%d, %d), want (2, 5)", fake.gotShardID, fake.gotReplicaID)
	}
	if !strings.Contains(out, "replica 5") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

// TestClusterRemove_MissingRequiredFlag verifies the required-flag guard.
func TestClusterRemove_MissingRequiredFlag(t *testing.T) {
	fake := &fakeClusterControl{}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	_, err := runClusterCmd(t, "cluster", "remove")
	if err == nil || !strings.Contains(err.Error(), "replica-id") {
		t.Fatalf("expected missing --replica-id error, got %v", err)
	}
}

// TestClusterRemove_Error verifies the typed error path.
func TestClusterRemove_Error(t *testing.T) {
	fake := &fakeClusterControl{removeErr: errors.New("boom")}
	installClusterControlFactory(t, &QRDBControlClient{Cluster: fake})

	_, err := runClusterCmd(t, "cluster", "remove", "--replica-id", "5")
	if !errors.Is(err, ErrClusterRemoveReplicaFailed) {
		t.Fatalf("expected ErrClusterRemoveReplicaFailed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Factory / transport derivation
// ---------------------------------------------------------------------------

// TestQRDBControlClient_MissingFactory verifies the guard when no factory
// is wired.
func TestQRDBControlClient_MissingFactory(t *testing.T) {
	restore := SetQRDBControlClientFactory(nil)
	t.Cleanup(restore)

	_, _, err := qrdbControlClient(context.Background())
	var missing *QRDBControlClientMissingError
	if !errors.As(err, &missing) {
		t.Fatalf("expected QRDBControlClientMissingError, got %v", err)
	}
}

// TestNewQRDBControlTransport_Derivation table-tests the target-to-transport
// mapping. Constructing a transport never dials, so these run in-process.
func TestNewQRDBControlTransport_Derivation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "default unix socket",
			cfg:  &Config{Protocol: "unix"},
		},
		{
			name: "empty protocol defaults to unix",
			cfg:  &Config{},
		},
		{
			name: "unix URL",
			cfg:  &Config{Server: "unix:///tmp/xkms-test.sock"},
		},
		{
			name: "grpc URL plaintext",
			cfg:  &Config{Server: "grpc://localhost:9443"},
		},
		{
			name: "grpcs URL with TLS material",
			cfg: &Config{
				Server:    "grpcs://localhost:9443",
				TLSCACert: "/tmp/ca.pem",
			},
		},
		{
			name: "bare address over grpc protocol",
			cfg:  &Config{Protocol: "grpc", Server: "localhost:9443"},
		},
		{
			name: "bare path over unix protocol",
			cfg:  &Config{Protocol: "unix", Server: "/tmp/xkms-test.sock"},
		},
		{
			name:    "grpcs URL without CA fails transport validation",
			cfg:     &Config{Server: "grpcs://localhost:9443"},
			wantErr: true,
		},
		{
			name:    "https scheme unsupported",
			cfg:     &Config{Server: "https://localhost:8443"},
			wantErr: true,
		},
		{
			name:    "rest protocol unsupported",
			cfg:     &Config{Protocol: "rest"},
			wantErr: true,
		},
		{
			name:    "quic protocol with bare address unsupported",
			cfg:     &Config{Protocol: "quic", Server: "localhost:8444"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := newQRDBControlTransport(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tr == nil {
				t.Fatal("expected transport, got nil")
			}
		})
	}
}

// TestNewQRDBControlTransport_UnsupportedSchemeErrorType verifies the
// unsupported-scheme failure is the typed error.
func TestNewQRDBControlTransport_UnsupportedSchemeErrorType(t *testing.T) {
	_, err := newQRDBControlTransport(&Config{Server: "quic://localhost:8444"})
	var unsupported *QRDBControlUnsupportedTransportError
	if !errors.As(err, &unsupported) {
		t.Fatalf("expected QRDBControlUnsupportedTransportError, got %v", err)
	}
	if !strings.Contains(unsupported.Error(), "quic://localhost:8444") {
		t.Errorf("error should name the rejected target: %v", unsupported)
	}
}

// TestClusterControlSeam_SDKConformance verifies the qrdb SDK cluster
// facade satisfies the ClusterControlClient seam (compile-time contract,
// asserted at runtime for regression clarity).
func TestClusterControlSeam_SDKConformance(t *testing.T) {
	var cc interface{} = (*qrdbsdk.ClusterClient)(nil)
	if _, ok := cc.(ClusterControlClient); !ok {
		t.Fatal("*qrdbsdk.ClusterClient must satisfy ClusterControlClient")
	}
}

// TestFormatAPIEndpoints_StableAndEmpty covers the endpoint formatter.
func TestFormatAPIEndpoints_StableAndEmpty(t *testing.T) {
	if got := formatAPIEndpoints(nil); got != "-" {
		t.Errorf("nil endpoints = %q, want \"-\"", got)
	}
	got := formatAPIEndpoints(map[qrdbsdk.APIProtocol]string{
		qrdbsdk.APIProtocolREST: "h:1",
		qrdbsdk.APIProtocolGRPC: "h:2",
	})
	if got != "grpc=h:2,rest=h:1" {
		t.Errorf("endpoints = %q, want sorted \"grpc=h:2,rest=h:1\"", got)
	}
}
