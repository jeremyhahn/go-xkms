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

// cluster_run_test.go closes the remaining gaps in cluster.go: the
// clusterStatus/clusterMembers RPC-error branches and the clusterStatusCmd /
// clusterMembersCmd Run closures.
package main

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func TestClusterStatus_ClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		clusterStatus(getConfig(), NewPrinter("text", nil))
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestClusterStatus_RPCError(t *testing.T) {
	mock := &mockClusterClient{statusErr: errTenantRunBoom}
	cfg := newTestClusterConfig(mock)
	code := captureExit(t, func() {
		clusterStatus(cfg, NewPrinter("text", nil))
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestClusterMembers_ClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		clusterMembers(getConfig(), NewPrinter("text", nil))
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestClusterMembers_RPCError(t *testing.T) {
	mock := &mockClusterClient{membersErr: errTenantRunBoom}
	cfg := newTestClusterConfig(mock)
	code := captureExit(t, func() {
		clusterMembers(cfg, NewPrinter("text", nil))
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestClusterStatusCmd_Run(t *testing.T) {
	mock := &mockClusterClient{statusResp: &transport.ClusterStatusResponse{
		Status: transport.ClusterStatusInfo{ShardID: 1, NodeID: 1, Clustered: false},
	}}
	withGlobalConfig(t, newTestClusterConfig(mock))

	captureStdout(t, func() {
		clusterStatusCmd.Run(clusterStatusCmd, nil)
	})
}

func TestClusterMembersCmd_Run(t *testing.T) {
	mock := &mockClusterClient{membersResp: &transport.ListClusterMembersResponse{
		Members: []transport.ClusterMemberInfo{{NodeID: 1, Address: "10.0.0.1:9000"}},
	}}
	withGlobalConfig(t, newTestClusterConfig(mock))

	captureStdout(t, func() {
		clusterMembersCmd.Run(clusterMembersCmd, nil)
	})
}
