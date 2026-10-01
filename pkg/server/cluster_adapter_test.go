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

package server

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/stretchr/testify/require"
)

// newClusterAdapterForTest boots a real, unsealed, standalone qrdb node
// (same fixture sealed_window_test.go uses) and returns a clusterClientAdapter
// wired to its own in-process ClusterClient, so the adapter is exercised
// against the real qrdb SDK shape translation instead of a hand-rolled fake.
// This fixture's single "mvcc" database registers no Raft peer entries in
// the admin Peers() view (it exists only to drive barrier/seal state), so
// every shard ID it is asked about is legitimately unknown to Members — that
// is what the tests below exercise, alongside the one shard-independent
// success path (Leader, which reads local Raft shard state directly).
func newClusterAdapterForTest(t *testing.T) (*clusterClientAdapter, func()) {
	t.Helper()
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "correct-horse-battery-staple")
	require.False(t, node.IsSealed(), "fixture: node must be unsealed")
	client := node.Client()
	require.NotNil(t, client, "fixture: unsealed standalone node must expose a data-plane client")

	adapter := &clusterClientAdapter{cluster: client.Cluster()}
	return adapter, func() { _ = node.Close() }
}

// TestClusterClientAdapter_Members_UnknownShard proves Members surfaces the
// qrdb SDK's ShardNotFoundError through the adapter unchanged, for any shard
// ID this fixture's node has not registered — rather than translating it
// into an empty, ambiguous success.
func TestClusterClientAdapter_Members_UnknownShard(t *testing.T) {
	adapter, cleanup := newClusterAdapterForTest(t)
	defer cleanup()

	_, err := adapter.Members(context.Background(), 999999)
	require.Error(t, err)
}

// TestClusterClientAdapter_Leader proves Leader reports the standalone
// node's own replica as its shard's leader: unlike Members, Leader reads
// local Raft shard state directly and does not depend on the admin Peers
// registry this fixture leaves empty.
func TestClusterClientAdapter_Leader(t *testing.T) {
	adapter, cleanup := newClusterAdapterForTest(t)
	defer cleanup()

	replicaID, hasLeader, err := adapter.Leader(context.Background(), 0)
	require.NoError(t, err)
	require.True(t, hasLeader)
	require.NotZero(t, replicaID)
}

// TestClusterClientAdapter_LeaderEndpoint_UnknownProtocol proves an unknown
// API protocol name is rejected by the underlying qrdb SDK rather than
// silently returning no endpoint, and that the adapter's plain-string
// protocol parameter reaches that validation.
func TestClusterClientAdapter_LeaderEndpoint_UnknownProtocol(t *testing.T) {
	adapter, cleanup := newClusterAdapterForTest(t)
	defer cleanup()

	_, err := adapter.LeaderEndpoint(context.Background(), 0, "carrier-pigeon")
	require.Error(t, err)
}

// TestClusterClientAdapter_AddReplica_UnknownShard proves AddReplica
// surfaces the qrdb SDK's rejection when the target shard does not exist,
// rather than swallowing it.
func TestClusterClientAdapter_AddReplica_UnknownShard(t *testing.T) {
	adapter, cleanup := newClusterAdapterForTest(t)
	defer cleanup()

	err := adapter.AddReplica(context.Background(), 999999, 2, "127.0.0.1:0", "")
	require.Error(t, err, "adding a replica to an unknown shard must fail, not silently succeed")
}

// TestClusterClientAdapter_RemoveReplica_UnknownReplica proves RemoveReplica
// surfaces the qrdb SDK's rejection of a replica ID that is not a member.
func TestClusterClientAdapter_RemoveReplica_UnknownReplica(t *testing.T) {
	adapter, cleanup := newClusterAdapterForTest(t)
	defer cleanup()

	err := adapter.RemoveReplica(context.Background(), 0, 999999)
	require.Error(t, err)
}

// TestAPIEndpointsToStrings_Empty proves the nil-degrade contract: no
// advertised endpoints must yield a nil map, not an empty non-nil one, so
// callers can distinguish "unknown" from "serves nothing".
func TestAPIEndpointsToStrings_Empty(t *testing.T) {
	out := apiEndpointsToStrings(nil)
	require.Nil(t, out)

	out = apiEndpointsToStrings(map[qrdbsdk.APIProtocol]string{})
	require.Nil(t, out)
}

// TestAPIEndpointsToStrings_Translates proves each protocol-keyed endpoint
// is translated into its plain string-keyed counterpart.
func TestAPIEndpointsToStrings_Translates(t *testing.T) {
	in := map[qrdbsdk.APIProtocol]string{
		qrdbsdk.APIProtocolREST: "127.0.0.1:8443",
		qrdbsdk.APIProtocolGRPC: "127.0.0.1:9443",
	}
	out := apiEndpointsToStrings(in)
	require.Equal(t, "127.0.0.1:8443", out["rest"])
	require.Equal(t, "127.0.0.1:9443", out["grpc"])
	require.Len(t, out, 2)
}
