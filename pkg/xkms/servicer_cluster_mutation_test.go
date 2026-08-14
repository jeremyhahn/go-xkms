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

package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// addReplicaCall records the exact arguments AddReplica was invoked with.
type addReplicaCall struct {
	shardID   uint64
	replicaID uint64
	raftAddr  string
}

// removeReplicaCall records the exact arguments RemoveReplica was invoked
// with.
type removeReplicaCall struct {
	shardID   uint64
	replicaID uint64
}

// leaderEndpointCall records the exact arguments LeaderEndpoint was invoked
// with.
type leaderEndpointCall struct {
	shardID  uint64
	protocol string
}

// fakeClusterClient is a test double satisfying the full ClusterClient
// contract (ClusterReader + ClusterEndpointResolver + ClusterMutator), so it
// can be wired via SetClusterClient to exercise the membership-mutation and
// leader-endpoint paths without a live embedded qrdb node.
type fakeClusterClient struct {
	members    []ClusterMember
	membersErr error

	leaderID  uint64
	hasLeader bool
	leaderErr error

	leaderEndpoint      string
	leaderEndpointErr   error
	leaderEndpointCalls []leaderEndpointCall

	addErr   error
	addCalls []addReplicaCall

	removeErr   error
	removeCalls []removeReplicaCall
}

func (f *fakeClusterClient) Members(_ context.Context, _ uint64) ([]ClusterMember, error) {
	if f.membersErr != nil {
		return nil, f.membersErr
	}
	return f.members, nil
}

func (f *fakeClusterClient) Leader(_ context.Context, _ uint64) (uint64, bool, error) {
	if f.leaderErr != nil {
		return 0, false, f.leaderErr
	}
	return f.leaderID, f.hasLeader, nil
}

func (f *fakeClusterClient) LeaderEndpoint(_ context.Context, shardID uint64, protocol string) (string, error) {
	f.leaderEndpointCalls = append(f.leaderEndpointCalls, leaderEndpointCall{shardID: shardID, protocol: protocol})
	if f.leaderEndpointErr != nil {
		return "", f.leaderEndpointErr
	}
	return f.leaderEndpoint, nil
}

func (f *fakeClusterClient) AddReplica(_ context.Context, shardID, replicaID uint64, raftAddr string) error {
	f.addCalls = append(f.addCalls, addReplicaCall{shardID: shardID, replicaID: replicaID, raftAddr: raftAddr})
	return f.addErr
}

func (f *fakeClusterClient) RemoveReplica(_ context.Context, shardID, replicaID uint64) error {
	f.removeCalls = append(f.removeCalls, removeReplicaCall{shardID: shardID, replicaID: replicaID})
	return f.removeErr
}

func TestAddClusterReplica_Success(t *testing.T) {
	fake := &fakeClusterClient{}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 3, 1)

	err := svc.AddClusterReplica(context.Background(), 5, "10.0.0.2:63001")
	require.NoError(t, err)

	require.Len(t, fake.addCalls, 1)
	assert.Equal(t, uint64(3), fake.addCalls[0].shardID, "must add on the configured shard")
	assert.Equal(t, uint64(5), fake.addCalls[0].replicaID)
	assert.Equal(t, "10.0.0.2:63001", fake.addCalls[0].raftAddr)
}

func TestAddClusterReplica_Standalone(t *testing.T) {
	svc := &XKMSService{}
	svc.SetClusterClient(nil, 1, 1)

	err := svc.AddClusterReplica(context.Background(), 5, "10.0.0.2:63001")
	require.Error(t, err)

	var notClustered *ClusterNotClusteredError
	require.True(t, errors.As(err, &notClustered))
	assert.Equal(t, "add_replica", notClustered.Operation)
}

func TestAddClusterReplica_ReplicaIDZero(t *testing.T) {
	fake := &fakeClusterClient{}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 1, 1)

	err := svc.AddClusterReplica(context.Background(), 0, "10.0.0.2:63001")
	require.Error(t, err)

	var invalid *ClusterReplicaInvalidError
	require.True(t, errors.As(err, &invalid))
	assert.Equal(t, uint64(0), invalid.ReplicaID)
	assert.Empty(t, fake.addCalls, "an invalid replica id must never reach the cluster client")
}

func TestAddClusterReplica_InvalidRaftAddress(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"empty", ""},
		{"no port", "no-port"},
		{"empty port", "host:"},
		{"empty host", ":9000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeClusterClient{}
			svc := &XKMSService{}
			svc.SetClusterClient(fake, 1, 1)

			err := svc.AddClusterReplica(context.Background(), 5, tt.addr)
			require.Error(t, err)

			var invalid *ClusterReplicaInvalidError
			require.True(t, errors.As(err, &invalid))
			assert.Equal(t, uint64(5), invalid.ReplicaID)
			assert.Empty(t, fake.addCalls, "an invalid raft address must never reach the cluster client")
		})
	}
}

func TestAddClusterReplica_ValidRaftAddresses(t *testing.T) {
	addrs := []string{"10.0.0.2:63001", "[fe80::1]:63001", "node.internal:63001"}
	for _, addr := range addrs {
		t.Run(addr, func(t *testing.T) {
			fake := &fakeClusterClient{}
			svc := &XKMSService{}
			svc.SetClusterClient(fake, 1, 1)

			err := svc.AddClusterReplica(context.Background(), 5, addr)
			require.NoError(t, err)

			require.Len(t, fake.addCalls, 1)
			assert.Equal(t, addr, fake.addCalls[0].raftAddr)
		})
	}
}

func TestAddClusterReplica_UnderlyingFailure(t *testing.T) {
	sentinel := errors.New("raft join rejected")
	fake := &fakeClusterClient{addErr: sentinel}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 4, 1)

	err := svc.AddClusterReplica(context.Background(), 9, "10.0.0.9:63001")
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)

	var addErr *ClusterAddReplicaError
	require.True(t, errors.As(err, &addErr))
	assert.Equal(t, uint64(4), addErr.ShardID)
	assert.Equal(t, uint64(9), addErr.ReplicaID)
}

func TestAddClusterReplica_Idempotent(t *testing.T) {
	fake := &fakeClusterClient{}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 1, 1)

	require.NoError(t, svc.AddClusterReplica(context.Background(), 5, "10.0.0.2:63001"))
	require.NoError(t, svc.AddClusterReplica(context.Background(), 5, "10.0.0.2:63001"))
	assert.Len(t, fake.addCalls, 2, "the servicer must not itself deduplicate; idempotency is the underlying qrdb AddMember's contract")
}

func TestRemoveClusterReplica_Success(t *testing.T) {
	fake := &fakeClusterClient{}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 3, 1)

	err := svc.RemoveClusterReplica(context.Background(), 5)
	require.NoError(t, err)

	require.Len(t, fake.removeCalls, 1)
	assert.Equal(t, uint64(3), fake.removeCalls[0].shardID, "must remove on the configured shard")
	assert.Equal(t, uint64(5), fake.removeCalls[0].replicaID)
}

func TestRemoveClusterReplica_Standalone(t *testing.T) {
	svc := &XKMSService{}
	svc.SetClusterClient(nil, 1, 1)

	err := svc.RemoveClusterReplica(context.Background(), 5)
	require.Error(t, err)

	var notClustered *ClusterNotClusteredError
	require.True(t, errors.As(err, &notClustered))
	assert.Equal(t, "remove_replica", notClustered.Operation)
}

func TestRemoveClusterReplica_ReplicaIDZero(t *testing.T) {
	fake := &fakeClusterClient{}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 1, 1)

	err := svc.RemoveClusterReplica(context.Background(), 0)
	require.Error(t, err)

	var invalid *ClusterReplicaInvalidError
	require.True(t, errors.As(err, &invalid))
	assert.Equal(t, uint64(0), invalid.ReplicaID)
	assert.Empty(t, fake.removeCalls, "an invalid replica id must never reach the cluster client")
}

func TestRemoveClusterReplica_UnderlyingFailure(t *testing.T) {
	sentinel := errors.New("raft removal rejected")
	fake := &fakeClusterClient{removeErr: sentinel}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 4, 1)

	err := svc.RemoveClusterReplica(context.Background(), 9)
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)

	var removeErr *ClusterRemoveReplicaError
	require.True(t, errors.As(err, &removeErr))
	assert.Equal(t, uint64(4), removeErr.ShardID)
	assert.Equal(t, uint64(9), removeErr.ReplicaID)
}

func TestRemoveClusterReplica_Idempotent(t *testing.T) {
	fake := &fakeClusterClient{}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 1, 1)

	require.NoError(t, svc.RemoveClusterReplica(context.Background(), 5))
	require.NoError(t, svc.RemoveClusterReplica(context.Background(), 5))
	assert.Len(t, fake.removeCalls, 2, "the servicer must not itself deduplicate; idempotency is the underlying qrdb RemoveMember's contract")
}

func TestClusterLeaderEndpoint_Success(t *testing.T) {
	fake := &fakeClusterClient{leaderEndpoint: "10.0.0.5:8443"}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 2, 1)

	addr, err := svc.ClusterLeaderEndpoint(context.Background(), "rest")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.5:8443", addr)

	require.Len(t, fake.leaderEndpointCalls, 1)
	assert.Equal(t, uint64(2), fake.leaderEndpointCalls[0].shardID)
	assert.Equal(t, "rest", fake.leaderEndpointCalls[0].protocol)
}

func TestClusterLeaderEndpoint_Standalone(t *testing.T) {
	svc := &XKMSService{}
	svc.SetClusterClient(nil, 1, 1)

	addr, err := svc.ClusterLeaderEndpoint(context.Background(), "rest")
	require.NoError(t, err, "a standalone node degrades to no endpoint rather than erroring")
	assert.Empty(t, addr)
}

func TestClusterLeaderEndpoint_UnderlyingError(t *testing.T) {
	sentinel := errors.New("registry unreachable")
	fake := &fakeClusterClient{leaderEndpointErr: sentinel}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 2, 1)

	addr, err := svc.ClusterLeaderEndpoint(context.Background(), "grpc")
	require.Error(t, err)
	assert.Empty(t, addr)
	assert.ErrorIs(t, err, sentinel)

	var epErr *ClusterLeaderEndpointError
	require.True(t, errors.As(err, &epErr))
	assert.Equal(t, "grpc", epErr.Protocol)
	assert.Equal(t, uint64(2), epErr.ShardID)
}

func TestClusterLeaderEndpoint_LeaderAdvertisesNothing(t *testing.T) {
	fake := &fakeClusterClient{leaderEndpoint: ""}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 1, 1)

	addr, err := svc.ClusterLeaderEndpoint(context.Background(), "rest")
	require.NoError(t, err)
	assert.Empty(t, addr)
}

func TestClusterMembers_APIEndpointsFlowThrough(t *testing.T) {
	fake := &fakeClusterClient{
		members: []ClusterMember{
			{
				ReplicaID: 1,
				Address:   "10.0.0.1:63001",
				APIEndpoints: map[string]string{
					"rest": "10.0.0.1:8443",
					"grpc": "10.0.0.1:9443",
				},
				IsLeader: true,
			},
			{
				ReplicaID:    2,
				Address:      "10.0.0.2:63001",
				APIEndpoints: nil,
				IsLeader:     false,
			},
		},
	}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 1, 1)

	members, err := svc.ClusterMembers(context.Background())
	require.NoError(t, err)
	require.Len(t, members, 2)

	assert.Equal(t, map[string]string{"rest": "10.0.0.1:8443", "grpc": "10.0.0.1:9443"}, members[0].APIEndpoints)
	assert.Nil(t, members[1].APIEndpoints, "a member advertising nothing must serialize as a nil map, not an empty one")
}

func TestErrNotLeader_Error(t *testing.T) {
	t.Run("with api address", func(t *testing.T) {
		e := &ErrNotLeader{
			ShardID:          3,
			LeaderID:         2,
			LeaderAddress:    "10.0.0.2:63001",
			LeaderAPIAddress: "10.0.0.2:8443",
		}
		msg := e.Error()
		assert.Contains(t, msg, "10.0.0.2:8443")
	})

	t.Run("without api address", func(t *testing.T) {
		e := &ErrNotLeader{
			ShardID:       3,
			LeaderID:      2,
			LeaderAddress: "10.0.0.2:63001",
		}
		msg := e.Error()
		assert.Contains(t, msg, "10.0.0.2:63001")
		assert.NotContains(t, msg, "api")
	})

	t.Run("leader unknown", func(t *testing.T) {
		e := &ErrNotLeader{ShardID: 3}
		msg := e.Error()
		assert.Contains(t, msg, "leader unknown")
	})
}
