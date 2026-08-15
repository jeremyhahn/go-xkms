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
// can be wired via SetClusterClient to exercise the leader-endpoint
// resolution path without a live embedded qrdb node.
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
