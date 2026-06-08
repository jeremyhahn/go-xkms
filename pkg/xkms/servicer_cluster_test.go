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

// fakeClusterReader is a test double for the embedded qrdb cluster client.
type fakeClusterReader struct {
	members    []ClusterMember
	leaderID   uint64
	hasLeader  bool
	membersErr error
	leaderErr  error

	gotShardID uint64
}

func (f *fakeClusterReader) Members(_ context.Context, shardID uint64) ([]ClusterMember, error) {
	f.gotShardID = shardID
	if f.membersErr != nil {
		return nil, f.membersErr
	}
	return f.members, nil
}

func (f *fakeClusterReader) Leader(_ context.Context, shardID uint64) (uint64, bool, error) {
	f.gotShardID = shardID
	if f.leaderErr != nil {
		return 0, false, f.leaderErr
	}
	return f.leaderID, f.hasLeader, nil
}

func TestClusterStatus_Standalone(t *testing.T) {
	svc := &XKMSService{}
	svc.SetClusterClient(nil, 1, 7)

	status, err := svc.ClusterStatus(context.Background())
	require.NoError(t, err)
	assert.False(t, status.Clustered)
	assert.Equal(t, uint64(1), status.ShardID)
	assert.Equal(t, uint64(7), status.NodeID)
	assert.Equal(t, uint64(7), status.LeaderID, "standalone node is its own leader")
	assert.True(t, status.HasLeader)
}

func TestClusterStatus_Clustered(t *testing.T) {
	reader := &fakeClusterReader{leaderID: 2, hasLeader: true}
	svc := &XKMSService{}
	svc.SetClusterClient(reader, 3, 1)

	status, err := svc.ClusterStatus(context.Background())
	require.NoError(t, err)
	assert.True(t, status.Clustered)
	assert.Equal(t, uint64(3), status.ShardID)
	assert.Equal(t, uint64(3), reader.gotShardID, "servicer reports on its configured shard")
	assert.Equal(t, uint64(1), status.NodeID)
	assert.Equal(t, uint64(2), status.LeaderID)
	assert.True(t, status.HasLeader)
}

func TestClusterStatus_NoLeader(t *testing.T) {
	reader := &fakeClusterReader{hasLeader: false}
	svc := &XKMSService{}
	svc.SetClusterClient(reader, 1, 1)

	status, err := svc.ClusterStatus(context.Background())
	require.NoError(t, err)
	assert.True(t, status.Clustered)
	assert.False(t, status.HasLeader)
	assert.Equal(t, uint64(0), status.LeaderID)
}

func TestClusterStatus_ReaderError(t *testing.T) {
	sentinel := errors.New("raft unreachable")
	reader := &fakeClusterReader{leaderErr: sentinel}
	svc := &XKMSService{}
	svc.SetClusterClient(reader, 1, 1)

	_, err := svc.ClusterStatus(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)

	var statusErr *ClusterStatusError
	require.True(t, errors.As(err, &statusErr))
	assert.Equal(t, uint64(1), statusErr.ShardID)
}

func TestClusterMembers_Standalone(t *testing.T) {
	svc := &XKMSService{}
	svc.SetClusterClient(nil, 1, 1)

	members, err := svc.ClusterMembers(context.Background())
	require.NoError(t, err)
	assert.Empty(t, members)
	assert.NotNil(t, members, "standalone returns an empty, non-nil set")
}

func TestClusterMembers_Clustered(t *testing.T) {
	reader := &fakeClusterReader{
		members: []ClusterMember{
			{ReplicaID: 1, Address: "10.0.0.1:63001", IsLeader: true},
			{ReplicaID: 2, Address: "10.0.0.2:63001", IsLeader: false},
		},
	}
	svc := &XKMSService{}
	svc.SetClusterClient(reader, 5, 1)

	members, err := svc.ClusterMembers(context.Background())
	require.NoError(t, err)
	require.Len(t, members, 2)
	assert.Equal(t, uint64(5), reader.gotShardID)
	assert.Equal(t, uint64(1), members[0].NodeID)
	assert.Equal(t, "10.0.0.1:63001", members[0].Address)
	assert.True(t, members[0].IsLeader)
	assert.Equal(t, uint64(2), members[1].NodeID)
	assert.False(t, members[1].IsLeader)
}

func TestClusterMembers_ReaderError(t *testing.T) {
	sentinel := errors.New("raft unreachable")
	reader := &fakeClusterReader{membersErr: sentinel}
	svc := &XKMSService{}
	svc.SetClusterClient(reader, 2, 1)

	_, err := svc.ClusterMembers(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)

	var membersErr *ClusterMembersError
	require.True(t, errors.As(err, &membersErr))
	assert.Equal(t, uint64(2), membersErr.ShardID)
}
