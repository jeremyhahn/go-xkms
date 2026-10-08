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

// leaderEndpointCall records the exact arguments LeaderEndpoint was invoked
// with.
type leaderEndpointCall struct {
	shardID  uint64
	protocol string
}

// fakeClusterClient is a ClusterClient test double, wired via
// SetClusterClient to exercise the leader-endpoint resolution path without a
// live embedded qrdb node.
type fakeClusterClient struct {
	leaderEndpoint      string
	leaderEndpointErr   error
	leaderEndpointCalls []leaderEndpointCall
}

func (f *fakeClusterClient) LeaderEndpoint(_ context.Context, shardID uint64, protocol string) (string, error) {
	f.leaderEndpointCalls = append(f.leaderEndpointCalls, leaderEndpointCall{shardID: shardID, protocol: protocol})
	if f.leaderEndpointErr != nil {
		return "", f.leaderEndpointErr
	}
	return f.leaderEndpoint, nil
}

func TestClusterLeaderEndpoint_Success(t *testing.T) {
	fake := &fakeClusterClient{leaderEndpoint: "10.0.0.5:8443"}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 2)

	addr, err := svc.ClusterLeaderEndpoint(context.Background(), "rest")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.5:8443", addr)

	require.Len(t, fake.leaderEndpointCalls, 1)
	assert.Equal(t, uint64(2), fake.leaderEndpointCalls[0].shardID)
	assert.Equal(t, "rest", fake.leaderEndpointCalls[0].protocol)
}

func TestClusterLeaderEndpoint_Standalone(t *testing.T) {
	svc := &XKMSService{}
	svc.SetClusterClient(nil, 1)

	addr, err := svc.ClusterLeaderEndpoint(context.Background(), "rest")
	require.NoError(t, err, "a standalone node degrades to no endpoint rather than erroring")
	assert.Empty(t, addr)
}

func TestClusterLeaderEndpoint_UnderlyingError(t *testing.T) {
	sentinel := errors.New("registry unreachable")
	fake := &fakeClusterClient{leaderEndpointErr: sentinel}
	svc := &XKMSService{}
	svc.SetClusterClient(fake, 2)

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
	svc.SetClusterClient(fake, 1)

	addr, err := svc.ClusterLeaderEndpoint(context.Background(), "rest")
	require.NoError(t, err)
	assert.Empty(t, addr)
}

func TestXKMSService_Clustered(t *testing.T) {
	t.Run("clustered", func(t *testing.T) {
		svc := &XKMSService{}
		svc.SetClusterClient(&fakeClusterClient{}, 1)
		assert.True(t, svc.Clustered())
	})

	t.Run("standalone", func(t *testing.T) {
		svc := &XKMSService{}
		svc.SetClusterClient(nil, 1)
		assert.False(t, svc.Clustered())
	})
}
