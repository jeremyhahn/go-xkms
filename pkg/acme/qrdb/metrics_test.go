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

package qrdb

import (
	"context"
	"testing"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRaftMetricsCollector(t *testing.T) {
	t.Run("creates and registers metrics", func(t *testing.T) {
		// Use a fresh registry to avoid conflicts between tests.
		origRegistry := Registry
		Registry = prometheus.NewRegistry()
		defer func() { Registry = origRegistry }()

		svc := &mockMetricsService{}
		c := NewRaftMetricsCollector(svc, "node-1", "cluster-1")
		require.NotNil(t, c)
		assert.Equal(t, "node-1", c.nodeID)
		assert.Equal(t, "cluster-1", c.clusterID)

		// Verify metrics are registered by gathering.
		families, err := Registry.Gather()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(families), 5)

		c.Unregister()
	})

	t.Run("unregister removes metrics", func(t *testing.T) {
		origRegistry := Registry
		Registry = prometheus.NewRegistry()
		defer func() { Registry = origRegistry }()

		svc := &mockMetricsService{}
		c := NewRaftMetricsCollector(svc, "node-2", "cluster-2")
		c.Unregister()

		families, err := Registry.Gather()
		require.NoError(t, err)
		assert.Empty(t, families)
	})
}

func TestRaftMetricsCollectorCollect(t *testing.T) {
	t.Run("collects metrics from service", func(t *testing.T) {
		origRegistry := Registry
		Registry = prometheus.NewRegistry()
		defer func() { Registry = origRegistry }()

		svc := &mockMetricsService{
			statusResp: &db.StatusResponse{
				IsLeader:   true,
				ShardCount: 3,
				IsDraining: false,
			},
			peersResp: &db.PeersResponse{
				Shards: []db.ShardPeers{
					{
						ShardID: 1,
						Peers: []db.PeerInfo{
							{ReplicaID: 1, Address: "addr1"},
							{ReplicaID: 2, Address: "addr2"},
						},
					},
					{
						ShardID: 2,
						Peers: []db.PeerInfo{
							{ReplicaID: 3, Address: "addr3"},
						},
					},
				},
			},
		}

		c := NewRaftMetricsCollector(svc, "node-1", "cluster-1")
		defer c.Unregister()

		err := c.Collect(context.Background())
		require.NoError(t, err)

		// Verify leader gauge is set to 1.
		leaderVal := getGaugeValue(t, c.raftLeader)
		assert.Equal(t, float64(1), leaderVal)

		// Verify shard count.
		shardVal := getGaugeValue(t, c.raftShardCount)
		assert.Equal(t, float64(3), shardVal)

		// Verify not draining.
		drainVal := getGaugeValue(t, c.raftIsDraining)
		assert.Equal(t, float64(0), drainVal)

		// Verify peer count (2 + 1 = 3).
		peerVal := getGaugeValue(t, c.raftPeers)
		assert.Equal(t, float64(3), peerVal)
	})

	t.Run("status error returns internal error", func(t *testing.T) {
		origRegistry := Registry
		Registry = prometheus.NewRegistry()
		defer func() { Registry = origRegistry }()

		svc := &mockMetricsService{
			statusErr: NewError(ErrorCodeConnection, "connection lost"),
		}

		c := NewRaftMetricsCollector(svc, "node-1", "cluster-1")
		defer c.Unregister()

		err := c.Collect(context.Background())
		require.Error(t, err)
		assert.True(t, IsInternal(err))
	})

	t.Run("peers error returns internal error", func(t *testing.T) {
		origRegistry := Registry
		Registry = prometheus.NewRegistry()
		defer func() { Registry = origRegistry }()

		svc := &mockMetricsService{
			statusResp: &db.StatusResponse{},
			peersErr:   NewError(ErrorCodeConnection, "connection lost"),
		}

		c := NewRaftMetricsCollector(svc, "node-1", "cluster-1")
		defer c.Unregister()

		err := c.Collect(context.Background())
		require.Error(t, err)
		assert.True(t, IsInternal(err))
	})
}

// getGaugeValue extracts the current value from a Prometheus gauge.
func getGaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	err := g.Write(m)
	require.NoError(t, err)
	return m.GetGauge().GetValue()
}

// mockMetricsService implements the Service interface for metrics testing.
type mockMetricsService struct {
	statusResp *db.StatusResponse
	statusErr  error
	peersResp  *db.PeersResponse
	peersErr   error
}

func (m *mockMetricsService) KV() db.KVClient       { return nil }
func (m *mockMetricsService) Watch() db.WatchClient { return nil }
func (m *mockMetricsService) Lease() db.LeaseClient { return nil }
func (m *mockMetricsService) Batch() db.BatchClient { return nil }
func (m *mockMetricsService) Transaction() db.TransactionClient {
	return nil
}
func (m *mockMetricsService) Index() db.IndexClient            { return nil }
func (m *mockMetricsService) Users() db.UserClient             { return nil }
func (m *mockMetricsService) Roles() db.RoleClient             { return nil }
func (m *mockMetricsService) Certs() db.CertClient             { return nil }
func (m *mockMetricsService) Barrier() db.BarrierClient        { return nil }
func (m *mockMetricsService) Ceremony() db.CeremonyClient      { return nil }
func (m *mockMetricsService) Credentials() db.CredentialClient { return nil }
func (m *mockMetricsService) Config() *Config                  { return DefaultConfig() }
func (m *mockMetricsService) Healthy(_ context.Context) bool {
	return true
}
func (m *mockMetricsService) Close() error { return nil }
func (m *mockMetricsService) Admin() db.AdminClient {
	return &mockMetricsAdmin{
		statusResp: m.statusResp,
		statusErr:  m.statusErr,
		peersResp:  m.peersResp,
		peersErr:   m.peersErr,
	}
}

// mockMetricsAdmin implements AdminClient for metrics testing.
type mockMetricsAdmin struct {
	statusResp *db.StatusResponse
	statusErr  error
	peersResp  *db.PeersResponse
	peersErr   error
}

func (a *mockMetricsAdmin) Health(_ context.Context) (*db.HealthResponse, error) {
	return &db.HealthResponse{Status: "healthy"}, nil
}
func (a *mockMetricsAdmin) Status(_ context.Context) (*db.StatusResponse, error) {
	return a.statusResp, a.statusErr
}
func (a *mockMetricsAdmin) Peers(_ context.Context) (*db.PeersResponse, error) {
	return a.peersResp, a.peersErr
}
func (a *mockMetricsAdmin) AddMember(_ context.Context, _, _ uint64, _, _ string) error {
	return nil
}
func (a *mockMetricsAdmin) RemoveMember(_ context.Context, _, _ uint64) error {
	return nil
}
func (a *mockMetricsAdmin) RequestSnapshot(_ context.Context, _ uint64) error {
	return nil
}
func (a *mockMetricsAdmin) Drain(_ context.Context) error { return nil }
func (a *mockMetricsAdmin) Capabilities(_ context.Context) (*db.CapabilitiesResponse, error) {
	return nil, nil
}
func (a *mockMetricsAdmin) StartShard(_ context.Context, _ *db.StartShardRequest) error {
	return nil
}
func (a *mockMetricsAdmin) StopShard(_ context.Context, _ uint64) error { return nil }
func (a *mockMetricsAdmin) GetShardState(_ context.Context, _ uint64) (*db.ShardStateResponse, error) {
	return nil, nil
}
func (a *mockMetricsAdmin) GetTopology(_ context.Context) (*db.TopologyResponse, error) {
	return nil, nil
}
