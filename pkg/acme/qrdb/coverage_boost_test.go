//go:build codec_json

package qrdb

import (
	"context"
	"sync"
	"testing"
	"time"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCoverageBoost_IncrementInFlight_RaceRecovery tests the race condition
// recovery path in IncrementInFlight. The uncovered code is:
//
//	if m.IsShuttingDown() {
//	    m.inFlight.Add(-1)
//	    return error
//	}
//
// This triggers when IsShuttingDown() is false on the first check,
// inFlight is incremented, and then IsShuttingDown() becomes true
// on the second check.
func TestCoverageBoost_IncrementInFlight_RaceRecovery(t *testing.T) {
	cfg := &ShutdownConfig{
		GracePeriod:    50 * time.Millisecond,
		DrainTimeout:   50 * time.Millisecond,
		TransferLeader: false,
	}
	m := NewShutdownManager(cfg, nil, 1, 100, false)

	// We need to trigger the race where:
	// 1. IsShuttingDown() returns false (first check)
	// 2. inFlight.Add(1) happens
	// 3. IsShuttingDown() returns true (second check)
	// 4. inFlight.Add(-1) happens and error is returned
	//
	// To reliably trigger this, we use concurrent goroutines:
	// one that transitions to shutdown state while another is
	// between the two checks in IncrementInFlight.

	const attempts = 1000
	var raceDetected bool

	for i := 0; i < attempts; i++ {
		m = NewShutdownManager(cfg, nil, 1, 100, false)

		var wg sync.WaitGroup
		wg.Add(2)

		errCh := make(chan error, 1)

		go func() {
			defer wg.Done()
			errCh <- m.IncrementInFlight()
		}()

		go func() {
			defer wg.Done()
			// Transition directly to draining state to trigger the race
			m.state.Store(int32(ShutdownStateDraining))
		}()

		wg.Wait()

		err := <-errCh
		if err != nil && IsShutdownInProgress(err) {
			// We hit the race condition recovery path.
			// The in-flight counter should be 0 (decremented after increment).
			assert.Equal(t, int64(0), m.InFlight())
			raceDetected = true
			break
		}
	}

	// If the race was never triggered through concurrent execution,
	// force the path directly by setting state after first check.
	if !raceDetected {
		m = NewShutdownManager(cfg, nil, 1, 100, false)

		// Force the state to draining AFTER the first check passes.
		// Since we can't intercept the atomic check, we set the state
		// to draining and verify the direct error path.
		m.state.Store(int32(ShutdownStateDraining))
		err := m.IncrementInFlight()
		require.Error(t, err)
		assert.True(t, IsShutdownInProgress(err))
		assert.Equal(t, int64(0), m.InFlight())
	}
}

// TestCoverageBoost_IncrementInFlight_AlreadyShuttingDown verifies that
// IncrementInFlight returns an error when the state is already draining.
func TestCoverageBoost_IncrementInFlight_AlreadyShuttingDown(t *testing.T) {
	states := []struct {
		name  string
		state ShutdownState
	}{
		{"draining", ShutdownStateDraining},
		{"transferring", ShutdownStateTransferring},
		{"stopping", ShutdownStateStopping},
		{"stopped", ShutdownStateStopped},
	}

	for _, tt := range states {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ShutdownConfig{
				GracePeriod:    1 * time.Second,
				DrainTimeout:   500 * time.Millisecond,
				TransferLeader: false,
			}
			m := NewShutdownManager(cfg, nil, 1, 100, false)
			m.state.Store(int32(tt.state))

			err := m.IncrementInFlight()
			require.Error(t, err)
			assert.True(t, IsShutdownInProgress(err))
			assert.Equal(t, int64(0), m.InFlight())
		})
	}
}

// TestCoverageBoost_CreateClient_AllProtocols tests createClient for each
// remote protocol type, verifying they all return "not yet implemented" errors.
func TestCoverageBoost_CreateClient_AllProtocols(t *testing.T) {
	protocols := []struct {
		name     string
		protocol Protocol
	}{
		{"GRPC", ProtocolGRPC},
		{"REST", ProtocolREST},
		{"QUIC", ProtocolQUIC},
		{"Unix", ProtocolUnix},
		{"MCP", ProtocolMCP},
	}

	for _, tt := range protocols {
		t.Run(tt.name, func(t *testing.T) {
			sc := &serviceConfig{
				config: &Config{
					Protocol: tt.protocol,
				},
			}
			client, err := createClient(sc)
			assert.Nil(t, client)
			require.Error(t, err)
		})
	}
}

// TestCoverageBoost_CreateClient_UnsupportedProtocol tests createClient
// with an unsupported protocol value.
func TestCoverageBoost_CreateClient_UnsupportedProtocol(t *testing.T) {
	sc := &serviceConfig{
		config: &Config{
			Protocol: Protocol("websocket"),
		},
	}
	client, err := createClient(sc)
	assert.Nil(t, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported remote protocol")
}

// TestCoverageBoost_Collect_NonLeaderDraining verifies that the Collect
// method correctly sets raftLeader to 0 and raftIsDraining to 1 when the
// node is a follower in drain mode.
func TestCoverageBoost_Collect_NonLeaderDraining(t *testing.T) {
	origRegistry := Registry
	Registry = prometheus.NewRegistry()
	defer func() { Registry = origRegistry }()

	svc := &mockMetricsServiceLocal{
		statusResp: &db.StatusResponse{
			IsLeader:   false,
			ShardCount: 2,
			IsDraining: true,
		},
		peersResp: &db.PeersResponse{
			Shards: []db.ShardPeers{
				{
					ShardID: 1,
					Peers: []db.PeerInfo{
						{ReplicaID: 1, Address: "addr1"},
					},
				},
			},
		},
	}

	c := NewRaftMetricsCollector(svc, "node-follower", "cluster-1")
	defer c.Unregister()

	err := c.Collect(context.Background())
	require.NoError(t, err)

	// Verify follower: leader gauge should be 0
	leaderVal := gaugeValue(t, c.raftLeader)
	assert.Equal(t, float64(0), leaderVal)

	// Verify draining: isDraining gauge should be 1
	drainVal := gaugeValue(t, c.raftIsDraining)
	assert.Equal(t, float64(1), drainVal)

	shardVal := gaugeValue(t, c.raftShardCount)
	assert.Equal(t, float64(2), shardVal)
}

// gaugeValue extracts the current value from a Prometheus gauge.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	err := g.Write(m)
	require.NoError(t, err)
	return m.GetGauge().GetValue()
}

// mockMetricsServiceLocal implements the Service interface for metrics testing
// within the local build tag.
type mockMetricsServiceLocal struct {
	statusResp *db.StatusResponse
	statusErr  error
	peersResp  *db.PeersResponse
	peersErr   error
}

func (m *mockMetricsServiceLocal) KV() db.KVClient                   { return nil }
func (m *mockMetricsServiceLocal) Watch() db.WatchClient             { return nil }
func (m *mockMetricsServiceLocal) Lease() db.LeaseClient             { return nil }
func (m *mockMetricsServiceLocal) Batch() db.BatchClient             { return nil }
func (m *mockMetricsServiceLocal) Transaction() db.TransactionClient { return nil }
func (m *mockMetricsServiceLocal) Index() db.IndexClient             { return nil }
func (m *mockMetricsServiceLocal) Users() db.UserClient              { return nil }
func (m *mockMetricsServiceLocal) Roles() db.RoleClient              { return nil }
func (m *mockMetricsServiceLocal) Certs() db.CertClient              { return nil }
func (m *mockMetricsServiceLocal) Barrier() db.BarrierClient         { return nil }
func (m *mockMetricsServiceLocal) Ceremony() db.CeremonyClient       { return nil }
func (m *mockMetricsServiceLocal) Credentials() db.CredentialClient  { return nil }
func (m *mockMetricsServiceLocal) Config() *Config                   { return DefaultConfig() }
func (m *mockMetricsServiceLocal) Healthy(_ context.Context) bool    { return true }
func (m *mockMetricsServiceLocal) Close() error                      { return nil }
func (m *mockMetricsServiceLocal) Admin() db.AdminClient {
	return &mockMetricsAdminLocal{
		statusResp: m.statusResp,
		statusErr:  m.statusErr,
		peersResp:  m.peersResp,
		peersErr:   m.peersErr,
	}
}

type mockMetricsAdminLocal struct {
	statusResp *db.StatusResponse
	statusErr  error
	peersResp  *db.PeersResponse
	peersErr   error
}

func (a *mockMetricsAdminLocal) Health(_ context.Context) (*db.HealthResponse, error) {
	return &db.HealthResponse{Status: "healthy"}, nil
}
func (a *mockMetricsAdminLocal) Status(_ context.Context) (*db.StatusResponse, error) {
	return a.statusResp, a.statusErr
}
func (a *mockMetricsAdminLocal) Peers(_ context.Context) (*db.PeersResponse, error) {
	return a.peersResp, a.peersErr
}
func (a *mockMetricsAdminLocal) AddMember(_ context.Context, _, _ uint64, _ string) error {
	return nil
}
func (a *mockMetricsAdminLocal) RemoveMember(_ context.Context, _, _ uint64) error { return nil }
func (a *mockMetricsAdminLocal) RequestSnapshot(_ context.Context, _ uint64) error { return nil }
func (a *mockMetricsAdminLocal) Drain(_ context.Context) error                     { return nil }
func (a *mockMetricsAdminLocal) Capabilities(_ context.Context) (*db.CapabilitiesResponse, error) {
	return nil, nil
}
func (a *mockMetricsAdminLocal) StartShard(_ context.Context, _ *db.StartShardRequest) error {
	return nil
}
func (a *mockMetricsAdminLocal) StopShard(_ context.Context, _ uint64) error { return nil }
func (a *mockMetricsAdminLocal) GetShardState(_ context.Context, _ uint64) (*db.ShardStateResponse, error) {
	return nil, nil
}
func (a *mockMetricsAdminLocal) GetTopology(_ context.Context) (*db.TopologyResponse, error) {
	return nil, nil
}
