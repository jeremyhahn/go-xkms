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

	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestAdvertisedAPIEndpoints_AllProtocols proves every enabled protocol
// contributes its configured port to the advertised endpoint map, not just
// REST and gRPC.
func TestAdvertisedAPIEndpoints_AllProtocols(t *testing.T) {
	cfg := &config.Config{
		Cluster: config.ClusterConfig{AdvertiseHost: "10.0.0.5"},
		Server: config.ServerConfig{
			RESTPort: 8443,
			GRPCPort: 9443,
			QUICPort: 8444,
			MCPPort:  9444,
		},
		Protocols: config.ProtocolsConfig{REST: true, GRPC: true, QUIC: true, MCP: true},
	}
	s := &Server{config: cfg, logger: custodyQuietLogger()}

	endpoints, err := s.advertisedAPIEndpoints()
	require.NoError(t, err)
	require.Equal(t, "10.0.0.5:8443", endpoints[qrdbsdk.APIProtocolREST])
	require.Equal(t, "10.0.0.5:9443", endpoints[qrdbsdk.APIProtocolGRPC])
	require.Equal(t, "10.0.0.5:8444", endpoints[qrdbsdk.APIProtocolQUIC])
	require.Equal(t, "10.0.0.5:9444", endpoints[qrdbsdk.APIProtocolMCP])
}

// newClusterAdvertiseTestServer builds a *Server wired to a real, in-process
// qrdb client (from the standalone node fixture) with clustering enabled, so
// startClusterAdvertiser/stopClusterAdvertiser exercise the real
// NewNodeAdvertiser/Start/Close path instead of a hand-rolled fake.
func newClusterAdvertiseTestServer(t *testing.T, cfg *config.Config) (*Server, func()) {
	t.Helper()
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "correct-horse-battery-staple")
	require.False(t, node.IsSealed())
	client := node.Client()
	require.NotNil(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		config:     cfg,
		logger:     custodyQuietLogger(),
		qrdbClient: client,
		ctx:        ctx,
		cancel:     cancel,
	}
	return s, func() { cancel(); _ = node.Close() }
}

// TestStartClusterAdvertiser_Disabled proves the no-op contract: clustering
// disabled must not touch the qrdb client at all, regardless of its state.
func TestStartClusterAdvertiser_Disabled(t *testing.T) {
	s := &Server{config: &config.Config{}, logger: custodyQuietLogger()}
	require.NoError(t, s.startClusterAdvertiser())
}

// TestStartClusterAdvertiser_NoAdvertisableHost proves a node with no
// advertisable host logs a warning and returns nil rather than an error,
// since advertisement failing must never block the node from serving.
func TestStartClusterAdvertiser_NoAdvertisableHost(t *testing.T) {
	cfg := &config.Config{Cluster: config.ClusterConfig{Enabled: true}}
	s, cleanup := newClusterAdvertiseTestServer(t, cfg)
	defer cleanup()

	require.NoError(t, s.startClusterAdvertiser())
	require.Nil(t, s.clusterAdvertiser)
}

// advertisableConfig is a clustered config with a real advertisable REST
// endpoint.
func advertisableConfig() *config.Config {
	return &config.Config{
		Cluster: config.ClusterConfig{
			Enabled:       true,
			NodeID:        1,
			RaftAddress:   "127.0.0.1:0",
			AdvertiseHost: "127.0.0.1",
		},
		Server:    config.ServerConfig{RESTPort: 18080},
		Protocols: config.ProtocolsConfig{REST: true},
	}
}

// TestStartClusterAdvertiser_RegistersOnALeaseServingNode proves a node with
// an advertisable endpoint registers it and keeps the advertiser, and that
// stopping removes it. Since go-qrdb v0.27 a standalone node serves leases,
// so this fixture's node can hold the advertisement lease.
func TestStartClusterAdvertiser_RegistersOnALeaseServingNode(t *testing.T) {
	s, cleanup := newClusterAdvertiseTestServer(t, advertisableConfig())
	defer cleanup()

	require.NoError(t, s.startClusterAdvertiser())
	require.NotNil(t, s.clusterAdvertiser)

	require.NoError(t, s.stopClusterAdvertiser())
	require.Nil(t, s.clusterAdvertiser)
	require.NoError(t, s.stopClusterAdvertiser(), "stopping twice is a no-op")
}

// TestStartClusterAdvertiser_StartFailureWraps proves an advertiser that
// cannot register -- here because the node behind its client is closed --
// surfaces as a *ClusterAdvertiseError naming the "start node advertiser"
// stage, rather than a bare or swallowed error, and leaves clusterAdvertiser
// unset.
func TestStartClusterAdvertiser_StartFailureWraps(t *testing.T) {
	s, cleanup := newClusterAdvertiseTestServer(t, advertisableConfig())
	cleanup()

	err := s.startClusterAdvertiser()
	require.Error(t, err)
	var advErr *ClusterAdvertiseError
	require.ErrorAs(t, err, &advErr)
	require.Equal(t, "start node advertiser", advErr.Stage)
	require.Nil(t, s.clusterAdvertiser)

	// Nothing was registered, so stopping is still a safe no-op.
	require.NoError(t, s.stopClusterAdvertiser())
}
