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

package server

import (
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: startClusterAdvertiser is not exercised here. It calls
// s.qrdbClient.NewNodeAdvertiser and Start against a live embedded qrdb node
// and therefore belongs to an integration test, not this in-memory unit suite.

func TestAdvertisedAPIEndpoints_ExplicitHostWins(t *testing.T) {
	s := &Server{config: &config.Config{
		Server:    config.ServerConfig{RESTPort: 8443},
		Protocols: config.ProtocolsConfig{REST: true},
		Cluster: config.ClusterConfig{
			AdvertiseHost: "203.0.113.5",
			RaftAddress:   "10.0.0.1:63001",
		},
	}}

	endpoints, err := s.advertisedAPIEndpoints()
	require.NoError(t, err)
	require.NotNil(t, endpoints)
	assert.Equal(t, "203.0.113.5:8443", endpoints[qrdbsdk.APIProtocolREST])
}

func TestAdvertisedAPIEndpoints_FallsBackToRaftHost(t *testing.T) {
	s := &Server{config: &config.Config{
		Server:    config.ServerConfig{RESTPort: 8443},
		Protocols: config.ProtocolsConfig{REST: true},
		Cluster: config.ClusterConfig{
			RaftAddress: "10.0.0.1:63001",
		},
	}}

	endpoints, err := s.advertisedAPIEndpoints()
	require.NoError(t, err)
	require.NotNil(t, endpoints)
	assert.Equal(t, "10.0.0.1:8443", endpoints[qrdbsdk.APIProtocolREST],
		"an empty AdvertiseHost must fall back to the host portion of the raft address")
}

func TestAdvertisedAPIEndpoints_OnlyEnabledProtocols(t *testing.T) {
	s := &Server{config: &config.Config{
		Server: config.ServerConfig{
			RESTPort: 8443,
			GRPCPort: 9443,
			QUICPort: 7443,
			MCPPort:  6443,
		},
		Protocols: config.ProtocolsConfig{REST: true, GRPC: true, QUIC: false, MCP: false},
		Cluster:   config.ClusterConfig{AdvertiseHost: "10.0.0.1"},
	}}

	endpoints, err := s.advertisedAPIEndpoints()
	require.NoError(t, err)
	require.Len(t, endpoints, 2)
	assert.Contains(t, endpoints, qrdbsdk.APIProtocolREST)
	assert.Contains(t, endpoints, qrdbsdk.APIProtocolGRPC)
	assert.NotContains(t, endpoints, qrdbsdk.APIProtocolQUIC, "disabled protocols must be absent")
	assert.NotContains(t, endpoints, qrdbsdk.APIProtocolMCP, "disabled protocols must be absent")
}

func TestAdvertisedAPIEndpoints_EnabledProtocolPortZeroOmitted(t *testing.T) {
	s := &Server{config: &config.Config{
		Server:    config.ServerConfig{RESTPort: 0, GRPCPort: 9443},
		Protocols: config.ProtocolsConfig{REST: true, GRPC: true},
		Cluster:   config.ClusterConfig{AdvertiseHost: "10.0.0.1"},
	}}

	endpoints, err := s.advertisedAPIEndpoints()
	require.NoError(t, err)
	assert.NotContains(t, endpoints, qrdbsdk.APIProtocolREST,
		"an enabled protocol with port 0 has nothing dialable and must be omitted")
	assert.Contains(t, endpoints, qrdbsdk.APIProtocolGRPC)
}

func TestAdvertisedAPIEndpoints_AddressIsHostPort(t *testing.T) {
	s := &Server{config: &config.Config{
		Server:    config.ServerConfig{RESTPort: 8443},
		Protocols: config.ProtocolsConfig{REST: true},
		Cluster:   config.ClusterConfig{AdvertiseHost: "10.0.0.1"},
	}}

	endpoints, err := s.advertisedAPIEndpoints()
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1:8443", endpoints[qrdbsdk.APIProtocolREST])
}

func TestAdvertisedAPIEndpoints_IPv6HostBracketed(t *testing.T) {
	s := &Server{config: &config.Config{
		Server:    config.ServerConfig{RESTPort: 8443},
		Protocols: config.ProtocolsConfig{REST: true},
		Cluster:   config.ClusterConfig{AdvertiseHost: "fe80::1"},
	}}

	endpoints, err := s.advertisedAPIEndpoints()
	require.NoError(t, err)
	assert.Equal(t, "[fe80::1]:8443", endpoints[qrdbsdk.APIProtocolREST],
		"an IPv6 advertise host must be bracketed in the dialable address")
}

func TestAdvertisedAPIEndpoints_WildcardRaftHostNoAdvertiseHost(t *testing.T) {
	s := &Server{config: &config.Config{
		Server:    config.ServerConfig{RESTPort: 8443},
		Protocols: config.ProtocolsConfig{REST: true},
		Cluster:   config.ClusterConfig{RaftAddress: "0.0.0.0:63001"},
	}}

	endpoints, err := s.advertisedAPIEndpoints()
	require.NoError(t, err, "a wildcard bind host must degrade to no advertisement, not an error")
	assert.Nil(t, endpoints)
}

func TestAdvertisedAPIEndpoints_AllProtocolsDisabled(t *testing.T) {
	s := &Server{config: &config.Config{
		Server: config.ServerConfig{
			RESTPort: 8443,
			GRPCPort: 9443,
			QUICPort: 7443,
			MCPPort:  6443,
		},
		Cluster: config.ClusterConfig{AdvertiseHost: "10.0.0.1"},
	}}

	endpoints, err := s.advertisedAPIEndpoints()
	require.NoError(t, err)
	assert.Nil(t, endpoints)
}

func TestAdvertisedAPIEndpoints_UnixNeverAdvertised(t *testing.T) {
	s := &Server{config: &config.Config{
		Server:    config.ServerConfig{RESTPort: 8443},
		Protocols: config.ProtocolsConfig{REST: true, Unix: true},
		Cluster:   config.ClusterConfig{AdvertiseHost: "10.0.0.1"},
	}}

	endpoints, err := s.advertisedAPIEndpoints()
	require.NoError(t, err)
	require.Len(t, endpoints, 1, "only rest is enabled; unix must never contribute a key regardless of Protocols.Unix")
	_, hasUnix := endpoints[qrdbsdk.APIProtocol("unix")]
	assert.False(t, hasUnix, "the unix socket must never be advertised into the cluster registry")
}

func TestStopClusterAdvertiser_NilIsIdempotent(t *testing.T) {
	s := &Server{}

	require.NoError(t, s.stopClusterAdvertiser())
	require.NoError(t, s.stopClusterAdvertiser())
}
