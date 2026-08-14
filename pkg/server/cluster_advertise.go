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
	"fmt"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ClusterAdvertiseError is returned when this node's client-facing API
// endpoints cannot be published into the cluster registry.
type ClusterAdvertiseError struct {
	// Stage names the step that failed.
	Stage string

	// Err is the underlying cause.
	Err error
}

func (e *ClusterAdvertiseError) Error() string {
	return fmt.Sprintf("server: cluster advertise: %s: %v", e.Stage, e.Err)
}

func (e *ClusterAdvertiseError) Unwrap() error { return e.Err }

// advertisedAPIEndpoints builds the client-facing endpoint map this node
// publishes into the cluster registry.
//
// Every value comes from this node's own configuration: the advertise host
// (explicit, else the host portion of the Raft address peers already use to
// reach us) plus the configured port of each protocol that is actually enabled.
// A disabled protocol is omitted, which is how this node states that it does
// not serve it. Addresses are never derived from the Raft address by port
// arithmetic — that breaks under NAT, split networking and non-default ports.
//
// The unix socket is deliberately not advertised: a socket path is meaningful
// only on the node that owns it, so publishing one cluster-wide would hand
// peers an address they cannot dial.
//
// A wildcard bind host with no explicit advertise host yields a nil map: the
// node publishes nothing rather than an address no client can dial, and
// consumers degrade to the leader hint alone.
func (s *Server) advertisedAPIEndpoints() (map[qrdbsdk.APIProtocol]string, error) {
	host := s.config.Cluster.AdvertiseHost
	if host == "" {
		host = qrdbsdk.HostFromAddress(s.config.Cluster.RaftAddress)
	}

	ports := make(map[qrdbsdk.APIProtocol]int, len(qrdbsdk.APIProtocols))
	if s.config.Protocols.REST {
		ports[qrdbsdk.APIProtocolREST] = s.config.Server.RESTPort
	}
	if s.config.Protocols.GRPC {
		ports[qrdbsdk.APIProtocolGRPC] = s.config.Server.GRPCPort
	}
	if s.config.Protocols.QUIC {
		ports[qrdbsdk.APIProtocolQUIC] = s.config.Server.QUICPort
	}
	if s.config.Protocols.MCP {
		ports[qrdbsdk.APIProtocolMCP] = s.config.Server.MCPPort
	}

	return qrdbsdk.BuildAPIEndpoints(host, ports)
}

// startClusterAdvertiser publishes this node's Raft address and client-facing
// API endpoints into the cluster registry and keeps the registration's lease
// alive, so any peer can turn "the leader is replica N" into an address a
// client can actually dial.
//
// xkms advertises its OWN API ports rather than the embedded qrdb node's: the
// process a client talks to is xkms, so xkms's endpoints are the reachable
// ones. There is exactly one advertiser per node process, so the registry entry
// for a replica ID is unambiguous.
//
// It is a no-op on a standalone node: a single node is always its own leader,
// so there is never another replica to redirect a client to.
//
// Advertisement failing must not prevent the node from serving. When it fails,
// or when the node has no advertisable host, peers simply see no endpoint for
// this replica and fall back to the pre-advertisement behavior.
func (s *Server) startClusterAdvertiser() error {
	if !s.config.Cluster.Enabled || s.qrdbClient == nil {
		return nil
	}

	endpoints, err := s.advertisedAPIEndpoints()
	if err != nil {
		return &ClusterAdvertiseError{Stage: "build api endpoints", Err: err}
	}
	if len(endpoints) == 0 {
		s.logger.Warn("cluster: advertising no API endpoints for this node; "+
			"clients cannot be redirected to it when it leads",
			"node_id", s.config.Cluster.NodeID,
			"advertise_host", s.config.Cluster.AdvertiseHost,
			"raft_address", s.config.Cluster.RaftAddress)
		return nil
	}

	advertiser, err := s.qrdbClient.NewNodeAdvertiser(
		qrdbsdk.ClusterNode{
			NodeID:       s.config.Cluster.NodeID,
			Address:      s.config.Cluster.RaftAddress,
			APIEndpoints: endpoints,
		},
		qrdbsdk.AdvertiseConfig{},
		qrdbsdk.WithAdvertiseLogger(s.logger),
	)
	if err != nil {
		return &ClusterAdvertiseError{Stage: "new node advertiser", Err: err}
	}

	if err := advertiser.Start(s.ctx); err != nil {
		return &ClusterAdvertiseError{Stage: "start node advertiser", Err: err}
	}

	s.clusterAdvertiser = advertiser
	s.logger.Info("cluster: advertised this node's API endpoints",
		"node_id", s.config.Cluster.NodeID,
		"raft_address", s.config.Cluster.RaftAddress,
		"endpoints", len(endpoints))
	return nil
}

// stopClusterAdvertiser stops the lease refresh loop and removes this node's
// registration so peers stop redirecting clients to an address that is going
// away. It is idempotent and safe on a node that never advertised.
func (s *Server) stopClusterAdvertiser() error {
	advertiser := s.clusterAdvertiser
	if advertiser == nil {
		return nil
	}
	s.clusterAdvertiser = nil

	if err := advertiser.Close(); err != nil {
		return &ClusterAdvertiseError{Stage: "close node advertiser", Err: err}
	}
	return nil
}
