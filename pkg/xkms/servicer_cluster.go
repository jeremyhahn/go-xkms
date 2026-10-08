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
)

// ClusterClient is the one piece of the embedded go-qrdb node's cluster client
// the servicer depends on: resolving the leader's dialable API address for a
// protocol, which is what makes a not-leader redirect actionable. The qrdb sdk
// *ClusterClient satisfies it, bridged by the server-side adapter; tests
// provide a fake.
//
// Cluster status, membership and Raft membership changes are go-qrdb's own
// control plane (its AdminService, registered on xkmsd by
// pkg/server/qrdb_control_plane.go); xkms neither reads nor proxies them.
type ClusterClient interface {
	// LeaderEndpoint returns the address to dial to reach the shard leader over
	// the named API protocol.
	LeaderEndpoint(ctx context.Context, shardID uint64, protocol string) (string, error)
}

// ClusterLeaderEndpoint returns the address a client should dial to reach the
// shard leader over the named API protocol, as published by the leader itself
// into the cluster registry.
//
// It returns an empty address and no error on a standalone node: there is no
// other replica to redirect to, which callers treat the same as "unknown".
// A resolution failure is returned as a *ClusterLeaderEndpointError so a caller
// can distinguish it from "no endpoint advertised", but no caller is required
// to fail because of it.
func (s *XKMSService) ClusterLeaderEndpoint(ctx context.Context, protocol string) (string, error) {
	if s.cluster == nil {
		return "", nil
	}

	addr, err := s.cluster.LeaderEndpoint(ctx, s.clusterShardID, protocol)
	if err != nil {
		return "", &ClusterLeaderEndpointError{
			ShardID:  s.clusterShardID,
			Protocol: protocol,
			Err:      err,
		}
	}
	return addr, nil
}
