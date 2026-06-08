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
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// clusterReaderAdapter bridges the embedded go-qrdb node's *ClusterClient to
// the narrow xkms.ClusterReader contract the servicer depends on. It performs
// only the read translation between the qrdb Member shape and the xkms one;
// membership mutation is intentionally not bridged.
type clusterReaderAdapter struct {
	cluster *qrdbsdk.ClusterClient
}

// Members returns the shard membership translated into the xkms shape.
func (a *clusterReaderAdapter) Members(ctx context.Context, shardID uint64) ([]xkms.ClusterMember, error) {
	members, err := a.cluster.Members(ctx, shardID)
	if err != nil {
		return nil, err
	}
	out := make([]xkms.ClusterMember, len(members))
	for i, m := range members {
		out[i] = xkms.ClusterMember{
			ReplicaID: m.ReplicaID,
			Address:   m.Address,
			IsLeader:  m.IsLeader,
		}
	}
	return out, nil
}

// Leader reports the shard's current leader replica ID.
func (a *clusterReaderAdapter) Leader(ctx context.Context, shardID uint64) (uint64, bool, error) {
	return a.cluster.Leader(ctx, shardID)
}
