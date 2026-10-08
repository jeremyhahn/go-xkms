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

// clusterClientAdapter bridges the embedded go-qrdb node's *ClusterClient to
// the xkms.ClusterClient contract the servicer depends on. It performs only
// shape translation; every decision (validation, authorization, standalone
// handling) stays in the layers that own it.
type clusterClientAdapter struct {
	cluster *qrdbsdk.ClusterClient
}

var _ xkms.ClusterClient = (*clusterClientAdapter)(nil)

// LeaderEndpoint resolves the address to dial to reach the shard leader over
// the named API protocol. An unknown protocol name is rejected by the qrdb SDK
// with a typed error rather than silently returning no endpoint.
func (a *clusterClientAdapter) LeaderEndpoint(ctx context.Context, shardID uint64, protocol string) (string, error) {
	return a.cluster.LeaderEndpoint(ctx, shardID, qrdbsdk.APIProtocol(protocol))
}
