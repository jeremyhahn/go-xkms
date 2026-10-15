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

package main

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"google.golang.org/grpc/metadata"
)

// controlPlaneAuthorizationKey is the gRPC metadata key the qrdb node reads a
// caller's bearer token from on its gRPC and Unix transports.
const controlPlaneAuthorizationKey = "authorization"

// withControlPlaneBearer returns ctx carrying token as the bearer a qrdb
// control-plane RPC presents, or ctx unchanged when token is empty.
func withControlPlaneBearer(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, controlPlaneAuthorizationKey, "Bearer "+token)
}

// withBearer returns ctrl with every cluster and rebalance RPC presenting
// token, or ctrl unchanged when token is empty.
func (ctrl *QRDBControlClient) withBearer(token string) *QRDBControlClient {
	if token == "" {
		return ctrl
	}
	out := &QRDBControlClient{}
	if ctrl.Cluster != nil {
		out.Cluster = &bearerClusterControl{next: ctrl.Cluster, token: token}
	}
	if ctrl.Rebalance != nil {
		out.Rebalance = &bearerRebalanceClient{next: ctrl.Rebalance, token: token}
	}
	return out
}

// bearerClusterControl presents a bearer token on every cluster RPC.
type bearerClusterControl struct {
	next  ClusterControlClient
	token string
}

func (b *bearerClusterControl) Members(ctx context.Context, shardID uint64) ([]qrdbsdk.Member, error) {
	return b.next.Members(withControlPlaneBearer(ctx, b.token), shardID)
}

func (b *bearerClusterControl) Leader(ctx context.Context, shardID uint64) (uint64, bool, error) {
	return b.next.Leader(withControlPlaneBearer(ctx, b.token), shardID)
}

func (b *bearerClusterControl) AddReplica(ctx context.Context, shardID, replicaID uint64, raftAddr, identity string) error {
	return b.next.AddReplica(withControlPlaneBearer(ctx, b.token), shardID, replicaID, raftAddr, identity)
}

func (b *bearerClusterControl) RemoveReplica(ctx context.Context, shardID, replicaID uint64) error {
	return b.next.RemoveReplica(withControlPlaneBearer(ctx, b.token), shardID, replicaID)
}

// bearerRebalanceClient presents a bearer token on every rebalance RPC.
type bearerRebalanceClient struct {
	next  qrdbtransport.RebalanceClient
	token string
}

func (b *bearerRebalanceClient) GetShardStats(ctx context.Context, shardID uint64) (*qrdbtransport.ShardStatsResponse, error) {
	return b.next.GetShardStats(withControlPlaneBearer(ctx, b.token), shardID)
}

func (b *bearerRebalanceClient) CreateRebalancePlan(ctx context.Context, req *qrdbtransport.RebalancePlanRequest) (*qrdbtransport.RebalancePlan, error) {
	return b.next.CreateRebalancePlan(withControlPlaneBearer(ctx, b.token), req)
}

func (b *bearerRebalanceClient) ExecuteRebalance(ctx context.Context, plan *qrdbtransport.RebalancePlan) (*qrdbtransport.RebalanceResult, error) {
	return b.next.ExecuteRebalance(withControlPlaneBearer(ctx, b.token), plan)
}

func (b *bearerRebalanceClient) GetImbalanceReport(ctx context.Context) (*qrdbtransport.ImbalanceReport, error) {
	return b.next.GetImbalanceReport(withControlPlaneBearer(ctx, b.token))
}
