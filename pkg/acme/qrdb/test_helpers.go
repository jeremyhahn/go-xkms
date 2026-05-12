// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package qrdb

import (
	"context"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// testService is an in-memory Service implementation for unit testing.
// It wraps a MemoryKVClient and provides stub implementations for all
// Service interface methods that do not require a real QRDB connection.
type testService struct {
	kv     *MemoryKVClient
	admin  *testAdminClient
	roles  *memoryRoleClient
	users  *memoryUserClient
	cfg    *Config
	closed bool
}

// NewTestService creates a Service backed by an in-memory KVClient
// for unit testing. No real QRDB connection is required.
func NewTestService() Service {
	return &testService{
		kv:    NewMemoryKVClient(),
		admin: newTestAdminClient(),
		roles: newMemoryRoleClient(),
		users: newMemoryUserClient(),
		cfg:   DefaultConfig(),
	}
}

func (s *testService) KV() db.KVClient                   { return s.kv }
func (s *testService) Admin() db.AdminClient             { return s.admin }
func (s *testService) Watch() db.WatchClient             { return nil }
func (s *testService) Lease() db.LeaseClient             { return nil }
func (s *testService) Batch() db.BatchClient             { return nil }
func (s *testService) Transaction() db.TransactionClient { return nil }
func (s *testService) Index() db.IndexClient             { return nil }
func (s *testService) Users() db.UserClient              { return s.users }
func (s *testService) Roles() db.RoleClient              { return s.roles }
func (s *testService) Certs() db.CertClient              { return nil }
func (s *testService) Barrier() db.BarrierClient         { return nil }
func (s *testService) Ceremony() db.CeremonyClient       { return nil }
func (s *testService) Credentials() db.CredentialClient  { return nil }
func (s *testService) Config() *Config                   { return s.cfg }

func (s *testService) Healthy(ctx context.Context) bool {
	return !s.closed
}

func (s *testService) Close() error {
	s.closed = true
	return nil
}

// testAdminClient is an in-memory AdminClient for unit testing.
type testAdminClient struct {
	healthy    bool
	isDraining bool
	shardCount int
	isLeader   bool
	peers      *db.PeersResponse
}

func newTestAdminClient() *testAdminClient {
	return &testAdminClient{
		healthy:    true,
		shardCount: 1,
		isLeader:   true,
		peers: &db.PeersResponse{
			Shards: []db.ShardPeers{
				{
					ShardID:  1,
					LeaderID: 1,
					Peers: []db.PeerInfo{
						{ReplicaID: 1, Address: "localhost:63001", IsLeader: true},
					},
				},
			},
		},
	}
}

func (a *testAdminClient) Health(ctx context.Context) (*db.HealthResponse, error) {
	status := "healthy"
	if !a.healthy {
		status = "unhealthy"
	}
	return &db.HealthResponse{
		Status:   status,
		IsLeader: a.isLeader,
	}, nil
}

func (a *testAdminClient) Status(ctx context.Context) (*db.StatusResponse, error) {
	return &db.StatusResponse{
		NodeID:     "test-node-1",
		IsLeader:   a.isLeader,
		ShardCount: a.shardCount,
		IsDraining: a.isDraining,
	}, nil
}

func (a *testAdminClient) Peers(ctx context.Context) (*db.PeersResponse, error) {
	return a.peers, nil
}

func (a *testAdminClient) AddMember(ctx context.Context, shardID, replicaID uint64, raftAddr string) error {
	return nil
}

func (a *testAdminClient) RemoveMember(ctx context.Context, shardID, replicaID uint64) error {
	return nil
}

func (a *testAdminClient) RequestSnapshot(ctx context.Context, shardID uint64) error {
	return nil
}

func (a *testAdminClient) Drain(ctx context.Context) error {
	a.isDraining = true
	return nil
}

func (a *testAdminClient) Capabilities(ctx context.Context) (*db.CapabilitiesResponse, error) {
	return &db.CapabilitiesResponse{KV: true}, nil
}

func (a *testAdminClient) StartShard(ctx context.Context, req *db.StartShardRequest) error {
	return nil
}

func (a *testAdminClient) StopShard(ctx context.Context, shardID uint64) error {
	return nil
}

func (a *testAdminClient) GetShardState(ctx context.Context, shardID uint64) (*db.ShardStateResponse, error) {
	return &db.ShardStateResponse{
		ShardID:   shardID,
		Term:      1,
		LeaderID:  1,
		HasLeader: true,
	}, nil
}

func (a *testAdminClient) GetTopology(ctx context.Context) (*db.TopologyResponse, error) {
	return &db.TopologyResponse{
		NodeID:     "test-node-1",
		ShardCount: a.shardCount,
	}, nil
}
