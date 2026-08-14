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

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClusterReader is an in-memory test double for the embedded qrdb cluster
// client, satisfying the full xkms.ClusterClient contract (reads, leader
// endpoint resolution, and membership mutation). The name predates the
// widened interface; it is kept so existing call sites in this file don't
// churn.
type fakeClusterReader struct {
	members   []xkms.ClusterMember
	leaderID  uint64
	hasLeader bool

	// leaderEndpoint is returned by LeaderEndpoint for every protocol. Empty
	// means "no endpoint advertised", mirroring a standalone or
	// pre-advertisement replica.
	leaderEndpoint string
	// leaderEndpointErr, when set, is returned by LeaderEndpoint instead of
	// leaderEndpoint.
	leaderEndpointErr error

	// addReplicaErr / removeReplicaErr, when set, are returned by AddReplica /
	// RemoveReplica instead of succeeding.
	addReplicaErr    error
	removeReplicaErr error

	// mu guards the mutation-tracking fields below so tests can assert on them
	// after driving requests through the router.
	mu             sync.Mutex
	addedReplicas  []addReplicaCall
	removedReplica []uint64
}

// addReplicaCall records the arguments a single AddReplica invocation was
// made with, so tests can assert the servicer received the right arguments.
type addReplicaCall struct {
	shardID   uint64
	replicaID uint64
	raftAddr  string
}

func (f *fakeClusterReader) Members(_ context.Context, _ uint64) ([]xkms.ClusterMember, error) {
	return f.members, nil
}

func (f *fakeClusterReader) Leader(_ context.Context, _ uint64) (uint64, bool, error) {
	return f.leaderID, f.hasLeader, nil
}

func (f *fakeClusterReader) LeaderEndpoint(_ context.Context, _ uint64, _ string) (string, error) {
	if f.leaderEndpointErr != nil {
		return "", f.leaderEndpointErr
	}
	return f.leaderEndpoint, nil
}

func (f *fakeClusterReader) AddReplica(_ context.Context, shardID, replicaID uint64, raftAddr string) error {
	if f.addReplicaErr != nil {
		return f.addReplicaErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addedReplicas = append(f.addedReplicas, addReplicaCall{shardID: shardID, replicaID: replicaID, raftAddr: raftAddr})
	return nil
}

func (f *fakeClusterReader) RemoveReplica(_ context.Context, _, replicaID uint64) error {
	if f.removeReplicaErr != nil {
		return f.removeReplicaErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removedReplica = append(f.removedReplica, replicaID)
	return nil
}

func (f *fakeClusterReader) addCalls() []addReplicaCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]addReplicaCall, len(f.addedReplicas))
	copy(out, f.addedReplicas)
	return out
}

func (f *fakeClusterReader) removeCalls() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]uint64, len(f.removedReplica))
	copy(out, f.removedReplica)
	return out
}

// setupClusterTestHandlers wires the XKMSService singleton with a clustered
// cluster client and mounts the cluster routes, mirroring production wiring.
// A nil client configures a standalone node, matching SetClusterClient's own
// contract.
func setupClusterTestHandlers(t *testing.T, client xkms.ClusterClient, shardID, nodeID uint64) *chi.Mux {
	t.Helper()

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	if client != nil {
		svc.SetClusterClient(client, shardID, nodeID)
	} else {
		svc.SetClusterClient(nil, shardID, nodeID)
	}
	t.Cleanup(func() { xkms.Reset() })

	handlers := NewClusterHandlers(svc)
	r := chi.NewRouter()
	r.Route("/cluster", func(r chi.Router) {
		r.Get("/status", handlers.StatusHandler)
		r.Get("/members", handlers.MembersHandler)
		r.Post("/members", handlers.AddReplicaHandler)
		r.Delete("/members/{replicaID}", handlers.RemoveReplicaHandler)
	})
	return r
}

func TestClusterStatusHandler_Clustered(t *testing.T) {
	router := setupClusterTestHandlers(t,
		&fakeClusterReader{leaderID: 2, hasLeader: true}, 3, 1)

	req := httptest.NewRequest(http.MethodGet, "/cluster/status", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp transport.ClusterStatusResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.True(t, resp.Status.Clustered)
	assert.Equal(t, uint64(3), resp.Status.ShardID)
	assert.Equal(t, uint64(1), resp.Status.NodeID)
	assert.Equal(t, uint64(2), resp.Status.LeaderID)
	assert.True(t, resp.Status.HasLeader)
}

func TestClusterStatusHandler_Standalone(t *testing.T) {
	router := setupClusterTestHandlers(t, nil, 1, 9)

	req := httptest.NewRequest(http.MethodGet, "/cluster/status", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp transport.ClusterStatusResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.False(t, resp.Status.Clustered)
	assert.Equal(t, uint64(9), resp.Status.NodeID)
	assert.Equal(t, uint64(9), resp.Status.LeaderID)
	assert.True(t, resp.Status.HasLeader)
}

func TestClusterMembersHandler_Clustered(t *testing.T) {
	reader := &fakeClusterReader{
		members: []xkms.ClusterMember{
			{ReplicaID: 1, Address: "10.0.0.1:63001", IsLeader: true},
			{ReplicaID: 2, Address: "10.0.0.2:63001", IsLeader: false},
		},
	}
	router := setupClusterTestHandlers(t, reader, 1, 1)

	req := httptest.NewRequest(http.MethodGet, "/cluster/members", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp transport.ListClusterMembersResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Len(t, resp.Members, 2)
	assert.Equal(t, uint64(1), resp.Members[0].NodeID)
	assert.Equal(t, "10.0.0.1:63001", resp.Members[0].Address)
	assert.True(t, resp.Members[0].IsLeader)
	assert.Equal(t, uint64(2), resp.Members[1].NodeID)
	assert.False(t, resp.Members[1].IsLeader)
}

func TestClusterMembersHandler_Standalone(t *testing.T) {
	router := setupClusterTestHandlers(t, nil, 1, 1)

	req := httptest.NewRequest(http.MethodGet, "/cluster/members", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp transport.ListClusterMembersResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Empty(t, resp.Members)
}

func TestClusterStatusHandler_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	t.Cleanup(func() { xkms.Reset() })

	handlers := NewClusterHandlers(nil)
	req := httptest.NewRequest(http.MethodGet, "/cluster/status", nil)
	rr := httptest.NewRecorder()
	handlers.StatusHandler(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}
