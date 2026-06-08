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
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClusterReader is an in-memory test double for the embedded qrdb cluster
// client, satisfying xkms.ClusterReader.
type fakeClusterReader struct {
	members   []xkms.ClusterMember
	leaderID  uint64
	hasLeader bool
}

func (f *fakeClusterReader) Members(_ context.Context, _ uint64) ([]xkms.ClusterMember, error) {
	return f.members, nil
}

func (f *fakeClusterReader) Leader(_ context.Context, _ uint64) (uint64, bool, error) {
	return f.leaderID, f.hasLeader, nil
}

// setupClusterTestHandlers wires the XKMSService singleton with a clustered
// cluster reader and mounts the cluster routes, mirroring production wiring.
func setupClusterTestHandlers(t *testing.T, reader xkms.ClusterReader, shardID, nodeID uint64) *chi.Mux {
	t.Helper()

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetClusterClient(reader, shardID, nodeID)
	t.Cleanup(func() { xkms.Reset() })

	handlers := NewClusterHandlers()
	r := chi.NewRouter()
	r.Route("/cluster", func(r chi.Router) {
		r.Get("/status", handlers.StatusHandler)
		r.Get("/members", handlers.MembersHandler)
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

	handlers := NewClusterHandlers()
	req := httptest.NewRequest(http.MethodGet, "/cluster/status", nil)
	rr := httptest.NewRecorder()
	handlers.StatusHandler(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}
