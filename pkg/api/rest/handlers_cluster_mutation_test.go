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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- AddReplicaHandler / RemoveReplicaHandler success + argument passthrough ---

func TestAddReplicaHandler_Success(t *testing.T) {
	fake := &fakeClusterReader{leaderID: 1, hasLeader: true}
	router := setupClusterTestHandlers(t, fake, 7, 1)

	body, err := json.Marshal(transport.AddClusterReplicaRequest{ReplicaID: 2, RaftAddress: "10.0.0.2:63001"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/cluster/members", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp transport.ClusterReplicaResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, uint64(7), resp.ShardID)
	assert.Equal(t, uint64(2), resp.ReplicaID)

	calls := fake.addCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, uint64(7), calls[0].shardID)
	assert.Equal(t, uint64(2), calls[0].replicaID)
	assert.Equal(t, "10.0.0.2:63001", calls[0].raftAddr)
}

func TestRemoveReplicaHandler_Success(t *testing.T) {
	fake := &fakeClusterReader{leaderID: 1, hasLeader: true}
	router := setupClusterTestHandlers(t, fake, 7, 1)

	req := httptest.NewRequest(http.MethodDelete, "/cluster/members/3", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp transport.ClusterReplicaResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, uint64(7), resp.ShardID)
	assert.Equal(t, uint64(3), resp.ReplicaID)

	assert.Equal(t, []uint64{3}, fake.removeCalls())
}

// TestAddReplicaHandler_Idempotent proves adding the same replica twice
// succeeds both times, mirroring the underlying qrdb AddMember's idempotency
// contract that the servicer documents.
func TestAddReplicaHandler_Idempotent(t *testing.T) {
	fake := &fakeClusterReader{leaderID: 1, hasLeader: true}
	router := setupClusterTestHandlers(t, fake, 1, 1)

	body, err := json.Marshal(transport.AddClusterReplicaRequest{ReplicaID: 5, RaftAddress: "10.0.0.5:63001"})
	require.NoError(t, err)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/cluster/members", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, "attempt %d", i+1)
	}

	assert.Len(t, fake.addCalls(), 2)
}

// --- Malformed / invalid request handling ---

func TestAddReplicaHandler_MalformedJSON(t *testing.T) {
	fake := &fakeClusterReader{}
	router := setupClusterTestHandlers(t, fake, 1, 1)

	req := httptest.NewRequest(http.MethodPost, "/cluster/members", bytes.NewReader([]byte("{not json")))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Empty(t, fake.addCalls())
}

func TestAddReplicaHandler_ReplicaIDZero(t *testing.T) {
	fake := &fakeClusterReader{}
	router := setupClusterTestHandlers(t, fake, 1, 1)

	body, err := json.Marshal(transport.AddClusterReplicaRequest{ReplicaID: 0, RaftAddress: "10.0.0.1:63001"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/cluster/members", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Empty(t, fake.addCalls())
}

func TestRemoveReplicaHandler_NonNumericPathParam(t *testing.T) {
	fake := &fakeClusterReader{}
	router := setupClusterTestHandlers(t, fake, 1, 1)

	req := httptest.NewRequest(http.MethodDelete, "/cluster/members/not-a-number", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Empty(t, fake.removeCalls())
}

func TestRemoveReplicaHandler_ReplicaIDZero(t *testing.T) {
	fake := &fakeClusterReader{}
	router := setupClusterTestHandlers(t, fake, 1, 1)

	req := httptest.NewRequest(http.MethodDelete, "/cluster/members/0", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Empty(t, fake.removeCalls())
}

// --- Standalone node ---

func TestAddReplicaHandler_Standalone(t *testing.T) {
	router := setupClusterTestHandlers(t, nil, 1, 9)

	body, err := json.Marshal(transport.AddClusterReplicaRequest{ReplicaID: 2, RaftAddress: "10.0.0.2:63001"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/cluster/members", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestRemoveReplicaHandler_Standalone(t *testing.T) {
	router := setupClusterTestHandlers(t, nil, 1, 9)

	req := httptest.NewRequest(http.MethodDelete, "/cluster/members/2", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
}

// --- Not-leader redirect enrichment ---

// TestAddReplicaHandler_NotLeaderWithAPIAddress proves a clustered write that
// reaches a follower is surfaced as 421 with the leader's dialable REST
// address, resolved via ClusterLeaderEndpoint and echoed in both the
// X-XKMS-Leader-API-Address header and the JSON body.
func TestAddReplicaHandler_NotLeaderWithAPIAddress(t *testing.T) {
	fake := &fakeClusterReader{
		leaderEndpoint: "10.0.0.9:8443",
		addReplicaErr: &qrdbtransport.NotLeaderError{
			ShardID:       1,
			LeaderID:      9,
			LeaderAddress: "10.0.0.9:63001",
		},
	}
	router := setupClusterTestHandlers(t, fake, 1, 1)

	body, err := json.Marshal(transport.AddClusterReplicaRequest{ReplicaID: 2, RaftAddress: "10.0.0.2:63001"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/cluster/members", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusMisdirectedRequest, rr.Code)
	assert.Equal(t, "10.0.0.9:8443", rr.Header().Get("X-XKMS-Leader-API-Address"))
	assert.Equal(t, "10.0.0.9:63001", rr.Header().Get("X-XKMS-Leader-Address"))

	var resp NotLeaderResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "10.0.0.9:8443", resp.LeaderAPIAddress)
	assert.Equal(t, "10.0.0.9:63001", resp.LeaderAddress)
}

// TestAddReplicaHandler_NotLeaderWithoutAPIAddress proves the redirect
// degrades gracefully to the pre-advertisement behavior (Raft coordinates
// only, no API address header) when the leader has advertised no REST
// endpoint.
func TestAddReplicaHandler_NotLeaderWithoutAPIAddress(t *testing.T) {
	fake := &fakeClusterReader{
		leaderEndpoint: "", // nothing advertised
		addReplicaErr: &qrdbtransport.NotLeaderError{
			ShardID:       1,
			LeaderID:      9,
			LeaderAddress: "10.0.0.9:63001",
		},
	}
	router := setupClusterTestHandlers(t, fake, 1, 1)

	body, err := json.Marshal(transport.AddClusterReplicaRequest{ReplicaID: 2, RaftAddress: "10.0.0.2:63001"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/cluster/members", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusMisdirectedRequest, rr.Code)
	assert.Empty(t, rr.Header().Get("X-XKMS-Leader-API-Address"))
	_, gotHeader := rr.Header()["X-Xkms-Leader-Api-Address"]
	assert.False(t, gotHeader, "empty leader API address must never be emitted as a header")

	var resp NotLeaderResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Empty(t, resp.LeaderAPIAddress)
	assert.Equal(t, "10.0.0.9:63001", resp.LeaderAddress)
}

// --- Members response api_endpoints presence/omission ---

func TestMembersHandler_APIEndpointsPresentAndOmitted(t *testing.T) {
	fake := &fakeClusterReader{
		members: []xkms.ClusterMember{
			{ReplicaID: 1, Address: "10.0.0.1:63001", APIEndpoints: map[string]string{"rest": "10.0.0.1:8443"}, IsLeader: true},
			{ReplicaID: 2, Address: "10.0.0.2:63001", IsLeader: false},
		},
	}
	router := setupClusterTestHandlers(t, fake, 1, 1)

	req := httptest.NewRequest(http.MethodGet, "/cluster/members", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var raw struct {
		Members []map[string]interface{} `json:"members"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &raw))
	require.Len(t, raw.Members, 2)

	_, hasEndpoints := raw.Members[0]["api_endpoints"]
	assert.True(t, hasEndpoints, "replica advertising endpoints must carry api_endpoints")

	_, hasEndpoints = raw.Members[1]["api_endpoints"]
	assert.False(t, hasEndpoints, "replica advertising nothing must omit api_endpoints entirely")
}

// --- RBAC gating ---

func TestClusterMutationRoutes_RBACDenied(t *testing.T) {
	addBody := transport.AddClusterReplicaRequest{ReplicaID: 1, RaftAddress: "10.0.0.1:63001"}
	requireRBACDenied(t, http.MethodPost, "/api/v1/cluster/members", addBody)
	requireRBACDenied(t, http.MethodDelete, "/api/v1/cluster/members/1", nil)
}

func TestClusterMutationRoutes_RBACRequiredPermission(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		path     string
		resource string
		action   string
	}{
		{"add", http.MethodPost, "/api/v1/cluster/members", auth.ResourceClusterAdmin, auth.ActionAddMember},
		{"remove", http.MethodDelete, "/api/v1/cluster/members/1", auth.ResourceClusterAdmin, auth.ActionRemoveMember},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rbac := &recordingRBACClient{allowResource: tc.resource, allowAction: tc.action}

			server, err := NewServer(&Config{
				Authenticator:  auth.NewNoOpAuthenticator(),
				Backends:       map[string]xkms.Backend{"test": newMockKeyStore()},
				EnableRBAC:     true,
				RBACAuthorizer: auth.NewAuthorizer(rbac),
			})
			require.NoError(t, err)

			var body []byte
			if tc.method == http.MethodPost {
				body, err = json.Marshal(transport.AddClusterReplicaRequest{ReplicaID: 1, RaftAddress: "10.0.0.1:63001"})
				require.NoError(t, err)
			}

			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(body))
			w := httptest.NewRecorder()
			server.server.Handler.ServeHTTP(w, req)

			assert.Equal(t, tc.resource, rbac.gotResource, "decorator asked for wrong resource")
			assert.Equal(t, tc.action, rbac.gotAction, "decorator asked for wrong action")
			assert.NotEqual(t, http.StatusUnauthorized, w.Code)
			assert.NotEqual(t, http.StatusForbidden, w.Code)
		})
	}
}

// TestClusterMutationRoutes_FailClosedWithoutRBAC proves membership mutation
// is denied with 403 when the server has no RBAC middleware wired at all —
// the fail-closed path, distinct from an RBAC denial. Unlike the read-only
// cluster routes (which stay reachable on a standalone/no-RBAC server), the
// mutation routes must never be silently open.
func TestClusterMutationRoutes_FailClosedWithoutRBAC(t *testing.T) {
	server, err := NewServer(&Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
	})
	require.NoError(t, err)
	require.Nil(t, server.rbacMiddleware)

	body, err := json.Marshal(transport.AddClusterReplicaRequest{ReplicaID: 1, RaftAddress: "10.0.0.1:63001"})
	require.NoError(t, err)

	addReq := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/members", bytes.NewReader(body))
	addRR := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(addRR, addReq)
	assert.Equal(t, http.StatusForbidden, addRR.Code)

	removeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/cluster/members/1", nil)
	removeRR := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(removeRR, removeReq)
	assert.Equal(t, http.StatusForbidden, removeRR.Code)
}
