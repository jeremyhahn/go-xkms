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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// fakeClusterClient is an in-memory xkms.ClusterClient double. It mirrors the
// embedded go-qrdb node's cluster semantics so the REST handler ->
// XKMSService servicer pass-through can be exercised end to end without a
// live node. AddReplica/RemoveReplica are implemented only to satisfy the
// ClusterMutator half of the xkms.ClusterClient interface — nothing in the
// REST surface calls them (membership mutation is never exposed over REST;
// see docs/cluster/api.md), so they are unconditional no-ops.
type fakeClusterClient struct {
	members    []xkms.ClusterMember
	membersErr error

	leaderID  uint64
	hasLeader bool
	leaderErr error
}

func (f *fakeClusterClient) Members(_ context.Context, _ uint64) ([]xkms.ClusterMember, error) {
	if f.membersErr != nil {
		return nil, f.membersErr
	}
	return f.members, nil
}

func (f *fakeClusterClient) Leader(_ context.Context, _ uint64) (uint64, bool, error) {
	if f.leaderErr != nil {
		return 0, false, f.leaderErr
	}
	return f.leaderID, f.hasLeader, nil
}

func (f *fakeClusterClient) LeaderEndpoint(_ context.Context, _ uint64, _ string) (string, error) {
	return "", nil
}

func (f *fakeClusterClient) AddReplica(_ context.Context, _, _ uint64, _ string) error {
	return nil
}

func (f *fakeClusterClient) RemoveReplica(_ context.Context, _, _ uint64) error {
	return nil
}

// setupClusterTestHandlers builds a *ClusterHandlers wired to a fresh
// XKMSService singleton and a chi router serving the two read-only cluster
// routes. A nil cluster leaves the service standalone; a non-nil cluster
// wires it via SetClusterClient.
func setupClusterTestHandlers(t *testing.T, cluster xkms.ClusterClient, shardID, nodeID uint64) (*ClusterHandlers, *chi.Mux) {
	t.Helper()

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetClusterClient(cluster, shardID, nodeID)
	t.Cleanup(func() { xkms.Reset() })

	handlers := NewClusterHandlers(svc)
	r := chi.NewRouter()
	r.Route("/cluster", func(r chi.Router) {
		r.Get("/status", handlers.StatusHandler)
		r.Get("/members", handlers.MembersHandler)
	})
	return handlers, r
}

func TestClusterStatusHandler_Clustered(t *testing.T) {
	fake := &fakeClusterClient{leaderID: 2, hasLeader: true}
	_, router := setupClusterTestHandlers(t, fake, 3, 2)

	req := httptest.NewRequest(http.MethodGet, "/cluster/status", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp transport.ClusterStatusResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, uint64(3), resp.Status.ShardID)
	assert.Equal(t, uint64(2), resp.Status.NodeID)
	assert.Equal(t, uint64(2), resp.Status.LeaderID)
	assert.True(t, resp.Status.HasLeader)
	assert.True(t, resp.Status.Clustered)
}

func TestClusterStatusHandler_Standalone(t *testing.T) {
	_, router := setupClusterTestHandlers(t, nil, 1, 0)

	req := httptest.NewRequest(http.MethodGet, "/cluster/status", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp transport.ClusterStatusResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.False(t, resp.Status.Clustered)
	assert.False(t, resp.Status.HasLeader)
}

func TestClusterStatusHandler_NotConfigured(t *testing.T) {
	handlers := NewClusterHandlers(nil)
	req := httptest.NewRequest(http.MethodGet, "/cluster/status", nil)
	rr := httptest.NewRecorder()
	handlers.StatusHandler(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, ErrClusterNotConfigured.Error(), errResp.Error)
}

func TestClusterMembersHandler_Clustered(t *testing.T) {
	want := []xkms.ClusterMember{
		{ReplicaID: 1, Address: "10.0.0.1:63001", IsLeader: true},
		{ReplicaID: 2, Address: "10.0.0.2:63001", APIEndpoints: map[string]string{"rest": "10.0.0.2:8443"}},
	}
	fake := &fakeClusterClient{members: want}
	_, router := setupClusterTestHandlers(t, fake, 1, 1)

	req := httptest.NewRequest(http.MethodGet, "/cluster/members", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp transport.ListClusterMembersResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	require.Len(t, resp.Members, 2)
	assert.Equal(t, uint64(1), resp.Members[0].ReplicaID)
	assert.True(t, resp.Members[0].IsLeader)
	assert.Equal(t, "10.0.0.2:8443", resp.Members[1].APIEndpoints["rest"])
}

func TestClusterMembersHandler_Standalone(t *testing.T) {
	_, router := setupClusterTestHandlers(t, nil, 1, 0)

	req := httptest.NewRequest(http.MethodGet, "/cluster/members", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp transport.ListClusterMembersResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Empty(t, resp.Members)
}

func TestClusterMembersHandler_UnderlyingError(t *testing.T) {
	fake := &fakeClusterClient{membersErr: assert.AnError}
	_, router := setupClusterTestHandlers(t, fake, 1, 1)

	req := httptest.NewRequest(http.MethodGet, "/cluster/members", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// clusterRoutePermissions ties every REST cluster route to the resource:action
// pair the RequirePermission decorator must demand. Spelled out literally
// (not built from auth.Resource*/auth.Action*) so the test fails if a
// constant is retyped or repointed, matching frostRoutePermissions'
// rationale: this table is the wire contract. Only the two read routes
// exist: REST never mutates Raft membership (docs/cluster/api.md).
var clusterRoutePermissions = []struct {
	name     string
	method   string
	path     string
	resource string
	action   string
}{
	{"status", http.MethodGet, "/api/v1/cluster/status", "admin", "status"},
	{"members", http.MethodGet, "/api/v1/cluster/members", "admin", "peers"},
}

// TestClusterRoutes_RBACDenied proves every cluster route is behind the
// RequirePermission decorator: a caller whose every permission check is
// refused receives 403 from the middleware before the handler runs.
func TestClusterRoutes_RBACDenied(t *testing.T) {
	for _, tc := range clusterRoutePermissions {
		t.Run(tc.name, func(t *testing.T) {
			requireRBACDenied(t, tc.method, tc.path, nil)
		})
	}
}

// TestClusterRoutes_RBACRequiredPermission is the positive control: a caller
// holding exactly the cross-transport resource:action pair passes the gate.
func TestClusterRoutes_RBACRequiredPermission(t *testing.T) {
	for _, tc := range clusterRoutePermissions {
		t.Run(tc.name, func(t *testing.T) {
			rbac := &recordingRBACClient{
				allowResource: tc.resource,
				allowAction:   tc.action,
			}

			server, err := NewServer(&Config{
				Authenticator:  auth.NewNoOpAuthenticator(),
				Backends:       map[string]xkms.Backend{"test": newMockKeyStore()},
				EnableRBAC:     true,
				RBACAuthorizer: auth.NewAuthorizer(rbac),
			})
			require.NoError(t, err)

			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			server.server.Handler.ServeHTTP(w, req)

			assert.Equal(t, tc.resource, rbac.gotResource, "decorator asked for wrong resource")
			assert.Equal(t, tc.action, rbac.gotAction, "decorator asked for wrong action")

			assert.NotEqual(t, http.StatusUnauthorized, w.Code)
			assert.NotEqual(t, http.StatusForbidden, w.Code)
		})
	}
}

func TestCapabilityFlags_Cluster(t *testing.T) {
	t.Run("clustered", func(t *testing.T) {
		xkms.Reset()
		require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
			Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
			DefaultBackend: "mem",
		}))
		svc, err := xkms.Get()
		require.NoError(t, err)
		svc.SetClusterClient(&fakeClusterClient{}, 1, 1)
		t.Cleanup(func() { xkms.Reset() })

		server, err := NewServer(&Config{
			Authenticator: auth.NewNoOpAuthenticator(),
			Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
			XKMSService:   svc,
		})
		require.NoError(t, err)

		assert.True(t, server.capabilityFlags()["cluster"])
	})

	t.Run("standalone", func(t *testing.T) {
		xkms.Reset()
		require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
			Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
			DefaultBackend: "mem",
		}))
		svc, err := xkms.Get()
		require.NoError(t, err)
		svc.SetClusterClient(nil, 1, 0)
		t.Cleanup(func() { xkms.Reset() })

		server, err := NewServer(&Config{
			Authenticator: auth.NewNoOpAuthenticator(),
			Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
			XKMSService:   svc,
		})
		require.NoError(t, err)

		assert.False(t, server.capabilityFlags()["cluster"])
	})

	t.Run("no xkms service wired", func(t *testing.T) {
		server, err := NewServer(&Config{
			Authenticator: auth.NewNoOpAuthenticator(),
			Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		})
		require.NoError(t, err)

		assert.False(t, server.capabilityFlags()["cluster"])
	})
}
