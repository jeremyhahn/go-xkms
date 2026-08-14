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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// healthOK writes the minimal 200 response Connect's health check accepts.
func healthOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"}); err != nil {
		panic(err)
	}
}

// --- AddClusterReplica / RemoveClusterReplica ---

func TestAddClusterReplica_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.AddClusterReplica(context.Background(), 1, "10.0.0.1:63001")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRemoveClusterReplica_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.RemoveClusterReplica(context.Background(), 1)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestAddClusterReplica_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			healthOK(w)
			return
		}
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/cluster/members", r.URL.Path)

		var req transport.AddClusterReplicaRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, uint64(2), req.ReplicaID)
		assert.Equal(t, "10.0.0.2:63001", req.RaftAddress)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(transport.ClusterReplicaResponse{ShardID: 1, ReplicaID: 2}))
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.AddClusterReplica(context.Background(), 2, "10.0.0.2:63001")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, uint64(1), resp.ShardID)
	assert.Equal(t, uint64(2), resp.ReplicaID)
}

func TestRemoveClusterReplica_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			healthOK(w)
			return
		}
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/cluster/members/5", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(transport.ClusterReplicaResponse{ShardID: 1, ReplicaID: 5}))
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.RemoveClusterReplica(context.Background(), 5)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, uint64(1), resp.ShardID)
	assert.Equal(t, uint64(5), resp.ReplicaID)
}

// --- Transparent leader redirect ---

// TestDoRawRequest_LeaderRedirect proves a 421 carrying
// X-XKMS-Leader-API-Address is retried exactly once against the leader, with
// the identical method/path/body, and that the caller's own credentials
// (bearer token, custom headers) reach the leader — never the follower's.
func TestDoRawRequest_LeaderRedirect(t *testing.T) {
	var (
		followerHits int
		leaderHits   int

		leaderGotAuth   string
		leaderGotHeader string
		leaderGotMethod string
		leaderGotPath   string
		leaderGotBody   []byte
	)

	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaderHits++
		leaderGotAuth = r.Header.Get("Authorization")
		leaderGotHeader = r.Header.Get("X-Test-Header")
		leaderGotMethod = r.Method
		leaderGotPath = r.URL.Path
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		leaderGotBody = body

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(transport.ClusterReplicaResponse{ShardID: 7, ReplicaID: 3}))
	}))
	defer leader.Close()
	leaderHostPort := strings.TrimPrefix(leader.URL, "http://")

	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			healthOK(w)
			return
		}
		followerHits++
		w.Header().Set("X-XKMS-Leader-API-Address", leaderHostPort)
		w.WriteHeader(http.StatusMisdirectedRequest)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "not leader"}))
	}))
	defer follower.Close()

	tr, err := New(
		transport.WithAddress(follower.URL),
		transport.WithJWTToken("secret-token"),
		transport.WithHeader("X-Test-Header", "abc"),
	)
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.AddClusterReplica(context.Background(), 3, "10.0.0.3:63001")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, uint64(7), resp.ShardID)
	assert.Equal(t, uint64(3), resp.ReplicaID)

	assert.Equal(t, 1, followerHits, "exactly one attempt against the follower")
	assert.Equal(t, 1, leaderHits, "exactly one retry against the leader")

	assert.Equal(t, "Bearer secret-token", leaderGotAuth, "caller's own bearer token must reach the leader")
	assert.Equal(t, "abc", leaderGotHeader, "caller's own custom header must reach the leader")
	assert.Equal(t, http.MethodPost, leaderGotMethod)
	assert.Equal(t, "/api/v1/cluster/members", leaderGotPath)

	var gotReq transport.AddClusterReplicaRequest
	require.NoError(t, json.Unmarshal(leaderGotBody, &gotReq))
	assert.Equal(t, uint64(3), gotReq.ReplicaID)
	assert.Equal(t, "10.0.0.3:63001", gotReq.RaftAddress)
}

// TestDoRawRequest_NotLeaderWithoutAddress_NoRetry proves a 421 without the
// leader API address header is returned to the caller as-is: no retry is
// attempted, matching the pre-redirect behavior.
func TestDoRawRequest_NotLeaderWithoutAddress_NoRetry(t *testing.T) {
	var followerHits int
	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			healthOK(w)
			return
		}
		followerHits++
		w.WriteHeader(http.StatusMisdirectedRequest)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "not leader"}))
	}))
	defer follower.Close()

	tr, err := New(transport.WithAddress(follower.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	_, err = tr.ClusterStatus(context.Background())
	require.Error(t, err)
	assert.Equal(t, 1, followerHits)
}

// TestDoRawRequest_LeaderRedirect_SingleHop proves a 421 returned by the
// leader on the retry is handed back to the caller unchanged: the transport
// never chases a second hop, even when the leader's own response advertises
// yet another leader address.
func TestDoRawRequest_LeaderRedirect_SingleHop(t *testing.T) {
	var followerHits, leaderHits int

	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaderHits++
		// The "leader" is implausibly also not-leader and points elsewhere;
		// this must never be followed.
		w.Header().Set("X-XKMS-Leader-API-Address", "127.0.0.1:1")
		w.WriteHeader(http.StatusMisdirectedRequest)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "still not leader"}))
	}))
	defer leader.Close()
	leaderHostPort := strings.TrimPrefix(leader.URL, "http://")

	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			healthOK(w)
			return
		}
		followerHits++
		w.Header().Set("X-XKMS-Leader-API-Address", leaderHostPort)
		w.WriteHeader(http.StatusMisdirectedRequest)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "not leader"}))
	}))
	defer follower.Close()

	tr, err := New(transport.WithAddress(follower.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	_, err = tr.ClusterStatus(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "still not leader")
	assert.Equal(t, 1, followerHits)
	assert.Equal(t, 1, leaderHits, "the leader's own 421 must not be chased again")
}

// TestDoRawRequest_LeaderRedirect_MalformedAddress proves a leader API
// address that cannot be parsed into host:port surfaces a typed
// *ErrMalformedLeaderAddress instead of silently retrying against garbage or
// silently ignoring the header.
func TestDoRawRequest_LeaderRedirect_MalformedAddress(t *testing.T) {
	var followerHits int
	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			healthOK(w)
			return
		}
		followerHits++
		w.Header().Set("X-XKMS-Leader-API-Address", "not-a-valid-address")
		w.WriteHeader(http.StatusMisdirectedRequest)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "not leader"}))
	}))
	defer follower.Close()

	tr, err := New(transport.WithAddress(follower.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	_, err = tr.ClusterStatus(context.Background())
	require.Error(t, err)

	var malformed *ErrMalformedLeaderAddress
	require.ErrorAs(t, err, &malformed)
	assert.Equal(t, "not-a-valid-address", malformed.Address)
	assert.Equal(t, 1, followerHits)
}

// TestDoRawRequest_LeaderRedirect_PreservesBaseURL proves the retry never
// mutates the transport's own base URL: a transient leadership change must
// not permanently repoint the client at the old leader.
func TestDoRawRequest_LeaderRedirect_PreservesBaseURL(t *testing.T) {
	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(transport.ClusterStatusResponse{}))
	}))
	defer leader.Close()
	leaderHostPort := strings.TrimPrefix(leader.URL, "http://")

	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			healthOK(w)
			return
		}
		w.Header().Set("X-XKMS-Leader-API-Address", leaderHostPort)
		w.WriteHeader(http.StatusMisdirectedRequest)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "not leader"}))
	}))
	defer follower.Close()

	tr, err := New(transport.WithAddress(follower.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	originalBaseURL := tr.BaseURL()

	_, err = tr.ClusterStatus(context.Background())
	require.NoError(t, err)

	assert.Equal(t, originalBaseURL, tr.BaseURL(), "a per-request redirect must not repoint the transport")
}
