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

package quic

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

func testServer() *Server {
	return &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// fakeClusterEndpointClient is a minimal xkms.ClusterClient double whose only
// interesting behavior is LeaderEndpoint. Members/Leader/AddReplica/
// RemoveReplica are never exercised by sendNotLeader, but the interface
// requires them.
type fakeClusterEndpointClient struct {
	endpoint    string
	endpointErr error
	gotShardID  uint64
	gotProtocol string
}

func (f *fakeClusterEndpointClient) Members(context.Context, uint64) ([]xkms.ClusterMember, error) {
	return nil, nil
}

func (f *fakeClusterEndpointClient) Leader(context.Context, uint64) (uint64, bool, error) {
	return 0, false, nil
}

func (f *fakeClusterEndpointClient) LeaderEndpoint(_ context.Context, shardID uint64, protocol string) (string, error) {
	f.gotShardID = shardID
	f.gotProtocol = protocol
	if f.endpointErr != nil {
		return "", f.endpointErr
	}
	return f.endpoint, nil
}

func (f *fakeClusterEndpointClient) AddReplica(context.Context, uint64, uint64, string) error {
	return nil
}

func (f *fakeClusterEndpointClient) RemoveReplica(context.Context, uint64, uint64) error {
	return nil
}

// serverWithCluster wires a *xkms.XKMSService backed by the given fake cluster
// client into a fresh test Server, so sendNotLeader's endpoint-resolution path
// can be exercised.
func serverWithCluster(cluster xkms.ClusterClient, shardID, nodeID uint64) *Server {
	svc := &xkms.XKMSService{}
	svc.SetClusterClient(cluster, shardID, nodeID)
	s := testServer()
	s.xkmsService = svc
	return s
}

func TestSendServiceError_NotLeader(t *testing.T) {
	s := testServer()
	rec := httptest.NewRecorder()
	src := &qrdbtransport.NotLeaderError{ShardID: 1, LeaderID: 2, LeaderAddress: "10.0.0.2:63001"}

	s.sendServiceError(context.Background(), rec, &errs.Wrapped{Msg: "generate key", Err: src}, http.StatusInternalServerError, "failed to generate key")

	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMisdirectedRequest)
	}
	if got := rec.Header().Get("X-XKMS-Leader-Address"); got != "10.0.0.2:63001" {
		t.Fatalf("X-XKMS-Leader-Address = %q, want 10.0.0.2:63001", got)
	}
	if got := rec.Header().Get("X-XKMS-Shard-ID"); got != "1" {
		t.Fatalf("X-XKMS-Shard-ID = %q, want 1", got)
	}
	// No xkmsService is wired on this server, so the QUIC leader endpoint can
	// never be resolved: the field and header must be entirely absent, not
	// merely empty.
	if got := rec.Header().Get("X-XKMS-Leader-API-Address"); got != "" {
		t.Fatalf("X-XKMS-Leader-API-Address = %q, want empty", got)
	}
	raw := rec.Body.String()
	if strings.Contains(raw, "leader_api_address") {
		t.Fatalf("raw body contains leader_api_address key when unresolved: %s", raw)
	}

	var body NotLeaderResponse
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.ShardID != 1 || body.LeaderID != 2 || body.LeaderAddress != "10.0.0.2:63001" {
		t.Fatalf("body = %+v", body)
	}
	if body.LeaderAPIAddress != "" {
		t.Fatalf("body.LeaderAPIAddress = %q, want empty", body.LeaderAPIAddress)
	}
}

func TestSendServiceError_Fallback(t *testing.T) {
	s := testServer()
	rec := httptest.NewRecorder()

	s.sendServiceError(context.Background(), rec, &errs.Message{Msg: "disk full"}, http.StatusInternalServerError, "failed to generate key")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if rec.Header().Get("X-XKMS-Shard-ID") != "" {
		t.Fatal("unexpected leader header on non-leader error")
	}
}

func TestSendNotLeader_ResolvesLeaderAPIAddress(t *testing.T) {
	cluster := &fakeClusterEndpointClient{endpoint: "leader.example.com:8444"}
	s := serverWithCluster(cluster, 1, 9)

	rec := httptest.NewRecorder()
	src := &qrdbtransport.NotLeaderError{ShardID: 1, LeaderID: 2, LeaderAddress: "10.0.0.2:63001"}

	s.sendServiceError(context.Background(), rec, &errs.Wrapped{Msg: "generate key", Err: src}, http.StatusInternalServerError, "failed to generate key")

	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMisdirectedRequest)
	}
	if got := rec.Header().Get("X-XKMS-Leader-API-Address"); got != "leader.example.com:8444" {
		t.Fatalf("X-XKMS-Leader-API-Address = %q, want leader.example.com:8444", got)
	}
	if cluster.gotProtocol != transport.APIProtocolQUIC {
		t.Fatalf("resolved protocol = %q, want %q", cluster.gotProtocol, transport.APIProtocolQUIC)
	}
	if cluster.gotShardID != 1 {
		t.Fatalf("resolved shard = %d, want 1", cluster.gotShardID)
	}

	var body NotLeaderResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.LeaderAPIAddress != "leader.example.com:8444" {
		t.Fatalf("body.LeaderAPIAddress = %q, want leader.example.com:8444", body.LeaderAPIAddress)
	}
}

func TestSendNotLeader_NoAdvertisedEndpointOmitsField(t *testing.T) {
	// The leader is known but advertises no QUIC endpoint (predates API
	// advertisement, or was configured with no advertise host).
	cluster := &fakeClusterEndpointClient{endpoint: ""}
	s := serverWithCluster(cluster, 1, 9)

	rec := httptest.NewRecorder()
	src := &qrdbtransport.NotLeaderError{ShardID: 1, LeaderID: 2, LeaderAddress: "10.0.0.2:63001"}

	s.sendServiceError(context.Background(), rec, &errs.Wrapped{Msg: "generate key", Err: src}, http.StatusInternalServerError, "failed to generate key")

	if got := rec.Header().Get("X-XKMS-Leader-API-Address"); got != "" {
		t.Fatalf("X-XKMS-Leader-API-Address = %q, want empty", got)
	}
	raw := rec.Body.String()
	if strings.Contains(raw, "leader_api_address") {
		t.Fatalf("raw body contains leader_api_address key when address is empty: %s", raw)
	}
}

func TestSendNotLeader_ResolutionErrorDegradesToRaftCoordinates(t *testing.T) {
	cluster := &fakeClusterEndpointClient{endpointErr: errors.New("cluster registry unavailable")}
	s := serverWithCluster(cluster, 1, 9)

	rec := httptest.NewRecorder()
	src := &qrdbtransport.NotLeaderError{ShardID: 1, LeaderID: 2, LeaderAddress: "10.0.0.2:63001"}

	// A leader-endpoint resolution error must not prevent a valid 421 from
	// being sent -- it degrades to the Raft coordinates, it never fails the
	// response.
	s.sendServiceError(context.Background(), rec, &errs.Wrapped{Msg: "generate key", Err: src}, http.StatusInternalServerError, "failed to generate key")

	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMisdirectedRequest)
	}
	if got := rec.Header().Get("X-XKMS-Leader-API-Address"); got != "" {
		t.Fatalf("X-XKMS-Leader-API-Address = %q, want empty on resolution failure", got)
	}
	if got := rec.Header().Get("X-XKMS-Leader-Address"); got != "10.0.0.2:63001" {
		t.Fatalf("X-XKMS-Leader-Address = %q, want 10.0.0.2:63001", got)
	}
	if got := rec.Header().Get("X-XKMS-Shard-ID"); got != "1" {
		t.Fatalf("X-XKMS-Shard-ID = %q, want 1", got)
	}

	var body NotLeaderResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.ShardID != 1 || body.LeaderID != 2 || body.LeaderAddress != "10.0.0.2:63001" {
		t.Fatalf("body = %+v", body)
	}
	if body.LeaderAPIAddress != "" {
		t.Fatalf("body.LeaderAPIAddress = %q, want empty on resolution failure", body.LeaderAPIAddress)
	}
}
