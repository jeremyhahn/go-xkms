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

//go:build integration

package oidccredentials

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/jeremyhahn/go-qrdb/sdk/go/testutil/qrdbdharness"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
)

// schedulerLeaseKey is the qrdb lease the credential scheduler's leader
// holds (pkg/oidc/credential).
const schedulerLeaseKey = "xkms/oidc/scheduler"

// raftCoordinator boots a real single-replica raft qrdb node -- the run mode
// in which qrdb serves leases -- and returns its coordination client.
func raftCoordinator(t *testing.T) *qrdbsdk.Coordinator {
	t.Helper()
	port, err := qrdbdharness.ReserveTCPPort()
	require.NoError(t, err)

	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Raft.RaftAddress = fmt.Sprintf("127.0.0.1:%d", port)
	cfg.Raft.ReplicaID = 1
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "pebble"}}
	cfg.Storage.VolumePools = []qrdbsdk.DaemonVolumePoolConfig{{Name: "default", Paths: []string{t.TempDir()}}}
	cfg.Seal.Enabled = true
	cfg.Seal.Strategy = "none"
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	node, err := qrdbnode.NewClusteredNode(ctx, cfg, map[uint64]string{1: cfg.Raft.RaftAddress}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, node.Close()) })

	// The replica accepts writes once it has elected itself.
	kv := node.Client().KV()
	deadline := time.Now().Add(30 * time.Second)
	for kv.Put(ctx, "oidc-it/ready", []byte{1}) != nil {
		require.True(t, time.Now().Before(deadline), "raft node never became writable")
		timer := time.NewTimer(100 * time.Millisecond)
		<-timer.C
	}
	coord, err := node.Client().Coordination()
	require.NoError(t, err)
	return coord
}

// rotatingIdP is a token endpoint whose refresh tokens rotate on use and
// whose reuse is refused the way OpenAI refuses it.
type rotatingIdP struct {
	srv       *httptest.Server
	mu        sync.Mutex
	current   string
	gen       int
	refreshes int
	gate      chan struct{}
}

func newRotatingIdP(t *testing.T) *rotatingIdP {
	t.Helper()
	idp := &rotatingIdP{current: "rt-0"}
	idp.srv = httptest.NewServer(http.HandlerFunc(idp.serve))
	t.Cleanup(idp.srv.Close)
	return idp
}

func (p *rotatingIdP) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req map[string]string
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	gate := p.gate
	p.mu.Unlock()
	if gate != nil {
		<-gate
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshes++
	w.Header().Set("Content-Type", "application/json")
	if req["refresh_token"] != p.current {
		w.WriteHeader(http.StatusUnauthorized)
		if err := json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "refresh_token_reused"}}); err != nil {
			return
		}
		return
	}
	p.gen++
	p.current = fmt.Sprintf("rt-%d", p.gen)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"access_token": fmt.Sprintf("at-%d", p.gen), "refresh_token": p.current, "expires_in": 3600,
	}); err != nil {
		return
	}
}

func (p *rotatingIdP) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshes
}

// node is one credential service, as one xkmsd node runs it: its own
// process-local locks, the cluster's lease primitive, the shared barriers.
func newNode(t *testing.T, registry *seal.BarrierRegistry, coord *qrdbsdk.Coordinator, idp *rotatingIdP) *credential.Service {
	t.Helper()
	svc, err := credential.New(credential.RegistryBarriers(registry),
		credential.WithLeases(coord), credential.WithHTTPClient(idp.srv.Client()))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, svc.Close()) })
	return svc
}

// importDue creates a credential whose access token is inside its refresh
// margin.
func importDue(t *testing.T, svc *credential.Service, idp *rotatingIdP, name string) credential.Ref {
	t.Helper()
	ref := credential.Ref{Scope: scope.Tenant, Name: name}
	idp.mu.Lock()
	current := idp.current
	idp.mu.Unlock()
	_, err := svc.Create(context.Background(), platform, ref, credential.Config{
		Issuer: idp.srv.URL, ClientID: "app", TokenEndpoint: idp.srv.URL + "/oauth/token", TokenEncoding: "json",
	}, &credential.Tokens{AccessToken: "at-0", RefreshToken: current, ExpiresAt: time.Now().Add(time.Minute)})
	require.NoError(t, err)
	return ref
}

var platform = scope.Principal{TenantID: scope.SystemTenant, Subject: "it", Platform: true}

// TestLeaseSerializesRefreshAcrossNodes proves the raft lease is the
// cross-node lock: two services, each with its own in-process locks, so
// only the qrdb lease stands between them, race to refresh one credential
// whose refresh token rotates. Exactly one refresh reaches the provider and
// every caller on both nodes gets its token; a second refresh would have
// presented the spent token and lost the login.
func TestLeaseSerializesRefreshAcrossNodes(t *testing.T) {
	coord := raftCoordinator(t)
	registry := barriertest.NewRegistry(t)
	idp := newRotatingIdP(t)
	nodeA := newNode(t, registry, coord, idp)
	nodeB := newNode(t, registry, coord, idp)
	ref := importDue(t, nodeA, idp, "codex")

	gate := make(chan struct{})
	idp.mu.Lock()
	idp.gate = gate
	idp.mu.Unlock()

	const perNode = 8
	var started, done sync.WaitGroup
	results := make(chan string, 2*perNode)
	errs := make(chan error, 2*perNode)
	for _, svc := range []*credential.Service{nodeA, nodeB} {
		for range perNode {
			started.Add(1)
			done.Add(1)
			go func() {
				defer done.Done()
				started.Done()
				tok, err := svc.GetAccessToken(context.Background(), platform, ref)
				if err != nil {
					errs <- err
					return
				}
				results <- tok.AccessToken
			}()
		}
	}
	started.Wait()
	close(gate)
	done.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Errorf("a caller failed: %v", err)
	}
	for tok := range results {
		assert.Equal(t, "at-1", tok)
	}
	assert.Equal(t, 1, idp.count(), "one refresh reached the provider")
	c, err := nodeB.Get(context.Background(), platform, ref)
	require.NoError(t, err)
	assert.Equal(t, credential.StatusActive, c.Status)
}

// TestSchedulerLeaderElectionOverRaft proves only the lease holder's
// scheduler refreshes, and that another node takes over when it stops.
func TestSchedulerLeaderElectionOverRaft(t *testing.T) {
	coord := raftCoordinator(t)
	registry := barriertest.NewRegistry(t)
	idp := newRotatingIdP(t)
	leader := newNode(t, registry, coord, idp)
	follower := newNode(t, registry, coord, idp)

	leaderEvents := make(chan credential.Event, 16)
	followerEvents := make(chan credential.Event, 16)
	defer leader.Subscribe(func(ev credential.Event) { leaderEvents <- ev })()
	defer follower.Subscribe(func(ev credential.Event) { followerEvents <- ev })()

	leader.Start(200 * time.Millisecond)
	waitLeaseHeld(t, coord)
	follower.Start(200 * time.Millisecond)

	importDue(t, leader, idp, "first")
	ev := awaitRefresh(t, leaderEvents)
	assert.Equal(t, "first", ev.Ref.Name)
	select {
	case ev := <-followerEvents:
		t.Fatalf("the follower refreshed while the leader held the lease: %+v", ev)
	default:
	}

	require.NoError(t, leader.Close(), "closing releases the leadership lease")
	importDue(t, follower, idp, "second")
	ev = awaitRefresh(t, followerEvents)
	assert.Equal(t, "second", ev.Ref.Name)
}

func waitLeaseHeld(t *testing.T, coord *qrdbsdk.Coordinator) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		v, err := coord.Get(context.Background(), schedulerLeaseKey)
		require.NoError(t, err)
		if v != nil {
			return
		}
		require.True(t, time.Now().Before(deadline), "no scheduler took the lease")
		timer := time.NewTimer(50 * time.Millisecond)
		<-timer.C
	}
}

func awaitRefresh(t *testing.T, events <-chan credential.Event) credential.Event {
	t.Helper()
	timeout := time.NewTimer(20 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case ev := <-events:
			if ev.Type == credential.EventRefreshed {
				return ev
			}
		case <-timeout.C:
			t.Fatal("no refresh")
			return credential.Event{}
		}
	}
}
