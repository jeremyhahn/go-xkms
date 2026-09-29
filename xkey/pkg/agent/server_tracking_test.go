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

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/stats"
)

// trackingConn simulates one gRPC connection: the context the stats
// handler tags, carrying the peer the interceptor reads.
func trackingConn(t *testing.T, server *Server, p *peer.Peer) context.Context {
	t.Helper()
	tracker := connTracker{server: server}
	ctx := tracker.TagConn(context.Background(), &stats.ConnTagInfo{RemoteAddr: p.Addr})
	return peer.NewContext(ctx, p)
}

// callRPC runs one unary RPC through the tracking interceptor.
func callRPC(t *testing.T, server *Server, ctx context.Context) {
	t.Helper()
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	handler := func(context.Context, any) (any, error) { return "ok", nil }
	if _, err := server.trackingUnaryInterceptor(ctx, "request", info, handler); err != nil {
		t.Fatalf("interceptor error: %v", err)
	}
}

// closeConn delivers the connection-end event for ctx.
func closeConn(server *Server, ctx context.Context) {
	connTracker{server: server}.HandleConn(ctx, &stats.ConnEnd{})
}

func tcpAddr(t *testing.T, s string) net.Addr {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatalf("resolve %q: %v", s, err)
	}
	return addr
}

// mTLSPeer returns a peer whose TLS state carries a verified client
// certificate for key.
func mTLSPeer(t *testing.T, key *ecdsa.PrivateKey, addr string) *peer.Peer {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return &peer.Peer{
		Addr: tcpAddr(t, addr),
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
			VerifiedChains:   [][]*x509.Certificate{{cert}},
		}},
	}
}

func TestConnTracking_UnauthenticatedEntryRemovedOnDisconnect(t *testing.T) {
	server := testServer(t)
	ctx := trackingConn(t, server, &peer.Peer{Addr: tcpAddr(t, "192.0.2.10:40000")})

	callRPC(t, server, ctx)
	callRPC(t, server, ctx)
	if got := len(server.ConnectedAgents()); got != 1 {
		t.Fatalf("expected 1 tracked connection, got %d", got)
	}

	closeConn(server, ctx)
	if got := len(server.ConnectedAgents()); got != 0 {
		t.Fatalf("expected the entry to be removed on disconnect, got %d", got)
	}
}

func TestConnTracking_ReconnectsDoNotAccumulate(t *testing.T) {
	server := testServer(t)

	for port := 40000; port < 40100; port++ {
		ctx := trackingConn(t, server, &peer.Peer{Addr: tcpAddr(t, fmt.Sprintf("192.0.2.10:%d", port))})
		callRPC(t, server, ctx)
		closeConn(server, ctx)
	}

	if got := len(server.ConnectedAgents()); got != 0 {
		t.Fatalf("reconnecting peer left %d entries behind", got)
	}
}

func TestConnTracking_AuthenticatedAgentKeyedOnID(t *testing.T) {
	server := testServer(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wantID, err := publicKeyFingerprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	first := trackingConn(t, server, mTLSPeer(t, key, "192.0.2.20:50000"))
	second := trackingConn(t, server, mTLSPeer(t, key, "192.0.2.20:50001"))
	callRPC(t, server, first)
	callRPC(t, server, second)

	agents := server.ConnectedAgents()
	if len(agents) != 1 {
		t.Fatalf("two connections from one agent must share one entry, got %d", len(agents))
	}
	if agents[0].Info.ID != wantID {
		t.Errorf("entry ID = %q, want %q", agents[0].Info.ID, wantID)
	}
	if agents[0].Info.Address != "192.0.2.20:50001" {
		t.Errorf("entry address = %q, want the most recent peer address", agents[0].Info.Address)
	}

	closeConn(server, first)
	if got := len(server.ConnectedAgents()); got != 1 {
		t.Fatalf("entry must survive while a connection is open, got %d", got)
	}
	closeConn(server, second)
	if got := len(server.ConnectedAgents()); got != 0 {
		t.Fatalf("entry must be removed when the last connection closes, got %d", got)
	}
}

func TestConnTracking_UnverifiedCertificateIsNotAnIdentity(t *testing.T) {
	server := testServer(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := mTLSPeer(t, key, "192.0.2.30:50000")
	tlsInfo := p.AuthInfo.(credentials.TLSInfo)
	tlsInfo.State.VerifiedChains = nil
	p.AuthInfo = tlsInfo

	callRPC(t, server, trackingConn(t, server, p))

	agents := server.ConnectedAgents()
	if len(agents) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(agents))
	}
	if agents[0].Info.ID != "" {
		t.Errorf("an unverified certificate must not be trusted as an agent ID, got %q", agents[0].Info.ID)
	}
}

func TestConnTracking_TableIsCapped(t *testing.T) {
	server := testServer(t)

	for i := 0; i < maxConnectedAgents+50; i++ {
		addr := fmt.Sprintf("10.%d.%d.1:4000", i/256, i%256)
		callRPC(t, server, trackingConn(t, server, &peer.Peer{Addr: tcpAddr(t, addr)}))
	}

	if got := len(server.ConnectedAgents()); got != maxConnectedAgents {
		t.Fatalf("table size = %d, want the cap %d", got, maxConnectedAgents)
	}
}

func TestConnTracking_FullTableEvictsIdleEntries(t *testing.T) {
	server := testServer(t)

	for i := 0; i < maxConnectedAgents; i++ {
		server.recordActivity(nil, "", fmt.Sprintf("10.%d.%d.1:4000", i/256, i%256))
	}
	server.mu.Lock()
	for _, ca := range server.agents {
		ca.LastActivity = time.Now().Add(-2 * agentIdleTimeout)
	}
	server.mu.Unlock()

	server.recordActivity(nil, "", "192.0.2.99:4000")

	agents := server.ConnectedAgents()
	if len(agents) != 1 || agents[0].Info.Address != "192.0.2.99:4000" {
		t.Fatalf("expected idle entries evicted and the new peer tracked, got %d entries", len(agents))
	}
}

func TestConnTracking_StaleCloseLeavesNewerEntryAlone(t *testing.T) {
	server := testServer(t)
	stale := trackingConn(t, server, &peer.Peer{Addr: tcpAddr(t, "192.0.2.40:40000")})
	callRPC(t, server, stale)

	// Stop resets the table; the stale connection's end event must not
	// disturb an entry created afterwards under the same key.
	server.mu.Lock()
	server.agents = make(map[string]*ConnectedAgent)
	server.mu.Unlock()
	server.recordActivity(nil, "", "192.0.2.40:40000")

	closeConn(server, stale)
	if got := len(server.ConnectedAgents()); got != 1 {
		t.Fatalf("stale close removed a newer entry: %d entries", got)
	}
}

func TestConnTracking_IgnoresOtherConnStats(t *testing.T) {
	server := testServer(t)
	ctx := trackingConn(t, server, &peer.Peer{Addr: tcpAddr(t, "192.0.2.50:40000")})
	callRPC(t, server, ctx)

	connTracker{server: server}.HandleConn(ctx, &stats.ConnBegin{})
	closeConn(server, context.Background()) // no tag: nothing to release

	if got := len(server.ConnectedAgents()); got != 1 {
		t.Fatalf("only ConnEnd on the tagged connection may release it, got %d entries", got)
	}
}
