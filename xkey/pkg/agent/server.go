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
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/stats"
)

const (
	// maxConnectedAgents caps the number of entries the server keeps in its
	// connected-agent table. Without mTLS every connection is its own entry,
	// so the cap is what stops a network peer from growing the table by
	// reconnecting from fresh source ports.
	maxConnectedAgents = 1024

	// agentIdleTimeout is how long an entry may go without an RPC before it
	// becomes eligible for eviction when the table is full.
	agentIdleTimeout = 10 * time.Minute
)

// ConnectedAgent tracks an active agent connection on the server side.
type ConnectedAgent struct {
	// Info holds the enrollment details of the connected agent.
	Info *AgentInfo

	// ConnectedAt is the time the connection was established.
	ConnectedAt time.Time

	// LastActivity is the time of the most recent RPC from this agent.
	LastActivity time.Time

	// conns counts the open gRPC connections bound to this entry. The entry
	// is removed when the last of them closes.
	conns int
}

// connTagKey is the context key under which connTracker stores a
// connection's *connTag.
type connTagKey struct{}

// connTag binds one gRPC connection to the connected-agent entry its RPCs
// were recorded against, so the entry can be released when the connection
// closes. Its fields are guarded by Server.mu.
type connTag struct {
	key   string
	entry *ConnectedAgent
}

// Server is the master-side agent server that accepts mTLS connections
// from enrolled remote agents and proxies their requests to local xKey
// services. Thread-safe.
type Server struct {
	config     *Config
	enrollment *EnrollmentService
	logger     *slog.Logger
	listener   net.Listener
	grpcServer *grpc.Server
	agents     map[string]*ConnectedAgent
	mu         sync.RWMutex
	running    atomic.Bool
	done       chan struct{}
}

// NewServer creates a new agent server. Returns an error if any required
// parameter is nil.
func NewServer(cfg *Config, enrollment *EnrollmentService, logger *slog.Logger) (*Server, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	if enrollment == nil {
		return nil, ErrNilEnrollmentService
	}
	if logger == nil {
		return nil, ErrNilLogger
	}
	return &Server{
		config:     cfg,
		enrollment: enrollment,
		logger:     logger,
		agents:     make(map[string]*ConnectedAgent),
		done:       make(chan struct{}),
	}, nil
}

// Start begins listening for agent connections. If TLS credentials are
// configured, the server uses mTLS. Otherwise, it listens in plaintext
// (for development/testing only).
func (s *Server) Start() error {
	if s.running.Load() {
		return ErrServerAlreadyRunning
	}

	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		return &AgentError{Operation: "start_server", Err: err}
	}

	var listener net.Listener
	if tlsConfig != nil {
		listener, err = tls.Listen("tcp", s.config.ListenAddress, tlsConfig)
	} else {
		listener, err = net.Listen("tcp", s.config.ListenAddress)
	}
	if err != nil {
		return &AgentError{Operation: "start_server", Err: err}
	}

	var grpcOpts []grpc.ServerOption
	if tlsConfig != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// Track agents per RPC (interceptor) and release them when their
	// connection closes (stats handler).
	grpcOpts = append(grpcOpts,
		grpc.UnaryInterceptor(s.trackingUnaryInterceptor),
		grpc.StatsHandler(connTracker{server: s}))

	grpcServer := grpc.NewServer(grpcOpts...)

	s.mu.Lock()
	s.listener = listener
	s.grpcServer = grpcServer
	s.done = make(chan struct{})
	s.mu.Unlock()

	s.running.Store(true)
	s.logger.Info("agent server started",
		"address", s.config.ListenAddress,
		"tls", tlsConfig != nil)

	// Serve in a goroutine so Start returns immediately.
	go func() {
		if serveErr := grpcServer.Serve(listener); serveErr != nil {
			if s.running.Load() {
				s.logger.Error("agent server error", "error", serveErr)
			}
		}
		close(s.done)
	}()

	return nil
}

// Stop gracefully shuts down the server, closing all active connections.
func (s *Server) Stop() error {
	if !s.running.CompareAndSwap(true, false) {
		return ErrServerNotStarted
	}

	s.logger.Info("stopping agent server")

	s.mu.RLock()
	grpcServer := s.grpcServer
	s.mu.RUnlock()

	if grpcServer != nil {
		grpcServer.GracefulStop()
	}

	// Wait for the serve goroutine to finish.
	<-s.done

	s.mu.Lock()
	s.agents = make(map[string]*ConnectedAgent)
	s.listener = nil
	s.grpcServer = nil
	s.mu.Unlock()

	s.logger.Info("agent server stopped")
	return nil
}

// ConnectedAgents returns a snapshot of all currently connected agents.
// The returned values are copies: later activity does not change them.
func (s *Server) ConnectedAgents() []*ConnectedAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ConnectedAgent, 0, len(s.agents))
	for _, ca := range s.agents {
		snapshot := *ca
		info := *ca.Info
		snapshot.Info = &info
		result = append(result, &snapshot)
	}
	return result
}

// IsRunning reports whether the server is currently accepting connections.
func (s *Server) IsRunning() bool {
	return s.running.Load()
}

// Addr returns the listener address, or empty string if not started.
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// trackingUnaryInterceptor is a gRPC unary interceptor that tracks agent
// connections and updates last-activity timestamps.
func (s *Server) trackingUnaryInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	if p, ok := peer.FromContext(ctx); ok {
		tag, _ := ctx.Value(connTagKey{}).(*connTag)
		s.recordActivity(tag, peerAgentID(p), p.Addr.String())
	}
	return handler(ctx, req)
}

// peerAgentID returns the enrolled agent ID of an mTLS peer: the public-key
// fingerprint of its verified client certificate, the same identifier the
// enrollment store keys agents on. It returns "" for a peer that did not
// present a verified certificate.
func peerAgentID(p *peer.Peer) string {
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.PeerCertificates) == 0 {
		return ""
	}
	id, err := publicKeyFingerprint(tlsInfo.State.PeerCertificates[0].PublicKey)
	if err != nil {
		return ""
	}
	return id
}

// recordActivity records an RPC from the peer at addr. An authenticated
// peer is tracked under its agent ID, so its reconnections share one entry;
// an unauthenticated peer is tracked per connection under its address. The
// connection's tag is bound to the entry so connectionClosed can release it.
//
// The table never grows beyond maxConnectedAgents: when it is full, idle
// entries are evicted, and if none are idle the activity goes untracked.
func (s *Server) recordActivity(tag *connTag, agentID, addr string) {
	key := addr
	if agentID != "" {
		key = agentID
	}
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	ca, ok := s.agents[key]
	if !ok {
		if len(s.agents) >= maxConnectedAgents {
			s.evictIdleLocked(now)
		}
		if len(s.agents) >= maxConnectedAgents {
			s.logger.Warn("connected-agent table full; activity not tracked",
				"address", addr,
				"limit", maxConnectedAgents)
			return
		}
		ca = &ConnectedAgent{
			Info: &AgentInfo{
				ID:     agentID,
				Status: "connected",
			},
			ConnectedAt: now,
		}
		s.agents[key] = ca
	}

	ca.LastActivity = now
	ca.Info.Address = addr
	ca.Info.LastSeen = now

	if tag != nil && tag.entry != ca {
		tag.key = key
		tag.entry = ca
		ca.conns++
	}
}

// evictIdleLocked removes every entry with no RPC for agentIdleTimeout.
// The caller must hold s.mu for writing.
func (s *Server) evictIdleLocked(now time.Time) {
	for key, ca := range s.agents {
		if now.Sub(ca.LastActivity) > agentIdleTimeout {
			delete(s.agents, key)
		}
	}
}

// connectionClosed releases the connection's hold on the entry it was bound
// to, removing the entry once no open connection holds it. An entry that
// was evicted or replaced since the binding is left alone.
func (s *Server) connectionClosed(tag *connTag) {
	if tag == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if tag.entry == nil || s.agents[tag.key] != tag.entry {
		return
	}
	tag.entry.conns--
	if tag.entry.conns <= 0 {
		delete(s.agents, tag.key)
	}
	tag.entry = nil
}

// connTracker is the gRPC stats handler that tells the Server when an agent
// connection closes. It tags each connection's context with a *connTag that
// the tracking interceptor binds on the connection's first RPC.
type connTracker struct {
	server *Server
}

var _ stats.Handler = connTracker{}

// TagRPC returns ctx unchanged; RPCs are tracked by the interceptor.
func (connTracker) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

// HandleRPC ignores per-RPC stats.
func (connTracker) HandleRPC(context.Context, stats.RPCStats) {}

// TagConn attaches a fresh, unbound *connTag to the connection's context.
func (connTracker) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return context.WithValue(ctx, connTagKey{}, &connTag{})
}

// HandleConn releases the connection's tracked entry when it ends.
func (t connTracker) HandleConn(ctx context.Context, cs stats.ConnStats) {
	if _, ok := cs.(*stats.ConnEnd); !ok {
		return
	}
	tag, _ := ctx.Value(connTagKey{}).(*connTag)
	t.server.connectionClosed(tag)
}

// buildTLSConfig creates a TLS configuration for the server. Returns nil
// if no TLS files are configured (plaintext mode).
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	if s.config.TLSCertFile == "" || s.config.TLSKeyFile == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// If a CA file is configured, require and verify client certificates (mTLS).
	if s.config.TLSCAFile != "" {
		caCert, err := os.ReadFile(s.config.TLSCAFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, ErrCertificateInvalid
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.VerifyPeerCertificate = s.verifyPeerCertificate
	}

	return tlsConfig, nil
}

// verifyPeerCertificate runs after Go's TLS stack has already verified the
// connecting agent's certificate chains to a trusted CA (tls.Config.ClientCAs).
// It adds the two checks chain validation alone cannot make: that the
// certificate has not been revoked, and that it belongs to an agent still
// present in the enrollment store (a removed agent has no record there,
// regardless of what its certificate says). Both checks are delegated to
// EnrollmentService.VerifyAgentCertificate, which fails closed.
func (s *Server) verifyPeerCertificate(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return ErrCertificateInvalid
	}

	leaf := verifiedChains[0][0]
	if err := s.enrollment.VerifyAgentCertificate(leaf); err != nil {
		s.logger.Warn("rejected agent connection",
			"subject", leaf.Subject.String(),
			"serial", leaf.SerialNumber.Text(16),
			"error", err)
		return err
	}

	return nil
}
