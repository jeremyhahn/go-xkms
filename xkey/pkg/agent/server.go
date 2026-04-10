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
)

// ConnectedAgent tracks an active agent connection on the server side.
type ConnectedAgent struct {
	// Info holds the enrollment details of the connected agent.
	Info *AgentInfo

	// ConnectedAt is the time the connection was established.
	ConnectedAt time.Time

	// LastActivity is the time of the most recent RPC from this agent.
	LastActivity time.Time
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

	// Add unary interceptor for connection tracking.
	grpcOpts = append(grpcOpts, grpc.UnaryInterceptor(s.trackingUnaryInterceptor))

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
func (s *Server) ConnectedAgents() []*ConnectedAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ConnectedAgent, 0, len(s.agents))
	for _, ca := range s.agents {
		result = append(result, ca)
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
	// Extract peer info for connection tracking.
	if p, ok := peer.FromContext(ctx); ok {
		s.updateAgentActivity(p.Addr.String())
	}
	return handler(ctx, req)
}

// updateAgentActivity updates the last-activity timestamp for a connected
// agent identified by its address.
func (s *Server) updateAgentActivity(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ca, ok := s.agents[addr]; ok {
		ca.LastActivity = time.Now()
	} else {
		// First time seeing this address; register as connected.
		s.agents[addr] = &ConnectedAgent{
			Info: &AgentInfo{
				Address:  addr,
				LastSeen: time.Now(),
				Status:   "connected",
			},
			ConnectedAt:  time.Now(),
			LastActivity: time.Now(),
		}
	}
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
	}

	return tlsConfig, nil
}
