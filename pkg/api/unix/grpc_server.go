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

// Package unix provides Unix domain socket servers for local IPC.
package unix

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"google.golang.org/grpc"
	"google.golang.org/grpc/stats"

	grpcinternal "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/peercred"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// DefaultSocketPath is the default path for the Unix socket
const DefaultSocketPath = "/var/run/xkms/xkms.sock"

// connTrackerKey is the stats.Handler connection context key connMetricsHandler
// stashes its metrics.ConnectionTracker under between TagConn and HandleConn.
type connTrackerKey struct{}

// connMetricsHandler is a grpc.StatsHandler that tracks the unix listener's
// active connections (metrics.ProtocolUnix) through metrics.ConnectionTracker.
// It implements only the connection-lifecycle half of stats.Handler
// (TagConn/HandleConn); the RPC half (TagRPC/HandleRPC) is a required no-op
// passthrough -- per-RPC accounting on this listener is
// TenantUnaryInterceptor/TenantStreamInterceptor's job, not this handler's.
type connMetricsHandler struct{}

// TagRPC is a no-op passthrough; connMetricsHandler only tracks connections.
func (connMetricsHandler) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

// HandleRPC is a no-op; connMetricsHandler only tracks connections.
func (connMetricsHandler) HandleRPC(context.Context, stats.RPCStats) {}

// TagConn starts a ConnectionTracker for the new connection and stashes it
// in the context HandleConn receives when the connection ends.
func (connMetricsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return context.WithValue(ctx, connTrackerKey{}, metrics.NewConnectionTracker(metrics.ProtocolUnix))
}

// HandleConn closes the connection's tracker on stats.ConnEnd, decrementing
// the active-connections gauge. Every other stats.ConnStats variant
// (currently only stats.ConnBegin, already accounted for by TagConn's
// NewConnectionTracker call) is ignored.
func (connMetricsHandler) HandleConn(ctx context.Context, cs stats.ConnStats) {
	if _, ok := cs.(*stats.ConnEnd); !ok {
		return
	}
	if tracker, ok := ctx.Value(connTrackerKey{}).(*metrics.ConnectionTracker); ok {
		tracker.Close()
	}
}

// GRPCConfig holds the gRPC Unix socket server configuration
type GRPCConfig struct {
	// SocketPath is the path to the Unix socket file
	SocketPath string

	// SocketMode is the file mode for the socket (default: 0660)
	SocketMode os.FileMode

	// AllowedUIDs extends the accept-time peer-credential check
	// (PeerCredentialPolicy) beyond its defaults -- the daemon's own uid and
	// root (uid 0) -- with additional uids permitted to connect. Optional;
	// nil admits only the defaults.
	AllowedUIDs []uint32

	// AllowedGIDs extends PeerCredentialPolicy by primary group, evaluated
	// the same way as AllowedUIDs. Optional; nil admits only the defaults.
	AllowedGIDs []uint32

	// Logger is the logging adapter
	Logger *slog.Logger

	// MaxRecvMsgSize is the maximum message size the server can receive (default: 4MB)
	MaxRecvMsgSize int

	// MaxSendMsgSize is the maximum message size the server can send (default: 4MB)
	MaxSendMsgSize int

	// ConnectionTimeout is the maximum duration for connection establishment
	ConnectionTimeout time.Duration

	// MaxConcurrentStreams is the maximum number of concurrent streams per connection
	MaxConcurrentStreams uint32

	// XKMSService is the composed XKMS service injected by the composition
	// root. It is forwarded to the keystore gRPC service; when nil the
	// service reports ErrNotInitialized on every operation.
	XKMSService *xkms.XKMSService

	// SSHClient is the shared SSH SDK client forwarded to the keystore gRPC
	// service so SSH RPCs are served over the unix socket. Optional; when nil
	// the SSH RPCs return codes.Unavailable.
	SSHClient sdkssh.Client

	// CA is the CA servicer forwarded to the keystore gRPC service (via
	// grpcinternal.Service.SetCA) so CA RPCs (GetCACertificate, SignCSR,
	// IssueCertificate, the TCG EK/AK/enroll variants, ...) are served over
	// the unix socket. Optional; when nil those RPCs return
	// codes.Unavailable, mirroring the REST transport's Config.CA gate
	// (go-xkms#951).
	CA any

	// CABundler optionally overrides how the keystore gRPC service's
	// GetCABundle resolves its response (via
	// grpcinternal.Service.SetCABundler). When nil, GetCABundle falls back
	// to the CA servicer's own GetCABundle method (see CA above).
	CABundler grpcinternal.CABundler

	// BarrierRegistry gates per-request tenant access the same way the
	// network gRPC, REST, QUIC, and MCP transports do (see
	// pkg/api/tenantgate). Unlike the network gRPC server -- which resolves
	// the registry per call from grpcinternal.GetBarrierRegistry() so it can
	// be reconfigured after that server starts -- this listener captures the
	// registry once at construction time: the Unix socket is brought up by
	// the same composition root that already holds the final
	// *seal.BarrierRegistry, so there is no later reconfiguration to track.
	// Nil disables tenant enforcement.
	BarrierRegistry *seal.BarrierRegistry

	// ExtraServices are additional gRPC service registration hooks invoked on
	// this listener's *grpc.Server after the keystore service registers. The
	// composition root uses this to host the embedded qrdb node's own
	// control-plane services (cluster admin, rebalance, user auth factors) on
	// the unix socket without this package importing qrdb.
	ExtraServices []func(*grpc.Server)
}

// GRPCServer represents a gRPC server listening on a Unix domain socket
type GRPCServer struct {
	config   *GRPCConfig
	server   *grpc.Server
	listener net.Listener
	logger   *slog.Logger
	mu       sync.RWMutex

	// stopped records that Stop ran. Start checks it under mu before
	// serving so a Stop that races ahead of Start (before s.server is
	// assigned) still prevents the server from starting; without this,
	// Stop would find a nil server, do nothing, and the subsequent
	// Serve would block forever with nothing left to stop it.
	stopped bool
}

// NewGRPCServer creates a new gRPC Unix socket server
func NewGRPCServer(cfg *GRPCConfig) (*GRPCServer, error) {
	if cfg == nil {
		return nil, &errs.Message{Msg: "config is required"}
	}

	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath
	}

	if cfg.SocketMode == 0 {
		cfg.SocketMode = 0660
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	if cfg.MaxRecvMsgSize == 0 {
		cfg.MaxRecvMsgSize = 4 * 1024 * 1024 // 4MB default
	}

	if cfg.MaxSendMsgSize == 0 {
		cfg.MaxSendMsgSize = 4 * 1024 * 1024 // 4MB default
	}

	if cfg.ConnectionTimeout == 0 {
		cfg.ConnectionTimeout = 120 * time.Second
	}

	if cfg.MaxConcurrentStreams == 0 {
		cfg.MaxConcurrentStreams = 100
	}

	s := &GRPCServer{
		config: cfg,
		logger: cfg.Logger,
	}

	return s, nil
}

// Start starts the gRPC Unix socket server
func (s *GRPCServer) Start() error {
	// The kernel peer-credential check below (peercred.FromConn, via
	// peerCredentialTransport) is this listener's only gate now that the
	// keystore service registers with grpcinternal.WithLocalTrust (RBAC
	// off): refuse to start on a platform this project has not verified a
	// kernel peer-credential mechanism for, rather than silently serving
	// every peer unauthenticated.
	if err := peercred.CheckSupport(); err != nil {
		return &errs.Wrapped{Msg: "peer credential support required for Unix socket listener", Err: err}
	}

	// An existing socket directory must already be privately owned by this
	// process: its mode is what stands between an unrelated user replacing
	// the socket pathname and this daemon binding it (see sockdir.go).
	socketDir := filepath.Dir(s.config.SocketPath)
	if err := validateSocketDir(socketDir); err != nil {
		return err
	}

	// Ensure the socket directory exists
	if err := os.MkdirAll(socketDir, 0750); err != nil {
		return &errs.Wrapped{Msg: "failed to create socket directory", Err: err}
	}

	// Remove existing socket file if present
	if err := os.Remove(s.config.SocketPath); err != nil && !os.IsNotExist(err) {
		return &errs.Wrapped{Msg: "failed to remove existing socket", Err: err}
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", s.config.SocketPath)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to create Unix socket listener", Err: err}
	}
	s.listener = listener

	// Set socket permissions
	if err := os.Chmod(s.config.SocketPath, s.config.SocketMode); err != nil {
		closeErr := s.listener.Close()
		return errors.Join(&errs.Wrapped{Msg: "failed to set socket permissions", Err: err}, closeErr)
	}

	s.logger.Info("gRPC Unix socket created", slog.String("path", s.config.SocketPath))

	// Create gRPC server with options. The tenant interceptors are the same
	// constructors the network gRPC server uses (see
	// pkg/api/grpc/interceptor_tenant.go); the Unix socket has no
	// authentication interceptor and therefore ordinarily carries no
	// identity, so tenant scoping is a no-op passthrough unless a caller
	// context ever carries one -- kept for parity with every other transport
	// rather than because a nil identity needs gating today.
	peerPolicy := NewPeerCredentialPolicy(s.config.AllowedUIDs, s.config.AllowedGIDs)
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(s.config.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(s.config.MaxSendMsgSize),
		grpc.ConnectionTimeout(s.config.ConnectionTimeout),
		grpc.MaxConcurrentStreams(s.config.MaxConcurrentStreams),
		// Refuses any peer whose kernel-verified uid/gid is not the daemon's
		// own, root, or configured (AllowedUIDs/AllowedGIDs) -- at accept
		// time, before this listener's WithLocalTrust (RBAC off) keystore
		// service would otherwise trust the connection on file mode alone.
		grpc.Creds(newPeerCredentialTransport(peerPolicy)),
		grpc.ChainUnaryInterceptor(grpcinternal.TenantUnaryInterceptor(s.config.BarrierRegistry, s.logger)),
		grpc.ChainStreamInterceptor(grpcinternal.TenantStreamInterceptor(s.config.BarrierRegistry, s.logger)),
		// Tracks this listener's active connections (go-xkms#720): the unix
		// socket has no per-request middleware chain the way REST and network
		// gRPC do (metrics.HTTPMiddleware, metrics.GRPCUnaryServerInterceptor),
		// so connection lifecycle is the only point at which to count it.
		grpc.StatsHandler(connMetricsHandler{}),
	}

	s.mu.Lock()
	if s.stopped {
		// Stop already ran; do not start serving a listener nothing can
		// stop. Release the socket and return as a clean shutdown.
		s.mu.Unlock()
		if err := listener.Close(); err != nil {
			s.logger.Warn("Failed to close listener during shutdown race", slog.String("error", err.Error()))
		}
		if err := os.Remove(s.config.SocketPath); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("Failed to remove socket file", slog.String("error", err.Error()))
		}
		return nil
	}
	s.server = grpc.NewServer(opts...)

	// Register the keystore service with the injected XKMS service. The nil
	// authorizer disables RBAC the way every other RPC on this listener
	// already treats it; WithLocalTrust makes that explicit for privileged
	// RPCs, whose fail-closed policy would otherwise deny them outright on a
	// nil authorizer. This listener's trust boundary is the Unix socket's
	// file mode and directory permissions, not RBAC.
	service := grpcinternal.NewService(nil, nil, s.config.XKMSService, grpcinternal.WithLocalTrust())
	service.SetSSHClient(s.config.SSHClient)
	service.SetCA(s.config.CA)
	service.SetCABundler(s.config.CABundler)
	pb.RegisterKeystoreServiceServer(s.server, service)

	// Composition-root service registrations (e.g. the embedded qrdb node's
	// control plane) attach to the same server, after the keystore service. The
	// trust boundary is the same socket file mode noted above.
	for _, register := range s.config.ExtraServices {
		register(s.server)
	}
	s.mu.Unlock()

	s.logger.Info("Starting gRPC Unix socket server", slog.String("socket", s.config.SocketPath))

	// Start serving
	if err := s.server.Serve(s.listener); err != nil {
		return &errs.Wrapped{Msg: "gRPC Unix socket server error", Err: err}
	}

	return nil
}

// Stop gracefully stops the gRPC Unix socket server
func (s *GRPCServer) Stop(ctx context.Context) error {
	s.logger.Info("Stopping gRPC Unix socket server...")

	s.mu.Lock()
	s.stopped = true
	srv := s.server
	s.mu.Unlock()

	if srv != nil {
		// Create a channel to signal when graceful stop completes
		stopped := make(chan struct{})

		go func() {
			srv.GracefulStop()
			close(stopped)
		}()

		// Wait for graceful stop or context cancellation
		select {
		case <-stopped:
			s.logger.Info("gRPC server stopped gracefully")
		case <-ctx.Done():
			s.logger.Warn("gRPC server graceful stop timeout, forcing shutdown")
			srv.Stop()
		}
	}

	// Remove socket file
	if err := os.Remove(s.config.SocketPath); err != nil && !os.IsNotExist(err) {
		s.logger.Warn("Failed to remove socket file", slog.String("error", err.Error()))
	}

	s.logger.Info("gRPC Unix socket server stopped")
	return nil
}

// SocketPath returns the path to the Unix socket
func (s *GRPCServer) SocketPath() string {
	return s.config.SocketPath
}

// GRPCServer returns the underlying gRPC server instance
func (s *GRPCServer) GRPCServer() *grpc.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.server
}
