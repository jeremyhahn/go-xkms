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

package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Server wraps the gRPC server with lifecycle management
type Server struct {
	service       *Service
	grpcSrv       *grpc.Server
	listener      net.Listener
	host          string
	port          atomic.Int32
	tlsConfig     *tls.Config
	authenticator auth.Authenticator
	logger        *slog.Logger
	rateLimiter   *ratelimit.Limiter
}

// ServerConfig contains configuration for the gRPC server
type ServerConfig struct {
	// Host is the bind host of the listener. It comes from the daemon's
	// resolved server.host; empty binds all interfaces, dual-stack.
	Host           string
	Port           int
	TLSConfig      *tls.Config
	Authenticator  auth.Authenticator
	Authorizer     *auth.Authorizer
	AuditLogger    audit.Logger
	Logger         *slog.Logger
	EnableLogging  bool
	EnableRecovery bool
	RateLimiter    *ratelimit.Limiter
	XKMSService    *xkms.XKMSService
}

// NewServer creates a new gRPC server
// The server uses the XKMSService in cfg for backend management
func NewServer(cfg *ServerConfig) (*Server, error) {
	// Don't set a default port here - let Port 0 remain 0 for ephemeral ports
	// The port will be set in Start() after the listener is created

	// The authenticator is mandatory. Substituting a NoOp authenticator for a
	// missing one would silently disable authentication for every RPC, so an
	// omitted authenticator is an error: selecting auth.NewNoOpAuthenticator()
	// must always be an explicit caller decision.
	authenticator := cfg.Authenticator
	if authenticator == nil {
		return nil, ErrAuthenticatorRequired
	}

	// Set up logger (default to stdlib if not provided)
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	// Create service with authorizer, audit logger, and xkms service
	service := NewService(cfg.Authorizer, cfg.AuditLogger, cfg.XKMSService)

	// Create server instance for interceptor access
	server := &Server{
		service:       service,
		host:          cfg.Host,
		tlsConfig:     cfg.TLSConfig,
		authenticator: authenticator,
		logger:        log,
		rateLimiter:   cfg.RateLimiter,
	}
	server.port.Store(int32(cfg.Port))

	// Build interceptors
	var unaryInterceptors []grpc.UnaryServerInterceptor
	var streamInterceptors []grpc.StreamServerInterceptor

	// Correlation interceptor (first to establish correlation ID for tracing)
	unaryInterceptors = append(unaryInterceptors, server.correlationUnaryInterceptor)
	streamInterceptors = append(streamInterceptors, server.correlationStreamInterceptor)

	// Rate limiting interceptor (early to prevent abuse before other processing)
	if cfg.RateLimiter != nil && cfg.RateLimiter.IsEnabled() {
		unaryInterceptors = append(unaryInterceptors, ratelimit.UnaryServerInterceptor(cfg.RateLimiter))
		streamInterceptors = append(streamInterceptors, ratelimit.StreamServerInterceptor(cfg.RateLimiter))
		log.Info("Rate limiting enabled for gRPC")
	}

	// Metrics interceptor (second to track all requests)
	unaryInterceptors = append(unaryInterceptors, metrics.GRPCUnaryServerInterceptor())
	streamInterceptors = append(streamInterceptors, metrics.GRPCStreamServerInterceptor())

	// Authentication interceptor (third to establish identity)
	unaryInterceptors = append(unaryInterceptors, server.authenticationUnaryInterceptor)
	streamInterceptors = append(streamInterceptors, server.authenticationStreamInterceptor)

	// Tenant enforcement interceptor (after authentication to use identity)
	unaryInterceptors = append(unaryInterceptors, server.tenantUnaryInterceptor)
	streamInterceptors = append(streamInterceptors, server.tenantStreamInterceptor)

	// Logging interceptor
	if cfg.EnableLogging {
		unaryInterceptors = append(unaryInterceptors, server.loggingUnaryInterceptor)
		streamInterceptors = append(streamInterceptors, server.loggingStreamInterceptor)
	}

	// Recovery interceptor (always enabled for production safety)
	if cfg.EnableRecovery {
		unaryInterceptors = append(unaryInterceptors, server.recoveryUnaryInterceptor)
		streamInterceptors = append(streamInterceptors, server.recoveryStreamInterceptor)
	}

	// Error handling interceptor
	unaryInterceptors = append(unaryInterceptors, server.errorHandlingUnaryInterceptor)
	streamInterceptors = append(streamInterceptors, server.errorHandlingStreamInterceptor)

	// Create gRPC server options
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	}

	// Add TLS credentials if configured
	if cfg.TLSConfig != nil {
		creds := credentials.NewTLS(cfg.TLSConfig)
		opts = append(opts, grpc.Creds(creds))
	}

	// Create gRPC server with options
	grpcSrv := grpc.NewServer(opts...)

	// Register service
	pb.RegisterKeystoreServiceServer(grpcSrv, service)

	server.grpcSrv = grpcSrv

	return server, nil
}

// Start starts the gRPC server on the configured host and port. Port 0
// selects an ephemeral port, which Port reports once the listener is bound.
func (s *Server) Start() error {
	addr := net.JoinHostPort(s.host, strconv.Itoa(int(s.port.Load())))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return &errs.Wrapped{Msg: fmt.Sprintf("failed to listen on %s", addr), Err: err}
	}

	s.listener = listener

	// Update port with actual listener port (important for ephemeral ports)
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		s.port.Store(int32(tcpAddr.Port))
	}

	actualPort := int(s.port.Load())
	if s.tlsConfig != nil {
		s.logger.Info("Starting gRPC server with TLS",
			slog.Int("port", actualPort),
			slog.String("auth", s.authenticator.Name()))
	} else {
		s.logger.Info("Starting gRPC server",
			slog.Int("port", actualPort),
			slog.String("auth", s.authenticator.Name()))
	}

	if err := s.grpcSrv.Serve(listener); err != nil {
		return &errs.Wrapped{Msg: "failed to serve", Err: err}
	}

	return nil
}

// Stop gracefully stops the gRPC server
func (s *Server) Stop() error {
	s.logger.Info("Stopping gRPC server")

	// Graceful stop with timeout
	stopped := make(chan struct{})
	go func() {
		s.grpcSrv.GracefulStop()
		close(stopped)
	}()

	// Wait for graceful stop or force stop after timeout
	select {
	case <-stopped:
		s.logger.Info("gRPC server stopped gracefully")
	case <-time.After(30 * time.Second):
		s.logger.Warn("Forcing gRPC server stop after timeout")
		s.grpcSrv.Stop()
	}

	// Close the xkms service
	if err := xkms.Close(); err != nil {
		s.logger.Error("Failed to close xkms service", slog.String("error", err.Error()))
		return &errs.Wrapped{Msg: "failed to close xkms service", Err: err}
	}

	return nil
}

// Port returns the port the server is listening on
func (s *Server) Port() int {
	return int(s.port.Load())
}

// Interceptors

// authenticationUnaryInterceptor authenticates unary RPC calls
func (s *Server) authenticationUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Extract metadata from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.MD{}
	}

	// Authenticate the request
	identity, err := s.authenticator.AuthenticateGRPC(ctx, md)
	if err != nil {
		s.logger.Warn("Authentication failed",
			slog.String("method", info.FullMethod),
			slog.String("error", err.Error()))
		return nil, status.Error(codes.Unauthenticated, errAuthenticationFailed)
	}

	// Store identity in context
	ctx = auth.WithIdentity(ctx, identity)

	return handler(ctx, req)
}

// authenticationStreamInterceptor authenticates streaming RPC calls
func (s *Server) authenticationStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	// Extract metadata from context
	md, ok := metadata.FromIncomingContext(ss.Context())
	if !ok {
		md = metadata.MD{}
	}

	// Authenticate the request
	identity, err := s.authenticator.AuthenticateGRPC(ss.Context(), md)
	if err != nil {
		s.logger.Warn("Authentication failed",
			slog.String("method", info.FullMethod),
			slog.String("error", err.Error()))
		return status.Error(codes.Unauthenticated, errAuthenticationFailed)
	}

	// Store identity in context and wrap the stream
	ctx := auth.WithIdentity(ss.Context(), identity)
	wrappedStream := &authenticatedServerStream{
		ServerStream: ss,
		ctx:          ctx,
	}

	return handler(srv, wrappedStream)
}

// authenticatedServerStream wraps ServerStream with an authenticated context
type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}

// loggingUnaryInterceptor logs unary RPC calls
func (s *Server) loggingUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	start := time.Now()

	// Get identity from context if available
	identity := auth.GetIdentity(ctx)
	subject := "anonymous"
	if identity != nil {
		subject = identity.Subject
	}

	// Use context-aware logging to include correlation ID
	s.logger.DebugContext(ctx, "RPC started",
		slog.String("method", info.FullMethod),
		slog.String("subject", subject))

	// Call the handler
	resp, err := handler(ctx, req)

	// Log the call
	duration := time.Since(start)
	statusCode := codes.OK
	if err != nil {
		if st, ok := status.FromError(err); ok {
			statusCode = st.Code()
		}
	}

	s.logger.InfoContext(ctx, "RPC completed",
		slog.String("method", info.FullMethod),
		slog.String("duration", duration.String()),
		slog.String("code", statusCode.String()),
		slog.String("subject", subject))

	return resp, err
}

// loggingStreamInterceptor logs streaming RPC calls
func (s *Server) loggingStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	start := time.Now()
	ctx := ss.Context()

	// Get identity from context if available
	identity := auth.GetIdentity(ctx)
	subject := "anonymous"
	if identity != nil {
		subject = identity.Subject
	}

	// Use context-aware logging to include correlation ID
	s.logger.DebugContext(ctx, "Stream started",
		slog.String("method", info.FullMethod),
		slog.String("subject", subject))

	// Call the handler
	err := handler(srv, ss)

	// Log the call
	duration := time.Since(start)
	statusCode := codes.OK
	if err != nil {
		if st, ok := status.FromError(err); ok {
			statusCode = st.Code()
		}
	}

	s.logger.InfoContext(ctx, "Stream completed",
		slog.String("method", info.FullMethod),
		slog.String("duration", duration.String()),
		slog.String("code", statusCode.String()),
		slog.String("subject", subject))

	return err
}

// recoveryUnaryInterceptor recovers from panics in unary RPC handlers
func (s *Server) recoveryUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (resp interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("Recovered from panic",
				slog.String("method", info.FullMethod),
				slog.Any("panic", r))
			err = status.Errorf(codes.Internal, "internal server error")
		}
	}()

	return handler(ctx, req)
}

// recoveryStreamInterceptor recovers from panics in streaming RPC handlers
func (s *Server) recoveryStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("Recovered from panic in stream",
				slog.String("method", info.FullMethod),
				slog.Any("panic", r))
			err = status.Errorf(codes.Internal, "internal server error")
		}
	}()

	return handler(srv, ss)
}

// errorHandlingUnaryInterceptor normalizes error responses. It is a Server
// method (rather than a free function) so it can pass s.service.xkmsService
// through to notLeaderStatus, which needs it to resolve the leader's dialable
// gRPC endpoint for a not-leader redirect.
func (s *Server) errorHandlingUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	resp, err := handler(ctx, req)

	if err != nil {
		// Clustered not-leader writes get a dedicated FailedPrecondition status
		// carrying the leader coordinates so the client can retry on the leader.
		if translated, ok := notLeaderStatus(ctx, s.service.xkmsService, err); ok {
			return resp, translated
		}
		err = s.scrubInternalError(err, info.FullMethod)
	}

	return resp, err
}

// errorHandlingStreamInterceptor normalizes error responses for streams. See
// errorHandlingUnaryInterceptor for why this is a Server method.
func (s *Server) errorHandlingStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	err := handler(srv, ss)

	if err != nil {
		// Clustered not-leader writes get a dedicated FailedPrecondition status
		// carrying the leader coordinates so the client can retry on the leader.
		if translated, ok := notLeaderStatus(ss.Context(), s.service.xkmsService, err); ok {
			return translated
		}
		err = s.scrubInternalError(err, info.FullMethod)
	}

	return err
}

// scrubbedErrorMessage is the fixed text a client receives in place of an
// internal error's own message. It mirrors REST's ErrInternalError wire text
// (pkg/api/rest/errors.go) so both transports report the same signal to a
// caller when the server withholds detail.
const scrubbedErrorMessage = "internal error"

// scrubInternalError withholds internal detail from a gRPC error response.
// A non-status error -- a handler or a lower layer returned a plain Go error
// instead of a *status.Status -- is converted to codes.Internal, matching
// this interceptor's previous behavior. A status error whose code is
// codes.Internal or codes.Unknown has its message replaced, keeping its
// original code; every RPC handler in this package that builds
// status.Errorf(codes.Internal, "...: %v", err) (mapBarrierError,
// mapPINError, mapKeyOpError's floor, and the rest) is scrubbed here, in one
// place, rather than at each of those call sites. A status error carrying a
// client-facing code (InvalidArgument, NotFound, PermissionDenied, and so on)
// is returned unchanged: those messages are written for the caller.
//
// Either way the original err is logged at Error level with the RPC's full
// method name, so the detail a storage path, a backend message, a barrier
// state reaches the operator through s.logger and never the client
// (go-xkms#1258, mirroring pkg/api/rest/errors.go's clientErrorText and
// pkg/api/mcp/errors_keyops.go's ClientError).
func (s *Server) scrubInternalError(err error, method string) error {
	st, ok := status.FromError(err)
	if ok && st.Code() != codes.Internal && st.Code() != codes.Unknown {
		return err
	}

	logger := s.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Error("grpc: internal error withheld from client",
		slog.String("method", method),
		slog.Any("error", err))

	if !ok {
		return status.Error(codes.Internal, scrubbedErrorMessage)
	}
	return status.Error(st.Code(), scrubbedErrorMessage)
}
