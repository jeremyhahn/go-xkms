// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
	"net"
	"time"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/metrics"
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
	port          int
	tlsConfig     *tls.Config
	authenticator auth.Authenticator
	logger        logger.Logger
}

// ServerConfig contains configuration for the gRPC server
type ServerConfig struct {
	Port           int
	TLSConfig      *tls.Config
	Authenticator  auth.Authenticator
	Logger         logger.Logger
	EnableLogging  bool
	EnableRecovery bool
}

// NewServer creates a new gRPC server
// The server uses the global keychain facade for backend management
func NewServer(cfg *ServerConfig) (*Server, error) {
	// Don't set a default port here - let Port 0 remain 0 for ephemeral ports
	// The port will be set in Start() after the listener is created

	// Set up authenticator (default to NoOp if not provided)
	authenticator := cfg.Authenticator
	if authenticator == nil {
		authenticator = auth.NewNoOpAuthenticator()
	}

	// Set up logger (default to stdlib if not provided)
	log := cfg.Logger
	if log == nil {
		log = logger.NewSlogAdapter(&logger.SlogConfig{
			Level: logger.LevelInfo,
		})
	}

	// Create service
	service := NewService()

	// Create server instance for interceptor access
	server := &Server{
		service:       service,
		port:          cfg.Port,
		tlsConfig:     cfg.TLSConfig,
		authenticator: authenticator,
		logger:        log,
	}

	// Build interceptors
	var unaryInterceptors []grpc.UnaryServerInterceptor
	var streamInterceptors []grpc.StreamServerInterceptor

	// Correlation interceptor (first to establish correlation ID for tracing)
	unaryInterceptors = append(unaryInterceptors, server.correlationUnaryInterceptor)
	streamInterceptors = append(streamInterceptors, server.correlationStreamInterceptor)

	// Metrics interceptor (second to track all requests)
	unaryInterceptors = append(unaryInterceptors, metrics.GRPCUnaryServerInterceptor())
	streamInterceptors = append(streamInterceptors, metrics.GRPCStreamServerInterceptor())

	// Authentication interceptor (third to establish identity)
	unaryInterceptors = append(unaryInterceptors, server.authenticationUnaryInterceptor)
	streamInterceptors = append(streamInterceptors, server.authenticationStreamInterceptor)

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
	unaryInterceptors = append(unaryInterceptors, errorHandlingUnaryInterceptor)
	streamInterceptors = append(streamInterceptors, errorHandlingStreamInterceptor)

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

// Start starts the gRPC server
func (s *Server) Start() error {
	// Use default port 9090 if no port was specified
	port := s.port
	if port == 0 {
		port = 0 // Keep 0 for ephemeral port assignment
	}

	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = listener

	// Update port with actual listener port (important for ephemeral ports)
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		s.port = tcpAddr.Port
	}

	if s.tlsConfig != nil {
		s.logger.Info("Starting gRPC server with TLS",
			logger.Int("port", s.port),
			logger.String("auth", s.authenticator.Name()))
	} else {
		s.logger.Info("Starting gRPC server",
			logger.Int("port", s.port),
			logger.String("auth", s.authenticator.Name()))
	}

	if err := s.grpcSrv.Serve(listener); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
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

	// Close the keychain facade
	if err := keychain.Close(); err != nil {
		s.logger.Error("Failed to close keychain facade", logger.Error(err))
		return fmt.Errorf("failed to close keychain facade: %w", err)
	}

	return nil
}

// Port returns the port the server is listening on
func (s *Server) Port() int {
	return s.port
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
			logger.String("method", info.FullMethod),
			logger.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
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
			logger.String("method", info.FullMethod),
			logger.Error(err))
		return status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
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
	if slogAdapter, ok := s.logger.(*logger.SlogAdapter); ok {
		slogAdapter.DebugContext(ctx, "RPC started",
			logger.String("method", info.FullMethod),
			logger.String("subject", subject))
	} else {
		s.logger.Debug("RPC started",
			logger.String("method", info.FullMethod),
			logger.String("subject", subject))
	}

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

	if slogAdapter, ok := s.logger.(*logger.SlogAdapter); ok {
		slogAdapter.InfoContext(ctx, "RPC completed",
			logger.String("method", info.FullMethod),
			logger.String("duration", duration.String()),
			logger.String("code", statusCode.String()),
			logger.String("subject", subject))
	} else {
		s.logger.Info("RPC completed",
			logger.String("method", info.FullMethod),
			logger.String("duration", duration.String()),
			logger.String("code", statusCode.String()),
			logger.String("subject", subject))
	}

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
	if slogAdapter, ok := s.logger.(*logger.SlogAdapter); ok {
		slogAdapter.DebugContext(ctx, "Stream started",
			logger.String("method", info.FullMethod),
			logger.String("subject", subject))
	} else {
		s.logger.Debug("Stream started",
			logger.String("method", info.FullMethod),
			logger.String("subject", subject))
	}

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

	if slogAdapter, ok := s.logger.(*logger.SlogAdapter); ok {
		slogAdapter.InfoContext(ctx, "Stream completed",
			logger.String("method", info.FullMethod),
			logger.String("duration", duration.String()),
			logger.String("code", statusCode.String()),
			logger.String("subject", subject))
	} else {
		s.logger.Info("Stream completed",
			logger.String("method", info.FullMethod),
			logger.String("duration", duration.String()),
			logger.String("code", statusCode.String()),
			logger.String("subject", subject))
	}

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
				logger.String("method", info.FullMethod),
				logger.Any("panic", r))
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
				logger.String("method", info.FullMethod),
				logger.Any("panic", r))
			err = status.Errorf(codes.Internal, "internal server error")
		}
	}()

	return handler(srv, ss)
}

// errorHandlingUnaryInterceptor normalizes error responses
func errorHandlingUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	resp, err := handler(ctx, req)

	if err != nil {
		// Ensure error is a proper gRPC status error
		if _, ok := status.FromError(err); !ok {
			// Convert non-gRPC errors to Internal errors
			err = status.Errorf(codes.Internal, "internal error: %v", err)
		}
	}

	return resp, err
}

// errorHandlingStreamInterceptor normalizes error responses for streams
func errorHandlingStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	err := handler(srv, ss)

	if err != nil {
		// Ensure error is a proper gRPC status error
		if _, ok := status.FromError(err); !ok {
			// Convert non-gRPC errors to Internal errors
			err = status.Errorf(codes.Internal, "internal error: %v", err)
		}
	}

	return err
}
