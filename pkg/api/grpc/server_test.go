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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/correlation"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// discardLogger creates a logger that discards all output
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
}

// setupXKMSForTest initializes the global xkms service for tests
func setupXKMSForTest(t *testing.T) {
	t.Helper()

	// Reset any previous state
	xkms.Reset()

	// Create in-memory storage
	keyStorage := storage.New()
	certStorage := storage.New()

	// Create PKCS8 backend
	backend, err := pkcs8.NewBackend(&pkcs8.Config{
		KeyStorage: keyStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Create keystore
	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     backend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	// Initialize global xkms service
	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"test": ks,
		},
		DefaultBackend: "test",
	})
	if err != nil {
		t.Fatalf("Failed to initialize xkms: %v", err)
	}
}

func TestNewServer(t *testing.T) {
	t.Run("creates server with default config", func(t *testing.T) {
		setupXKMSForTest(t)
		defer xkms.Reset()

		cfg := &ServerConfig{
			Port:   0,
			Logger: discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		if server == nil {
			t.Fatal("Expected non-nil server")
		}
		if server.service == nil {
			t.Error("Expected service to be set")
		}
		if server.grpcSrv == nil {
			t.Error("Expected gRPC server to be set")
		}
		if server.authenticator == nil {
			t.Error("Expected authenticator to be set")
		}
		if server.logger == nil {
			t.Error("Expected logger to be set")
		}
	})

	t.Run("creates server with custom authenticator", func(t *testing.T) {
		setupXKMSForTest(t)
		defer xkms.Reset()

		authenticator := auth.NewNoOpAuthenticator()

		cfg := &ServerConfig{
			Port:          0,
			Authenticator: authenticator,
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		if server.authenticator != authenticator {
			t.Error("Expected custom authenticator to be used")
		}
	})

	t.Run("creates server with logging enabled", func(t *testing.T) {
		setupXKMSForTest(t)
		defer xkms.Reset()

		cfg := &ServerConfig{
			Port:          0,
			EnableLogging: true,
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		if server == nil {
			t.Fatal("Expected non-nil server")
		}
	})

	t.Run("creates server with recovery enabled", func(t *testing.T) {
		setupXKMSForTest(t)
		defer xkms.Reset()

		cfg := &ServerConfig{
			Port:           0,
			EnableRecovery: true,
			Logger:         discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		if server == nil {
			t.Fatal("Expected non-nil server")
		}
	})
}

func TestServerPort(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	cfg := &ServerConfig{
		Port:   9876,
		Logger: discardLogger(),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if server.Port() != 9876 {
		t.Errorf("Expected port 9876, got %d", server.Port())
	}
}

// mockFailingAuthenticator is an authenticator that always fails
type mockFailingAuthenticator struct{}

func (a *mockFailingAuthenticator) Name() string { return "mock-failing" }

func (a *mockFailingAuthenticator) AuthenticateHTTP(r *http.Request) (*auth.Identity, error) {
	return nil, errors.New("authentication failed")
}

func (a *mockFailingAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*auth.Identity, error) {
	return nil, errors.New("authentication failed")
}

func TestAuthenticationUnaryInterceptor(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	t.Run("passes with no-op authenticator", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		// Create context with metadata
		ctx := context.Background()
		md := metadata.New(nil)
		ctx = metadata.NewIncomingContext(ctx, md)

		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			// Verify identity is in context
			identity := auth.GetIdentity(ctx)
			if identity == nil {
				t.Error("Expected identity in context")
				return "response", nil
			}
			if identity.Subject != "anonymous" {
				t.Errorf("Expected subject 'anonymous', got '%s'", identity.Subject)
			}
			return "response", nil
		}

		resp, err := server.authenticationUnaryInterceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if resp != "response" {
			t.Errorf("Expected 'response', got %v", resp)
		}
	})

	t.Run("fails with failing authenticator", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: &mockFailingAuthenticator{},
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		md := metadata.New(nil)
		ctx = metadata.NewIncomingContext(ctx, md)

		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return "response", nil
		}

		_, err = server.authenticationUnaryInterceptor(ctx, nil, info, handler)
		if err == nil {
			t.Error("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unauthenticated {
			t.Errorf("Expected Unauthenticated code, got %v", st.Code())
		}
	})

	t.Run("handles missing metadata", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		// Context without metadata
		ctx := context.Background()

		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return "response", nil
		}

		resp, err := server.authenticationUnaryInterceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if resp != "response" {
			t.Errorf("Expected 'response', got %v", resp)
		}
	})
}

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SetHeader(md metadata.MD) error {
	return nil
}

func TestAuthenticationStreamInterceptor(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	t.Run("passes with no-op authenticator", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		md := metadata.New(nil)
		ctx = metadata.NewIncomingContext(ctx, md)

		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handlerCalled := false
		handler := func(srv interface{}, ss grpc.ServerStream) error {
			handlerCalled = true
			identity := auth.GetIdentity(ss.Context())
			if identity == nil {
				t.Error("Expected identity in context")
			}
			return nil
		}

		err = server.authenticationStreamInterceptor(nil, stream, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if !handlerCalled {
			t.Error("Expected handler to be called")
		}
	})

	t.Run("fails with failing authenticator", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: &mockFailingAuthenticator{},
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		md := metadata.New(nil)
		ctx = metadata.NewIncomingContext(ctx, md)

		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(srv interface{}, ss grpc.ServerStream) error {
			return nil
		}

		err = server.authenticationStreamInterceptor(nil, stream, info, handler)
		if err == nil {
			t.Error("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unauthenticated {
			t.Errorf("Expected Unauthenticated code, got %v", st.Code())
		}
	})
}

func TestLoggingUnaryInterceptor(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	t.Run("logs successful request", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			EnableLogging: true,
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return "response", nil
		}

		resp, err := server.loggingUnaryInterceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if resp != "response" {
			t.Errorf("Expected 'response', got %v", resp)
		}
	})

	t.Run("logs request with error", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			EnableLogging: true,
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		expectedErr := status.Error(codes.NotFound, "not found")
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return nil, expectedErr
		}

		_, err = server.loggingUnaryInterceptor(ctx, nil, info, handler)
		if err != expectedErr {
			t.Errorf("Expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("logs request with identity", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			EnableLogging: true,
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		ctx = auth.WithIdentity(ctx, &auth.Identity{Subject: "test-user"})

		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return "response", nil
		}

		resp, err := server.loggingUnaryInterceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if resp != "response" {
			t.Errorf("Expected 'response', got %v", resp)
		}
	})
}

func TestLoggingStreamInterceptor(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	t.Run("logs successful stream", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			EnableLogging: true,
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(srv interface{}, ss grpc.ServerStream) error {
			return nil
		}

		err = server.loggingStreamInterceptor(nil, stream, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("logs stream with error", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			EnableLogging: true,
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		expectedErr := status.Error(codes.Internal, "internal error")
		handler := func(srv interface{}, ss grpc.ServerStream) error {
			return expectedErr
		}

		err = server.loggingStreamInterceptor(nil, stream, info, handler)
		if err != expectedErr {
			t.Errorf("Expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("logs stream with identity", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			EnableLogging: true,
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		ctx = auth.WithIdentity(ctx, &auth.Identity{Subject: "test-user"})
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(srv interface{}, ss grpc.ServerStream) error {
			return nil
		}

		err = server.loggingStreamInterceptor(nil, stream, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})
}

func TestRecoveryUnaryInterceptor(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	t.Run("passes through normal request", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:           0,
			Authenticator:  auth.NewNoOpAuthenticator(),
			EnableRecovery: true,
			Logger:         discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return "response", nil
		}

		resp, err := server.recoveryUnaryInterceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if resp != "response" {
			t.Errorf("Expected 'response', got %v", resp)
		}
	})

	t.Run("recovers from panic", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:           0,
			Authenticator:  auth.NewNoOpAuthenticator(),
			EnableRecovery: true,
			Logger:         discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			panic("test panic")
		}

		_, err = server.recoveryUnaryInterceptor(ctx, nil, info, handler)
		if err == nil {
			t.Error("Expected error after panic")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal code, got %v", st.Code())
		}
	})
}

func TestRecoveryStreamInterceptor(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	t.Run("passes through normal stream", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:           0,
			Authenticator:  auth.NewNoOpAuthenticator(),
			EnableRecovery: true,
			Logger:         discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(srv interface{}, ss grpc.ServerStream) error {
			return nil
		}

		err = server.recoveryStreamInterceptor(nil, stream, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("recovers from panic in stream", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:           0,
			Authenticator:  auth.NewNoOpAuthenticator(),
			EnableRecovery: true,
			Logger:         discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(srv interface{}, ss grpc.ServerStream) error {
			panic("test stream panic")
		}

		err = server.recoveryStreamInterceptor(nil, stream, info, handler)
		if err == nil {
			t.Error("Expected error after panic")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal code, got %v", st.Code())
		}
	})
}

func TestCorrelationUnaryInterceptor(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	t.Run("uses provided correlation ID", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		md := metadata.Pairs(correlation.GRPCCorrelationIDKey, "test-correlation-id")
		ctx = metadata.NewIncomingContext(ctx, md)

		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			id := correlation.GetCorrelationID(ctx)
			if id != "test-correlation-id" {
				t.Errorf("Expected 'test-correlation-id', got '%s'", id)
			}
			return "response", nil
		}

		_, err = server.correlationUnaryInterceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("uses request ID as fallback", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		md := metadata.Pairs(correlation.GRPCRequestIDKey, "test-request-id")
		ctx = metadata.NewIncomingContext(ctx, md)

		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			id := correlation.GetCorrelationID(ctx)
			if id != "test-request-id" {
				t.Errorf("Expected 'test-request-id', got '%s'", id)
			}
			return "response", nil
		}

		_, err = server.correlationUnaryInterceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("generates new ID if none provided", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		md := metadata.New(nil)
		ctx = metadata.NewIncomingContext(ctx, md)

		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			id := correlation.GetCorrelationID(ctx)
			if id == "" {
				t.Error("Expected correlation ID to be generated")
			}
			return "response", nil
		}

		_, err = server.correlationUnaryInterceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("handles missing metadata", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		// Context without metadata
		ctx := context.Background()

		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			id := correlation.GetCorrelationID(ctx)
			if id == "" {
				t.Error("Expected correlation ID to be generated")
			}
			return "response", nil
		}

		_, err = server.correlationUnaryInterceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})
}

func TestCorrelationStreamInterceptor(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	t.Run("uses provided correlation ID", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		md := metadata.Pairs(correlation.GRPCCorrelationIDKey, "test-correlation-id")
		ctx = metadata.NewIncomingContext(ctx, md)

		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(srv interface{}, ss grpc.ServerStream) error {
			id := correlation.GetCorrelationID(ss.Context())
			if id != "test-correlation-id" {
				t.Errorf("Expected 'test-correlation-id', got '%s'", id)
			}
			return nil
		}

		err = server.correlationStreamInterceptor(nil, stream, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("generates new ID if none provided", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx := context.Background()
		md := metadata.New(nil)
		ctx = metadata.NewIncomingContext(ctx, md)

		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(srv interface{}, ss grpc.ServerStream) error {
			id := correlation.GetCorrelationID(ss.Context())
			if id == "" {
				t.Error("Expected correlation ID to be generated")
			}
			return nil
		}

		err = server.correlationStreamInterceptor(nil, stream, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})
}

func TestErrorHandlingUnaryInterceptor(t *testing.T) {
	t.Run("passes through gRPC errors", func(t *testing.T) {
		ctx := context.Background()
		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		expectedErr := status.Error(codes.NotFound, "not found")
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return nil, expectedErr
		}

		_, err := errorHandlingUnaryInterceptor(ctx, nil, info, handler)
		if err != expectedErr {
			t.Errorf("Expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("converts non-gRPC errors to Internal", func(t *testing.T) {
		ctx := context.Background()
		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return nil, fmt.Errorf("plain error")
		}

		_, err := errorHandlingUnaryInterceptor(ctx, nil, info, handler)
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal code, got %v", st.Code())
		}
	})

	t.Run("passes through success", func(t *testing.T) {
		ctx := context.Background()
		info := &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return "response", nil
		}

		resp, err := errorHandlingUnaryInterceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if resp != "response" {
			t.Errorf("Expected 'response', got %v", resp)
		}
	})
}

func TestErrorHandlingStreamInterceptor(t *testing.T) {
	t.Run("passes through gRPC errors", func(t *testing.T) {
		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		expectedErr := status.Error(codes.NotFound, "not found")
		handler := func(srv interface{}, ss grpc.ServerStream) error {
			return expectedErr
		}

		err := errorHandlingStreamInterceptor(nil, stream, info, handler)
		if err != expectedErr {
			t.Errorf("Expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("converts non-gRPC errors to Internal", func(t *testing.T) {
		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(srv interface{}, ss grpc.ServerStream) error {
			return fmt.Errorf("plain error")
		}

		err := errorHandlingStreamInterceptor(nil, stream, info, handler)
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal code, got %v", st.Code())
		}
	})

	t.Run("passes through success", func(t *testing.T) {
		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(srv interface{}, ss grpc.ServerStream) error {
			return nil
		}

		err := errorHandlingStreamInterceptor(nil, stream, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})
}

func TestAuthenticatedServerStream(t *testing.T) {
	t.Run("returns wrapped context", func(t *testing.T) {
		identity := &auth.Identity{Subject: "test-user"}
		ctx := auth.WithIdentity(context.Background(), identity)

		stream := &authenticatedServerStream{
			ctx: ctx,
		}

		if stream.Context() != ctx {
			t.Error("Expected stream to return wrapped context")
		}

		retrievedIdentity := auth.GetIdentity(stream.Context())
		if retrievedIdentity == nil {
			t.Fatal("Expected identity in context")
		}
		if retrievedIdentity.Subject != "test-user" {
			t.Errorf("Expected subject 'test-user', got '%s'", retrievedIdentity.Subject)
		}
	})
}

func TestCorrelatedServerStream(t *testing.T) {
	t.Run("returns wrapped context with correlation ID", func(t *testing.T) {
		ctx := correlation.WithCorrelationID(context.Background(), "test-id")

		stream := &correlatedServerStream{
			ctx: ctx,
		}

		if stream.Context() != ctx {
			t.Error("Expected stream to return wrapped context")
		}

		id := correlation.GetCorrelationID(stream.Context())
		if id != "test-id" {
			t.Errorf("Expected 'test-id', got '%s'", id)
		}
	})
}

func TestGetBackendDescription(t *testing.T) {
	tests := []struct {
		name        string
		backendType types.BackendType
		expected    string
	}{
		{
			name:        "Software backend",
			backendType: types.BackendTypeSoftware,
			expected:    "Software-based key storage",
		},
		{
			name:        "PKCS11 backend",
			backendType: types.BackendTypePKCS11,
			expected:    "Hardware Security Module (PKCS#11)",
		},
		{
			name:        "TPM2 backend",
			backendType: types.BackendTypeTPM2,
			expected:    "Trusted Platform Module 2.0",
		},
		{
			name:        "AWS KMS backend",
			backendType: types.BackendTypeAWSKMS,
			expected:    "AWS Key Management Service",
		},
		{
			name:        "GCP KMS backend",
			backendType: types.BackendTypeGCPKMS,
			expected:    "Google Cloud Key Management Service",
		},
		{
			name:        "Azure KV backend",
			backendType: types.BackendTypeAzureKV,
			expected:    "Azure Key Vault",
		},
		{
			name:        "Vault backend",
			backendType: types.BackendTypeVault,
			expected:    "HashiCorp Vault",
		},
		{
			name:        "Unknown backend",
			backendType: types.BackendType("unknown-type"),
			expected:    "unknown-type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := getBackendDescription(tt.backendType)
			if desc != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, desc)
			}
		})
	}
}
