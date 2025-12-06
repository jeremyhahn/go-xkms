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

//go:build integration

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"github.com/jeremyhahn/go-keychain/internal/testutil"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// createTestBackendRegistry creates a backend registry with a test keystore
func createTestBackendRegistry(t *testing.T) *BackendRegistry {
	t.Helper()

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
	ks, err := keychain.New(&keychain.Config{
		Backend:     backend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	// Create backend registry
	manager := NewBackendRegistry()
	if err := manager.Register("test", ks); err != nil {
		t.Fatalf("Failed to register backend: %v", err)
	}

	return manager
}

// waitForGRPCServer waits for the gRPC server to be ready
func waitForGRPCServer(t *testing.T, server *Server, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Check if server port is set (indicates listener is established)
		if server.Port() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("gRPC server did not become ready within %v", timeout)
}

func TestGRPCServer_NoOpAuthenticator_NoTLS(t *testing.T) {
	// Create test backend registry
	manager := createTestBackendRegistry(t)
	defer func() { _ = manager.Close() }()

	// Create NoOp authenticator
	authenticator := auth.NewNoOpAuthenticator()

	// Create gRPC server without TLS
	cfg := &ServerConfig{
		Port:           0, // Ephemeral port
		Registry:       manager,
		Authenticator:  authenticator,
		EnableLogging:  false,
		EnableRecovery: true,
		Logger: logger.NewSlogAdapter(&logger.SlogConfig{
			Level: logger.LevelError,
		}),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start()
	}()
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	}()

	// Wait for server to be ready
	waitForGRPCServer(t, server, 5*time.Second)

	// Get the actual port
	port := server.Port()
	addr := fmt.Sprintf("localhost:%d", port)

	// Create client connection (no TLS)
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewKeystoreServiceClient(conn)

	// Test health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := client.Health(ctx, &pb.HealthRequest{})
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}

		if resp.Status != "healthy" {
			t.Errorf("Expected status 'healthy', got '%s'", resp.Status)
		}
	})

	// Test authenticated endpoint (should succeed with NoOp auth)
	t.Run("ListBackends", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := client.ListBackends(ctx, &pb.ListBackendsRequest{})
		if err != nil {
			t.Fatalf("ListBackends failed: %v", err)
		}

		if resp.Count == 0 {
			t.Error("Expected at least one backend")
		}
	})
}

func TestGRPCServer_APIKeyAuthenticator_Metadata(t *testing.T) {
	// Create test backend manager
	manager := createTestBackendRegistry(t)
	defer func() { _ = manager.Close() }()

	// Create API key authenticator with test keys
	validAPIKey := "test-api-key-12345"
	invalidAPIKey := "invalid-api-key"

	authenticator := auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
		Keys: map[string]*auth.Identity{
			validAPIKey: {
				Subject: "test-user",
				Claims: map[string]interface{}{
					"roles": []string{"admin"},
				},
				Attributes: map[string]string{
					"scope": "full",
				},
			},
		},
	})

	// Create gRPC server
	cfg := &ServerConfig{
		Port:           0,
		Registry:       manager,
		Authenticator:  authenticator,
		EnableLogging:  false,
		EnableRecovery: true,
		Logger: logger.NewSlogAdapter(&logger.SlogConfig{
			Level: logger.LevelError,
		}),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start()
	}()
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	}()

	// Wait for server to be ready
	waitForGRPCServer(t, server, 5*time.Second)

	port := server.Port()
	addr := fmt.Sprintf("localhost:%d", port)

	// Create client connection
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewKeystoreServiceClient(conn)

	// Test with valid API key in metadata
	t.Run("ValidAPIKey", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Add API key to metadata
		md := metadata.Pairs("x-api-key", validAPIKey)
		ctx = metadata.NewOutgoingContext(ctx, md)

		resp, err := client.ListBackends(ctx, &pb.ListBackendsRequest{})
		if err != nil {
			t.Fatalf("Request with valid API key failed: %v", err)
		}

		if resp.Count == 0 {
			t.Error("Expected at least one backend")
		}
	})

	// Test with invalid API key
	t.Run("InvalidAPIKey", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		md := metadata.Pairs("x-api-key", invalidAPIKey)
		ctx = metadata.NewOutgoingContext(ctx, md)

		_, err := client.ListBackends(ctx, &pb.ListBackendsRequest{})
		if err == nil {
			t.Fatal("Expected error with invalid API key, got nil")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}

		if st.Code() != codes.Unauthenticated {
			t.Errorf("Expected code Unauthenticated, got %v", st.Code())
		}
	})

	// Test without API key
	t.Run("NoAPIKey", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := client.ListBackends(ctx, &pb.ListBackendsRequest{})
		if err == nil {
			t.Fatal("Expected error without API key, got nil")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}

		if st.Code() != codes.Unauthenticated {
			t.Errorf("Expected code Unauthenticated, got %v", st.Code())
		}
	})

	// Test with API key in authorization metadata
	t.Run("BearerToken", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		md := metadata.Pairs("authorization", "Bearer "+validAPIKey)
		ctx = metadata.NewOutgoingContext(ctx, md)

		resp, err := client.ListBackends(ctx, &pb.ListBackendsRequest{})
		if err != nil {
			t.Fatalf("Request with Bearer token failed: %v", err)
		}

		if resp.Count == 0 {
			t.Error("Expected at least one backend")
		}
	})
}

func TestGRPCServer_TLS_NoClientCert(t *testing.T) {
	// Generate test CA and server certificate
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	// Create test backend manager
	manager := createTestBackendRegistry(t)
	defer func() { _ = manager.Close() }()

	// Create TLS config (no client cert required)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert.TLSCert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create NoOp authenticator
	authenticator := auth.NewNoOpAuthenticator()

	// Create gRPC server with TLS
	cfg := &ServerConfig{
		Port:           0,
		Registry:       manager,
		TLSConfig:      tlsConfig,
		Authenticator:  authenticator,
		EnableLogging:  false,
		EnableRecovery: true,
		Logger: logger.NewSlogAdapter(&logger.SlogConfig{
			Level: logger.LevelError,
		}),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start()
	}()
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	}()

	// Wait for server to be ready
	waitForGRPCServer(t, server, 5*time.Second)

	port := server.Port()
	addr := fmt.Sprintf("localhost:%d", port)

	// Create CA cert pool for client
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca.CertPEM)

	// Create TLS credentials
	creds := credentials.NewTLS(&tls.Config{
		RootCAs: caCertPool,
	})

	// Create client connection with TLS
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewKeystoreServiceClient(conn)

	// Test TLS connection
	t.Run("TLSConnection", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := client.Health(ctx, &pb.HealthRequest{})
		if err != nil {
			t.Fatalf("Health check over TLS failed: %v", err)
		}

		if resp.Status != "healthy" {
			t.Errorf("Expected status 'healthy', got '%s'", resp.Status)
		}
	})

	// Test authenticated endpoint over TLS
	t.Run("AuthenticatedOverTLS", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := client.ListBackends(ctx, &pb.ListBackendsRequest{})
		if err != nil {
			t.Fatalf("ListBackends over TLS failed: %v", err)
		}

		if resp.Count == 0 {
			t.Error("Expected at least one backend")
		}
	})
}

func TestGRPCServer_mTLS_ClientCertRequired(t *testing.T) {
	// Generate test CA, server cert, and client cert
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	if err != nil {
		t.Fatalf("Failed to generate client certificate: %v", err)
	}

	// Create test backend manager
	manager := createTestBackendRegistry(t)
	defer func() { _ = manager.Close() }()

	// Create CA cert pool for client verification
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca.CertPEM)

	// Create TLS config with client cert verification
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert.TLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Create mTLS authenticator
	authenticator := auth.NewMTLSAuthenticator(nil)

	// Create gRPC server with mTLS
	cfg := &ServerConfig{
		Port:           0,
		Registry:       manager,
		TLSConfig:      tlsConfig,
		Authenticator:  authenticator,
		EnableLogging:  false,
		EnableRecovery: true,
		Logger: logger.NewSlogAdapter(&logger.SlogConfig{
			Level: logger.LevelError,
		}),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start()
	}()
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	}()

	// Wait for server to be ready
	waitForGRPCServer(t, server, 5*time.Second)

	port := server.Port()
	addr := fmt.Sprintf("localhost:%d", port)

	// Create CA cert pool for client
	caCertPoolClient := x509.NewCertPool()
	caCertPoolClient.AppendCertsFromPEM(ca.CertPEM)

	// Test with valid client certificate
	t.Run("ValidClientCert", func(t *testing.T) {
		// Create TLS credentials with client certificate
		creds := credentials.NewTLS(&tls.Config{
			RootCAs:      caCertPoolClient,
			Certificates: []tls.Certificate{clientCert.TLSCert},
		})

		conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
		if err != nil {
			t.Fatalf("Failed to connect with client cert: %v", err)
		}
		defer func() { _ = conn.Close() }()

		client := pb.NewKeystoreServiceClient(conn)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := client.ListBackends(ctx, &pb.ListBackendsRequest{})
		if err != nil {
			t.Fatalf("Request with valid client cert failed: %v", err)
		}

		if resp.Count == 0 {
			t.Error("Expected at least one backend")
		}
	})

	// Test without client certificate (should fail)
	t.Run("NoClientCert", func(t *testing.T) {
		// Create TLS credentials without client certificate
		creds := credentials.NewTLS(&tls.Config{
			RootCAs: caCertPoolClient,
		})

		conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
		if err != nil {
			// This is expected - connection should fail without client cert
			t.Logf("Connection failed as expected without client cert: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()

		client := pb.NewKeystoreServiceClient(conn)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err = client.ListBackends(ctx, &pb.ListBackendsRequest{})
		if err == nil {
			t.Error("Expected error when connecting without client cert, but got none")
		}
		// The error should be related to TLS handshake or authentication
		t.Logf("Got expected error: %v", err)
	})
}

func TestGRPCServer_AuthenticationFailureScenarios(t *testing.T) {
	tests := []struct {
		name          string
		setupAuth     func() auth.Authenticator
		setupMetadata func(context.Context) context.Context
		expectedCode  codes.Code
		description   string
	}{
		{
			name: "APIKey_EmptyKey",
			setupAuth: func() auth.Authenticator {
				return auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
					Keys: map[string]*auth.Identity{
						"valid-key": {Subject: "test"},
					},
				})
			},
			setupMetadata: func(ctx context.Context) context.Context {
				md := metadata.Pairs("x-api-key", "")
				return metadata.NewOutgoingContext(ctx, md)
			},
			expectedCode: codes.Unauthenticated,
			description:  "Empty API key should be rejected",
		},
		{
			name: "APIKey_WrongKey",
			setupAuth: func() auth.Authenticator {
				return auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
					Keys: map[string]*auth.Identity{
						"valid-key": {Subject: "test"},
					},
				})
			},
			setupMetadata: func(ctx context.Context) context.Context {
				md := metadata.Pairs("x-api-key", "wrong-key")
				return metadata.NewOutgoingContext(ctx, md)
			},
			expectedCode: codes.Unauthenticated,
			description:  "Wrong API key should be rejected",
		},
		{
			name: "APIKey_MissingKey",
			setupAuth: func() auth.Authenticator {
				return auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
					Keys: map[string]*auth.Identity{
						"valid-key": {Subject: "test"},
					},
				})
			},
			setupMetadata: func(ctx context.Context) context.Context {
				return ctx // No metadata
			},
			expectedCode: codes.Unauthenticated,
			description:  "Missing API key should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test backend manager
			manager := createTestBackendRegistry(t)
			defer func() { _ = manager.Close() }()

			// Create server with the specified authenticator
			cfg := &ServerConfig{
				Port:           0,
				Registry:       manager,
				Authenticator:  tt.setupAuth(),
				EnableLogging:  false,
				EnableRecovery: true,
				Logger: logger.NewSlogAdapter(&logger.SlogConfig{
					Level: logger.LevelError,
				}),
			}

			server, err := NewServer(cfg)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			// Start server
			serverErrCh := make(chan error, 1)
			go func() {
				serverErrCh <- server.Start()
			}()
			defer func() {
				if err := server.Stop(); err != nil {
					t.Logf("Failed to stop server: %v", err)
				}
			}()

			// Wait for server to be ready
			waitForGRPCServer(t, server, 5*time.Second)

			port := server.Port()
			addr := fmt.Sprintf("localhost:%d", port)

			// Create client connection
			conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			defer func() { _ = conn.Close() }()

			client := pb.NewKeystoreServiceClient(conn)

			// Give server a moment to fully initialize
			time.Sleep(50 * time.Millisecond)

			// Create context with metadata
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			ctx = tt.setupMetadata(ctx)

			// Make request
			_, err = client.ListBackends(ctx, &pb.ListBackendsRequest{})
			if err == nil {
				t.Fatalf("%s: Expected error, got nil", tt.description)
			}

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, got: %v", err)
			}

			if st.Code() != tt.expectedCode {
				t.Errorf("%s: Expected code %v, got %v", tt.description, tt.expectedCode, st.Code())
			}
		})
	}
}
