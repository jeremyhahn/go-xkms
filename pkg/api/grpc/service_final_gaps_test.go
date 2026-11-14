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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// setupFinalGapsTest initializes xkms for final coverage gap tests
func setupFinalGapsTest(t *testing.T) *Service {
	t.Helper()
	xkms.Reset()

	keyStorage := storage.New()
	certStorage := storage.New()

	backend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     backend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": ks,
		},
		DefaultBackend: "software",
	})
	if err != nil {
		t.Fatalf("Failed to initialize xkms: %v", err)
	}

	svc, err := xkms.Get()
	if err != nil {
		t.Fatalf("Failed to get xkms service: %v", err)
	}
	wireKeyVersionStore(t)
	return NewService(nil, nil, svc)
}

// TestVerifyErrorPaths tests Verify error handling paths
func TestVerifyErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer xkms.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: []byte("signature"),
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "test-key",
			Data:      []byte("test data"),
			Signature: []byte("signature"),
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing data", func(t *testing.T) {
		// First create an RSA key so we can test the empty data path
		// (Ed25519 allows empty data per RFC 8032, so we need a non-Ed25519 key)
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "test-rsa-for-verify-empty-data",
			Backend: "software",
			KeyType: "RSA", Algorithm: "RSA",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		_, err = service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "test-rsa-for-verify-empty-data",
			Backend:   "software",
			Signature: []byte("signature"),
		})
		if err == nil {
			t.Fatal("Expected error for missing data")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing signature", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:   "test-key",
			Backend: "software",
			Data:    []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for missing signature")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "non-existent-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: []byte("signature"),
		})
		if err == nil {
			t.Fatal("Expected error for non-existent key")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestSaveCertChainErrorPaths tests SaveCertChain error handling paths
func TestSaveCertChainErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer xkms.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
			CertChainPem: []string{"cert-pem"},
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for empty cert_chain_pem", func(t *testing.T) {
		_, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
			KeyId:        "test-key",
			CertChainPem: []string{},
		})
		if err == nil {
			t.Fatal("Expected error for empty cert_chain_pem")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for invalid cert in chain", func(t *testing.T) {
		_, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
			KeyId:        "test-key",
			CertChainPem: []string{"invalid-cert-pem"},
		})
		if err == nil {
			t.Fatal("Expected error for invalid cert in chain")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})
}

// TestEncryptErrorPaths tests Encrypt error handling paths
func TestEncryptErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer xkms.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			Backend:   "software",
			Plaintext: []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:     "test-key",
			Plaintext: []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing plaintext", func(t *testing.T) {
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for missing plaintext")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:     "non-existent-key",
			Backend:   "software",
			Plaintext: []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for non-existent key")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})
}

// TestDecryptErrorPaths tests Decrypt error handling paths
func TestDecryptErrorPaths(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer xkms.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			Backend:    "software",
			Ciphertext: []byte("encrypted"),
		})
		if err == nil {
			t.Fatal("Expected error for missing key_id")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:      "test-key",
			Ciphertext: []byte("encrypted"),
		})
		if err == nil {
			t.Fatal("Expected error for missing backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing ciphertext", func(t *testing.T) {
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for missing ciphertext")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})
}

// TestNewServerWithRateLimiter tests NewServer with rate limiter
func TestNewServerWithRateLimiter(t *testing.T) {
	setupFinalGapsTest(t)
	defer xkms.Reset()

	// Create a rate limiter
	limiter := ratelimit.New(&ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 100,
		Burst:             10,
		CleanupInterval:   time.Minute,
	})

	cfg := &ServerConfig{
		Authenticator: auth.NewNoOpAuthenticator(),
		Port:          0,
		RateLimiter:   limiter,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if server == nil {
		t.Fatal("Expected non-nil server")
	}
	if server.rateLimiter == nil {
		t.Error("Expected rate limiter to be set")
	}
}

// TestListKeysPagination tests ListKeys with pagination
func TestListKeysPagination(t *testing.T) {
	service := setupFinalGapsTest(t)
	defer xkms.Reset()

	// Generate multiple keys
	for i := 0; i < 5; i++ {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "pagination-key-" + string(rune('a'+i)),
			Backend: "software",
			KeyType: "ecdsa", Algorithm: "ecdsa",
			Curve: "P256",
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
	}

	// Test with limit
	resp, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
		Backend: "software",
		Limit:   2,
	})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(resp.Keys) != 2 {
		t.Errorf("Expected 2 keys with limit, got %d", len(resp.Keys))
	}

	// Test with offset
	resp2, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
		Backend: "software",
		Offset:  2,
		Limit:   2,
	})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(resp2.Keys) != 2 {
		t.Errorf("Expected 2 keys with offset, got %d", len(resp2.Keys))
	}

	// Test with offset beyond total
	resp3, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
		Backend: "software",
		Offset:  100,
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(resp3.Keys) != 0 {
		t.Errorf("Expected 0 keys with large offset, got %d", len(resp3.Keys))
	}
}

// TestAuthenticationStreamInterceptorWithMissingMetadata tests stream auth interceptor
func TestAuthenticationStreamInterceptorWithMissingMetadata(t *testing.T) {
	setupFinalGapsTest(t)
	defer xkms.Reset()

	cfg := &ServerConfig{
		Port:          0,
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Context without metadata
	ctx := context.Background()
	stream := &mockStreamServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handlerCalled := false
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err = server.authenticationStreamInterceptor(nil, stream, info, handler)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if !handlerCalled {
		t.Error("Handler should have been called")
	}
}

// mockStreamServerStream is a minimal mock for grpc.ServerStream
type mockStreamServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockStreamServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockStreamServerStream) SetHeader(md metadata.MD) error {
	return nil
}

// Helper function to generate test TLS certificate
func generateTestTLSCert(t *testing.T) (tls.Certificate, error) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "test-tls-cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}, nil
}

// Helper function to create test certificate

// TestServerStartWithTLS tests starting server with TLS
func TestServerStartWithTLS(t *testing.T) {
	setupFinalGapsTest(t)
	defer xkms.Reset()

	// Generate TLS certificates for testing
	tlsCert, err := generateTestTLSCert(t)
	if err != nil {
		t.Fatalf("Failed to generate TLS cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	cfg := &ServerConfig{
		Port:          0,
		TLSConfig:     tlsConfig,
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Wait for the listener to bind instead of sleeping a fixed duration.
	waitForListener(t, server, 5*time.Second)

	// Stop the server
	if err := server.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	// Check for any errors from Start
	select {
	case err := <-errChan:
		if err != nil {
			t.Logf("Server start returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Server stopped gracefully
	}
}
