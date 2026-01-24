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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	pb "github.com/jeremyhahn/go-keychain/pkg/api/grpc/proto/keychainv1"
	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/correlation"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// setupFinalCoverageTest initializes keychain for final coverage tests
func setupFinalCoverageTest(t *testing.T) *Service {
	t.Helper()
	keychain.Reset()

	keyStorage := storage.New()
	certStorage := storage.New()

	backend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	ks, err := keychain.New(&keychain.Config{
		Backend:     backend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	err = keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software": ks,
		},
		DefaultBackend: "software",
	})
	if err != nil {
		t.Fatalf("Failed to initialize keychain: %v", err)
	}

	return NewService()
}

// TestCorrelationStreamInterceptorRequestIDFallback tests the request ID fallback path
func TestCorrelationStreamInterceptorRequestIDFallback(t *testing.T) {
	setupFinalCoverageTest(t)
	defer keychain.Reset()

	t.Run("uses request ID when no correlation ID", func(t *testing.T) {
		cfg := &ServerConfig{
			Port:          0,
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        discardLogger(),
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		// Context with request ID but no correlation ID
		ctx := context.Background()
		md := metadata.Pairs(correlation.GRPCRequestIDKey, "test-request-id-12345")
		ctx = metadata.NewIncomingContext(ctx, md)

		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{
			FullMethod: "/test.Service/Method",
		}

		handler := func(srv interface{}, ss grpc.ServerStream) error {
			id := correlation.GetCorrelationID(ss.Context())
			if id != "test-request-id-12345" {
				t.Errorf("Expected 'test-request-id-12345', got '%s'", id)
			}
			return nil
		}

		err = server.correlationStreamInterceptor(nil, stream, info, handler)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("handles missing metadata in stream", func(t *testing.T) {
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

// TestListCertsWithCerts tests ListCerts when certificates exist
func TestListCertsWithCerts(t *testing.T) {
	service := setupFinalCoverageTest(t)
	defer keychain.Reset()

	// Save multiple certificates
	for i := 0; i < 3; i++ {
		cert := createTestCertForFinalCoverage(t)
		certPEM := encodeCertToPEM(cert)

		_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
			KeyId:   string(rune('a'+i)) + "-list-cert",
			CertPem: certPEM,
		})
		if err != nil {
			t.Fatalf("Failed to save certificate: %v", err)
		}
	}

	t.Run("lists all certificates", func(t *testing.T) {
		resp, err := service.ListCerts(context.Background(), &pb.ListCertsRequest{})
		if err != nil {
			t.Fatalf("ListCerts failed: %v", err)
		}

		if resp.Total < 3 {
			t.Errorf("Expected at least 3 certificates, got %d", resp.Total)
		}
		if len(resp.KeyIds) < 3 {
			t.Errorf("Expected at least 3 key IDs, got %d", len(resp.KeyIds))
		}
	})
}

// TestCertExistsWithExistingCert tests CertExists when certificate exists
func TestCertExistsWithExistingCert(t *testing.T) {
	service := setupFinalCoverageTest(t)
	defer keychain.Reset()

	// Save a certificate
	cert := createTestCertForFinalCoverage(t)
	certPEM := encodeCertToPEM(cert)

	_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "exists-check-cert",
		CertPem: certPEM,
	})
	if err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	t.Run("returns true for existing certificate", func(t *testing.T) {
		resp, err := service.CertExists(context.Background(), &pb.CertExistsRequest{
			KeyId: "exists-check-cert",
		})
		if err != nil {
			t.Fatalf("CertExists failed: %v", err)
		}

		if !resp.Exists {
			t.Error("Expected certificate to exist")
		}
	})
}

// TestAsymmetricDecryption tests asymmetric decryption path
func TestAsymmetricDecryption(t *testing.T) {
	service := setupFinalCoverageTest(t)
	defer keychain.Reset()

	t.Run("attempts asymmetric decryption with RSA key", func(t *testing.T) {
		// Generate RSA key for encryption/decryption
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "asymmetric-decrypt-key",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Try to decrypt with asymmetric key - this tests the asymmetric decryption path
		// even if it fails at the actual decryption step
		_, err = service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:      "asymmetric-decrypt-key",
			Backend:    "software",
			Ciphertext: []byte("some-encrypted-data"),
		})
		// We expect an error because we're passing invalid ciphertext,
		// but we're testing the code path
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			// Internal error is expected for invalid ciphertext
			if st.Code() != codes.Internal {
				t.Errorf("Expected Internal error for invalid ciphertext, got %v", st.Code())
			}
		}
	})
}

// TestParseCertFromPEMInvalidCertData tests parseCertFromPEM with invalid cert data
func TestParseCertFromPEMInvalidCertData(t *testing.T) {
	// This tests the error path when x509.ParseCertificate fails
	invalidCertPEM := `-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----`

	_, err := parseCertFromPEM(invalidCertPEM)
	if err == nil {
		t.Error("Expected error for invalid certificate data")
	}
}

// TestListBackendsWithMultipleBackends tests ListBackends behavior
func TestListBackendsWithMultipleBackends(t *testing.T) {
	keychain.Reset()

	keyStorage1 := storage.New()
	keyStorage2 := storage.New()
	certStorage := storage.New()

	backend1, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage1,
	})
	if err != nil {
		t.Fatalf("Failed to create backend 1: %v", err)
	}

	backend2, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage2,
	})
	if err != nil {
		t.Fatalf("Failed to create backend 2: %v", err)
	}

	ks1, err := keychain.New(&keychain.Config{
		Backend:     backend1,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create keystore 1: %v", err)
	}

	ks2, err := keychain.New(&keychain.Config{
		Backend:     backend2,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create keystore 2: %v", err)
	}

	err = keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software-1": ks1,
			"software-2": ks2,
		},
		DefaultBackend: "software-1",
	})
	if err != nil {
		t.Fatalf("Failed to initialize keychain: %v", err)
	}
	defer keychain.Reset()

	service := NewService()

	t.Run("lists multiple backends", func(t *testing.T) {
		resp, err := service.ListBackends(context.Background(), &pb.ListBackendsRequest{})
		if err != nil {
			t.Fatalf("ListBackends failed: %v", err)
		}

		if resp.Count < 2 {
			t.Errorf("Expected at least 2 backends, got %d", resp.Count)
		}
	})
}

// TestDeleteKeyError tests DeleteKey when key deletion fails
func TestDeleteKeyError(t *testing.T) {
	service := setupFinalCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns error for already deleted key", func(t *testing.T) {
		// Generate a key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "double-delete-key",
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "P256",
		})
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Delete the key
		_, err = service.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
			KeyId:   "double-delete-key",
			Backend: "software",
		})
		if err != nil {
			t.Fatalf("First DeleteKey failed: %v", err)
		}

		// Try to delete again
		_, err = service.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
			KeyId:   "double-delete-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error for deleted key")
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

// TestSignError tests Sign when signing fails
func TestSignError(t *testing.T) {
	service := setupFinalCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns error when key not found in backend", func(t *testing.T) {
		_, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "nonexistent-sign-key",
			Backend: "software",
			Data:    []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error")
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

// TestVerifyError tests Verify when verification fails
func TestVerifyError(t *testing.T) {
	service := setupFinalCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns error when key not found", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "nonexistent-verify-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: []byte("invalid-signature"),
		})
		if err == nil {
			t.Fatal("Expected error")
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

// TestRotateKeyError tests RotateKey when rotation fails
func TestRotateKeyError(t *testing.T) {
	service := setupFinalCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns error for nonexistent key rotation", func(t *testing.T) {
		_, err := service.RotateKey(context.Background(), &pb.RotateKeyRequest{
			KeyId:   "nonexistent-rotate-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error")
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

// TestDeleteCertSuccessfully tests DeleteCert when it succeeds
func TestDeleteCertSuccessfully(t *testing.T) {
	service := setupFinalCoverageTest(t)
	defer keychain.Reset()

	// Save a certificate first
	cert := createTestCertForFinalCoverage(t)
	certPEM := encodeCertToPEM(cert)

	_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "delete-success-cert",
		CertPem: certPEM,
	})
	if err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	t.Run("deletes certificate successfully", func(t *testing.T) {
		resp, err := service.DeleteCert(context.Background(), &pb.DeleteCertRequest{
			KeyId: "delete-success-cert",
		})
		if err != nil {
			t.Fatalf("DeleteCert failed: %v", err)
		}

		if !resp.Success {
			t.Error("Expected success to be true")
		}

		// Verify certificate no longer exists
		existsResp, err := service.CertExists(context.Background(), &pb.CertExistsRequest{
			KeyId: "delete-success-cert",
		})
		if err != nil {
			t.Fatalf("CertExists failed: %v", err)
		}

		if existsResp.Exists {
			t.Error("Expected certificate to not exist after deletion")
		}
	})
}

// TestSaveCertNoBackends tests SaveCert when no backends are available
func TestSaveCertNoBackends(t *testing.T) {
	// Reset keychain without initializing
	keychain.Reset()

	service := NewService()

	cert := createTestCertForFinalCoverage(t)
	certPEM := encodeCertToPEM(cert)

	t.Run("returns error when no backends available", func(t *testing.T) {
		_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
			KeyId:   "no-backend-cert",
			CertPem: certPEM,
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal, got %v", st.Code())
		}
	})
}

// TestGetCertNoBackends tests GetCert when no backends are available
func TestGetCertNoBackends(t *testing.T) {
	keychain.Reset()

	service := NewService()

	t.Run("returns error when no backends available", func(t *testing.T) {
		_, err := service.GetCert(context.Background(), &pb.GetCertRequest{
			KeyId: "no-backend-cert",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal, got %v", st.Code())
		}
	})
}

// TestDeleteCertNoBackends tests DeleteCert when no backends are available
func TestDeleteCertNoBackends(t *testing.T) {
	keychain.Reset()

	service := NewService()

	t.Run("returns error when no backends available", func(t *testing.T) {
		_, err := service.DeleteCert(context.Background(), &pb.DeleteCertRequest{
			KeyId: "no-backend-cert",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal, got %v", st.Code())
		}
	})
}

// TestListCertsNoBackends tests ListCerts when no backends are available
func TestListCertsNoBackends(t *testing.T) {
	keychain.Reset()

	service := NewService()

	t.Run("returns error when no backends available", func(t *testing.T) {
		_, err := service.ListCerts(context.Background(), &pb.ListCertsRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal, got %v", st.Code())
		}
	})
}

// TestCertExistsNoBackends tests CertExists when no backends are available
func TestCertExistsNoBackends(t *testing.T) {
	keychain.Reset()

	service := NewService()

	t.Run("returns error when no backends available", func(t *testing.T) {
		_, err := service.CertExists(context.Background(), &pb.CertExistsRequest{
			KeyId: "no-backend-cert",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal, got %v", st.Code())
		}
	})
}

// TestSaveCertChainNoBackends tests SaveCertChain when no backends are available
func TestSaveCertChainNoBackends(t *testing.T) {
	keychain.Reset()

	service := NewService()

	cert := createTestCertForFinalCoverage(t)
	certPEM := encodeCertToPEM(cert)

	t.Run("returns error when no backends available", func(t *testing.T) {
		_, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
			KeyId:        "no-backend-chain",
			CertChainPem: []string{certPEM},
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal, got %v", st.Code())
		}
	})
}

// TestGetCertChainNoBackends tests GetCertChain when no backends are available
func TestGetCertChainNoBackends(t *testing.T) {
	keychain.Reset()

	service := NewService()

	t.Run("returns error when no backends available", func(t *testing.T) {
		_, err := service.GetCertChain(context.Background(), &pb.GetCertChainRequest{
			KeyId: "no-backend-chain",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal, got %v", st.Code())
		}
	})
}

// TestWrapKeyNoBackends tests WrapKey when no backends are available
func TestWrapKeyNoBackends(t *testing.T) {
	keychain.Reset()

	service := NewService()

	// Generate a test wrapping key for the request
	wrappingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrappingPubKeyDER, _ := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)

	t.Run("returns error when no backends available", func(t *testing.T) {
		_, err := service.WrapKey(context.Background(), &pb.WrapKeyRequest{
			KeyMaterial:       []byte("test-key-material"),
			WrappingPublicKey: wrappingPubKeyDER,
			Algorithm:         "RSAES_OAEP_SHA_256",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal, got %v", st.Code())
		}
	})
}

// TestUnwrapKeyNoBackends tests UnwrapKey when no backends are available
func TestUnwrapKeyNoBackends(t *testing.T) {
	keychain.Reset()

	service := NewService()

	wrappingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrappingPubKeyDER, _ := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)

	t.Run("returns error when no backends available", func(t *testing.T) {
		_, err := service.UnwrapKey(context.Background(), &pb.UnwrapKeyRequest{
			WrappedKey:        []byte("wrapped-key"),
			Algorithm:         "RSAES_OAEP_SHA_256",
			WrappingPublicKey: wrappingPubKeyDER,
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal, got %v", st.Code())
		}
	})
}

// Helper function to create a test certificate
func createTestCertForFinalCoverage(t *testing.T) *x509.Certificate {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}
