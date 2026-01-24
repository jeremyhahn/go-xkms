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

	pb "github.com/jeremyhahn/go-keychain/pkg/api/grpc/proto/keychainv1"
	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setupServiceTest initializes keychain for service tests
func setupServiceTest(t *testing.T) *Service {
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

func TestNewService(t *testing.T) {
	service := NewService()
	if service == nil {
		t.Fatal("Expected non-nil service")
	}
}

func TestService_Health(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	t.Run("returns healthy status", func(t *testing.T) {
		resp, err := service.Health(context.Background(), &pb.HealthRequest{})
		if err != nil {
			t.Fatalf("Health failed: %v", err)
		}

		if resp.Status != "healthy" {
			t.Errorf("Expected status 'healthy', got '%s'", resp.Status)
		}
		if resp.Version == "" {
			t.Error("Expected non-empty version")
		}
	})
}

func TestService_ListBackends(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	t.Run("lists all backends", func(t *testing.T) {
		resp, err := service.ListBackends(context.Background(), &pb.ListBackendsRequest{})
		if err != nil {
			t.Fatalf("ListBackends failed: %v", err)
		}

		if resp.Count == 0 {
			t.Error("Expected at least one backend")
		}
		if len(resp.Backends) == 0 {
			t.Error("Expected backends list to be non-empty")
		}

		// Verify backend info
		found := false
		for _, b := range resp.Backends {
			if b.Name == "software" {
				found = true
				if b.Type == "" {
					t.Error("Expected non-empty backend type")
				}
			}
		}
		if !found {
			t.Error("Expected to find 'software' backend")
		}
	})
}

func TestService_GetBackendInfo(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	t.Run("returns backend info", func(t *testing.T) {
		resp, err := service.GetBackendInfo(context.Background(), &pb.GetBackendInfoRequest{
			Name: "software",
		})
		if err != nil {
			t.Fatalf("GetBackendInfo failed: %v", err)
		}

		if resp.Backend == nil {
			t.Fatal("Expected non-nil backend")
		}
		if resp.Backend.Name != "software" {
			t.Errorf("Expected name 'software', got '%s'", resp.Backend.Name)
		}
	})

	t.Run("returns error for empty name", func(t *testing.T) {
		_, err := service.GetBackendInfo(context.Background(), &pb.GetBackendInfoRequest{
			Name: "",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for unknown backend", func(t *testing.T) {
		_, err := service.GetBackendInfo(context.Background(), &pb.GetBackendInfoRequest{
			Name: "nonexistent",
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

func TestService_GenerateKey(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	t.Run("generates RSA key", func(t *testing.T) {
		resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "test-rsa-key",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if resp.KeyId != "test-rsa-key" {
			t.Errorf("Expected key_id 'test-rsa-key', got '%s'", resp.KeyId)
		}
		if resp.CreatedAt == nil {
			t.Error("Expected non-nil created_at")
		}
	})

	t.Run("generates ECDSA key", func(t *testing.T) {
		resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "test-ecdsa-key",
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "P256",
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if resp.KeyId != "test-ecdsa-key" {
			t.Errorf("Expected key_id 'test-ecdsa-key', got '%s'", resp.KeyId)
		}
		if resp.PublicKeyPem == "" {
			t.Error("Expected non-empty public key PEM")
		}
	})

	t.Run("generates Ed25519 key", func(t *testing.T) {
		resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "test-ed25519-key",
			Backend: "software",
			KeyType: "ed25519",
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if resp.KeyId != "test-ed25519-key" {
			t.Errorf("Expected key_id 'test-ed25519-key', got '%s'", resp.KeyId)
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			Backend: "software",
			KeyType: "rsa",
		})
		if err == nil {
			t.Fatal("Expected error")
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
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "test-key",
			KeyType: "rsa",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing key_type", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "test-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for unknown backend", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "test-key",
			Backend: "nonexistent",
			KeyType: "rsa",
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

	t.Run("returns error for invalid curve", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "test-key",
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "invalid-curve",
		})
		if err == nil {
			t.Fatal("Expected error")
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

func TestService_ListKeys(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	// Generate a key first
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "list-test-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Run("lists keys", func(t *testing.T) {
		resp, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
			Backend: "software",
		})
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}

		if resp.Total == 0 {
			t.Error("Expected at least one key")
		}
	})

	t.Run("applies pagination", func(t *testing.T) {
		resp, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
			Backend: "software",
			Offset:  0,
			Limit:   1,
		})
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}

		if len(resp.Keys) > 1 {
			t.Error("Expected at most 1 key with limit=1")
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for unknown backend", func(t *testing.T) {
		_, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
			Backend: "nonexistent",
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

func TestService_GetKey(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	// Generate a key first
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "get-test-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Run("gets key info", func(t *testing.T) {
		resp, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
			KeyId:   "get-test-key",
			Backend: "software",
		})
		if err != nil {
			t.Fatalf("GetKey failed: %v", err)
		}

		if resp.Key == nil {
			t.Fatal("Expected non-nil key")
		}
		if resp.Key.KeyId != "get-test-key" {
			t.Errorf("Expected key_id 'get-test-key', got '%s'", resp.Key.KeyId)
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error")
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
		_, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
			KeyId: "test-key",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for nonexistent key", func(t *testing.T) {
		_, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
			KeyId:   "nonexistent-key",
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

func TestService_Sign(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	// Generate a key for signing
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "sign-test-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Run("signs data", func(t *testing.T) {
		resp, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "sign-test-key",
			Backend: "software",
			Data:    []byte("test data to sign"),
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if len(resp.Signature) == 0 {
			t.Error("Expected non-empty signature")
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.Sign(context.Background(), &pb.SignRequest{
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
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId: "sign-test-key",
			Data:  []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error")
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
		_, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "sign-test-key",
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error")
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

func TestService_Verify(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	// Generate a key and sign data
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "verify-test-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	testData := []byte("test data to sign and verify")
	signResp, err := service.Sign(context.Background(), &pb.SignRequest{
		KeyId:   "verify-test-key",
		Backend: "software",
		Data:    testData,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	t.Run("verifies valid signature", func(t *testing.T) {
		resp, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "verify-test-key",
			Backend:   "software",
			Data:      testData,
			Signature: signResp.Signature,
		})
		if err != nil {
			t.Fatalf("Verify failed: %v", err)
		}

		if !resp.Valid {
			t.Error("Expected signature to be valid")
		}
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		resp, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "verify-test-key",
			Backend:   "software",
			Data:      testData,
			Signature: []byte("invalid-signature"),
		})
		if err != nil {
			t.Fatalf("Verify failed: %v", err)
		}

		if resp.Valid {
			t.Error("Expected signature to be invalid")
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			Backend:   "software",
			Data:      testData,
			Signature: signResp.Signature,
		})
		if err == nil {
			t.Fatal("Expected error")
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
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "verify-test-key",
			Backend:   "software",
			Signature: signResp.Signature,
		})
		if err == nil {
			t.Fatal("Expected error")
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
			KeyId:   "verify-test-key",
			Backend: "software",
			Data:    testData,
		})
		if err == nil {
			t.Fatal("Expected error")
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

func TestService_DeleteKey(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	// Generate a key to delete
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "delete-test-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Run("deletes key", func(t *testing.T) {
		resp, err := service.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
			KeyId:   "delete-test-key",
			Backend: "software",
		})
		if err != nil {
			t.Fatalf("DeleteKey failed: %v", err)
		}

		if !resp.Success {
			t.Error("Expected success to be true")
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error")
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
		_, err := service.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
			KeyId: "delete-test-key",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for nonexistent key", func(t *testing.T) {
		_, err := service.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
			KeyId:   "nonexistent-key",
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

func TestService_RotateKey(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	// Generate a key to rotate
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "rotate-test-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Run("rotates key", func(t *testing.T) {
		resp, err := service.RotateKey(context.Background(), &pb.RotateKeyRequest{
			KeyId:   "rotate-test-key",
			Backend: "software",
		})
		if err != nil {
			t.Fatalf("RotateKey failed: %v", err)
		}

		if resp.KeyId != "rotate-test-key" {
			t.Errorf("Expected key_id 'rotate-test-key', got '%s'", resp.KeyId)
		}
		if resp.RotatedAt == nil {
			t.Error("Expected non-nil rotated_at")
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.RotateKey(context.Background(), &pb.RotateKeyRequest{
			Backend: "software",
		})
		if err == nil {
			t.Fatal("Expected error")
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
		_, err := service.RotateKey(context.Background(), &pb.RotateKeyRequest{
			KeyId: "rotate-test-key",
		})
		if err == nil {
			t.Fatal("Expected error")
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

// Helper to create a test certificate
func createTestCertificate(t *testing.T) *x509.Certificate {
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

func TestService_SaveCert(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	cert := createTestCertificate(t)
	certPEM := encodeCertToPEM(cert)

	t.Run("saves certificate", func(t *testing.T) {
		resp, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
			KeyId:   "save-cert-test",
			CertPem: certPEM,
		})
		if err != nil {
			t.Fatalf("SaveCert failed: %v", err)
		}

		if !resp.Success {
			t.Error("Expected success to be true")
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
			CertPem: certPEM,
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing cert_pem", func(t *testing.T) {
		_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
			KeyId: "save-cert-test",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for invalid PEM", func(t *testing.T) {
		_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
			KeyId:   "save-cert-test",
			CertPem: "invalid pem",
		})
		if err == nil {
			t.Fatal("Expected error")
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

func TestService_GetCert(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	// Save a certificate first
	cert := createTestCertificate(t)
	certPEM := encodeCertToPEM(cert)

	_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "get-cert-test",
		CertPem: certPEM,
	})
	if err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	t.Run("gets certificate", func(t *testing.T) {
		resp, err := service.GetCert(context.Background(), &pb.GetCertRequest{
			KeyId: "get-cert-test",
		})
		if err != nil {
			t.Fatalf("GetCert failed: %v", err)
		}

		if resp.CertPem == "" {
			t.Error("Expected non-empty cert_pem")
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.GetCert(context.Background(), &pb.GetCertRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for nonexistent certificate", func(t *testing.T) {
		_, err := service.GetCert(context.Background(), &pb.GetCertRequest{
			KeyId: "nonexistent-cert",
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

func TestService_DeleteCert(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	// Save a certificate first
	cert := createTestCertificate(t)
	certPEM := encodeCertToPEM(cert)

	_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "delete-cert-test",
		CertPem: certPEM,
	})
	if err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	t.Run("deletes certificate", func(t *testing.T) {
		resp, err := service.DeleteCert(context.Background(), &pb.DeleteCertRequest{
			KeyId: "delete-cert-test",
		})
		if err != nil {
			t.Fatalf("DeleteCert failed: %v", err)
		}

		if !resp.Success {
			t.Error("Expected success to be true")
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.DeleteCert(context.Background(), &pb.DeleteCertRequest{})
		if err == nil {
			t.Fatal("Expected error")
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

func TestService_ListCerts(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	// Save a certificate first
	cert := createTestCertificate(t)
	certPEM := encodeCertToPEM(cert)

	_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "list-cert-test",
		CertPem: certPEM,
	})
	if err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	t.Run("lists certificates", func(t *testing.T) {
		resp, err := service.ListCerts(context.Background(), &pb.ListCertsRequest{})
		if err != nil {
			t.Fatalf("ListCerts failed: %v", err)
		}

		if resp.Total == 0 {
			t.Error("Expected at least one certificate")
		}
	})
}

func TestService_CertExists(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	// Save a certificate first
	cert := createTestCertificate(t)
	certPEM := encodeCertToPEM(cert)

	_, err := service.SaveCert(context.Background(), &pb.SaveCertRequest{
		KeyId:   "exists-cert-test",
		CertPem: certPEM,
	})
	if err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	t.Run("returns true for existing certificate", func(t *testing.T) {
		resp, err := service.CertExists(context.Background(), &pb.CertExistsRequest{
			KeyId: "exists-cert-test",
		})
		if err != nil {
			t.Fatalf("CertExists failed: %v", err)
		}

		if !resp.Exists {
			t.Error("Expected certificate to exist")
		}
	})

	t.Run("returns false for nonexistent certificate", func(t *testing.T) {
		resp, err := service.CertExists(context.Background(), &pb.CertExistsRequest{
			KeyId: "nonexistent-cert",
		})
		if err != nil {
			t.Fatalf("CertExists failed: %v", err)
		}

		if resp.Exists {
			t.Error("Expected certificate to not exist")
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.CertExists(context.Background(), &pb.CertExistsRequest{})
		if err == nil {
			t.Fatal("Expected error")
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

func TestService_SaveCertChain(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	cert := createTestCertificate(t)
	certPEM := encodeCertToPEM(cert)

	t.Run("saves certificate chain", func(t *testing.T) {
		resp, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
			KeyId:        "chain-test",
			CertChainPem: []string{certPEM},
		})
		if err != nil {
			t.Fatalf("SaveCertChain failed: %v", err)
		}

		if !resp.Success {
			t.Error("Expected success to be true")
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
			CertChainPem: []string{certPEM},
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for empty chain", func(t *testing.T) {
		_, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
			KeyId:        "chain-test",
			CertChainPem: []string{},
		})
		if err == nil {
			t.Fatal("Expected error")
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

func TestService_GetCertChain(t *testing.T) {
	service := setupServiceTest(t)
	defer keychain.Reset()

	// Save a certificate chain first
	cert := createTestCertificate(t)
	certPEM := encodeCertToPEM(cert)

	_, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
		KeyId:        "get-chain-test",
		CertChainPem: []string{certPEM},
	})
	if err != nil {
		t.Fatalf("Failed to save certificate chain: %v", err)
	}

	t.Run("gets certificate chain", func(t *testing.T) {
		resp, err := service.GetCertChain(context.Background(), &pb.GetCertChainRequest{
			KeyId: "get-chain-test",
		})
		if err != nil {
			t.Fatalf("GetCertChain failed: %v", err)
		}

		if len(resp.CertChainPem) == 0 {
			t.Error("Expected non-empty certificate chain")
		}
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.GetCertChain(context.Background(), &pb.GetCertChainRequest{})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for nonexistent chain", func(t *testing.T) {
		_, err := service.GetCertChain(context.Background(), &pb.GetCertChainRequest{
			KeyId: "nonexistent-chain",
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
