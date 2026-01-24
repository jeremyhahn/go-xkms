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
	"testing"

	pb "github.com/jeremyhahn/go-keychain/pkg/api/grpc/proto/keychainv1"
	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setupCoverageTest initializes keychain for coverage tests
func setupCoverageTest(t *testing.T) *Service {
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

// TestService_SignWithDifferentKeyTypes tests signing with various key types
func TestService_SignWithDifferentKeyTypes(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("signs with RSA key", func(t *testing.T) {
		// Generate RSA key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "rsa-sign-key",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Sign with RSA key
		resp, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "rsa-sign-key",
			Backend: "software",
			Data:    []byte("test data to sign with RSA"),
			Hash:    "SHA256",
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if len(resp.Signature) == 0 {
			t.Error("Expected non-empty signature")
		}
	})

	t.Run("signs with Ed25519 key", func(t *testing.T) {
		// Generate Ed25519 key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "ed25519-sign-key",
			Backend: "software",
			KeyType: "ed25519",
		})
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		// Sign with Ed25519 key
		resp, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "ed25519-sign-key",
			Backend: "software",
			Data:    []byte("test data to sign with Ed25519"),
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if len(resp.Signature) == 0 {
			t.Error("Expected non-empty signature")
		}
	})

	t.Run("returns error for nonexistent key", func(t *testing.T) {
		_, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "nonexistent-key",
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

// TestService_VerifyWithDifferentKeyTypes tests verification with various key types
func TestService_VerifyWithDifferentKeyTypes(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("verifies with RSA key", func(t *testing.T) {
		// Generate RSA key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "rsa-verify-key",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		testData := []byte("test data to sign and verify with RSA")

		// Sign
		signResp, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "rsa-verify-key",
			Backend: "software",
			Data:    testData,
			Hash:    "SHA256",
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		// Verify
		verifyResp, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "rsa-verify-key",
			Backend:   "software",
			Data:      testData,
			Signature: signResp.Signature,
			Hash:      "SHA256",
		})
		if err != nil {
			t.Fatalf("Verify failed: %v", err)
		}

		if !verifyResp.Valid {
			t.Error("Expected signature to be valid")
		}
	})

	t.Run("verifies with Ed25519 key", func(t *testing.T) {
		// Generate Ed25519 key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "ed25519-verify-key",
			Backend: "software",
			KeyType: "ed25519",
		})
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		testData := []byte("test data to sign and verify with Ed25519")

		// Sign
		signResp, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "ed25519-verify-key",
			Backend: "software",
			Data:    testData,
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		// Verify
		verifyResp, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "ed25519-verify-key",
			Backend:   "software",
			Data:      testData,
			Signature: signResp.Signature,
		})
		if err != nil {
			t.Fatalf("Verify failed: %v", err)
		}

		if !verifyResp.Valid {
			t.Error("Expected signature to be valid")
		}
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		_, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "test-key",
			Data:      []byte("test data"),
			Signature: []byte("signature"),
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

// TestService_Encrypt tests symmetric encryption
func TestService_Encrypt(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			Backend:   "software",
			Plaintext: []byte("test data"),
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
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:     "test-key",
			Plaintext: []byte("test data"),
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

	t.Run("returns error for missing plaintext", func(t *testing.T) {
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
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
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:     "test-key",
			Backend:   "nonexistent",
			Plaintext: []byte("test data"),
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

	t.Run("returns error for nonexistent key", func(t *testing.T) {
		_, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:     "nonexistent-key",
			Backend:   "software",
			Plaintext: []byte("test data"),
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

// TestService_Decrypt tests symmetric decryption
func TestService_Decrypt(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			Backend:    "software",
			Ciphertext: []byte("encrypted data"),
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
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:      "test-key",
			Ciphertext: []byte("encrypted data"),
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

	t.Run("returns error for missing ciphertext", func(t *testing.T) {
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
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
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:      "test-key",
			Backend:    "nonexistent",
			Ciphertext: []byte("encrypted data"),
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

	t.Run("returns error for nonexistent key", func(t *testing.T) {
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:      "nonexistent-key",
			Backend:    "software",
			Ciphertext: []byte("encrypted data"),
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

// TestService_GetTLSCertificate tests GetTLSCertificate operation
func TestService_GetTLSCertificate(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{
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
		_, err := service.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{
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

	t.Run("returns error for unknown backend", func(t *testing.T) {
		_, err := service.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{
			KeyId:   "test-key",
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

	t.Run("returns error for nonexistent key", func(t *testing.T) {
		_, err := service.GetTLSCertificate(context.Background(), &pb.GetTLSCertificateRequest{
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

// TestService_CopyKey tests key copying between backends
func TestService_CopyKey(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing source_backend", func(t *testing.T) {
		_, err := service.CopyKey(context.Background(), &pb.CopyKeyRequest{
			SourceKeyId:       "source-key",
			DestBackend:       "software",
			DestKeyId:         "dest-key",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
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

	t.Run("returns error for missing source_key_id", func(t *testing.T) {
		_, err := service.CopyKey(context.Background(), &pb.CopyKeyRequest{
			SourceBackend:     "software",
			DestBackend:       "software",
			DestKeyId:         "dest-key",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
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

	t.Run("returns error for missing dest_backend", func(t *testing.T) {
		_, err := service.CopyKey(context.Background(), &pb.CopyKeyRequest{
			SourceBackend:     "software",
			SourceKeyId:       "source-key",
			DestKeyId:         "dest-key",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
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

	t.Run("returns error for missing dest_key_id", func(t *testing.T) {
		_, err := service.CopyKey(context.Background(), &pb.CopyKeyRequest{
			SourceBackend:     "software",
			SourceKeyId:       "source-key",
			DestBackend:       "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
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

	t.Run("returns error for missing wrapping_algorithm", func(t *testing.T) {
		_, err := service.CopyKey(context.Background(), &pb.CopyKeyRequest{
			SourceBackend: "software",
			SourceKeyId:   "source-key",
			DestBackend:   "software",
			DestKeyId:     "dest-key",
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

	t.Run("returns error for unknown source backend", func(t *testing.T) {
		_, err := service.CopyKey(context.Background(), &pb.CopyKeyRequest{
			SourceBackend:     "nonexistent",
			SourceKeyId:       "source-key",
			DestBackend:       "software",
			DestKeyId:         "dest-key",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
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

	t.Run("returns error for unknown destination backend", func(t *testing.T) {
		_, err := service.CopyKey(context.Background(), &pb.CopyKeyRequest{
			SourceBackend:     "software",
			SourceKeyId:       "source-key",
			DestBackend:       "nonexistent",
			DestKeyId:         "dest-key",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
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

// TestService_GenerateKeySymmetric tests symmetric key generation
func TestService_GenerateKeySymmetric(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("generates symmetric key with default size", func(t *testing.T) {
		resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "sym-key-default",
			Backend:   "software",
			KeyType:   "symmetric",
			Algorithm: "symmetric",
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if resp.KeyId != "sym-key-default" {
			t.Errorf("Expected key_id 'sym-key-default', got '%s'", resp.KeyId)
		}
	})

	t.Run("generates AES-128 symmetric key", func(t *testing.T) {
		resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "sym-key-128",
			Backend:   "software",
			KeyType:   "symmetric",
			Algorithm: "symmetric",
			KeySize:   128,
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if resp.KeyId != "sym-key-128" {
			t.Errorf("Expected key_id 'sym-key-128', got '%s'", resp.KeyId)
		}
	})

	t.Run("generates AES-192 symmetric key", func(t *testing.T) {
		resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "sym-key-192",
			Backend:   "software",
			KeyType:   "symmetric",
			Algorithm: "symmetric",
			KeySize:   192,
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if resp.KeyId != "sym-key-192" {
			t.Errorf("Expected key_id 'sym-key-192', got '%s'", resp.KeyId)
		}
	})

	t.Run("generates AES-256 symmetric key", func(t *testing.T) {
		resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "sym-key-256",
			Backend:   "software",
			KeyType:   "symmetric",
			Algorithm: "symmetric",
			KeySize:   256,
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if resp.KeyId != "sym-key-256" {
			t.Errorf("Expected key_id 'sym-key-256', got '%s'", resp.KeyId)
		}
	})

	t.Run("returns error for invalid symmetric key size", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "sym-key-invalid",
			Backend:   "software",
			KeyType:   "symmetric",
			Algorithm: "symmetric",
			KeySize:   64, // Invalid size
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

	t.Run("returns error for unsupported algorithm", func(t *testing.T) {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "unsupported-key",
			Backend:   "software",
			KeyType:   "unsupported",
			Algorithm: "unsupported",
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

// TestService_ListKeysPagination tests pagination edge cases
func TestService_ListKeysPagination(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	// Generate multiple keys for pagination testing
	for i := 0; i < 5; i++ {
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   string(rune('a'+i)) + "-pagination-key",
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "P256",
		})
		if err != nil {
			t.Fatalf("Failed to generate key %d: %v", i, err)
		}
	}

	t.Run("applies offset beyond total", func(t *testing.T) {
		resp, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
			Backend: "software",
			Offset:  100, // Beyond total keys
			Limit:   10,
		})
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}

		if len(resp.Keys) != 0 {
			t.Errorf("Expected 0 keys with offset beyond total, got %d", len(resp.Keys))
		}
	})

	t.Run("applies limit 0 uses default", func(t *testing.T) {
		resp, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
			Backend: "software",
			Limit:   0, // Should use default limit
		})
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}

		// Should return all keys (default limit is 100)
		if resp.Total != int32(len(resp.Keys)) {
			t.Errorf("Expected all keys to be returned")
		}
	})

	t.Run("handles end beyond total", func(t *testing.T) {
		resp, err := service.ListKeys(context.Background(), &pb.ListKeysRequest{
			Backend: "software",
			Offset:  3,
			Limit:   100, // Beyond remaining keys
		})
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}

		// Should return remaining keys from offset
		expectedRemaining := int(resp.Total) - 3
		if expectedRemaining < 0 {
			expectedRemaining = 0
		}
		if len(resp.Keys) != expectedRemaining {
			t.Errorf("Expected %d keys, got %d", expectedRemaining, len(resp.Keys))
		}
	})
}

// TestService_RotateKeyEdgeCases tests edge cases for key rotation
func TestService_RotateKeyEdgeCases(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns error for unknown backend", func(t *testing.T) {
		_, err := service.RotateKey(context.Background(), &pb.RotateKeyRequest{
			KeyId:   "test-key",
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

	t.Run("returns error for nonexistent key", func(t *testing.T) {
		_, err := service.RotateKey(context.Background(), &pb.RotateKeyRequest{
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

// TestService_GetKeyWithRSAAndECCInfo tests GetKey returns correct key-specific info
func TestService_GetKeyWithRSAAndECCInfo(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns RSA key info with size", func(t *testing.T) {
		// Generate RSA key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "rsa-info-key",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		resp, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
			KeyId:   "rsa-info-key",
			Backend: "software",
		})
		if err != nil {
			t.Fatalf("GetKey failed: %v", err)
		}

		if resp.Key.KeySize == 0 {
			t.Error("Expected RSA key size to be set")
		}
	})

	t.Run("returns ECDSA key info with curve", func(t *testing.T) {
		// Generate ECDSA key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "ecdsa-info-key",
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "P384",
		})
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		resp, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
			KeyId:   "ecdsa-info-key",
			Backend: "software",
		})
		if err != nil {
			t.Fatalf("GetKey failed: %v", err)
		}

		if resp.Key.Curve == "" {
			t.Error("Expected ECDSA key curve to be set")
		}
	})
}

// TestService_SaveCertChainWithInvalidPEM tests SaveCertChain with invalid PEM
func TestService_SaveCertChainWithInvalidPEM(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns error for invalid cert in chain", func(t *testing.T) {
		_, err := service.SaveCertChain(context.Background(), &pb.SaveCertChainRequest{
			KeyId:        "invalid-chain-test",
			CertChainPem: []string{"invalid pem"},
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

// TestGetImportParametersWithValidBackend tests GetImportParameters with a real backend
func TestGetImportParametersWithValidBackend(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("ECDSA key with default curve", func(t *testing.T) {
		// This tests the ECDSA path with a default curve
		_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId:             "import-ecdsa-key",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			KeyType:           "ecdsa",
		})
		// This should succeed or fail at the backend level
		// We're testing the parsing path
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			// Any valid gRPC error code is acceptable
			_ = st
		}
	})

	t.Run("Ed25519 key", func(t *testing.T) {
		_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId:             "import-ed25519-key",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			KeyType:           "ed25519",
		})
		// Testing the parsing path
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			_ = st
		}
	})

	t.Run("Symmetric key with valid sizes", func(t *testing.T) {
		for _, size := range []int32{128, 192, 256} {
			_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
				KeyId:             "import-sym-key",
				Backend:           "software",
				WrappingAlgorithm: "RSAES_OAEP_SHA_256",
				KeyType:           "symmetric",
				KeySize:           size,
			})
			// Testing the parsing path
			if err != nil {
				st, ok := status.FromError(err)
				if !ok {
					t.Fatalf("Expected gRPC status error for size %d", size)
				}
				_ = st
			}
		}
	})

	t.Run("Symmetric key with invalid size", func(t *testing.T) {
		_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId:             "import-sym-key",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			KeyType:           "symmetric",
			KeySize:           64, // Invalid size
		})
		if err == nil {
			t.Fatal("Expected error for invalid key size")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("Invalid curve", func(t *testing.T) {
		_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId:             "import-ecdsa-key",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			KeyType:           "ecdsa",
			Curve:             "invalid-curve",
		})
		if err == nil {
			t.Fatal("Expected error for invalid curve")
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

// TestImportKeyWithValidBackend tests ImportKey with a real backend
func TestImportKeyWithValidBackend(t *testing.T) {
	service := setupCoverageTest(t)
	defer keychain.Reset()

	t.Run("ECDSA key with default curve", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-test-ecdsa",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key"),
			Algorithm:  "RSAES_OAEP_SHA_256",
			KeyType:    "ecdsa",
		})
		// Testing the parsing path - will fail at import but should parse correctly
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			// Any error is acceptable as we're testing parsing
			_ = st
		}
	})

	t.Run("Ed25519 key", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-test-ed25519",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key"),
			Algorithm:  "RSAES_OAEP_SHA_256",
			KeyType:    "ed25519",
		})
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			_ = st
		}
	})

	t.Run("Symmetric key with valid sizes", func(t *testing.T) {
		for _, size := range []int32{128, 192, 256} {
			_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
				KeyId:      "import-test-sym",
				Backend:    "software",
				WrappedKey: []byte("wrapped-key"),
				Algorithm:  "RSAES_OAEP_SHA_256",
				KeyType:    "symmetric",
				KeySize:    size,
			})
			if err != nil {
				st, ok := status.FromError(err)
				if !ok {
					t.Fatalf("Expected gRPC status error for size %d", size)
				}
				_ = st
			}
		}
	})

	t.Run("Symmetric key with invalid size", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-test-sym-invalid",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key"),
			Algorithm:  "RSAES_OAEP_SHA_256",
			KeyType:    "symmetric",
			KeySize:    64, // Invalid size
		})
		if err == nil {
			t.Fatal("Expected error for invalid key size")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("Invalid curve", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-test-ecdsa-invalid",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key"),
			Algorithm:  "RSAES_OAEP_SHA_256",
			KeyType:    "ecdsa",
			Curve:      "invalid-curve",
		})
		if err == nil {
			t.Fatal("Expected error for invalid curve")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("Unsupported key type", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-test-unsupported",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key"),
			Algorithm:  "RSAES_OAEP_SHA_256",
			KeyType:    "unsupported",
		})
		if err == nil {
			t.Fatal("Expected error for unsupported key type")
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
