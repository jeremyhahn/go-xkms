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

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setupAsymVersionTest initializes keychain for asymmetric encryption and version tests
func setupAsymVersionTest(t *testing.T) *Service {
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

// TestService_EncryptAsym tests asymmetric encryption functionality
func TestService_EncryptAsym(t *testing.T) {
	service := setupAsymVersionTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing key_id", func(t *testing.T) {
		_, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
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
		_, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
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
		_, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
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

	t.Run("returns error for nonexistent backend", func(t *testing.T) {
		_, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "test-key",
			Backend:   "nonexistent",
			Plaintext: []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for nonexistent backend")
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
		_, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "nonexistent-key",
			Backend:   "software",
			Plaintext: []byte("test data"),
		})
		if err == nil {
			t.Fatal("Expected error for nonexistent key")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound, got %v", st.Code())
		}
	})

	t.Run("encrypts data with RSA key and default hash", func(t *testing.T) {
		// Generate RSA key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "rsa-asym-key",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Encrypt with RSA key
		resp, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "rsa-asym-key",
			Backend:   "software",
			Plaintext: []byte("test data to encrypt"),
		})
		if err != nil {
			t.Fatalf("EncryptAsym failed: %v", err)
		}

		if len(resp.Ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext")
		}
	})

	t.Run("encrypts data with RSA key and SHA256 hash", func(t *testing.T) {
		// Generate RSA key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "rsa-asym-key-sha256",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Encrypt with RSA key using SHA256
		resp, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "rsa-asym-key-sha256",
			Backend:   "software",
			Plaintext: []byte("test data to encrypt"),
			Hash:      "SHA-256",
		})
		if err != nil {
			t.Fatalf("EncryptAsym failed: %v", err)
		}

		if len(resp.Ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext")
		}
	})

	t.Run("encrypts data with RSA key and SHA384 hash", func(t *testing.T) {
		// Generate RSA key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "rsa-asym-key-sha384",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Encrypt with RSA key using SHA384
		resp, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "rsa-asym-key-sha384",
			Backend:   "software",
			Plaintext: []byte("test data to encrypt"),
			Hash:      "sha384",
		})
		if err != nil {
			t.Fatalf("EncryptAsym failed: %v", err)
		}

		if len(resp.Ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext")
		}
	})

	t.Run("encrypts data with RSA key and SHA512 hash", func(t *testing.T) {
		// Generate RSA key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "rsa-asym-key-sha512",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Encrypt with RSA key using SHA512
		resp, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "rsa-asym-key-sha512",
			Backend:   "software",
			Plaintext: []byte("test data to encrypt"),
			Hash:      "sha-512",
		})
		if err != nil {
			t.Fatalf("EncryptAsym failed: %v", err)
		}

		if len(resp.Ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext")
		}
	})

	t.Run("encrypts data with RSA key and SHA1 hash", func(t *testing.T) {
		// Generate RSA key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "rsa-asym-key-sha1",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Encrypt with RSA key using SHA1
		resp, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "rsa-asym-key-sha1",
			Backend:   "software",
			Plaintext: []byte("test data to encrypt"),
			Hash:      "sha1",
		})
		if err != nil {
			t.Fatalf("EncryptAsym failed: %v", err)
		}

		if len(resp.Ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext")
		}
	})

	t.Run("encrypts data with unknown hash defaults to SHA256", func(t *testing.T) {
		// Generate RSA key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "rsa-asym-key-unknown-hash",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Encrypt with RSA key using unknown hash (should default to SHA256)
		resp, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "rsa-asym-key-unknown-hash",
			Backend:   "software",
			Plaintext: []byte("test data to encrypt"),
			Hash:      "unknown-hash",
		})
		if err != nil {
			t.Fatalf("EncryptAsym failed: %v", err)
		}

		if len(resp.Ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext")
		}
	})

	t.Run("returns error for EC key (not supported)", func(t *testing.T) {
		// Generate EC key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "ec-asym-key",
			Backend: "software",
			KeyType: "ecdsa",
			KeySize: 256,
		})
		if err != nil {
			t.Fatalf("Failed to generate EC key: %v", err)
		}

		// Try to encrypt with EC key (should fail)
		_, err = service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "ec-asym-key",
			Backend:   "software",
			Plaintext: []byte("test data to encrypt"),
		})
		if err == nil {
			t.Fatal("Expected error for EC key")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for Ed25519 key (not supported)", func(t *testing.T) {
		// Generate Ed25519 key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "ed25519-asym-key",
			Backend: "software",
			KeyType: "ed25519",
		})
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		// Try to encrypt with Ed25519 key (should fail)
		_, err = service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "ed25519-asym-key",
			Backend:   "software",
			Plaintext: []byte("test data to encrypt"),
		})
		if err == nil {
			t.Fatal("Expected error for Ed25519 key")
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

// TestService_KeyVersioning tests key versioning endpoints (all unimplemented)
func TestService_KeyVersioning(t *testing.T) {
	service := setupAsymVersionTest(t)
	defer keychain.Reset()

	t.Run("ListKeyVersions returns unimplemented", func(t *testing.T) {
		_, err := service.ListKeyVersions(context.Background(), &pb.ListKeyVersionsRequest{
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
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("EnableKeyVersion returns unimplemented", func(t *testing.T) {
		_, err := service.EnableKeyVersion(context.Background(), &pb.EnableKeyVersionRequest{
			KeyId:   "test-key",
			Backend: "software",
			Version: 1,
		})
		if err == nil {
			t.Fatal("Expected error")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("DisableKeyVersion returns unimplemented", func(t *testing.T) {
		_, err := service.DisableKeyVersion(context.Background(), &pb.DisableKeyVersionRequest{
			KeyId:   "test-key",
			Backend: "software",
			Version: 1,
		})
		if err == nil {
			t.Fatal("Expected error")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("EnableAllKeyVersions returns unimplemented", func(t *testing.T) {
		_, err := service.EnableAllKeyVersions(context.Background(), &pb.EnableAllKeyVersionsRequest{
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
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})

	t.Run("DisableAllKeyVersions returns unimplemented", func(t *testing.T) {
		_, err := service.DisableAllKeyVersions(context.Background(), &pb.DisableAllKeyVersionsRequest{
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
		if st.Code() != codes.Unimplemented {
			t.Errorf("Expected Unimplemented, got %v", st.Code())
		}
	})
}

// TestParseHashAlgorithmForOAEP tests the hash parsing helper function
func TestParseHashAlgorithmForOAEP(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string defaults to SHA256", "", "SHA-256"},
		{"sha256 lowercase", "sha256", "SHA-256"},
		{"SHA-256 uppercase with dash", "SHA-256", "SHA-256"},
		{"256 only", "256", "SHA-256"},
		{"sha384 lowercase", "sha384", "SHA-384"},
		{"SHA-384 uppercase with dash", "SHA-384", "SHA-384"},
		{"384 only", "384", "SHA-384"},
		{"sha512 lowercase", "sha512", "SHA-512"},
		{"SHA-512 uppercase with dash", "SHA-512", "SHA-512"},
		{"512 only", "512", "SHA-512"},
		{"sha1 lowercase", "sha1", "SHA-1"},
		{"SHA-1 uppercase with dash", "SHA-1", "SHA-1"},
		{"1 only", "1", "SHA-1"},
		{"unknown defaults to SHA256", "md5", "SHA-256"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseHashAlgorithmForOAEP(tc.input)
			if result.String() != tc.expected {
				t.Errorf("parseHashAlgorithmForOAEP(%q) = %s, expected %s", tc.input, result.String(), tc.expected)
			}
		})
	}
}
