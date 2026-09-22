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
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setupAsymVersionTest initializes xkms for asymmetric encryption and version tests
func setupAsymVersionTest(t *testing.T) *Service {
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
	return NewService(nil, nil, svc)
}

// TestService_EncryptAsym tests asymmetric encryption functionality
func TestService_EncryptAsym(t *testing.T) {
	service := setupAsymVersionTest(t)
	defer xkms.Reset()

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
			KeyType: "rsa", Algorithm: "rsa",
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
			KeyType: "rsa", Algorithm: "rsa",
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
			KeyType: "rsa", Algorithm: "rsa",
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
			KeyType: "rsa", Algorithm: "rsa",
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

	t.Run("rejects RSA OAEP with SHA-1 hash", func(t *testing.T) {
		// Generate RSA key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "rsa-asym-key-sha1",
			Backend: "software",
			KeyType: "rsa", Algorithm: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// SHA-1 OAEP must be rejected — F-14 security policy.
		_, err = service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "rsa-asym-key-sha1",
			Backend:   "software",
			Plaintext: []byte("test data to encrypt"),
			Hash:      "sha1",
		})
		if err == nil {
			t.Fatal("EncryptAsym with SHA-1 hash should return an error but did not")
		}
	})

	// An OAEP hash name the caller did supply that does not resolve must be
	// refused. Defaulting it to SHA-256 produces a ciphertext under a hash the
	// caller did not choose, and the peer that decrypts it has no way to know
	// which hash was actually used.
	t.Run("unknown hash is refused, not defaulted", func(t *testing.T) {
		// Generate RSA key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "rsa-asym-key-unknown-hash",
			Backend: "software",
			KeyType: "rsa", Algorithm: "rsa",
			KeySize: 2048,
		})
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		resp, err := service.EncryptAsym(context.Background(), &pb.EncryptAsymRequest{
			KeyId:     "rsa-asym-key-unknown-hash",
			Backend:   "software",
			Plaintext: []byte("test data to encrypt"),
			Hash:      "unknown-hash",
		})
		if err == nil {
			t.Fatal("EncryptAsym with an unresolvable hash must return an error")
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", status.Code(err))
		}
		if resp != nil {
			t.Error("Expected no ciphertext when the hash is refused")
		}
	})

	t.Run("returns error for EC key (not supported)", func(t *testing.T) {
		// Generate EC key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "ec-asym-key",
			Backend: "software",
			KeyType: "ecdsa", Algorithm: "ecdsa",
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
		// The key-type check belongs to the service layer, which has to make
		// it against the resolved public key rather than against
		// KeyAttributes.KeyAlgorithm, and which reports it as
		// xkms.ErrEncryptionFailed -- codes.Internal. It is the same answer
		// QUIC already gave for the identical request.
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal, got %v", st.Code())
		}
	})

	t.Run("returns error for Ed25519 key (not supported)", func(t *testing.T) {
		// Generate Ed25519 key first
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "ed25519-asym-key",
			Backend: "software",
			KeyType: "ed25519", Algorithm: "ed25519",
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
		// The key-type check belongs to the service layer, which has to make
		// it against the resolved public key rather than against
		// KeyAttributes.KeyAlgorithm, and which reports it as
		// xkms.ErrEncryptionFailed -- codes.Internal. It is the same answer
		// QUIC already gave for the identical request.
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal, got %v", st.Code())
		}
	})
}
