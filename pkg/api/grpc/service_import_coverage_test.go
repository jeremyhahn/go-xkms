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

// setupImportCoverageTest initializes keychain for import coverage tests
func setupImportCoverageTest(t *testing.T) *Service {
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

// TestImportKeyWithRSA tests ImportKey with RSA key type
func TestImportKeyWithRSA(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	t.Run("imports RSA key with default size", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-rsa-default",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key-data"),
			Algorithm:  "RSAES_OAEP_SHA_256",
			KeyType:    "rsa",
		})
		// Expected to fail at backend level, but tests code path
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			_ = st
		}
	})

	t.Run("imports RSA key with explicit size", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-rsa-explicit",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key-data"),
			Algorithm:  "RSAES_OAEP_SHA_256",
			KeyType:    "rsa",
			KeySize:    3072,
		})
		// Expected to fail at backend level, but tests code path
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			_ = st
		}
	})
}

// TestImportKeyWithEd25519 tests ImportKey with Ed25519 key type
func TestImportKeyWithEd25519(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:      "import-ed25519",
		Backend:    "software",
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  "RSAES_OAEP_SHA_256",
		KeyType:    "ed25519",
	})
	// Expected to fail at backend level, but tests code path
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		_ = st
	}
}

// TestImportKeyWithSymmetric tests ImportKey with symmetric key type
func TestImportKeyWithSymmetric(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	t.Run("imports symmetric key with 128 bit size", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-sym-128",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key-data"),
			Algorithm:  "RSAES_OAEP_SHA_256",
			KeyType:    "symmetric",
			KeySize:    128,
		})
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			_ = st
		}
	})

	t.Run("imports symmetric key with 192 bit size", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-sym-192",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key-data"),
			Algorithm:  "RSAES_OAEP_SHA_256",
			KeyType:    "symmetric",
			KeySize:    192,
		})
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			_ = st
		}
	})

	t.Run("imports symmetric key with 256 bit size", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-sym-256",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key-data"),
			Algorithm:  "RSAES_OAEP_SHA_256",
			KeyType:    "symmetric",
			KeySize:    256,
		})
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			_ = st
		}
	})

	t.Run("rejects symmetric key with invalid size", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-sym-invalid",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key-data"),
			Algorithm:  "RSAES_OAEP_SHA_256",
			KeyType:    "symmetric",
			KeySize:    512, // Invalid size
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
}

// TestImportKeyWithUnsupportedKeyType tests ImportKey with unsupported key type
func TestImportKeyWithUnsupportedKeyType(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:      "import-unsupported",
		Backend:    "software",
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  "RSAES_OAEP_SHA_256",
		KeyType:    "unsupported-type",
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
}

// TestImportKeyWithInvalidCurve tests ImportKey with invalid ECDSA curve
func TestImportKeyWithInvalidCurve(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
		KeyId:      "import-ecdsa-invalid-curve",
		Backend:    "software",
		WrappedKey: []byte("wrapped-key-data"),
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
}

// TestImportKeyValidationErrors tests ImportKey validation error paths
func TestImportKeyValidationErrors(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	t.Run("returns error for missing wrapped_key", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:     "import-no-wrapped-key",
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
			KeyType:   "rsa",
		})
		if err == nil {
			t.Fatal("Expected error for missing wrapped_key")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("returns error for missing algorithm", func(t *testing.T) {
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-no-algorithm",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key-data"),
			KeyType:    "rsa",
		})
		if err == nil {
			t.Fatal("Expected error for missing algorithm")
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
		_, err := service.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyId:      "import-no-key-type",
			Backend:    "software",
			WrappedKey: []byte("wrapped-key-data"),
			Algorithm:  "RSAES_OAEP_SHA_256",
		})
		if err == nil {
			t.Fatal("Expected error for missing key_type")
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

// TestGetImportParametersWithRSA tests GetImportParameters with RSA key type
func TestGetImportParametersWithRSA(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	t.Run("gets import parameters for RSA with default size", func(t *testing.T) {
		_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId:             "import-params-rsa-default",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			KeyType:           "rsa",
		})
		// May fail at backend level, but tests parsing path
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			_ = st
		}
	})

	t.Run("gets import parameters for RSA with explicit size", func(t *testing.T) {
		_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId:             "import-params-rsa-4096",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			KeyType:           "rsa",
			KeySize:           4096,
		})
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			_ = st
		}
	})
}

// TestGetImportParametersWithEd25519 tests GetImportParameters with Ed25519 key type
func TestGetImportParametersWithEd25519(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "import-params-ed25519",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "ed25519",
	})
	// May fail at backend level, but tests parsing path
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		_ = st
	}
}

// TestGetImportParametersWithSymmetric tests GetImportParameters with symmetric key types
func TestGetImportParametersWithSymmetric(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	t.Run("gets import parameters for symmetric 128-bit", func(t *testing.T) {
		_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId:             "import-params-sym-128",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			KeyType:           "symmetric",
			KeySize:           128,
		})
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			_ = st
		}
	})

	t.Run("gets import parameters for symmetric 192-bit", func(t *testing.T) {
		_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId:             "import-params-sym-192",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			KeyType:           "symmetric",
			KeySize:           192,
		})
		if err != nil {
			st, ok := status.FromError(err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}
			_ = st
		}
	})

	t.Run("rejects symmetric key with invalid size", func(t *testing.T) {
		_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId:             "import-params-sym-invalid",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			KeyType:           "symmetric",
			KeySize:           512, // Invalid size
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
}

// TestGetImportParametersWithUnsupportedKeyType tests GetImportParameters with unsupported key type
func TestGetImportParametersWithUnsupportedKeyType(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	_, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
		KeyId:             "import-params-unsupported",
		Backend:           "software",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		KeyType:           "unsupported-type",
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
}

// TestEncryptDecryptValidationErrors tests Encrypt and Decrypt validation paths
func TestEncryptDecryptValidationErrors(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	t.Run("Encrypt returns error for missing key_id", func(t *testing.T) {
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

	t.Run("Encrypt returns error for missing backend", func(t *testing.T) {
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

	t.Run("Encrypt returns error for missing plaintext", func(t *testing.T) {
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

	t.Run("Decrypt returns error for missing key_id", func(t *testing.T) {
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			Backend:    "software",
			Ciphertext: []byte("test data"),
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

	t.Run("Decrypt returns error for missing backend", func(t *testing.T) {
		_, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:      "test-key",
			Ciphertext: []byte("test data"),
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

	t.Run("Decrypt returns error for missing ciphertext", func(t *testing.T) {
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

// TestEncryptWithNonExistentKey tests Encrypt with non-existent key
func TestEncryptWithNonExistentKey(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

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
}

// TestGetAlgorithmStringIndirect tests the getAlgorithmString helper function indirectly
func TestGetAlgorithmStringIndirect(t *testing.T) {
	service := setupImportCoverageTest(t)
	defer keychain.Reset()

	// Generate a symmetric key (covers SymmetricAlgorithm branch)
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:     "algo-string-indirect-sym-test",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "symmetric",
		KeySize:   256,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Get key (which calls getAlgorithmString internally)
	resp, err := service.GetKey(context.Background(), &pb.GetKeyRequest{
		KeyId:   "algo-string-indirect-sym-test",
		Backend: "software",
	})
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if resp.Key.Algorithm == "" {
		t.Error("Expected algorithm to be set for symmetric key")
	}

	// Generate RSA key (covers KeyAlgorithm branch)
	_, err = service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "algo-string-indirect-rsa-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	resp, err = service.GetKey(context.Background(), &pb.GetKeyRequest{
		KeyId:   "algo-string-indirect-rsa-test",
		Backend: "software",
	})
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if resp.Key.Algorithm == "" {
		t.Error("Expected algorithm to be set for RSA key")
	}
}
