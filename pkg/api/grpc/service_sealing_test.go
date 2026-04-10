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
	"strings"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setupSealingTest initializes xkms service for sealing tests.
// The software backend supports sealing via PKCS8 (HKDF + AES-GCM).
func setupSealingTest(t *testing.T) *Service {
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

	return NewService(nil, nil)
}

// ============================================================================
// Seal Handler Tests
// ============================================================================

// TestService_Seal_MissingBackend tests Seal with empty backend parameter.
// The handler should validate that backend is required and return InvalidArgument.
func TestService_Seal_MissingBackend(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()
	testData := []byte("secret data to seal")

	t.Run("returns InvalidArgument for empty backend", func(t *testing.T) {
		_, err := service.Seal(ctx, &pb.SealRequest{
			Backend: "",
			Data:    testData,
		})
		if err == nil {
			t.Fatal("Expected error for empty backend")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument code, got: %v", st.Code())
		}
		if st.Message() != "backend is required" {
			t.Errorf("Expected 'backend is required' message, got: %s", st.Message())
		}
	})
}

// TestService_Seal_EmptyData tests Seal with empty data parameter.
// The handler should validate that data is required and return InvalidArgument.
func TestService_Seal_EmptyData(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	t.Run("returns InvalidArgument for empty data", func(t *testing.T) {
		_, err := service.Seal(ctx, &pb.SealRequest{
			Backend: "software",
			Data:    []byte{},
		})
		if err == nil {
			t.Fatal("Expected error for empty data")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument code, got: %v", st.Code())
		}
		if st.Message() != "data is required" {
			t.Errorf("Expected 'data is required' message, got: %s", st.Message())
		}
	})

	t.Run("returns InvalidArgument for nil data", func(t *testing.T) {
		_, err := service.Seal(ctx, &pb.SealRequest{
			Backend: "software",
			Data:    nil,
		})
		if err == nil {
			t.Fatal("Expected error for nil data")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument code, got: %v", st.Code())
		}
	})
}

// TestService_Seal_NonExistentBackend tests Seal with a backend that does not exist.
// The handler should return Internal error when the backend is not found.
func TestService_Seal_NonExistentBackend(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()
	testData := []byte("secret data to seal")

	t.Run("returns Internal error for non-existent backend", func(t *testing.T) {
		_, err := service.Seal(ctx, &pb.SealRequest{
			Backend: "nonexistent",
			Data:    testData,
		})
		if err == nil {
			t.Fatal("Expected error for non-existent backend")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal code, got: %v", st.Code())
		}
	})
}

// TestService_Seal_InvalidBackendName tests Seal with invalid backend name characters.
// The handler should reject backend names with injection attempts or invalid characters.
func TestService_Seal_InvalidBackendName(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()
	testData := []byte("test data")

	invalidBackendNames := []struct {
		name        string
		backendName string
	}{
		{"injection attempt", "software; drop table keys"},
		{"path traversal", "../../../etc/passwd"},
		{"null byte", "software\x00evil"},
	}

	for _, tc := range invalidBackendNames {
		t.Run(tc.name, func(t *testing.T) {
			_, err := service.Seal(ctx, &pb.SealRequest{
				Backend: tc.backendName,
				Data:    testData,
			})
			if err == nil {
				t.Fatal("Expected error for invalid backend name")
			}

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, got: %v", err)
			}
			// Should fail with Internal error from validation or backend not found
			if st.Code() != codes.Internal && st.Code() != codes.InvalidArgument {
				t.Errorf("Expected Internal or InvalidArgument code, got: %v", st.Code())
			}
		})
	}
}

// TestService_Seal_WithValidBackend tests Seal with a valid backend.
// Note: The current implementation requires KeyAttributes from key_id, which is not
// yet implemented in the handler. This test verifies the expected error behavior.
func TestService_Seal_WithValidBackend(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()
	testData := []byte("secret data to seal")

	t.Run("returns error when KeyAttributes not provided", func(t *testing.T) {
		// The current handler does not populate KeyAttributes from key_id,
		// so the backend will return an error about missing KeyAttributes.
		_, err := service.Seal(ctx, &pb.SealRequest{
			Backend: "software",
			Data:    testData,
		})

		// We expect an Internal error because the handler passes nil KeyAttributes
		// to the backend, which requires them for sealing.
		if err == nil {
			t.Fatal("Expected error when KeyAttributes is missing")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal code, got: %v", st.Code())
		}

		// Verify the error message indicates the KeyAttributes issue
		if !strings.Contains(st.Message(), "seal") {
			t.Errorf("Expected error message to contain 'seal', got: %s", st.Message())
		}
	})

	t.Run("returns NotFound error when key_id references non-existent key", func(t *testing.T) {
		// The handler now looks up the key by key_id (CN) and returns NotFound
		// if the key doesn't exist in the keystore.
		_, err := service.Seal(ctx, &pb.SealRequest{
			Backend: "software",
			KeyId:   "non-existent-key",
			Data:    testData,
		})

		if err == nil {
			t.Fatal("Expected error when key does not exist")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound code, got: %v", st.Code())
		}
	})

	t.Run("returns error with AAD when KeyAttributes missing", func(t *testing.T) {
		// Even when AAD is provided, the operation fails without KeyAttributes
		_, err := service.Seal(ctx, &pb.SealRequest{
			Backend: "software",
			Data:    testData,
			Aad:     []byte("additional authenticated data"),
		})

		if err == nil {
			t.Fatal("Expected error when KeyAttributes is missing")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal code, got: %v", st.Code())
		}
	})
}

// ============================================================================
// Unseal Handler Tests
// ============================================================================

// TestService_Unseal_MissingBackend tests Unseal with empty backend parameter.
// The handler should validate that backend is required and return InvalidArgument.
func TestService_Unseal_MissingBackend(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	t.Run("returns InvalidArgument for empty backend", func(t *testing.T) {
		_, err := service.Unseal(ctx, &pb.UnsealRequest{
			Backend:    "",
			Ciphertext: []byte("some ciphertext"),
		})
		if err == nil {
			t.Fatal("Expected error for empty backend")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument code, got: %v", st.Code())
		}
		if st.Message() != "backend is required" {
			t.Errorf("Expected 'backend is required' message, got: %s", st.Message())
		}
	})
}

// TestService_Unseal_EmptyCiphertext tests Unseal with empty ciphertext parameter.
// The handler should validate that ciphertext is required and return InvalidArgument.
func TestService_Unseal_EmptyCiphertext(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	t.Run("returns InvalidArgument for empty ciphertext", func(t *testing.T) {
		_, err := service.Unseal(ctx, &pb.UnsealRequest{
			Backend:    "software",
			Ciphertext: []byte{},
		})
		if err == nil {
			t.Fatal("Expected error for empty ciphertext")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument code, got: %v", st.Code())
		}
		if st.Message() != "ciphertext is required" {
			t.Errorf("Expected 'ciphertext is required' message, got: %s", st.Message())
		}
	})

	t.Run("returns InvalidArgument for nil ciphertext", func(t *testing.T) {
		_, err := service.Unseal(ctx, &pb.UnsealRequest{
			Backend:    "software",
			Ciphertext: nil,
		})
		if err == nil {
			t.Fatal("Expected error for nil ciphertext")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument code, got: %v", st.Code())
		}
	})
}

// TestService_Unseal_NonExistentBackend tests Unseal with a backend that does not exist.
// The handler should return NotFound error when the backend is not found.
func TestService_Unseal_NonExistentBackend(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	t.Run("returns NotFound error for non-existent backend", func(t *testing.T) {
		_, err := service.Unseal(ctx, &pb.UnsealRequest{
			Backend:    "nonexistent",
			Ciphertext: []byte("some ciphertext"),
		})
		if err == nil {
			t.Fatal("Expected error for non-existent backend")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound code, got: %v", st.Code())
		}
	})
}

// TestService_Unseal_WithValidBackend tests Unseal with valid backend.
// Note: The current implementation requires KeyAttributes, which is not
// yet implemented in the handler. This test verifies the expected error behavior.
func TestService_Unseal_WithValidBackend(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	t.Run("returns error when KeyAttributes not provided", func(t *testing.T) {
		// The current handler does not populate KeyAttributes from key_id,
		// so the backend will return an error about missing KeyAttributes.
		_, err := service.Unseal(ctx, &pb.UnsealRequest{
			Backend:    "software",
			Ciphertext: []byte("some ciphertext data"),
			Nonce:      []byte("nonce12bytes"),
		})

		// We expect an Internal error because the handler passes nil KeyAttributes
		if err == nil {
			t.Fatal("Expected error when KeyAttributes is missing")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal code, got: %v", st.Code())
		}
	})

	t.Run("returns NotFound error when key_id references non-existent key", func(t *testing.T) {
		// The handler now looks up the key by key_id (CN) and returns NotFound
		// if the key doesn't exist in the keystore.
		_, err := service.Unseal(ctx, &pb.UnsealRequest{
			Backend:    "software",
			KeyId:      "non-existent-key",
			Ciphertext: []byte("some ciphertext data"),
			Nonce:      []byte("nonce12bytes"),
		})

		if err == nil {
			t.Fatal("Expected error when key does not exist")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound code, got: %v", st.Code())
		}
	})
}

// TestService_Unseal_InvalidBackendName tests Unseal with invalid backend name characters.
func TestService_Unseal_InvalidBackendName(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	invalidBackendNames := []struct {
		name        string
		backendName string
	}{
		{"injection attempt", "software; drop table keys"},
		{"path traversal", "../../../etc/passwd"},
		{"null byte", "software\x00evil"},
	}

	for _, tc := range invalidBackendNames {
		t.Run(tc.name, func(t *testing.T) {
			_, err := service.Unseal(ctx, &pb.UnsealRequest{
				Backend:    tc.backendName,
				Ciphertext: []byte("some ciphertext"),
			})
			if err == nil {
				t.Fatal("Expected error for invalid backend name")
			}

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, got: %v", err)
			}
			// Should fail with NotFound error since invalid backend names won't be found
			if st.Code() != codes.NotFound && st.Code() != codes.InvalidArgument {
				t.Errorf("Expected NotFound or InvalidArgument code, got: %v", st.Code())
			}
		})
	}
}

// ============================================================================
// CanSeal Handler Tests
// ============================================================================

// TestService_CanSeal_WithBackend tests CanSeal with a specific backend.
// The handler should check if the specified backend supports sealing.
func TestService_CanSeal_WithBackend(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	t.Run("returns true for software backend", func(t *testing.T) {
		resp, err := service.CanSeal(ctx, &pb.CanSealRequest{
			Backend: "software",
		})
		if err != nil {
			t.Fatalf("CanSeal failed: %v", err)
		}

		if resp == nil {
			t.Fatal("Expected non-nil response")
		}
		if !resp.CanSeal {
			t.Error("Expected CanSeal to be true for software backend")
		}
	})

	t.Run("returns false for non-existent backend", func(t *testing.T) {
		resp, err := service.CanSeal(ctx, &pb.CanSealRequest{
			Backend: "nonexistent",
		})
		if err != nil {
			t.Fatalf("CanSeal failed: %v", err)
		}

		if resp == nil {
			t.Fatal("Expected non-nil response")
		}
		if resp.CanSeal {
			t.Error("Expected CanSeal to be false for non-existent backend")
		}
	})
}

// TestService_CanSeal_WithoutBackend tests CanSeal without specifying a backend.
// The handler should check the default backend when no backend is specified.
func TestService_CanSeal_WithoutBackend(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	t.Run("checks default backend when no backend specified", func(t *testing.T) {
		resp, err := service.CanSeal(ctx, &pb.CanSealRequest{
			Backend: "",
		})
		if err != nil {
			t.Fatalf("CanSeal failed: %v", err)
		}

		if resp == nil {
			t.Fatal("Expected non-nil response")
		}
		// Default backend is "software" which supports sealing
		if !resp.CanSeal {
			t.Error("Expected CanSeal to be true for default backend")
		}
	})

	t.Run("handles empty request", func(t *testing.T) {
		resp, err := service.CanSeal(ctx, &pb.CanSealRequest{})
		if err != nil {
			t.Fatalf("CanSeal failed: %v", err)
		}

		if resp == nil {
			t.Fatal("Expected non-nil response")
		}
		// Default backend is "software" which supports sealing
		if !resp.CanSeal {
			t.Error("Expected CanSeal to be true for default backend")
		}
	})
}

// TestService_CanSeal_InvalidBackendNames tests CanSeal with various invalid backend names.
// These should not cause panics and should return false gracefully.
func TestService_CanSeal_InvalidBackendNames(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	invalidBackendNames := []struct {
		name        string
		backendName string
	}{
		{"special characters", "backend@#$%"},
		{"very long name", strings.Repeat("a", 1000)},
		{"unicode characters", "backend-\xe4\xb8\xad\xe6\x96\x87"},
	}

	for _, tc := range invalidBackendNames {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := service.CanSeal(ctx, &pb.CanSealRequest{
				Backend: tc.backendName,
			})

			// CanSeal should not error, just return false for non-existent/invalid backends
			if err != nil {
				t.Fatalf("CanSeal should not return error, got: %v", err)
			}
			if resp == nil {
				t.Fatal("Expected non-nil response")
			}
			if resp.CanSeal {
				t.Errorf("Expected CanSeal to be false for invalid backend name %q", tc.backendName)
			}
		})
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

// TestService_Seal_MultipleBackendValidation tests validation with various input combinations.
func TestService_Seal_MultipleBackendValidation(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	testCases := []struct {
		name          string
		backend       string
		data          []byte
		expectedCode  codes.Code
		expectedError string
	}{
		{
			name:          "empty backend and empty data",
			backend:       "",
			data:          []byte{},
			expectedCode:  codes.InvalidArgument,
			expectedError: "backend is required",
		},
		{
			name:          "empty backend with valid data",
			backend:       "",
			data:          []byte("test"),
			expectedCode:  codes.InvalidArgument,
			expectedError: "backend is required",
		},
		{
			name:          "valid backend with empty data",
			backend:       "software",
			data:          []byte{},
			expectedCode:  codes.InvalidArgument,
			expectedError: "data is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := service.Seal(ctx, &pb.SealRequest{
				Backend: tc.backend,
				Data:    tc.data,
			})
			if err == nil {
				t.Fatal("Expected error")
			}

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, got: %v", err)
			}
			if st.Code() != tc.expectedCode {
				t.Errorf("Expected %v code, got: %v", tc.expectedCode, st.Code())
			}
			if tc.expectedError != "" && st.Message() != tc.expectedError {
				t.Errorf("Expected '%s' message, got: %s", tc.expectedError, st.Message())
			}
		})
	}
}

// TestService_Unseal_MultipleBackendValidation tests validation with various input combinations.
func TestService_Unseal_MultipleBackendValidation(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	testCases := []struct {
		name          string
		backend       string
		ciphertext    []byte
		expectedCode  codes.Code
		expectedError string
	}{
		{
			name:          "empty backend and empty ciphertext",
			backend:       "",
			ciphertext:    []byte{},
			expectedCode:  codes.InvalidArgument,
			expectedError: "backend is required",
		},
		{
			name:          "empty backend with valid ciphertext",
			backend:       "",
			ciphertext:    []byte("encrypted"),
			expectedCode:  codes.InvalidArgument,
			expectedError: "backend is required",
		},
		{
			name:          "valid backend with empty ciphertext",
			backend:       "software",
			ciphertext:    []byte{},
			expectedCode:  codes.InvalidArgument,
			expectedError: "ciphertext is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := service.Unseal(ctx, &pb.UnsealRequest{
				Backend:    tc.backend,
				Ciphertext: tc.ciphertext,
			})
			if err == nil {
				t.Fatal("Expected error")
			}

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, got: %v", err)
			}
			if st.Code() != tc.expectedCode {
				t.Errorf("Expected %v code, got: %v", tc.expectedCode, st.Code())
			}
			if tc.expectedError != "" && st.Message() != tc.expectedError {
				t.Errorf("Expected '%s' message, got: %s", tc.expectedError, st.Message())
			}
		})
	}
}

// TestService_Seal_LargeData tests Seal behavior with large data payloads.
func TestService_Seal_LargeData(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	t.Run("handles large data payload", func(t *testing.T) {
		// Create a 1MB data payload
		largeData := make([]byte, 1024*1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		_, err := service.Seal(ctx, &pb.SealRequest{
			Backend: "software",
			Data:    largeData,
		})

		// The operation should fail due to missing KeyAttributes, not due to data size
		if err == nil {
			t.Fatal("Expected error when KeyAttributes is missing")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.Internal {
			t.Errorf("Expected Internal code (KeyAttributes missing), got: %v", st.Code())
		}
	})
}
