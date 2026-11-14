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

	svc, err := xkms.Get()
	if err != nil {
		t.Fatalf("Failed to get xkms service: %v", err)
	}
	return NewService(nil, nil, svc)
}

// ============================================================================
// Seal Handler Tests
// ============================================================================

// TestService_Seal_WithValidBackend tests Seal with a valid backend: without a
// key_id the caller's default sealing key is used, and a key_id that names no
// key is NotFound.
func TestService_Seal_WithValidBackend(t *testing.T) {
	service := setupSealingTest(t)
	defer xkms.Reset()

	ctx := context.Background()
	testData := []byte("secret data to seal")

	t.Run("seals under the default sealing key when no key_id is given", func(t *testing.T) {
		resp, err := service.Seal(ctx, &pb.SealRequest{
			Backend: "software",
			Data:    testData,
		})
		if err != nil {
			t.Fatalf("Seal without key_id failed: %v", err)
		}
		if len(resp.Ciphertext) == 0 {
			t.Error("Expected ciphertext from the default sealing key")
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

	t.Run("seals with AAD under the default sealing key", func(t *testing.T) {
		aad := []byte("additional authenticated data")
		sealed, err := service.Seal(ctx, &pb.SealRequest{
			Backend: "software",
			Data:    testData,
			Aad:     aad,
		})
		if err != nil {
			t.Fatalf("Seal with AAD failed: %v", err)
		}

		opened, err := service.Unseal(ctx, &pb.UnsealRequest{
			Backend: "software", Ciphertext: sealed.Ciphertext,
			Nonce: sealed.Nonce, Tag: sealed.Tag, Aad: aad,
		})
		if err != nil {
			t.Fatalf("Unseal with AAD failed: %v", err)
		}
		if string(opened.Plaintext) != string(testData) {
			t.Errorf("round trip returned %q", opened.Plaintext)
		}

		_, err = service.Unseal(ctx, &pb.UnsealRequest{
			Backend: "software", Ciphertext: sealed.Ciphertext,
			Nonce: sealed.Nonce, Tag: sealed.Tag, Aad: []byte("other"),
		})
		if err == nil {
			t.Error("Expected unseal with different AAD to fail")
		}
	})
}

// ============================================================================
// Unseal Handler Tests
// ============================================================================

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
			expectedError: "ciphertext is required (or tpm_public and tpm_private for a TPM2 sealed object)",
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
