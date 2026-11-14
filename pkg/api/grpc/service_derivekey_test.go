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
	"bytes"
	"context"
	"math"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestService_DeriveKey_Errors(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("missing algorithm", func(t *testing.T) {
		_, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			InputKeyMaterial: []byte("test-ikm"),
			KeyLength:        32,
		})
		if err == nil {
			t.Fatal("Expected error for missing algorithm")
		}
		if st, ok := status.FromError(err); ok {
			if st.Code() != codes.InvalidArgument {
				t.Errorf("Expected InvalidArgument, got %v", st.Code())
			}
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		_, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "unsupported-algorithm",
			InputKeyMaterial: []byte("test-ikm"),
			KeyLength:        32,
		})
		if err == nil {
			t.Fatal("Expected error for unsupported algorithm")
		}
		if st, ok := status.FromError(err); ok {
			if st.Code() != codes.InvalidArgument {
				t.Errorf("Expected InvalidArgument, got %v", st.Code())
			}
		}
	})

	t.Run("missing input key material", func(t *testing.T) {
		_, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm: "HKDF",
			KeyLength: 32,
		})
		if err == nil {
			t.Fatal("Expected error for missing IKM")
		}
		if st, ok := status.FromError(err); ok {
			if st.Code() != codes.InvalidArgument {
				t.Errorf("Expected InvalidArgument, got %v", st.Code())
			}
		}
	})

	t.Run("key_length exceeds maximum", func(t *testing.T) {
		_, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "HKDF",
			InputKeyMaterial: []byte("test-ikm-32-bytes-long-enough!!"),
			KeyLength:        int32(types.MaxDerivedKeyLength) + 1,
		})
		if err == nil {
			t.Fatal("Expected error for an oversized key_length")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected a gRPC status error, got %v", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	// The proto field is int32, so this is the largest key_length the wire
	// can carry -- still nine orders of magnitude past MaxDerivedKeyLength,
	// and the go-xkms#1259 report's own 100_000_000_000 does not fit an
	// int32 at all, which is itself informative: the internal service type
	// (a Go int) had no such ceiling before this fix, so a caller reaching
	// DeriveKey through a wider transport (REST's JSON, or the SDK used
	// in-process) was not bounded by the gRPC field width either.
	t.Run("key_length at the wire's own limit", func(t *testing.T) {
		_, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "HKDF",
			InputKeyMaterial: []byte("test-ikm-32-bytes-long-enough!!"),
			KeyLength:        math.MaxInt32,
		})
		if err == nil {
			t.Fatal("Expected error for an oversized key_length")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected a gRPC status error, got %v", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("store result not supported", func(t *testing.T) {
		_, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "HKDF",
			InputKeyMaterial: []byte("test-ikm-32-bytes-long-enough!!"),
			KeyLength:        32,
			StoreResult:      true,
		})
		if err == nil {
			t.Fatal("Expected error for store result")
		}
		if st, ok := status.FromError(err); ok {
			if st.Code() != codes.Unimplemented {
				t.Errorf("Expected Unimplemented, got %v", st.Code())
			}
		}
	})

	t.Run("key-based derivation reaches the backend", func(t *testing.T) {
		// This used to assert Unimplemented, pinning a refusal that had to go:
		// naming a base key by identity is the only way a key whose material
		// stays in the backend can be derived from at all.
		//
		// The setup's backends hold no key material, so the request cannot
		// succeed here. What matters is that it is refused for a reason about
		// this key or this backend, and not with the blanket "the operation
		// does not do that" the old code returned for every such request.
		_, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm: "HKDF",
			Backend:   "software",
			KeyId:     "test-key",
			KeyLength: 32,
		})
		if err == nil {
			t.Fatal("Expected an error: no key named test-key exists in this backend")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected a gRPC status error, got %v", err)
		}
		if st.Code() == codes.InvalidArgument {
			t.Errorf("Expected the request itself to be well-formed, got InvalidArgument: %v", st.Message())
		}
	})

	t.Run("input key material and key id together are refused", func(t *testing.T) {
		// The two name different base keys. Answering the request means
		// choosing one and returning a key derived from material the caller
		// did not select, in a response identical to the one they wanted.
		_, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "HKDF",
			Backend:          "software",
			KeyId:            "test-key",
			InputKeyMaterial: []byte("test-input-key-material-32bytes!"),
			KeyLength:        32,
		})
		if err == nil {
			t.Fatal("Expected an error for a request naming two base keys")
		}
	})
}

func TestService_DeriveKey_CaseInsensitive(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	ikm := []byte("test-input-key-material-32bytes!")

	t.Run("algorithm name is case insensitive", func(t *testing.T) {
		algorithms := []string{"hkdf", "HKDF", "Hkdf", "HkDf"}

		var firstKey []byte
		for i, alg := range algorithms {
			resp, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
				Algorithm:        alg,
				InputKeyMaterial: ikm,
				Salt:             []byte("test-salt"),
				Info:             []byte("test-info"),
				KeyLength:        32,
				Hash:             "SHA256",
			})
			if err != nil {
				t.Fatalf("DeriveKey with algorithm '%s' failed: %v", alg, err)
			}

			if i == 0 {
				firstKey = resp.DerivedKey
			} else if !bytes.Equal(resp.DerivedKey, firstKey) {
				t.Errorf("Algorithm '%s' produced different key than 'hkdf'", alg)
			}
		}
	})
}

func TestService_DeriveKey_DefaultKeyLength(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("default key length is 32", func(t *testing.T) {
		resp, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "HKDF",
			InputKeyMaterial: []byte("test-input-key-material-32bytes!"),
			Salt:             []byte("test-salt"),
			Hash:             "SHA256",
			// KeyLength not specified
		})
		if err != nil {
			t.Fatalf("DeriveKey failed: %v", err)
		}

		if len(resp.DerivedKey) != 32 {
			t.Errorf("Expected default key length 32, got %d", len(resp.DerivedKey))
		}
	})
}
