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
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestService_DeriveKey_HKDF(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("valid HKDF derivation", func(t *testing.T) {
		ikm := []byte("test-input-key-material-32bytes!")
		salt := []byte("test-salt-value")
		info := []byte("test-info-value")

		resp, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "HKDF",
			InputKeyMaterial: ikm,
			Salt:             salt,
			Info:             info,
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("DeriveKey failed: %v", err)
		}

		if len(resp.DerivedKey) != 32 {
			t.Errorf("Expected derived key length 32, got %d", len(resp.DerivedKey))
		}
		if resp.Algorithm != "HKDF" {
			t.Errorf("Expected algorithm 'HKDF', got '%s'", resp.Algorithm)
		}
		if resp.KeyLength != 32 {
			t.Errorf("Expected key length 32, got %d", resp.KeyLength)
		}
	})

	t.Run("HKDF is deterministic", func(t *testing.T) {
		ikm := []byte("test-input-key-material-32bytes!")
		salt := []byte("test-salt-value")
		info := []byte("test-info-value")

		resp1, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "HKDF",
			InputKeyMaterial: ikm,
			Salt:             salt,
			Info:             info,
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("First DeriveKey failed: %v", err)
		}

		resp2, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "HKDF",
			InputKeyMaterial: ikm,
			Salt:             salt,
			Info:             info,
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("Second DeriveKey failed: %v", err)
		}

		if !bytes.Equal(resp1.DerivedKey, resp2.DerivedKey) {
			t.Error("HKDF should produce deterministic results")
		}
	})

	t.Run("different inputs produce different keys", func(t *testing.T) {
		ikm := []byte("test-input-key-material-32bytes!")

		resp1, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "HKDF",
			InputKeyMaterial: ikm,
			Salt:             []byte("salt-1"),
			Info:             []byte("info-1"),
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("First DeriveKey failed: %v", err)
		}

		resp2, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "HKDF",
			InputKeyMaterial: ikm,
			Salt:             []byte("salt-2"),
			Info:             []byte("info-2"),
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("Second DeriveKey failed: %v", err)
		}

		if bytes.Equal(resp1.DerivedKey, resp2.DerivedKey) {
			t.Error("Different inputs should produce different keys")
		}
	})
}

func TestService_DeriveKey_SP800108Counter(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("valid SP800-108 Counter derivation", func(t *testing.T) {
		kdk := []byte("test-key-derivation-key-32bytes!")

		resp, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "SP800-108-Counter",
			InputKeyMaterial: kdk,
			Label:            []byte("test-label"),
			Context:          []byte("test-context"),
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("DeriveKey failed: %v", err)
		}

		if len(resp.DerivedKey) != 32 {
			t.Errorf("Expected derived key length 32, got %d", len(resp.DerivedKey))
		}
		if resp.Algorithm != "SP800-108-Counter" {
			t.Errorf("Expected algorithm 'SP800-108-Counter', got '%s'", resp.Algorithm)
		}
	})

	t.Run("SP800-108 Counter is deterministic", func(t *testing.T) {
		kdk := []byte("test-key-derivation-key-32bytes!")

		resp1, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "SP800-108-Counter",
			InputKeyMaterial: kdk,
			Label:            []byte("test-label"),
			Context:          []byte("test-context"),
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("First DeriveKey failed: %v", err)
		}

		resp2, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "SP800-108-Counter",
			InputKeyMaterial: kdk,
			Label:            []byte("test-label"),
			Context:          []byte("test-context"),
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("Second DeriveKey failed: %v", err)
		}

		if !bytes.Equal(resp1.DerivedKey, resp2.DerivedKey) {
			t.Error("SP800-108 Counter should produce deterministic results")
		}
	})
}

func TestService_DeriveKey_SP800108Feedback(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("valid SP800-108 Feedback derivation", func(t *testing.T) {
		kdk := []byte("test-key-derivation-key-32bytes!")

		resp, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "SP800-108-Feedback",
			InputKeyMaterial: kdk,
			Label:            []byte("test-label"),
			Context:          []byte("test-context"),
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("DeriveKey failed: %v", err)
		}

		if len(resp.DerivedKey) != 32 {
			t.Errorf("Expected derived key length 32, got %d", len(resp.DerivedKey))
		}
	})

	t.Run("SP800-108 Feedback with IV", func(t *testing.T) {
		kdk := []byte("test-key-derivation-key-32bytes!")

		// Without IV
		resp1, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "SP800-108-Feedback",
			InputKeyMaterial: kdk,
			Label:            []byte("test-label"),
			Context:          []byte("test-context"),
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("First DeriveKey failed: %v", err)
		}

		// With IV (passed via Salt)
		resp2, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "SP800-108-Feedback",
			InputKeyMaterial: kdk,
			Label:            []byte("test-label"),
			Context:          []byte("test-context"),
			Salt:             []byte("initial-vector-16"),
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("Second DeriveKey failed: %v", err)
		}

		if bytes.Equal(resp1.DerivedKey, resp2.DerivedKey) {
			t.Error("Keys with and without IV should be different")
		}
	})
}

func TestService_DeriveKey_SP800108DoublePipeline(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	t.Run("valid SP800-108 Double-Pipeline derivation", func(t *testing.T) {
		kdk := []byte("test-key-derivation-key-32bytes!")

		resp, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "SP800-108-Double-Pipeline",
			InputKeyMaterial: kdk,
			Label:            []byte("test-label"),
			Context:          []byte("test-context"),
			KeyLength:        32,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("DeriveKey failed: %v", err)
		}

		if len(resp.DerivedKey) != 32 {
			t.Errorf("Expected derived key length 32, got %d", len(resp.DerivedKey))
		}
	})
}

func TestService_DeriveKey_DifferentModes(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	kdk := []byte("test-key-derivation-key-32bytes!")

	// Use 64-byte output to require multiple iterations
	// This ensures modes produce different results
	t.Run("different modes produce different keys", func(t *testing.T) {
		respCounter, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "SP800-108-Counter",
			InputKeyMaterial: kdk,
			Label:            []byte("test-label"),
			Context:          []byte("test-context"),
			KeyLength:        64,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("Counter DeriveKey failed: %v", err)
		}

		respFeedback, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "SP800-108-Feedback",
			InputKeyMaterial: kdk,
			Label:            []byte("test-label"),
			Context:          []byte("test-context"),
			KeyLength:        64,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("Feedback DeriveKey failed: %v", err)
		}

		respDoublePipeline, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm:        "SP800-108-Double-Pipeline",
			InputKeyMaterial: kdk,
			Label:            []byte("test-label"),
			Context:          []byte("test-context"),
			KeyLength:        64,
			Hash:             "SHA256",
		})
		if err != nil {
			t.Fatalf("Double-Pipeline DeriveKey failed: %v", err)
		}

		if bytes.Equal(respCounter.DerivedKey, respFeedback.DerivedKey) {
			t.Error("Counter and Feedback modes should produce different keys")
		}
		if bytes.Equal(respCounter.DerivedKey, respDoublePipeline.DerivedKey) {
			t.Error("Counter and Double-Pipeline modes should produce different keys")
		}
		if bytes.Equal(respFeedback.DerivedKey, respDoublePipeline.DerivedKey) {
			t.Error("Feedback and Double-Pipeline modes should produce different keys")
		}
	})
}

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

	t.Run("key-based derivation not supported", func(t *testing.T) {
		_, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
			Algorithm: "HKDF",
			Backend:   "software",
			KeyId:     "test-key",
			KeyLength: 32,
		})
		if err == nil {
			t.Fatal("Expected error for key-based derivation")
		}
		if st, ok := status.FromError(err); ok {
			if st.Code() != codes.Unimplemented {
				t.Errorf("Expected Unimplemented, got %v", st.Code())
			}
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

func TestService_DeriveKey_DifferentKeyLengths(t *testing.T) {
	service := setupServiceTest(t)
	defer xkms.Reset()

	ikm := []byte("test-input-key-material-32bytes!")
	keyLengths := []int32{16, 32, 48, 64, 128}

	for _, keyLen := range keyLengths {
		t.Run("key length %d", func(t *testing.T) {
			resp, err := service.DeriveKey(context.Background(), &pb.DeriveKeyRequest{
				Algorithm:        "SP800-108-Counter",
				InputKeyMaterial: ikm,
				Label:            []byte("test-label"),
				Context:          []byte("test-context"),
				KeyLength:        keyLen,
				Hash:             "SHA256",
			})
			if err != nil {
				t.Fatalf("DeriveKey with length %d failed: %v", keyLen, err)
			}

			if int32(len(resp.DerivedKey)) != keyLen {
				t.Errorf("Expected key length %d, got %d", keyLen, len(resp.DerivedKey))
			}
		})
	}
}
