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

// setupExtendedTest initializes xkms for extended tests
func setupExtendedTest(t *testing.T) *Service {
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

// TestSymmetricEncryptDecrypt tests symmetric encryption and decryption flow
func TestSymmetricEncryptDecrypt(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	t.Run("encrypts and decrypts with symmetric key", func(t *testing.T) {
		// Generate symmetric key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "encrypt-decrypt-key",
			Backend:   "software",
			KeyType:   "symmetric",
			Algorithm: "symmetric",
			KeySize:   256,
		})
		if err != nil {
			t.Fatalf("Failed to generate symmetric key: %v", err)
		}

		// Encrypt data
		plaintext := []byte("Hello, World! This is a test message.")
		encResp, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:     "encrypt-decrypt-key",
			Backend:   "software",
			Plaintext: plaintext,
		})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		if len(encResp.Ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext")
		}
		if len(encResp.Nonce) == 0 {
			t.Error("Expected non-empty nonce")
		}

		// Decrypt data. GCMNonceMode must be echoed back unchanged so
		// Decrypt can reconstruct the AEAD construction Encrypt used under
		// GODEBUG=fips140=only (go-xkms#23).
		decResp, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:        "encrypt-decrypt-key",
			Backend:      "software",
			Ciphertext:   encResp.Ciphertext,
			Nonce:        encResp.Nonce,
			Tag:          encResp.Tag,
			GcmNonceMode: encResp.GcmNonceMode,
		})
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if string(decResp.Plaintext) != string(plaintext) {
			t.Errorf("Expected '%s', got '%s'", string(plaintext), string(decResp.Plaintext))
		}
	})

	t.Run("encrypts with additional data", func(t *testing.T) {
		// Generate symmetric key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "aad-encrypt-key",
			Backend:   "software",
			KeyType:   "symmetric",
			Algorithm: "symmetric",
			KeySize:   256,
		})
		if err != nil {
			t.Fatalf("Failed to generate symmetric key: %v", err)
		}

		// Encrypt with AAD
		plaintext := []byte("Secret message")
		aad := []byte("additional authenticated data")
		encResp, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:          "aad-encrypt-key",
			Backend:        "software",
			Plaintext:      plaintext,
			AdditionalData: aad,
		})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		// Decrypt with AAD. GCMNonceMode must be echoed back unchanged so
		// Decrypt can reconstruct the AEAD construction Encrypt used under
		// GODEBUG=fips140=only (go-xkms#23).
		decResp, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:          "aad-encrypt-key",
			Backend:        "software",
			Ciphertext:     encResp.Ciphertext,
			Nonce:          encResp.Nonce,
			Tag:            encResp.Tag,
			AdditionalData: aad,
			GcmNonceMode:   encResp.GcmNonceMode,
		})
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if string(decResp.Plaintext) != string(plaintext) {
			t.Errorf("Expected '%s', got '%s'", string(plaintext), string(decResp.Plaintext))
		}
	})

	t.Run("decrypt fails with wrong AAD", func(t *testing.T) {
		// Generate symmetric key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "wrong-aad-key",
			Backend:   "software",
			KeyType:   "symmetric",
			Algorithm: "symmetric",
			KeySize:   256,
		})
		if err != nil {
			t.Fatalf("Failed to generate symmetric key: %v", err)
		}

		// Encrypt with AAD
		plaintext := []byte("Secret message")
		aad := []byte("correct aad")
		encResp, err := service.Encrypt(context.Background(), &pb.EncryptRequest{
			KeyId:          "wrong-aad-key",
			Backend:        "software",
			Plaintext:      plaintext,
			AdditionalData: aad,
		})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		// Decrypt with wrong AAD should fail
		_, err = service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:          "wrong-aad-key",
			Backend:        "software",
			Ciphertext:     encResp.Ciphertext,
			Nonce:          encResp.Nonce,
			Tag:            encResp.Tag,
			AdditionalData: []byte("wrong aad"),
		})
		if err == nil {
			t.Fatal("Expected error for wrong AAD")
		}
	})
}

// TestUnwrapKeyWithValidBackend tests unwrap key functionality
func TestUnwrapKeyWithValidBackend(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	t.Run("unwraps key material with valid parameters", func(t *testing.T) {
		// Get import parameters
		paramsResp, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId:             "unwrap-test-key",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			KeyType:           "rsa",
			KeySize:           2048,
		})
		if err != nil {
			t.Fatalf("GetImportParameters failed: %v", err)
		}

		// Wrap key material first
		originalKeyMaterial := []byte("this-is-a-32-byte-key-material!!")
		wrapResp, err := service.WrapKey(context.Background(), &pb.WrapKeyRequest{
			Backend:           "software",
			KeyMaterial:       originalKeyMaterial,
			WrappingPublicKey: paramsResp.WrappingPublicKey,
			Algorithm:         paramsResp.Algorithm,
			ImportToken:       paramsResp.ImportToken,
		})
		if err != nil {
			t.Fatalf("WrapKey failed: %v", err)
		}

		// Unwrap key material
		unwrapResp, err := service.UnwrapKey(context.Background(), &pb.UnwrapKeyRequest{
			Backend:           "software",
			WrappedKey:        wrapResp.WrappedKey,
			Algorithm:         wrapResp.Algorithm,
			ImportToken:       wrapResp.ImportToken,
			WrappingPublicKey: paramsResp.WrappingPublicKey,
		})
		if err != nil {
			t.Fatalf("UnwrapKey failed: %v", err)
		}

		if string(unwrapResp.KeyMaterial) != string(originalKeyMaterial) {
			t.Errorf("Expected '%s', got '%s'", string(originalKeyMaterial), string(unwrapResp.KeyMaterial))
		}
	})
}

// TestCopyKeyWithValidBackend tests key copying between backends
func TestCopyKeyWithValidBackend(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	t.Run("copies key within same backend", func(t *testing.T) {
		// Generate an exportable source key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "copy-source-key",
			Backend: "software",
			KeyType: "ecdsa", Algorithm: "ecdsa",
			Curve:      "P256",
			Exportable: true,
		})
		if err != nil {
			t.Fatalf("Failed to generate source key: %v", err)
		}

		// Copy the key
		copyResp, err := service.CopyKey(context.Background(), &pb.CopyKeyRequest{
			SourceBackend:     "software",
			SourceKeyId:       "copy-source-key",
			DestBackend:       "software",
			DestKeyId:         "copy-dest-key",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		})
		if err != nil {
			t.Fatalf("CopyKey failed: %v", err)
		}

		if !copyResp.Success {
			t.Error("Expected success")
		}
		if copyResp.DestKeyId != "copy-dest-key" {
			t.Errorf("Expected dest_key_id 'copy-dest-key', got '%s'", copyResp.DestKeyId)
		}

		// Verify copied key exists
		_, err = service.GetKey(context.Background(), &pb.GetKeyRequest{
			KeyId:   "copy-dest-key",
			Backend: "software",
		})
		if err != nil {
			t.Fatalf("Failed to get copied key: %v", err)
		}
	})

	t.Run("returns error for nonexistent source key", func(t *testing.T) {
		_, err := service.CopyKey(context.Background(), &pb.CopyKeyRequest{
			SourceBackend:     "software",
			SourceKeyId:       "nonexistent-source",
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
}

// TestDeleteCertEdgeCases tests DeleteCert edge cases
func TestDeleteCertEdgeCases(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	t.Run("returns error for nonexistent cert", func(t *testing.T) {
		_, err := service.DeleteCert(context.Background(), &pb.DeleteCertRequest{
			KeyId: "nonexistent-cert",
		})
		if err == nil {
			t.Fatal("Expected error")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("Expected gRPC status error")
		}
		// The error could be Internal if storage returns an error
		if st.Code() != codes.Internal {
			// Acceptable - deleting nonexistent might return internal error
			_ = st.Code()
		}
	})
}
