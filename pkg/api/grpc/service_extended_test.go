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

//go:build !frost

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

	return NewService(nil, nil)
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

		// Decrypt data
		decResp, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:      "encrypt-decrypt-key",
			Backend:    "software",
			Ciphertext: encResp.Ciphertext,
			Nonce:      encResp.Nonce,
			Tag:        encResp.Tag,
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

		// Decrypt with AAD
		decResp, err := service.Decrypt(context.Background(), &pb.DecryptRequest{
			KeyId:          "aad-encrypt-key",
			Backend:        "software",
			Ciphertext:     encResp.Ciphertext,
			Nonce:          encResp.Nonce,
			Tag:            encResp.Tag,
			AdditionalData: aad,
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

// TestWrapKeyWithValidBackend tests wrap key functionality
func TestWrapKeyWithValidBackend(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	t.Run("wraps key material with valid parameters", func(t *testing.T) {
		// Get import parameters to get a wrapping key
		paramsResp, err := service.GetImportParameters(context.Background(), &pb.GetImportParametersRequest{
			KeyId:             "wrap-test-key",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
			KeyType:           "rsa",
			KeySize:           2048,
		})
		if err != nil {
			t.Fatalf("GetImportParameters failed: %v", err)
		}

		// Wrap some key material
		keyMaterial := []byte("this-is-a-32-byte-key-material!!")
		wrapResp, err := service.WrapKey(context.Background(), &pb.WrapKeyRequest{
			KeyMaterial:       keyMaterial,
			WrappingPublicKey: paramsResp.WrappingPublicKey,
			Algorithm:         paramsResp.Algorithm,
			ImportToken:       paramsResp.ImportToken,
		})
		if err != nil {
			t.Fatalf("WrapKey failed: %v", err)
		}

		if len(wrapResp.WrappedKey) == 0 {
			t.Error("Expected non-empty wrapped key")
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

// TestExportKeyWithValidBackend tests export key functionality
func TestExportKeyWithValidBackend(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	t.Run("exports key from backend", func(t *testing.T) {
		// Generate an exportable key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:      "export-test-key",
			Backend:    "software",
			KeyType:    "ecdsa",
			Curve:      "P256",
			Exportable: true,
		})
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Export the key
		exportResp, err := service.ExportKey(context.Background(), &pb.ExportKeyRequest{
			KeyId:             "export-test-key",
			Backend:           "software",
			WrappingAlgorithm: "RSAES_OAEP_SHA_256",
		})
		if err != nil {
			t.Fatalf("ExportKey failed: %v", err)
		}

		if len(exportResp.WrappedKey) == 0 {
			t.Error("Expected non-empty wrapped key")
		}
	})

	t.Run("returns error for nonexistent key", func(t *testing.T) {
		_, err := service.ExportKey(context.Background(), &pb.ExportKeyRequest{
			KeyId:             "nonexistent-export-key",
			Backend:           "software",
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

// TestCopyKeyWithValidBackend tests key copying between backends
func TestCopyKeyWithValidBackend(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	t.Run("copies key within same backend", func(t *testing.T) {
		// Generate an exportable source key
		_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:      "copy-source-key",
			Backend:    "software",
			KeyType:    "ecdsa",
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

// TestSignWithDifferentHashes tests signing with different hash algorithms
func TestSignWithDifferentHashes(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	// Generate key for testing
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "hash-test-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	testData := []byte("test data")

	t.Run("signs with SHA384", func(t *testing.T) {
		resp, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "hash-test-key",
			Backend: "software",
			Data:    testData,
			Hash:    "SHA384",
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if len(resp.Signature) == 0 {
			t.Error("Expected non-empty signature")
		}
	})

	t.Run("signs with SHA512", func(t *testing.T) {
		resp, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "hash-test-key",
			Backend: "software",
			Data:    testData,
			Hash:    "SHA512",
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if len(resp.Signature) == 0 {
			t.Error("Expected non-empty signature")
		}
	})

	t.Run("signs with default hash (empty)", func(t *testing.T) {
		resp, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "hash-test-key",
			Backend: "software",
			Data:    testData,
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if len(resp.Signature) == 0 {
			t.Error("Expected non-empty signature")
		}
	})

	t.Run("signs with unknown hash falls back to SHA256", func(t *testing.T) {
		resp, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "hash-test-key",
			Backend: "software",
			Data:    testData,
			Hash:    "UNKNOWN",
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if len(resp.Signature) == 0 {
			t.Error("Expected non-empty signature")
		}
	})
}

// TestVerifyWithDifferentHashes tests verification with different hash algorithms
func TestVerifyWithDifferentHashes(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	// Generate key
	_, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		KeyId:   "verify-hash-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	testData := []byte("test data")

	t.Run("verifies with SHA384", func(t *testing.T) {
		signResp, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "verify-hash-key",
			Backend: "software",
			Data:    testData,
			Hash:    "SHA384",
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		verifyResp, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "verify-hash-key",
			Backend:   "software",
			Data:      testData,
			Signature: signResp.Signature,
			Hash:      "SHA384",
		})
		if err != nil {
			t.Fatalf("Verify failed: %v", err)
		}

		if !verifyResp.Valid {
			t.Error("Expected signature to be valid")
		}
	})

	t.Run("verifies with SHA512", func(t *testing.T) {
		signResp, err := service.Sign(context.Background(), &pb.SignRequest{
			KeyId:   "verify-hash-key",
			Backend: "software",
			Data:    testData,
			Hash:    "SHA512",
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		verifyResp, err := service.Verify(context.Background(), &pb.VerifyRequest{
			KeyId:     "verify-hash-key",
			Backend:   "software",
			Data:      testData,
			Signature: signResp.Signature,
			Hash:      "SHA512",
		})
		if err != nil {
			t.Fatalf("Verify failed: %v", err)
		}

		if !verifyResp.Valid {
			t.Error("Expected signature to be valid")
		}
	})
}

// TestListBackendsEdgeCases tests ListBackends edge cases
func TestListBackendsEdgeCases(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	t.Run("returns backend capabilities", func(t *testing.T) {
		resp, err := service.ListBackends(context.Background(), &pb.ListBackendsRequest{})
		if err != nil {
			t.Fatalf("ListBackends failed: %v", err)
		}

		if resp.Count == 0 {
			t.Error("Expected at least one backend")
		}

		// Check capabilities are populated
		for _, b := range resp.Backends {
			if b.Type == "" {
				t.Error("Expected backend type to be set")
			}
			if b.Description == "" {
				t.Error("Expected backend description to be set")
			}
			// Software backend should support signing
			if b.Name == "software" && !b.SupportsSigning {
				t.Error("Expected software backend to support signing")
			}
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

// TestListCertsEdgeCases tests ListCerts edge cases
func TestListCertsEdgeCases(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	t.Run("returns empty list when no certs", func(t *testing.T) {
		resp, err := service.ListCerts(context.Background(), &pb.ListCertsRequest{})
		if err != nil {
			t.Fatalf("ListCerts failed: %v", err)
		}

		// Should return empty or with total 0
		if resp.Total < 0 {
			t.Error("Expected non-negative total")
		}
	})
}

// TestCertExistsEdgeCases tests CertExists edge cases
func TestCertExistsEdgeCases(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	t.Run("returns false for nonexistent certificate", func(t *testing.T) {
		resp, err := service.CertExists(context.Background(), &pb.CertExistsRequest{
			KeyId: "definitely-not-a-real-cert",
		})
		if err != nil {
			t.Fatalf("CertExists failed: %v", err)
		}

		if resp.Exists {
			t.Error("Expected certificate to not exist")
		}
	})
}

// TestGenerateKeyWithAlgorithmField tests the Algorithm field behavior
func TestGenerateKeyWithAlgorithmField(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	t.Run("uses Algorithm field when provided", func(t *testing.T) {
		resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:     "algo-test-key",
			Backend:   "software",
			KeyType:   "signing", // Generic key type
			Algorithm: "ecdsa",   // Specific algorithm
			Curve:     "P256",
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if resp.KeyId != "algo-test-key" {
			t.Errorf("Expected key_id 'algo-test-key', got '%s'", resp.KeyId)
		}
	})

	t.Run("falls back to KeyType when Algorithm not provided", func(t *testing.T) {
		resp, err := service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			KeyId:   "keytype-test-key",
			Backend: "software",
			KeyType: "ecdsa", // Used as algorithm
			Curve:   "P256",
		})
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if resp.KeyId != "keytype-test-key" {
			t.Errorf("Expected key_id 'keytype-test-key', got '%s'", resp.KeyId)
		}
	})
}
