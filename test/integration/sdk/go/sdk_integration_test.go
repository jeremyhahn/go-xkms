//go:build integration

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

// Package integration provides SDK integration tests for go-keychain.
// These tests verify that the SDK client works correctly using the embedded protocol
// which allows testing without external server dependencies.
package integration

import (
	"context"
	"testing"
	"time"

	keychain "github.com/jeremyhahn/go-keychain/sdk/go"
)

// createTestClient creates an embedded SDK client with the test service.
func createTestClient(t *testing.T) (keychain.Client, func()) {
	t.Helper()

	service, err := NewTestKeychainService()
	if err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	client, err := keychain.NewEmbedded(service)
	if err != nil {
		t.Fatalf("Failed to create embedded client: %v", err)
	}

	cleanup := func() {
		if err := client.Close(); err != nil {
			t.Logf("Warning: failed to close client: %v", err)
		}
	}

	return client, cleanup
}

// TestSDK_Embedded_Health tests the health endpoint with embedded client.
func TestSDK_Embedded_Health(t *testing.T) {
	client, cleanup := createTestClient(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Health(ctx)
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("Expected healthy status, got: %s", resp.Status)
	}

	if resp.Version == "" {
		t.Error("Expected non-empty version")
	}

	t.Logf("Health: status=%s, version=%s", resp.Status, resp.Version)
}

// TestSDK_Embedded_ListBackends tests listing backends with embedded client.
func TestSDK_Embedded_ListBackends(t *testing.T) {
	client, cleanup := createTestClient(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.ListBackends(ctx)
	if err != nil {
		t.Fatalf("ListBackends failed: %v", err)
	}

	if len(resp.Backends) == 0 {
		t.Error("Expected at least one backend")
	}

	foundSoftware := false
	for _, b := range resp.Backends {
		t.Logf("Backend: ID=%s, Type=%s, HardwareBacked=%v", b.ID, b.Type, b.HardwareBacked)
		if b.ID == "software" {
			foundSoftware = true
		}
	}

	if !foundSoftware {
		t.Error("Expected to find software backend")
	}
}

// TestSDK_Embedded_KeyLifecycle tests key generation, retrieval, listing, and deletion.
func TestSDK_Embedded_KeyLifecycle(t *testing.T) {
	client, cleanup := createTestClient(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keyID := "test-lifecycle-key"

	// Generate key
	genResp, err := client.GenerateKey(ctx, &keychain.GenerateKeyRequest{
		KeyID:      keyID,
		Backend:    "software",
		KeyType:    "ecdsa",
		Curve:      "P-256",
		Exportable: true,
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if genResp.KeyID != keyID {
		t.Errorf("Expected key ID %s, got %s", keyID, genResp.KeyID)
	}

	if genResp.PublicKeyPEM == "" {
		t.Error("Expected non-empty public key PEM")
	}

	t.Logf("Generated key: %s (type=%s)", genResp.KeyID, genResp.KeyType)

	// Get key
	getResp, err := client.GetKey(ctx, "software", keyID)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if getResp.KeyID != keyID {
		t.Errorf("GetKey returned wrong key ID: %s", getResp.KeyID)
	}

	t.Logf("Retrieved key: %s", getResp.KeyID)

	// List keys
	listResp, err := client.ListKeys(ctx, "software")
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	found := false
	for _, k := range listResp.Keys {
		if k.KeyID == keyID {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Key %s not found in list of %d keys", keyID, len(listResp.Keys))
	}

	t.Logf("Listed %d keys, found test key: %v", len(listResp.Keys), found)

	// Delete key
	_, err = client.DeleteKey(ctx, "software", keyID)
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	t.Logf("Deleted key: %s", keyID)

	// Verify deletion
	_, err = client.GetKey(ctx, "software", keyID)
	if err == nil {
		t.Error("Expected error after deletion, but GetKey succeeded")
	}
}

// TestSDK_Embedded_SignVerify tests signing and verification with embedded client.
func TestSDK_Embedded_SignVerify(t *testing.T) {
	client, cleanup := createTestClient(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keyID := "test-sign-key"

	// Generate signing key
	_, err := client.GenerateKey(ctx, &keychain.GenerateKeyRequest{
		KeyID:   keyID,
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P-256",
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer client.DeleteKey(ctx, "software", keyID)

	// Sign data
	testData := []byte("Hello, SDK integration test!")
	signResp, err := client.Sign(ctx, &keychain.SignRequest{
		Backend: "software",
		KeyID:   keyID,
		Data:    testData,
		Hash:    "SHA256",
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signResp.Signature) == 0 {
		t.Error("Expected non-empty signature")
	}

	t.Logf("Signed data, signature length: %d bytes", len(signResp.Signature))

	// Verify signature
	verifyResp, err := client.Verify(ctx, &keychain.VerifyRequest{
		Backend:   "software",
		KeyID:     keyID,
		Data:      testData,
		Signature: signResp.Signature,
		Hash:      "SHA256",
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !verifyResp.Valid {
		t.Error("Signature verification failed - expected valid signature")
	}

	t.Log("Signature verified successfully")

	// Test verification with wrong data (should fail)
	wrongData := []byte("Wrong data!")
	verifyWrongResp, err := client.Verify(ctx, &keychain.VerifyRequest{
		Backend:   "software",
		KeyID:     keyID,
		Data:      wrongData,
		Signature: signResp.Signature,
		Hash:      "SHA256",
	})
	if err != nil {
		t.Fatalf("Verify with wrong data failed unexpectedly: %v", err)
	}

	if verifyWrongResp.Valid {
		t.Error("Signature verification should fail with wrong data")
	}

	t.Log("Verification correctly rejected wrong data")
}

// TestSDK_Embedded_EncryptDecrypt tests symmetric encryption and decryption.
func TestSDK_Embedded_EncryptDecrypt(t *testing.T) {
	client, cleanup := createTestClient(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keyID := "test-aes-key"

	// Generate symmetric key
	_, err := client.GenerateKey(ctx, &keychain.GenerateKeyRequest{
		KeyID:     keyID,
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer client.DeleteKey(ctx, "software", keyID)

	// Encrypt data
	plaintext := []byte("Secret message for encryption test!")
	encResp, err := client.Encrypt(ctx, &keychain.EncryptRequest{
		Backend:   "software",
		KeyID:     keyID,
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

	t.Logf("Encrypted data: ciphertext=%d bytes, nonce=%d bytes", len(encResp.Ciphertext), len(encResp.Nonce))

	// Decrypt data
	decResp, err := client.Decrypt(ctx, &keychain.DecryptRequest{
		Backend:    "software",
		KeyID:      keyID,
		Ciphertext: encResp.Ciphertext,
		Nonce:      encResp.Nonce,
		Tag:        encResp.Tag,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decResp.Plaintext) != string(plaintext) {
		t.Errorf("Decrypted data mismatch:\n  got:  %q\n  want: %q", decResp.Plaintext, plaintext)
	}

	t.Log("Encryption/Decryption successful - data matches")
}

// TestSDK_Embedded_SealUnseal tests sealing capabilities.
func TestSDK_Embedded_SealUnseal(t *testing.T) {
	client, cleanup := createTestClient(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if sealing is supported
	canSealResp, err := client.CanSeal(ctx, "software")
	if err != nil {
		t.Fatalf("CanSeal failed: %v", err)
	}

	if !canSealResp.CanSeal {
		t.Skip("Sealing not supported for software backend")
	}

	t.Logf("CanSeal: backend=%s, supported=%v", canSealResp.Backend, canSealResp.CanSeal)

	// Seal data
	secretData := []byte("Sealed secret data for integration test!")
	sealResp, err := client.Seal(ctx, &keychain.SealRequest{
		Backend: "software",
		Data:    secretData,
	})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if len(sealResp.Ciphertext) == 0 {
		t.Error("Expected non-empty sealed ciphertext")
	}

	t.Logf("Sealed data: ciphertext=%d bytes", len(sealResp.Ciphertext))

	// Unseal data
	unsealResp, err := client.Unseal(ctx, &keychain.UnsealRequest{
		Backend:    "software",
		Ciphertext: sealResp.Ciphertext,
		Nonce:      sealResp.Nonce,
		Tag:        sealResp.Tag,
	})
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if string(unsealResp.Plaintext) != string(secretData) {
		t.Errorf("Unsealed data mismatch:\n  got:  %q\n  want: %q", unsealResp.Plaintext, secretData)
	}

	t.Log("Seal/Unseal successful - data matches")
}

// TestSDK_URLParsing tests creating clients from URLs.
func TestSDK_URLParsing(t *testing.T) {
	testCases := []struct {
		URL      string
		Expected keychain.Protocol
	}{
		{"http://localhost:8443", keychain.ProtocolREST},
		{"https://localhost:8443", keychain.ProtocolREST},
		{"grpc://localhost:9443", keychain.ProtocolGRPC},
		{"grpcs://localhost:9443", keychain.ProtocolGRPC},
		{"quic://localhost:8444", keychain.ProtocolQUIC},
		{"mcp://localhost:9444", keychain.ProtocolMCP},
		{"mcps://localhost:9444", keychain.ProtocolMCP},
		{"unix:///path/to/socket", keychain.ProtocolUnix},
	}

	for _, tc := range testCases {
		t.Run(tc.URL, func(t *testing.T) {
			client, err := keychain.NewFromURL(tc.URL)
			if err != nil {
				t.Fatalf("NewFromURL failed for %s: %v", tc.URL, err)
			}
			defer client.Close()
			t.Logf("Created client from URL: %s", tc.URL)
		})
	}
}

// TestSDK_Embedded_MultipleKeys tests operations with multiple keys.
func TestSDK_Embedded_MultipleKeys(t *testing.T) {
	client, cleanup := createTestClient(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Generate multiple keys
	keyIDs := []string{"multi-key-1", "multi-key-2", "multi-key-3"}
	for _, keyID := range keyIDs {
		_, err := client.GenerateKey(ctx, &keychain.GenerateKeyRequest{
			KeyID:   keyID,
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "P-256",
		})
		if err != nil {
			t.Fatalf("GenerateKey failed for %s: %v", keyID, err)
		}
		t.Logf("Generated key: %s", keyID)
	}

	// List and verify all keys exist
	listResp, err := client.ListKeys(ctx, "software")
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(listResp.Keys) < len(keyIDs) {
		t.Errorf("Expected at least %d keys, got %d", len(keyIDs), len(listResp.Keys))
	}

	t.Logf("Listed %d keys", len(listResp.Keys))

	// Sign with each key and verify
	testData := []byte("Multi-key test data")
	for _, keyID := range keyIDs {
		signResp, err := client.Sign(ctx, &keychain.SignRequest{
			Backend: "software",
			KeyID:   keyID,
			Data:    testData,
			Hash:    "SHA256",
		})
		if err != nil {
			t.Fatalf("Sign failed for %s: %v", keyID, err)
		}

		verifyResp, err := client.Verify(ctx, &keychain.VerifyRequest{
			Backend:   "software",
			KeyID:     keyID,
			Data:      testData,
			Signature: signResp.Signature,
			Hash:      "SHA256",
		})
		if err != nil {
			t.Fatalf("Verify failed for %s: %v", keyID, err)
		}

		if !verifyResp.Valid {
			t.Errorf("Signature verification failed for key %s", keyID)
		}
	}

	t.Log("Multi-key sign/verify operations successful")

	// Cleanup
	for _, keyID := range keyIDs {
		_, err := client.DeleteKey(ctx, "software", keyID)
		if err != nil {
			t.Errorf("DeleteKey failed for %s: %v", keyID, err)
		}
	}

	t.Log("All keys deleted successfully")
}

// TestSDK_Embedded_ErrorHandling tests error cases.
func TestSDK_Embedded_ErrorHandling(t *testing.T) {
	client, cleanup := createTestClient(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get non-existent key
	t.Run("GetNonExistentKey", func(t *testing.T) {
		_, err := client.GetKey(ctx, "software", "non-existent-key")
		if err == nil {
			t.Error("Expected error for non-existent key, but got nil")
		}
		t.Logf("Correctly returned error for non-existent key: %v", err)
	})

	// Delete non-existent key
	t.Run("DeleteNonExistentKey", func(t *testing.T) {
		_, err := client.DeleteKey(ctx, "software", "non-existent-key")
		if err == nil {
			t.Error("Expected error for deleting non-existent key, but got nil")
		}
		t.Logf("Correctly returned error for deleting non-existent key: %v", err)
	})

	// Sign with non-existent key
	t.Run("SignWithNonExistentKey", func(t *testing.T) {
		_, err := client.Sign(ctx, &keychain.SignRequest{
			Backend: "software",
			KeyID:   "non-existent-key",
			Data:    []byte("test"),
			Hash:    "SHA256",
		})
		if err == nil {
			t.Error("Expected error for signing with non-existent key, but got nil")
		}
		t.Logf("Correctly returned error for signing with non-existent key: %v", err)
	})

	// Get non-existent backend
	t.Run("GetNonExistentBackend", func(t *testing.T) {
		_, err := client.GetBackend(ctx, "non-existent-backend")
		if err == nil {
			t.Error("Expected error for non-existent backend, but got nil")
		}
		t.Logf("Correctly returned error for non-existent backend: %v", err)
	})
}
