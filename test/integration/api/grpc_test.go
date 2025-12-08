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

//go:build integration && grpc

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// GRPCClient wraps gRPC client for testing
type GRPCClient struct {
	conn   *grpc.ClientConn
	client pb.KeystoreServiceClient
}

// NewGRPCClient creates a new gRPC client
func NewGRPCClient(addr string) (*GRPCClient, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	return &GRPCClient{
		conn:   conn,
		client: pb.NewKeystoreServiceClient(conn),
	}, nil
}

// Close closes the gRPC connection
func (c *GRPCClient) Close() error {
	return c.conn.Close()
}

// TestGRPCHealth tests the gRPC health check
func TestGRPCHealth(t *testing.T) {
	cfg := LoadTestConfig()
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.client.Health(ctx, &pb.HealthRequest{})
	assertNoError(t, err, "Health check failed")

	if resp.Status != "healthy" {
		t.Fatalf("Unexpected health status: %s", resp.Status)
	}

	assertNotEmpty(t, resp.Version, "Version should not be empty")

	t.Logf("Health check passed: status=%s, version=%s", resp.Status, resp.Version)
}

// TestGRPCListBackends tests listing backends via gRPC
func TestGRPCListBackends(t *testing.T) {
	cfg := LoadTestConfig()
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.client.ListBackends(ctx, &pb.ListBackendsRequest{})
	assertNoError(t, err, "ListBackends failed")

	if len(resp.Backends) == 0 {
		t.Fatal("No backends available")
	}

	if resp.Count != int32(len(resp.Backends)) {
		t.Fatalf("Backend count mismatch: count=%d, len=%d", resp.Count, len(resp.Backends))
	}

	t.Logf("Found %d backend(s)", resp.Count)

	for _, backend := range resp.Backends {
		assertNotEmpty(t, backend.Name, "Backend name should not be empty")
		assertNotEmpty(t, backend.Type, "Backend type should not be empty")
		t.Logf("  - %s (%s): %s", backend.Name, backend.Type, backend.Description)
	}
}

// TestGRPCGetBackendInfo tests getting backend info via gRPC
func TestGRPCGetBackendInfo(t *testing.T) {
	cfg := LoadTestConfig()
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get info for software backend (should always be available)
	resp, err := client.client.GetBackendInfo(ctx, &pb.GetBackendInfoRequest{
		Name: "software",
	})
	assertNoError(t, err, "GetBackendInfo failed")

	if resp.Backend == nil {
		t.Fatal("Backend info is nil")
	}

	assertEqual(t, "software", resp.Backend.Name, "Backend name mismatch")

	t.Logf("Backend info: %s (%s) - %s", resp.Backend.Name, resp.Backend.Type, resp.Backend.Description)
}

// TestGRPCGenerateKey tests key generation via gRPC
func TestGRPCGenerateKey(t *testing.T) {
	cfg := LoadTestConfig()
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer client.Close()

	tests := []struct {
		name    string
		keyType string
		keySize int32
		curve   string
	}{
		{
			name:    "RSA 2048",
			keyType: "rsa",
			keySize: 2048,
		},
		{
			name:    "ECDSA P256",
			keyType: "ecdsa",
			curve:   "P256",
		},
		{
			name:    "Ed25519",
			keyType: "ed25519",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID := generateUniqueID(fmt.Sprintf("grpc-key-%s", tt.keyType))

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			req := &pb.GenerateKeyRequest{
				KeyId:   keyID,
				Backend: "software",
				KeyType: tt.keyType,
				KeySize: tt.keySize,
				Curve:   tt.curve,
			}

			resp, err := client.client.GenerateKey(ctx, req)
			assertNoError(t, err, "GenerateKey failed")

			assertEqual(t, keyID, resp.KeyId, "Key ID mismatch")
			assertEqual(t, "software", resp.Backend, "Backend mismatch")
			assertEqual(t, tt.keyType, resp.KeyType, "Key type mismatch")

			if tt.keyType != "ed25519" && tt.keyType != "aes" {
				assertNotEmpty(t, resp.PublicKeyPem, "Public key PEM should not be empty")
			}

			if resp.CreatedAt == nil {
				t.Fatal("CreatedAt timestamp is nil")
			}

			t.Logf("Generated %s key: %s", tt.keyType, keyID)

			// Cleanup
			defer func() {
				delCtx, delCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer delCancel()

				_, _ = client.client.DeleteKey(delCtx, &pb.DeleteKeyRequest{
					KeyId:   keyID,
					Backend: "software",
				})
			}()
		})
	}
}

// TestGRPCListKeys tests listing keys via gRPC
func TestGRPCListKeys(t *testing.T) {
	cfg := LoadTestConfig()
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer client.Close()

	keyID := generateUniqueID("grpc-list-key")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a test key
	_, err = client.client.GenerateKey(ctx, &pb.GenerateKeyRequest{
		KeyId:   keyID,
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	assertNoError(t, err, "Failed to create test key")

	defer func() {
		delCtx, delCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer delCancel()
		_, _ = client.client.DeleteKey(delCtx, &pb.DeleteKeyRequest{
			KeyId:   keyID,
			Backend: "software",
		})
	}()

	// List keys
	resp, err := client.client.ListKeys(ctx, &pb.ListKeysRequest{
		Backend: "software",
		Limit:   100,
		Offset:  0,
	})
	assertNoError(t, err, "ListKeys failed")

	if len(resp.Keys) == 0 {
		t.Fatal("No keys returned")
	}

	// Verify our key is in the list
	found := false
	for _, key := range resp.Keys {
		if key.KeyId == keyID {
			found = true
			assertEqual(t, "software", key.Backend, "Backend mismatch")
			assertEqual(t, "rsa", key.KeyType, "Key type mismatch")
			break
		}
	}

	if !found {
		t.Fatalf("Created key %s not found in list", keyID)
	}

	t.Logf("Listed %d key(s), found test key", len(resp.Keys))
}

// TestGRPCGetKey tests getting a specific key via gRPC
func TestGRPCGetKey(t *testing.T) {
	cfg := LoadTestConfig()
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer client.Close()

	keyID := generateUniqueID("grpc-get-key")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a test key
	_, err = client.client.GenerateKey(ctx, &pb.GenerateKeyRequest{
		KeyId:   keyID,
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	assertNoError(t, err, "Failed to create test key")

	defer func() {
		delCtx, delCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer delCancel()
		_, _ = client.client.DeleteKey(delCtx, &pb.DeleteKeyRequest{
			KeyId:   keyID,
			Backend: "software",
		})
	}()

	// Get the key
	resp, err := client.client.GetKey(ctx, &pb.GetKeyRequest{
		KeyId:   keyID,
		Backend: "software",
	})
	assertNoError(t, err, "GetKey failed")

	if resp.Key == nil {
		t.Fatal("Key is nil")
	}

	assertEqual(t, keyID, resp.Key.KeyId, "Key ID mismatch")
	assertEqual(t, "software", resp.Key.Backend, "Backend mismatch")
	assertEqual(t, "rsa", resp.Key.KeyType, "Key type mismatch")

	t.Logf("Retrieved key: %s", keyID)
}

// TestGRPCSignVerify tests sign and verify operations via gRPC
func TestGRPCSignVerify(t *testing.T) {
	cfg := LoadTestConfig()
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer client.Close()

	keyID := generateUniqueID("grpc-sign-key")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a test key
	_, err = client.client.GenerateKey(ctx, &pb.GenerateKeyRequest{
		KeyId:   keyID,
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	assertNoError(t, err, "Failed to create test key")

	defer func() {
		delCtx, delCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer delCancel()
		_, _ = client.client.DeleteKey(delCtx, &pb.DeleteKeyRequest{
			KeyId:   keyID,
			Backend: "software",
		})
	}()

	testData := []byte("test data for signing via grpc")

	// Sign data
	signResp, err := client.client.Sign(ctx, &pb.SignRequest{
		KeyId:   keyID,
		Backend: "software",
		Data:    testData,
		Hash:    "SHA256",
	})
	assertNoError(t, err, "Sign failed")

	if len(signResp.Signature) == 0 {
		t.Fatal("Signature is empty")
	}

	t.Logf("Signed data successfully, signature length: %d", len(signResp.Signature))

	// Verify signature
	verifyResp, err := client.client.Verify(ctx, &pb.VerifyRequest{
		KeyId:     keyID,
		Backend:   "software",
		Data:      testData,
		Signature: signResp.Signature,
		Hash:      "SHA256",
	})
	assertNoError(t, err, "Verify failed")

	if !verifyResp.Valid {
		t.Fatal("Signature verification failed")
	}

	t.Logf("Verified signature successfully")

	// Test verification with wrong data
	wrongData := []byte("wrong data")
	verifyResp, err = client.client.Verify(ctx, &pb.VerifyRequest{
		KeyId:     keyID,
		Backend:   "software",
		Data:      wrongData,
		Signature: signResp.Signature,
		Hash:      "SHA256",
	})
	assertNoError(t, err, "Verify request failed")

	if verifyResp.Valid {
		t.Fatal("Signature should not be valid for wrong data")
	}

	t.Logf("Correctly rejected invalid signature")
}

// TestGRPCDeleteKey tests key deletion via gRPC
func TestGRPCDeleteKey(t *testing.T) {
	cfg := LoadTestConfig()
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer client.Close()

	keyID := generateUniqueID("grpc-delete-key")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a test key
	_, err = client.client.GenerateKey(ctx, &pb.GenerateKeyRequest{
		KeyId:   keyID,
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	assertNoError(t, err, "Failed to create test key")

	// Delete the key
	delResp, err := client.client.DeleteKey(ctx, &pb.DeleteKeyRequest{
		KeyId:   keyID,
		Backend: "software",
	})
	assertNoError(t, err, "DeleteKey failed")

	if !delResp.Success {
		t.Fatalf("Key deletion failed: %s", delResp.Message)
	}

	t.Logf("Deleted key successfully")

	// Verify key is gone
	_, err = client.client.GetKey(ctx, &pb.GetKeyRequest{
		KeyId:   keyID,
		Backend: "software",
	})

	if err == nil {
		t.Fatal("Key still exists after deletion")
	}

	// Should get NotFound error
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.NotFound {
		t.Fatalf("Expected NotFound error, got: %v", st.Code())
	}

	t.Logf("Confirmed key deletion")
}

// TestGRPCErrorHandling tests error handling in gRPC API
func TestGRPCErrorHandling(t *testing.T) {
	cfg := LoadTestConfig()
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tests := []struct {
		name      string
		operation func() error
		wantCode  codes.Code
	}{
		{
			name: "Generate key without key_id",
			operation: func() error {
				_, err := client.client.GenerateKey(ctx, &pb.GenerateKeyRequest{
					KeyType: "rsa",
				})
				return err
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "Get non-existent key",
			operation: func() error {
				_, err := client.client.GetKey(ctx, &pb.GetKeyRequest{
					KeyId:   "non-existent-key",
					Backend: "software",
				})
				return err
			},
			wantCode: codes.NotFound,
		},
		{
			name: "Delete non-existent key",
			operation: func() error {
				_, err := client.client.DeleteKey(ctx, &pb.DeleteKeyRequest{
					KeyId:   "non-existent-key",
					Backend: "software",
				})
				return err
			},
			wantCode: codes.NotFound,
		},
		{
			name: "Sign without key_id",
			operation: func() error {
				_, err := client.client.Sign(ctx, &pb.SignRequest{
					Data: []byte("test"),
				})
				return err
			},
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.operation()
			assertError(t, err, "Expected error but got none")

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, got: %v", err)
			}

			if st.Code() != tt.wantCode {
				t.Fatalf("Expected error code %v, got %v: %s", tt.wantCode, st.Code(), st.Message())
			}

			t.Logf("Got expected error: %s", st.Message())
		})
	}
}
