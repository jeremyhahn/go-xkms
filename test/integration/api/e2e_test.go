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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
)

// TestE2ECompleteWorkflow tests a complete workflow across all interfaces
func TestE2ECompleteWorkflow(t *testing.T) {
	cfg := LoadTestConfig()

	// Check which interfaces are available
	hasREST := isServerAvailable(t, cfg)
	hasGRPC := isGRPCServerAvailable(t, cfg)

	if !hasREST && !hasGRPC {
		t.Skip("Server interfaces required for integration tests. Run: make integration-test (uses Docker)")
	}

	keyID := generateUniqueID("e2e-workflow-key")

	t.Run("Complete_Lifecycle", func(t *testing.T) {
		// Step 1: Generate key via REST
		if hasREST {
			t.Log("Step 1: Generating key via REST API...")
			restClient := NewRESTClient(cfg.RESTBaseURL)

			reqBody := map[string]interface{}{
				"key_id":   keyID,
				"backend":  "software",
				"key_type": "rsa",
				"key_size": 2048,
			}

			resp, err := restClient.doRequest("POST", "/api/v1/keys", reqBody)
			assertNoError(t, err, "Failed to generate key via REST")
			resp.Body.Close()

			assertEqual(t, 201, resp.StatusCode, "Unexpected status code")
			t.Logf("  ✓ Key generated via REST: %s", keyID)
		}

		// Step 2: Verify key exists via gRPC
		if hasGRPC {
			t.Log("Step 2: Verifying key exists via gRPC...")
			grpcClient, err := NewGRPCClient(cfg.GRPCAddr)
			assertNoError(t, err, "Failed to create gRPC client")
			defer grpcClient.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := grpcClient.client.GetKey(ctx, &pb.GetKeyRequest{
				KeyId:   keyID,
				Backend: "software",
			})
			assertNoError(t, err, "Failed to get key via gRPC")

			assertEqual(t, keyID, resp.Key.KeyId, "Key ID mismatch")
			t.Logf("  ✓ Key verified via gRPC")
		}

		// Step 3: List keys and verify our key is in the list
		if hasREST {
			t.Log("Step 3: Listing keys via REST...")
			restClient := NewRESTClient(cfg.RESTBaseURL)

			resp, err := restClient.doRequest("GET", "/api/v1/keys?backend=software", nil)
			assertNoError(t, err, "Failed to list keys")
			defer resp.Body.Close()

			var result map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&result)
			assertNoError(t, err, "Failed to decode list response")

			keys, ok := result["keys"].([]interface{})
			if !ok {
				t.Fatal("Response missing keys array")
			}

			found := false
			for _, k := range keys {
				keyMap := k.(map[string]interface{})
				if keyMap["key_id"] == keyID {
					found = true
					break
				}
			}

			if !found {
				t.Fatalf("Key %s not found in list", keyID)
			}
			t.Logf("  ✓ Key found in list (%d total keys)", len(keys))
		}

		// Step 4: Sign data via gRPC
		var signature []byte
		if hasGRPC {
			t.Log("Step 4: Signing data via gRPC...")
			grpcClient, err := NewGRPCClient(cfg.GRPCAddr)
			assertNoError(t, err, "Failed to create gRPC client")
			defer grpcClient.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			testData := []byte("e2e test data")

			signResp, err := grpcClient.client.Sign(ctx, &pb.SignRequest{
				KeyId:   keyID,
				Backend: "software",
				Data:    testData,
				Hash:    "SHA256",
			})
			assertNoError(t, err, "Failed to sign via gRPC")

			signature = signResp.Signature
			t.Logf("  ✓ Data signed via gRPC (signature length: %d)", len(signature))
		}

		// Step 5: Verify signature via REST
		if hasREST && len(signature) > 0 {
			t.Log("Step 5: Verifying signature via REST...")
			restClient := NewRESTClient(cfg.RESTBaseURL)

			verifyReq := map[string]interface{}{
				"data":      []byte("e2e test data"),
				"signature": signature,
				"hash":      "SHA256",
			}

			resp, err := restClient.doRequest("POST", fmt.Sprintf("/api/v1/keys/%s/verify?backend=software", keyID), verifyReq)
			assertNoError(t, err, "Failed to verify via REST")
			defer resp.Body.Close()

			var result map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&result)
			assertNoError(t, err, "Failed to decode verify response")

			valid, ok := result["valid"].(bool)
			if !ok {
				t.Fatal("Verify response missing valid field")
			}

			if !valid {
				t.Fatal("Signature verification failed")
			}
			t.Logf("  ✓ Signature verified via REST")
		}

		// Step 6: Delete key via REST
		if hasREST {
			t.Log("Step 6: Deleting key via REST...")
			restClient := NewRESTClient(cfg.RESTBaseURL)

			resp, err := restClient.doRequest("DELETE", fmt.Sprintf("/api/v1/keys/%s?backend=software", keyID), nil)
			assertNoError(t, err, "Failed to delete key via REST")
			resp.Body.Close()

			assertEqual(t, 200, resp.StatusCode, "Unexpected delete status")
			t.Logf("  ✓ Key deleted via REST")
		}

		// Step 7: Verify key is gone via gRPC
		if hasGRPC {
			t.Log("Step 7: Verifying key is deleted via gRPC...")
			grpcClient, err := NewGRPCClient(cfg.GRPCAddr)
			assertNoError(t, err, "Failed to create gRPC client")
			defer grpcClient.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err = grpcClient.client.GetKey(ctx, &pb.GetKeyRequest{
				KeyId:   keyID,
				Backend: "software",
			})

			if err == nil {
				t.Fatal("Key still exists after deletion")
			}
			t.Logf("  ✓ Key deletion confirmed via gRPC")
		}

		t.Log("✓ Complete workflow test passed!")
	})
}

// TestE2ERESTToGRPC tests creating via REST and using via gRPC
func TestE2ERESTToGRPC(t *testing.T) {
	cfg := LoadTestConfig()

	if !isServerAvailable(t, cfg) {
		t.Skip("REST server required for integration tests. Run: make integration-test (uses Docker)")
	}
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	keyID := generateUniqueID("e2e-rest-to-grpc")

	// Create key via REST
	t.Log("Creating key via REST...")
	restClient := NewRESTClient(cfg.RESTBaseURL)

	reqBody := map[string]interface{}{
		"key_id":   keyID,
		"backend":  "software",
		"key_type": "ecdsa",
		"curve":    "P256",
	}

	resp, err := restClient.doRequest("POST", "/api/v1/keys", reqBody)
	assertNoError(t, err, "Failed to create key via REST")
	resp.Body.Close()

	defer func() {
		restClient.doRequest("DELETE", fmt.Sprintf("/api/v1/keys/%s?backend=software", keyID), nil)
	}()

	// Use key via gRPC for signing
	t.Log("Using key via gRPC for signing...")
	grpcClient, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer grpcClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testData := []byte("test data")

	signResp, err := grpcClient.client.Sign(ctx, &pb.SignRequest{
		KeyId:   keyID,
		Backend: "software",
		Data:    testData,
		Hash:    "SHA256",
	})
	assertNoError(t, err, "Failed to sign via gRPC")

	if len(signResp.Signature) == 0 {
		t.Fatal("Empty signature")
	}

	t.Log("✓ REST-to-gRPC test passed!")
}

// TestE2EGRPCToREST tests creating via gRPC and using via REST
func TestE2EGRPCToREST(t *testing.T) {
	cfg := LoadTestConfig()

	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}
	if !isServerAvailable(t, cfg) {
		t.Skip("REST server required for integration tests. Run: make integration-test (uses Docker)")
	}

	keyID := generateUniqueID("e2e-grpc-to-rest")

	// Create key via gRPC
	t.Log("Creating key via gRPC...")
	grpcClient, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer grpcClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = grpcClient.client.GenerateKey(ctx, &pb.GenerateKeyRequest{
		KeyId:   keyID,
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	})
	assertNoError(t, err, "Failed to create key via gRPC")

	defer func() {
		grpcClient.client.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
			KeyId:   keyID,
			Backend: "software",
		})
	}()

	// Use key via REST for signing
	t.Log("Using key via REST for signing...")
	restClient := NewRESTClient(cfg.RESTBaseURL)

	signReq := map[string]interface{}{
		"data": []byte("test data"),
		"hash": "SHA256",
	}

	resp, err := restClient.doRequest("POST", fmt.Sprintf("/api/v1/keys/%s/sign?backend=software", keyID), signReq)
	assertNoError(t, err, "Failed to sign via REST")
	defer resp.Body.Close()

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	assertNoError(t, err, "Failed to decode sign response")

	signature := result["signature"]
	if signature == nil {
		t.Fatal("Empty signature")
	}

	t.Log("✓ gRPC-to-REST test passed!")
}

// TestE2EConcurrentAccess tests concurrent access from multiple interfaces
func TestE2EConcurrentAccess(t *testing.T) {
	cfg := LoadTestConfig()

	if !isServerAvailable(t, cfg) {
		t.Skip("REST server required for integration tests. Run: make integration-test (uses Docker)")
	}
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	keyID := generateUniqueID("e2e-concurrent")

	// Create key
	restClient := NewRESTClient(cfg.RESTBaseURL)
	reqBody := map[string]interface{}{
		"key_id":   keyID,
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	}

	resp, err := restClient.doRequest("POST", "/api/v1/keys", reqBody)
	assertNoError(t, err, "Failed to create key")
	resp.Body.Close()

	defer func() {
		restClient.doRequest("DELETE", fmt.Sprintf("/api/v1/keys/%s?backend=software", keyID), nil)
	}()

	// Concurrent operations
	t.Log("Running concurrent operations...")

	done := make(chan bool, 2)

	// REST signing in goroutine
	go func() {
		for i := 0; i < 5; i++ {
			signReq := map[string]interface{}{
				"data": []byte(fmt.Sprintf("test data %d", i)),
				"hash": "SHA256",
			}

			resp, err := restClient.doRequest("POST", fmt.Sprintf("/api/v1/keys/%s/sign?backend=software", keyID), signReq)
			if err != nil {
				t.Errorf("REST sign failed: %v", err)
				done <- false
				return
			}
			resp.Body.Close()
		}
		done <- true
	}()

	// gRPC signing in goroutine
	go func() {
		grpcClient, err := NewGRPCClient(cfg.GRPCAddr)
		if err != nil {
			t.Errorf("Failed to create gRPC client: %v", err)
			done <- false
			return
		}
		defer grpcClient.Close()

		for i := 0; i < 5; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := grpcClient.client.Sign(ctx, &pb.SignRequest{
				KeyId:   keyID,
				Backend: "software",
				Data:    []byte(fmt.Sprintf("test data %d", i)),
				Hash:    "SHA256",
			})
			cancel()

			if err != nil {
				t.Errorf("gRPC sign failed: %v", err)
				done <- false
				return
			}
		}
		done <- true
	}()

	// Wait for both goroutines
	success1 := <-done
	success2 := <-done

	if !success1 || !success2 {
		t.Fatal("Concurrent operations failed")
	}

	t.Log("✓ Concurrent access test passed!")
}

// TestE2EMultipleKeyTypes tests working with multiple key types
func TestE2EMultipleKeyTypes(t *testing.T) {
	cfg := LoadTestConfig()

	if !isServerAvailable(t, cfg) {
		t.Skip("REST server required for integration tests. Run: make integration-test (uses Docker)")
	}
	if !isGRPCServerAvailable(t, cfg) {
		t.Skip("gRPC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	keyTypes := []struct {
		keyType string
		keySize int32
		curve   string
	}{
		{"rsa", 2048, ""},
		{"ecdsa", 0, "P256"},
		{"ed25519", 0, ""},
	}

	restClient := NewRESTClient(cfg.RESTBaseURL)
	grpcClient, err := NewGRPCClient(cfg.GRPCAddr)
	assertNoError(t, err, "Failed to create gRPC client")
	defer grpcClient.Close()

	for _, kt := range keyTypes {
		t.Run(kt.keyType, func(t *testing.T) {
			keyID := generateUniqueID(fmt.Sprintf("e2e-multi-%s", kt.keyType))

			// Create via gRPC
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req := &pb.GenerateKeyRequest{
				KeyId:   keyID,
				Backend: "software",
				KeyType: kt.keyType,
				KeySize: kt.keySize,
				Curve:   kt.curve,
			}

			_, err := grpcClient.client.GenerateKey(ctx, req)
			assertNoError(t, err, "Failed to generate key")

			defer func() {
				restClient.doRequest("DELETE", fmt.Sprintf("/api/v1/keys/%s?backend=software", keyID), nil)
			}()

			// Sign via REST
			signReq := map[string]interface{}{
				"data": []byte("test data"),
				"hash": "SHA256",
			}

			resp, err := restClient.doRequest("POST", fmt.Sprintf("/api/v1/keys/%s/sign?backend=software", keyID), signReq)
			assertNoError(t, err, "Failed to sign")
			defer resp.Body.Close()

			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)

			if result["signature"] == nil {
				t.Fatal("Missing signature")
			}

			t.Logf("✓ %s key workflow completed", kt.keyType)
		})
	}

	t.Log("✓ Multiple key types test passed!")
}
