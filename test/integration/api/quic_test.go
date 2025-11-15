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

//go:build integration

package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// QUICTestClient wraps HTTP/3 client for QUIC testing
type QUICTestClient struct {
	baseURL string
	client  *http.Client
	apiKey  string
}

// newQUICClient creates a new QUIC/HTTP3 test client
func newQUICClient(baseURL string) *QUICTestClient {
	return &QUICTestClient{
		baseURL: baseURL,
		apiKey:  "test-api-key",
		client: &http.Client{
			Transport: &http3.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Test only
				},
			},
			Timeout: 10 * time.Second,
		},
	}
}

// doRequest performs an HTTP/3 request and returns the response
func (c *QUICTestClient) doRequest(method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	return c.client.Do(req)
}

// Close closes the QUIC client
func (c *QUICTestClient) Close() error {
	if transport, ok := c.client.Transport.(*http3.Transport); ok {
		return transport.Close()
	}
	return nil
}

// isQUICServerAvailable checks if QUIC server is available
func isQUICServerAvailable(t *testing.T, cfg *TestConfig) bool {
	t.Helper()

	client := newQUICClient(cfg.QUICBaseURL)
	defer client.Close()

	resp, err := client.doRequest("GET", "/health", nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// TestQUIC_HealthEndpoint tests the health check endpoint via HTTP/3
func TestQUIC_HealthEndpoint(t *testing.T) {
	cfg := LoadTestConfig()
	if !isQUICServerAvailable(t, cfg) {
		t.Fatal("QUIC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := newQUICClient(cfg.QUICBaseURL)
	defer client.Close()

	resp, err := client.doRequest("GET", "/health", nil)
	assertNoError(t, err, "Health check request failed")
	defer resp.Body.Close()

	assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected status code")

	// Verify HTTP/3 protocol
	if resp.ProtoMajor != 3 {
		t.Logf("Warning: Expected HTTP/3, got HTTP/%d.%d", resp.ProtoMajor, resp.ProtoMinor)
	}

	var health map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&health)
	assertNoError(t, err, "Failed to decode health response")

	status, ok := health["status"].(string)
	if !ok {
		t.Fatal("Health response missing status field")
	}

	if status != "healthy" && status != "ok" {
		t.Fatalf("Unexpected health status: %s", status)
	}

	t.Logf("Health check passed via HTTP/3: %s (protocol: HTTP/%d.%d)",
		status, resp.ProtoMajor, resp.ProtoMinor)
}

// TestQUIC_ListBackends tests listing backends via HTTP/3
func TestQUIC_ListBackends(t *testing.T) {
	cfg := LoadTestConfig()
	if !isQUICServerAvailable(t, cfg) {
		t.Fatal("QUIC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := newQUICClient(cfg.QUICBaseURL)
	defer client.Close()

	resp, err := client.doRequest("GET", "/api/v1/backends", nil)
	assertNoError(t, err, "List backends request failed")
	defer resp.Body.Close()

	assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected status code")

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	assertNoError(t, err, "Failed to decode backends response")

	backends, ok := result["backends"].([]interface{})
	if !ok {
		t.Fatal("Backends response missing backends array")
	}

	if len(backends) == 0 {
		t.Fatal("No backends available")
	}

	t.Logf("Found %d backend(s) via HTTP/3", len(backends))
}

// TestQUIC_GenerateKey tests key generation via HTTP/3
func TestQUIC_GenerateKey(t *testing.T) {
	cfg := LoadTestConfig()
	if !isQUICServerAvailable(t, cfg) {
		t.Fatal("QUIC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := newQUICClient(cfg.QUICBaseURL)
	defer client.Close()

	keyID := generateUniqueID("quic-key")

	tests := []struct {
		name     string
		keyType  string
		keySize  int
		curve    string
		wantCode int
	}{
		{
			name:     "RSA 2048",
			keyType:  "rsa",
			keySize:  2048,
			wantCode: http.StatusCreated,
		},
		{
			name:     "ECDSA P256",
			keyType:  "ecdsa",
			curve:    "P256",
			wantCode: http.StatusCreated,
		},
		{
			name:     "Ed25519",
			keyType:  "ed25519",
			wantCode: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testKeyID := fmt.Sprintf("%s-%s", keyID, tt.keyType)

			reqBody := map[string]interface{}{
				"key_id":   testKeyID,
				"backend":  "pkcs8",
				"key_type": tt.keyType,
			}

			if tt.keySize > 0 {
				reqBody["key_size"] = tt.keySize
			}
			if tt.curve != "" {
				reqBody["curve"] = tt.curve
			}

			resp, err := client.doRequest("POST", "/api/v1/keys", reqBody)
			assertNoError(t, err, "Generate key request failed")
			defer resp.Body.Close()

			assertEqual(t, tt.wantCode, resp.StatusCode, "Unexpected status code")

			if resp.StatusCode == http.StatusCreated {
				var result map[string]interface{}
				err = json.NewDecoder(resp.Body).Decode(&result)
				assertNoError(t, err, "Failed to decode generate key response")

				returnedKeyID, ok := result["key_id"].(string)
				if !ok {
					t.Fatal("Response missing key_id field")
				}

				assertEqual(t, testKeyID, returnedKeyID, "Key ID mismatch")

				if tt.keyType != "ed25519" && tt.keyType != "aes" {
					pubKey, ok := result["public_key_pem"].(string)
					if !ok || pubKey == "" {
						t.Fatal("Response missing public_key_pem")
					}
				}

				t.Logf("Generated %s key via HTTP/3: %s", tt.keyType, testKeyID)

				// Cleanup
				defer func() {
					delResp, _ := client.doRequest("DELETE",
						fmt.Sprintf("/api/v1/keys/%s?backend=pkcs8", testKeyID), nil)
					if delResp != nil {
						delResp.Body.Close()
					}
				}()
			}
		})
	}
}

// TestQUIC_ListKeys tests listing keys via HTTP/3
func TestQUIC_ListKeys(t *testing.T) {
	cfg := LoadTestConfig()
	if !isQUICServerAvailable(t, cfg) {
		t.Fatal("QUIC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := newQUICClient(cfg.QUICBaseURL)
	defer client.Close()

	keyID := generateUniqueID("quic-list-key")

	// Create a test key first
	reqBody := map[string]interface{}{
		"key_id":   keyID,
		"backend":  "pkcs8",
		"key_type": "rsa",
		"key_size": 2048,
	}

	resp, err := client.doRequest("POST", "/api/v1/keys", reqBody)
	assertNoError(t, err, "Failed to create test key")
	resp.Body.Close()

	defer func() {
		delResp, _ := client.doRequest("DELETE",
			fmt.Sprintf("/api/v1/keys/%s?backend=pkcs8", keyID), nil)
		if delResp != nil {
			delResp.Body.Close()
		}
	}()

	// List keys
	resp, err = client.doRequest("GET", "/api/v1/keys?backend=pkcs8", nil)
	assertNoError(t, err, "List keys request failed")
	defer resp.Body.Close()

	assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected status code")

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	assertNoError(t, err, "Failed to decode list keys response")

	keys, ok := result["keys"].([]interface{})
	if !ok {
		t.Fatal("Response missing keys array")
	}

	// Verify our key is in the list
	found := false
	for _, k := range keys {
		keyMap, ok := k.(map[string]interface{})
		if !ok {
			continue
		}
		if id, ok := keyMap["key_id"].(string); ok && id == keyID {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("Created key %s not found in list", keyID)
	}

	t.Logf("Listed %d key(s) via HTTP/3, found test key", len(keys))
}

// TestQUIC_GetKey tests retrieving key details via HTTP/3
func TestQUIC_GetKey(t *testing.T) {
	cfg := LoadTestConfig()
	if !isQUICServerAvailable(t, cfg) {
		t.Fatal("QUIC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := newQUICClient(cfg.QUICBaseURL)
	defer client.Close()

	keyID := generateUniqueID("quic-get-key")

	// Create a test key
	reqBody := map[string]interface{}{
		"key_id":   keyID,
		"backend":  "pkcs8",
		"key_type": "rsa",
		"key_size": 2048,
	}

	resp, err := client.doRequest("POST", "/api/v1/keys", reqBody)
	assertNoError(t, err, "Failed to create test key")
	resp.Body.Close()

	defer func() {
		delResp, _ := client.doRequest("DELETE",
			fmt.Sprintf("/api/v1/keys/%s?backend=pkcs8", keyID), nil)
		if delResp != nil {
			delResp.Body.Close()
		}
	}()

	// Get the key
	resp, err = client.doRequest("GET", fmt.Sprintf("/api/v1/keys/%s?backend=pkcs8", keyID), nil)
	assertNoError(t, err, "Get key request failed")
	defer resp.Body.Close()

	assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected status code")

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	assertNoError(t, err, "Failed to decode get key response")

	returnedKeyID, ok := result["key_id"].(string)
	if !ok {
		t.Fatal("Response missing key_id field")
	}

	assertEqual(t, keyID, returnedKeyID, "Key ID mismatch")

	t.Logf("Retrieved key via HTTP/3: %s", keyID)
}

// TestQUIC_SignAndVerify tests sign and verify operations via HTTP/3
func TestQUIC_SignAndVerify(t *testing.T) {
	cfg := LoadTestConfig()
	if !isQUICServerAvailable(t, cfg) {
		t.Fatal("QUIC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := newQUICClient(cfg.QUICBaseURL)
	defer client.Close()

	keyID := generateUniqueID("quic-sign-key")

	// Create a test key
	reqBody := map[string]interface{}{
		"key_id":   keyID,
		"backend":  "pkcs8",
		"key_type": "rsa",
		"key_size": 2048,
	}

	resp, err := client.doRequest("POST", "/api/v1/keys", reqBody)
	assertNoError(t, err, "Failed to create test key")
	resp.Body.Close()

	defer func() {
		delResp, _ := client.doRequest("DELETE",
			fmt.Sprintf("/api/v1/keys/%s?backend=pkcs8", keyID), nil)
		if delResp != nil {
			delResp.Body.Close()
		}
	}()

	testData := []byte("test data for signing via QUIC")

	// Sign data
	signReq := map[string]interface{}{
		"data": testData,
		"hash": "SHA256",
	}

	resp, err = client.doRequest("POST",
		fmt.Sprintf("/api/v1/keys/%s/sign?backend=pkcs8", keyID), signReq)
	assertNoError(t, err, "Sign request failed")
	defer resp.Body.Close()

	assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected sign status code")

	var signResult map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&signResult)
	assertNoError(t, err, "Failed to decode sign response")

	signature, ok := signResult["signature"]
	if !ok {
		t.Fatal("Sign response missing signature")
	}

	t.Logf("Signed data successfully via HTTP/3")

	// Verify signature
	verifyReq := map[string]interface{}{
		"data":      testData,
		"signature": signature,
		"hash":      "SHA256",
	}

	resp, err = client.doRequest("POST",
		fmt.Sprintf("/api/v1/keys/%s/verify?backend=pkcs8", keyID), verifyReq)
	assertNoError(t, err, "Verify request failed")
	defer resp.Body.Close()

	assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected verify status code")

	var verifyResult map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&verifyResult)
	assertNoError(t, err, "Failed to decode verify response")

	valid, ok := verifyResult["valid"].(bool)
	if !ok {
		t.Fatal("Verify response missing valid field")
	}

	if !valid {
		t.Fatal("Signature verification failed")
	}

	t.Logf("Verified signature successfully via HTTP/3")
}

// TestQUIC_DeleteKey tests key deletion via HTTP/3
func TestQUIC_DeleteKey(t *testing.T) {
	cfg := LoadTestConfig()
	if !isQUICServerAvailable(t, cfg) {
		t.Fatal("QUIC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := newQUICClient(cfg.QUICBaseURL)
	defer client.Close()

	keyID := generateUniqueID("quic-delete-key")

	// Create a test key
	reqBody := map[string]interface{}{
		"key_id":   keyID,
		"backend":  "pkcs8",
		"key_type": "rsa",
		"key_size": 2048,
	}

	resp, err := client.doRequest("POST", "/api/v1/keys", reqBody)
	assertNoError(t, err, "Failed to create test key")
	resp.Body.Close()

	// Delete the key
	resp, err = client.doRequest("DELETE",
		fmt.Sprintf("/api/v1/keys/%s?backend=pkcs8", keyID), nil)
	assertNoError(t, err, "Delete request failed")
	defer resp.Body.Close()

	assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected delete status code")

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	assertNoError(t, err, "Failed to decode delete response")

	success, ok := result["success"].(bool)
	if !ok {
		t.Fatal("Delete response missing success field")
	}

	if !success {
		t.Fatal("Key deletion reported as failed")
	}

	t.Logf("Deleted key successfully via HTTP/3")

	// Verify key is gone
	resp, err = client.doRequest("GET",
		fmt.Sprintf("/api/v1/keys/%s?backend=pkcs8", keyID), nil)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("Key still exists after deletion")
		}
	}
}

// TestQUIC_ErrorHandling tests error handling in QUIC/HTTP3 API
func TestQUIC_ErrorHandling(t *testing.T) {
	cfg := LoadTestConfig()
	if !isQUICServerAvailable(t, cfg) {
		t.Fatal("QUIC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := newQUICClient(cfg.QUICBaseURL)
	defer client.Close()

	tests := []struct {
		name     string
		method   string
		path     string
		body     interface{}
		wantCode int
	}{
		{
			name:     "Invalid key type",
			method:   "POST",
			path:     "/api/v1/keys",
			body:     map[string]interface{}{"key_id": "test", "key_type": "invalid"},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "Missing key ID",
			method:   "POST",
			path:     "/api/v1/keys",
			body:     map[string]interface{}{"key_type": "rsa"},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "Get non-existent key",
			method:   "GET",
			path:     "/api/v1/keys/non-existent-key-quic?backend=pkcs8",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Delete non-existent key",
			method:   "DELETE",
			path:     "/api/v1/keys/non-existent-key-quic?backend=pkcs8",
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.doRequest(tt.method, tt.path, tt.body)
			assertNoError(t, err, "Request failed")
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantCode {
				body, _ := io.ReadAll(resp.Body)
				t.Logf("Response body: %s", string(body))
			}

			assertEqual(t, tt.wantCode, resp.StatusCode, "Unexpected status code")
			t.Logf("Correctly received error code %d via HTTP/3", resp.StatusCode)
		})
	}
}

// TestQUIC_ConcurrentRequests tests concurrent HTTP/3 requests
func TestQUIC_ConcurrentRequests(t *testing.T) {
	cfg := LoadTestConfig()
	if !isQUICServerAvailable(t, cfg) {
		t.Fatal("QUIC server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := newQUICClient(cfg.QUICBaseURL)
	defer client.Close()

	const numRequests = 5

	var wg sync.WaitGroup
	errors := make(chan error, numRequests)
	keyIDs := make([]string, numRequests)

	// Create keys concurrently
	t.Run("Concurrent key generation", func(t *testing.T) {
		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				keyID := generateUniqueID(fmt.Sprintf("quic-concurrent-%d", idx))
				keyIDs[idx] = keyID

				reqBody := map[string]interface{}{
					"key_id":   keyID,
					"backend":  "pkcs8",
					"key_type": "rsa",
					"key_size": 2048,
				}

				resp, err := client.doRequest("POST", "/api/v1/keys", reqBody)
				if err != nil {
					errors <- fmt.Errorf("request %d failed: %w", idx, err)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusCreated {
					errors <- fmt.Errorf("request %d: unexpected status %d", idx, resp.StatusCode)
					return
				}

				t.Logf("Concurrent request %d succeeded via HTTP/3", idx)
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Error(err)
		}
	})

	// Cleanup all created keys
	defer func() {
		for _, keyID := range keyIDs {
			if keyID != "" {
				resp, _ := client.doRequest("DELETE",
					fmt.Sprintf("/api/v1/keys/%s?backend=pkcs8", keyID), nil)
				if resp != nil {
					resp.Body.Close()
				}
			}
		}
	}()

	// Verify all keys exist concurrently
	t.Run("Concurrent key retrieval", func(t *testing.T) {
		errors := make(chan error, numRequests)
		var wg sync.WaitGroup

		for i := 0; i < numRequests; i++ {
			if keyIDs[i] == "" {
				continue
			}

			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				resp, err := client.doRequest("GET",
					fmt.Sprintf("/api/v1/keys/%s?backend=pkcs8", keyIDs[idx]), nil)
				if err != nil {
					errors <- fmt.Errorf("get request %d failed: %w", idx, err)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					errors <- fmt.Errorf("get request %d: unexpected status %d", idx, resp.StatusCode)
					return
				}

				t.Logf("Concurrent get request %d succeeded via HTTP/3", idx)
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Error(err)
		}
	})

	t.Logf("Successfully completed %d concurrent HTTP/3 operations", numRequests)
}
