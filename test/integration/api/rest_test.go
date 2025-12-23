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
	"testing"
	"time"
)

// RESTClient wraps HTTP client for REST API testing
type RESTClient struct {
	baseURL string
	client  *http.Client
}

// NewRESTClient creates a new REST API client
func NewRESTClient(baseURL string) *RESTClient {
	return &RESTClient{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// doRequest performs an HTTP request and returns the response
func (c *RESTClient) doRequest(method, path string, body interface{}) (*http.Response, error) {
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

	return c.client.Do(req)
}

// TestRESTHealth tests the REST health endpoint
func TestRESTHealth(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := NewRESTClient(cfg.RESTBaseURL)

	resp, err := client.doRequest("GET", "/health", nil)
	assertNoError(t, err, "Health check request failed")
	defer resp.Body.Close()

	assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected status code")

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

	t.Logf("Health check passed: %s", status)
}

// TestRESTListBackends tests listing backends via REST
func TestRESTListBackends(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := NewRESTClient(cfg.RESTBaseURL)

	resp, err := client.doRequest("GET", "/api/v1/backends", nil)
	assertNoError(t, err, "List backends request failed")
	defer resp.Body.Close()

	assertEqual(t, http.StatusOK, resp.StatusCode, "API endpoint /api/v1/backends should be available")

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	assertNoError(t, err, "Failed to decode backends response")

	backends, ok := result["backends"].([]interface{})
	if !ok {
		t.Fatal("Backends response missing backends array")
	}

	if len(backends) == 0 {
		t.Fatal("No backends available - server configuration error")
	}

	t.Logf("Found %d backend(s)", len(backends))
}

// TestRESTGenerateKey tests key generation via REST
func TestRESTGenerateKey(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := NewRESTClient(cfg.RESTBaseURL)
	keyID := generateUniqueID("rest-key")

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
				"backend":  "software",
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

			assertEqual(t, tt.wantCode, resp.StatusCode, "Unexpected status code - API endpoint should be available")

			if resp.StatusCode == http.StatusCreated {
				var result map[string]interface{}
				err = json.NewDecoder(resp.Body).Decode(&result)
				assertNoError(t, err, "Failed to decode generate key response")

				returnedKeyID, ok := result["key_id"].(string)
				if !ok {
					t.Fatal("Response missing key_id field")
				}

				assertEqual(t, testKeyID, returnedKeyID, "Key ID mismatch")

				if tt.keyType != "ed25519" && tt.keyType != "symmetric" {
					pubKey, ok := result["public_key_pem"].(string)
					if !ok || pubKey == "" {
						t.Fatal("Response missing public_key_pem")
					}
				}

				t.Logf("Generated %s key: %s", tt.keyType, testKeyID)

				// Cleanup
				defer func() {
					delResp, _ := client.doRequest("DELETE", fmt.Sprintf("/api/v1/keys/%s?backend=software", testKeyID), nil)
					if delResp != nil {
						delResp.Body.Close()
					}
				}()
			}
		})
	}
}

// TestRESTListKeys tests listing keys via REST
func TestRESTListKeys(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := NewRESTClient(cfg.RESTBaseURL)
	keyID := generateUniqueID("rest-list-key")

	// Create a test key first
	reqBody := map[string]interface{}{
		"key_id":   keyID,
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	}

	resp, err := client.doRequest("POST", "/api/v1/keys", reqBody)
	assertNoError(t, err, "Failed to create test key")
	assertEqual(t, http.StatusCreated, resp.StatusCode, "API endpoint should be available")
	resp.Body.Close()

	defer func() {
		delResp, _ := client.doRequest("DELETE", fmt.Sprintf("/api/v1/keys/%s?backend=software", keyID), nil)
		if delResp != nil {
			delResp.Body.Close()
		}
	}()

	// List keys
	resp, err = client.doRequest("GET", "/api/v1/keys?backend=software", nil)
	assertNoError(t, err, "List keys request failed")
	defer resp.Body.Close()

	assertEqual(t, http.StatusOK, resp.StatusCode, "API endpoint /api/v1/keys should be available")

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

	t.Logf("Listed %d key(s), found test key", len(keys))
}

// TestRESTSignVerify tests sign and verify operations via REST
func TestRESTSignVerify(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := NewRESTClient(cfg.RESTBaseURL)
	keyID := generateUniqueID("rest-sign-key")

	// Create a test key
	reqBody := map[string]interface{}{
		"key_id":   keyID,
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	}

	resp, err := client.doRequest("POST", "/api/v1/keys", reqBody)
	assertNoError(t, err, "Failed to create test key")
	resp.Body.Close()

	defer func() {
		delResp, _ := client.doRequest("DELETE", fmt.Sprintf("/api/v1/keys/%s?backend=software", keyID), nil)
		if delResp != nil {
			delResp.Body.Close()
		}
	}()

	testData := []byte("test data for signing")

	// Sign data
	signReq := map[string]interface{}{
		"data": testData,
		"hash": "SHA256",
	}

	resp, err = client.doRequest("POST", fmt.Sprintf("/api/v1/keys/%s/sign?backend=software", keyID), signReq)
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

	t.Logf("Signed data successfully")

	// Verify signature
	verifyReq := map[string]interface{}{
		"data":      testData,
		"signature": signature,
		"hash":      "SHA256",
	}

	resp, err = client.doRequest("POST", fmt.Sprintf("/api/v1/keys/%s/verify?backend=software", keyID), verifyReq)
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

	t.Logf("Verified signature successfully")
}

// TestRESTDeleteKey tests key deletion via REST
func TestRESTDeleteKey(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := NewRESTClient(cfg.RESTBaseURL)
	keyID := generateUniqueID("rest-delete-key")

	// Create a test key
	reqBody := map[string]interface{}{
		"key_id":   keyID,
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	}

	resp, err := client.doRequest("POST", "/api/v1/keys", reqBody)
	assertNoError(t, err, "Failed to create test key")
	resp.Body.Close()

	// Delete the key
	resp, err = client.doRequest("DELETE", fmt.Sprintf("/api/v1/keys/%s?backend=software", keyID), nil)
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

	t.Logf("Deleted key successfully")

	// Verify key is gone
	resp, err = client.doRequest("GET", fmt.Sprintf("/api/v1/keys/%s?backend=software", keyID), nil)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("Key still exists after deletion")
		}
	}
}

// TestRESTErrorHandling tests error handling in REST API
func TestRESTErrorHandling(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client := NewRESTClient(cfg.RESTBaseURL)

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
			path:     "/api/v1/keys/non-existent-key?backend=software",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Delete non-existent key",
			method:   "DELETE",
			path:     "/api/v1/keys/non-existent-key?backend=software",
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
		})
	}
}
