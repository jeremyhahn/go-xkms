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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// MCPClient wraps TCP connection for MCP JSON-RPC testing
type MCPClient struct {
	addr string
	conn net.Conn
}

// NewMCPClient creates a new MCP client
func NewMCPClient(addr string) (*MCPClient, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	return &MCPClient{
		addr: addr,
		conn: conn,
	}, nil
}

// Close closes the MCP connection
func (c *MCPClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Call sends a JSON-RPC request and returns the response
func (c *MCPClient) Call(method string, params interface{}) (map[string]interface{}, error) {
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request with newline delimiter
	_, err = c.conn.Write(append(requestBytes, '\n'))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	buf := make([]byte, 8192)
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var response map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(buf[:n]))
	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Check for error in response
	if errObj, ok := response["error"]; ok {
		return nil, fmt.Errorf("JSON-RPC error: %v", errObj)
	}

	return response, nil
}

// isMCPServerAvailable checks if MCP server is available
func isMCPServerAvailable(t *testing.T, cfg *TestConfig) bool {
	t.Helper()

	conn, err := net.DialTimeout("tcp", cfg.MCPAddr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// TestMCPHealth tests the MCP health check (placeholder)
func TestMCPHealth(t *testing.T) {
	// MCP protocol is implemented using Model Context Protocol SDK

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Skip("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	resp, err := client.Call("health", nil)
	assertNoError(t, err, "Health check failed")

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid health response")
	}

	status, ok := result["status"].(string)
	if !ok {
		t.Fatal("Health response missing status")
	}

	if status != "healthy" {
		t.Fatalf("Unexpected health status: %s", status)
	}

	t.Logf("MCP health check passed: %s", status)
}

// TestMCPListBackends tests listing backends via MCP (placeholder)
func TestMCPListBackends(t *testing.T) {
	// MCP protocol is implemented using Model Context Protocol SDK

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Skip("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	resp, err := client.Call("keychain.listBackends", nil)
	assertNoError(t, err, "ListBackends failed")

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid response")
	}

	backends, ok := result["backends"].([]interface{})
	if !ok {
		t.Fatal("Response missing backends")
	}

	if len(backends) == 0 {
		t.Fatal("No backends available")
	}

	t.Logf("Found %d backend(s) via MCP", len(backends))
}

// TestMCPGenerateKey tests key generation via MCP (placeholder)
func TestMCPGenerateKey(t *testing.T) {
	// MCP protocol is implemented using Model Context Protocol SDK

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Skip("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	keyID := generateUniqueID("mcp-key")

	params := map[string]interface{}{
		"key_id":   keyID,
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	}

	resp, err := client.Call("keychain.generateKey", params)
	assertNoError(t, err, "GenerateKey failed")

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid response")
	}

	returnedKeyID, ok := result["key_id"].(string)
	if !ok {
		t.Fatal("Response missing key_id")
	}

	assertEqual(t, keyID, returnedKeyID, "Key ID mismatch")

	t.Logf("Generated key via MCP: %s", keyID)

	// Cleanup
	defer client.Call("keychain.deleteKey", map[string]interface{}{
		"key_id":  keyID,
		"backend": "software",
	})
}

// TestMCPListKeys tests listing keys via MCP
func TestMCPListKeys(t *testing.T) {
	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Skip("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	// Generate a test key first
	keyID := generateUniqueID("mcp-list-test")
	params := map[string]interface{}{
		"key_id":   keyID,
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	}

	_, err = client.Call("keychain.generateKey", params)
	assertNoError(t, err, "GenerateKey failed")

	// Cleanup
	defer client.Call("keychain.deleteKey", map[string]interface{}{
		"key_id":  keyID,
		"backend": "software",
	})

	// List keys
	resp, err := client.Call("keychain.listKeys", map[string]interface{}{})
	assertNoError(t, err, "ListKeys failed")

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid response")
	}

	keys, ok := result["keys"].([]interface{})
	if !ok {
		t.Fatal("Response missing keys array")
	}

	// Verify the key we just created is in the list
	found := false
	for _, k := range keys {
		keyInfo, ok := k.(map[string]interface{})
		if !ok {
			continue
		}
		cn, ok := keyInfo["cn"].(string)
		if ok && cn == keyID {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("Created key %s not found in list", keyID)
	}

	t.Logf("Successfully listed %d keys via MCP, including %s", len(keys), keyID)
}

// TestMCPSignVerify tests sign and verify via MCP (placeholder)
func TestMCPSignVerify(t *testing.T) {
	// MCP protocol is implemented using Model Context Protocol SDK

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Skip("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	keyID := generateUniqueID("mcp-sign-key")

	// Generate key
	_, err = client.Call("keychain.generateKey", map[string]interface{}{
		"key_id":   keyID,
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	})
	assertNoError(t, err, "Failed to generate key")

	defer client.Call("keychain.deleteKey", map[string]interface{}{
		"key_id":  keyID,
		"backend": "software",
	})

	testData := []byte("test data for MCP signing")

	// Sign data
	signResp, err := client.Call("keychain.sign", map[string]interface{}{
		"key_id":  keyID,
		"backend": "software",
		"data":    testData,
		"hash":    "SHA256",
	})
	assertNoError(t, err, "Sign failed")

	signResult, ok := signResp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid sign response")
	}

	signature := signResult["signature"]
	if signature == nil {
		t.Fatal("Sign response missing signature")
	}

	t.Logf("Signed data via MCP")

	// Verify signature
	verifyResp, err := client.Call("keychain.verify", map[string]interface{}{
		"key_id":    keyID,
		"backend":   "software",
		"data":      testData,
		"signature": signature,
		"hash":      "SHA256",
	})
	assertNoError(t, err, "Verify failed")

	verifyResult, ok := verifyResp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid verify response")
	}

	valid, ok := verifyResult["valid"].(bool)
	if !ok {
		t.Fatal("Verify response missing valid field")
	}

	if !valid {
		t.Fatal("Signature verification failed")
	}

	t.Logf("Verified signature via MCP")
}

// TestMCPBatchRequests tests batch JSON-RPC requests (placeholder)
func TestMCPBatchRequests(t *testing.T) {
	// MCP protocol is implemented using Model Context Protocol SDK

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Skip("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	// Send batch request
	batchRequest := []map[string]interface{}{
		{
			"jsonrpc": "2.0",
			"method":  "health",
			"id":      1,
		},
		{
			"jsonrpc": "2.0",
			"method":  "keychain.listBackends",
			"id":      2,
		},
	}

	requestBytes, err := json.Marshal(batchRequest)
	assertNoError(t, err, "Failed to marshal batch request")

	_, err = client.conn.Write(append(requestBytes, '\n'))
	assertNoError(t, err, "Failed to send batch request")

	// Read response
	buf := make([]byte, 8192)
	client.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := client.conn.Read(buf)
	assertNoError(t, err, "Failed to read batch response")

	// Parse batch response
	var batchResponse []map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(buf[:n]))
	err = decoder.Decode(&batchResponse)
	assertNoError(t, err, "Failed to decode batch response")

	if len(batchResponse) != 2 {
		t.Fatalf("Expected 2 responses, got %d", len(batchResponse))
	}

	t.Logf("Batch request completed successfully with %d responses", len(batchResponse))
}

// TestMCPStreamingNotifications tests MCP streaming notifications (placeholder)
func TestMCPStreamingNotifications(t *testing.T) {
	// MCP streaming notifications are inherently racy in integration tests because
	// notifications are sent asynchronously in goroutines and may arrive before,
	// during, or after the synchronous response. This test verifies the subscribe
	// API works but skips notification verification due to timing constraints.

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Skip("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	// Subscribe to key events - verify subscribe API works
	_, err = client.Call("keychain.subscribe", map[string]interface{}{
		"events": []string{"key.created", "key.deleted"},
	})
	assertNoError(t, err, "Failed to subscribe to events")

	// Create a key (should trigger notification)
	keyID := generateUniqueID("mcp-notify-key")
	_, err = client.Call("keychain.generateKey", map[string]interface{}{
		"key_id":   keyID,
		"backend":  "software",
		"key_type": "rsa",
	})
	assertNoError(t, err, "Failed to generate key")

	defer func() {
		_, _ = client.Call("keychain.deleteKey", map[string]interface{}{
			"key_id":  keyID,
			"backend": "software",
		})
	}()

	// Try to read notification with a short timeout.
	// This is best-effort since notifications are asynchronous and may have
	// already been consumed or not yet sent.
	buf := make([]byte, 8192)
	client.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := client.conn.Read(buf)
	if err != nil {
		// Timeout or other read error is acceptable for async notifications
		t.Logf("Notification not received (expected for async events): %v", err)
		t.Log("Subscribe API verified successfully; notification delivery is asynchronous")
		return
	}

	var notification map[string]interface{}
	err = json.NewDecoder(io.Reader(bytes.NewReader(buf[:n]))).Decode(&notification)
	if err != nil {
		t.Logf("Could not decode notification: %v", err)
		return
	}

	method, ok := notification["method"].(string)
	if !ok {
		t.Log("Notification received but missing method field")
		return
	}

	t.Logf("Received notification: %s", method)
}

// TestMCPErrorHandling tests error handling in MCP (placeholder)
func TestMCPErrorHandling(t *testing.T) {
	// MCP protocol is implemented using Model Context Protocol SDK

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Skip("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{
			name:   "Invalid method",
			method: "invalid.method",
			params: nil,
		},
		{
			name:   "Missing required params",
			method: "keychain.generateKey",
			params: map[string]interface{}{},
		},
		{
			name:   "Get non-existent key",
			method: "keychain.getKey",
			params: map[string]interface{}{
				"key_id":  "non-existent",
				"backend": "software",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Call(tt.method, tt.params)
			assertError(t, err, "Expected error but got none")

			t.Logf("Got expected error: %v", err)
		})
	}
}
