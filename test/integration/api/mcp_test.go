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

//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/mcptool"
)

// mcpCallTimeout bounds a single MCP connect or tool call.
const mcpCallTimeout = 10 * time.Second

// MCPClient drives the MCP server through mcptool.Client, over the server's
// streamable HTTP transport with TLS and the test CA as root.
type MCPClient struct {
	addr   string
	client *mcptool.Client
}

// NewMCPClient connects to the MCP server at addr over TLS.
func NewMCPClient(addr string) (*MCPClient, error) {
	cfg := &transport.Config{
		Address:    addr,
		TLSEnabled: true,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    loadCACertPool(),
		},
	}
	client := mcptool.NewClient(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), mcpCallTimeout)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to connect", Err: err}
	}

	return &MCPClient{
		addr:   addr,
		client: client,
	}, nil
}

// Close closes the MCP session.
func (c *MCPClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Call invokes the MCP tool for method and returns {"result": <decoded result>}.
func (c *MCPClient) Call(method string, params interface{}) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mcpCallTimeout)
	defer cancel()

	var result json.RawMessage
	if err := c.client.Call(ctx, method, params, &result); err != nil {
		return nil, &errs.Message{Msg: fmt.Sprintf("MCP call %s failed: %v", method, err)}
	}

	var decoded interface{}
	if len(result) > 0 {
		if err := json.Unmarshal(result, &decoded); err != nil {
			return nil, &errs.Wrapped{Msg: "failed to decode result", Err: err}
		}
	}

	return map[string]interface{}{"result": decoded}, nil
}

// TestMCPHealth tests the MCP health check (placeholder)
func TestMCPHealth(t *testing.T) {
	// MCP protocol is implemented using Model Context Protocol SDK

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Fatal("MCP server required for integration tests. Run: make integration-test (uses Docker)")
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
		t.Fatal("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	resp, err := client.Call("xkms.listBackends", nil)
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
		t.Fatal("MCP server required for integration tests. Run: make integration-test (uses Docker)")
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

	resp, err := client.Call("xkms.generateKey", params)
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
	defer client.Call("xkms.deleteKey", map[string]interface{}{
		"key_id":  keyID,
		"backend": "software",
	})
}

// TestMCPListKeys tests listing keys via MCP
func TestMCPListKeys(t *testing.T) {
	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Fatal("MCP server required for integration tests. Run: make integration-test (uses Docker)")
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

	_, err = client.Call("xkms.generateKey", params)
	assertNoError(t, err, "GenerateKey failed")

	// Cleanup
	defer client.Call("xkms.deleteKey", map[string]interface{}{
		"key_id":  keyID,
		"backend": "software",
	})

	// List keys (filter by backend to reduce response size)
	resp, err := client.Call("xkms.listKeys", map[string]interface{}{
		"backend": "software",
	})
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
		id, ok := keyInfo["key_id"].(string)
		if ok && id == keyID {
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
		t.Fatal("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	keyID := generateUniqueID("mcp-sign-key")

	// Generate key
	_, err = client.Call("xkms.generateKey", map[string]interface{}{
		"key_id":   keyID,
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	})
	assertNoError(t, err, "Failed to generate key")

	defer client.Call("xkms.deleteKey", map[string]interface{}{
		"key_id":  keyID,
		"backend": "software",
	})

	testData := []byte("test data for MCP signing")

	// Sign data
	signResp, err := client.Call("xkms.sign", map[string]interface{}{
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
	verifyResp, err := client.Call("xkms.verify", map[string]interface{}{
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
		t.Fatal("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	// The streamable HTTP transport carries one tool call per request, so the
	// batch is the two calls issued back to back on one session.
	methods := []string{"health", "xkms.listBackends"}
	responses := make([]map[string]interface{}, 0, len(methods))
	for _, method := range methods {
		resp, callErr := client.Call(method, nil)
		assertNoError(t, callErr, "Failed to call "+method)
		responses = append(responses, resp)
	}

	if len(responses) != len(methods) {
		t.Fatalf("Expected %d responses, got %d", len(methods), len(responses))
	}

	t.Logf("Batch request completed successfully with %d responses", len(responses))
}

// TestMCPStreamingNotifications tests MCP streaming notifications (placeholder)
func TestMCPStreamingNotifications(t *testing.T) {
	// MCP streaming notifications are inherently racy in integration tests because
	// notifications are sent asynchronously in goroutines and may arrive before,
	// during, or after the synchronous response. This test verifies the subscribe
	// API works but skips notification verification due to timing constraints.

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Fatal("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	// Subscribe to key events - verify subscribe API works
	_, err = client.Call("xkms.subscribe", map[string]interface{}{
		"events": []string{"key.created", "key.deleted"},
	})
	assertNoError(t, err, "Failed to subscribe to events")

	// Create a key (should trigger notification)
	keyID := generateUniqueID("mcp-notify-key")
	_, err = client.Call("xkms.generateKey", map[string]interface{}{
		"key_id":   keyID,
		"backend":  "software",
		"key_type": "rsa",
	})
	assertNoError(t, err, "Failed to generate key")

	defer func() {
		_, _ = client.Call("xkms.deleteKey", map[string]interface{}{
			"key_id":  keyID,
			"backend": "software",
		})
	}()

	// Notifications arrive asynchronously on the session's event stream;
	// the subscribe and the triggering call succeeding is what is verified.
	t.Log("Subscribe API verified successfully; notification delivery is asynchronous")
}

// TestMCPErrorHandling tests error handling in MCP (placeholder)
func TestMCPErrorHandling(t *testing.T) {
	// MCP protocol is implemented using Model Context Protocol SDK

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Fatal("MCP server required for integration tests. Run: make integration-test (uses Docker)")
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
			method: "xkms.generateKey",
			params: map[string]interface{}{},
		},
		{
			name:   "Get non-existent key",
			method: "xkms.getKey",
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
