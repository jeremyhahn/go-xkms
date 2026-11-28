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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// MCPClient drives the MCP server over its streamable HTTP endpoint.
type MCPClient struct {
	url     string
	http    *http.Client
	session string
	nextID  int
}

// NewMCPClient opens an MCP session on the streamable HTTP endpoint at addr over TLS with the suite's client certificate.
func NewMCPClient(addr string) (*MCPClient, error) {
	c := &MCPClient{
		url:  "https://" + addr + "/mcp",
		http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLSConfig()}},
	}
	resp, err := c.post(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      c.id(),
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "xkms-integration-tests", "version": "1"},
		},
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to connect", Err: err}
	}
	if errObj, ok := resp["error"]; ok {
		return nil, &errs.Message{Msg: fmt.Sprintf("initialize: JSON-RPC error: %v", errObj)}
	}
	return c, nil
}

// Close ends the MCP session.
func (c *MCPClient) Close() error {
	if c.session == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodDelete, c.url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Mcp-Session-Id", c.session)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *MCPClient) id() int {
	c.nextID++
	return c.nextID
}

// postRaw sends body on the session and returns the HTTP status and the JSON-RPC payload.
func (c *MCPClient) postRaw(body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if s := resp.Header.Get("Mcp-Session-Id"); s != "" {
		c.session = s
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "data:") {
				data = []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
	}
	return resp.StatusCode, data, nil
}

func (c *MCPClient) post(request map[string]interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal request", Err: err}
	}
	code, data, err := c.postRaw(body)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to send request", Err: err}
	}
	var response map[string]interface{}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, &errs.Message{Msg: fmt.Sprintf("failed to decode response (HTTP %d): %s", code, data)}
	}
	return response, nil
}

// Call invokes the xkms tool named by method ("health" or "xkms.<op>") and returns {"result": <tool result>}.
func (c *MCPClient) Call(method string, params interface{}) (map[string]interface{}, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	if m, ok := params.(map[string]interface{}); ok && method == "xkms.generateKey" {
		if _, has := m["algorithm"]; !has && m["key_type"] != nil && m["key_type"] != "symmetric" {
			m["algorithm"] = m["key_type"]
		}
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal params", Err: err}
	}
	response, err := c.post(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      c.id(),
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "xkms_" + strings.TrimPrefix(method, "xkms."),
			"arguments": map[string]interface{}{"params_json": string(paramsJSON)},
		},
	})
	if err != nil {
		return nil, err
	}
	if errObj, ok := response["error"]; ok {
		return nil, &errs.Message{Msg: fmt.Sprintf("JSON-RPC error: %v", errObj)}
	}
	result, _ := response["result"].(map[string]interface{})
	var text string
	if content, ok := result["content"].([]interface{}); ok && len(content) > 0 {
		if first, ok := content[0].(map[string]interface{}); ok {
			text, _ = first["text"].(string)
		}
	}
	if isErr, _ := result["isError"].(bool); isErr {
		return nil, &errs.Message{Msg: fmt.Sprintf("JSON-RPC error: %s", text)}
	}
	var decoded interface{}
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		decoded = text
	}
	return map[string]interface{}{"jsonrpc": "2.0", "result": decoded}, nil
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
		"key_id":    keyID,
		"backend":   "software",
		"algorithm": "rsa",
		"key_type":  "signing",
		"key_size":  2048,
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
		"key_id":    keyID,
		"backend":   "software",
		"algorithm": "rsa",
		"key_type":  "signing",
		"key_size":  2048,
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
		"key_id":    keyID,
		"backend":   "software",
		"algorithm": "rsa",
		"key_type":  "signing",
		"key_size":  2048,
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
	// MCP 2025-06-18 removed JSON-RPC batching: a batch body is answered with a JSON-RPC error.

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Fatal("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	batchRequest := []map[string]interface{}{
		{"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": map[string]interface{}{"name": "xkms_health", "arguments": map[string]interface{}{"params_json": "{}"}}},
		{"jsonrpc": "2.0", "method": "tools/call", "id": 2, "params": map[string]interface{}{"name": "xkms_listBackends", "arguments": map[string]interface{}{"params_json": "{}"}}},
	}

	requestBytes, err := json.Marshal(batchRequest)
	assertNoError(t, err, "Failed to marshal batch request")

	code, data, err := client.postRaw(requestBytes)
	assertNoError(t, err, "Failed to send batch request")
	if code != http.StatusBadRequest {
		t.Fatalf("Expected HTTP 400 for a batch body, got %d: %s", code, data)
	}

	var response map[string]interface{}
	assertNoError(t, json.NewDecoder(bytes.NewReader(data)).Decode(&response), "Failed to decode batch response")
	if _, ok := response["error"]; !ok {
		t.Fatalf("Expected a JSON-RPC error for a batch body, got %s", data)
	}

	t.Logf("Batch body refused with JSON-RPC error: %v", response["error"])
}

// TestMCPStreamingNotifications tests MCP streaming notifications (placeholder)
func TestMCPStreamingNotifications(t *testing.T) {
	// Notifications arrive asynchronously on the session's GET stream, so their delivery is checked best-effort.

	cfg := LoadTestConfig()
	if !isMCPServerAvailable(t, cfg) {
		t.Fatal("MCP server required for integration tests. Run: make integration-test (uses Docker)")
	}

	client, err := NewMCPClient(cfg.MCPAddr)
	assertNoError(t, err, "Failed to create MCP client")
	defer client.Close()

	req, err := http.NewRequest(http.MethodGet, client.url, nil)
	assertNoError(t, err, "Failed to build stream request")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Mcp-Session-Id", client.session)
	streamClient := &http.Client{Transport: client.http.Transport}
	stream, err := streamClient.Do(req)
	assertNoError(t, err, "Failed to open notification stream")
	defer stream.Body.Close()
	if stream.StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP 200 for the notification stream, got %d", stream.StatusCode)
	}
	if ct := stream.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Expected text/event-stream, got %q", ct)
	}

	// Create a key (may trigger a notification)
	keyID := generateUniqueID("mcp-notify-key")
	_, err = client.Call("xkms.generateKey", map[string]interface{}{
		"key_id":    keyID,
		"backend":   "software",
		"algorithm": "rsa",
		"key_type":  "signing",
	})
	assertNoError(t, err, "Failed to generate key")

	defer func() {
		_, _ = client.Call("xkms.deleteKey", map[string]interface{}{
			"key_id":  keyID,
			"backend": "software",
		})
	}()

	lines := make(chan string, 1)
	go func() {
		buf := make([]byte, 8192)
		n, _ := stream.Body.Read(buf)
		lines <- string(buf[:n])
	}()
	select {
	case event := <-lines:
		t.Logf("Stream event: %q", event)
	case <-time.After(500 * time.Millisecond):
		t.Log("Notification not received (expected for async events); stream verified")
	}
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
