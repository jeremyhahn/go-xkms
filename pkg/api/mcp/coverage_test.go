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

package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandler_UnwrapKey tests the unwrap key handler
func TestHandler_UnwrapKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unwrapKey",
			Params:  json.RawMessage(`invalid json`),
			ID:      1,
		}

		_, err := server.handleUnwrapKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with missing wrapped_key", func(t *testing.T) {
		params := UnwrapKeyParams{
			WrappingPublicKey: "some-key",
			Algorithm:         "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wrapped_key is required")
	})

	t.Run("fails with missing wrapping_public_key", func(t *testing.T) {
		params := UnwrapKeyParams{
			WrappedKey: []byte("some-wrapped-data"),
			Algorithm:  "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wrapping_public_key is required")
	})

	t.Run("fails with missing algorithm", func(t *testing.T) {
		params := UnwrapKeyParams{
			WrappedKey:        []byte("some-wrapped-data"),
			WrappingPublicKey: "some-key",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm is required")
	})

	t.Run("fails with invalid wrapping public key PEM", func(t *testing.T) {
		params := UnwrapKeyParams{
			WrappedKey:        []byte("some-wrapped-data"),
			WrappingPublicKey: "not a valid PEM",
			Algorithm:         "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid wrapping public key PEM")
	})

	t.Run("fails with malformed public key", func(t *testing.T) {
		// Create a valid PEM but with invalid key data
		invalidPEM := "-----BEGIN PUBLIC KEY-----\naW52YWxpZCBrZXkgZGF0YQ==\n-----END PUBLIC KEY-----"

		params := UnwrapKeyParams{
			WrappedKey:        []byte("some-wrapped-data"),
			WrappingPublicKey: invalidPEM,
			Algorithm:         "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse wrapping public key")
	})

	t.Run("fails with valid public key but unwrap error", func(t *testing.T) {
		// Generate a valid RSA key
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		require.NoError(t, err)

		pubKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})

		params := UnwrapKeyParams{
			WrappedKey:        []byte("invalid-wrapped-data"),
			WrappingPublicKey: string(pubKeyPEM),
			Algorithm:         "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleUnwrapKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unwrap key")
	})
}

// TestHandler_ListKeyVersions tests the list key versions handler
func TestHandler_ListKeyVersions(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listKeyVersions",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleListKeyVersions(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := ListKeyVersionsParams{
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listKeyVersions",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleListKeyVersions(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("returns versioning not supported error", func(t *testing.T) {
		params := ListKeyVersionsParams{
			KeyID:   "test-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listKeyVersions",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleListKeyVersions(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrVersioningNotSupported)
	})
}

// TestHandler_EnableKeyVersion tests the enable key version handler
func TestHandler_EnableKeyVersion(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.enableKeyVersion",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleEnableKeyVersion(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := EnableKeyVersionParams{
			Version: 1,
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.enableKeyVersion",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEnableKeyVersion(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid version", func(t *testing.T) {
		params := EnableKeyVersionParams{
			KeyID:   "test-key",
			Version: 0, // Invalid version
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.enableKeyVersion",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEnableKeyVersion(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version must be a positive integer")
	})

	t.Run("fails with negative version", func(t *testing.T) {
		params := EnableKeyVersionParams{
			KeyID:   "test-key",
			Version: -1, // Negative version
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.enableKeyVersion",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEnableKeyVersion(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version must be a positive integer")
	})

	t.Run("returns versioning not supported error", func(t *testing.T) {
		params := EnableKeyVersionParams{
			KeyID:   "test-key",
			Version: 1,
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.enableKeyVersion",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEnableKeyVersion(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrVersioningNotSupported)
	})
}

// TestHandler_DisableKeyVersion tests the disable key version handler
func TestHandler_DisableKeyVersion(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.disableKeyVersion",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleDisableKeyVersion(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := DisableKeyVersionParams{
			Version: 1,
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.disableKeyVersion",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDisableKeyVersion(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid version", func(t *testing.T) {
		params := DisableKeyVersionParams{
			KeyID:   "test-key",
			Version: 0,
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.disableKeyVersion",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDisableKeyVersion(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version must be a positive integer")
	})

	t.Run("returns versioning not supported error", func(t *testing.T) {
		params := DisableKeyVersionParams{
			KeyID:   "test-key",
			Version: 1,
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.disableKeyVersion",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDisableKeyVersion(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrVersioningNotSupported)
	})
}

// TestHandler_EnableAllKeyVersions tests the enable all key versions handler
func TestHandler_EnableAllKeyVersions(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.enableAllKeyVersions",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleEnableAllKeyVersions(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := EnableAllKeyVersionsParams{
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.enableAllKeyVersions",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEnableAllKeyVersions(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("returns versioning not supported error", func(t *testing.T) {
		params := EnableAllKeyVersionsParams{
			KeyID:   "test-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.enableAllKeyVersions",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEnableAllKeyVersions(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrVersioningNotSupported)
	})
}

// TestHandler_DisableAllKeyVersions tests the disable all key versions handler
func TestHandler_DisableAllKeyVersions(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.disableAllKeyVersions",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleDisableAllKeyVersions(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := DisableAllKeyVersionsParams{
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.disableAllKeyVersions",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDisableAllKeyVersions(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("returns versioning not supported error", func(t *testing.T) {
		params := DisableAllKeyVersionsParams{
			KeyID:   "test-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.disableAllKeyVersions",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDisableAllKeyVersions(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrVersioningNotSupported)
	})
}

// TestServer_SendError tests the sendError method
func TestServer_SendError(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	t.Run("sends error response", func(t *testing.T) {
		// Create a pipe to simulate connection
		clientConn, serverConn := net.Pipe()
		defer func() { _ = clientConn.Close() }()
		defer func() { _ = serverConn.Close() }()

		// Start reading on client side
		done := make(chan struct{})
		var receivedData []byte
		go func() {
			defer close(done)
			scanner := bufio.NewScanner(clientConn)
			if scanner.Scan() {
				receivedData = scanner.Bytes()
			}
		}()

		// Send error through the server connection
		encoder := json.NewEncoder(serverConn)
		server.sendError(encoder, 1, ErrCodeInvalidParams, "test error", map[string]string{"detail": "extra info"})

		// Wait for response
		select {
		case <-done:
			var response JSONRPCResponse
			err := json.Unmarshal(receivedData, &response)
			require.NoError(t, err)
			assert.Equal(t, "2.0", response.JSONRPC)
			assert.Equal(t, float64(1), response.ID)
			require.NotNil(t, response.Error)
			assert.Equal(t, ErrCodeInvalidParams, response.Error.Code)
			assert.Equal(t, "test error", response.Error.Message)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Timeout waiting for error response")
		}
	})

	t.Run("sends error with nil ID", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer func() { _ = clientConn.Close() }()
		defer func() { _ = serverConn.Close() }()

		done := make(chan struct{})
		var receivedData []byte
		go func() {
			defer close(done)
			scanner := bufio.NewScanner(clientConn)
			if scanner.Scan() {
				receivedData = scanner.Bytes()
			}
		}()

		encoder := json.NewEncoder(serverConn)
		server.sendError(encoder, nil, ErrCodeParseError, "parse error", nil)

		select {
		case <-done:
			var response JSONRPCResponse
			err := json.Unmarshal(receivedData, &response)
			require.NoError(t, err)
			assert.Nil(t, response.ID)
			require.NotNil(t, response.Error)
			assert.Equal(t, ErrCodeParseError, response.Error.Code)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Timeout waiting for error response")
		}
	})

	t.Run("handles closed connection gracefully", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		_ = clientConn.Close()
		_ = serverConn.Close()

		encoder := json.NewEncoder(serverConn)
		// Should not panic
		server.sendError(encoder, 1, ErrCodeInternalError, "error", nil)
	})
}

// TestServer_HandleRequest_VersioningMethods tests version method routing
func TestServer_HandleRequest_VersioningMethods(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("routes keychain.listKeyVersions", func(t *testing.T) {
		params := ListKeyVersionsParams{KeyID: "test-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listKeyVersions",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error) // Should fail with versioning not supported
	})

	t.Run("routes keychain.enableKeyVersion", func(t *testing.T) {
		params := EnableKeyVersionParams{KeyID: "test-key", Version: 1}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.enableKeyVersion",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})

	t.Run("routes keychain.disableKeyVersion", func(t *testing.T) {
		params := DisableKeyVersionParams{KeyID: "test-key", Version: 1}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.disableKeyVersion",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})

	t.Run("routes keychain.enableAllKeyVersions", func(t *testing.T) {
		params := EnableAllKeyVersionsParams{KeyID: "test-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.enableAllKeyVersions",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})

	t.Run("routes keychain.disableAllKeyVersions", func(t *testing.T) {
		params := DisableAllKeyVersionsParams{KeyID: "test-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.disableAllKeyVersions",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})

	t.Run("routes keychain.unwrapKey", func(t *testing.T) {
		params := UnwrapKeyParams{
			WrappedKey:        []byte("data"),
			WrappingPublicKey: "key",
			Algorithm:         "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})
}

// TestServer_HandleConnection_RateLimit tests connection handling when rate limited
func TestServer_HandleConnection_RateLimit(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	// Create a rate limiter that will block all connections
	limiter := ratelimit.New(&ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 0,
		Burst:             0,
	})
	defer limiter.Stop()

	config := &Config{
		Addr:        "localhost:0",
		RateLimiter: limiter,
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() { _ = server.Stop() }()

	// Try to connect - should be rejected due to rate limit
	conn, err := net.Dial("tcp", server.listener.Addr().String())
	if err == nil {
		// Connection was accepted but should be closed immediately
		defer func() { _ = conn.Close() }()

		// Try to send data - connection might be closed
		request := JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "health",
			ID:      1,
		}
		requestBytes, _ := json.Marshal(request)
		_, writeErr := conn.Write(append(requestBytes, '\n'))
		// Either write fails or read times out
		if writeErr == nil {
			// Set short deadline
			_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			buf := make([]byte, 1024)
			_, readErr := conn.Read(buf)
			// Connection should be closed or timed out
			_ = readErr // Expected to fail
		}
	}
}

// TestHandler_GetTLSCertificate_InvalidBackend tests the getTLSCertificate handler with invalid backend
func TestHandler_GetTLSCertificate_InvalidBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := GetTLSCertificateParams{
			KeyID:   "test-key",
			Backend: "nonexistent",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getTLSCertificate",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetTLSCertificate(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})
}

// TestHandler_RotateKey_InvalidBackend tests the rotateKey handler with invalid backend
func TestHandler_RotateKey_InvalidBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key first
	genParams := GenerateKeyParams{
		KeyID:   "test-rotate-invalid-backend",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := RotateKeyParams{
			KeyID:   "test-rotate-invalid-backend",
			Backend: "nonexistent",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.rotateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleRotateKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})
}

// TestHandler_AsymmetricEncrypt_InvalidBackend tests the asymmetricEncrypt handler with invalid backend
func TestHandler_AsymmetricEncrypt_InvalidBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key first
	genParams := GenerateKeyParams{
		KeyID:   "test-asym-enc-invalid-backend",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := AsymmetricEncryptParams{
			KeyID:     "test-asym-enc-invalid-backend",
			Backend:   "nonexistent",
			Plaintext: []byte("secret"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.asymmetricEncrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleAsymmetricEncrypt(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})
}

// TestHandler_AsymmetricDecrypt_InvalidBackend tests the asymmetricDecrypt handler with invalid backend
func TestHandler_AsymmetricDecrypt_InvalidBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key first
	genParams := GenerateKeyParams{
		KeyID:   "test-asym-dec-invalid-backend",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := AsymmetricDecryptParams{
			KeyID:      "test-asym-dec-invalid-backend",
			Backend:    "nonexistent",
			Ciphertext: []byte("ciphertext"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.asymmetricDecrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleAsymmetricDecrypt(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})
}

// TestHandler_CopyKey_AdditionalErrors tests additional error paths in copyKey handler
func TestHandler_CopyKey_AdditionalErrors(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid source backend type", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "unknown-backend-type",
			SourceKeyID:   "test-key",
			DestBackend:   "software",
			DestKeyID:     "dest-key",
			Algorithm:     "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "source backend not found")
	})

	t.Run("fails with invalid dest backend type", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			SourceKeyID:   "test-key",
			DestBackend:   "unknown-backend-type",
			DestKeyID:     "dest-key",
			Algorithm:     "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "destination backend not found")
	})
}

// TestHandler_SaveCertChain_InvalidPEM tests additional error paths in saveCertChain handler
func TestHandler_SaveCertChain_InvalidPEM(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid PEM at middle index", func(t *testing.T) {
		// Generate a valid certificate
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "test-chain-cert"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
		require.NoError(t, err)

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})

		params := SaveCertChainParams{
			KeyID:     "test-chain-invalid-middle",
			ChainPEMs: []string{string(certPEM), "invalid-pem", string(certPEM)},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleSaveCertChain(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid certificate PEM at index 1")
	})

	t.Run("fails with malformed certificate data", func(t *testing.T) {
		// Create a PEM with invalid certificate data
		invalidCertPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not a valid certificate"),
		})

		params := SaveCertChainParams{
			KeyID:     "test-chain-malformed",
			ChainPEMs: []string{string(invalidCertPEM)},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCertChain(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse certificate at index 0")
	})
}

// TestHandler_ListCerts_EmptyResult tests the listCerts handler with empty result
func TestHandler_ListCerts_EmptyResult(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("returns empty list when no certs exist", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listCerts",
			ID:      1,
		}

		result, err := server.handleListCerts(req)
		require.NoError(t, err)

		listResult, ok := result.(ListCertsResult)
		require.True(t, ok)
		assert.NotNil(t, listResult.KeyIDs)
	})
}

// TestHandler_DeleteKey_SearchSymmetricBackend tests deleteKey searching symmetric backend
func TestHandler_DeleteKey_SearchSymmetricBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a symmetric key
	genParams := GenerateKeyParams{
		KeyID:     "test-delete-sym-search",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("deletes key from symmetric backend without specifying backend", func(t *testing.T) {
		params := DeleteKeyParams{
			KeyID: "test-delete-sym-search",
			// No backend specified - should search
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleDeleteKey(req)
		require.NoError(t, err)

		deleteResult, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.True(t, deleteResult["success"].(bool))
	})
}

// TestHandler_Decrypt_SearchSymmetricBackend tests decrypt searching symmetric backend
func TestHandler_Decrypt_SearchSymmetricBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a symmetric key and encrypt data
	genParams := GenerateKeyParams{
		KeyID:     "test-decrypt-sym-search",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Encrypt data
	encryptParams := EncryptParams{
		KeyID:     "test-decrypt-sym-search",
		Backend:   "software",
		Plaintext: []byte("secret data"),
	}
	encryptParamsJSON, _ := json.Marshal(encryptParams)
	encryptReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.encrypt", Params: encryptParamsJSON, ID: 1}
	encryptResult, err := server.handleEncrypt(encryptReq)
	require.NoError(t, err)

	encResult := encryptResult.(EncryptResult)

	t.Run("decrypts without specifying backend - searches backends", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "test-decrypt-sym-search",
			Ciphertext: encResult.Ciphertext,
			Nonce:      encResult.Nonce,
			Tag:        encResult.Tag,
			// No backend specified - should search
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.decrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleDecrypt(req)
		require.NoError(t, err)

		decResult, ok := result.(DecryptResult)
		require.True(t, ok)
		assert.Equal(t, []byte("secret data"), decResult.Plaintext)
	})
}

// TestHandler_Decrypt_NotFoundInAnyBackend tests decrypt when key not found in any backend
func TestHandler_Decrypt_NotFoundInAnyBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails when key not found in any backend", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "non-existent-key-for-decrypt",
			Ciphertext: []byte("some ciphertext"),
			Nonce:      []byte("some nonce"),
			// No backend specified
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.decrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDecrypt(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find key")
	})
}
