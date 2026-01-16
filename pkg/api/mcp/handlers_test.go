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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestServer creates a server with initialized keychain for handler tests
func createTestServer(t *testing.T) *Server {
	t.Helper()

	setupTestKeychain(t)

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	return server
}

// TestHandler_Health tests the health check handler
func TestHandler_Health(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("returns healthy status", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "health",
			ID:      1,
		}

		result, err := server.handleHealth(req)
		require.NoError(t, err)

		healthResult, ok := result.(HealthResult)
		require.True(t, ok)
		assert.Equal(t, "healthy", healthResult.Status)
	})
}

// TestHandler_ListBackends tests the list backends handler
func TestHandler_ListBackends(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("returns available backends", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listBackends",
			ID:      1,
		}

		result, err := server.handleListBackends(req)
		require.NoError(t, err)

		backendResult, ok := result.(ListBackendsResult)
		require.True(t, ok)
		assert.NotEmpty(t, backendResult.Backends)
		assert.Contains(t, backendResult.Backends, "software")
	})
}

// TestHandler_GenerateKey tests the key generation handler
func TestHandler_GenerateKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("generates RSA key", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-rsa-key",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(req)
		require.NoError(t, err)

		genResult, ok := result.(GenerateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-rsa-key", genResult.KeyID)
		assert.NotEmpty(t, genResult.PublicKeyPEM)
		assert.Contains(t, genResult.PublicKeyPEM, "BEGIN PUBLIC KEY")
	})

	t.Run("generates ECDSA key", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-ecdsa-key",
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "P-256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(req)
		require.NoError(t, err)

		genResult, ok := result.(GenerateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-ecdsa-key", genResult.KeyID)
		assert.NotEmpty(t, genResult.PublicKeyPEM)
	})

	t.Run("generates Ed25519 key", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-ed25519-key",
			Backend: "software",
			KeyType: "ed25519",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(req)
		require.NoError(t, err)

		genResult, ok := result.(GenerateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-ed25519-key", genResult.KeyID)
		assert.NotEmpty(t, genResult.PublicKeyPEM)
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := GenerateKeyParams{
			Backend: "software",
			KeyType: "rsa",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGenerateKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  json.RawMessage(`invalid json`),
			ID:      1,
		}

		_, err := server.handleGenerateKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-key",
			Backend: "nonexistent",
			KeyType: "rsa",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGenerateKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})

	t.Run("fails with unsupported key type", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-key",
			Backend: "software",
			KeyType: "unsupported",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGenerateKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key type")
	})

	t.Run("generates key with default backend", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-default-backend-key",
			KeyType: "rsa",
			KeySize: 2048,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(req)
		require.NoError(t, err)

		genResult, ok := result.(GenerateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-default-backend-key", genResult.KeyID)
	})

	t.Run("generates ECDSA key with default curve", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-ecdsa-default-curve",
			Backend: "software",
			KeyType: "ecdsa",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(req)
		require.NoError(t, err)

		genResult, ok := result.(GenerateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-ecdsa-default-curve", genResult.KeyID)
	})

	t.Run("fails with invalid curve", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-invalid-curve",
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "invalid-curve",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGenerateKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid curve")
	})
}

// TestHandler_GetKey tests the get key handler
func TestHandler_GetKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// First generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-get-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("gets existing key", func(t *testing.T) {
		params := GetKeyParams{
			KeyID:   "test-get-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetKey(req)
		require.NoError(t, err)

		getResult, ok := result.(GetKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-get-key", getResult.KeyID)
		assert.NotEmpty(t, getResult.PublicKeyPEM)
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := GetKeyParams{Backend: "software"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getKey",
			Params:  json.RawMessage(`not json`),
			ID:      1,
		}

		_, err := server.handleGetKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with non-existent key", func(t *testing.T) {
		params := GetKeyParams{
			KeyID:   "non-existent-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_DeleteKey tests the delete key handler
func TestHandler_DeleteKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// First generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-delete-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("deletes existing key", func(t *testing.T) {
		params := DeleteKeyParams{
			KeyID:   "test-delete-key",
			Backend: "software",
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

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := DeleteKeyParams{Backend: "software"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDeleteKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteKey",
			Params:  json.RawMessage(`not json`),
			ID:      1,
		}

		_, err := server.handleDeleteKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("deletes key without specifying backend", func(t *testing.T) {
		// Generate a key first
		genParams := GenerateKeyParams{
			KeyID:   "test-delete-no-backend",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		}
		genParamsJSON, _ := json.Marshal(genParams)
		genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
		_, err := server.handleGenerateKey(genReq)
		require.NoError(t, err)

		params := DeleteKeyParams{
			KeyID: "test-delete-no-backend",
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

// TestHandler_ListKeys tests the list keys handler
func TestHandler_ListKeys(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate some keys first
	for _, keyID := range []string{"list-key-1", "list-key-2"} {
		genParams := GenerateKeyParams{KeyID: keyID, Backend: "software", KeyType: "rsa", KeySize: 2048}
		genParamsJSON, _ := json.Marshal(genParams)
		genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
		_, err := server.handleGenerateKey(genReq)
		require.NoError(t, err)
	}

	t.Run("lists all keys", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listKeys",
			ID:      1,
		}

		result, err := server.handleListKeys(req)
		require.NoError(t, err)

		listResult, ok := result.(ListKeysResult)
		require.True(t, ok)
		assert.GreaterOrEqual(t, len(listResult.Keys), 2)
	})
}

// TestHandler_Sign tests the sign handler
func TestHandler_Sign(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key for signing
	genParams := GenerateKeyParams{
		KeyID:   "test-sign-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("signs data successfully", func(t *testing.T) {
		params := SignParams{
			KeyID:   "test-sign-key",
			Backend: "software",
			Data:    []byte("test data to sign"),
			Hash:    "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleSign(req)
		require.NoError(t, err)

		signResult, ok := result.(SignResult)
		require.True(t, ok)
		assert.NotNil(t, signResult.Signature)
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := SignParams{
			Backend: "software",
			Data:    []byte("test data"),
			Hash:    "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSign(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleSign(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with unsupported hash algorithm", func(t *testing.T) {
		params := SignParams{
			KeyID:   "test-sign-key",
			Backend: "software",
			Data:    []byte("test data"),
			Hash:    "MD5", // Unsupported
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSign(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported hash algorithm")
	})
}

// TestHandler_Verify tests the verify handler
func TestHandler_Verify(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key and sign some data
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Sign data
	signParams := SignParams{
		KeyID:   "test-verify-key",
		Backend: "software",
		Data:    []byte("test data"),
		Hash:    "SHA256",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.sign", Params: signParamsJSON, ID: 1}
	signResult, err := server.handleSign(signReq)
	require.NoError(t, err)

	signature := signResult.(SignResult).Signature

	t.Run("verifies valid signature", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-verify-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: signature,
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := VerifyParams{
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: signature,
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleVerify(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleVerify(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("verifies with string signature (base64)", func(t *testing.T) {
		// Get signature as bytes first
		sigBytes, ok := signature.([]byte)
		require.True(t, ok)

		// Encode as base64 string
		sigBase64 := base64.StdEncoding.EncodeToString(sigBytes)

		params := VerifyParams{
			KeyID:     "test-verify-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: sigBase64,
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})

	t.Run("fails with unsupported hash algorithm", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-verify-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: signature,
			Hash:      "MD5",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleVerify(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported hash algorithm")
	})
}

// TestHandler_RotateKey tests the rotate key handler
func TestHandler_RotateKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate initial key
	genParams := GenerateKeyParams{
		KeyID:   "test-rotate-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	initialResult, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)
	initialPEM := initialResult.(GenerateKeyResult).PublicKeyPEM

	t.Run("rotates existing key", func(t *testing.T) {
		params := RotateKeyParams{
			KeyID:   "test-rotate-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.rotateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleRotateKey(req)
		require.NoError(t, err)

		rotateResult, ok := result.(RotateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-rotate-key", rotateResult.KeyID)
		assert.NotEmpty(t, rotateResult.PublicKeyPEM)
		// Key should be different after rotation
		assert.NotEqual(t, initialPEM, rotateResult.PublicKeyPEM)
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := RotateKeyParams{Backend: "software"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.rotateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleRotateKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.rotateKey",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleRotateKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := RotateKeyParams{
			KeyID:   "test-rotate-key",
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

// TestHandler_Subscribe tests the subscribe handler
func TestHandler_Subscribe(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Create a mock connection
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	t.Run("subscribes to events", func(t *testing.T) {
		params := SubscribeParams{
			Events: []string{"key.created", "key.deleted"},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.subscribe",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleSubscribe(req, serverConn)
		require.NoError(t, err)

		subResult, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.True(t, subResult["success"].(bool))
		assert.Equal(t, 2, subResult["total_count"].(int))
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.subscribe",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleSubscribe(req, serverConn)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("adds events to existing subscriber", func(t *testing.T) {
		params := SubscribeParams{
			Events: []string{"key.rotated"},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.subscribe",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleSubscribe(req, serverConn)
		require.NoError(t, err)

		subResult, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.True(t, subResult["success"].(bool))
		assert.Equal(t, 3, subResult["total_count"].(int))
	})
}

// TestHandler_Certificates tests the certificate handlers
func TestHandler_Certificates(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key first
	genParams := GenerateKeyParams{
		KeyID:   "test-cert-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Create a self-signed certificate for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert-key",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	t.Run("saves certificate", func(t *testing.T) {
		params := SaveCertParams{
			KeyID:   "test-cert-key",
			CertPEM: string(certPEM),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleSaveCert(req)
		require.NoError(t, err)

		saveResult, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.True(t, saveResult["success"].(bool))
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := SaveCertParams{CertPEM: string(certPEM)}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with missing cert_pem", func(t *testing.T) {
		params := SaveCertParams{KeyID: "test-cert-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cert_pem is required")
	})

	t.Run("fails with invalid certificate PEM", func(t *testing.T) {
		params := SaveCertParams{
			KeyID:   "test-cert-key",
			CertPEM: "not a valid certificate",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid certificate PEM")
	})

	t.Run("fails saveCert with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCert",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleSaveCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("gets certificate", func(t *testing.T) {
		params := GetCertParams{KeyID: "test-cert-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getCert",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetCert(req)
		require.NoError(t, err)

		getCertResult, ok := result.(GetCertResult)
		require.True(t, ok)
		assert.Equal(t, "test-cert-key", getCertResult.KeyID)
		assert.Contains(t, getCertResult.CertPEM, "BEGIN CERTIFICATE")
	})

	t.Run("getCert fails with missing key_id", func(t *testing.T) {
		params := GetCertParams{}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("getCert fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getCert",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleGetCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("checks certificate exists", func(t *testing.T) {
		params := CertExistsParams{KeyID: "test-cert-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.certExists",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleCertExists(req)
		require.NoError(t, err)

		existsResult, ok := result.(CertExistsResult)
		require.True(t, ok)
		assert.True(t, existsResult.Exists)
	})

	t.Run("certExists fails with missing key_id", func(t *testing.T) {
		params := CertExistsParams{}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.certExists",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCertExists(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("certExists fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.certExists",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleCertExists(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("lists certificates", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listCerts",
			ID:      1,
		}

		result, err := server.handleListCerts(req)
		require.NoError(t, err)

		listResult, ok := result.(ListCertsResult)
		require.True(t, ok)
		assert.Contains(t, listResult.KeyIDs, "test-cert-key")
	})

	t.Run("deletes certificate", func(t *testing.T) {
		params := DeleteCertParams{KeyID: "test-cert-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteCert",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleDeleteCert(req)
		require.NoError(t, err)

		deleteResult, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.True(t, deleteResult["success"].(bool))
	})

	t.Run("deleteCert fails with missing key_id", func(t *testing.T) {
		params := DeleteCertParams{}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDeleteCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("deleteCert fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteCert",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleDeleteCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})
}

// TestHandler_CertificateChain tests the certificate chain handlers
func TestHandler_CertificateChain(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Create certificate chain for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	t.Run("saves certificate chain", func(t *testing.T) {
		params := SaveCertChainParams{
			KeyID:     "test-chain-key",
			ChainPEMs: []string{certPEM},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleSaveCertChain(req)
		require.NoError(t, err)

		saveResult, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.True(t, saveResult["success"].(bool))
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := SaveCertChainParams{ChainPEMs: []string{certPEM}}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCertChain(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with empty chain", func(t *testing.T) {
		params := SaveCertChainParams{
			KeyID:     "test-chain-key",
			ChainPEMs: []string{},
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
		assert.Contains(t, err.Error(), "chain_pems is required")
	})

	t.Run("fails with invalid PEM in chain", func(t *testing.T) {
		params := SaveCertChainParams{
			KeyID:     "test-chain-key",
			ChainPEMs: []string{"invalid pem"},
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
		assert.Contains(t, err.Error(), "invalid certificate PEM")
	})

	t.Run("saveCertChain fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCertChain",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleSaveCertChain(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("gets certificate chain", func(t *testing.T) {
		params := GetCertChainParams{KeyID: "test-chain-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetCertChain(req)
		require.NoError(t, err)

		getResult, ok := result.(GetCertChainResult)
		require.True(t, ok)
		assert.Equal(t, "test-chain-key", getResult.KeyID)
		assert.NotEmpty(t, getResult.ChainPEMs)
	})

	t.Run("getCertChain fails with missing key_id", func(t *testing.T) {
		params := GetCertChainParams{}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetCertChain(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("getCertChain fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getCertChain",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleGetCertChain(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})
}

// TestHandler_GetTLSCertificate tests the get TLS certificate handler
func TestHandler_GetTLSCertificate(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := GetTLSCertificateParams{Backend: "software"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getTLSCertificate",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetTLSCertificate(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getTLSCertificate",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleGetTLSCertificate(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

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

	t.Run("fails with non-existent key", func(t *testing.T) {
		params := GetTLSCertificateParams{
			KeyID:   "non-existent-tls-key",
			Backend: "software",
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
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_AsymmetricEncrypt tests the asymmetric encrypt handler
func TestHandler_AsymmetricEncrypt(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key for encryption
	genParams := GenerateKeyParams{
		KeyID:   "test-asym-encrypt-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("encrypts data", func(t *testing.T) {
		params := AsymmetricEncryptParams{
			KeyID:     "test-asym-encrypt-key",
			Backend:   "software",
			Plaintext: []byte("secret data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.asymmetricEncrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleAsymmetricEncrypt(req)
		require.NoError(t, err)

		encResult, ok := result.(AsymmetricEncryptResult)
		require.True(t, ok)
		assert.NotEmpty(t, encResult.Ciphertext)
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := AsymmetricEncryptParams{
			Backend:   "software",
			Plaintext: []byte("data"),
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
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.asymmetricEncrypt",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleAsymmetricEncrypt(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := AsymmetricEncryptParams{
			KeyID:     "test-asym-encrypt-key",
			Backend:   "nonexistent",
			Plaintext: []byte("data"),
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

	t.Run("fails with ECDSA key (not RSA)", func(t *testing.T) {
		// Generate an ECDSA key
		genParams := GenerateKeyParams{
			KeyID:   "test-ecdsa-for-encrypt",
			Backend: "software",
			KeyType: "ecdsa",
			Curve:   "P-256",
		}
		genParamsJSON, _ := json.Marshal(genParams)
		genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
		_, err := server.handleGenerateKey(genReq)
		require.NoError(t, err)

		params := AsymmetricEncryptParams{
			KeyID:     "test-ecdsa-for-encrypt",
			Backend:   "software",
			Plaintext: []byte("data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.asymmetricEncrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleAsymmetricEncrypt(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not an RSA key")
	})
}

// TestHandler_AsymmetricDecrypt tests the asymmetric decrypt handler
func TestHandler_AsymmetricDecrypt(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-asym-decrypt-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Get a signer for the key to extract the public key
	attrs, err := server.findKeyByCN("test-asym-decrypt-key")
	require.NoError(t, err)

	signer, err := server.keystore.Signer(attrs)
	require.NoError(t, err)

	rsaPubKey, ok := signer.Public().(*rsa.PublicKey)
	require.True(t, ok, "expected RSA public key")

	// Encrypt with PKCS1v15 to match the handler's decrypt behavior (nil opts = PKCS1v15)
	plaintext := []byte("secret data")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, plaintext)
	require.NoError(t, err)

	t.Run("decrypts data", func(t *testing.T) {
		params := AsymmetricDecryptParams{
			KeyID:      "test-asym-decrypt-key",
			Backend:    "software",
			Ciphertext: ciphertext,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.asymmetricDecrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleAsymmetricDecrypt(req)
		require.NoError(t, err)

		decResult, ok := result.(AsymmetricDecryptResult)
		require.True(t, ok)
		assert.Equal(t, []byte("secret data"), decResult.Plaintext)
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := AsymmetricDecryptParams{
			Backend:    "software",
			Ciphertext: ciphertext,
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
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.asymmetricDecrypt",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleAsymmetricDecrypt(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := AsymmetricDecryptParams{
			KeyID:      "test-asym-decrypt-key",
			Backend:    "nonexistent",
			Ciphertext: ciphertext,
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

// TestHandler_CopyKey tests the copy key handler
func TestHandler_CopyKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with missing source_backend", func(t *testing.T) {
		params := CopyKeyParams{
			SourceKeyID: "key1",
			DestBackend: "software",
			DestKeyID:   "key2",
			Algorithm:   "RSA_OAEP_SHA256",
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
		assert.Contains(t, err.Error(), "source_backend is required")
	})

	t.Run("fails with missing source_key_id", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			DestBackend:   "software",
			DestKeyID:     "key2",
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
		assert.Contains(t, err.Error(), "source_key_id is required")
	})

	t.Run("fails with missing dest_backend", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			SourceKeyID:   "key1",
			DestKeyID:     "key2",
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
		assert.Contains(t, err.Error(), "dest_backend is required")
	})

	t.Run("fails with missing dest_key_id", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			SourceKeyID:   "key1",
			DestBackend:   "software",
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
		assert.Contains(t, err.Error(), "dest_key_id is required")
	})

	t.Run("fails with missing algorithm", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			SourceKeyID:   "key1",
			DestBackend:   "software",
			DestKeyID:     "key2",
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
		assert.Contains(t, err.Error(), "algorithm is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.copyKey",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleCopyKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})
}

// TestHandler_GetImportParameters tests the get import parameters handler
func TestHandler_GetImportParameters(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := GetImportParametersParams{
			Backend:   "software",
			Algorithm: "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getImportParameters",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetImportParameters(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getImportParameters",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleGetImportParameters(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := GetImportParametersParams{
			KeyID:     "test-key",
			Backend:   "nonexistent",
			Algorithm: "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getImportParameters",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetImportParameters(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})
}

// TestHandler_WrapKey tests the wrap key handler
func TestHandler_WrapKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.wrapKey",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleWrapKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with invalid public key PEM", func(t *testing.T) {
		params := WrapKeyParams{
			KeyMaterial:          []byte("key material"),
			WrappingPublicKeyPEM: "not a valid PEM",
			Algorithm:            "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.wrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleWrapKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid wrapping public key PEM")
	})

	t.Run("fails with malformed public key", func(t *testing.T) {
		// Create a valid PEM but with invalid key data
		invalidPEM := "-----BEGIN PUBLIC KEY-----\naW52YWxpZCBrZXkgZGF0YQ==\n-----END PUBLIC KEY-----"

		params := WrapKeyParams{
			KeyMaterial:          []byte("key material"),
			WrappingPublicKeyPEM: invalidPEM,
			Algorithm:            "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.wrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleWrapKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse public key")
	})
}

// TestHandler_ImportKeyMaterial tests the import key material handler
func TestHandler_ImportKeyMaterial(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := ImportKeyParams{
			Backend:    "software",
			WrappedKey: []byte("wrapped"),
			Algorithm:  "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.importKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleImportKeyMaterial(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.importKey",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleImportKeyMaterial(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := ImportKeyParams{
			KeyID:      "test-key",
			Backend:    "nonexistent",
			WrappedKey: []byte("wrapped"),
			Algorithm:  "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.importKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleImportKeyMaterial(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})
}

// TestHandler_ExportKeyMaterial tests the export key material handler
func TestHandler_ExportKeyMaterial(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := ExportKeyParams{
			Backend:   "software",
			Algorithm: "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.exportKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleExportKeyMaterial(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.exportKey",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleExportKeyMaterial(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with non-existent key", func(t *testing.T) {
		params := ExportKeyParams{
			KeyID:     "non-existent-export-key",
			Backend:   "software",
			Algorithm: "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.exportKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleExportKeyMaterial(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_SymmetricEncrypt tests the symmetric encrypt handler
func TestHandler_SymmetricEncrypt(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a symmetric key using the software backend
	genParams := GenerateKeyParams{
		KeyID:     "test-sym-key",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("encrypts data", func(t *testing.T) {
		params := EncryptParams{
			KeyID:     "test-sym-key",
			Backend:   "software",
			Plaintext: []byte("secret data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleEncrypt(req)
		require.NoError(t, err)

		encResult, ok := result.(EncryptResult)
		require.True(t, ok)
		assert.NotEmpty(t, encResult.Ciphertext)
		assert.NotEmpty(t, encResult.Nonce)
	})

	t.Run("encrypts with additional data", func(t *testing.T) {
		params := EncryptParams{
			KeyID:          "test-sym-key",
			Backend:        "software",
			Plaintext:      []byte("secret data"),
			AdditionalData: []byte("additional authenticated data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleEncrypt(req)
		require.NoError(t, err)

		encResult, ok := result.(EncryptResult)
		require.True(t, ok)
		assert.NotEmpty(t, encResult.Ciphertext)
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := EncryptParams{
			Backend:   "software",
			Plaintext: []byte("data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEncrypt(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with empty plaintext", func(t *testing.T) {
		params := EncryptParams{
			KeyID:     "test-sym-key",
			Backend:   "software",
			Plaintext: []byte{},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEncrypt(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "plaintext is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.encrypt",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleEncrypt(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})
}

// TestHandler_SymmetricDecrypt tests the symmetric decrypt handler
func TestHandler_SymmetricDecrypt(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a symmetric key using the software backend
	genParams := GenerateKeyParams{
		KeyID:     "test-sym-decrypt-key",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Encrypt data first using the software backend
	encryptParams := EncryptParams{
		KeyID:     "test-sym-decrypt-key",
		Backend:   "software",
		Plaintext: []byte("secret data"),
	}
	encryptParamsJSON, _ := json.Marshal(encryptParams)
	encryptReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.encrypt", Params: encryptParamsJSON, ID: 1}
	encryptResult, err := server.handleEncrypt(encryptReq)
	require.NoError(t, err)

	encResult := encryptResult.(EncryptResult)

	t.Run("decrypts data", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "test-sym-decrypt-key",
			Backend:    "software",
			Ciphertext: encResult.Ciphertext,
			Nonce:      encResult.Nonce,
			Tag:        encResult.Tag,
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

	t.Run("decrypts with additional data", func(t *testing.T) {
		// First encrypt with AAD
		encryptParamsAAD := EncryptParams{
			KeyID:          "test-sym-decrypt-key",
			Backend:        "software",
			Plaintext:      []byte("secret with aad"),
			AdditionalData: []byte("aad"),
		}
		encryptParamsAADJSON, _ := json.Marshal(encryptParamsAAD)
		encryptReqAAD := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.encrypt", Params: encryptParamsAADJSON, ID: 1}
		encryptResultAAD, err := server.handleEncrypt(encryptReqAAD)
		require.NoError(t, err)

		encResultAAD := encryptResultAAD.(EncryptResult)

		params := DecryptParams{
			KeyID:          "test-sym-decrypt-key",
			Backend:        "software",
			Ciphertext:     encResultAAD.Ciphertext,
			Nonce:          encResultAAD.Nonce,
			Tag:            encResultAAD.Tag,
			AdditionalData: []byte("aad"),
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
		assert.Equal(t, []byte("secret with aad"), decResult.Plaintext)
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := DecryptParams{
			Backend:    "software",
			Ciphertext: encResult.Ciphertext,
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
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.decrypt",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleDecrypt(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("decrypts without specifying backend", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "test-sym-decrypt-key",
			Ciphertext: encResult.Ciphertext,
			Nonce:      encResult.Nonce,
			Tag:        encResult.Tag,
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

// TestHandler_FindKeyByCN tests the findKeyByCN helper function
func TestHandler_FindKeyByCN(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key first
	genParams := GenerateKeyParams{
		KeyID:   "find-key-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("finds existing key", func(t *testing.T) {
		attrs, err := server.findKeyByCN("find-key-test")
		require.NoError(t, err)
		assert.Equal(t, "find-key-test", attrs.CN)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		_, err := server.findKeyByCN("non-existent-key")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})
}

// TestHandler_FindKeyInBackend tests the findKeyInBackend helper function
func TestHandler_FindKeyInBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key first
	genParams := GenerateKeyParams{
		KeyID:   "find-backend-key-test",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("finds key in specified backend", func(t *testing.T) {
		attrs, err := server.findKeyInBackend("find-backend-key-test", "software")
		require.NoError(t, err)
		assert.Equal(t, "find-backend-key-test", attrs.CN)
	})

	t.Run("returns error for invalid backend", func(t *testing.T) {
		_, err := server.findKeyInBackend("find-backend-key-test", "nonexistent")
		require.Error(t, err)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		_, err := server.findKeyInBackend("non-existent-key", "software")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})
}

// TestHandler_DeleteKey_NonExistent tests deleting a non-existent key
func TestHandler_DeleteKey_NonExistent(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails when deleting non-existent key", func(t *testing.T) {
		params := DeleteKeyParams{
			KeyID:   "non-existent-delete-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDeleteKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_ListKeys_WithParams tests list keys with optional params
func TestHandler_ListKeys_WithParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("handles params in list keys request", func(t *testing.T) {
		params := map[string]string{"backend": "software"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listKeys",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleListKeys(req)
		require.NoError(t, err)

		listResult, ok := result.(ListKeysResult)
		require.True(t, ok)
		assert.NotNil(t, listResult.Keys)
	})
}

// TestHandler_ListCerts_Empty tests listing certificates when none exist
func TestHandler_ListCerts_Empty(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("returns empty list when no certs", func(t *testing.T) {
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

// TestHandler_CertExists_NotFound tests checking for non-existent cert
func TestHandler_CertExists_NotFound(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("returns false for non-existent cert", func(t *testing.T) {
		params := CertExistsParams{KeyID: "non-existent-cert"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.certExists",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleCertExists(req)
		require.NoError(t, err)

		existsResult, ok := result.(CertExistsResult)
		require.True(t, ok)
		assert.False(t, existsResult.Exists)
	})
}

// TestHandler_GetCert_NotFound tests getting a non-existent cert
func TestHandler_GetCert_NotFound(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails for non-existent cert", func(t *testing.T) {
		params := GetCertParams{KeyID: "non-existent-cert"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get certificate")
	})
}

// TestHandler_GetCertChain_NotFound tests getting a non-existent cert chain
func TestHandler_GetCertChain_NotFound(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails for non-existent cert chain", func(t *testing.T) {
		params := GetCertChainParams{KeyID: "non-existent-chain"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetCertChain(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get certificate chain")
	})
}

// TestHandler_DeleteCert_NotFound tests deleting a non-existent cert
func TestHandler_DeleteCert_NotFound(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails for non-existent cert", func(t *testing.T) {
		params := DeleteCertParams{KeyID: "non-existent-cert"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDeleteCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete certificate")
	})
}

// TestHandler_Sign_NonExistentKey tests signing with non-existent key
func TestHandler_Sign_NonExistentKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with non-existent key", func(t *testing.T) {
		params := SignParams{
			KeyID:   "non-existent-sign-key",
			Backend: "software",
			Data:    []byte("test data"),
			Hash:    "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSign(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_Verify_NonExistentKey tests verifying with non-existent key
func TestHandler_Verify_NonExistentKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with non-existent key", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "non-existent-verify-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: []byte("fake signature"),
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleVerify(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_RotateKey_NonExistent tests rotating a non-existent key
func TestHandler_RotateKey_NonExistent(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails for non-existent key", func(t *testing.T) {
		params := RotateKeyParams{
			KeyID:   "non-existent-rotate-key",
			Backend: "software",
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
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_Encrypt_NonExistentKey tests encrypting with non-existent key
func TestHandler_Encrypt_NonExistentKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with non-existent key", func(t *testing.T) {
		params := EncryptParams{
			KeyID:     "non-existent-encrypt-key",
			Backend:   "software",
			Plaintext: []byte("secret data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEncrypt(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_Decrypt_NonExistentKey tests decrypting with non-existent key
func TestHandler_Decrypt_NonExistentKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with non-existent key", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "non-existent-decrypt-key",
			Backend:    "software",
			Ciphertext: []byte("encrypted data"),
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

// TestHandler_AsymmetricEncrypt_NonExistentKey tests asymmetric encrypt with non-existent key
func TestHandler_AsymmetricEncrypt_NonExistentKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with non-existent key", func(t *testing.T) {
		params := AsymmetricEncryptParams{
			KeyID:     "non-existent-asym-key",
			Backend:   "software",
			Plaintext: []byte("secret data"),
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
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_AsymmetricDecrypt_NonExistentKey tests asymmetric decrypt with non-existent key
func TestHandler_AsymmetricDecrypt_NonExistentKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with non-existent key", func(t *testing.T) {
		params := AsymmetricDecryptParams{
			KeyID:      "non-existent-asym-key",
			Backend:    "software",
			Ciphertext: []byte("encrypted data"),
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
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_GetKey_NonExistentBackend tests get key with non-existent backend
func TestHandler_GetKey_NonExistentBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with non-existent backend", func(t *testing.T) {
		params := GetKeyParams{
			KeyID:   "test-key",
			Backend: "nonexistent-backend",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_Verify_InvalidSignature tests verify with invalid signature
func TestHandler_Verify_InvalidSignature(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-invalid-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("returns false for invalid signature", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-verify-invalid-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: []byte("invalid signature"),
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.False(t, verifyResult.Valid)
	})
}

// TestHandler_GenerateKey_Symmetric tests symmetric key generation
func TestHandler_GenerateKey_Symmetric(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("generates AES key", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:     "test-aes-key",
			Backend:   "software",
			KeyType:   "symmetric",
			Algorithm: "aes256-gcm",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(req)
		require.NoError(t, err)

		genResult, ok := result.(GenerateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-aes-key", genResult.KeyID)
	})

	t.Run("generates symmetric key with default algorithm", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-sym-default-alg",
			Backend: "software",
			KeyType: "symmetric",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(req)
		require.NoError(t, err)

		genResult, ok := result.(GenerateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-sym-default-alg", genResult.KeyID)
	})
}

// TestHandler_Sign_WithECDSA tests signing with ECDSA key
func TestHandler_Sign_WithECDSA(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an ECDSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-ecdsa-sign-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P-256",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("signs data with ECDSA", func(t *testing.T) {
		params := SignParams{
			KeyID:   "test-ecdsa-sign-key",
			Backend: "software",
			Data:    []byte("test data to sign"),
			Hash:    "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleSign(req)
		require.NoError(t, err)

		signResult, ok := result.(SignResult)
		require.True(t, ok)
		assert.NotNil(t, signResult.Signature)
	})
}

// TestHandler_Sign_WithEd25519 tests signing with Ed25519 key
func TestHandler_Sign_WithEd25519(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an Ed25519 key
	genParams := GenerateKeyParams{
		KeyID:   "test-ed25519-sign-key",
		Backend: "software",
		KeyType: "ed25519",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("signs data with Ed25519", func(t *testing.T) {
		params := SignParams{
			KeyID:   "test-ed25519-sign-key",
			Backend: "software",
			Data:    []byte("test data to sign"),
			Hash:    "", // Ed25519 doesn't use a hash
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleSign(req)
		require.NoError(t, err)

		signResult, ok := result.(SignResult)
		require.True(t, ok)
		assert.NotNil(t, signResult.Signature)
	})
}

// TestHandler_Verify_WithECDSA tests verifying with ECDSA key
func TestHandler_Verify_WithECDSA(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an ECDSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-ecdsa-verify-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P-256",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Sign data
	signParams := SignParams{
		KeyID:   "test-ecdsa-verify-key",
		Backend: "software",
		Data:    []byte("test data"),
		Hash:    "SHA256",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.sign", Params: signParamsJSON, ID: 1}
	signResult, err := server.handleSign(signReq)
	require.NoError(t, err)

	signature := signResult.(SignResult).Signature

	t.Run("verifies ECDSA signature", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-ecdsa-verify-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: signature,
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})
}

// TestHandler_Verify_WithEd25519 tests verifying with Ed25519 key
func TestHandler_Verify_WithEd25519(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an Ed25519 key
	genParams := GenerateKeyParams{
		KeyID:   "test-ed25519-verify-key",
		Backend: "software",
		KeyType: "ed25519",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Sign data
	signParams := SignParams{
		KeyID:   "test-ed25519-verify-key",
		Backend: "software",
		Data:    []byte("test data"),
		Hash:    "",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.sign", Params: signParamsJSON, ID: 1}
	signResult, err := server.handleSign(signReq)
	require.NoError(t, err)

	signature := signResult.(SignResult).Signature

	t.Run("verifies Ed25519 signature", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-ed25519-verify-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: signature,
			Hash:      "",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})
}

// TestHandler_Sign_WithDifferentHashes tests signing with different hash algorithms
func TestHandler_Sign_WithDifferentHashes(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-hash-sign-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	hashAlgs := []string{"SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}

	for _, hash := range hashAlgs {
		t.Run("signs with "+hash, func(t *testing.T) {
			params := SignParams{
				KeyID:   "test-hash-sign-key",
				Backend: "software",
				Data:    []byte("test data"),
				Hash:    hash,
			}
			paramsJSON, _ := json.Marshal(params)

			req := &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  "keychain.sign",
				Params:  paramsJSON,
				ID:      1,
			}

			result, err := server.handleSign(req)
			require.NoError(t, err)

			signResult, ok := result.(SignResult)
			require.True(t, ok)
			assert.NotNil(t, signResult.Signature)
		})
	}
}

// TestHandler_Verify_SignatureAsArray tests verify with signature as JSON array of numbers
func TestHandler_Verify_SignatureAsArray(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-array-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Sign data
	signParams := SignParams{
		KeyID:   "test-verify-array-key",
		Backend: "software",
		Data:    []byte("test data"),
		Hash:    "SHA256",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.sign", Params: signParamsJSON, ID: 1}
	signResult, err := server.handleSign(signReq)
	require.NoError(t, err)

	signature := signResult.(SignResult).Signature.([]byte)

	t.Run("verifies with signature as JSON array of numbers", func(t *testing.T) {
		// Convert signature to []interface{} to simulate JSON array
		sigArray := make([]interface{}, len(signature))
		for i, b := range signature {
			sigArray[i] = float64(b)
		}

		params := VerifyParams{
			KeyID:     "test-verify-array-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: sigArray,
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})

	t.Run("verifies with raw string signature", func(t *testing.T) {
		// Use a raw string that is NOT base64 encoded
		params := VerifyParams{
			KeyID:     "test-verify-array-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: "raw string not base64!", // This should be treated as raw bytes
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.False(t, verifyResult.Valid) // Should fail but not error
	})
}

// TestHandler_GetTLSCertificate_Success tests getting TLS certificate successfully
func TestHandler_GetTLSCertificate_Success(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key first
	genParams := GenerateKeyParams{
		KeyID:   "test-tls-cert-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Create a self-signed certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-tls-cert-key",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Save the certificate
	saveCertParams := SaveCertParams{
		KeyID:   "test-tls-cert-key",
		CertPEM: string(certPEM),
	}
	saveCertParamsJSON, _ := json.Marshal(saveCertParams)
	saveCertReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.saveCert", Params: saveCertParamsJSON, ID: 1}
	_, err = server.handleSaveCert(saveCertReq)
	require.NoError(t, err)

	t.Run("gets TLS certificate", func(t *testing.T) {
		params := GetTLSCertificateParams{
			KeyID:   "test-tls-cert-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getTLSCertificate",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetTLSCertificate(req)
		require.NoError(t, err)

		tlsResult, ok := result.(GetTLSCertificateResult)
		require.True(t, ok)
		assert.Contains(t, tlsResult.CertPEM, "BEGIN CERTIFICATE")
	})

	t.Run("gets TLS certificate without specifying backend", func(t *testing.T) {
		params := GetTLSCertificateParams{
			KeyID: "test-tls-cert-key",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getTLSCertificate",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetTLSCertificate(req)
		require.NoError(t, err)

		tlsResult, ok := result.(GetTLSCertificateResult)
		require.True(t, ok)
		assert.Contains(t, tlsResult.CertPEM, "BEGIN CERTIFICATE")
	})
}

// TestHandler_DecryptAsymmetric tests asymmetric decryption path
func TestHandler_DecryptAsymmetric(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key for asymmetric encryption/decryption
	genParams := GenerateKeyParams{
		KeyID:   "test-asym-decrypt-path",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Get the signer to extract the public key
	attrs, err := server.findKeyByCN("test-asym-decrypt-path")
	require.NoError(t, err)

	signer, err := server.keystore.Signer(attrs)
	require.NoError(t, err)

	rsaPubKey, ok := signer.Public().(*rsa.PublicKey)
	require.True(t, ok, "expected RSA public key")

	// Encrypt with PKCS1v15
	plaintext := []byte("asymmetric secret")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, plaintext)
	require.NoError(t, err)

	t.Run("decrypts asymmetrically without specifying backend", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "test-asym-decrypt-path",
			Ciphertext: ciphertext,
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
		assert.Equal(t, plaintext, decResult.Plaintext)
	})

	t.Run("decrypts asymmetrically with backend specified", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "test-asym-decrypt-path",
			Backend:    "software",
			Ciphertext: ciphertext,
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
		assert.Equal(t, plaintext, decResult.Plaintext)
	})
}

// TestHandler_CopyKey_InvalidSourceBackend tests copy key with invalid source backend
func TestHandler_CopyKey_InvalidSourceBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid source backend type", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "notreal",
			SourceKeyID:   "key1",
			DestBackend:   "software",
			DestKeyID:     "key2",
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
	})

	t.Run("fails with invalid destination backend type", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			SourceKeyID:   "key1",
			DestBackend:   "notreal",
			DestKeyID:     "key2",
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
	})
}

// TestHandler_SaveCertChain_InvalidCertInMiddle tests saving cert chain with bad cert in middle
func TestHandler_SaveCertChain_InvalidCertInMiddle(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Create a valid certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	validCertPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	// Create a corrupt certificate (valid PEM block but invalid DER)
	corruptCertPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid DER data"),
	}))

	t.Run("fails with malformed certificate in chain", func(t *testing.T) {
		params := SaveCertChainParams{
			KeyID:     "test-chain-invalid",
			ChainPEMs: []string{validCertPEM, corruptCertPEM},
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
		assert.Contains(t, err.Error(), "failed to parse certificate")
	})
}

// TestHandler_SaveCert_CorruptCertificate tests saving a corrupt certificate
func TestHandler_SaveCert_CorruptCertificate(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with corrupt certificate data", func(t *testing.T) {
		// Create a PEM block with invalid DER data
		corruptCertPEM := string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("totally invalid certificate data"),
		}))

		params := SaveCertParams{
			KeyID:   "test-corrupt-cert",
			CertPEM: corruptCertPEM,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse certificate")
	})

	t.Run("fails with wrong PEM type", func(t *testing.T) {
		// Create a PEM block with wrong type
		wrongTypePEM := string(pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("some data"),
		}))

		params := SaveCertParams{
			KeyID:   "test-wrong-type-cert",
			CertPEM: wrongTypePEM,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCert(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid certificate PEM")
	})
}

// TestHandler_SymmetricEncrypt_WithNonSymmetricBackend tests encrypt error handling
func TestHandler_SymmetricEncrypt_WithNonSymmetricBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key (not symmetric)
	genParams := GenerateKeyParams{
		KeyID:   "test-rsa-not-sym",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("fails when trying symmetric encrypt with asymmetric key", func(t *testing.T) {
		params := EncryptParams{
			KeyID:     "test-rsa-not-sym",
			Backend:   "software",
			Plaintext: []byte("secret data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEncrypt(req)
		require.Error(t, err)
	})
}

// TestHandler_Decrypt_InvalidBackend tests decrypt with invalid backend
func TestHandler_Decrypt_InvalidBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "test-key",
			Backend:    "invalidbackend123",
			Ciphertext: []byte("some data"),
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

// TestHandler_DeleteKey_SymmetricBackendSearch tests delete key fallback to symmetric
func TestHandler_DeleteKey_SymmetricBackendSearch(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a symmetric key
	genParams := GenerateKeyParams{
		KeyID:     "test-delete-sym",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("deletes symmetric key without specifying backend", func(t *testing.T) {
		params := DeleteKeyParams{
			KeyID: "test-delete-sym",
			// No backend specified - should search symmetric
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

// TestHandler_GenerateKey_SymmetricBadBackend tests symmetric key with bad backend
func TestHandler_GenerateKey_SymmetricBadBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid backend for symmetric key", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:     "test-sym-bad-backend",
			Backend:   "notexistent",
			KeyType:   "symmetric",
			Algorithm: "aes256-gcm",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGenerateKey(req)
		require.Error(t, err)
	})
}

// TestHandler_Verify_SHA1Hash tests verify with SHA1 hash
func TestHandler_Verify_SHA1Hash(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-sha1-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Sign with SHA1
	signParams := SignParams{
		KeyID:   "test-verify-sha1-key",
		Backend: "software",
		Data:    []byte("test data sha1"),
		Hash:    "SHA1",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.sign", Params: signParamsJSON, ID: 1}
	signResult, err := server.handleSign(signReq)
	require.NoError(t, err)

	signature := signResult.(SignResult).Signature

	t.Run("verifies with SHA1", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-verify-sha1-key",
			Backend:   "software",
			Data:      []byte("test data sha1"),
			Signature: signature,
			Hash:      "SHA1",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})
}

// TestHandler_Verify_SHA384Hash tests verify with SHA384 hash
func TestHandler_Verify_SHA384Hash(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-sha384-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Sign with SHA384
	signParams := SignParams{
		KeyID:   "test-verify-sha384-key",
		Backend: "software",
		Data:    []byte("test data sha384"),
		Hash:    "SHA384",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.sign", Params: signParamsJSON, ID: 1}
	signResult, err := server.handleSign(signReq)
	require.NoError(t, err)

	signature := signResult.(SignResult).Signature

	t.Run("verifies with SHA384", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-verify-sha384-key",
			Backend:   "software",
			Data:      []byte("test data sha384"),
			Signature: signature,
			Hash:      "SHA384",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})
}

// TestHandler_Verify_SHA512Hash tests verify with SHA512 hash
func TestHandler_Verify_SHA512Hash(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-sha512-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Sign with SHA512
	signParams := SignParams{
		KeyID:   "test-verify-sha512-key",
		Backend: "software",
		Data:    []byte("test data sha512"),
		Hash:    "SHA512",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.sign", Params: signParamsJSON, ID: 1}
	signResult, err := server.handleSign(signReq)
	require.NoError(t, err)

	signature := signResult.(SignResult).Signature

	t.Run("verifies with SHA512", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-verify-sha512-key",
			Backend:   "software",
			Data:      []byte("test data sha512"),
			Signature: signature,
			Hash:      "SHA512",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})
}

// TestHandler_GetTLSCertificate_WithChain tests TLS cert with chain
func TestHandler_GetTLSCertificate_WithChain(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-tls-chain-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Create certificates for chain
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test-tls-chain-key",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	leafPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	leafCertDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &leafPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)

	leafCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCertDER,
	})

	// Save leaf certificate
	saveCertParams := SaveCertParams{
		KeyID:   "test-tls-chain-key",
		CertPEM: string(leafCertPEM),
	}
	saveCertParamsJSON, _ := json.Marshal(saveCertParams)
	saveCertReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.saveCert", Params: saveCertParamsJSON, ID: 1}
	_, err = server.handleSaveCert(saveCertReq)
	require.NoError(t, err)

	// Save certificate chain
	saveChainParams := SaveCertChainParams{
		KeyID:     "test-tls-chain-key",
		ChainPEMs: []string{string(leafCertPEM), string(caCertPEM)},
	}
	saveChainParamsJSON, _ := json.Marshal(saveChainParams)
	saveChainReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.saveCertChain", Params: saveChainParamsJSON, ID: 1}
	_, err = server.handleSaveCertChain(saveChainReq)
	require.NoError(t, err)

	t.Run("gets TLS certificate with chain", func(t *testing.T) {
		params := GetTLSCertificateParams{
			KeyID:   "test-tls-chain-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getTLSCertificate",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetTLSCertificate(req)
		require.NoError(t, err)

		tlsResult, ok := result.(GetTLSCertificateResult)
		require.True(t, ok)
		assert.Contains(t, tlsResult.CertPEM, "BEGIN CERTIFICATE")
	})
}

// TestHandler_Encrypt_DefaultBackend tests encrypt with default backend
func TestHandler_Encrypt_DefaultBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a symmetric key using default backend name
	genParams := GenerateKeyParams{
		KeyID:     "test-encrypt-default-backend",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("encrypts without specifying backend", func(t *testing.T) {
		params := EncryptParams{
			KeyID:     "test-encrypt-default-backend",
			Plaintext: []byte("secret data without backend"),
			// No backend - should use default "symmetric"
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleEncrypt(req)
		require.NoError(t, err)

		encResult, ok := result.(EncryptResult)
		require.True(t, ok)
		assert.NotEmpty(t, encResult.Ciphertext)
	})
}

// TestHandler_GetImportParameters_Success tests successful import parameters retrieval
func TestHandler_GetImportParameters_Success(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("gets import parameters successfully", func(t *testing.T) {
		params := GetImportParametersParams{
			KeyID:     "test-import-key",
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getImportParameters",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetImportParameters(req)
		require.NoError(t, err)

		importResult, ok := result.(GetImportParametersResult)
		require.True(t, ok)
		assert.NotEmpty(t, importResult.WrappingPublicKeyPEM)
		assert.Contains(t, importResult.WrappingPublicKeyPEM, "BEGIN PUBLIC KEY")
	})
}

// TestHandler_WrapKey_Success tests successful key wrapping
func TestHandler_WrapKey_Success(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// First get import parameters to get a valid wrapping key
	importParamsReq := GetImportParametersParams{
		KeyID:     "test-wrap-key",
		Backend:   "software",
		Algorithm: "RSAES_OAEP_SHA_256",
	}
	importParamsJSON, _ := json.Marshal(importParamsReq)
	importReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.getImportParameters", Params: importParamsJSON, ID: 1}
	importResult, err := server.handleGetImportParameters(importReq)
	require.NoError(t, err)

	importParams := importResult.(GetImportParametersResult)

	t.Run("wraps key material successfully", func(t *testing.T) {
		// Create key material (32 bytes for AES-256)
		keyMaterial := make([]byte, 32)
		_, err := rand.Read(keyMaterial)
		require.NoError(t, err)

		params := WrapKeyParams{
			KeyMaterial:          keyMaterial,
			WrappingPublicKeyPEM: importParams.WrappingPublicKeyPEM,
			Algorithm:            "RSAES_OAEP_SHA_256",
			ImportToken:          importParams.ImportToken,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.wrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleWrapKey(req)
		require.NoError(t, err)

		wrapResult, ok := result.(WrapKeyResult)
		require.True(t, ok)
		assert.NotEmpty(t, wrapResult.WrappedKey)
	})
}

// TestHandler_ImportExportKeyFlow tests export key flow error handling
func TestHandler_ImportExportKeyFlow(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an exportable key
	genParams := GenerateKeyParams{
		KeyID:      "test-export-flow-key",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: true,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("handles export when wrapping key is too small", func(t *testing.T) {
		// RSA keys are typically too large to wrap with standard RSA-OAEP 2048
		params := ExportKeyParams{
			KeyID:     "test-export-flow-key",
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.exportKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleExportKeyMaterial(req)
		// This will error due to key size limitations
		require.Error(t, err)
	})
}

// TestHandler_ImportKey_ErrorPath tests key import error handling
func TestHandler_ImportKey_ErrorPath(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Get import parameters
	importParamsReq := GetImportParametersParams{
		KeyID:     "test-import-flow-key",
		Backend:   "software",
		Algorithm: "RSAES_OAEP_SHA_256",
	}
	importParamsJSON, _ := json.Marshal(importParamsReq)
	importReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.getImportParameters", Params: importParamsJSON, ID: 1}
	importResult, err := server.handleGetImportParameters(importReq)
	require.NoError(t, err)

	importParams := importResult.(GetImportParametersResult)

	// Create and wrap key material
	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err)

	wrapParamsReq := WrapKeyParams{
		KeyMaterial:          keyMaterial,
		WrappingPublicKeyPEM: importParams.WrappingPublicKeyPEM,
		Algorithm:            "RSAES_OAEP_SHA_256",
		ImportToken:          importParams.ImportToken,
	}
	wrapParamsJSON, _ := json.Marshal(wrapParamsReq)
	wrapReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.wrapKey", Params: wrapParamsJSON, ID: 1}
	wrapResult, err := server.handleWrapKey(wrapReq)
	require.NoError(t, err)

	wrapped := wrapResult.(WrapKeyResult)

	t.Run("handles import error for raw key material", func(t *testing.T) {
		// The wrapped key material cannot be directly imported as a private key
		params := ImportKeyParams{
			KeyID:       "test-import-flow-key",
			Backend:     "software",
			WrappedKey:  wrapped.WrappedKey,
			Algorithm:   wrapped.Algorithm,
			ImportToken: wrapped.ImportToken,
			Metadata:    wrapped.Metadata,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.importKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleImportKeyMaterial(req)
		require.Error(t, err)
	})
}

// TestHandler_ListKeys_Empty tests listing keys when empty
func TestHandler_ListKeys_Empty(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("returns empty list when no keys exist", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listKeys",
			ID:      1,
		}

		result, err := server.handleListKeys(req)
		require.NoError(t, err)

		listResult, ok := result.(ListKeysResult)
		require.True(t, ok)
		assert.NotNil(t, listResult.Keys)
	})
}

// TestHandler_CopyKey_ErrorFlow tests copy key error handling
func TestHandler_CopyKey_ErrorFlow(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key (non-exportable by default)
	genParams := GenerateKeyParams{
		KeyID:      "test-copy-source",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: false,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("fails to copy non-exportable key", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			SourceKeyID:   "test-copy-source",
			DestBackend:   "software",
			DestKeyID:     "test-copy-dest",
			Algorithm:     "RSAES_OAEP_SHA_256",
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
		assert.Contains(t, err.Error(), "failed to export key")
	})
}

// TestHandler_ExportKey_NonExportableKey tests export error for non-exportable key
func TestHandler_ExportKey_NonExportableKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a non-exportable key
	genParams := GenerateKeyParams{
		KeyID:      "test-export-nonexp",
		Backend:    "software",
		KeyType:    "rsa",
		KeySize:    2048,
		Exportable: false,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("fails to export non-exportable key", func(t *testing.T) {
		params := ExportKeyParams{
			KeyID:     "test-export-nonexp",
			Algorithm: "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.exportKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleExportKeyMaterial(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not exportable")
	})
}

// TestHandler_Decrypt_SymmetricWithInvalidCiphertext tests decrypt with invalid ciphertext
func TestHandler_Decrypt_SymmetricWithInvalidCiphertext(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a symmetric key
	genParams := GenerateKeyParams{
		KeyID:     "test-decrypt-invalid-ct",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("fails with invalid ciphertext", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "test-decrypt-invalid-ct",
			Backend:    "software",
			Ciphertext: []byte("invalid ciphertext"),
			Nonce:      []byte("12bytesnonce"),
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
	})
}

// TestHandler_ListCerts_WithCerts tests listing certs when some exist
func TestHandler_ListCerts_WithCerts(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Create and save a certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Save cert
	saveCertParams := SaveCertParams{
		KeyID:   "list-cert-test-key",
		CertPEM: string(certPEM),
	}
	saveCertParamsJSON, _ := json.Marshal(saveCertParams)
	saveCertReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.saveCert", Params: saveCertParamsJSON, ID: 1}
	_, err = server.handleSaveCert(saveCertReq)
	require.NoError(t, err)

	t.Run("lists certs with existing certs", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listCerts",
			ID:      1,
		}

		result, err := server.handleListCerts(req)
		require.NoError(t, err)

		listResult, ok := result.(ListCertsResult)
		require.True(t, ok)
		assert.Contains(t, listResult.KeyIDs, "list-cert-test-key")
	})
}

// TestHandler_DeleteKey_SearchFallback tests delete key search fallback
func TestHandler_DeleteKey_SearchFallback(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-delete-search-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("deletes key without specifying backend", func(t *testing.T) {
		params := DeleteKeyParams{
			KeyID: "test-delete-search-key",
			// No backend - should search
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

// TestHandler_ListKeys_MultipleKeys tests listing multiple keys
func TestHandler_ListKeys_MultipleKeys(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate multiple keys
	keyIDs := []string{"list-key-1", "list-key-2", "list-key-3"}
	for _, keyID := range keyIDs {
		genParams := GenerateKeyParams{
			KeyID:   keyID,
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		}
		genParamsJSON, _ := json.Marshal(genParams)
		genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
		_, err := server.handleGenerateKey(genReq)
		require.NoError(t, err)
	}

	t.Run("lists all keys", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listKeys",
			ID:      1,
		}

		result, err := server.handleListKeys(req)
		require.NoError(t, err)

		listResult, ok := result.(ListKeysResult)
		require.True(t, ok)
		assert.GreaterOrEqual(t, len(listResult.Keys), 3)
	})
}

// TestHandler_Sign_InvalidHashAlgorithm tests sign with invalid hash
func TestHandler_Sign_InvalidHashAlgorithm(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-sign-invalid-hash",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("fails with invalid hash algorithm", func(t *testing.T) {
		params := SignParams{
			KeyID:   "test-sign-invalid-hash",
			Backend: "software",
			Data:    []byte("test data"),
			Hash:    "INVALID_HASH",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSign(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported hash algorithm")
	})
}

// TestHandler_Verify_InvalidHashAlgorithm tests verify with invalid hash
func TestHandler_Verify_InvalidHashAlgorithm(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-invalid-hash",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("fails with invalid hash algorithm", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-verify-invalid-hash",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: []byte("fake sig"),
			Hash:      "INVALID_HASH",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleVerify(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported hash algorithm")
	})
}

// TestHandler_GetKey_WithDefaultBackend tests getting key without backend
func TestHandler_GetKey_WithDefaultBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-get-default-backend",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("gets key without specifying backend", func(t *testing.T) {
		params := GetKeyParams{
			KeyID: "test-get-default-backend",
			// No backend - should search
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetKey(req)
		require.NoError(t, err)

		getResult, ok := result.(GetKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-get-default-backend", getResult.KeyID)
	})
}

// TestHandler_DeleteKey_WithBackend tests deleting key with backend specified
func TestHandler_DeleteKey_WithBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-delete-with-backend",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("deletes key with backend specified", func(t *testing.T) {
		params := DeleteKeyParams{
			KeyID:   "test-delete-with-backend",
			Backend: "software",
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

// TestHandler_Decrypt_WithEmptyCiphertext tests decrypt with empty ciphertext
func TestHandler_Decrypt_WithEmptyCiphertext(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with empty ciphertext", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "any-key",
			Backend:    "software",
			Ciphertext: []byte{},
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

// TestHandler_Encrypt_InvalidBackend tests encrypt with invalid backend
func TestHandler_Encrypt_InvalidBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := EncryptParams{
			KeyID:     "test-key",
			Backend:   "nonexistent",
			Plaintext: []byte("data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEncrypt(req)
		require.Error(t, err)
	})
}

// TestHandler_GenerateKey_Ed25519 tests generating an Ed25519 key
func TestHandler_GenerateKey_Ed25519(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("generates Ed25519 key", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-ed25519-gen",
			Backend: "software",
			KeyType: "ed25519",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(req)
		require.NoError(t, err)

		genResult, ok := result.(GenerateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-ed25519-gen", genResult.KeyID)
	})
}

// TestHandler_Sign_DefaultHash tests signing with default hash (SHA256)
func TestHandler_Sign_DefaultHash(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-sign-default-hash",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("signs with default hash when not specified", func(t *testing.T) {
		params := SignParams{
			KeyID:   "test-sign-default-hash",
			Backend: "software",
			Data:    []byte("test data"),
			// No hash specified - should default to SHA256
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleSign(req)
		require.NoError(t, err)

		signResult, ok := result.(SignResult)
		require.True(t, ok)
		assert.NotNil(t, signResult.Signature)
	})
}

// TestHandler_RotateKey_WithBackend tests rotating key with backend
func TestHandler_RotateKey_WithBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-rotate-with-backend",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("rotates key with backend specified", func(t *testing.T) {
		params := RotateKeyParams{
			KeyID:   "test-rotate-with-backend",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.rotateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleRotateKey(req)
		require.NoError(t, err)

		rotateResult, ok := result.(RotateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-rotate-with-backend", rotateResult.KeyID)
	})
}

// TestHandler_Sign_WithoutBackend tests signing without specifying backend
func TestHandler_Sign_WithoutBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-sign-no-backend",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("signs without specifying backend", func(t *testing.T) {
		params := SignParams{
			KeyID: "test-sign-no-backend",
			// No backend - should search
			Data: []byte("test data"),
			Hash: "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleSign(req)
		require.NoError(t, err)

		signResult, ok := result.(SignResult)
		require.True(t, ok)
		assert.NotNil(t, signResult.Signature)
	})
}

// TestHandler_Verify_WithoutBackend tests verifying without specifying backend
func TestHandler_Verify_WithoutBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-no-backend",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Sign data
	signParams := SignParams{
		KeyID:   "test-verify-no-backend",
		Backend: "software",
		Data:    []byte("test data"),
		Hash:    "SHA256",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.sign", Params: signParamsJSON, ID: 1}
	signResult, err := server.handleSign(signReq)
	require.NoError(t, err)

	signature := signResult.(SignResult).Signature

	t.Run("verifies without specifying backend", func(t *testing.T) {
		params := VerifyParams{
			KeyID: "test-verify-no-backend",
			// No backend - should search
			Data:      []byte("test data"),
			Signature: signature,
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})
}

// TestHandler_ListKeys_InvalidParams tests list keys with invalid params
func TestHandler_ListKeys_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("handles invalid JSON params gracefully", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listKeys",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		// Should not error - listKeys can work without params
		result, err := server.handleListKeys(req)
		require.NoError(t, err)

		listResult, ok := result.(ListKeysResult)
		require.True(t, ok)
		assert.NotNil(t, listResult.Keys)
	})
}

// TestHandler_AsymmetricEncrypt_DefaultBackend tests asymmetric encrypt without backend
func TestHandler_AsymmetricEncrypt_DefaultBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-asym-enc-no-backend",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("encrypts without specifying backend", func(t *testing.T) {
		params := AsymmetricEncryptParams{
			KeyID: "test-asym-enc-no-backend",
			// No backend - should search
			Plaintext: []byte("secret"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.asymmetricEncrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleAsymmetricEncrypt(req)
		require.NoError(t, err)

		encResult, ok := result.(AsymmetricEncryptResult)
		require.True(t, ok)
		assert.NotEmpty(t, encResult.Ciphertext)
	})
}

// TestHandler_AsymmetricDecrypt_DefaultBackend tests asymmetric decrypt without backend
func TestHandler_AsymmetricDecrypt_DefaultBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-asym-dec-no-backend",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Get signer to get public key
	attrs, err := server.findKeyByCN("test-asym-dec-no-backend")
	require.NoError(t, err)

	signer, err := server.keystore.Signer(attrs)
	require.NoError(t, err)

	rsaPubKey := signer.Public().(*rsa.PublicKey)

	// Encrypt
	plaintext := []byte("secret")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, plaintext)
	require.NoError(t, err)

	t.Run("decrypts without specifying backend", func(t *testing.T) {
		params := AsymmetricDecryptParams{
			KeyID: "test-asym-dec-no-backend",
			// No backend - should search
			Ciphertext: ciphertext,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.asymmetricDecrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleAsymmetricDecrypt(req)
		require.NoError(t, err)

		decResult, ok := result.(AsymmetricDecryptResult)
		require.True(t, ok)
		assert.Equal(t, plaintext, decResult.Plaintext)
	})
}

// TestHandler_DeleteKey_SearchSymmetric tests delete key falling back to symmetric backend
func TestHandler_DeleteKey_SearchSymmetric(t *testing.T) {
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

	t.Run("deletes key found in search", func(t *testing.T) {
		params := DeleteKeyParams{
			KeyID: "test-delete-sym-search",
			// No backend - will search
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

// TestHandler_ListKeys_WithBackend tests listing keys with specific backend
func TestHandler_ListKeys_WithBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-list-with-backend",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("lists keys with backend filter", func(t *testing.T) {
		params := map[string]string{
			"backend": "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listKeys",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleListKeys(req)
		require.NoError(t, err)

		listResult, ok := result.(ListKeysResult)
		require.True(t, ok)
		assert.NotNil(t, listResult.Keys)
	})
}

// TestHandler_Decrypt_Asymmetric tests asymmetric decryption through handleDecrypt
func TestHandler_Decrypt_Asymmetric(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-asym-decrypt-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Get the public key to encrypt with
	getParams := GetKeyParams{
		KeyID:   "test-asym-decrypt-key",
		Backend: "software",
	}
	getParamsJSON, _ := json.Marshal(getParams)
	getReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.getKey", Params: getParamsJSON, ID: 2}
	result, err := server.handleGetKey(getReq)
	require.NoError(t, err)
	getResult := result.(GetKeyResult)

	// Parse the public key
	block, _ := pem.Decode([]byte(getResult.PublicKeyPEM))
	require.NotNil(t, block)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	rsaPubKey := pubKey.(*rsa.PublicKey)

	// Encrypt some data with RSA PKCS1v15
	plaintext := []byte("secret message for asymmetric decrypt test")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, plaintext)
	require.NoError(t, err)

	t.Run("decrypts asymmetric data", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "test-asym-decrypt-key",
			Backend:    "software",
			Ciphertext: ciphertext,
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

		decryptResult, ok := result.(DecryptResult)
		require.True(t, ok)
		assert.Equal(t, plaintext, decryptResult.Plaintext)
	})
}

// TestHandler_DeleteKey_ErrorPaths tests various error paths in deleteKey
func TestHandler_DeleteKey_ErrorPaths(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteKey",
			Params:  json.RawMessage(`{invalid`),
			ID:      1,
		}

		_, err := server.handleDeleteKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("missing key_id", func(t *testing.T) {
		params := DeleteKeyParams{
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDeleteKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("key not found in search", func(t *testing.T) {
		params := DeleteKeyParams{
			KeyID: "non-existent-delete-key",
			// No backend - will search
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDeleteKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_Verify_ErrorPaths tests error paths in handleVerify
func TestHandler_Verify_ErrorPaths(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  json.RawMessage(`{invalid`),
			ID:      1,
		}

		_, err := server.handleVerify(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("missing key_id", func(t *testing.T) {
		params := VerifyParams{
			Data:      []byte("test"),
			Signature: []byte("sig"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleVerify(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("key not found", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "non-existent-verify-key",
			Data:      []byte("test"),
			Signature: []byte("sig"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleVerify(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_Sign_ErrorPaths tests error paths in handleSign
func TestHandler_Sign_ErrorPaths(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  json.RawMessage(`{invalid`),
			ID:      1,
		}

		_, err := server.handleSign(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("missing key_id", func(t *testing.T) {
		params := SignParams{
			Data: []byte("test"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSign(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})
}

// TestHandler_HandleGenerateKey_MoreErrorPaths tests additional error paths
func TestHandler_HandleGenerateKey_MoreErrorPaths(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("unsupported key type", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-unsupported",
			Backend: "software",
			KeyType: "unsupported-type",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGenerateKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key type")
	})
}

// TestHandler_CopyKey_ErrorPaths tests error paths in handleCopyKey
func TestHandler_CopyKey_ErrorPaths(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("missing dest_backend", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			SourceKeyID:   "test-key",
			DestKeyID:     "dest-key",
			Algorithm:     "RAW",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dest_backend is required")
	})

	t.Run("missing dest_key_id", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			SourceKeyID:   "test-key",
			DestBackend:   "software",
			Algorithm:     "RAW",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dest_key_id is required")
	})

	t.Run("missing algorithm", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			SourceKeyID:   "test-key",
			DestBackend:   "software",
			DestKeyID:     "dest-key",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm is required")
	})

	t.Run("invalid source backend", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "nonexistent",
			SourceKeyID:   "test-key",
			DestBackend:   "software",
			DestKeyID:     "dest-key",
			Algorithm:     "RAW",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "source backend not found")
	})

	t.Run("invalid dest backend", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			SourceKeyID:   "test-key",
			DestBackend:   "nonexistent",
			DestKeyID:     "dest-key",
			Algorithm:     "RAW",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "destination backend not found")
	})
}

// TestHandler_Decrypt_WithBackendSearch tests decrypt with backend search
func TestHandler_Decrypt_WithBackendSearch(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate a symmetric key
	genParams := GenerateKeyParams{
		KeyID:     "test-decrypt-search",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Encrypt some data
	encryptParams := EncryptParams{
		KeyID:     "test-decrypt-search",
		Backend:   "software",
		Plaintext: []byte("search test data"),
	}
	encryptParamsJSON, _ := json.Marshal(encryptParams)
	encryptReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.encrypt", Params: encryptParamsJSON, ID: 2}
	encResult, err := server.handleEncrypt(encryptReq)
	require.NoError(t, err)
	encryptResult := encResult.(EncryptResult)

	t.Run("decrypts with backend search", func(t *testing.T) {
		params := DecryptParams{
			KeyID: "test-decrypt-search",
			// No backend - will search
			Ciphertext: encryptResult.Ciphertext,
			Nonce:      encryptResult.Nonce,
			Tag:        encryptResult.Tag,
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

		decryptResult, ok := result.(DecryptResult)
		require.True(t, ok)
		assert.Equal(t, []byte("search test data"), decryptResult.Plaintext)
	})
}

// TestHandler_Decrypt_SearchInSoftwareBackend tests decrypt searching in software backend
// when key is not found in symmetric backend
func TestHandler_Decrypt_SearchInSoftwareBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key in software backend (not symmetric)
	genParams := GenerateKeyParams{
		KeyID:   "test-decrypt-rsa-search",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Get the public key to encrypt with
	getParams := GetKeyParams{
		KeyID:   "test-decrypt-rsa-search",
		Backend: "software",
	}
	getParamsJSON, _ := json.Marshal(getParams)
	getReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.getKey", Params: getParamsJSON, ID: 2}
	result, err := server.handleGetKey(getReq)
	require.NoError(t, err)
	getResult := result.(GetKeyResult)

	// Parse the public key
	block, _ := pem.Decode([]byte(getResult.PublicKeyPEM))
	require.NotNil(t, block)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	rsaPubKey := pubKey.(*rsa.PublicKey)

	// Encrypt some data
	plaintext := []byte("test search in software backend")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, plaintext)
	require.NoError(t, err)

	t.Run("finds key in software backend after symmetric lookup fails", func(t *testing.T) {
		params := DecryptParams{
			KeyID: "test-decrypt-rsa-search",
			// No backend - will search symmetric first, then software
			Ciphertext: ciphertext,
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

		decryptResult, ok := result.(DecryptResult)
		require.True(t, ok)
		assert.Equal(t, plaintext, decryptResult.Plaintext)
	})
}

// TestHandler_Decrypt_KeyNotFoundAnywhere tests decrypt when key is not found in any backend
func TestHandler_Decrypt_KeyNotFoundAnywhere(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("returns error when key not found in any backend", func(t *testing.T) {
		params := DecryptParams{
			KeyID: "non-existent-decrypt-key",
			// No backend - will search both and fail
			Ciphertext: []byte("dummy"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.decrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDecrypt(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find key")
	})
}

// TestHandler_Verify_SignatureAsStruct tests verify with signature as a struct/map type
// This covers the default case in signature conversion (lines 459-463)
func TestHandler_Verify_SignatureAsStruct(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-struct-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	t.Run("handles signature as map/struct type", func(t *testing.T) {
		// Send a signature as a map type (will trigger default case)
		params := VerifyParams{
			KeyID:   "test-verify-struct-key",
			Backend: "software",
			Data:    []byte("test data"),
			Signature: map[string]interface{}{
				"data": "invalid",
			},
			Hash: "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		// Signature will be invalid but should not error
		assert.False(t, verifyResult.Valid)
	})

	t.Run("handles signature as integer type", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-verify-struct-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: 12345, // Integer type triggers default case
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.False(t, verifyResult.Valid)
	})
}

// TestHandler_Verify_WithByteSliceSignature tests verify with signature passed as []byte directly
func TestHandler_Verify_WithByteSliceSignature(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-bytes-key",
		Backend: "software",
		KeyType: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(genReq)
	require.NoError(t, err)

	// Sign data
	signParams := SignParams{
		KeyID:   "test-verify-bytes-key",
		Backend: "software",
		Data:    []byte("test data"),
		Hash:    "SHA256",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.sign", Params: signParamsJSON, ID: 1}
	signResult, err := server.handleSign(signReq)
	require.NoError(t, err)

	signature := signResult.(SignResult).Signature.([]byte)

	t.Run("verifies with raw []byte signature", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-verify-bytes-key",
			Backend:   "software",
			Data:      []byte("test data"),
			Signature: signature, // Pass as []byte directly
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})
}

// TestHandler_ListCerts_Success tests successful certificate listing
func TestHandler_ListCerts_Success(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	// Create a certificate to add to list
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-list-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Save the certificate
	saveCertParams := SaveCertParams{
		KeyID:   "list-test-cert",
		CertPEM: string(certPEM),
	}
	saveCertParamsJSON, _ := json.Marshal(saveCertParams)
	saveCertReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.saveCert", Params: saveCertParamsJSON, ID: 1}
	_, err = server.handleSaveCert(saveCertReq)
	require.NoError(t, err)

	t.Run("lists certificates with at least one cert", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listCerts",
			ID:      1,
		}

		result, err := server.handleListCerts(req)
		require.NoError(t, err)

		listResult, ok := result.(ListCertsResult)
		require.True(t, ok)
		assert.Contains(t, listResult.KeyIDs, "list-test-cert")
		assert.GreaterOrEqual(t, len(listResult.KeyIDs), 1)
	})
}
